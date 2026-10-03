//! Slave side of dial-in SSH agent forwarding: while the hub enables it, a
//! relay socket in the dial directory whose connections (after their first
//! byte) become `--mode agent` sessions over the master pool.

use std::io::{self, Read};
use std::net::Shutdown;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::traits::{Listener as _, Stream as _};

use super::control::{discard_preamble_with_deadline, Cancel, LoopTiming};
use super::failure::{is_session_refusal, remote_text_tail};
use super::lock;
use super::pool::{Master, MasterLease, MasterPool};
use super::process::{kill_and_reap, pump, wait_child_until, StderrTail, STDERR_SETTLE};
use super::ssh::{DialTools, SshArgs};
use super::streams::STREAM_REAP_GRACE;
use crate::client::endpoint::ProfileId;
use crate::ipc::{LocalListener, LocalStream, SocketFileIdentity};
use crate::remote::link::protocol;

/// How long a relay connection may stay silent before its first byte. The
/// local server probes agent liveness by connecting and closing, which must
/// not cost an ssh session.
const FIRST_BYTE_IDLE: Duration = Duration::from_secs(60);
const MAX_RELAY_CONNECTIONS: usize = 16;
const SOCKET_MODE: u32 = 0o600;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Serves one relay connection once its first bytes arrived.
pub(super) type ServeConnection = Arc<dyn Fn(LocalStream, Vec<u8>) + Send + Sync>;

/// The agent relay socket of one link attempt, bound while the hub
/// forwards its agent to this link.
pub(super) struct AgentRelay {
    path: PathBuf,
    serve: ServeConnection,
    /// Set when the attempt is torn down; the relay stays unbound.
    closed: AtomicBool,
    /// The bound socket and its accept loop's stop flag.
    bound: Mutex<Option<(SocketFileIdentity, Arc<AtomicBool>)>>,
}

impl AgentRelay {
    pub(super) fn new(path: PathBuf, serve: ServeConnection) -> Self {
        Self {
            path,
            serve,
            closed: AtomicBool::new(false),
            bound: Mutex::new(None),
        }
    }

    /// The relay socket while it is bound.
    pub(super) fn socket(&self) -> Option<PathBuf> {
        lock(&self.bound).is_some().then(|| self.path.clone())
    }

    /// Binds or unbinds the relay socket. Connections already relayed
    /// continue until they end.
    pub(super) fn set_enabled(&self, enabled: bool) {
        let mut bound = lock(&self.bound);
        if enabled && bound.is_none() && !self.closed.load(Ordering::SeqCst) {
            match self.bind() {
                Ok(socket) => {
                    *bound = Some(socket);
                    super::stderr_line(format_args!(
                        "herdr dial: the hub forwards its SSH agent at {}",
                        self.path.display()
                    ));
                }
                Err(error) => tracing::warn!(%error, "dial could not bind the agent relay"),
            }
        } else if !enabled {
            if let Some((identity, stopping)) = bound.take() {
                stopping.store(true, Ordering::SeqCst);
                // Wake the blocking accept so the loop sees the flag.
                let _ = crate::ipc::connect_local_stream(&self.path);
                let _ = crate::ipc::remove_socket_file_if_owned(&self.path, &identity);
                tracing::info!("dial agent relay unbound");
            }
        }
    }

    /// Unbinds for good (link attempt teardown).
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.set_enabled(false);
    }

    fn bind(&self) -> io::Result<(SocketFileIdentity, Arc<AtomicBool>)> {
        crate::ipc::prepare_socket_path(&self.path, |path| {
            format!("another process is serving {}", path.display())
        })?;
        let listener = crate::ipc::bind_private_local_listener(&self.path)?;
        let identity = crate::ipc::restrict_socket_permissions(&self.path, SOCKET_MODE)
            .and_then(|()| crate::ipc::socket_file_identity(&self.path))
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&self.path);
            })?;
        let stopping = Arc::new(AtomicBool::new(false));
        let (serve, stop) = (Arc::clone(&self.serve), Arc::clone(&stopping));
        thread::Builder::new()
            .name("herdr-dial-agent".into())
            .spawn(move || accept_loop(listener, serve, stop))
            .inspect_err(|_| {
                let _ = crate::ipc::remove_socket_file_if_owned(&self.path, &identity);
            })?;
        Ok((identity, stopping))
    }
}

fn accept_loop(listener: LocalListener, serve: ServeConnection, stopping: Arc<AtomicBool>) {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let accepted = listener.accept();
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let client = match accepted {
            Ok(client) => client,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                tracing::warn!(%error, "dial agent relay accept failed");
                thread::sleep(ACCEPT_RETRY_DELAY);
                continue;
            }
        };
        if !matches!(
            crate::platform::local_stream_peer_is_current_user(&client),
            Ok(true)
        ) || active.load(Ordering::SeqCst) >= MAX_RELAY_CONNECTIONS
        {
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (serve, finished) = (Arc::clone(&serve), Arc::clone(&active));
        let spawned = thread::Builder::new()
            .name("herdr-dial-agent-client".into())
            .spawn(move || {
                if let Some(first) = first_bytes(&client) {
                    serve(client, first);
                }
                finished.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// The first bytes a relay client sends; `None` when it closes (a liveness
/// probe) or stays silent for [`FIRST_BYTE_IDLE`].
fn first_bytes(client: &LocalStream) -> Option<Vec<u8>> {
    let mut first = vec![0_u8; 4 * 1024];
    client.set_recv_timeout(Some(FIRST_BYTE_IDLE)).ok()?;
    let read = (&*client).read(&mut first).ok().filter(|read| *read > 0)?;
    client.set_recv_timeout(None).ok()?;
    first.truncate(read);
    Some(first)
}

/// What agent sessions need from the link attempt.
pub(super) struct AgentSessions {
    pub(super) tools: DialTools,
    pub(super) ssh: SshArgs,
    pub(super) link_id: ProfileId,
    pub(super) pool: Arc<MasterPool>,
    pub(super) timing: LoopTiming,
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    leftover: Vec<u8>,
    _lease: MasterLease,
}

impl AgentSessions {
    /// Relays each connection through its own agent session on the hub.
    pub(super) fn into_serve(self) -> ServeConnection {
        Arc::new(move |client, first| match self.open() {
            Ok(session) => relay(client, first, session),
            Err(message) => tracing::info!(%message, "dial agent session failed"),
        })
    }

    /// An agent session on the least loaded master, adding a master once
    /// when the hub refuses the session (sshd `MaxSessions`).
    fn open(&self) -> Result<Session, String> {
        let (master, observed) = self
            .pool
            .least_loaded()
            .ok_or("the dialing machine has no live ssh connection to the hub")?;
        match self.open_on(master) {
            Err((true, message)) => match self.pool.grow(observed) {
                Some(extra) => self.open_on(extra).map_err(|(_, message)| message),
                None => Err(message),
            },
            result => result.map_err(|(_, message)| message),
        }
    }

    /// `Err((refused, message))` when the session did not start.
    fn open_on(&self, master: Arc<Master>) -> Result<Session, (bool, String)> {
        let lease = MasterLease::acquire(master);
        let args = self
            .ssh
            .session(&lease.0.ctl, protocol::agent_command(&self.link_id))
            .map_err(|error| {
                (
                    false,
                    format!("cannot build the agent ssh command: {error}"),
                )
            })?;
        let mut child = self
            .tools
            .ssh_command(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| (false, format!("failed to run ssh: {error}")))?;
        let stderr = StderrTail::capture(child.stderr.take());
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            kill_and_reap(&mut child);
            return Err((false, "ssh stdio was not captured".into()));
        };
        // Teardown stops the masters, which ends a session still starting.
        let cancel = Cancel {
            requested: &|| false,
            tick: self.timing.tick,
        };
        match discard_preamble_with_deadline(stdout, self.timing.preamble_deadline, cancel, || {
            let _ = child.kill();
        }) {
            Ok((stdout, leftover)) => Ok(Session {
                child,
                stdin,
                stdout,
                leftover,
                _lease: lease,
            }),
            Err(error) => {
                kill_and_reap(&mut child);
                let text = stderr.text_after_exit(STDERR_SETTLE);
                Err((
                    is_session_refusal(&text),
                    format!("{error} ({})", remote_text_tail(&text)),
                ))
            }
        }
    }
}

/// Pumps `client` (starting with `first`) and the session both ways until
/// either side ends, then reaps the session.
fn relay(client: LocalStream, first: Vec<u8>, session: Session) {
    let Session {
        mut child,
        mut stdin,
        mut stdout,
        leftover,
        _lease,
    } = session;
    let client = Arc::new(client);
    let upload_client = Arc::clone(&client);
    // Ends when the client closes; dropping stdin then ends the hub session.
    let upload = thread::Builder::new()
        .name("herdr-dial-agent-up".into())
        .spawn(move || pump(&mut &*upload_client, &mut stdin, &first));
    let _ = pump(&mut stdout, &mut &*client, &leftover);
    let _ = crate::platform::shutdown_local_stream(&client, Shutdown::Both);
    if let Ok(upload) = upload {
        let _ = upload.join();
    }
    if wait_child_until(&mut child, Instant::now() + STREAM_REAP_GRACE).is_none() {
        kill_and_reap(&mut child);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;

    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn relay_binds_privately_and_opens_sessions_only_after_the_first_byte() {
        let dir = std::env::temp_dir().join(format!("hda-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::platform::ensure_private_directory(&dir).unwrap();
        let path = dir.join("agent.sock");
        std::fs::write(&path, b"stale").unwrap();
        let served = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&served);
        let relay = AgentRelay::new(
            path.clone(),
            Arc::new(move |_client: LocalStream, first: Vec<u8>| lock(&record).push(first)),
        );
        assert_eq!(relay.socket(), None);

        relay.set_enabled(true);
        assert_eq!(relay.socket(), Some(path.clone()));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A liveness probe connects and closes without costing a session.
        drop(UnixStream::connect(&path).unwrap());
        let mut client = UnixStream::connect(&path).unwrap();
        client.write_all(b"\0\0\0\x01\x0b").unwrap();
        wait_until("the first session", || !lock(&served).is_empty());
        thread::sleep(Duration::from_millis(50));
        assert_eq!(*lock(&served), [b"\0\0\0\x01\x0b".to_vec()]);

        relay.set_enabled(false);
        assert_eq!(relay.socket(), None);
        assert!(!path.exists());
        relay.set_enabled(true);
        assert!(path.exists());
        relay.close();
        relay.set_enabled(true);
        assert_eq!(relay.socket(), None);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
