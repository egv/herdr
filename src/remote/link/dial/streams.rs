//! Stream sessions: one ssh session over the master pool per hub connection,
//! piped into a local bridge child.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::agent::AgentRelay;
use super::control::{discard_preamble_with_deadline, Cancel, LoopEvent, LoopTiming, StreamOpener};
use super::failure::{is_session_refusal, remote_text_tail};
use super::lock;
use super::pool::{Master, MasterLease, MasterPool};
use super::process::{
    bridge_command, kill_and_reap, kill_slot, pump, reap_slot, PrewarmGate, Reaped, StderrTail,
    CHILD_POLL, PREWARM_TIMEOUT, STDERR_SETTLE,
};
use super::reexec::ReexecRequest;
use super::ssh::{DialTools, SshArgs};
use crate::client::endpoint::ProfileId;
use crate::remote::link::protocol::{
    open_failed_code, ControlMessage, OpenFailed, OpenRequest, StreamKind,
};

/// After one direction of a stream ends, how long the rest may take.
pub(crate) const STREAM_REAP_GRACE: Duration = Duration::from_secs(5);

/// Buffer for the first bytes the hub sends on a stream.
const FIRST_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct StreamProcesses {
    ssh: Mutex<Option<Child>>,
    bridge: Mutex<Option<Child>>,
}

/// Live streams of one link attempt, for limits and teardown.
#[derive(Default)]
pub(crate) struct StreamRegistry {
    next_id: AtomicU64,
    streams: Mutex<HashMap<u64, Arc<StreamProcesses>>>,
    /// Set by `shutdown`; streams that start afterwards end immediately.
    closed: AtomicBool,
}

impl StreamRegistry {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn register(self: &Arc<Self>) -> StreamGuard {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let processes = Arc::new(StreamProcesses::default());
        lock(&self.streams).insert(id, Arc::clone(&processes));
        StreamGuard {
            registry: Arc::clone(self),
            id,
            processes,
        }
    }

    fn len(&self) -> usize {
        lock(&self.streams).len()
    }

    fn snapshot(&self) -> Vec<Arc<StreamProcesses>> {
        lock(&self.streams).values().cloned().collect()
    }

    /// Kills stream sessions, gives bridges `grace` to exit on stdin EOF,
    /// then kills the rest.
    pub(super) fn shutdown(&self, grace: Duration) {
        self.closed.store(true, Ordering::SeqCst);
        for processes in self.snapshot() {
            kill_slot(&processes.ssh);
        }
        let deadline = Instant::now() + grace;
        while self.len() > 0 && Instant::now() < deadline {
            thread::sleep(CHILD_POLL);
        }
        for processes in self.snapshot() {
            kill_slot(&processes.bridge);
        }
    }
}

struct StreamGuard {
    registry: Arc<StreamRegistry>,
    id: u64,
    processes: Arc<StreamProcesses>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        lock(&self.registry.streams).remove(&self.id);
    }
}

struct StreamSession {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    leftover: Vec<u8>,
    stderr: StderrTail,
}

struct SessionError {
    refused: bool,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PumpSide {
    FromHub,
    FromBridge,
}

fn spawn_pump<R, W>(
    name: &str,
    mut reader: R,
    mut writer: W,
    leftover: Vec<u8>,
    side: PumpSide,
    done: Sender<PumpSide>,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let spawned = thread::Builder::new().name(name.into()).spawn(move || {
        if let Err(error) = pump(&mut reader, &mut writer, &leftover) {
            tracing::debug!(%error, ?side, "dial stream pump ended with an error");
        }
        drop(writer);
        let _ = done.send(side);
    });
    if let Err(error) = spawned {
        tracing::warn!(%error, "dial could not start a stream pump");
    }
}

/// Production stream opener: a stream ssh session over the pool piped into
/// a local bridge child.
#[derive(Clone)]
pub(super) struct SshStreamOpener {
    pub(super) tools: DialTools,
    pub(super) ssh: SshArgs,
    /// The local name of the link (`herdr machine dial run <name>`).
    pub(super) dial_name: String,
    pub(super) link_id: ProfileId,
    pub(super) pool: Arc<MasterPool>,
    pub(super) registry: Arc<StreamRegistry>,
    pub(super) timing: LoopTiming,
    /// API bridges need a running server; the prewarm starts it.
    pub(super) prewarm: Arc<PrewarmGate>,
    /// Bridges get the agent relay as `SSH_AUTH_SOCK` while it is bound.
    pub(super) agent: Arc<AgentRelay>,
    /// Restarts the dialer once an update stream installed a new executable.
    pub(super) reexec: ReexecRequest,
    /// Where that update's probation is recorded.
    pub(super) probation_file: PathBuf,
}

impl StreamOpener for SshStreamOpener {
    fn active_streams(&self) -> usize {
        self.registry.len()
    }

    fn open(&self, request: OpenRequest, events: SyncSender<LoopEvent>) {
        let guard = self.registry.register();
        let worker = self.clone();
        let nonce = request.nonce.clone();
        let failure_events = events.clone();
        let spawned = thread::Builder::new()
            .name("herdr-dial-stream".into())
            .spawn(move || {
                if let Err(failed) = worker.run_stream(&request, &guard) {
                    tracing::info!(
                        code = %failed.code,
                        message = %failed.message,
                        kind = ?request.kind,
                        "dial stream failed"
                    );
                    let _ = events.send(LoopEvent::Send(ControlMessage::OpenFailed(failed)));
                }
            });
        if let Err(error) = spawned {
            // This runs on the control loop thread, which drains the queue:
            // never block on it. When it is full, the hub times the open out.
            let _ =
                failure_events.try_send(LoopEvent::Send(ControlMessage::OpenFailed(OpenFailed {
                    nonce,
                    code: open_failed_code::BRIDGE_FAILED.into(),
                    message: format!("the dialing machine could not start a stream: {error}"),
                })));
        }
    }

    fn set_agent_forwarding(&self, enabled: bool) {
        self.agent.set_enabled(enabled);
    }

    fn restart_server(&self, request_id: String, session: String, events: SyncSender<LoopEvent>) {
        let (exe, agent) = (self.tools.exe.clone(), self.agent.socket());
        super::update::spawn_restart(exe, agent, request_id, session, events);
    }
}

impl SshStreamOpener {
    fn open_session(&self, master: &Master, nonce: &str) -> Result<StreamSession, SessionError> {
        let local = |message: String| SessionError {
            refused: false,
            message,
        };
        let args = self
            .ssh
            .stream(&master.ctl, &self.link_id, nonce)
            .map_err(|error| local(format!("cannot build the stream ssh command: {error}")))?;
        let mut child = self
            .tools
            .ssh_command(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| local(format!("failed to run ssh: {error}")))?;
        let stderr = StderrTail::capture(child.stderr.take());
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            kill_and_reap(&mut child);
            return Err(local("ssh stdio was not captured".into()));
        };
        let disconnecting = || self.registry.is_closed();
        let cancel = Cancel {
            requested: &disconnecting,
            tick: self.timing.tick,
        };
        let preamble =
            discard_preamble_with_deadline(stdout, self.timing.preamble_deadline, cancel, || {
                let _ = child.kill();
            });
        match preamble {
            Ok((stdout, leftover)) => Ok(StreamSession {
                child,
                stdin,
                stdout,
                leftover,
                stderr,
            }),
            Err(error) => {
                kill_and_reap(&mut child);
                let text = stderr.text_after_exit(STDERR_SETTLE);
                let tail = remote_text_tail(&text);
                Err(SessionError {
                    refused: is_session_refusal(&text),
                    message: if tail.is_empty() {
                        format!("stream session failed: {error}")
                    } else {
                        format!("stream session failed: {error} ({tail})")
                    },
                })
            }
        }
    }

    fn run_stream(&self, request: &OpenRequest, guard: &StreamGuard) -> Result<(), OpenFailed> {
        let failed = |code: &str, message: String| OpenFailed {
            nonce: request.nonce.clone(),
            code: code.to_string(),
            message,
        };
        if self.registry.is_closed() {
            return Err(failed(
                open_failed_code::SSH_FAILED,
                "the dialing machine is disconnecting".into(),
            ));
        }
        let Some((master, observed)) = self.pool.least_loaded() else {
            return Err(failed(
                open_failed_code::SSH_FAILED,
                "the dialing machine has no live ssh connection to the hub".into(),
            ));
        };
        let mut lease = MasterLease::acquire(master);
        let session = match self.open_session(&lease.0, &request.nonce) {
            Ok(session) => session,
            Err(error) if error.refused => {
                let Some(extra) = self.pool.grow(observed) else {
                    return Err(failed(open_failed_code::SESSION_REFUSED, error.message));
                };
                lease = MasterLease::acquire(extra);
                self.open_session(&lease.0, &request.nonce)
                    .map_err(|retry| {
                        let code = if retry.refused {
                            open_failed_code::SESSION_REFUSED
                        } else {
                            open_failed_code::SSH_FAILED
                        };
                        failed(code, retry.message)
                    })?
            }
            Err(error) => return Err(failed(open_failed_code::SSH_FAILED, error.message)),
        };
        let StreamSession {
            child: ssh_child,
            stdin: ssh_stdin,
            stdout: mut ssh_stdout,
            mut leftover,
            stderr: ssh_stderr,
        } = session;
        // Registered before waiting on the hub, so a teardown can kill it.
        *lock(&guard.processes.ssh) = Some(ssh_child);
        if self.registry.is_closed() {
            kill_slot(&guard.processes.ssh);
        }

        // The hub-side acceptor prints its ready marker before it attaches
        // to the pending hub connection, and the hub client speaks first on
        // every stream kind (endpoint hello, API request). Start the bridge
        // only once the hub's first bytes arrive: an attach the hub refused
        // ends the session instead, and is reported with ssh's stderr.
        if leftover.is_empty() {
            match read_first_chunk(&mut ssh_stdout) {
                Ok(Some(chunk)) => leftover = chunk,
                Ok(None) | Err(_) => {
                    drop(ssh_stdin);
                    let exit = reap_slot(&guard.processes.ssh, Instant::now() + STREAM_REAP_GRACE);
                    if self.registry.is_closed() {
                        return Ok(());
                    }
                    let exit = match exit {
                        Reaped::Exited(status) => Some(status),
                        Reaped::Killed | Reaped::Missing => None,
                    };
                    return match stream_ended_before_data(
                        exit,
                        &ssh_stderr.text_after_exit(STDERR_SETTLE),
                    ) {
                        Some(message) => Err(failed(open_failed_code::SSH_FAILED, message)),
                        None => Ok(()),
                    };
                }
            }
        }

        if request.kind == StreamKind::Update {
            let link_id = self.link_id.to_string();
            let link = super::update::DialLink {
                name: &self.dial_name,
                link_id: &link_id,
            };
            let installed = super::update::serve_update(
                &self.tools.exe,
                &link,
                request,
                &mut ssh_stdout,
                &leftover,
                ssh_stdin,
            );
            // The hub closes the stream once it has read the result.
            let _ = reap_slot(&guard.processes.ssh, Instant::now() + STREAM_REAP_GRACE);
            if let Some(installed) = installed {
                super::update::restart_into_update(&self.reexec, &self.probation_file, &installed);
            }
            return Ok(());
        }

        // The API bridge does not start the server; right after the link
        // connected, the prewarm may still be starting it.
        if request.kind == StreamKind::Api && !self.prewarm.wait(PREWARM_TIMEOUT) {
            tracing::warn!("dial API stream stopped waiting for the server prewarm");
        }
        let agent_socket = self.agent.socket();
        let Some(mut command) = bridge_command(
            &self.tools.exe,
            request.kind,
            &request.session,
            agent_socket.as_deref(),
        ) else {
            kill_and_reap_slot(&guard.processes.ssh);
            return Err(failed(
                open_failed_code::UNSUPPORTED_KIND,
                "unsupported stream kind".into(),
            ));
        };
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut bridge = match command.spawn() {
            Ok(bridge) => bridge,
            Err(error) => {
                kill_and_reap_slot(&guard.processes.ssh);
                return Err(failed(
                    open_failed_code::BRIDGE_FAILED,
                    format!("failed to start the local herdr bridge: {error}"),
                ));
            }
        };
        let bridge_stderr = StderrTail::capture(bridge.stderr.take());
        let (Some(bridge_stdin), Some(bridge_stdout)) = (bridge.stdin.take(), bridge.stdout.take())
        else {
            kill_and_reap(&mut bridge);
            kill_and_reap_slot(&guard.processes.ssh);
            return Err(failed(
                open_failed_code::BRIDGE_FAILED,
                "local herdr bridge stdio was not captured".into(),
            ));
        };
        *lock(&guard.processes.bridge) = Some(bridge);
        if self.registry.is_closed() {
            // Teardown began while this stream was starting: its processes
            // were not registered yet when the teardown kill pass ran.
            kill_slot(&guard.processes.ssh);
            kill_slot(&guard.processes.bridge);
        }

        let (done_sender, done) = mpsc::channel();
        spawn_pump(
            "herdr-dial-to-bridge",
            ssh_stdout,
            bridge_stdin,
            leftover,
            PumpSide::FromHub,
            done_sender.clone(),
        );
        spawn_pump(
            "herdr-dial-to-hub",
            bridge_stdout,
            ssh_stdin,
            Vec::new(),
            PumpSide::FromBridge,
            done_sender,
        );

        // Whichever side ends first has closed the other's stdin; give the
        // rest a bounded grace period.
        let first = done.recv().unwrap_or(PumpSide::FromHub);
        let deadline = Instant::now() + STREAM_REAP_GRACE;
        let bridge_exit = reap_slot(&guard.processes.bridge, deadline);
        if done
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_err()
        {
            kill_slot(&guard.processes.ssh);
        }
        let _ = reap_slot(&guard.processes.ssh, Instant::now() + STREAM_REAP_GRACE);
        tracing::debug!(
            ssh_stderr = %remote_text_tail(&ssh_stderr.text()),
            "dial stream ended"
        );

        if first == PumpSide::FromBridge {
            if let Reaped::Exited(status) = bridge_exit {
                if status.code().is_some_and(|code| code != 0) {
                    let text = bridge_stderr.text_after_exit(STDERR_SETTLE);
                    let code = if text.contains("needs one final update") {
                        open_failed_code::SERVER_NEEDS_UPDATE
                    } else {
                        open_failed_code::BRIDGE_FAILED
                    };
                    let tail = remote_text_tail(&text);
                    let message = if tail.is_empty() {
                        format!("the local herdr bridge exited with {status}")
                    } else {
                        tail
                    };
                    return Err(failed(code, message));
                }
            }
        }
        Ok(())
    }
}

/// Reads the first bytes of a stream; `None` at end-of-file.
fn read_first_chunk(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut buffer = vec![0_u8; FIRST_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(None),
            Ok(read) => {
                buffer.truncate(read);
                return Ok(Some(buffer));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Why a stream session that ended before the hub sent anything failed, or
/// `None` when it ended cleanly (the hub connection closed without data).
/// `exit` is `None` when the ssh process had to be killed. A hub-side
/// refusal is recognized by its exit status or by the acceptor's own stderr
/// line, which survives forced-command shells that lose the exit status.
fn stream_ended_before_data(exit: Option<ExitStatus>, ssh_stderr: &str) -> Option<String> {
    let acceptor_refused = ssh_stderr.contains(ACCEPTOR_STDERR_PREFIX);
    if exit.is_some_and(|status| status.success()) && !acceptor_refused {
        return None;
    }
    let tail = remote_text_tail(ssh_stderr);
    Some(if !tail.is_empty() {
        format!("the hub did not attach the stream: {tail}")
    } else if let Some(status) = exit {
        format!("the stream session ended before the hub attached it ({status})")
    } else {
        "the stream session did not end after the hub closed it".to_string()
    })
}

/// How the hub-side `herdr link-accept` prefixes the errors it prints.
const ACCEPTOR_STDERR_PREFIX: &str = "herdr link-accept:";

fn kill_and_reap_slot(slot: &Mutex<Option<Child>>) {
    if let Some(child) = lock(slot).as_mut() {
        kill_and_reap(child);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Command;

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn first_hub_bytes_gate_the_bridge_and_early_ends_are_explained() {
        use std::io::Cursor;
        use std::os::unix::process::ExitStatusExt;

        let first = read_first_chunk(&mut Cursor::new(b"hello".to_vec())).unwrap();
        assert_eq!(first.as_deref(), Some(&b"hello"[..]));
        assert_eq!(
            read_first_chunk(&mut Cursor::new(Vec::new())).unwrap(),
            None
        );

        // A clean exit before any data: the hub connection closed unused.
        assert_eq!(
            stream_ended_before_data(Some(ExitStatus::from_raw(0)), "noise\n"),
            None
        );
        // A refusal is recognized even when a shell lost the exit status.
        let lost_status = stream_ended_before_data(
            Some(ExitStatus::from_raw(0)),
            "herdr link-accept: the hub refused the stream: not private\n",
        )
        .unwrap();
        assert!(lost_status.contains("not private"), "{lost_status}");
        // The hub refused the attach: its reason comes from ssh stderr.
        let refused = stream_ended_before_data(
            Some(ExitStatus::from_raw(1 << 8)),
            "herdr link-accept: this machine has no active link on the hub\n",
        )
        .unwrap();
        assert!(refused.contains("no active link on the hub"), "{refused}");
        let silent = stream_ended_before_data(Some(ExitStatus::from_raw(1 << 8)), "").unwrap();
        assert!(silent.contains("before the hub attached it"), "{silent}");
        assert!(stream_ended_before_data(None, "").is_some());
    }

    #[test]
    fn registry_teardown_kills_stream_processes_and_refuses_new_streams() {
        let registry = Arc::new(StreamRegistry::default());
        let guard = registry.register();
        *lock(&guard.processes.ssh) = Some(sleeper());
        *lock(&guard.processes.bridge) = Some(sleeper());
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_closed());

        registry.shutdown(Duration::from_millis(50));
        assert!(registry.is_closed());
        let deadline = Instant::now() + Duration::from_secs(5);
        for slot in [&guard.processes.ssh, &guard.processes.bridge] {
            assert!(
                matches!(reap_slot(slot, deadline), Reaped::Exited(status) if status.code().is_none()),
                "teardown must kill the process"
            );
        }
        drop(guard);
        assert_eq!(registry.len(), 0);

        // A bounded wait kills a child that outlives its deadline.
        let slot = Mutex::new(Some(sleeper()));
        assert!(matches!(reap_slot(&slot, Instant::now()), Reaped::Killed));
        assert!(matches!(
            reap_slot(&Mutex::new(None), Instant::now()),
            Reaped::Missing
        ));
    }
}
