//! Local child processes of the dialer: bridge children, byte pumps, bounded
//! stderr capture, and bounded waits.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::failure::remote_text_tail;
use super::lock;
use crate::remote::link::protocol::StreamKind;
use crate::remote::link::status::sanitize_remote_text;

pub(crate) const PREWARM_TIMEOUT: Duration = Duration::from_secs(15);

const PUMP_BUFFER_BYTES: usize = 64 * 1024;

const STDERR_TAIL_BYTES: usize = 4 * 1024;

pub(super) const STDERR_SETTLE: Duration = Duration::from_millis(500);

pub(super) const CHILD_POLL: Duration = Duration::from_millis(25);

const MAX_PREWARM_SESSIONS: usize = 8;

/// Environment variables removed from bridge children: they describe the
/// dialer's own surroundings (for example a Herdr pane it was started in, or
/// the update it was re-executed after), not the session the hub asked for.
/// Servers the bridges start, and their panes, must not inherit them.
pub(crate) const CLEARED_CHILD_ENV: [&str; 6] = [
    "HERDR_ENV",
    "HERDR_SOCKET_PATH",
    "HERDR_CLIENT_SOCKET_PATH",
    "HERDR_PANE_ID",
    crate::session::SESSION_ENV_VAR,
    super::update::ROLLED_BACK_ENV,
];

/// Arguments of the local bridge for `kind` (`None` for kinds without a
/// bridge), omitting `--session` for the default session like `herdr
/// --remote` does.
pub(crate) fn bridge_args(kind: StreamKind, session: &str) -> Option<Vec<String>> {
    let subcommand = match kind {
        StreamKind::Client => "remote-client-bridge",
        StreamKind::Api => "remote-api-bridge",
        StreamKind::Update | StreamKind::Unknown => return None,
    };
    let mut args = Vec::with_capacity(3);
    if session != crate::session::DEFAULT_SESSION_NAME {
        args.push("--session".to_string());
        args.push(session.to_string());
    }
    args.push(subcommand.to_string());
    Some(args)
}

/// The local bridge child for one stream, with the dialer's Herdr
/// environment removed and `SSH_AUTH_SOCK` set to the agent relay while the
/// hub forwards its agent. Stdio is left to the caller.
pub(crate) fn bridge_command(
    exe: &Path,
    kind: StreamKind,
    session: &str,
    agent_socket: Option<&Path>,
) -> Option<Command> {
    let args = bridge_args(kind, session)?;
    let mut command = Command::new(exe);
    command.args(args);
    for name in CLEARED_CHILD_ENV {
        command.env_remove(name);
    }
    if let Some(socket) = agent_socket {
        command.env("SSH_AUTH_SOCK", socket);
    }
    Some(command)
}

/// Copies `reader` into `writer` with one fixed buffer, forwarding `leftover`
/// (bytes read past a ready marker) first. Returns the bytes forwarded.
pub(crate) fn pump(
    reader: &mut impl Read,
    writer: &mut impl Write,
    leftover: &[u8],
) -> io::Result<u64> {
    let mut total = 0_u64;
    if !leftover.is_empty() {
        writer.write_all(leftover)?;
        writer.flush()?;
        total = leftover.len() as u64;
    }
    let mut buffer = vec![0_u8; PUMP_BUFFER_BYTES];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        writer.write_all(&buffer[..read])?;
        writer.flush()?;
        total += read as u64;
    }
}

/// Bounded capture of a child's stderr (the last few KiB).
#[derive(Clone, Default)]
pub(crate) struct StderrTail {
    shared: Arc<(Mutex<TailBuffer>, Condvar)>,
}

#[derive(Default)]
struct TailBuffer {
    bytes: Vec<u8>,
    done: bool,
}

impl StderrTail {
    pub(crate) fn capture<R: Read + Send + 'static>(reader: Option<R>) -> Self {
        let tail = Self::default();
        let Some(mut reader) = reader else {
            tail.mark_done();
            return tail;
        };
        let shared = Arc::clone(&tail.shared);
        let spawned = thread::Builder::new()
            .name("herdr-dial-stderr".into())
            .spawn(move || {
                let mut chunk = [0_u8; 4 * 1024];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => {
                            let mut buffer = lock(&shared.0);
                            buffer.bytes.extend_from_slice(&chunk[..read]);
                            if buffer.bytes.len() > STDERR_TAIL_BYTES {
                                let excess = buffer.bytes.len() - STDERR_TAIL_BYTES;
                                buffer.bytes.drain(..excess);
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                lock(&shared.0).done = true;
                shared.1.notify_all();
            });
        if spawned.is_err() {
            tail.mark_done();
        }
        tail
    }

    fn mark_done(&self) {
        lock(&self.shared.0).done = true;
        self.shared.1.notify_all();
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&lock(&self.shared.0).bytes).into_owned()
    }

    /// The captured text once the stream ended, waiting at most `wait`.
    pub(crate) fn text_after_exit(&self, wait: Duration) -> String {
        let (mutex, condvar) = &*self.shared;
        let deadline = Instant::now() + wait;
        let mut buffer = lock(mutex);
        while !buffer.done {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            buffer = match condvar.wait_timeout(buffer, deadline - now) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        String::from_utf8_lossy(&buffer.bytes).into_owned()
    }
}

pub(super) fn wait_child_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(CHILD_POLL);
    }
}

pub(super) fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs a short command with null stdio; true on success within `timeout`.
pub(super) fn run_quick(mut command: Command, timeout: Duration) -> bool {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    match wait_child_until(&mut child, Instant::now() + timeout) {
        Some(status) => status.success(),
        None => {
            kill_and_reap(&mut child);
            false
        }
    }
}

pub(super) enum Reaped {
    Exited(ExitStatus),
    Killed,
    Missing,
}

/// Waits for the child in `slot` until `deadline`, then kills it.
pub(super) fn reap_slot(slot: &Mutex<Option<Child>>, deadline: Instant) -> Reaped {
    loop {
        {
            let mut guard = lock(slot);
            let Some(child) = guard.as_mut() else {
                return Reaped::Missing;
            };
            match child.try_wait() {
                Ok(Some(status)) => return Reaped::Exited(status),
                Ok(None) if Instant::now() < deadline => {}
                Ok(None) | Err(_) => {
                    kill_and_reap(child);
                    return Reaped::Killed;
                }
            }
        }
        thread::sleep(CHILD_POLL);
    }
}

pub(super) fn kill_slot(slot: &Mutex<Option<Child>>) {
    if let Some(child) = lock(slot).as_mut() {
        let _ = child.kill();
    }
}

/// Completion of the prewarm that follows a connected hello. API bridges do
/// not start the local server, so API streams that arrive right after the
/// link connected wait (bounded) for it instead of failing.
#[derive(Default)]
pub(crate) struct PrewarmGate {
    done: Mutex<bool>,
    finished: Condvar,
}

impl PrewarmGate {
    pub(crate) fn finish(&self) {
        *lock(&self.done) = true;
        self.finished.notify_all();
    }

    /// A guard that finishes the gate when dropped, so waiters are released
    /// even if the prewarm thread panics.
    pub(crate) fn finish_on_drop(self: Arc<Self>) -> PrewarmFinisher {
        PrewarmFinisher(self)
    }

    /// Waits until [`Self::finish`] or `timeout`; true when finished.
    pub(crate) fn wait(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut done = lock(&self.done);
        while !*done {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            done = match self.finished.wait_timeout(done, deadline - now) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        true
    }
}

/// Finishes its [`PrewarmGate`] on drop.
pub(crate) struct PrewarmFinisher(Arc<PrewarmGate>);

impl Drop for PrewarmFinisher {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// Runs the bridge once per session with null stdio so the local server is
/// started (the bridge owns daemon startup) before the hub connects.
pub(super) fn prewarm_sessions(
    exe: &Path,
    sessions: &[String],
    agent_socket: Option<&Path>,
    shutdown: &AtomicBool,
) {
    let mut seen = Vec::new();
    for session in sessions {
        if seen.len() >= MAX_PREWARM_SESSIONS || seen.contains(session) {
            continue;
        }
        if crate::session::validate_name(session).is_err() {
            tracing::warn!(
                session = %sanitize_remote_text(session, 64),
                "dial ignored an invalid prewarm session"
            );
            continue;
        }
        seen.push(session.clone());
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let Some(mut command) = bridge_command(exe, StreamKind::Client, session, agent_socket)
        else {
            continue;
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                tracing::warn!(%error, %session, "dial could not start the prewarm bridge");
                continue;
            }
        };
        let stderr = StderrTail::capture(child.stderr.take());
        match wait_child_until(&mut child, Instant::now() + PREWARM_TIMEOUT) {
            Some(status) if status.success() => {
                tracing::info!(%session, "dial prewarmed the local herdr server");
            }
            Some(status) => {
                let detail = remote_text_tail(&stderr.text_after_exit(STDERR_SETTLE));
                tracing::warn!(%session, %status, %detail, "dial prewarm bridge failed");
                super::stderr_line(format_args!(
                    "herdr dial: preparing session '{session}' failed: {detail}"
                ));
            }
            None => {
                kill_and_reap(&mut child);
                tracing::warn!(%session, "dial prewarm bridge timed out");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::link::protocol;
    use crate::remote::link::MAX_PREAMBLE_BYTES;
    use std::io::Cursor;

    #[test]
    fn prewarm_gate_releases_waiters_once_finished() {
        let gate = Arc::new(PrewarmGate::default());
        assert!(!gate.wait(Duration::from_millis(10)));
        let finisher = Arc::clone(&gate);
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            finisher.finish();
        });
        assert!(gate.wait(Duration::from_secs(5)));
        thread.join().unwrap();
        assert!(gate.wait(Duration::ZERO));
    }

    #[test]
    fn prewarm_gate_is_released_when_the_prewarm_thread_panics() {
        let gate = Arc::new(PrewarmGate::default());
        let finisher = Arc::clone(&gate).finish_on_drop();
        let thread = thread::spawn(move || {
            let _finisher = finisher;
            panic!("prewarm failed");
        });
        assert!(thread.join().is_err());
        assert!(gate.wait(Duration::ZERO));
    }

    #[test]
    fn bridge_child_command_omits_default_session_and_cleans_env() {
        assert_eq!(
            bridge_args(StreamKind::Client, crate::session::DEFAULT_SESSION_NAME).unwrap(),
            ["remote-client-bridge"]
        );
        assert_eq!(
            bridge_args(StreamKind::Api, "work").unwrap(),
            ["--session", "work", "remote-api-bridge"]
        );
        assert_eq!(bridge_args(StreamKind::Unknown, "work"), None);
        assert_eq!(bridge_args(StreamKind::Update, "work"), None);

        let command = bridge_command(
            Path::new("/opt/herdr/bin/herdr"),
            StreamKind::Client,
            "dev",
            None,
        )
        .unwrap();
        assert_eq!(command.get_program(), "/opt/herdr/bin/herdr");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["--session", "dev", "remote-client-bridge"]
        );
        let removed = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for name in CLEARED_CHILD_ENV {
            assert!(removed.contains(&name.to_string()), "{name} not removed");
        }
        assert!(removed.contains(&"HERDR_SESSION".to_string()));
        assert!(!command.get_envs().any(|(name, _)| name == "SSH_AUTH_SOCK"));
        assert!(bridge_command(Path::new("/x"), StreamKind::Unknown, "dev", None).is_none());
        let relayed = bridge_command(
            Path::new("/x"),
            StreamKind::Api,
            "dev",
            Some(Path::new("/d/agent.sock")),
        )
        .unwrap();
        assert!(relayed
            .get_envs()
            .any(|env| env == ("SSH_AUTH_SOCK".as_ref(), Some("/d/agent.sock".as_ref()))));
    }

    /// A writer that records each write call.
    #[derive(Default)]
    struct Recorder {
        bytes: Vec<u8>,
    }

    impl Write for Recorder {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pump_forwards_leftover_post_marker_bytes_first() {
        let mut wire = b"shell noise\n".to_vec();
        protocol::write_marker(&mut wire).unwrap();
        wire.extend_from_slice(b"FIRST-");
        let mut reader = Cursor::new(wire);
        let leftover = protocol::discard_until_marker(&mut reader, MAX_PREAMBLE_BYTES).unwrap();
        // A small cursor delivers everything in one read, so the post-marker
        // bytes arrive as leftover.
        assert_eq!(leftover, b"FIRST-");

        let rest = vec![b'x'; PUMP_BUFFER_BYTES * 2 + 17];
        let mut sink = Recorder::default();
        let total = pump(&mut Cursor::new(rest.clone()), &mut sink, &leftover).unwrap();
        assert_eq!(total, (leftover.len() + rest.len()) as u64);
        let mut expected = leftover.clone();
        expected.extend_from_slice(&rest);
        assert_eq!(sink.bytes, expected);

        let mut sink = Recorder::default();
        assert_eq!(
            pump(&mut Cursor::new(Vec::new()), &mut sink, &[]).unwrap(),
            0
        );
        assert!(sink.bytes.is_empty());
    }

    #[test]
    fn stderr_tail_keeps_only_the_last_bytes() {
        let mut input = vec![b'a'; STDERR_TAIL_BYTES * 3];
        input.extend_from_slice(b"\nPermission denied (publickey).\n");
        let tail = StderrTail::capture(Some(Cursor::new(input)));
        let text = tail.text_after_exit(Duration::from_secs(5));
        assert!(text.len() <= STDERR_TAIL_BYTES);
        assert!(text.ends_with("Permission denied (publickey).\n"));
        assert_eq!(
            remote_text_tail("one\n\ntwo\nthree\nfour\n"),
            "two | three | four"
        );
        assert_eq!(
            StderrTail::capture(None::<Cursor<Vec<u8>>>).text_after_exit(Duration::ZERO),
            ""
        );
    }
}
