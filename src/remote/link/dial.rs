//! Slave-side dialer for dial-in links (`herdr machine dial run`).
//!
//! One attempt of the link:
//!
//! 1. Start an OpenSSH master (`ssh -M -N`) to the hub and wait until
//!    `ssh -O check` reports it ready ([`pool`]).
//! 2. Open the control session over the master (`herdr link-accept ... --mode
//!    control` on the hub), discard any shell noise up to the acceptor's ready
//!    marker, exchange hellos, and prewarm the sessions the hub asked for
//!    ([`control`], [`process`]).
//! 3. Serve the control loop: answer pings, ping when idle, declare the link
//!    dead when nothing arrives, and for every `Open` start a new stream
//!    session over the master (`--mode stream --nonce N`) piped into a local
//!    `remote-client-bridge` / `remote-api-bridge` child ([`streams`]).
//! 4. On link death or a shutdown signal, tear everything down and retry with
//!    backoff ([`failure`]).
//!
//! The dialer stops or restarts the local Herdr server only when the hub
//! asks it to ([`update`]). When asked to, or when its executable on disk was
//! replaced ([`reexec`]), it replaces itself with a fresh copy of its own
//! executable once the current attempt is torn down. On start it stops ssh
//! masters that a killed earlier run left behind ([`pool`]).

mod agent;
mod control;
mod failure;
mod pool;
mod process;
mod reexec;
mod ssh;
mod streams;
mod update;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use self::agent::{AgentRelay, AgentSessions};
use self::control::{run_control_session, LinkEnd, LoopTiming};
use self::failure::{failure_code, Backoff, LinkFailure};
use self::pool::{stop_orphan_masters, Master, MasterPids, MasterPool};
use self::process::{kill_and_reap, prewarm_sessions, PrewarmGate, StderrTail, STDERR_SETTLE};
use self::reexec::{BinaryWatch, Reexec, ReexecRequest, BINARY_CHECK_INTERVAL};
use self::ssh::{DialTools, SshArgs};
use self::streams::{SshStreamOpener, StreamRegistry};
use super::dial_config::{self, ControlSockets, DialConfig, DialPaths, DialRunState, DialState};
use super::protocol::{error_code, Hello};
use super::status::{now_ms, sanitize_remote_text, ErrorRecord, SlaveInfo, MAX_REMOTE_TEXT_BYTES};

/// On teardown, how long bridge children get to exit after their streams close.
pub(crate) const TEARDOWN_GRACE: Duration = Duration::from_secs(2);

/// Upper bound on one blocking wait, so a shutdown request is noticed promptly.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

/// Locks `mutex`, recovering the data if a panicking thread poisoned it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Writes one state line to stderr. The dialer runs for a long time and its
/// stderr may be a pipe or terminal that goes away (`| tee`, a closed
/// terminal); unlike `eprintln!`, a failed write is dropped instead of
/// panicking the supervisor or one of its threads.
pub(super) fn stderr_line(line: std::fmt::Arguments<'_>) {
    write_line_ignoring_errors(&mut io::stderr().lock(), line);
}

/// Reports a state line of dial `name` to the log and stderr.
fn report_line(name: &str, line: &str) {
    tracing::info!(dial = %name, "{line}");
    stderr_line(format_args!("herdr dial {name}: {line}"));
}

fn write_line_ignoring_errors(writer: &mut impl Write, line: std::fmt::Arguments<'_>) {
    let _ = writer
        .write_fmt(line)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush());
}

/// The result of one link attempt.
struct Attempt {
    connected_at: Option<Instant>,
    end: LinkEnd,
}

/// The `herdr machine dial run` supervisor.
pub(crate) struct Dialer {
    config: DialConfig,
    paths: DialPaths,
    tools: DialTools,
    ssh: SshArgs,
    sockets: ControlSockets,
    shutdown: Arc<AtomicBool>,
    master_pids: MasterPids,
    timing: LoopTiming,
    reexec: ReexecRequest,
    binary: Arc<BinaryWatch>,
    probation: update::Probation,
}

impl Dialer {
    pub(crate) fn new(
        config: DialConfig,
        paths: DialPaths,
        tools: DialTools,
        sockets: ControlSockets,
        shutdown: Arc<AtomicBool>,
        master_pids: MasterPids,
    ) -> Self {
        let ssh = SshArgs::from_config(&config);
        let reexec = ReexecRequest::new(Arc::clone(&shutdown));
        let binary = Arc::new(BinaryWatch::new(reexec::restart_executable(&tools.exe)));
        update::remove_stale_update_files(&tools.exe);
        let probation = update::Probation::start(&tools.exe, &paths.dir, reexec.clone());
        Self {
            config,
            paths,
            tools,
            ssh,
            sockets,
            shutdown,
            master_pids,
            timing: LoopTiming::default(),
            reexec,
            binary,
            probation,
        }
    }

    /// A handle that asks this dialer to re-exec itself (see [`reexec`]).
    pub(crate) fn reexec_request(&self) -> ReexecRequest {
        self.reexec.clone()
    }

    fn report(&self, line: &str) {
        report_line(&self.config.name, line);
    }

    fn write_state(&self, state: &DialState) {
        if let Err(error) = dial_config::write_state(&self.paths.state_file, state) {
            tracing::warn!(%error, "dial could not write its state file");
        }
    }

    fn shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Reconnects with backoff until shutdown is requested.
    pub(crate) fn run(&self) -> io::Result<()> {
        let mut backoff = Backoff::default();
        // A rollback note, or the failure carried over from a previous run
        // (or re-exec), so the hub hears why that one failed.
        let mut last_error = update::rolled_back_error().or_else(|| {
            dial_config::read_state(&self.paths.state_file)
                .ok()
                .flatten()
                .and_then(|state| state.last_error)
        });
        let mut last_hint_code: Option<String> = None;
        self.report(&format!(
            "dialing {} for link {}",
            self.config.hub, self.config.link_id
        ));
        let leftovers = ControlSockets::all_for_dial(&self.paths);
        let stopped = stop_orphan_masters(&self.tools, &self.ssh, &leftovers);
        if stopped > 0 {
            self.report(&format!(
                "stopped {stopped} ssh master connection(s) left by an earlier run"
            ));
        }
        let name = self.config.name.clone();
        BinaryWatch::spawn(
            Arc::downgrade(&self.binary),
            self.reexec.clone(),
            BINARY_CHECK_INTERVAL,
            move |line| report_line(&name, line),
        );
        loop {
            self.run_attempts(&mut backoff, &mut last_error, &mut last_hint_code);
            let Some(reexec) = self.reexec.take() else {
                break;
            };
            self.reexec_now(&reexec);
            // The re-exec did not happen: keep serving the link.
            self.shutdown.store(false, Ordering::SeqCst);
        }
        let mut state = DialState::new(DialRunState::Stopped);
        state.last_error = last_error;
        self.write_state(&state);
        self.report("stopped");
        Ok(())
    }

    /// Reconnects with backoff until shutdown (or a re-exec) is requested.
    fn run_attempts(
        &self,
        backoff: &mut Backoff,
        last_error: &mut Option<ErrorRecord>,
        last_hint_code: &mut Option<String>,
    ) {
        loop {
            if let Some(line) = self.binary.check(&self.reexec) {
                self.report(&line);
            }
            if self.shutting_down() {
                break;
            }
            let mut state = DialState::new(DialRunState::Connecting);
            state.last_error = last_error.clone();
            self.write_state(&state);

            let attempt = self.attempt(last_error.as_ref().map(dial_error_text));
            if attempt.connected_at.is_some() {
                // The hub heard it in this link's hello: later hellos, and
                // the next run, report only newer failures.
                *last_error = None;
            }
            let failure = match attempt.end {
                LinkEnd::Shutdown => break,
                LinkEnd::Failed(_) if self.shutting_down() => break,
                LinkEnd::Failed(failure) => failure,
            };
            let delay = backoff.delay_after(&failure, attempt.connected_at.map(|at| at.elapsed()));
            let record = ErrorRecord::new(&failure.code, &failure.message);
            let mut state = DialState::new(DialRunState::Backoff);
            state.last_error = Some(record.clone());
            state.next_attempt_ms =
                Some(now_ms().saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)));
            self.write_state(&state);
            *last_error = Some(record);
            self.report(&format!(
                "disconnected: {failure}; retrying in {}s",
                delay.as_secs()
            ));
            if last_hint_code.as_deref() != Some(failure.code.as_str()) {
                if let Some(hint) = self.hint(&failure) {
                    stderr_line(format_args!("hint: {hint}"));
                }
                *last_hint_code = Some(failure.code.clone());
            }
            self.sleep(delay);
        }
    }

    /// Execs a fresh copy of this dialer with the same arguments once it
    /// passes `--version`. Returns only when the re-exec did not happen.
    fn reexec_now(&self, reexec: &Reexec) {
        self.report(&format!("restarting ({})", reexec.reason));
        let exe = reexec::restart_executable(&self.tools.exe);
        if !reexec::self_test(&exe) {
            self.report(&format!(
                "not restarting: `{} --version` failed",
                exe.display()
            ));
            return;
        }
        let Ok(args) = std::env::args_os()
            .skip(1)
            .map(std::ffi::OsString::into_string)
            .collect::<Result<Vec<_>, _>>()
        else {
            self.report("not restarting: the command line is not valid UTF-8");
            return;
        };
        let error = crate::platform::reexec_process(&exe, &args, &update::reexec_env(&reexec.env));
        self.report(&format!(
            "not restarting: exec {} failed: {error}",
            exe.display()
        ));
    }

    fn hint(&self, failure: &LinkFailure) -> Option<String> {
        let hub = &self.config.hub;
        let id = &self.config.link_id;
        Some(match failure.code.as_str() {
            failure_code::AUTHENTICATION_FAILED => {
                let public_key = self
                    .config
                    .identity_file
                    .as_deref()
                    .and_then(dial_config::read_public_key_line)
                    .map(|key| format!("'{}'", key.replace('\'', "'\\''")))
                    .unwrap_or_else(|| "'<public key>'".to_string());
                format!(
                    "the hub refused this machine's key; on the hub run `herdr machine authorize {id} {public_key} --write`, or re-pair from here with `herdr machine dial setup {} --hub {hub} --pair` (a new machine on the hub) and restart this dialer",
                    self.config.name
                )
            }
            failure_code::HOST_KEY_UNVERIFIED => format!(
                "the hub's host key is not trusted yet; verify and accept it once with `ssh {hub} true`"
            ),
            error_code::LINK_UNKNOWN => format!(
                "the hub has no dial-in machine {id}; check `herdr machine list` on the hub"
            ),
            error_code::LINK_DISABLED => {
                "this machine is disabled on the hub; enable it there with `herdr machine enable`"
                    .to_string()
            }
            error_code::LINK_BUSY => {
                "another dialer is connected for this link; stop it before running this one"
                    .to_string()
            }
            error_code::LINK_VERSION_UNSUPPORTED => {
                "this machine and the hub run incompatible Herdr versions; update the older one"
                    .to_string()
            }
            _ => return None,
        })
    }

    fn sleep(&self, delay: Duration) {
        let deadline = Instant::now() + delay;
        while !self.shutting_down() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            thread::sleep(remaining.min(SHUTDOWN_POLL));
        }
    }

    /// One link attempt; `dial_error` is the previous failure, reported to the hub.
    fn attempt(&self, dial_error: Option<String>) -> Attempt {
        let pool = Arc::new(MasterPool::new(
            self.tools.clone(),
            self.ssh.clone(),
            self.sockets.clone(),
            Arc::clone(&self.shutdown),
            self.master_pids.clone(),
        ));
        let registry = Arc::new(StreamRegistry::default());
        let sessions = AgentSessions {
            tools: self.tools.clone(),
            ssh: self.ssh.clone(),
            link_id: self.config.link_id.clone(),
            pool: Arc::clone(&pool),
            timing: self.timing,
        };
        let agent = Arc::new(AgentRelay::new(
            self.sockets.agent_socket(),
            sessions.into_serve(),
        ));
        // Runs on return and on unwind, so an unexpected panic never leaves an
        // authenticated master connection to the hub behind.
        let _teardown = AttemptTeardown {
            pool: Arc::clone(&pool),
            registry: Arc::clone(&registry),
            agent: Arc::clone(&agent),
        };
        match pool.start_first() {
            Ok(master) => self.control_session(&pool, &master, &registry, &agent, dial_error),
            Err(failure) => Attempt {
                connected_at: None,
                end: LinkEnd::Failed(failure),
            },
        }
    }

    fn control_session(
        &self,
        pool: &Arc<MasterPool>,
        master: &Master,
        registry: &Arc<StreamRegistry>,
        agent: &Arc<AgentRelay>,
        dial_error: Option<String>,
    ) -> Attempt {
        let failed = |failure| Attempt {
            connected_at: None,
            end: LinkEnd::Failed(failure),
        };
        let args = match self.ssh.control(&master.ctl, &self.config.link_id) {
            Ok(args) => args,
            Err(error) => {
                return failed(LinkFailure::new(
                    failure_code::LOCAL_ERROR,
                    format!("cannot build the control ssh command: {error}"),
                ))
            }
        };
        let mut child = match self
            .tools
            .ssh_command(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => ReapOnDrop(child),
            Err(error) => {
                return failed(LinkFailure::new(
                    failure_code::SSH_FAILED,
                    format!("failed to run ssh: {error}"),
                ))
            }
        };
        let stderr = StderrTail::capture(child.0.stderr.take());
        let (Some(stdin), Some(stdout)) = (child.0.stdin.take(), child.0.stdout.take()) else {
            return failed(LinkFailure::new(
                failure_code::LOCAL_ERROR,
                "ssh stdio was not captured",
            ));
        };
        let prewarm = Arc::new(PrewarmGate::default());
        let opener = SshStreamOpener {
            tools: self.tools.clone(),
            ssh: self.ssh.clone(),
            dial_name: self.config.name.clone(),
            link_id: self.config.link_id.clone(),
            pool: Arc::clone(pool),
            registry: Arc::clone(registry),
            timing: self.timing,
            prewarm: Arc::clone(&prewarm),
            agent: Arc::clone(agent),
            reexec: self.reexec_request(),
            probation_file: self.probation.file().to_path_buf(),
        };
        let mut connected_at = None;
        let end = run_control_session(
            stdout,
            stdin,
            &self.config.link_id,
            dial_error,
            &opener,
            &self.shutdown,
            self.timing,
            || {
                let _ = child.0.kill();
            },
            |hello| {
                connected_at = Some(Instant::now());
                agent.set_enabled(hello.agent_forwarding);
                self.on_connected(hello, prewarm, agent.socket());
            },
        );
        kill_and_reap(&mut child.0);
        let end = match end {
            LinkEnd::Failed(failure)
                if matches!(
                    failure.code.as_str(),
                    failure_code::LINK_LOST | failure_code::PREAMBLE_FAILED
                ) =>
            {
                LinkEnd::Failed(failure.with_detail(&stderr.text_after_exit(STDERR_SETTLE)))
            }
            end => end,
        };
        Attempt { connected_at, end }
    }

    fn on_connected(&self, hello: &Hello, prewarm: Arc<PrewarmGate>, agent: Option<PathBuf>) {
        self.probation.connected();
        let hub = SlaveInfo::from_hello(hello);
        let mut state = DialState::new(DialRunState::Connected);
        state.hub = Some(hub.clone());
        self.write_state(&state);
        let mut line = format!("connected to {}", self.config.hub);
        if let Some(version) = &hub.herdr_version {
            line.push_str(&format!(" (hub herdr {version})"));
        }
        self.report(&line);

        let exe = self.tools.exe.clone();
        let sessions = hello.sessions.clone();
        let shutdown = Arc::clone(&self.shutdown);
        if sessions.is_empty() {
            prewarm.finish();
            return;
        }
        // Dropping the finisher (also if spawning fails or the thread
        // panics) releases API streams waiting for the prewarm.
        let finished = Arc::clone(&prewarm).finish_on_drop();
        let spawned = thread::Builder::new()
            .name("herdr-dial-prewarm".into())
            .spawn(move || {
                let _finished = finished;
                prewarm_sessions(&exe, &sessions, agent.as_deref(), &shutdown);
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "dial could not start the prewarm thread");
        }
    }
}

/// How this dialer describes its latest failure in its hello (`last_dial_error`).
fn dial_error_text(record: &ErrorRecord) -> String {
    sanitize_remote_text(
        &format!("{} ({})", record.message, record.code),
        MAX_REMOTE_TEXT_BYTES,
    )
}

/// Tears one link attempt down when dropped: the agent relay socket, stream
/// sessions and bridges, then the masters (`ssh -O exit`, kill, control
/// sockets).
struct AttemptTeardown {
    pool: Arc<MasterPool>,
    registry: Arc<StreamRegistry>,
    agent: Arc<AgentRelay>,
}

impl Drop for AttemptTeardown {
    fn drop(&mut self) {
        self.agent.close();
        self.registry.shutdown(TEARDOWN_GRACE);
        self.pool.shutdown();
    }
}

/// Kills and reaps the control ssh session when dropped.
struct ReapOnDrop(Child);

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        kill_and_reap(&mut self.0);
    }
}

/// Sets `shutdown` on Ctrl-C / SIGTERM / SIGHUP. A second signal exits now,
/// after killing the ssh masters: they run with null stdin and `-N`, so they
/// would otherwise outlive the dialer and keep their hub sessions open.
fn install_shutdown_handler(shutdown: Arc<AtomicBool>, masters: MasterPids) {
    let result = ctrlc::set_handler(move || {
        if shutdown.swap(true, Ordering::SeqCst) {
            masters.kill_all();
            std::process::exit(130);
        }
    });
    if let Err(error) = result {
        tracing::warn!(%error, "dial could not install its signal handler");
    }
}

/// `herdr machine dial run <name>`: runs the dialer in the foreground until
/// a shutdown signal. Fails if another dialer runs for the same name.
pub(crate) fn run_foreground(paths: &DialPaths, config: DialConfig) -> io::Result<()> {
    // Every stream holds several descriptors, and launchd agents and macOS
    // shells start with a soft limit of 256 (a no-op on other platforms).
    crate::platform::raise_server_nofile_limit();
    crate::platform::verify_private_directory(&paths.dir)?;
    let Some(run_lock) = crate::platform::try_lock_exclusive(&paths.lock_file)? else {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "a dialer for '{}' is already running on this machine",
                config.name
            ),
        ));
    };
    if let Err(error) = run_lock.record_pid() {
        tracing::debug!(%error, "dial could not record its pid");
    }
    let exe = crate::platform::launch_executable()?;
    let sockets = ControlSockets::for_dial(paths)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let master_pids = MasterPids::default();
    install_shutdown_handler(Arc::clone(&shutdown), master_pids.clone());
    let dialer = Dialer::new(
        config,
        paths.clone(),
        DialTools::new(exe),
        sockets,
        shutdown,
        master_pids,
    );
    let result = dialer.run();
    drop(run_lock);
    result
}

/// Whether a dialer currently holds the run lock for `paths`.
pub(crate) fn dialer_is_running(paths: &DialPaths) -> io::Result<bool> {
    match crate::platform::try_lock_exclusive(&paths.lock_file) {
        Ok(Some(_probe)) => Ok(false),
        Ok(None) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stderr that went away: every write fails.
    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn state_lines_tolerate_a_closed_stderr() {
        write_line_ignoring_errors(&mut BrokenPipe, format_args!("disconnected: {}", 1));
        let mut buffer = Vec::new();
        write_line_ignoring_errors(&mut buffer, format_args!("herdr dial {}: up", "work"));
        assert_eq!(buffer, b"herdr dial work: up\n");
    }
}
