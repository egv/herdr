//! Hub-side acceptor for dial-in links (`herdr link-accept`).
//!
//! sshd runs the acceptor under the forced command printed by
//! `herdr machine authorize`, once per SSH session the dialer opens:
//!
//! - **Control mode** (one per link): validates the dialer hello against the
//!   hub catalog, takes the per-link lock (asking a previous holder to yield
//!   when its dialer no longer answers), binds `link.sock`, `client.sock` and
//!   `api.sock`, and serves until the link ends. Every hub connection to
//!   `client.sock`/`api.sock` becomes a pending open: the dialer is asked over
//!   the control channel to start a stream session for its nonce.
//! - **Stream mode** (one per hub connection): attaches to the pending
//!   connection through `link.sock` and pumps raw bytes between its stdio and
//!   that connection.
//!
//! Everything is plain `std` threads: one control reader, one control writer,
//! one blocking accept thread per listener, and two copy threads per relay.

mod agent;
mod claim;
mod relay;
mod sockets;
#[cfg(all(test, unix))]
mod tests;
pub(crate) mod update;

pub(crate) use agent::lease_agent;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::traits::Stream as _;

use super::protocol::{
    self, error_code, local_code, open_failed_code, ControlMessage, ControlReader, Hello,
    HelloRole, LinkError, LocalRequest, LocalResponse, OpenFailed, OpenRequest, RequestedMode,
    StreamKind,
};
use super::status::{self, ErrorRecord, LinkState, LinkStatus, SlaveInfo, MAX_REMOTE_TEXT_BYTES};
use super::{
    LinkPaths, HELLO_DEADLINE, LINK_DEAD_AFTER, LINK_VERSION_MAX, LINK_VERSION_MIN, LOCK_WAIT,
    MAX_ACTIVE_STREAMS, MAX_PENDING_OPENS, OPEN_TIMEOUT, PING_IDLE, SUPERSEDE_PROBE,
};
use crate::client::endpoint::{dial_in_catalog_path, DialInCatalog, DialInMachine, ProfileId};
use crate::ipc::LocalStream;
/// Shared with `herdr link-connect`, which pumps its stdio the same way.
pub(super) use relay::pump_stdio;
use relay::{serve_stream, ActiveRelay, HolderRefused};
use sockets::{respond, LinkSockets};

const CATALOG_RECHECK: Duration = Duration::from_secs(5);
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_COALESCE: Duration = Duration::from_secs(1);
const LOCK_POLL: Duration = Duration::from_millis(100);
const WRITER_DRAIN: Duration = Duration::from_secs(1);
const MAX_LOGGED_COMMAND_BYTES: usize = 160;
const MAX_SUPERSEDE_WAITERS: usize = 16;
/// Control messages queued for the writer thread before the link ends.
const WRITER_QUEUE: usize = 256;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Hub-side failures (link directory, lock file, sockets) are reported as
/// `shutting_down` so the dialer retries with its normal backoff.
const HUB_UNAVAILABLE: &str = error_code::SHUTTING_DOWN;

/// `status.json` `last_error` codes for link ends that are not protocol errors.
mod end_code {
    pub(super) const LINK_CLOSED: &str = "link_closed";
    pub(super) const LINK_DEAD: &str = "link_dead";
    pub(super) const SUPERSEDED: &str = "superseded";
    pub(super) const CONTROL_FAILED: &str = "control_failed";
    pub(super) const ACCEPTOR_STOPPED: &str = "acceptor_stopped";
}

/// Checks that a connected local stream belongs to the effective user.
pub(super) type PeerCheck = fn(&LocalStream) -> io::Result<bool>;

/// Runs `herdr link-accept [--catalog <path>] --link <id> [--mode control|stream] [--nonce <hex>]`.
///
/// Without `--mode` (the forced-command case) the mode and nonce come from
/// `SSH_ORIGINAL_COMMAND`; argv stays the identity authority.
pub(crate) fn run(args: &[String]) -> io::Result<()> {
    let original_command = std::env::var("SSH_ORIGINAL_COMMAND").ok();
    let invocation = match parse_invocation(args, original_command.as_deref()) {
        Ok(invocation) => invocation,
        Err(message) => {
            stderr_line(format_args!("herdr link-accept: {message}"));
            std::process::exit(2);
        }
    };
    match invocation.mode.clone() {
        RequestedMode::Control => run_control(invocation),
        RequestedMode::Stream { nonce } => run_stream(&invocation, &nonce),
        RequestedMode::Agent => agent::run_agent(&invocation),
    }
}

fn run_control(invocation: Invocation) -> io::Result<()> {
    crate::logging::init_file_logging(&format!(
        "herdr-link-{}.log",
        super::link_dir_name(&invocation.link_id)
    ));
    let mut output = crate::platform::take_stdout_unbuffered()?;
    if invocation.link_mismatch {
        let refused = Refused::new(
            error_code::LINK_ID_MISMATCH,
            "the requested link id does not match the link id this key is authorized for",
        );
        let _ = protocol::write_marker(&mut output).and_then(|()| {
            protocol::write_control_message(
                &mut output,
                &ControlMessage::Error(refused.link_error()),
            )
        });
        exit_refused(&refused);
    }
    let mut options = ControlOptions::new(invocation.catalog, invocation.link_id);
    options.peer_addr = claim::peer_addr(std::env::var("SSH_CONNECTION").ok().as_deref());
    let (events_tx, events) = mpsc::channel();
    install_termination_handler(events_tx.clone());
    match serve_control_with_events(&options, io::stdin(), output, (events_tx, events)) {
        Ok(end) => {
            tracing::info!(link = %options.link_id, end = ?end, "dial-in link ended");
            Ok(())
        }
        Err(refused) => exit_refused(&refused),
    }
}

/// On SIGTERM / SIGINT / SIGHUP (for example the hub shutting down), ends
/// the link through the holder loop so `status.json` says disconnected and
/// the socket files are removed. A second signal exits at once.
fn install_termination_handler(events: Sender<Event>) {
    let signalled = AtomicBool::new(false);
    let result = ctrlc::set_handler(move || {
        if signalled.swap(true, Ordering::SeqCst) {
            std::process::exit(143);
        }
        let _ = events.send(Event::Terminate);
    });
    if let Err(error) = result {
        tracing::warn!("failed to install the link acceptor signal handler: {error}");
    }
}

fn run_stream(invocation: &Invocation, nonce: &str) -> io::Result<()> {
    if invocation.link_mismatch {
        stderr_line(format_args!(
            "herdr link-accept: the requested link id does not match the link id this key is authorized for"
        ));
        std::process::exit(1);
    }
    let output = crate::platform::take_stdout_unbuffered()?;
    let paths = LinkPaths::for_catalog(&invocation.catalog, &invocation.link_id);
    let result = serve_stream(
        &paths,
        nonce,
        crate::platform::local_stream_peer_is_current_user,
        LOCAL_REQUEST_TIMEOUT,
        io::stdin(),
        output,
    );
    if let Err(error) = result {
        // Stream sessions log only when they fail, to the link's log.
        crate::logging::init_file_logging(&format!(
            "herdr-link-{}.log",
            super::link_dir_name(&invocation.link_id)
        ));
        tracing::warn!(link = %invocation.link_id, "dial-in stream session failed: {error}");
        stderr_line(format_args!(
            "herdr link-accept: {}",
            stream_failure_message(&error)
        ));
        std::process::exit(1);
    }
    Ok(())
}

/// What a failed stream session tells the dialing machine (through ssh
/// stderr): the reason, without hub paths or OS details.
fn stream_failure_message(error: &io::Error) -> String {
    if let Some(refused) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<HolderRefused>())
    {
        return refused.to_string();
    }
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            "this machine has no active link on the hub".into()
        }
        io::ErrorKind::PermissionDenied => {
            "the hub refused the stream: this machine's link directory or socket on the hub is not private to the hub account".into()
        }
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            "the hub's link holder did not answer in time".into()
        }
        io::ErrorKind::InvalidInput => {
            "the hub cannot use this machine's link: its socket paths are too long".into()
        }
        _ => "the hub could not relay the stream".into(),
    }
}

fn exit_refused(refused: &Refused) -> ! {
    tracing::warn!(
        code = %refused.code,
        detail = refused.detail.as_deref().unwrap_or(""),
        "refused dial-in link: {}",
        refused.message
    );
    stderr_line(format_args!("herdr link-accept: {refused}"));
    std::process::exit(1);
}

/// Writes one line to stderr (forwarded by sshd to the dialing machine),
/// ignoring failures: the dialer may already be gone.
fn stderr_line(line: std::fmt::Arguments<'_>) {
    let mut stderr = io::stderr().lock();
    let _ = stderr
        .write_fmt(line)
        .and_then(|()| stderr.write_all(b"\n"));
}

/// A resolved `link-accept` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Invocation {
    pub(super) catalog: PathBuf,
    pub(super) link_id: ProfileId,
    pub(super) mode: RequestedMode,
    /// `SSH_ORIGINAL_COMMAND` named a different link than argv.
    pub(super) link_mismatch: bool,
}

/// Resolves argv (`--catalog`, `--link`, `--mode`, `--nonce`, each at most
/// once) and, when argv has no `--mode`, the dialer's requested command.
pub(super) fn parse_invocation(
    args: &[String],
    original_command: Option<&str>,
) -> Result<Invocation, String> {
    let mut catalog = None;
    let mut link = None;
    let mut mode = None;
    let mut nonce = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--catalog" => &mut catalog,
            "--link" => &mut link,
            "--mode" => &mut mode,
            "--nonce" => &mut nonce,
            other => {
                return Err(format!(
                    "unexpected argument '{}'",
                    status::sanitize_remote_text(other, MAX_LOGGED_COMMAND_BYTES)
                ))
            }
        };
        if slot.is_some() {
            return Err(format!("{flag} was given more than once"));
        }
        let Some(value) = args.next() else {
            return Err(format!("missing value for {flag}"));
        };
        *slot = Some(value.as_str());
    }
    let link_id = ProfileId::parse(link.ok_or("missing --link <machine id>")?)
        .map_err(|_| "--link must be a 32-character lowercase hex machine id".to_string())?;
    let catalog = match catalog {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("--catalog must be an absolute path".into());
            }
            path
        }
        None => dial_in_catalog_path(),
    };
    let (mode, link_mismatch) = match (mode, nonce) {
        (Some("control"), None) => (RequestedMode::Control, false),
        (Some("control"), Some(_)) => return Err("--nonce is only valid with --mode stream".into()),
        (Some("stream"), Some(nonce)) if protocol::is_valid_nonce(nonce) => (
            RequestedMode::Stream {
                nonce: nonce.to_string(),
            },
            false,
        ),
        (Some("stream"), Some(_)) => {
            return Err("--nonce must be 32 lowercase hexadecimal characters".into())
        }
        (Some("stream"), None) => return Err("--mode stream requires --nonce".into()),
        (Some("agent"), None) => (RequestedMode::Agent, false),
        (Some("agent"), Some(_)) => return Err("--nonce is only valid with --mode stream".into()),
        (Some(_), _) => return Err("--mode must be control, stream or agent".into()),
        (None, Some(_)) => return Err("--nonce is only valid with --mode stream".into()),
        (None, None) => {
            let command = original_command
                .ok_or("this key only runs `herdr link-accept`; no link command was requested")?;
            let requested = protocol::parse_requested_command(command).map_err(|error| {
                format!(
                    "{error}: {}",
                    status::sanitize_remote_text(command, MAX_LOGGED_COMMAND_BYTES)
                )
            })?;
            (requested.mode, requested.link_id != link_id)
        }
    };
    Ok(Invocation {
        catalog,
        link_id,
        mode,
        link_mismatch,
    })
}

/// Timeouts of one link holder; tests shorten them.
#[derive(Clone, Copy, Debug)]
pub(super) struct Timings {
    pub(super) hello_deadline: Duration,
    pub(super) ping_idle: Duration,
    pub(super) dead_after: Duration,
    pub(super) open_timeout: Duration,
    pub(super) supersede_probe: Duration,
    pub(super) lock_wait: Duration,
    pub(super) catalog_recheck: Duration,
    pub(super) local_request_timeout: Duration,
    pub(super) status_coalesce: Duration,
    pub(super) claim_clear_after: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            hello_deadline: HELLO_DEADLINE,
            ping_idle: PING_IDLE,
            dead_after: LINK_DEAD_AFTER,
            open_timeout: OPEN_TIMEOUT,
            supersede_probe: SUPERSEDE_PROBE,
            lock_wait: LOCK_WAIT,
            catalog_recheck: CATALOG_RECHECK,
            local_request_timeout: LOCAL_REQUEST_TIMEOUT,
            status_coalesce: STATUS_COALESCE,
            claim_clear_after: claim::CONFLICT_CLEAR_AFTER,
        }
    }
}

#[derive(Clone)]
pub(super) struct ControlOptions {
    pub(super) catalog_path: PathBuf,
    pub(super) link_id: ProfileId,
    pub(super) timings: Timings,
    pub(super) peer_check: PeerCheck,
    /// The dialer's address, from sshd's `SSH_CONNECTION`.
    pub(super) peer_addr: Option<String>,
}

impl ControlOptions {
    pub(super) fn new(catalog_path: PathBuf, link_id: ProfileId) -> Self {
        Self {
            catalog_path,
            link_id,
            timings: Timings::default(),
            peer_check: crate::platform::local_stream_peer_is_current_user,
            peer_addr: None,
        }
    }
}

/// Why the acceptor refused a dialer before the link was established. The
/// same code and message were sent to the dialer as a control `error`.
#[derive(Debug)]
pub(super) struct Refused {
    pub(super) code: String,
    /// Sent to the dialer and printed on stderr, which sshd forwards to the
    /// dialing machine: never hub paths or host details.
    pub(super) message: String,
    /// Hub-side specifics (paths, OS errors), logged on the hub only.
    pub(super) detail: Option<String>,
}

impl Refused {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            detail: None,
        }
    }

    pub(super) fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    fn link_error(&self) -> LinkError {
        LinkError::new(self.code.clone(), self.message.clone())
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} ({})", self.message, self.code)
    }
}

/// Why an established link ended.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LinkEnd {
    /// The dialer closed the control session.
    DialerClosed,
    /// Nothing arrived from the dialer for `dead_after`.
    Dead,
    /// A newer link for this machine asked to take over and the dialer did
    /// not answer the probe.
    Superseded,
    /// The machine was disabled or removed from the hub catalog.
    Disabled,
    /// The dialer reported an error.
    DialerError { code: String, message: String },
    /// The dialer sent an undecodable control message.
    ProtocolError(String),
    /// Reading or writing the control session failed.
    ControlFailed(String),
    /// The acceptor received a termination signal (SIGTERM, SIGINT, SIGHUP).
    Terminated,
}

impl LinkEnd {
    /// `(code, message)` recorded as `status.json` `last_error`.
    fn record(&self, timings: &Timings) -> (String, String) {
        let (code, message) = match self {
            Self::DialerClosed => (
                end_code::LINK_CLOSED,
                "the machine closed its control session".to_string(),
            ),
            Self::Dead => (
                end_code::LINK_DEAD,
                format!(
                    "no traffic from the machine for {}",
                    format_duration(timings.dead_after)
                ),
            ),
            Self::Superseded => (
                end_code::SUPERSEDED,
                "a newer link from the machine replaced this one".to_string(),
            ),
            Self::Disabled => (
                error_code::LINK_DISABLED,
                "the machine was disabled or removed on the hub".to_string(),
            ),
            Self::DialerError { code, message } => (code.as_str(), message.clone()),
            Self::ProtocolError(message) => (error_code::PROTOCOL_ERROR, message.clone()),
            Self::ControlFailed(message) => (end_code::CONTROL_FAILED, message.clone()),
            Self::Terminated => (
                end_code::ACCEPTOR_STOPPED,
                "the link acceptor on this hub was stopped".to_string(),
            ),
        };
        (code.to_string(), message)
    }

    /// The control `error` sent to the dialer before closing, if any.
    fn notice(&self) -> Option<LinkError> {
        match self {
            Self::Superseded => Some(LinkError::new(
                error_code::SHUTTING_DOWN,
                "a newer link from this machine replaced this one",
            )),
            Self::Disabled => Some(LinkError::new(
                error_code::LINK_DISABLED,
                "this machine was disabled or removed on the hub",
            )),
            Self::Dead => Some(LinkError::new(
                error_code::SHUTTING_DOWN,
                "the hub stopped hearing from this machine",
            )),
            Self::ProtocolError(message) => {
                Some(LinkError::new(error_code::PROTOCOL_ERROR, message.clone()))
            }
            Self::Terminated => Some(LinkError::new(
                error_code::SHUTTING_DOWN,
                "the hub is shutting this link down",
            )),
            Self::DialerClosed | Self::DialerError { .. } | Self::ControlFailed(_) => None,
        }
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.subsec_millis() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

enum Event {
    /// One result from the control reader; it stops after `Ok(None)` or `Err`.
    Control(io::Result<Option<ControlMessage>>),
    ControlWriteFailed(io::Error),
    /// A peer-checked hub connection to `client.sock` or `api.sock`.
    Opened {
        kind: StreamKind,
        stream: LocalStream,
    },
    /// A peer-checked request on `link.sock`; the response goes to `stream`.
    Local {
        request: LocalRequest,
        stream: LocalStream,
    },
    RelayFinished(u64),
    /// The `link.sock` connection of an agent lease closed.
    AgentLeaseEnded(u64),
    /// A termination signal: end the link and clean up.
    Terminate,
}

/// Serves one control session: validate, lock, bind, then hold the link
/// until it ends. Refusals are sent to the dialer before returning `Err`.
#[cfg(test)]
pub(super) fn serve_control<R, W>(
    options: &ControlOptions,
    input: R,
    output: W,
) -> Result<LinkEnd, Refused>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    serve_control_with_events(options, input, output, mpsc::channel())
}

/// [`serve_control`] on a caller-made event channel, so the caller can also
/// deliver [`Event::Terminate`].
fn serve_control_with_events<R, W>(
    options: &ControlOptions,
    input: R,
    mut output: W,
    (events_tx, events): (Sender<Event>, Receiver<Event>),
) -> Result<LinkEnd, Refused>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    // Printed before anything is read so the dialer can discard shell noise.
    protocol::write_marker(&mut output).map_err(|error| {
        Refused::new(
            end_code::CONTROL_FAILED,
            format!("failed to write the ready marker: {error}"),
        )
    })?;
    let mut writer = ControlWriter::spawn(output, events_tx.clone()).map_err(|error| {
        Refused::new(
            HUB_UNAVAILABLE,
            format!("failed to start the control writer: {error}"),
        )
    })?;
    if let Err(error) = spawn_control_reader(input, events_tx.clone()) {
        return Err(refuse(
            writer,
            Refused::new(
                HUB_UNAVAILABLE,
                format!("failed to start the control reader: {error}"),
            ),
        ));
    }
    let hello = match wait_for_hello(&events, options.timings.hello_deadline) {
        Ok(hello) => hello,
        Err(refused) => return Err(refuse(writer, refused)),
    };
    let machine = match validate_dialer(options, &hello) {
        Ok(machine) => machine,
        Err(refused) => return Err(refuse(writer, refused)),
    };
    let paths = LinkPaths::for_catalog(&options.catalog_path, &options.link_id);
    let (lock, superseded) = match acquire_link(&paths, options) {
        Ok(acquired) => acquired,
        Err(refused) => return Err(refuse(writer, refused)),
    };
    let sockets = match LinkSockets::bind(&paths, &events_tx, options) {
        Ok(sockets) => sockets,
        Err(refused) => {
            drop(lock);
            return Err(refuse(writer, refused));
        }
    };

    let previous = status::read_status(&paths.status_file).unwrap_or_else(|error| {
        tracing::warn!(
            path = %paths.status_file.display(),
            "ignoring unreadable link status: {error}"
        );
        None
    });
    let connected_at = status::now_ms();
    let mut link_status = LinkStatus {
        state: LinkState::Connected,
        link_epoch: previous
            .as_ref()
            .map_or(0, |previous| previous.link_epoch)
            .saturating_add(1),
        pid: Some(std::process::id()),
        updated_at_ms: connected_at,
        connected_since_ms: Some(connected_at),
        slave: Some(SlaveInfo::from_hello(&hello)),
        last_error: None,
        last_stream_error: previous
            .as_ref()
            .and_then(|previous| previous.last_stream_error.clone()),
        peer_addr: options.peer_addr.clone(),
        ..LinkStatus::default()
    };
    claim::note_claim(
        &mut link_status,
        previous.as_ref(),
        superseded,
        connected_at,
    );
    if let Some(conflict) = &link_status.claim_conflict {
        tracing::warn!(link = %options.link_id, "{conflict}");
    }
    writer.send(ControlMessage::Hello(acceptor_hello(
        &options.link_id,
        &machine,
    )));

    let now = Instant::now();
    let mut holder = LinkHolder {
        options,
        paths: &paths,
        machine,
        writer,
        events,
        events_tx,
        status: link_status,
        status_dirty: false,
        last_status_write: now,
        pending: HashMap::new(),
        relays: HashMap::new(),
        next_relay_id: 1,
        agent: agent::AgentLeases::default(),
        next_ping_seq: 1,
        last_received: now,
        probe: None,
        next_catalog_check: now + options.timings.catalog_recheck,
        last_claim_at: now,
        restarts: update::PendingRestarts::default(),
    };
    holder.write_status_now(now);
    tracing::info!(
        link = %options.link_id,
        epoch = holder.status.link_epoch,
        "dial-in link connected"
    );
    let end = holder.run();
    tracing::info!(link = %options.link_id, end = ?end, "dial-in link closing");
    holder.finish(&end, sockets, lock);
    Ok(end)
}

/// The acceptor's hello: link versions, Herdr and protocol versions, the
/// sessions to prewarm, and whether agent forwarding is on. Unlike the
/// dialer's, it does not describe the hub host (hostname, OS, architecture):
/// the dialing machine does not need it.
fn acceptor_hello(link_id: &ProfileId, machine: &DialInMachine) -> Hello {
    let mut hello = Hello::local(HelloRole::Acceptor, link_id.to_string());
    hello.os = None;
    hello.arch = None;
    hello.hostname = None;
    hello.sessions = vec![machine.session.clone()];
    hello.agent_forwarding = machine.agent_forwarding;
    hello
}

/// Sends the refusal to the dialer and waits (bounded) for it to be written.
fn refuse(mut writer: ControlWriter, refused: Refused) -> Refused {
    writer.send(ControlMessage::Error(refused.link_error()));
    writer.finish(WRITER_DRAIN);
    refused
}

fn wait_for_hello(events: &Receiver<Event>, deadline: Duration) -> Result<Hello, Refused> {
    let until = Instant::now() + deadline;
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        let event = match events.recv_timeout(remaining) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                return Err(Refused::new(
                    error_code::PROTOCOL_ERROR,
                    format!(
                        "timed out after {} waiting for the dialer hello",
                        format_duration(deadline)
                    ),
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Refused::new(
                    end_code::CONTROL_FAILED,
                    "the control reader stopped before the dialer hello",
                ))
            }
        };
        match event {
            Event::Control(Ok(Some(ControlMessage::Hello(hello)))) => return Ok(hello),
            Event::Control(Ok(Some(ControlMessage::Unknown))) => {}
            Event::Control(Ok(Some(_))) => {
                return Err(Refused::new(
                    error_code::PROTOCOL_ERROR,
                    "the dialer must send its hello first",
                ))
            }
            Event::Control(Ok(None)) => {
                return Err(Refused::new(
                    end_code::LINK_CLOSED,
                    "the dialer closed the control session before its hello",
                ))
            }
            Event::Control(Err(error)) => {
                return Err(Refused::new(
                    error_code::PROTOCOL_ERROR,
                    format!("invalid control message from the dialer: {error}"),
                ))
            }
            Event::ControlWriteFailed(error) => {
                return Err(Refused::new(
                    end_code::CONTROL_FAILED,
                    format!("failed to write to the control session: {error}"),
                ))
            }
            Event::Terminate => {
                return Err(Refused::new(
                    error_code::SHUTTING_DOWN,
                    "the hub is shutting down",
                ))
            }
            Event::Opened { .. }
            | Event::Local { .. }
            | Event::RelayFinished(_)
            | Event::AgentLeaseEnded(_) => {}
        }
    }
}

/// Checks the dialer hello against the hub catalog, in the order unknown,
/// disabled, id mismatch, version.
fn validate_dialer(options: &ControlOptions, hello: &Hello) -> Result<DialInMachine, Refused> {
    if hello.role != HelloRole::Dialer {
        return Err(Refused::new(
            error_code::PROTOCOL_ERROR,
            "expected a hello from a dialer",
        ));
    }
    let catalog =
        DialInCatalog::load_from_trusted_path(&options.catalog_path).map_err(|error| {
            Refused::new(
                error_code::LINK_UNKNOWN,
                "the hub could not read its dial-in machine catalog",
            )
            .with_detail(error)
        })?;
    let Some(machine) = catalog.get(&options.link_id) else {
        return Err(Refused::new(
            error_code::LINK_UNKNOWN,
            format!(
                "machine link {} is not registered on this hub",
                options.link_id
            ),
        ));
    };
    if !machine.enabled {
        return Err(Refused::new(
            error_code::LINK_DISABLED,
            format!(
                "dial-in machine '{}' is disabled on this hub",
                machine.label
            ),
        ));
    }
    if hello.link_id != options.link_id.as_str() {
        return Err(Refused::new(
            error_code::LINK_ID_MISMATCH,
            "the dialer is configured for a different machine link than this key",
        ));
    }
    if protocol::negotiate_version(
        LINK_VERSION_MIN,
        LINK_VERSION_MAX,
        hello.link_min,
        hello.link_max,
    )
    .is_none()
    {
        return Err(Refused::new(
            error_code::LINK_VERSION_UNSUPPORTED,
            format!(
                "the hub supports link versions {LINK_VERSION_MIN} to {LINK_VERSION_MAX}; the dialer offered {} to {}",
                hello.link_min, hello.link_max
            ),
        ));
    }
    Ok(machine.clone())
}

/// Prepares the private link directory and takes `link.lock`. A busy lock
/// means another holder exists: it is asked to yield, which it does only when
/// its own dialer fails a liveness probe. The flag tells whether this link
/// took over from such a holder.
fn acquire_link(
    paths: &LinkPaths,
    options: &ControlOptions,
) -> Result<(crate::platform::ExclusiveFileLock, bool), Refused> {
    // Hub-side failures here are described to the dialer without paths;
    // the details go to the hub log.
    paths.ensure_socket_paths_fit().map_err(|error| {
        Refused::new(
            HUB_UNAVAILABLE,
            "the hub cannot serve this machine's link: its socket paths are too long",
        )
        .with_detail(error.to_string())
    })?;
    // The parent `links/` directory is made private too, so no other user
    // can swap a link directory out from under a hub client.
    if let Some(links) = paths.dir.parent() {
        crate::platform::ensure_private_directory(links).map_err(|error| {
            Refused::new(
                HUB_UNAVAILABLE,
                "the hub could not prepare its link directory",
            )
            .with_detail(format!("{}: {error}", links.display()))
        })?;
    }
    crate::platform::ensure_private_directory(&paths.dir).map_err(|error| {
        Refused::new(
            HUB_UNAVAILABLE,
            "the hub could not prepare this machine's link directory",
        )
        .with_detail(format!("{}: {error}", paths.dir.display()))
    })?;
    let try_lock = || {
        crate::platform::try_lock_exclusive(&paths.lock_file).map_err(|error| {
            Refused::new(
                HUB_UNAVAILABLE,
                "the hub could not open this machine's link lock",
            )
            .with_detail(format!("{}: {error}", paths.lock_file.display()))
        })
    };
    let (lock, superseded) = match try_lock()? {
        Some(lock) => (lock, false),
        None => {
            match request_supersede(paths, options) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Refused::new(
                        error_code::LINK_BUSY,
                        "this machine already has a live link to the hub",
                    ))
                }
                Err(error) => {
                    tracing::info!("link holder did not answer a supersede request: {error}");
                }
            }
            let deadline = Instant::now() + options.timings.lock_wait;
            loop {
                if let Some(lock) = try_lock()? {
                    break (lock, true);
                }
                if Instant::now() >= deadline {
                    return Err(Refused::new(
                        error_code::LINK_BUSY,
                        "another link for this machine still holds the hub lock",
                    ));
                }
                thread::sleep(LOCK_POLL);
            }
        }
    };
    if let Err(error) = lock.record_pid() {
        tracing::warn!("failed to record the link holder pid: {error}");
    }
    Ok((lock, superseded))
}

/// Asks the current holder to yield. `Ok(true)` when it agreed, `Ok(false)`
/// when its link is alive.
fn request_supersede(paths: &LinkPaths, options: &ControlOptions) -> io::Result<bool> {
    let stream = connect_link_socket(paths, options.peer_check)?;
    let timeout = options.timings.supersede_probe + options.timings.local_request_timeout;
    stream.set_recv_timeout(Some(timeout))?;
    stream.set_send_timeout(Some(timeout))?;
    let request = LocalRequest::Supersede {
        peer_addr: options.peer_addr.clone(),
    };
    protocol::write_local_request(&mut &stream, &request)?;
    let response = protocol::read_local_response(&mut &stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the link holder closed the connection without answering",
        )
    })?;
    if response.ok {
        return Ok(true);
    }
    if response.code.as_deref() == Some(local_code::LINK_BUSY) {
        return Ok(false);
    }
    Err(io::Error::other(format!(
        "the link holder answered {}: {}",
        response.code.as_deref().unwrap_or("an error"),
        response.message.as_deref().unwrap_or("")
    )))
}

/// Connects to `link.sock` after verifying the link directory is private and
/// that the listener runs as the effective user.
fn connect_link_socket(paths: &LinkPaths, peer_check: PeerCheck) -> io::Result<LocalStream> {
    crate::platform::verify_private_directory(&paths.dir)?;
    let stream = crate::ipc::connect_local_stream(&paths.link_socket)?;
    if !peer_check(&stream)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing link socket served by another user: {}",
                paths.link_socket.display()
            ),
        ));
    }
    Ok(stream)
}

/// Serializes control messages on a dedicated thread so a congested control
/// channel never stalls the holder loop. The queue is bounded: a dialer that
/// stops reading its control channel (while, say, flooding it with pings)
/// fills it, and the link ends instead of hub memory growing without bound.
struct ControlWriter {
    queue: Option<SyncSender<ControlMessage>>,
    drained: Receiver<()>,
    /// When the last message was queued; drives idle pings.
    last_sent: Instant,
    /// When the write in progress started, if one is in progress.
    writing_since: Arc<Mutex<Option<Instant>>>,
    /// A message was dropped because the queue was full.
    overflowed: bool,
}

impl ControlWriter {
    fn spawn<W: Write + Send + 'static>(mut output: W, events: Sender<Event>) -> io::Result<Self> {
        let (queue, messages) = mpsc::sync_channel::<ControlMessage>(WRITER_QUEUE);
        let (drained_tx, drained) = mpsc::channel();
        let writing_since = Arc::new(Mutex::new(None));
        let writing = Arc::clone(&writing_since);
        thread::Builder::new()
            .name("herdr-link-writer".into())
            .spawn(move || {
                for message in messages {
                    *lock(&writing) = Some(Instant::now());
                    let written = protocol::write_control_message(&mut output, &message);
                    *lock(&writing) = None;
                    if let Err(error) = written {
                        let _ = events.send(Event::ControlWriteFailed(error));
                        break;
                    }
                }
                drop(output);
                let _ = drained_tx.send(());
            })?;
        Ok(Self {
            queue: Some(queue),
            drained,
            last_sent: Instant::now(),
            writing_since,
            overflowed: false,
        })
    }

    /// Queues `message` without blocking; a full queue sets `overflowed`.
    fn send(&mut self, message: ControlMessage) {
        if let Some(queue) = &self.queue {
            match queue.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => self.overflowed = true,
                // The writer stopped after a failed write and reported it.
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
        self.last_sent = Instant::now();
    }

    /// When the write in progress started, if one is in progress.
    fn write_started(&self) -> Option<Instant> {
        *lock(&self.writing_since)
    }

    /// Closes the queue and waits up to `wait` for queued messages to be written.
    fn finish(mut self, wait: Duration) {
        self.queue = None;
        let _ = self.drained.recv_timeout(wait);
    }
}

fn spawn_control_reader<R: Read + Send + 'static>(
    input: R,
    events: Sender<Event>,
) -> io::Result<()> {
    thread::Builder::new()
        .name("herdr-link-reader".into())
        .spawn(move || {
            let mut reader = ControlReader::new(input);
            loop {
                let result = reader.read_message();
                let last = !matches!(result, Ok(Some(_)));
                if events.send(Event::Control(result)).is_err() || last {
                    break;
                }
            }
        })?;
    Ok(())
}

struct PendingOpen {
    stream: LocalStream,
    opened_at: Instant,
}

struct SupersedeProbe {
    seq: u64,
    deadline: Instant,
    /// Each claimant's connection and dialer address.
    waiters: Vec<(LocalStream, Option<String>)>,
}

/// State of an established link, owned by the holder loop thread.
struct LinkHolder<'a> {
    options: &'a ControlOptions,
    paths: &'a LinkPaths,
    machine: DialInMachine,
    writer: ControlWriter,
    events: Receiver<Event>,
    events_tx: Sender<Event>,
    status: LinkStatus,
    status_dirty: bool,
    last_status_write: Instant,
    pending: HashMap<String, PendingOpen>,
    relays: HashMap<u64, ActiveRelay>,
    next_relay_id: u64,
    agent: agent::AgentLeases,
    next_ping_seq: u64,
    last_received: Instant,
    probe: Option<SupersedeProbe>,
    next_catalog_check: Instant,
    /// The link's start or its latest refused claim: a recorded conflict
    /// clears once the link stays up without claims for a while.
    last_claim_at: Instant,
    restarts: update::PendingRestarts,
}

impl LinkHolder<'_> {
    /// Handles events and timers until the link ends. Waits block on the
    /// event channel until the next timer deadline; nothing is polled.
    fn run(&mut self) -> LinkEnd {
        loop {
            if let Some(end) = self
                .on_timers(Instant::now())
                .or_else(|| self.writer_overflow())
            {
                return end;
            }
            let wait = self
                .next_deadline()
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            match self.events.recv_timeout(wait) {
                Ok(event) => {
                    if let Some(end) = self.on_event(event).or_else(|| self.writer_overflow()) {
                        return end;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return LinkEnd::ControlFailed("the holder event channel closed".into())
                }
            }
        }
    }

    /// A full writer queue: the dialer stopped reading its control channel.
    fn writer_overflow(&self) -> Option<LinkEnd> {
        self.writer
            .overflowed
            .then(|| LinkEnd::ControlFailed("the dialer is not reading its control channel".into()))
    }

    fn next_deadline(&self) -> Instant {
        let timings = &self.options.timings;
        let mut next = (self.last_received + timings.dead_after)
            .min(self.writer.last_sent + timings.ping_idle)
            .min(self.next_catalog_check);
        if let Some(started) = self.writer.write_started() {
            next = next.min(started + timings.dead_after);
        }
        if let Some(oldest) = self.pending.values().map(|pending| pending.opened_at).min() {
            next = next.min(oldest + timings.open_timeout);
        }
        if let Some(probe) = &self.probe {
            next = next.min(probe.deadline);
        }
        if let Some(deadline) = self.restarts.next_deadline() {
            next = next.min(deadline);
        }
        if self.status_dirty {
            next = next.min(self.last_status_write + timings.status_coalesce);
        }
        if self.status.claim_conflict.is_some() {
            next = next.min(self.last_claim_at + timings.claim_clear_after);
        }
        next
    }

    fn on_timers(&mut self, now: Instant) -> Option<LinkEnd> {
        let timings = self.options.timings;
        if now.duration_since(self.last_received) >= timings.dead_after {
            return Some(LinkEnd::Dead);
        }
        // Incoming traffic keeps `last_received` fresh, so a dialer that
        // sends but never reads is caught by its stalled writes instead.
        if self
            .writer
            .write_started()
            .is_some_and(|started| now.saturating_duration_since(started) >= timings.dead_after)
        {
            return Some(LinkEnd::ControlFailed(format!(
                "writing to the dialer stalled for {}",
                format_duration(timings.dead_after)
            )));
        }
        if self
            .probe
            .as_ref()
            .is_some_and(|probe| now >= probe.deadline)
        {
            return Some(LinkEnd::Superseded);
        }
        if now.duration_since(self.writer.last_sent) >= timings.ping_idle {
            let seq = self.next_seq();
            self.writer.send(ControlMessage::Ping { seq });
        }
        self.expire_pending(now);
        if self.status.claim_conflict.is_some()
            && now >= self.last_claim_at + timings.claim_clear_after
        {
            self.status.claim_conflict = None;
            self.write_status_now(now);
        }
        self.restarts.expire(now);
        if now >= self.next_catalog_check {
            self.next_catalog_check = now + timings.catalog_recheck;
            if let Some(end) = self.recheck_catalog() {
                return Some(end);
            }
        }
        self.flush_status(now);
        None
    }

    fn on_event(&mut self, event: Event) -> Option<LinkEnd> {
        match event {
            Event::Control(Ok(Some(message))) => {
                self.last_received = Instant::now();
                self.on_control(message)
            }
            Event::Control(Ok(None)) => Some(LinkEnd::DialerClosed),
            Event::Control(Err(error)) if error.kind() == io::ErrorKind::InvalidData => Some(
                LinkEnd::ProtocolError(format!("invalid control message from the dialer: {error}")),
            ),
            Event::Control(Err(error)) => Some(LinkEnd::ControlFailed(format!(
                "failed to read the control session: {error}"
            ))),
            Event::ControlWriteFailed(error) => Some(LinkEnd::ControlFailed(format!(
                "failed to write to the control session: {error}"
            ))),
            Event::Opened { kind, stream } => {
                self.on_opened(kind, stream);
                None
            }
            Event::Local { request, stream } => {
                self.on_local(request, stream);
                None
            }
            Event::RelayFinished(id) => {
                self.relays.remove(&id);
                None
            }
            Event::AgentLeaseEnded(id) => {
                self.agent_lease_ended(id);
                None
            }
            Event::Terminate => Some(LinkEnd::Terminated),
        }
    }

    fn on_control(&mut self, message: ControlMessage) -> Option<LinkEnd> {
        match message {
            ControlMessage::Ping { seq } => self.writer.send(ControlMessage::Pong { seq }),
            ControlMessage::Pong { seq } => {
                if self.probe.as_ref().is_some_and(|probe| seq >= probe.seq) {
                    if let Some(probe) = self.probe.take() {
                        for (waiter, peer_addr) in probe.waiters {
                            let _ = respond(
                                &waiter,
                                &LocalResponse::error(
                                    local_code::LINK_BUSY,
                                    "the current link answered and is still alive",
                                ),
                            );
                            self.refused_claim(peer_addr);
                        }
                    }
                }
            }
            ControlMessage::OpenFailed(failed) => self.on_open_failed(failed),
            ControlMessage::Error(error) => {
                return Some(LinkEnd::DialerError {
                    code: error.code,
                    message: error.message,
                })
            }
            ControlMessage::RestartServerResult {
                request_id,
                ok,
                message,
            } => self.restarts.finish(&request_id, ok, &message),
            ControlMessage::Hello(_)
            | ControlMessage::Open(_)
            | ControlMessage::AgentForwarding { .. }
            | ControlMessage::RestartServer { .. } => {
                tracing::debug!("ignoring an unexpected control message from the dialer");
            }
            ControlMessage::Unknown => {}
        }
        None
    }

    fn on_open_failed(&mut self, failed: OpenFailed) {
        let was_pending = self.pending.remove(&failed.nonce).is_some();
        tracing::info!(
            code = %status::sanitize_remote_text(&failed.code, 64),
            was_pending,
            "dial-in stream failed: {}",
            status::sanitize_remote_text(&failed.message, MAX_REMOTE_TEXT_BYTES)
        );
        self.record_stream_error(&failed.code, &failed.message);
    }

    fn on_opened(&mut self, kind: StreamKind, stream: LocalStream) {
        if self.streams_full() {
            tracing::warn!(
                pending = self.pending.len(),
                active = self.relays.len(),
                "refusing a hub connection: too many dial-in streams"
            );
            return;
        }
        let session = self.machine.session.clone();
        self.queue_open(stream, |nonce| OpenRequest::stream(nonce, kind, session));
    }

    /// Whether one more stream would exceed the pending or active limits.
    fn streams_full(&self) -> bool {
        self.pending.len() >= MAX_PENDING_OPENS
            || self.pending.len() + self.relays.len() >= MAX_ACTIVE_STREAMS
    }

    /// Asks the dialer for a stream session (`request` gets a fresh nonce)
    /// and holds `stream` until that session attaches to it.
    fn queue_open(&mut self, stream: LocalStream, request: impl FnOnce(String) -> OpenRequest) {
        let nonce = loop {
            let nonce = protocol::generate_nonce();
            if !self.pending.contains_key(&nonce) {
                break nonce;
            }
        };
        self.writer
            .send(ControlMessage::Open(request(nonce.clone())));
        self.pending.insert(
            nonce,
            PendingOpen {
                stream,
                opened_at: Instant::now(),
            },
        );
    }

    fn on_local(&mut self, request: LocalRequest, stream: LocalStream) {
        let response = match request {
            LocalRequest::Attach { nonce } => return self.attach(&nonce, stream),
            LocalRequest::Supersede { peer_addr } => {
                return self.begin_supersede(stream, peer_addr)
            }
            LocalRequest::Status => LocalResponse::with_status(self.status.clone()),
            LocalRequest::AgentLease { socket } => return self.agent_lease(socket, stream),
            LocalRequest::AgentTarget => self.agent_target(),
            LocalRequest::Update {
                size,
                sha256,
                version,
            } => return self.begin_update(size, sha256, version, stream),
            LocalRequest::RestartServer { session } => return self.begin_restart(session, stream),
            LocalRequest::Unknown => {
                LocalResponse::error(local_code::UNSUPPORTED_OP, "unsupported link operation")
            }
        };
        if let Err(error) = respond(&stream, &response) {
            tracing::debug!("failed to answer a link request: {error}");
        }
    }

    fn attach(&mut self, nonce: &str, stream: LocalStream) {
        let Some(pending) = self.pending.remove(nonce) else {
            let _ = respond(
                &stream,
                &LocalResponse::error(
                    local_code::UNKNOWN_NONCE,
                    "no pending hub connection for this stream",
                ),
            );
            return;
        };
        let ready = respond(&stream, &LocalResponse::ok())
            .and_then(|()| stream.set_recv_timeout(None))
            .and_then(|()| stream.set_send_timeout(None));
        if let Err(error) = ready {
            tracing::debug!("failed to attach a dial-in stream: {error}");
            return;
        }
        self.start_relay(pending.stream, stream);
    }

    fn start_relay(&mut self, hub: LocalStream, attached: LocalStream) {
        let id = self.next_relay_id;
        self.next_relay_id += 1;
        match ActiveRelay::start(id, hub, attached, self.events_tx.clone()) {
            Ok(relay) => {
                self.relays.insert(id, relay);
            }
            Err(error) => tracing::warn!("failed to start a dial-in relay: {error}"),
        }
    }

    fn begin_supersede(&mut self, stream: LocalStream, peer_addr: Option<String>) {
        if let Some(probe) = &mut self.probe {
            if probe.waiters.len() < MAX_SUPERSEDE_WAITERS {
                probe.waiters.push((stream, peer_addr));
            } else {
                let _ = respond(
                    &stream,
                    &LocalResponse::error(local_code::LINK_BUSY, "too many supersede requests"),
                );
            }
            return;
        }
        let seq = self.next_seq();
        self.writer.send(ControlMessage::Ping { seq });
        self.probe = Some(SupersedeProbe {
            seq,
            deadline: Instant::now() + self.options.timings.supersede_probe,
            waiters: vec![(stream, peer_addr)],
        });
    }

    /// A claim from `peer_addr` that this live link refused.
    fn refused_claim(&mut self, peer_addr: Option<String>) {
        if !claim::note_refused_claim(&mut self.status, peer_addr, status::now_ms()) {
            return;
        }
        if let Some(conflict) = &self.status.claim_conflict {
            tracing::warn!(link = %self.options.link_id, "{conflict}");
        }
        self.last_claim_at = Instant::now();
        self.status_dirty = true;
    }

    fn expire_pending(&mut self, now: Instant) {
        let timeout = self.options.timings.open_timeout;
        let before = self.pending.len();
        // Dropping an expired entry closes its hub connection.
        self.pending
            .retain(|_, pending| now.duration_since(pending.opened_at) < timeout);
        let expired = before - self.pending.len();
        if expired > 0 {
            tracing::warn!(expired, "dial-in streams were not opened in time");
            self.record_stream_error(
                open_failed_code::STREAM_TIMEOUT,
                &format!(
                    "the machine did not open a stream within {}",
                    format_duration(timeout)
                ),
            );
        }
    }

    fn recheck_catalog(&mut self) -> Option<LinkEnd> {
        match DialInCatalog::load_from_trusted_path(&self.options.catalog_path) {
            Ok(catalog) => match catalog.get(&self.options.link_id) {
                Some(machine) if machine.enabled => {
                    if machine.session != self.machine.session {
                        tracing::info!(
                            session = %machine.session,
                            "dial-in machine session changed"
                        );
                    }
                    if machine.agent_forwarding != self.machine.agent_forwarding {
                        let enabled = machine.agent_forwarding;
                        tracing::info!(enabled, "dial-in agent forwarding changed");
                        self.writer
                            .send(ControlMessage::AgentForwarding { enabled });
                    }
                    self.machine = machine.clone();
                    None
                }
                _ => Some(LinkEnd::Disabled),
            },
            Err(error) => {
                tracing::warn!("keeping the link; failed to re-read the dial-in catalog: {error}");
                None
            }
        }
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.next_ping_seq;
        self.next_ping_seq = self.next_ping_seq.wrapping_add(1);
        seq
    }

    fn record_stream_error(&mut self, code: &str, message: &str) {
        self.status.last_stream_error = Some(ErrorRecord::new(code, message));
        self.status_dirty = true;
        self.flush_status(Instant::now());
    }

    /// Writes a pending `last_stream_error` update, at most once per coalesce window.
    fn flush_status(&mut self, now: Instant) {
        if self.status_dirty
            && now.duration_since(self.last_status_write) >= self.options.timings.status_coalesce
        {
            self.write_status_now(now);
        }
    }

    fn write_status_now(&mut self, now: Instant) {
        self.status.updated_at_ms = status::now_ms();
        if let Err(error) = status::write_status(&self.paths.status_file, &self.status) {
            tracing::warn!(
                path = %self.paths.status_file.display(),
                "failed to write link status: {error}"
            );
        }
        self.status_dirty = false;
        self.last_status_write = now;
    }

    /// Tears the link down: listeners and socket files first, then pending and
    /// relayed connections, then `status.json`, and only then the lock, so a
    /// successor never races this holder's cleanup.
    fn finish(
        mut self,
        end: &LinkEnd,
        mut sockets: LinkSockets,
        lock: crate::platform::ExclusiveFileLock,
    ) {
        if let Some(notice) = end.notice() {
            self.writer.send(ControlMessage::Error(notice));
        }
        sockets.stop();
        // Whoever asked this holder to yield may take over once the lock is released.
        if let Some(probe) = self.probe.take() {
            for (waiter, _) in probe.waiters {
                let _ = respond(&waiter, &LocalResponse::ok());
            }
        }
        self.pending.clear();
        self.agent.close_all();
        for relay in self.relays.values() {
            relay.abort();
        }
        self.relays.clear();
        let (code, message) = end.record(&self.options.timings);
        self.status.state = LinkState::Disconnected;
        self.status.pid = None;
        self.status.connected_since_ms = None;
        self.status.last_error = Some(ErrorRecord::new(&code, &message));
        self.write_status_now(Instant::now());
        drop(lock);
        self.writer.finish(WRITER_DRAIN);
    }
}
