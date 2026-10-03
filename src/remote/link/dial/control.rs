//! The dialer's control session: ready-marker preamble, hello exchange, and
//! the control loop (pings, liveness, and `Open` dispatch).

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use super::failure::{failure_code, LinkFailure};
use super::SHUTDOWN_POLL;
use crate::client::endpoint::ProfileId;
use crate::remote::link::protocol::{
    self, error_code, open_failed_code, ControlMessage, ControlReader, Hello, HelloRole,
    OpenFailed, OpenRequest, StreamKind,
};
use crate::remote::link::status::sanitize_remote_text;
use crate::remote::link::{
    HELLO_DEADLINE, LINK_DEAD_AFTER, LINK_VERSION_MAX, LINK_VERSION_MIN, MAX_ACTIVE_STREAMS,
    MAX_PREAMBLE_BYTES, PING_IDLE, PREAMBLE_DEADLINE,
};

/// Control events queued for the control loop (messages read from the hub
/// and messages stream workers want sent).
pub(crate) const CONTROL_EVENT_QUEUE: usize = 256;

/// Checks an `Open` before any process is started.
pub(crate) fn validate_open(request: &OpenRequest) -> Result<(), OpenFailed> {
    let failed = |code: &str, message: String| OpenFailed {
        nonce: request.nonce.clone(),
        code: code.to_string(),
        message,
    };
    if !protocol::is_valid_nonce(&request.nonce) {
        return Err(failed(
            error_code::PROTOCOL_ERROR,
            "open request carries an invalid nonce".into(),
        ));
    }
    if request.kind == StreamKind::Unknown {
        return Err(failed(
            open_failed_code::UNSUPPORTED_KIND,
            "this Herdr version does not support the requested stream kind".into(),
        ));
    }
    // Update streams belong to no session.
    if request.kind == StreamKind::Update {
        return Ok(());
    }
    if let Err(error) = crate::session::validate_name(&request.session) {
        return Err(failed(
            open_failed_code::INVALID_SESSION,
            format!("invalid session name: {error}"),
        ));
    }
    Ok(())
}

/// How a bounded wait checks for cancellation (a shutdown request or the
/// link attempt being torn down).
#[derive(Clone, Copy)]
pub(crate) struct Cancel<'a> {
    pub(crate) requested: &'a dyn Fn() -> bool,
    /// Upper bound on one wait between checks.
    pub(crate) tick: Duration,
}

/// Runs [`protocol::discard_until_marker`] on a helper thread. On `deadline`
/// or cancellation calls `abort` (which must make the reader fail, e.g. by
/// killing the ssh process) and fails with `TimedOut` or `Interrupted`.
/// Returns the reader and the bytes read past the marker.
pub(crate) fn discard_preamble_with_deadline<R: Read + Send + 'static>(
    reader: R,
    deadline: Duration,
    cancel: Cancel<'_>,
    abort: impl FnOnce(),
) -> io::Result<(R, Vec<u8>)> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("herdr-dial-preamble".into())
        .spawn(move || {
            let mut reader = reader;
            let result = protocol::discard_until_marker(&mut reader, MAX_PREAMBLE_BYTES);
            let _ = sender.send(result.map(|leftover| (reader, leftover)));
        })?;
    let started = Instant::now();
    let error = loop {
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the hub did not print the herdr link ready marker within {}s",
                    deadline.as_secs()
                ),
            );
        }
        match receiver.recv_timeout(remaining.min(cancel.tick)) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => {
                if (cancel.requested)() {
                    break io::Error::new(io::ErrorKind::Interrupted, "shutting down");
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other(
                    "link preamble reader stopped unexpectedly",
                ))
            }
        }
    };
    abort();
    Err(error)
}

/// Events consumed by the control loop.
#[derive(Debug)]
pub(crate) enum LoopEvent {
    /// A message from the hub.
    Message(ControlMessage),
    /// The hub closed the control channel.
    Closed,
    ReadFailed(io::Error),
    /// A message to send to the hub (from stream workers).
    Send(ControlMessage),
}

/// Starts streams for validated `Open` requests.
pub(crate) trait StreamOpener: Send + Sync {
    fn active_streams(&self) -> usize;
    /// Starts the stream asynchronously; failures are reported by sending
    /// `LoopEvent::Send(ControlMessage::OpenFailed(..))` on `events`. Runs on
    /// the control loop thread, which drains `events`: it must not block on
    /// a full queue (use `try_send` there).
    fn open(&self, request: OpenRequest, events: SyncSender<LoopEvent>);
    /// The hub turned agent forwarding for this link on or off.
    fn set_agent_forwarding(&self, _enabled: bool) {}
    /// Restarts the local server of `session` asynchronously and reports a
    /// `RestartServerResult` on `events`, under the same rules as `open`.
    fn restart_server(&self, request_id: String, session: String, events: SyncSender<LoopEvent>);
}

/// Control-session timing; production uses the link constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LoopTiming {
    pub(crate) preamble_deadline: Duration,
    pub(crate) hello_deadline: Duration,
    pub(crate) ping_idle: Duration,
    pub(crate) dead_after: Duration,
    /// Upper bound on one wait, so a shutdown request is noticed promptly.
    pub(crate) tick: Duration,
}

impl Default for LoopTiming {
    fn default() -> Self {
        Self {
            preamble_deadline: PREAMBLE_DEADLINE,
            hello_deadline: HELLO_DEADLINE,
            ping_idle: PING_IDLE,
            dead_after: LINK_DEAD_AFTER,
            tick: SHUTDOWN_POLL,
        }
    }
}

/// How a control session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LinkEnd {
    /// Local shutdown was requested.
    Shutdown,
    Failed(LinkFailure),
}

/// Forwards control messages from `reader` to `events` until EOF or error.
pub(crate) fn spawn_control_reader<R: Read + Send + 'static>(
    mut reader: ControlReader<R>,
    events: SyncSender<LoopEvent>,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("herdr-dial-control".into())
        .spawn(move || loop {
            match reader.read_message() {
                Ok(Some(message)) => {
                    if events.send(LoopEvent::Message(message)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = events.send(LoopEvent::Closed);
                    return;
                }
                Err(error) => {
                    let _ = events.send(LoopEvent::ReadFailed(error));
                    return;
                }
            }
        })
}

fn send_message(writer: &mut impl Write, message: &ControlMessage) -> Result<(), LinkFailure> {
    protocol::write_control_message(writer, message).map_err(|error| {
        LinkFailure::new(
            failure_code::LINK_LOST,
            format!("failed to write to the hub: {error}"),
        )
    })
}

fn read_failure(error: &io::Error) -> LinkFailure {
    match error.kind() {
        io::ErrorKind::InvalidData => LinkFailure::new(
            failure_code::PROTOCOL_ERROR,
            format!("the hub sent an invalid control message: {error}"),
        ),
        _ => LinkFailure::new(
            failure_code::LINK_LOST,
            format!("reading from the hub failed: {error}"),
        ),
    }
}

/// Checks the acceptor's hello against this link.
pub(crate) fn validate_acceptor_hello(
    hello: Hello,
    link_id: &ProfileId,
) -> Result<Hello, LinkFailure> {
    if hello.role != HelloRole::Acceptor {
        return Err(LinkFailure::new(
            failure_code::PROTOCOL_ERROR,
            "the hub answered with a hello that is not from a link acceptor",
        ));
    }
    if hello.link_id != link_id.as_str() {
        return Err(LinkFailure::new(
            error_code::LINK_ID_MISMATCH,
            format!(
                "the hub answered for link {} instead of {link_id}",
                sanitize_remote_text(&hello.link_id, 64)
            ),
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
        return Err(LinkFailure::new(
            error_code::LINK_VERSION_UNSUPPORTED,
            format!(
                "the hub supports link versions {}..={}, this Herdr supports {LINK_VERSION_MIN}..={LINK_VERSION_MAX}",
                hello.link_min, hello.link_max
            ),
        ));
    }
    Ok(hello)
}

/// Sends the dialer hello (reporting `last_dial_error`) and waits for the
/// acceptor's hello (or error). Cancellation fails with a local "shutting
/// down" failure.
pub(crate) fn exchange_hello(
    writer: &mut impl Write,
    events: &Receiver<LoopEvent>,
    link_id: &ProfileId,
    last_dial_error: Option<String>,
    deadline: Duration,
    cancel: Cancel<'_>,
) -> Result<Hello, LinkFailure> {
    let mut hello = Hello::local(HelloRole::Dialer, link_id.to_string());
    hello.last_dial_error = last_dial_error;
    send_message(writer, &ControlMessage::Hello(hello))?;
    let started = Instant::now();
    let timeout = || {
        LinkFailure::new(
            failure_code::HELLO_TIMEOUT,
            format!(
                "the hub did not answer the hello within {}s",
                deadline.as_secs()
            ),
        )
    };
    loop {
        if (cancel.requested)() {
            return Err(LinkFailure::new(failure_code::LOCAL_ERROR, "shutting down"));
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(timeout());
        }
        match events.recv_timeout(remaining.min(cancel.tick)) {
            Ok(LoopEvent::Message(ControlMessage::Hello(hello))) => {
                return validate_acceptor_hello(hello, link_id)
            }
            Ok(LoopEvent::Message(ControlMessage::Error(error))) => {
                return Err(LinkFailure::from_link_error(&error))
            }
            Ok(LoopEvent::Message(ControlMessage::Ping { seq })) => {
                send_message(writer, &ControlMessage::Pong { seq })?;
            }
            Ok(LoopEvent::Message(ControlMessage::Unknown | ControlMessage::Pong { .. }))
            | Ok(LoopEvent::Send(_)) => {}
            Ok(LoopEvent::Message(_)) => {
                return Err(LinkFailure::new(
                    failure_code::PROTOCOL_ERROR,
                    "the hub sent a control message before its hello",
                ))
            }
            Ok(LoopEvent::Closed) => {
                return Err(LinkFailure::new(
                    failure_code::LINK_LOST,
                    "the hub closed the link before answering the hello",
                ))
            }
            Ok(LoopEvent::ReadFailed(error)) => return Err(read_failure(&error)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(LinkFailure::new(
                    failure_code::LINK_LOST,
                    "the link control reader stopped",
                ))
            }
        }
    }
}

/// Validates an `Open` and hands it to `opener`; returns the `OpenFailed`
/// to send when it is refused up front.
pub(crate) fn handle_open(
    request: OpenRequest,
    opener: &dyn StreamOpener,
    events: &SyncSender<LoopEvent>,
) -> Option<OpenFailed> {
    if let Err(failed) = validate_open(&request) {
        return Some(failed);
    }
    if opener.active_streams() >= MAX_ACTIVE_STREAMS {
        return Some(OpenFailed {
            nonce: request.nonce,
            code: open_failed_code::SESSION_REFUSED.into(),
            message: format!("the dialing machine already serves {MAX_ACTIVE_STREAMS} streams"),
        });
    }
    opener.open(request, events.clone());
    None
}

/// Serves an established control session until the link fails or
/// `shutdown` is set.
pub(crate) fn run_control_loop(
    writer: &mut impl Write,
    events: &Receiver<LoopEvent>,
    event_sender: &SyncSender<LoopEvent>,
    opener: &dyn StreamOpener,
    shutdown: &AtomicBool,
    timing: LoopTiming,
) -> LinkEnd {
    let mut last_sent = Instant::now();
    let mut last_received = Instant::now();
    let mut next_seq = 1_u64;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return LinkEnd::Shutdown;
        }
        let since_received = last_received.elapsed();
        if since_received >= timing.dead_after {
            return LinkEnd::Failed(LinkFailure::new(
                failure_code::LINK_DEAD,
                format!(
                    "nothing received from the hub for {}s",
                    since_received.as_secs()
                ),
            ));
        }
        if last_sent.elapsed() >= timing.ping_idle {
            if let Err(failure) = send_message(writer, &ControlMessage::Ping { seq: next_seq }) {
                return LinkEnd::Failed(failure);
            }
            next_seq = next_seq.wrapping_add(1);
            last_sent = Instant::now();
        }
        let wait = timing
            .tick
            .min(timing.ping_idle.saturating_sub(last_sent.elapsed()))
            .min(timing.dead_after.saturating_sub(last_received.elapsed()))
            .max(Duration::from_millis(1));
        let event = match events.recv_timeout(wait) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                return LinkEnd::Failed(LinkFailure::new(
                    failure_code::LINK_LOST,
                    "the link control reader stopped",
                ))
            }
        };
        let outgoing = match event {
            LoopEvent::Message(message) => {
                last_received = Instant::now();
                match message {
                    ControlMessage::Ping { seq } => Some(ControlMessage::Pong { seq }),
                    ControlMessage::Open(request) => {
                        handle_open(request, opener, event_sender).map(ControlMessage::OpenFailed)
                    }
                    ControlMessage::Error(error) => {
                        return LinkEnd::Failed(LinkFailure::from_link_error(&error))
                    }
                    ControlMessage::AgentForwarding { enabled } => {
                        opener.set_agent_forwarding(enabled);
                        None
                    }
                    ControlMessage::RestartServer {
                        request_id,
                        session,
                    } => {
                        opener.restart_server(request_id, session, event_sender.clone());
                        None
                    }
                    ControlMessage::Pong { .. }
                    | ControlMessage::Hello(_)
                    | ControlMessage::OpenFailed(_)
                    | ControlMessage::RestartServerResult { .. }
                    | ControlMessage::Unknown => None,
                }
            }
            LoopEvent::Send(message) => Some(message),
            LoopEvent::Closed => {
                return LinkEnd::Failed(LinkFailure::new(
                    failure_code::LINK_LOST,
                    "the hub closed the link",
                ))
            }
            LoopEvent::ReadFailed(error) => return LinkEnd::Failed(read_failure(&error)),
        };
        if let Some(message) = outgoing {
            if let Err(failure) = send_message(writer, &message) {
                return LinkEnd::Failed(failure);
            }
            last_sent = Instant::now();
        }
    }
}

/// One control session over already-open stdio: discard the preamble, run
/// the hello exchange, call `on_connected`, then serve the control loop.
#[allow(clippy::too_many_arguments)] // one call site each in production and tests
pub(crate) fn run_control_session<R: Read + Send + 'static, W: Write>(
    reader: R,
    mut writer: W,
    link_id: &ProfileId,
    last_dial_error: Option<String>,
    opener: &dyn StreamOpener,
    shutdown: &AtomicBool,
    timing: LoopTiming,
    on_preamble_timeout: impl FnOnce(),
    on_connected: impl FnOnce(&Hello),
) -> LinkEnd {
    let shutting_down = || shutdown.load(Ordering::SeqCst);
    let cancel = Cancel {
        requested: &shutting_down,
        tick: timing.tick,
    };
    let (reader, leftover) = match discard_preamble_with_deadline(
        reader,
        timing.preamble_deadline,
        cancel,
        on_preamble_timeout,
    ) {
        Ok(result) => result,
        Err(_) if shutting_down() => return LinkEnd::Shutdown,
        Err(error) => {
            return LinkEnd::Failed(LinkFailure::new(
                failure_code::PREAMBLE_FAILED,
                format!("the hub link acceptor did not start: {error}"),
            ))
        }
    };
    // Bounded, so a hub that floods the control channel while this side is
    // blocked writing to it pushes back into ssh instead of growing memory.
    let (sender, events) = mpsc::sync_channel(CONTROL_EVENT_QUEUE);
    if let Err(error) = spawn_control_reader(
        ControlReader::with_leftover(reader, leftover),
        sender.clone(),
    ) {
        return LinkEnd::Failed(LinkFailure::new(
            failure_code::LOCAL_ERROR,
            format!("failed to start the control reader: {error}"),
        ));
    }
    let hello = match exchange_hello(
        &mut writer,
        &events,
        link_id,
        last_dial_error,
        timing.hello_deadline,
        cancel,
    ) {
        Ok(hello) => hello,
        Err(_) if shutting_down() => return LinkEnd::Shutdown,
        Err(failure) => return LinkEnd::Failed(failure),
    };
    on_connected(&hello);
    run_control_loop(&mut writer, &events, &sender, opener, shutdown, timing)
}

#[cfg(test)]
mod tests {
    use super::super::lock;
    use super::*;
    use crate::remote::link::protocol::LinkError;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    fn id() -> ProfileId {
        ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    #[derive(Default)]
    struct RecordingOpener {
        opened: Mutex<Vec<OpenRequest>>,
        active: usize,
        agent_forwarding: Mutex<Vec<bool>>,
    }

    impl StreamOpener for RecordingOpener {
        fn active_streams(&self) -> usize {
            self.active
        }

        fn open(&self, request: OpenRequest, events: SyncSender<LoopEvent>) {
            let nonce = request.nonce.clone();
            lock(&self.opened).push(request);
            let _ = events.try_send(LoopEvent::Send(ControlMessage::OpenFailed(OpenFailed {
                nonce,
                code: open_failed_code::BRIDGE_FAILED.into(),
                message: "fake bridge".into(),
            })));
        }

        fn set_agent_forwarding(&self, enabled: bool) {
            lock(&self.agent_forwarding).push(enabled);
        }

        fn restart_server(&self, request_id: String, _: String, events: SyncSender<LoopEvent>) {
            let _ = events.try_send(LoopEvent::Send(ControlMessage::RestartServerResult {
                request_id,
                ok: true,
                message: "fake restart".into(),
            }));
        }
    }

    fn open(nonce: &str, kind: StreamKind, session: &str) -> OpenRequest {
        OpenRequest::stream(nonce.into(), kind, session.into())
    }

    #[test]
    fn open_handling_rejects_invalid_session_kind_nonce_and_overload() {
        let opener = RecordingOpener::default();
        let (sender, _events) = mpsc::sync_channel(CONTROL_EVENT_QUEUE);

        let failed = handle_open(
            open(NONCE, StreamKind::Client, "bad name"),
            &opener,
            &sender,
        )
        .unwrap();
        assert_eq!(failed.code, open_failed_code::INVALID_SESSION);
        assert_eq!(failed.nonce, NONCE);

        let failed =
            handle_open(open(NONCE, StreamKind::Unknown, "work"), &opener, &sender).unwrap();
        assert_eq!(failed.code, open_failed_code::UNSUPPORTED_KIND);

        let failed = handle_open(open("nonce", StreamKind::Api, "work"), &opener, &sender).unwrap();
        assert_eq!(failed.code, error_code::PROTOCOL_ERROR);

        assert!(lock(&opener.opened).is_empty());
        assert_eq!(
            handle_open(open(NONCE, StreamKind::Api, "work"), &opener, &sender),
            None
        );
        // Update streams carry no session.
        assert_eq!(
            handle_open(open(NONCE, StreamKind::Update, ""), &opener, &sender),
            None
        );
        assert_eq!(lock(&opener.opened).len(), 2);

        let busy = RecordingOpener {
            active: MAX_ACTIVE_STREAMS,
            ..RecordingOpener::default()
        };
        let failed = handle_open(open(NONCE, StreamKind::Client, "work"), &busy, &sender).unwrap();
        assert_eq!(failed.code, open_failed_code::SESSION_REFUSED);
        assert!(lock(&busy.opened).is_empty());
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

    fn never_cancelled() -> bool {
        false
    }

    const NO_CANCEL: Cancel<'static> = Cancel {
        requested: &never_cancelled,
        tick: Duration::from_millis(10),
    };

    #[test]
    fn preamble_deadline_invokes_the_timeout_hook() {
        let (reader, writer) = io::pipe().unwrap();
        let mut fired = false;
        let error =
            discard_preamble_with_deadline(reader, Duration::from_millis(50), NO_CANCEL, || {
                fired = true;
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(fired);
        drop(writer);

        let mut wire = b"motd\n".to_vec();
        protocol::write_marker(&mut wire).unwrap();
        wire.extend_from_slice(b"after");
        let (_, leftover) = discard_preamble_with_deadline(
            Cursor::new(wire),
            Duration::from_secs(5),
            NO_CANCEL,
            || panic!("must not time out"),
        )
        .unwrap();
        assert_eq!(leftover, b"after");
    }

    #[test]
    fn preamble_wait_ends_promptly_on_cancellation() {
        let (reader, writer) = io::pipe().unwrap();
        let requested = AtomicBool::new(false);
        let is_requested = || requested.load(Ordering::SeqCst);
        let cancel = Cancel {
            requested: &is_requested,
            tick: Duration::from_millis(10),
        };
        let started = Instant::now();
        let mut aborted = false;
        let error = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(30));
                requested.store(true, Ordering::SeqCst);
            });
            discard_preamble_with_deadline(reader, Duration::from_secs(30), cancel, || {
                aborted = true;
            })
            .unwrap_err()
        });
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(aborted, "cancellation must abort the reader");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(writer);
    }

    fn acceptor_hello() -> Hello {
        let mut hello = Hello::local(HelloRole::Acceptor, id().to_string());
        hello.sessions = vec!["default".into()];
        hello
    }

    #[test]
    fn hello_validation_rejects_wrong_role_link_and_version() {
        assert!(validate_acceptor_hello(acceptor_hello(), &id()).is_ok());

        let mut wrong_role = acceptor_hello();
        wrong_role.role = HelloRole::Dialer;
        assert_eq!(
            validate_acceptor_hello(wrong_role, &id()).unwrap_err().code,
            failure_code::PROTOCOL_ERROR
        );

        let mut wrong_link = acceptor_hello();
        wrong_link.link_id = "ffffffffffffffffffffffffffffffff".into();
        let failure = validate_acceptor_hello(wrong_link, &id()).unwrap_err();
        assert_eq!(failure.code, error_code::LINK_ID_MISMATCH);
        assert!(failure.is_persistent());

        let mut future = acceptor_hello();
        future.link_min = LINK_VERSION_MAX + 1;
        future.link_max = LINK_VERSION_MAX + 3;
        assert_eq!(
            validate_acceptor_hello(future, &id()).unwrap_err().code,
            error_code::LINK_VERSION_UNSUPPORTED
        );
    }

    fn fast_timing() -> LoopTiming {
        LoopTiming {
            preamble_deadline: Duration::from_secs(5),
            hello_deadline: Duration::from_secs(5),
            ping_idle: Duration::from_millis(100),
            dead_after: Duration::from_secs(10),
            tick: Duration::from_millis(20),
        }
    }

    /// Reads messages until one matches, answering dialer pings meanwhile.
    fn expect_message(
        reader: &mut ControlReader<io::PipeReader>,
        writer: &mut io::PipeWriter,
        matches: impl Fn(&ControlMessage) -> bool,
    ) -> ControlMessage {
        loop {
            let message = reader
                .read_message()
                .unwrap()
                .expect("dialer closed the control channel");
            if matches(&message) {
                return message;
            }
            if let ControlMessage::Ping { seq } = message {
                protocol::write_control_message(writer, &ControlMessage::Pong { seq }).unwrap();
            }
        }
    }

    #[test]
    fn control_session_with_fake_acceptor_over_pipes() {
        let (dialer_reader, mut acceptor_writer) = io::pipe().unwrap();
        let (acceptor_reader, dialer_writer) = io::pipe().unwrap();

        let acceptor = thread::spawn(move || {
            acceptor_writer
                .write_all(b"Welcome to the hub\nlast login: never\n")
                .unwrap();
            protocol::write_marker(&mut acceptor_writer).unwrap();
            let mut reader = ControlReader::new(acceptor_reader);

            let Some(ControlMessage::Hello(hello)) = reader.read_message().unwrap() else {
                panic!("expected the dialer hello first");
            };
            assert_eq!(hello.role, HelloRole::Dialer);
            assert_eq!(hello.link_id, id().as_str());
            assert_eq!(
                hello.last_dial_error.as_deref(),
                Some("no route (ssh_failed)")
            );
            assert_eq!(
                (hello.link_min, hello.link_max),
                (LINK_VERSION_MIN, LINK_VERSION_MAX)
            );
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::Hello(acceptor_hello()),
            )
            .unwrap();

            // Unknown message types are ignored; agent forwarding goes to the opener.
            acceptor_writer
                .write_all(b"{\"type\":\"future\",\"x\":1}\n")
                .unwrap();
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::AgentForwarding { enabled: true },
            )
            .unwrap();
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::Ping { seq: 41 },
            )
            .unwrap();
            expect_message(&mut reader, &mut acceptor_writer, |message| {
                *message == ControlMessage::Pong { seq: 41 }
            });

            // Server restarts go to the opener, which answers through the loop.
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::RestartServer {
                    request_id: "r1".into(),
                    session: "work".into(),
                },
            )
            .unwrap();
            expect_message(&mut reader, &mut acceptor_writer, |message| {
                *message
                    == ControlMessage::RestartServerResult {
                        request_id: "r1".into(),
                        ok: true,
                        message: "fake restart".into(),
                    }
            });

            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::Open(open(NONCE, StreamKind::Client, "no spaces allowed")),
            )
            .unwrap();
            let ControlMessage::OpenFailed(failed) =
                expect_message(&mut reader, &mut acceptor_writer, |message| {
                    matches!(message, ControlMessage::OpenFailed(_))
                })
            else {
                unreachable!()
            };
            assert_eq!(failed.nonce, NONCE);
            assert_eq!(failed.code, open_failed_code::INVALID_SESSION);

            acceptor_writer
                .write_all(
                    format!(
                        "{{\"type\":\"open\",\"nonce\":\"{NONCE}\",\"kind\":\"terminal\",\"session\":\"work\"}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            let ControlMessage::OpenFailed(failed) =
                expect_message(&mut reader, &mut acceptor_writer, |message| {
                    matches!(message, ControlMessage::OpenFailed(_))
                })
            else {
                unreachable!()
            };
            assert_eq!(failed.code, open_failed_code::UNSUPPORTED_KIND);

            let valid = "ffeeddccbbaa99887766554433221100";
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::Open(open(valid, StreamKind::Api, "work")),
            )
            .unwrap();
            let ControlMessage::OpenFailed(failed) =
                expect_message(&mut reader, &mut acceptor_writer, |message| {
                    matches!(message, ControlMessage::OpenFailed(_))
                })
            else {
                unreachable!()
            };
            assert_eq!(failed.nonce, valid);
            assert_eq!(failed.message, "fake bridge");

            // With nothing else to say, the dialer pings when idle.
            let ControlMessage::Ping { seq } =
                expect_message(&mut reader, &mut acceptor_writer, |message| {
                    matches!(message, ControlMessage::Ping { .. })
                })
            else {
                unreachable!()
            };
            protocol::write_control_message(&mut acceptor_writer, &ControlMessage::Pong { seq })
                .unwrap();
            // Closing the control channel ends the dialer's session.
        });

        let opener = RecordingOpener::default();
        let shutdown = AtomicBool::new(false);
        let mut connected = None;
        let end = run_control_session(
            dialer_reader,
            dialer_writer,
            &id(),
            Some("no route (ssh_failed)".into()),
            &opener,
            &shutdown,
            fast_timing(),
            || panic!("preamble must not time out"),
            |hello| connected = Some(hello.clone()),
        );
        acceptor.join().unwrap();

        assert_eq!(connected.unwrap().sessions, ["default"]);
        let LinkEnd::Failed(failure) = end else {
            panic!("expected link loss, got {end:?}");
        };
        assert_eq!(failure.code, failure_code::LINK_LOST);
        let opened = lock(&opener.opened);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, StreamKind::Api);
        assert_eq!(opened[0].session, "work");
        assert_eq!(*lock(&opener.agent_forwarding), [true]);
    }

    #[test]
    fn control_session_reports_hub_errors_and_honors_shutdown() {
        // The acceptor refuses the link: a persistent failure.
        let (dialer_reader, mut acceptor_writer) = io::pipe().unwrap();
        let (acceptor_reader, dialer_writer) = io::pipe().unwrap();
        let acceptor = thread::spawn(move || {
            protocol::write_marker(&mut acceptor_writer).unwrap();
            let mut reader = ControlReader::new(acceptor_reader);
            assert!(matches!(
                reader.read_message().unwrap(),
                Some(ControlMessage::Hello(_))
            ));
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::Error(LinkError::new(
                    error_code::LINK_BUSY,
                    "another dialer \u{1b}[2Jholds it",
                )),
            )
            .unwrap();
        });
        let end = run_control_session(
            dialer_reader,
            dialer_writer,
            &id(),
            None,
            &RecordingOpener::default(),
            &AtomicBool::new(false),
            fast_timing(),
            || {},
            |_| panic!("must not connect"),
        );
        acceptor.join().unwrap();
        let LinkEnd::Failed(failure) = end else {
            panic!("expected a failure");
        };
        assert_eq!(failure.code, error_code::LINK_BUSY);
        assert!(failure.is_persistent());
        assert!(!failure.message.contains('\u{1b}'));

        // Shutdown ends an established session without a failure.
        let (dialer_reader, mut acceptor_writer) = io::pipe().unwrap();
        let (acceptor_reader, dialer_writer) = io::pipe().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let acceptor = thread::spawn(move || {
            protocol::write_marker(&mut acceptor_writer).unwrap();
            let mut reader = ControlReader::new(acceptor_reader);
            assert!(matches!(
                reader.read_message().unwrap(),
                Some(ControlMessage::Hello(_))
            ));
            protocol::write_control_message(
                &mut acceptor_writer,
                &ControlMessage::Hello(acceptor_hello()),
            )
            .unwrap();
            // Drain until the dialer closes its side.
            while let Ok(Some(_)) = reader.read_message() {}
        });
        let flag = Arc::clone(&shutdown);
        let end = run_control_session(
            dialer_reader,
            dialer_writer,
            &id(),
            None,
            &RecordingOpener::default(),
            &shutdown,
            fast_timing(),
            || {},
            move |_| flag.store(true, Ordering::SeqCst),
        );
        assert_eq!(end, LinkEnd::Shutdown);
        acceptor.join().unwrap();

        // A shutdown while a slow hub has not answered the hello yet ends the
        // session promptly instead of after the hello deadline.
        let (dialer_reader, mut acceptor_writer) = io::pipe().unwrap();
        let (acceptor_reader, dialer_writer) = io::pipe().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let acceptor = thread::spawn(move || {
            protocol::write_marker(&mut acceptor_writer).unwrap();
            let mut reader = ControlReader::new(acceptor_reader);
            assert!(matches!(
                reader.read_message().unwrap(),
                Some(ControlMessage::Hello(_))
            ));
            flag.store(true, Ordering::SeqCst);
            // Never answer; drain until the dialer closes its side.
            while let Ok(Some(_)) = reader.read_message() {}
            drop(acceptor_writer);
        });
        let started = Instant::now();
        let end = run_control_session(
            dialer_reader,
            dialer_writer,
            &id(),
            None,
            &RecordingOpener::default(),
            &shutdown,
            LoopTiming {
                hello_deadline: Duration::from_secs(60),
                ..fast_timing()
            },
            || {},
            |_| panic!("must not connect"),
        );
        assert_eq!(end, LinkEnd::Shutdown);
        assert!(started.elapsed() < Duration::from_secs(10));
        acceptor.join().unwrap();
    }

    #[test]
    fn control_loop_declares_a_silent_link_dead() {
        let (sender, events) = mpsc::sync_channel(CONTROL_EVENT_QUEUE);
        let mut sink = Recorder::default();
        let timing = LoopTiming {
            ping_idle: Duration::from_millis(10),
            dead_after: Duration::from_millis(80),
            tick: Duration::from_millis(5),
            ..fast_timing()
        };
        let end = run_control_loop(
            &mut sink,
            &events,
            &sender,
            &RecordingOpener::default(),
            &AtomicBool::new(false),
            timing,
        );
        let LinkEnd::Failed(failure) = end else {
            panic!("expected a dead link");
        };
        assert_eq!(failure.code, failure_code::LINK_DEAD);
        let mut reader = ControlReader::new(Cursor::new(sink.bytes));
        let mut pings = 0;
        while let Some(message) = reader.read_message().unwrap() {
            assert!(matches!(message, ControlMessage::Ping { .. }));
            pings += 1;
        }
        assert!(pings >= 2, "expected idle pings, saw {pings}");
    }
}
