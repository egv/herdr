//! Acceptor tests: the control and stream cores driven over in-process
//! socket pairs, with real link sockets in short temporary directories.

use super::*;
use crate::remote::link::MAX_PREAMBLE_BYTES;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const WAIT: Duration = Duration::from_secs(10);
const NONCE: &str = "00112233445566778899aabbccddeeff";

fn quick_timings() -> Timings {
    Timings {
        hello_deadline: Duration::from_secs(5),
        ping_idle: Duration::from_secs(60),
        dead_after: Duration::from_secs(120),
        open_timeout: Duration::from_secs(60),
        supersede_probe: Duration::from_millis(300),
        lock_wait: Duration::from_secs(3),
        catalog_recheck: Duration::from_secs(60),
        local_request_timeout: Duration::from_secs(5),
        status_coalesce: Duration::from_millis(50),
        claim_clear_after: Duration::from_secs(600),
    }
}

fn deny_peer(_stream: &LocalStream) -> io::Result<bool> {
    Ok(false)
}

/// Socket paths must fit sun_path; macOS temp dirs are long.
fn short_temp_root() -> PathBuf {
    let temp = std::env::temp_dir();
    if crate::platform::local_socket_path_fits(&temp.join("x".repeat(80))) {
        temp
    } else {
        PathBuf::from("/tmp")
    }
}

struct Fixture {
    root: PathBuf,
    catalog_path: PathBuf,
    id: ProfileId,
    paths: LinkPaths,
}

impl Fixture {
    fn new(name: &str) -> Self {
        Self::with_machine(name, true)
    }

    fn with_machine(name: &str, enabled: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = short_temp_root().join(format!(
            "hla-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        crate::platform::ensure_private_directory(&root).unwrap();
        let catalog_path = root.join("client").join("dial-in-machines.json");
        let mut catalog = DialInCatalog::default();
        let id = catalog.add("slave", "default", &[]).unwrap();
        catalog.set_enabled(&id, enabled);
        catalog.store_to_path(&catalog_path).unwrap();
        let paths = LinkPaths::for_catalog(&catalog_path, &id);
        Self {
            root,
            catalog_path,
            id,
            paths,
        }
    }

    fn options(&self) -> ControlOptions {
        ControlOptions {
            timings: quick_timings(),
            ..ControlOptions::new(self.catalog_path.clone(), self.id.clone())
        }
    }

    fn set_enabled(&self, enabled: bool) {
        let mut catalog = DialInCatalog::load_from_path(&self.catalog_path).unwrap();
        assert!(catalog.set_enabled(&self.id, enabled));
        catalog.store_to_path(&self.catalog_path).unwrap();
    }

    fn status(&self) -> LinkStatus {
        status::read_status(&self.paths.status_file)
            .unwrap()
            .expect("status.json")
    }

    fn wait_status(&self, matches: impl Fn(&LinkStatus) -> bool) -> LinkStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Ok(Some(status)) = status::read_status(&self.paths.status_file) {
                if matches(&status) {
                    return status;
                }
                if Instant::now() >= deadline {
                    panic!("status never matched; last: {status:?}");
                }
            } else if Instant::now() >= deadline {
                panic!("status.json never appeared");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// One `link.sock` request; `None` when the holder closed the
    /// connection without answering.
    fn local_request(&self, request: &LocalRequest) -> Option<LocalResponse> {
        let stream = self.connect(&self.paths.link_socket);
        protocol::write_local_request(&mut &stream, request).ok()?;
        protocol::read_local_response(&mut &stream).ok().flatten()
    }

    fn connect(&self, path: &Path) -> LocalStream {
        let stream = crate::ipc::connect_local_stream(path).unwrap();
        stream.set_recv_timeout(Some(WAIT)).unwrap();
        stream
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The slave side of a control session, driven by the test. Pings are
/// answered automatically unless `auto_pong` is cleared, and are not
/// delivered to `messages`.
struct FakeDialer {
    stream: UnixStream,
    writer: Arc<Mutex<UnixStream>>,
    messages: Receiver<ControlMessage>,
    auto_pong: Arc<AtomicBool>,
    pings: Arc<AtomicU64>,
}

impl FakeDialer {
    fn new(stream: UnixStream) -> Self {
        let mut reader = stream.try_clone().unwrap();
        reader.set_read_timeout(Some(WAIT)).unwrap();
        let leftover = protocol::discard_until_marker(&mut reader, MAX_PREAMBLE_BYTES).unwrap();
        reader.set_read_timeout(None).unwrap();
        let writer = Arc::new(Mutex::new(stream.try_clone().unwrap()));
        let auto_pong = Arc::new(AtomicBool::new(true));
        let pings = Arc::new(AtomicU64::new(0));
        let (tx, messages) = mpsc::channel();
        {
            let writer = Arc::clone(&writer);
            let auto_pong = Arc::clone(&auto_pong);
            let pings = Arc::clone(&pings);
            thread::spawn(move || {
                let mut reader = ControlReader::with_leftover(reader, leftover);
                while let Ok(Some(message)) = reader.read_message() {
                    if let ControlMessage::Ping { seq } = message {
                        pings.fetch_add(1, Ordering::Relaxed);
                        if auto_pong.load(Ordering::Relaxed) {
                            let mut writer = writer.lock().unwrap();
                            let _ = protocol::write_control_message(
                                &mut *writer,
                                &ControlMessage::Pong { seq },
                            );
                        }
                        continue;
                    }
                    if tx.send(message).is_err() {
                        break;
                    }
                }
            });
        }
        Self {
            stream,
            writer,
            messages,
            auto_pong,
            pings,
        }
    }

    fn send(&self, message: &ControlMessage) {
        let mut writer = self.writer.lock().unwrap();
        protocol::write_control_message(&mut *writer, message).unwrap();
    }

    fn hello(&self, link_id: &str) {
        self.send(&ControlMessage::Hello(dialer_hello(link_id)));
    }

    fn recv(&self) -> ControlMessage {
        self.messages
            .recv_timeout(WAIT)
            .expect("expected a control message")
    }

    fn expect_error(&self, code: &str) {
        match self.recv() {
            ControlMessage::Error(error) => assert_eq!(error.code, code, "{error:?}"),
            other => panic!("expected error {code}, got {other:?}"),
        }
    }

    fn expect_acceptor_hello(&self, id: &ProfileId) {
        match self.recv() {
            ControlMessage::Hello(hello) => {
                assert_eq!(hello.role, HelloRole::Acceptor);
                assert_eq!(hello.link_id, id.as_str());
                assert_eq!(hello.sessions, vec!["default".to_string()]);
                assert_eq!(hello.link_min, LINK_VERSION_MIN);
                assert_eq!(hello.link_max, LINK_VERSION_MAX);
                assert!(hello.herdr_version.is_some());
                // The hub does not describe its host to the dialing machine.
                assert_eq!((hello.hostname, hello.os, hello.arch), (None, None, None));
            }
            other => panic!("expected acceptor hello, got {other:?}"),
        }
    }

    fn expect_open(&self, kind: StreamKind) -> OpenRequest {
        match self.recv() {
            ControlMessage::Open(open) => {
                assert_eq!(open.kind, kind);
                assert_eq!(open.session, "default");
                assert!(protocol::is_valid_nonce(&open.nonce), "{}", open.nonce);
                open
            }
            other => panic!("expected open, got {other:?}"),
        }
    }

    fn expect_quiet(&self, wait: Duration) {
        if let Ok(message) = self.messages.recv_timeout(wait) {
            panic!("expected no control message, got {message:?}");
        }
    }

    /// Ends the control session's input (the acceptor's stdin).
    fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Write);
    }
}

impl Drop for FakeDialer {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

fn dialer_hello(link_id: &str) -> Hello {
    let mut hello = Hello::local(HelloRole::Dialer, link_id);
    hello.hostname = Some("slave\x1b]0;owned\x07".into());
    hello
}

type Holder = JoinHandle<Result<LinkEnd, Refused>>;

fn start_holder(options: ControlOptions) -> (Holder, FakeDialer) {
    let (acceptor, dialer) = UnixStream::pair().unwrap();
    let input = acceptor.try_clone().unwrap();
    let holder = thread::spawn(move || serve_control(&options, input, acceptor));
    (holder, FakeDialer::new(dialer))
}

fn connect_holder(fixture: &Fixture, options: ControlOptions) -> (Holder, FakeDialer) {
    let (holder, dialer) = start_holder(options);
    dialer.hello(fixture.id.as_str());
    dialer.expect_acceptor_hello(&fixture.id);
    (holder, dialer)
}

fn join<T>(thread: JoinHandle<T>) -> T {
    let deadline = Instant::now() + WAIT;
    while !thread.is_finished() {
        assert!(Instant::now() < deadline, "thread did not finish in time");
        thread::sleep(Duration::from_millis(5));
    }
    thread.join().unwrap()
}

fn refusal_code(holder: Holder) -> String {
    match join(holder) {
        Err(refused) => refused.code,
        Ok(end) => panic!("expected a refusal, got {end:?}"),
    }
}

fn assert_closed_by_peer(stream: &LocalStream) {
    let mut byte = [0_u8; 1];
    match (&*stream).read(&mut byte) {
        Ok(0) => {}
        Err(error) if crate::ipc::is_connection_closed_error(&error) => {}
        other => panic!("expected the connection to be closed, got {other:?}"),
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn invocation_takes_mode_from_argv_or_the_forced_command() {
    let id = "0123456789abcdef0123456789abcdef";
    let link = ProfileId::parse(id).unwrap();
    let control = parse_invocation(
        &args(&["--catalog", "/c/m.json", "--link", id, "--mode", "control"]),
        Some("ignored"),
    )
    .unwrap();
    assert_eq!(
        control,
        Invocation {
            catalog: PathBuf::from("/c/m.json"),
            link_id: link.clone(),
            mode: RequestedMode::Control,
            link_mismatch: false,
        }
    );
    let stream = parse_invocation(
        &args(&["--link", id, "--mode", "stream", "--nonce", NONCE]),
        None,
    )
    .unwrap();
    assert_eq!(
        stream.mode,
        RequestedMode::Stream {
            nonce: NONCE.into()
        }
    );
    assert_eq!(stream.catalog, dial_in_catalog_path());

    let forced = args(&["--catalog", "/c/m.json", "--link", id]);
    let requested = parse_invocation(&forced, Some(&protocol::control_command(&link))).unwrap();
    assert_eq!(requested.mode, RequestedMode::Control);
    assert!(!requested.link_mismatch);
    let requested =
        parse_invocation(&forced, Some(&protocol::stream_command(&link, NONCE))).unwrap();
    assert_eq!(
        requested.mode,
        RequestedMode::Stream {
            nonce: NONCE.into()
        }
    );
    let other = ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap();
    let mismatched = parse_invocation(&forced, Some(&protocol::control_command(&other))).unwrap();
    assert!(mismatched.link_mismatch);
    assert_eq!(mismatched.link_id, link);
}

#[test]
fn invocation_rejects_malformed_arguments_and_requests() {
    let id = "0123456789abcdef0123456789abcdef";
    for (argv, original) in [
        (args(&[]), None),
        (args(&["--link"]), None),
        (args(&["--link", "0123"]), None),
        (
            args(&["--link", id, "--link", id, "--mode", "control"]),
            None,
        ),
        (args(&["--link", id, "--mode", "control", "--extra"]), None),
        (
            args(&["--catalog", "rel.json", "--link", id, "--mode", "control"]),
            None,
        ),
        (args(&["--link", id, "--mode", "shell"]), None),
        (args(&["--link", id, "--mode", "stream"]), None),
        (
            args(&["--link", id, "--mode", "stream", "--nonce", "ABC"]),
            None,
        ),
        (
            args(&["--link", id, "--mode", "control", "--nonce", NONCE]),
            None,
        ),
        (args(&["--link", id, "--nonce", NONCE]), None),
        (args(&["--link", id]), None),
        (args(&["--link", id]), Some("bash -i")),
        (
            args(&["--link", id]),
            Some("herdr link-accept --link x --mode control; rm -rf ~"),
        ),
    ] {
        assert!(
            parse_invocation(&argv, original).is_err(),
            "{argv:?} {original:?} should be rejected"
        );
    }
    let error = parse_invocation(&args(&["--link", id]), Some("evil\x1b[2Jcommand")).unwrap_err();
    assert!(!error.contains('\x1b'), "{error:?}");
}

#[test]
fn hello_validation_refuses_unknown_disabled_mismatched_and_unsupported_links() {
    let fixture = Fixture::new("unknown");
    let other = ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap();
    let options = ControlOptions {
        link_id: other.clone(),
        ..fixture.options()
    };
    let (holder, dialer) = start_holder(options);
    dialer.hello(other.as_str());
    dialer.expect_error(error_code::LINK_UNKNOWN);
    assert_eq!(refusal_code(holder), error_code::LINK_UNKNOWN);
    assert!(!LinkPaths::for_catalog(&fixture.catalog_path, &other)
        .dir
        .exists());

    let fixture = Fixture::with_machine("disabled", false);
    let (holder, dialer) = start_holder(fixture.options());
    dialer.hello(fixture.id.as_str());
    dialer.expect_error(error_code::LINK_DISABLED);
    assert_eq!(refusal_code(holder), error_code::LINK_DISABLED);
    assert!(!fixture.paths.dir.exists());

    let fixture = Fixture::new("mismatch");
    let (holder, dialer) = start_holder(fixture.options());
    dialer.hello(other.as_str());
    dialer.expect_error(error_code::LINK_ID_MISMATCH);
    assert_eq!(refusal_code(holder), error_code::LINK_ID_MISMATCH);

    let (holder, dialer) = start_holder(fixture.options());
    let mut hello = dialer_hello(fixture.id.as_str());
    (hello.link_min, hello.link_max) = (LINK_VERSION_MAX + 1, LINK_VERSION_MAX + 3);
    dialer.send(&ControlMessage::Hello(hello));
    dialer.expect_error(error_code::LINK_VERSION_UNSUPPORTED);
    assert_eq!(refusal_code(holder), error_code::LINK_VERSION_UNSUPPORTED);

    let (holder, dialer) = start_holder(fixture.options());
    let mut hello = dialer_hello(fixture.id.as_str());
    hello.role = HelloRole::Acceptor;
    dialer.send(&ControlMessage::Hello(hello));
    dialer.expect_error(error_code::PROTOCOL_ERROR);
    assert_eq!(refusal_code(holder), error_code::PROTOCOL_ERROR);

    let (holder, dialer) = start_holder(fixture.options());
    dialer.send(&ControlMessage::Open(OpenRequest::stream(
        NONCE.into(),
        StreamKind::Client,
        "default".into(),
    )));
    dialer.expect_error(error_code::PROTOCOL_ERROR);
    assert_eq!(refusal_code(holder), error_code::PROTOCOL_ERROR);
    assert!(!fixture.paths.dir.exists());
}

#[test]
fn missing_hello_and_untrusted_catalog_are_refused() {
    let fixture = Fixture::new("deadline");
    let mut options = fixture.options();
    options.timings.hello_deadline = Duration::from_millis(200);
    let (holder, dialer) = start_holder(options);
    dialer.expect_error(error_code::PROTOCOL_ERROR);
    assert_eq!(refusal_code(holder), error_code::PROTOCOL_ERROR);

    let (holder, dialer) = start_holder(fixture.options());
    dialer.close();
    assert_eq!(refusal_code(holder), end_code::LINK_CLOSED);

    std::fs::set_permissions(
        &fixture.catalog_path,
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let (holder, dialer) = start_holder(fixture.options());
    dialer.hello(fixture.id.as_str());
    dialer.expect_error(error_code::LINK_UNKNOWN);
    assert_eq!(refusal_code(holder), error_code::LINK_UNKNOWN);
    assert!(!fixture.paths.dir.exists());
}

#[test]
fn connected_link_writes_next_epoch_serves_local_ops_and_disconnects_on_eof() {
    use std::os::unix::fs::MetadataExt;

    let fixture = Fixture::new("epoch");
    crate::platform::ensure_private_directory(&fixture.paths.dir).unwrap();
    status::write_status(
        &fixture.paths.status_file,
        &LinkStatus {
            link_epoch: 5,
            last_error: Some(ErrorRecord::new("link_dead", "old")),
            ..LinkStatus::default()
        },
    )
    .unwrap();

    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    let connected = fixture.wait_status(LinkStatus::is_connected);
    assert_eq!(connected.link_epoch, 6);
    assert_eq!(connected.pid, Some(std::process::id()));
    assert!(connected.connected_since_ms.is_some());
    assert_eq!(connected.last_error, None);
    let slave = connected.slave.clone().unwrap();
    assert_eq!(slave.hostname.as_deref(), Some("slave]0;owned"));
    assert_eq!(slave.herdr_version, Some(crate::build_info::version()));
    for path in [
        &fixture.paths.client_socket,
        &fixture.paths.api_socket,
        &fixture.paths.link_socket,
    ] {
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        std::fs::metadata(&fixture.paths.dir).unwrap().mode() & 0o777,
        0o700
    );
    assert!(
        crate::platform::try_lock_exclusive(&fixture.paths.lock_file)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.paths.lock_file)
            .unwrap()
            .trim(),
        std::process::id().to_string()
    );

    let response = fixture.local_request(&LocalRequest::Status).unwrap();
    assert!(response.ok);
    assert_eq!(response.status, Some(connected.clone()));
    let response = fixture.local_request(&LocalRequest::Unknown).unwrap();
    assert_eq!(response.code.as_deref(), Some(local_code::UNSUPPORTED_OP));
    let response = fixture
        .local_request(&LocalRequest::Attach {
            nonce: NONCE.into(),
        })
        .unwrap();
    assert_eq!(response.code.as_deref(), Some(local_code::UNKNOWN_NONCE));
    let stream = fixture.connect(&fixture.paths.link_socket);
    (&stream).write_all(b"{not json\n").unwrap();
    let response = protocol::read_local_response(&mut &stream)
        .unwrap()
        .unwrap();
    assert_eq!(response.code.as_deref(), Some(error_code::PROTOCOL_ERROR));

    // The holder answers the dialer's pings.
    dialer.send(&ControlMessage::Ping { seq: 41 });
    match dialer.recv() {
        ControlMessage::Pong { seq } => assert_eq!(seq, 41),
        other => panic!("expected pong, got {other:?}"),
    }

    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
    let disconnected = fixture.status();
    assert_eq!(disconnected.state, LinkState::Disconnected);
    assert_eq!(disconnected.link_epoch, 6);
    assert_eq!(disconnected.pid, None);
    assert_eq!(disconnected.connected_since_ms, None);
    assert_eq!(
        disconnected.last_error.map(|error| error.code),
        Some(end_code::LINK_CLOSED.to_string())
    );
    assert_eq!(disconnected.slave, connected.slave);
    for path in [
        &fixture.paths.client_socket,
        &fixture.paths.api_socket,
        &fixture.paths.link_socket,
    ] {
        assert!(!path.exists(), "{} should be removed", path.display());
    }
    assert!(
        crate::platform::try_lock_exclusive(&fixture.paths.lock_file)
            .unwrap()
            .is_some()
    );

    // A reconnect increments the epoch again.
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    assert_eq!(fixture.wait_status(LinkStatus::is_connected).link_epoch, 7);
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn newer_dialer_facts_are_recorded_and_unimplemented_extensions_degrade() {
    let fixture = Fixture::new("extensions");
    let (holder, dialer) = start_holder(fixture.options());
    let mut hello = dialer_hello(fixture.id.as_str());
    hello.features = vec!["agent".into(), "future".into()];
    hello.last_dial_error = Some("ssh: connect timed out\x1b[2J".into());
    dialer.send(&ControlMessage::Hello(hello));
    match dialer.recv() {
        ControlMessage::Hello(hello) => {
            assert_eq!(hello.features, protocol::feature::SUPPORTED);
            assert!(!hello.agent_forwarding);
        }
        other => panic!("expected acceptor hello, got {other:?}"),
    }
    let slave = fixture.wait_status(LinkStatus::is_connected).slave.unwrap();
    assert_eq!(slave.features, ["agent", "future"]);
    assert_eq!(
        slave.last_dial_error.as_deref(),
        Some("ssh: connect timed out[2J")
    );

    // Operations this dialer does not advertise are answered, not dropped.
    for (request, code) in [
        (
            LocalRequest::Update {
                size: 1,
                sha256: "00".repeat(32),
                version: None,
            },
            open_failed_code::UPDATE_UNSUPPORTED,
        ),
        (
            LocalRequest::RestartServer {
                session: "default".into(),
            },
            local_code::RESTART_FAILED,
        ),
    ] {
        let response = fixture.local_request(&request).unwrap();
        assert!(!response.ok, "{request:?}");
        assert_eq!(response.code.as_deref(), Some(code));
    }

    // Messages for features the holder does not handle keep the link up.
    dialer.send(&ControlMessage::RestartServerResult {
        request_id: "r".into(),
        ok: true,
        message: String::new(),
    });
    dialer.send(&ControlMessage::AgentForwarding { enabled: true });
    (&dialer.stream)
        .write_all(b"{\"type\":\"from_the_future\",\"x\":1}\n")
        .unwrap();
    dialer.send(&ControlMessage::Ping { seq: 9 });
    match dialer.recv() {
        ControlMessage::Pong { seq } => assert_eq!(seq, 9),
        other => panic!("expected pong, got {other:?}"),
    }
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn agent_leases_follow_their_connections_and_agent_sessions_filter_requests() {
    use std::os::unix::net::UnixListener;

    let fixture = Fixture::new("agent");
    let set_forwarding = |enabled: bool| {
        let mut catalog = DialInCatalog::load_from_path(&fixture.catalog_path).unwrap();
        assert!(catalog.set_agent_forwarding(&fixture.id, enabled));
        catalog.store_to_path(&fixture.catalog_path).unwrap();
    };
    set_forwarding(true);
    let mut options = fixture.options();
    options.timings.catalog_recheck = Duration::from_millis(50);
    let (holder, dialer) = start_holder(options);
    dialer.hello(fixture.id.as_str());
    match dialer.recv() {
        ControlMessage::Hello(hello) => assert!(hello.agent_forwarding),
        other => panic!("expected acceptor hello, got {other:?}"),
    }
    let target = || fixture.local_request(&LocalRequest::AgentTarget).unwrap();
    let peer = crate::platform::local_stream_peer_is_current_user;
    // One agent session over in-memory stdio: (served, bytes after the marker).
    let session = |requests: &[u8]| {
        let mut output = Vec::new();
        let served = agent::serve_agent(&fixture.paths, peer, WAIT, requests, &mut output).unwrap();
        let rest =
            protocol::discard_until_marker(&mut output.as_slice(), MAX_PREAMBLE_BYTES).unwrap();
        (served, rest)
    };
    assert_eq!(target().code.as_deref(), Some(local_code::NO_AGENT));
    assert_eq!(session(&[0, 0, 0, 1, 11]), (false, Vec::new()));

    let agent_path = fixture.root.join("agent.sock");
    let listener = UnixListener::bind(&agent_path).unwrap();
    let not_a_socket = fixture.root.join("plain");
    std::fs::write(&not_a_socket, b"").unwrap();
    for socket in [PathBuf::from("agent.sock"), not_a_socket] {
        let socket = socket.to_string_lossy().into_owned();
        let refused = agent::request_agent_lease(&fixture.paths, &socket, peer, WAIT).unwrap_err();
        assert!(
            refused.to_string().contains(local_code::NO_AGENT),
            "{refused}"
        );
    }
    let lease =
        agent::request_agent_lease(&fixture.paths, agent_path.to_str().unwrap(), peer, WAIT)
            .unwrap();
    fixture.wait_status(|status| status.agent_leases == 1);
    assert_eq!(
        target().agent_socket.as_deref(),
        Some(agent_path.to_str().unwrap())
    );

    // Only the identity listing reaches the agent; removal is refused locally.
    let fake_agent = thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = [0_u8; 5];
        connection.read_exact(&mut request).unwrap();
        connection.write_all(&[0, 0, 0, 5, 12, 0, 0, 0, 0]).unwrap();
        let mut rest = Vec::new();
        connection.read_to_end(&mut rest).unwrap();
        (request, rest, listener)
    });
    let (served, replies) = session(&[0, 0, 0, 1, 19, 0, 0, 0, 1, 11]);
    assert!(served);
    assert_eq!(replies, [0, 0, 0, 1, 5, 0, 0, 0, 5, 12, 0, 0, 0, 0]);
    let (request, rest, listener) = join(fake_agent);
    assert_eq!((request, rest), ([0, 0, 0, 1, 11], Vec::new()));

    // A session still open when its lease ends forwards nothing more.
    let (mut to_session, stdin) = UnixStream::pair().unwrap();
    let paths = fixture.paths.clone();
    let open = thread::spawn(move || agent::serve_agent(&paths, peer, WAIT, stdin, io::sink()));
    let (mut connection, _) = listener.accept().unwrap();
    drop(lease);
    fixture.wait_status(|status| status.agent_leases == 0);
    assert_eq!(target().code.as_deref(), Some(local_code::NO_AGENT));
    to_session.write_all(&[0, 0, 0, 1, 11]).unwrap();
    assert!(join(open).unwrap());
    let mut forwarded = Vec::new();
    connection.read_to_end(&mut forwarded).unwrap();
    assert!(forwarded.is_empty());

    // Turning forwarding off tells the dialer and refuses agent sessions.
    let lease =
        agent::request_agent_lease(&fixture.paths, agent_path.to_str().unwrap(), peer, WAIT)
            .unwrap();
    set_forwarding(false);
    assert_eq!(
        dialer.recv(),
        ControlMessage::AgentForwarding { enabled: false }
    );
    assert_eq!(target().code.as_deref(), Some(local_code::AGENT_DISABLED));
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
    // The link's end closes the leases it held.
    assert_closed_by_peer(&lease);
}

struct StreamSession {
    thread: JoinHandle<io::Result<()>>,
    /// What the stream acceptor writes to its stdout (towards the dialer),
    /// starting with any relay bytes read together with the marker.
    from_hub: io::Chain<io::Cursor<Vec<u8>>, UnixStream>,
    /// What the dialer writes into the stream acceptor's stdin.
    to_hub: UnixStream,
}

fn start_stream(fixture: &Fixture, nonce: &str, peer_check: PeerCheck) -> StreamSession {
    let (stdin, to_hub) = UnixStream::pair().unwrap();
    let (stdout, mut from_hub) = UnixStream::pair().unwrap();
    let paths = fixture.paths.clone();
    let nonce = nonce.to_string();
    let thread =
        thread::spawn(move || serve_stream(&paths, &nonce, peer_check, WAIT, stdin, stdout));
    from_hub.set_read_timeout(Some(WAIT)).unwrap();
    // Bytes the hub sent before attach may arrive in the same read as the
    // marker; the dialer forwards such leftovers first.
    let leftover = protocol::discard_until_marker(&mut from_hub, MAX_PREAMBLE_BYTES).unwrap();
    StreamSession {
        thread,
        from_hub: io::Cursor::new(leftover).chain(from_hub),
        to_hub,
    }
}

fn relay_round_trip(fixture: &Fixture, dialer: &FakeDialer, socket: &Path, kind: StreamKind) {
    let hub = fixture.connect(socket);
    // The hub client may speak first; bytes wait in the socket until attach.
    (&hub).write_all(b"endpoint-hello").unwrap();
    let open = dialer.expect_open(kind);
    let mut session = start_stream(
        fixture,
        &open.nonce,
        crate::platform::local_stream_peer_is_current_user,
    );

    let mut received = [0_u8; 14];
    session.from_hub.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"endpoint-hello");
    session.to_hub.write_all(b"slave-reply").unwrap();
    let mut reply = [0_u8; 11];
    (&hub).read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"slave-reply");

    // Half-close towards the slave: the stream acceptor closes its stdout
    // but keeps relaying the slave's answer.
    crate::platform::shutdown_local_stream(&hub, Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    session.from_hub.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    session.to_hub.write_all(b"late").unwrap();
    let mut late = [0_u8; 4];
    (&hub).read_exact(&mut late).unwrap();
    assert_eq!(&late, b"late");

    session.to_hub.shutdown(Shutdown::Write).unwrap();
    assert_closed_by_peer(&hub);
    join(session.thread).unwrap();
    // The nonce is single-use.
    let response = fixture
        .local_request(&LocalRequest::Attach { nonce: open.nonce })
        .unwrap();
    assert_eq!(response.code.as_deref(), Some(local_code::UNKNOWN_NONCE));
}

#[test]
fn pending_open_relays_bytes_both_ways_through_a_stream_session() {
    let fixture = Fixture::new("relay");
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    relay_round_trip(
        &fixture,
        &dialer,
        &fixture.paths.client_socket,
        StreamKind::Client,
    );
    relay_round_trip(
        &fixture,
        &dialer,
        &fixture.paths.api_socket,
        StreamKind::Api,
    );

    // Closing the link tears down attached relays too.
    let hub = fixture.connect(&fixture.paths.client_socket);
    let open = dialer.expect_open(StreamKind::Client);
    let mut session = start_stream(
        &fixture,
        &open.nonce,
        crate::platform::local_stream_peer_is_current_user,
    );
    (&hub).write_all(b"x").unwrap();
    let mut attached = [0_u8; 1];
    session.from_hub.read_exact(&mut attached).unwrap();
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
    assert_closed_by_peer(&hub);
    let mut rest = Vec::new();
    session.from_hub.read_to_end(&mut rest).unwrap();
    drop(session.to_hub);
    join(session.thread).unwrap();
}

#[test]
fn update_and_restart_requests_reach_the_dialer() {
    let fixture = Fixture::new("update");
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    // Malformed requests are refused before the dialer hears of them.
    for (size, sha256, version) in [(0, "ab", None), (9, "AB", None), (9, "ab", Some("9 9"))] {
        let request = LocalRequest::Update {
            size,
            sha256: sha256.repeat(32),
            version: version.map(Into::into),
        };
        let response = fixture.local_request(&request).unwrap();
        assert_eq!(response.code.as_deref(), Some(local_code::UPDATE_REJECTED));
    }
    let restart = LocalRequest::RestartServer {
        session: "bad name".into(),
    };
    let response = fixture.local_request(&restart).unwrap();
    assert_eq!(response.code.as_deref(), Some(local_code::RESTART_FAILED));
    dialer.expect_quiet(Duration::from_millis(200));

    // The update's link.sock connection is the hub side of an update stream.
    let paths = fixture.paths.clone();
    let client = thread::spawn(move || {
        update::send_update(
            &paths,
            &mut &b"new herdr"[..],
            9,
            &"ab".repeat(32),
            Some("9.9.9"),
        )
    });
    let open = match dialer.recv() {
        ControlMessage::Open(open) => open,
        other => panic!("expected an update open, got {other:?}"),
    };
    assert_eq!((open.kind, open.session.as_str()), (StreamKind::Update, ""));
    assert_eq!(
        (open.size, open.version.as_deref()),
        (Some(9), Some("9.9.9"))
    );
    assert_eq!(open.sha256, Some("ab".repeat(32)));
    let mut session = start_stream(
        &fixture,
        &open.nonce,
        crate::platform::local_stream_peer_is_current_user,
    );
    let mut received = [0_u8; 9];
    session.from_hub.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"new herdr");
    let installed = protocol::UpdateResult {
        ok: true,
        code: None,
        message: None,
        version: Some("9.9.9".into()),
    };
    protocol::write_json_line(&mut session.to_hub, &installed).unwrap();
    session.to_hub.shutdown(Shutdown::Write).unwrap();
    assert_eq!(join(client).unwrap(), installed);
    join(session.thread).unwrap();

    // Restarts are relayed, and answered with the dialer's sanitized result.
    let paths = fixture.paths.clone();
    let client = thread::spawn(move || update::restart_server(&paths, "default"));
    let ControlMessage::RestartServer {
        request_id,
        session,
    } = dialer.recv()
    else {
        panic!("expected a restart request");
    };
    assert_eq!(session, "default");
    dialer.send(&ControlMessage::RestartServerResult {
        request_id,
        ok: false,
        message: "stop \x1b[2Jtimed out".into(),
    });
    let response = join(client).unwrap();
    assert_eq!(response.code.as_deref(), Some(local_code::RESTART_FAILED));
    assert_eq!(response.message.as_deref(), Some("stop [2Jtimed out"));

    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn open_failed_and_open_timeout_close_the_pending_connection_and_record_it() {
    let fixture = Fixture::new("openfail");
    let mut options = fixture.options();
    options.timings.open_timeout = Duration::from_millis(400);
    let (holder, dialer) = connect_holder(&fixture, options);

    let hub = fixture.connect(&fixture.paths.client_socket);
    let open = dialer.expect_open(StreamKind::Client);
    dialer.send(&ControlMessage::OpenFailed(OpenFailed {
        nonce: open.nonce.clone(),
        code: open_failed_code::BRIDGE_FAILED.into(),
        message: "bridge \x1b[31mexploded\nbadly".into(),
    }));
    assert_closed_by_peer(&hub);
    let status = fixture.wait_status(|status| {
        status
            .last_stream_error
            .as_ref()
            .is_some_and(|error| error.code == open_failed_code::BRIDGE_FAILED)
    });
    assert!(status.is_connected());
    assert_eq!(
        status.last_stream_error.unwrap().message,
        "bridge [31mexploded badly"
    );

    let started = Instant::now();
    let hub = fixture.connect(&fixture.paths.api_socket);
    let open = dialer.expect_open(StreamKind::Api);
    assert_closed_by_peer(&hub);
    assert!(started.elapsed() >= Duration::from_millis(400));
    let status = fixture.wait_status(|status| {
        status
            .last_stream_error
            .as_ref()
            .is_some_and(|error| error.code == open_failed_code::STREAM_TIMEOUT)
    });
    assert!(status.is_connected());
    let response = fixture
        .local_request(&LocalRequest::Attach { nonce: open.nonce })
        .unwrap();
    assert_eq!(response.code.as_deref(), Some(local_code::UNKNOWN_NONCE));

    // A late OpenFailed for an attached or expired stream is still recorded.
    dialer.send(&ControlMessage::OpenFailed(OpenFailed {
        nonce: NONCE.into(),
        code: open_failed_code::SERVER_NEEDS_UPDATE.into(),
        message: "needs one final update".into(),
    }));
    fixture.wait_status(|status| {
        status
            .last_stream_error
            .as_ref()
            .is_some_and(|error| error.code == open_failed_code::SERVER_NEEDS_UPDATE)
    });

    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
    // The final status keeps the latest stream error.
    assert_eq!(
        fixture.status().last_stream_error.map(|error| error.code),
        Some(open_failed_code::SERVER_NEEDS_UPDATE.to_string())
    );
}

#[test]
fn connections_from_other_users_are_refused() {
    let fixture = Fixture::new("peer");
    let options = ControlOptions {
        peer_check: deny_peer,
        ..fixture.options()
    };
    let (holder, dialer) = connect_holder(&fixture, options);
    let hub = fixture.connect(&fixture.paths.client_socket);
    assert_closed_by_peer(&hub);
    dialer.expect_quiet(Duration::from_millis(300));
    assert_eq!(fixture.local_request(&LocalRequest::Status), None);

    // The stream acceptor refuses a link socket owned by someone else.
    let (stdin, _to_hub) = UnixStream::pair().unwrap();
    let (stdout, _from_hub) = UnixStream::pair().unwrap();
    let error = serve_stream(&fixture.paths, NONCE, deny_peer, WAIT, stdin, stdout).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let shown = stream_failure_message(&error);
    assert!(shown.contains("not private"), "{shown}");
    assert!(!shown.contains(&*fixture.root.to_string_lossy()), "{shown}");
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);

    // Without a holder the stream acceptor reports an inactive link.
    let (stdin, _to_hub) = UnixStream::pair().unwrap();
    let (stdout, _from_hub) = UnixStream::pair().unwrap();
    let error = serve_stream(
        &fixture.paths,
        NONCE,
        crate::platform::local_stream_peer_is_current_user,
        WAIT,
        stdin,
        stdout,
    )
    .unwrap_err();
    let shown = stream_failure_message(&error);
    assert!(shown.contains("no active link"), "{shown}");
    assert!(!shown.contains(&*fixture.root.to_string_lossy()), "{shown}");
}

#[test]
fn stream_refusals_from_the_holder_reach_the_dialer_without_hub_paths() {
    let fixture = Fixture::new("refusal");
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    let (stdin, _to_hub) = UnixStream::pair().unwrap();
    let (stdout, _from_hub) = UnixStream::pair().unwrap();
    let error = serve_stream(
        &fixture.paths,
        NONCE,
        crate::platform::local_stream_peer_is_current_user,
        WAIT,
        stdin,
        stdout,
    )
    .unwrap_err();
    let shown = stream_failure_message(&error);
    assert!(shown.contains(local_code::UNKNOWN_NONCE), "{shown}");
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);

    assert!(stream_failure_message(&io::Error::other(format!(
        "{}: secret",
        fixture.paths.dir.display()
    )))
    .starts_with("the hub could not relay"));
}

#[test]
fn live_holder_answers_busy_to_a_superseding_link() {
    let fixture = Fixture::new("busy");
    let options = |addr: &str| ControlOptions {
        peer_addr: Some(addr.into()),
        ..fixture.options()
    };
    let (first, first_dialer) = connect_holder(&fixture, options("192.0.2.1"));
    assert_eq!(fixture.wait_status(LinkStatus::is_connected).link_epoch, 1);

    let (second, second_dialer) = start_holder(options("192.0.2.2"));
    second_dialer.hello(fixture.id.as_str());
    second_dialer.expect_error(error_code::LINK_BUSY);
    assert_eq!(refusal_code(second), error_code::LINK_BUSY);
    assert!(first_dialer.pings.load(Ordering::Relaxed) >= 1);

    // A second machine claiming the live link is a conflict.
    let status = fixture.wait_status(|status| status.claim_conflict.is_some());
    assert_eq!(
        status.claim_conflict.as_deref(),
        Some("link claimed by more than one machine (192.0.2.1, 192.0.2.2)")
    );
    assert!(status.is_connected());
    assert_eq!(status.link_epoch, 1);
    assert!(fixture.local_request(&LocalRequest::Status).unwrap().ok);
    first_dialer.close();
    assert_eq!(join(first).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn unresponsive_holder_yields_to_a_superseding_link() {
    let fixture = Fixture::new("yield");
    let (first, first_dialer) = connect_holder(&fixture, fixture.options());
    first_dialer.auto_pong.store(false, Ordering::Relaxed);
    let stale_hub = fixture.connect(&fixture.paths.client_socket);
    let _ = first_dialer.expect_open(StreamKind::Client);

    let (second, second_dialer) = connect_holder(&fixture, fixture.options());
    assert_eq!(join(first).unwrap(), LinkEnd::Superseded);
    first_dialer.expect_error(error_code::SHUTTING_DOWN);
    assert_closed_by_peer(&stale_hub);
    let status = fixture.wait_status(|status| status.is_connected() && status.link_epoch == 2);
    assert_eq!(status.last_error, None);

    // The successor serves its own sockets.
    let _hub = fixture.connect(&fixture.paths.client_socket);
    let _ = second_dialer.expect_open(StreamKind::Client);
    first_dialer.expect_quiet(Duration::from_millis(100));

    second_dialer.close();
    assert_eq!(join(second).unwrap(), LinkEnd::DialerClosed);
    let status = fixture.status();
    assert_eq!(status.state, LinkState::Disconnected);
    assert_eq!(status.link_epoch, 2);
}

#[test]
fn takeovers_from_two_addresses_flag_a_claim_conflict_until_the_link_stays_up() {
    let fixture = Fixture::new("claim");
    crate::platform::ensure_private_directory(&fixture.paths.dir).unwrap();
    let earlier = status::now_ms() - 1_000;
    status::write_status(
        &fixture.paths.status_file,
        &LinkStatus {
            recent_supersedes: ["192.0.2.1", "192.0.2.2"]
                .map(|addr| status::SupersedeRecord {
                    at_ms: earlier,
                    peer_addr: Some(addr.into()),
                })
                .to_vec(),
            ..LinkStatus::default()
        },
    )
    .unwrap();
    let options = |addr: &str| ControlOptions {
        peer_addr: Some(addr.into()),
        ..fixture.options()
    };
    let (first, first_dialer) = connect_holder(&fixture, options("192.0.2.1"));
    let status = fixture.wait_status(LinkStatus::is_connected);
    assert_eq!(status.peer_addr.as_deref(), Some("192.0.2.1"));
    assert_eq!(status.recent_supersedes.len(), 2, "no takeover yet");
    assert_eq!(status.claim_conflict, None);

    first_dialer.auto_pong.store(false, Ordering::Relaxed);
    let mut second_options = options("192.0.2.2");
    second_options.timings.claim_clear_after = Duration::from_millis(500);
    let (second, second_dialer) = connect_holder(&fixture, second_options);
    assert_eq!(join(first).unwrap(), LinkEnd::Superseded);
    let status = fixture.wait_status(|status| status.link_epoch == 2);
    assert_eq!(status.recent_supersedes.len(), 3);
    assert_eq!(
        status.recent_supersedes[2].peer_addr.as_deref(),
        Some("192.0.2.2")
    );
    assert_eq!(
        status.claim_conflict.as_deref(),
        Some("link claimed by more than one machine (192.0.2.1, 192.0.2.2)")
    );
    // The link stays up: the conflict clears.
    fixture.wait_status(|status| status.is_connected() && status.claim_conflict.is_none());
    second_dialer.close();
    assert_eq!(join(second).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn silent_dialer_is_pinged_then_declared_dead() {
    let fixture = Fixture::new("dead");
    let mut options = fixture.options();
    options.timings.ping_idle = Duration::from_millis(100);
    options.timings.dead_after = Duration::from_millis(600);
    let (holder, dialer) = connect_holder(&fixture, options);
    dialer.auto_pong.store(false, Ordering::Relaxed);
    dialer.expect_error(error_code::SHUTTING_DOWN);
    assert_eq!(join(holder).unwrap(), LinkEnd::Dead);
    assert!(dialer.pings.load(Ordering::Relaxed) >= 2);
    assert_eq!(
        fixture.status().last_error.map(|error| error.code),
        Some(end_code::LINK_DEAD.to_string())
    );

    // Answering pings keeps the link alive past dead_after.
    let mut options = fixture.options();
    options.timings.ping_idle = Duration::from_millis(100);
    options.timings.dead_after = Duration::from_millis(600);
    let (holder, dialer) = connect_holder(&fixture, options);
    dialer.expect_quiet(Duration::from_millis(1200));
    assert!(!holder.is_finished());
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn disabling_or_removing_the_machine_shuts_the_link_down() {
    let fixture = Fixture::new("disable");
    let mut options = fixture.options();
    options.timings.catalog_recheck = Duration::from_millis(100);
    let (holder, dialer) = connect_holder(&fixture, options.clone());
    fixture.set_enabled(false);
    dialer.expect_error(error_code::LINK_DISABLED);
    assert_eq!(join(holder).unwrap(), LinkEnd::Disabled);
    let status = fixture.status();
    assert_eq!(status.state, LinkState::Disconnected);
    assert_eq!(
        status.last_error.map(|error| error.code),
        Some(error_code::LINK_DISABLED.to_string())
    );

    fixture.set_enabled(true);
    let (holder, dialer) = connect_holder(&fixture, options);
    std::fs::remove_file(&fixture.catalog_path).unwrap();
    dialer.expect_error(error_code::LINK_DISABLED);
    assert_eq!(join(holder).unwrap(), LinkEnd::Disabled);
}

#[test]
fn dialer_error_and_garbage_end_the_link() {
    let fixture = Fixture::new("garbage");
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    dialer.send(&ControlMessage::Error(LinkError::new(
        "dialer_stopping",
        "bye\x1b[2J",
    )));
    assert_eq!(
        join(holder).unwrap(),
        LinkEnd::DialerError {
            code: "dialer_stopping".into(),
            message: "bye\x1b[2J".into()
        }
    );
    let error = fixture.status().last_error.unwrap();
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("dialer_stopping", "bye[2J")
    );

    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    // Unknown message types are ignored; malformed lines end the link.
    dialer
        .writer
        .lock()
        .unwrap()
        .write_all(b"{\"type\":\"future\",\"x\":1}\n{\"type\":\"ping\"}\n")
        .unwrap();
    dialer.expect_error(error_code::PROTOCOL_ERROR);
    assert!(matches!(join(holder).unwrap(), LinkEnd::ProtocolError(_)));
}

#[test]
fn shutdown_removes_only_socket_files_it_still_owns() {
    let fixture = Fixture::new("owned");
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    // Something else takes over client.sock while the holder runs. (The
    // holder's accept thread on the unlinked socket is left blocked.)
    std::fs::remove_file(&fixture.paths.client_socket).unwrap();
    let replacement =
        crate::ipc::bind_private_local_listener(&fixture.paths.client_socket).unwrap();
    let replacement_identity =
        crate::ipc::socket_file_identity(&fixture.paths.client_socket).unwrap();

    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
    assert_eq!(
        crate::ipc::socket_file_identity(&fixture.paths.client_socket).unwrap(),
        replacement_identity
    );
    assert!(!fixture.paths.api_socket.exists());
    assert!(!fixture.paths.link_socket.exists());
    drop(replacement);
}

#[test]
fn stale_socket_files_from_a_dead_holder_are_replaced() {
    let fixture = Fixture::new("stale");
    crate::platform::ensure_private_directory(&fixture.paths.dir).unwrap();
    for path in [&fixture.paths.client_socket, &fixture.paths.link_socket] {
        drop(crate::ipc::bind_private_local_listener(path).unwrap());
        assert!(path.exists());
    }
    let (holder, dialer) = connect_holder(&fixture, fixture.options());
    assert!(fixture.local_request(&LocalRequest::Status).unwrap().ok);
    dialer.close();
    assert_eq!(join(holder).unwrap(), LinkEnd::DialerClosed);
}

#[test]
fn link_end_records_and_notices_are_stable() {
    let timings = Timings::default();
    assert_eq!(
        LinkEnd::Dead.record(&timings),
        (
            end_code::LINK_DEAD.to_string(),
            "no traffic from the machine for 20s".to_string()
        )
    );
    assert_eq!(LinkEnd::DialerClosed.notice(), None);
    assert_eq!(
        LinkEnd::Disabled.notice().map(|error| error.code),
        Some(error_code::LINK_DISABLED.to_string())
    );
    assert_eq!(
        LinkEnd::Terminated.record(&timings).0,
        end_code::ACCEPTOR_STOPPED
    );
    assert_eq!(
        LinkEnd::Terminated.notice().map(|error| error.code),
        Some(error_code::SHUTTING_DOWN.to_string())
    );
    assert_eq!(format_duration(Duration::from_millis(1500)), "1500ms");
    assert_eq!(format_duration(Duration::from_secs(15)), "15s");
}

#[test]
fn termination_signal_ends_the_link_and_cleans_up() {
    let fixture = Fixture::new("term");
    let (acceptor, dialer) = UnixStream::pair().unwrap();
    let input = acceptor.try_clone().unwrap();
    let (events_tx, events) = mpsc::channel();
    let terminate = events_tx.clone();
    let options = fixture.options();
    let holder = thread::spawn(move || {
        serve_control_with_events(&options, input, acceptor, (events_tx, events))
    });
    let dialer = FakeDialer::new(dialer);
    dialer.hello(fixture.id.as_str());
    dialer.expect_acceptor_hello(&fixture.id);
    fixture.wait_status(LinkStatus::is_connected);

    terminate.send(Event::Terminate).unwrap();
    assert_eq!(join(holder).unwrap(), LinkEnd::Terminated);
    dialer.expect_error(error_code::SHUTTING_DOWN);
    let status = fixture.status();
    assert!(!status.is_connected());
    assert_eq!(status.pid, None);
    assert_eq!(
        status.last_error.map(|error| error.code),
        Some(end_code::ACCEPTOR_STOPPED.to_string())
    );
    for socket in [
        &fixture.paths.link_socket,
        &fixture.paths.client_socket,
        &fixture.paths.api_socket,
    ] {
        assert!(!socket.exists(), "{} was left behind", socket.display());
    }
}

/// A control session writer that blocks while `stall` is set, like a pipe
/// whose reader stopped reading, until `release` makes it fail.
struct StallingWriter {
    inner: UnixStream,
    stall: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

impl Write for StallingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        while self.stall.load(Ordering::SeqCst) {
            if self.release.load(Ordering::SeqCst) {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.inner.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct StalledLink {
    holder: Holder,
    dialer: FakeDialer,
    stall: Arc<AtomicBool>,
    _release: ReleaseOnDrop,
}

/// Lets the stalled writer thread fail and exit when the test ends.
struct ReleaseOnDrop(Arc<AtomicBool>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn start_stallable_holder(fixture: &Fixture, options: ControlOptions) -> StalledLink {
    let (acceptor, dialer) = UnixStream::pair().unwrap();
    let input = acceptor.try_clone().unwrap();
    let stall = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let output = StallingWriter {
        inner: acceptor,
        stall: Arc::clone(&stall),
        release: Arc::clone(&release),
    };
    let holder = thread::spawn(move || serve_control(&options, input, output));
    let dialer = FakeDialer::new(dialer);
    dialer.hello(fixture.id.as_str());
    dialer.expect_acceptor_hello(&fixture.id);
    fixture.wait_status(LinkStatus::is_connected);
    StalledLink {
        holder,
        dialer,
        stall,
        _release: ReleaseOnDrop(release),
    }
}

#[test]
fn a_dialer_that_floods_pings_without_reading_ends_the_link() {
    let fixture = Fixture::new("flood");
    let link = start_stallable_holder(&fixture, fixture.options());
    link.stall.store(true, Ordering::SeqCst);
    // Every ping queues a pong the stalled writer never takes.
    for seq in 0..(WRITER_QUEUE as u64 + 64) {
        link.dialer.send(&ControlMessage::Ping { seq });
    }
    let deadline = Instant::now() + WAIT;
    while !link.holder.is_finished() {
        assert!(Instant::now() < deadline, "the flooded link did not end");
        thread::sleep(Duration::from_millis(5));
    }
    let StalledLink { holder, .. } = link;
    match holder.join().unwrap() {
        Ok(LinkEnd::ControlFailed(message)) => {
            assert!(message.contains("not reading"), "{message}")
        }
        other => panic!("expected a control failure, got {other:?}"),
    }
    assert!(!fixture.status().is_connected());
}

#[test]
fn a_stalled_control_write_ends_the_link_even_while_pings_arrive() {
    let fixture = Fixture::new("stall");
    let mut options = fixture.options();
    options.timings.dead_after = Duration::from_millis(400);
    let link = start_stallable_holder(&fixture, options);
    link.stall.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let mut seq = 0;
    while !link.holder.is_finished() {
        assert!(started.elapsed() < WAIT, "the stalled link did not end");
        // Incoming traffic alone must not keep a stalled link alive.
        link.dialer.send(&ControlMessage::Ping { seq });
        seq += 1;
        thread::sleep(Duration::from_millis(40));
    }
    let StalledLink { holder, .. } = link;
    match holder.join().unwrap() {
        Ok(LinkEnd::ControlFailed(message)) => assert!(message.contains("stalled"), "{message}"),
        other => panic!("expected a control failure, got {other:?}"),
    }
}
