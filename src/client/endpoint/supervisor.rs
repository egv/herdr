use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{
    ClientEndpointId, ClientEndpointStatus, DialInMachine, EndpointNegotiation,
    NativeEndpointTransport, SavedSshEndpoint, ViaMachine,
};
use crate::protocol::{ClientSurfaceSize, RenderEncoding};
use crate::remote::link::status::{read_status, ErrorRecord, LinkStatus};
use crate::remote::LinkPaths;
use interprocess::TryClone as _;

mod via;
pub(crate) use via::take_relay_poll_request;

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(120);
const MAX_LOCAL_RETRY_DELAY: Duration = Duration::from_secs(30);
/// Dial-in links are cheap local socket probes and come back on their own.
const MAX_DIAL_IN_RETRY_DELAY: Duration = Duration::from_secs(10);
const STABLE_CONNECTION_PERIOD: Duration = Duration::from_secs(60);
/// The link holder records a stream failure (coalesced to one write per
/// second) after the hub connection has already ended; wait this long for it.
const DIAL_IN_STREAM_ERROR_GRACE: Duration = Duration::from_millis(1500);
const DIAL_IN_STREAM_ERROR_POLL: Duration = Duration::from_millis(100);
const DIAL_IN_OFFLINE_MESSAGE: &str = "offline; waiting for it to dial in";

#[derive(Clone, Copy)]
pub(crate) struct EndpointConnectOptions {
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    pub(crate) cell_width_px: u32,
    pub(crate) cell_height_px: u32,
    pub(crate) pixel_geometry_exact: bool,
    pub(crate) surface_size: ClientSurfaceSize,
    pub(crate) endpoint_keybindings: bool,
    pub(crate) mouse_capture: bool,
}

pub(crate) enum EndpointSupervisorEvent {
    Status {
        endpoint_id: ClientEndpointId,
        generation: u64,
        status: ClientEndpointStatus,
        message: String,
    },
    Connected {
        endpoint_id: ClientEndpointId,
        generation: u64,
        reader: crate::ipc::LocalStream,
        writer: NativeEndpointTransport,
        negotiation: EndpointNegotiation,
    },
}

#[derive(Clone)]
enum ConnectTarget {
    Local(PathBuf),
    Ssh(SavedSshEndpoint),
    DialIn {
        machine: DialInMachine,
        paths: LinkPaths,
    },
    /// A relay hub's dial-in machine, through `herdr link-connect` on the hub.
    Via(ViaMachine),
}

impl ConnectTarget {
    fn dial_in(machine: &DialInMachine) -> Self {
        Self::DialIn {
            machine: machine.clone(),
            paths: machine.paths(),
        }
    }

    fn max_retry_delay(&self) -> Duration {
        match self {
            Self::Local(_) => MAX_LOCAL_RETRY_DELAY,
            Self::Ssh(_) => MAX_RETRY_DELAY,
            Self::DialIn { .. } => MAX_DIAL_IN_RETRY_DELAY,
            Self::Via(_) => via::MAX_VIA_RETRY_DELAY,
        }
    }
}

struct ReconnectState {
    target: ConnectTarget,
    attempts: u32,
    next_attempt: Option<Instant>,
    in_flight: bool,
    generation: Option<u64>,
    online_since: Option<Instant>,
}

impl ReconnectState {
    fn new(target: ConnectTarget, now: Instant) -> Self {
        Self {
            target,
            attempts: 0,
            next_attempt: Some(now),
            in_flight: false,
            generation: None,
            online_since: None,
        }
    }
}

pub(crate) struct EndpointSupervisors {
    endpoints: HashMap<ClientEndpointId, ReconnectState>,
    next_generation: u64,
    shutdown: Arc<AtomicBool>,
}

impl EndpointSupervisors {
    pub(crate) fn new(
        profiles: &[SavedSshEndpoint],
        dial_in: &[DialInMachine],
        now: Instant,
    ) -> Self {
        let mut supervisors = Self {
            endpoints: HashMap::new(),
            next_generation: 2,
            shutdown: Arc::new(AtomicBool::new(false)),
        };
        supervisors.reconcile_profiles(profiles, dial_in, now);
        supervisors
    }

    pub(crate) fn add_local(&mut self, path: PathBuf, generation: Option<u64>, now: Instant) {
        let mut state = ReconnectState::new(ConnectTarget::Local(path), now);
        state.generation = generation;
        if generation.is_some() {
            state.next_attempt = None;
        }
        self.endpoints.insert(ClientEndpointId::Local, state);
    }

    /// Applies a catalog change. Machines that were removed, disabled, or now
    /// point at another destination (SSH target or session) are retired so
    /// their late connections are fenced; renames keep their connection.
    pub(crate) fn reconcile_profiles(
        &mut self,
        profiles: &[SavedSshEndpoint],
        dial_in: &[DialInMachine],
        now: Instant,
    ) -> Vec<ClientEndpointId> {
        let ssh_id = |id: &super::ProfileId| profiles.iter().any(|profile| &profile.id == id);
        let mut retired = Vec::new();
        self.endpoints.retain(|endpoint_id, state| {
            let keep = match &state.target {
                ConnectTarget::Local(_) => true,
                // Relay listings reconcile via machines (`reconcile_via`), but
                // a saved machine takes over a colliding id.
                ConnectTarget::Via(previous) => {
                    !ssh_id(&previous.id)
                        && !dial_in
                            .iter()
                            .any(|machine| machine.enabled && machine.id == previous.id)
                }
                ConnectTarget::Ssh(previous) => profiles.iter().any(|profile| {
                    profile.id == previous.id
                        && profile.enabled
                        && profile.target == previous.target
                        && profile.session == previous.session
                }),
                // An SSH profile keeps a colliding id; see `dial_in_without_id_collisions`.
                ConnectTarget::DialIn {
                    machine: previous, ..
                } => {
                    !ssh_id(&previous.id)
                        && dial_in.iter().any(|machine| {
                            machine.id == previous.id
                                && machine.enabled
                                && machine.session == previous.session
                        })
                }
            };
            if !keep {
                retired.push(endpoint_id.clone());
            }
            keep
        });
        let targets = profiles
            .iter()
            .filter(|profile| profile.enabled)
            .map(|profile| (profile.id.clone(), ConnectTarget::Ssh(profile.clone())))
            .chain(
                dial_in
                    .iter()
                    .filter(|machine| machine.enabled && !ssh_id(&machine.id))
                    .map(|machine| (machine.id.clone(), ConnectTarget::dial_in(machine))),
            );
        for (id, target) in targets {
            match self.endpoints.entry(ClientEndpointId::Ssh(id)) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().target = target;
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ReconnectState::new(target, now));
                }
            }
        }
        retired
    }

    /// A dial-in machine just (re)connected its link: retry it now instead of
    /// waiting out its backoff. No-op while an attempt is in flight or the
    /// endpoint is online. Returns whether an attempt was scheduled.
    pub(crate) fn wake(&mut self, endpoint_id: &ClientEndpointId, now: Instant) -> bool {
        let Some(state) = self.endpoints.get_mut(endpoint_id) else {
            return false;
        };
        if state.in_flight || state.online_since.is_some() {
            return false;
        }
        state.attempts = 0;
        state.next_attempt = Some(now);
        true
    }

    pub(crate) fn spawn_due(
        &mut self,
        now: Instant,
        options: EndpointConnectOptions,
        event_tx: &tokio::sync::mpsc::Sender<EndpointSupervisorEvent>,
    ) {
        for (endpoint_id, state) in &mut self.endpoints {
            if state.in_flight || state.next_attempt.is_none_or(|deadline| deadline > now) {
                continue;
            }
            state.in_flight = true;
            state.next_attempt = None;
            let generation = self.next_generation;
            state.generation = Some(generation);
            self.next_generation = self.next_generation.saturating_add(1);
            let endpoint_id = endpoint_id.clone();
            let target = state.target.clone();
            let event_tx = event_tx.clone();
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                if shutdown.load(Ordering::Acquire) {
                    return;
                }
                let task_endpoint_id = endpoint_id.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let attempt_started_ms = crate::remote::link::status::now_ms();
                    connect_once(&target, options, endpoint_id.clone(), generation).unwrap_or_else(
                        |error| {
                            let (status, message) =
                                classify_failure(&target, &error, attempt_started_ms);
                            EndpointSupervisorEvent::Status {
                                endpoint_id,
                                generation,
                                status,
                                message,
                            }
                        },
                    )
                })
                .await;
                let event = match result {
                    Ok(event) => event,
                    Err(error) => EndpointSupervisorEvent::Status {
                        endpoint_id: task_endpoint_id,
                        generation,
                        status: ClientEndpointStatus::Reconnecting,
                        message: format!("endpoint connection task stopped unexpectedly: {error}"),
                    },
                };
                if !shutdown.load(Ordering::Acquire) {
                    let _ = event_tx.send(event).await;
                }
            });
        }
    }

    pub(crate) fn record_status(
        &mut self,
        endpoint_id: &ClientEndpointId,
        generation: u64,
        status: ClientEndpointStatus,
        now: Instant,
    ) -> bool {
        let Some(state) = self.endpoints.get_mut(endpoint_id) else {
            return false;
        };
        if state.generation != Some(generation) {
            return false;
        }
        state.in_flight = false;
        match status {
            ClientEndpointStatus::Online => {
                if endpoint_id.is_local() {
                    state.attempts = 0;
                }
                state.online_since.get_or_insert(now);
                state.next_attempt = None;
            }
            ClientEndpointStatus::Attention => {
                state.online_since = None;
                // Authentication or configuration may be repaired outside this client.
                state.next_attempt =
                    (!endpoint_id.is_local()).then_some(now + Duration::from_secs(30));
            }
            ClientEndpointStatus::Disabled => {
                state.online_since = None;
                state.next_attempt = None;
            }
            ClientEndpointStatus::Connecting | ClientEndpointStatus::Reconnecting => {
                // A brief maintenance wake can complete a handshake without restoring the link.
                if state.online_since.take().is_some_and(|connected| {
                    now.saturating_duration_since(connected) >= STABLE_CONNECTION_PERIOD
                }) {
                    state.attempts = 0;
                }
                state.attempts = state.attempts.saturating_add(1);
                let delay = retry_delay(state.attempts).min(state.target.max_retry_delay());
                state.next_attempt = Some(now + delay);
            }
        }
        true
    }

    pub(crate) fn disconnected(
        &mut self,
        endpoint_id: &ClientEndpointId,
        generation: u64,
        now: Instant,
    ) -> bool {
        self.record_status(
            endpoint_id,
            generation,
            ClientEndpointStatus::Reconnecting,
            now,
        )
    }
}

impl Drop for EndpointSupervisors {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

fn connect_once(
    target: &ConnectTarget,
    options: EndpointConnectOptions,
    endpoint_id: ClientEndpointId,
    generation: u64,
) -> Result<EndpointSupervisorEvent, std::io::Error> {
    let mut via_bridge = None;
    let (mut stream, lifetime): (_, Box<dyn Send>) = match target {
        ConnectTarget::Local(path) => {
            let stream = crate::ipc::connect_local_stream(path).map_err(|error| {
                // An absent Local socket is transient, unlike a missing SSH install.
                if error.kind() == std::io::ErrorKind::NotFound {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "Local is unavailable; start its server to reconnect",
                    )
                } else {
                    error
                }
            })?;
            (stream, Box::new(()))
        }
        ConnectTarget::Ssh(profile) => {
            let connected = crate::remote::connect_saved_ssh(
                profile.id.as_str(),
                &profile.target,
                &profile.session,
            )?;
            (connected.stream, Box::new(connected.bridge))
        }
        ConnectTarget::DialIn { machine, paths } => {
            let stream = connect_dial_in(paths)?;
            // Held with the transport: the hub lends its agent while attached.
            let agent_lease = machine
                .agent_forwarding
                .then(|| crate::remote::link::accept::lease_agent(paths))
                .flatten();
            (stream, Box::new(agent_lease))
        }
        ConnectTarget::Via(machine) => {
            let connected = via::connect(machine)?;
            via_bridge = Some(connected.bridge);
            (connected.stream, Box::new(()))
        }
    };
    let handshake = super::super::do_handshake(
        &mut stream,
        options.cols,
        options.rows,
        options.cell_width_px,
        options.cell_height_px,
        options.pixel_geometry_exact,
        Some(options.surface_size),
        options.endpoint_keybindings,
        options.mouse_capture,
        false,
        matches!(target, ConnectTarget::Local(_)),
    )
    .map_err(|error| {
        // The relay's SSH session explains a stream that ended early.
        let error = handshake_error(error);
        via_bridge
            .as_ref()
            .and_then(crate::remote::ViaBridge::reported_failure)
            .unwrap_or(error)
    })?;
    let lifetime: Box<dyn Send> = match via_bridge {
        Some(bridge) => Box::new(bridge),
        None => lifetime,
    };
    if handshake.encoding != RenderEncoding::SemanticFrame {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "endpoint did not negotiate the semantic client shell",
        ));
    }
    let negotiation = EndpointNegotiation::new(
        handshake.endpoint_methods.unwrap_or_default(),
        handshake.endpoint_capabilities.unwrap_or_default(),
    );
    if !negotiation.supports_surface_interest()
        || (!endpoint_id.is_local() && !negotiation.supports_health_check())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this machine needs a server update before it can participate in multi-machine viewing",
        ));
    }
    let reader = stream.try_clone()?;
    let writer = NativeEndpointTransport::with_lifetime(stream, lifetime)?;
    Ok(EndpointSupervisorEvent::Connected {
        endpoint_id,
        generation,
        reader,
        writer,
        negotiation,
    })
}

/// Connects to a dial-in machine's hub-local client socket. Each connection
/// becomes a fresh SSH session over the machine's own outbound link.
fn connect_dial_in(paths: &LinkPaths) -> std::io::Result<crate::ipc::LocalStream> {
    use std::io::{Error, ErrorKind};

    let offline = || Error::new(ErrorKind::ConnectionRefused, DIAL_IN_OFFLINE_MESSAGE);
    paths.ensure_socket_paths_fit()?;
    crate::platform::verify_private_directory(&paths.dir).map_err(|error| {
        match error.kind() {
            // The link holder creates the directory the first time it dials in.
            ErrorKind::NotFound => offline(),
            kind => Error::new(
                kind,
                format!(
                    "refusing dial-in link directory {}: {error}",
                    paths.dir.display()
                ),
            ),
        }
    })?;
    let stream =
        crate::ipc::connect_local_stream(&paths.client_socket).map_err(|error| {
            match error.kind() {
                ErrorKind::NotFound | ErrorKind::ConnectionRefused => offline(),
                _ => error,
            }
        })?;
    if !crate::platform::local_stream_peer_is_current_user(&stream)? {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "refusing dial-in link socket {}: it is served by another user",
                paths.client_socket.display()
            ),
        ));
    }
    Ok(stream)
}

fn classify_failure(
    target: &ConnectTarget,
    error: &std::io::Error,
    attempt_started_ms: u64,
) -> (ClientEndpointStatus, String) {
    match target {
        ConnectTarget::DialIn { paths, .. } => dial_in_failure(
            &paths.status_file,
            error,
            attempt_started_ms,
            DIAL_IN_STREAM_ERROR_GRACE,
        ),
        ConnectTarget::Via(machine) => via::classify(machine, error),
        ConnectTarget::Local(_) | ConnectTarget::Ssh(_) => (
            if failure_needs_attention(error) {
                ClientEndpointStatus::Attention
            } else {
                ClientEndpointStatus::Reconnecting
            },
            error.to_string(),
        ),
    }
}

fn failure_needs_attention(error: &std::io::Error) -> bool {
    crate::remote::saved_ssh_failure_needs_attention(error)
}

/// Dial-in links come and go with the remote machine, so transport failures
/// keep retrying; only refusals that retrying cannot fix need attention.
fn dial_in_failure_status(kind: std::io::ErrorKind) -> ClientEndpointStatus {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::Unsupported
        | ErrorKind::InvalidData
        | ErrorKind::PermissionDenied
        | ErrorKind::InvalidInput => ClientEndpointStatus::Attention,
        _ => ClientEndpointStatus::Reconnecting,
    }
}

/// Failures after the link accepted the connection, which the link holder may
/// explain in `status.json` shortly afterwards.
fn dial_in_stream_failure(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind;
    matches!(
        kind,
        ErrorKind::UnexpectedEof
            | ErrorKind::BrokenPipe
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::TimedOut
    )
}

fn dial_in_failure(
    status_file: &std::path::Path,
    error: &std::io::Error,
    attempt_started_ms: u64,
    grace: Duration,
) -> (ClientEndpointStatus, String) {
    use crate::remote::link::protocol::open_failed_code;
    use crate::remote::link::status::{sanitize_remote_text, MAX_REMOTE_TEXT_BYTES};

    let mut status = dial_in_failure_status(error.kind());
    let mut message = error.to_string();
    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    ) {
        if let Some(link) = read_link_status(status_file).filter(|link| !link.is_connected()) {
            if let Some(record) = link.last_error {
                message = format!(
                    "{message} (last link error: {})",
                    sanitize_remote_text(&record.message, MAX_REMOTE_TEXT_BYTES)
                );
            }
            if let Some(reported) = link.slave.and_then(|slave| slave.last_dial_error) {
                message = format!(
                    "{message}; that machine last reported: {}",
                    sanitize_remote_text(&reported, MAX_REMOTE_TEXT_BYTES)
                );
            }
        }
        return (status, message);
    }
    let grace = if dial_in_stream_failure(error.kind()) {
        grace
    } else {
        Duration::ZERO
    };
    if let Some(record) = recent_stream_error(status_file, attempt_started_ms, grace) {
        let detail = sanitize_remote_text(&record.message, MAX_REMOTE_TEXT_BYTES);
        if record.code == open_failed_code::SERVER_NEEDS_UPDATE {
            status = ClientEndpointStatus::Attention;
            message = format!("{message}; that machine needs a Herdr server update: {detail}");
        } else {
            message = format!("{message}; that machine reported: {detail}");
        }
    }
    (status, message)
}

fn read_link_status(status_file: &std::path::Path) -> Option<LinkStatus> {
    read_status(status_file)
        .inspect_err(|error| {
            tracing::debug!(%error, path = %status_file.display(), "dial-in link status unavailable");
        })
        .ok()
        .flatten()
}

/// The link holder's latest stream error if it was recorded at or after
/// `since_ms`, polling up to `grace` for it to appear.
fn recent_stream_error(
    status_file: &std::path::Path,
    since_ms: u64,
    grace: Duration,
) -> Option<ErrorRecord> {
    let deadline = Instant::now() + grace;
    loop {
        if let Some(record) = read_link_status(status_file)
            .and_then(|link| link.last_stream_error)
            .filter(|record| record.at_ms >= since_ms)
        {
            return Some(record);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        std::thread::sleep(DIAL_IN_STREAM_ERROR_POLL.min(deadline - now));
    }
}

fn handshake_error(error: crate::client::ClientError) -> std::io::Error {
    use crate::client::ClientError;
    use crate::protocol::FramingError;
    match error {
        ClientError::ConnectionFailed(error) | ClientError::ConnectionLost(error) => error,
        ClientError::HandshakeRejected { error, .. } => {
            std::io::Error::new(std::io::ErrorKind::Unsupported, error)
        }
        ClientError::Protocol(FramingError::Io(error)) => error,
        ClientError::Protocol(error) => {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        }
        ClientError::ServerShutdown { reason } => std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            reason.unwrap_or_else(|| "server shut down during handshake".into()),
        ),
    }
}

fn retry_delay(attempt: u32) -> Duration {
    INITIAL_RETRY_DELAY
        .saturating_mul(
            1_u32
                .checked_shl(attempt.saturating_sub(1).min(8))
                .unwrap_or(u32::MAX),
        )
        .min(MAX_RETRY_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::ProfileId;

    fn profile() -> super::super::SavedSshEndpoint {
        super::super::SavedSshEndpoint {
            id: ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            label: "Build".into(),
            target: "build".into(),
            session: "agents".into(),
            enabled: true,
        }
    }

    fn dial_in_machine() -> DialInMachine {
        DialInMachine {
            id: ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap(),
            ..DialInMachine::new("Laptop", "default").unwrap()
        }
    }

    #[cfg(unix)]
    fn link_root(name: &str) -> PathBuf {
        // Short absolute root: link socket paths must fit `sun_path` on macOS too.
        let root = PathBuf::from(format!("/tmp/hsup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[cfg(unix)]
    fn connect_options() -> EndpointConnectOptions {
        EndpointConnectOptions {
            cols: 80,
            rows: 24,
            cell_width_px: 8,
            cell_height_px: 16,
            pixel_geometry_exact: false,
            surface_size: ClientSurfaceSize { cols: 80, rows: 24 },
            endpoint_keybindings: false,
            mouse_capture: false,
        }
    }

    #[test]
    fn dial_in_failures_retry_unless_retrying_cannot_help() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::ConnectionRefused,
            ErrorKind::UnexpectedEof,
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::TimedOut,
            ErrorKind::ConnectionAborted,
            ErrorKind::Other,
        ] {
            assert_eq!(
                dial_in_failure_status(kind),
                ClientEndpointStatus::Reconnecting,
                "{kind:?}"
            );
        }
        for kind in [
            ErrorKind::Unsupported,
            ErrorKind::InvalidData,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
        ] {
            assert_eq!(
                dial_in_failure_status(kind),
                ClientEndpointStatus::Attention,
                "{kind:?}"
            );
        }
        let rejected = handshake_error(crate::client::ClientError::HandshakeRejected {
            version: 1,
            error: "surface capability missing".into(),
        });
        assert_eq!(
            dial_in_failure_status(rejected.kind()),
            ClientEndpointStatus::Attention
        );

        // Classification is per target: a missing SSH install needs attention,
        // while a dial-in machine that has not dialed in just waits.
        let missing = std::io::Error::new(ErrorKind::NotFound, "missing");
        assert_eq!(
            classify_failure(&ConnectTarget::Ssh(profile()), &missing, 0).0,
            ClientEndpointStatus::Attention
        );
        let offline = std::io::Error::new(ErrorKind::ConnectionRefused, DIAL_IN_OFFLINE_MESSAGE);
        let machine = dial_in_machine();
        let target = ConnectTarget::DialIn {
            paths: LinkPaths::for_catalog(
                &std::env::temp_dir()
                    .join(format!("herdr-sup-absent-{}", std::process::id()))
                    .join("dial-in-machines.json"),
                &machine.id,
            ),
            machine,
        };
        assert_eq!(
            classify_failure(&target, &offline, 0),
            (
                ClientEndpointStatus::Reconnecting,
                DIAL_IN_OFFLINE_MESSAGE.to_string()
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn dial_in_failures_include_recent_stream_errors_from_link_status() {
        use crate::remote::link::status::{write_status, LinkState};
        use std::io::ErrorKind;

        let root = link_root("enrich");
        std::fs::create_dir_all(&root).unwrap();
        let status_file = root.join("status.json");
        let lost = std::io::Error::new(ErrorKind::UnexpectedEof, "connection was lost");
        let record = |at_ms, code: &str, message: &str| ErrorRecord {
            at_ms,
            code: code.into(),
            message: message.into(),
        };

        assert_eq!(
            dial_in_failure(&status_file, &lost, 0, Duration::ZERO),
            (
                ClientEndpointStatus::Reconnecting,
                "connection was lost".to_string()
            )
        );
        write_status(
            &status_file,
            &LinkStatus {
                state: LinkState::Connected,
                link_epoch: 1,
                last_stream_error: Some(record(100, "bridge_failed", "bridge exited")),
                ..LinkStatus::default()
            },
        )
        .unwrap();
        assert_eq!(
            dial_in_failure(&status_file, &lost, 200, Duration::ZERO).1,
            "connection was lost",
            "an error recorded before this attempt belongs to an older attempt"
        );
        let (status, message) = dial_in_failure(&status_file, &lost, 100, Duration::ZERO);
        assert_eq!(status, ClientEndpointStatus::Reconnecting);
        assert!(message.contains("bridge exited"), "{message}");

        write_status(
            &status_file,
            &LinkStatus {
                state: LinkState::Connected,
                link_epoch: 1,
                last_stream_error: Some(record(
                    100,
                    crate::remote::link::protocol::open_failed_code::SERVER_NEEDS_UPDATE,
                    "needs one final update\u{1b}[2J",
                )),
                ..LinkStatus::default()
            },
        )
        .unwrap();
        let (status, message) = dial_in_failure(&status_file, &lost, 100, Duration::ZERO);
        assert_eq!(status, ClientEndpointStatus::Attention);
        assert!(message.contains("needs a Herdr server update"), "{message}");
        assert!(!message.contains('\u{1b}'), "{message:?}");

        // Offline: the link-level reason is shown only while disconnected.
        let offline = std::io::Error::new(ErrorKind::ConnectionRefused, DIAL_IN_OFFLINE_MESSAGE);
        write_status(
            &status_file,
            &LinkStatus {
                state: LinkState::Disconnected,
                link_epoch: 1,
                last_error: Some(record(5, "link_disabled", "disabled on the hub")),
                last_stream_error: Some(record(u64::MAX, "bridge_failed", "ignored")),
                slave: Some(crate::remote::link::status::SlaveInfo {
                    last_dial_error: Some("hello timed out\u{1b}[2J".into()),
                    ..Default::default()
                }),
                ..LinkStatus::default()
            },
        )
        .unwrap();
        let (status, message) = dial_in_failure(&status_file, &offline, 0, Duration::ZERO);
        assert_eq!(status, ClientEndpointStatus::Reconnecting);
        assert!(message.starts_with(DIAL_IN_OFFLINE_MESSAGE), "{message}");
        assert!(message.contains("disabled on the hub"), "{message}");
        assert!(
            message.ends_with("; that machine last reported: hello timed out[2J"),
            "{message}"
        );
        assert!(!message.contains("ignored"), "{message}");

        // A stream error recorded shortly after the connection ended still counts.
        std::fs::remove_file(&status_file).unwrap();
        let since = crate::remote::link::status::now_ms();
        let writer_path = status_file.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            write_status(
                &writer_path,
                &LinkStatus {
                    state: LinkState::Connected,
                    link_epoch: 2,
                    last_stream_error: Some(ErrorRecord::new("stream_timeout", "late")),
                    ..LinkStatus::default()
                },
            )
            .unwrap();
        });
        let (_, message) = dial_in_failure(&status_file, &lost, since, Duration::from_secs(5));
        writer.join().unwrap();
        assert!(message.contains("late"), "{message}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dial_in_connect_waits_offline_refuses_non_private_dirs_and_reaches_listeners() {
        use interprocess::local_socket::traits::Listener as _;
        use std::io::ErrorKind;
        use std::os::unix::fs::PermissionsExt as _;

        let root = link_root("connect");
        let machine = dial_in_machine();
        let paths = LinkPaths::for_catalog(&root.join("dial-in-machines.json"), &machine.id);
        let target = ConnectTarget::DialIn {
            machine: machine.clone(),
            paths: paths.clone(),
        };
        let attempt = || {
            let error = connect_once(
                &target,
                connect_options(),
                ClientEndpointId::Ssh(machine.id.clone()),
                2,
            )
            .err()
            .expect("no herdr server answers in this test");
            let (status, message) =
                dial_in_failure(&paths.status_file, &error, u64::MAX, Duration::ZERO);
            (error.kind(), status, message)
        };
        let offline = (
            ErrorKind::ConnectionRefused,
            ClientEndpointStatus::Reconnecting,
            DIAL_IN_OFFLINE_MESSAGE.to_string(),
        );

        // Never dialed in: no link directory yet.
        assert_eq!(attempt(), offline);
        // Dialed in before, link holder gone: private directory, no socket.
        crate::platform::ensure_private_directory(&paths.dir).unwrap();
        assert_eq!(attempt(), offline);
        // A stale socket file left behind by a crashed link holder.
        drop(crate::ipc::bind_private_local_listener(&paths.client_socket).unwrap());
        assert!(paths.client_socket.exists());
        assert_eq!(attempt(), offline);
        std::fs::remove_file(&paths.client_socket).unwrap();

        // A directory other users can enter is never trusted.
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (kind, status, message) = attempt();
        assert_eq!(kind, ErrorKind::PermissionDenied);
        assert_eq!(status, ClientEndpointStatus::Attention);
        assert!(
            message.contains("refusing dial-in link directory"),
            "{message}"
        );
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // A live link holder: the connection passes the peer check and reaches
        // the handshake, whose transport failure keeps retrying.
        let listener = crate::ipc::bind_private_local_listener(&paths.client_socket).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                drop(listener.accept().unwrap());
            }
        });
        drop(connect_dial_in(&paths).unwrap());
        let (kind, status, _) = attempt();
        server.join().unwrap();
        assert_eq!(status, ClientEndpointStatus::Reconnecting, "{kind:?}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn dial_in_backoff_is_capped_and_wake_retries_immediately() {
        let now = Instant::now();
        let machine = dial_in_machine();
        let id = ClientEndpointId::Ssh(machine.id.clone());
        let ssh = ClientEndpointId::Ssh(profile().id);
        let mut supervisors = EndpointSupervisors::new(&[profile()], &[machine], now);
        assert_eq!(supervisors.endpoints[&id].next_attempt, Some(now));
        for endpoint_id in [&id, &ssh] {
            supervisors
                .endpoints
                .get_mut(endpoint_id)
                .unwrap()
                .generation = Some(2);
            for _ in 0..12 {
                assert!(supervisors.record_status(
                    endpoint_id,
                    2,
                    ClientEndpointStatus::Reconnecting,
                    now
                ));
            }
        }
        assert_eq!(
            supervisors.endpoints[&id].next_attempt,
            Some(now + MAX_DIAL_IN_RETRY_DELAY)
        );
        assert_eq!(
            supervisors.endpoints[&ssh].next_attempt,
            Some(now + MAX_RETRY_DELAY),
            "SSH keeps its own backoff"
        );

        let later = now + Duration::from_secs(1);
        assert!(supervisors.wake(&id, later));
        assert_eq!(supervisors.endpoints[&id].attempts, 0);
        assert_eq!(supervisors.endpoints[&id].next_attempt, Some(later));

        // In flight: the running attempt reports on its own.
        let state = supervisors.endpoints.get_mut(&id).unwrap();
        state.in_flight = true;
        state.next_attempt = None;
        assert!(!supervisors.wake(&id, later));
        assert_eq!(supervisors.endpoints[&id].next_attempt, None);

        // Online: nothing to do.
        assert!(supervisors.record_status(&id, 2, ClientEndpointStatus::Online, later));
        assert!(!supervisors.wake(&id, later));
        assert_eq!(supervisors.endpoints[&id].next_attempt, None);

        // Attention waits 30 s unless the machine dials in again.
        assert!(supervisors.record_status(&id, 2, ClientEndpointStatus::Attention, later));
        assert_eq!(
            supervisors.endpoints[&id].next_attempt,
            Some(later + Duration::from_secs(30))
        );
        assert!(supervisors.wake(&id, later));
        assert_eq!(supervisors.endpoints[&id].next_attempt, Some(later));

        let unknown =
            ClientEndpointId::Ssh(ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap());
        assert!(!supervisors.wake(&unknown, later));
    }

    #[test]
    fn dial_in_catalog_changes_retire_session_changes_disables_and_removals() {
        let now = Instant::now();
        let mut machine = dial_in_machine();
        let id = ClientEndpointId::Ssh(machine.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[], &[machine.clone()], now);
        supervisors.add_local(PathBuf::from("local"), Some(1), now);
        assert!(matches!(
            &supervisors.endpoints[&id].target,
            ConnectTarget::DialIn { paths, .. } if *paths == machine.paths()
        ));

        // A rename keeps the live connection.
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(5);
        machine.label = "Renamed".into();
        assert!(supervisors
            .reconcile_profiles(&[], &[machine.clone()], now)
            .is_empty());
        assert_eq!(supervisors.endpoints[&id].generation, Some(5));
        assert!(matches!(
            &supervisors.endpoints[&id].target,
            ConnectTarget::DialIn { machine: current, .. } if current.label == "Renamed"
        ));

        // Another session is another destination.
        machine.session = "work".into();
        assert_eq!(
            supervisors.reconcile_profiles(&[], &[machine.clone()], now),
            vec![id.clone()]
        );
        assert_eq!(supervisors.endpoints[&id].generation, None);
        assert_eq!(supervisors.endpoints[&id].next_attempt, Some(now));
        assert!(!supervisors.record_status(&id, 5, ClientEndpointStatus::Online, now));

        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(6);
        machine.enabled = false;
        assert_eq!(
            supervisors.reconcile_profiles(&[], &[machine.clone()], now),
            vec![id.clone()]
        );
        assert!(!supervisors.endpoints.contains_key(&id));
        assert!(!supervisors.record_status(&id, 6, ClientEndpointStatus::Online, now));

        machine.enabled = true;
        assert!(supervisors
            .reconcile_profiles(&[], &[machine.clone()], now)
            .is_empty());
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(7);
        assert_eq!(
            supervisors.reconcile_profiles(&[], &[], now),
            vec![id.clone()]
        );
        assert!(!supervisors.endpoints.contains_key(&id));

        // A hand-edited id collision: the SSH profile keeps the identity.
        let mut colliding = profile();
        colliding.id = machine.id.clone();
        assert!(supervisors
            .reconcile_profiles(&[], &[machine.clone()], now)
            .is_empty());
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(8);
        assert_eq!(
            supervisors.reconcile_profiles(&[colliding.clone()], &[machine], now),
            vec![id.clone()]
        );
        assert!(matches!(
            supervisors.endpoints[&id].target,
            ConnectTarget::Ssh(_)
        ));
        assert_eq!(
            supervisors.endpoints[&ClientEndpointId::Local].generation,
            Some(1)
        );
    }

    #[test]
    fn live_catalog_preserves_renamed_connections_and_local_recovery() {
        let now = Instant::now();
        let mut profile = profile();
        let id = ClientEndpointId::Ssh(profile.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[profile.clone()], &[], now);
        supervisors.add_local(PathBuf::from("local"), Some(1), now);
        let state = supervisors.endpoints.get_mut(&id).unwrap();
        state.generation = Some(7);
        state.attempts = 3;
        state.next_attempt = Some(now + Duration::from_secs(4));
        profile.label = "Renamed".into();
        assert!(supervisors
            .reconcile_profiles(&[profile], &[], now)
            .is_empty());
        let state = &supervisors.endpoints[&id];
        assert_eq!(state.generation, Some(7));
        assert_eq!(state.attempts, 3);
        assert_eq!(state.next_attempt, Some(now + Duration::from_secs(4)));
        assert_eq!(
            supervisors.endpoints[&ClientEndpointId::Local].generation,
            Some(1)
        );
    }

    #[test]
    fn live_catalog_add_disable_enable_and_remove_fence_late_connections() {
        let now = Instant::now();
        let mut profile = profile();
        let id = ClientEndpointId::Ssh(profile.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[], &[], now);
        assert!(supervisors
            .reconcile_profiles(&[profile.clone()], &[], now)
            .is_empty());
        assert_eq!(supervisors.endpoints[&id].next_attempt, Some(now));
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(7);
        supervisors.next_generation = 8;
        profile.enabled = false;
        assert_eq!(
            supervisors.reconcile_profiles(&[profile.clone()], &[], now),
            vec![id.clone()]
        );
        assert!(!supervisors.record_status(&id, 7, ClientEndpointStatus::Online, now));
        profile.enabled = true;
        assert!(supervisors
            .reconcile_profiles(&[profile.clone()], &[], now)
            .is_empty());
        assert!(!supervisors.record_status(&id, 7, ClientEndpointStatus::Online, now));
        assert_eq!(supervisors.next_generation, 8);
        assert_eq!(
            supervisors.reconcile_profiles(&[], &[], now),
            vec![id.clone()]
        );
        assert!(!supervisors.record_status(&id, 7, ClientEndpointStatus::Online, now));
    }

    #[test]
    fn live_catalog_destination_change_retires_only_that_machine() {
        let now = Instant::now();
        let mut changed = profile();
        let other = super::super::SavedSshEndpoint::new("Other", "other", "main").unwrap();
        let id = ClientEndpointId::Ssh(changed.id.clone());
        let other_id = ClientEndpointId::Ssh(other.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[changed.clone(), other.clone()], &[], now);
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(2);
        supervisors.endpoints.get_mut(&other_id).unwrap().generation = Some(3);
        changed.session = "another-session".into();
        assert_eq!(
            supervisors.reconcile_profiles(&[changed, other], &[], now),
            vec![id.clone()]
        );
        assert_eq!(supervisors.endpoints[&id].generation, None);
        assert_eq!(supervisors.endpoints[&other_id].generation, Some(3));
    }

    #[test]
    fn brief_ssh_reconnections_do_not_reset_backoff() {
        let now = Instant::now();
        let profile = profile();
        let id = ClientEndpointId::Ssh(profile.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[profile], &[], now);
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(2);
        for attempt in 1..=5 {
            let connected = now + Duration::from_secs(attempt * 20);
            assert!(supervisors.record_status(&id, 2, ClientEndpointStatus::Online, connected));
            let failed = connected + Duration::from_secs(15);
            assert!(supervisors.disconnected(&id, 2, failed));
            assert_eq!(
                supervisors.endpoints[&id].next_attempt,
                Some(failed + INITIAL_RETRY_DELAY * (1 << (attempt - 1)))
            );
        }
        let connected = now + Duration::from_secs(200);
        assert!(supervisors.record_status(&id, 2, ClientEndpointStatus::Online, connected));
        let failed = connected + Duration::from_secs(60);
        assert!(supervisors.disconnected(&id, 2, failed));
        assert_eq!(
            supervisors.endpoints[&id].next_attempt,
            Some(failed + INITIAL_RETRY_DELAY)
        );
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_delay(1), INITIAL_RETRY_DELAY);
        assert_eq!(retry_delay(100), MAX_RETRY_DELAY);
    }

    #[test]
    fn handshake_network_failures_retry_but_incompatibility_needs_attention() {
        let timeout = handshake_error(crate::client::ClientError::ConnectionLost(
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"),
        ));
        assert!(!failure_needs_attention(&timeout));
        let rejected = handshake_error(crate::client::ClientError::HandshakeRejected {
            version: 1,
            error: "surface capability missing".into(),
        });
        assert_eq!(rejected.kind(), std::io::ErrorKind::Unsupported);
        assert!(failure_needs_attention(&rejected));
    }

    #[test]
    fn healthy_local_only_retries_after_its_connection_fails() {
        let now = Instant::now();
        let mut supervisors = EndpointSupervisors::new(&[profile()], &[], now);
        supervisors.add_local(PathBuf::from("local.sock"), Some(1), now);
        assert!(supervisors.endpoints[&ClientEndpointId::Local]
            .next_attempt
            .is_none());
        assert!(!supervisors.disconnected(&ClientEndpointId::Local, 0, now));
        assert!(supervisors.endpoints[&ClientEndpointId::Local]
            .next_attempt
            .is_none());
        assert!(supervisors.disconnected(&ClientEndpointId::Local, 1, now));
        assert_eq!(
            supervisors.endpoints[&ClientEndpointId::Local].next_attempt,
            Some(now + INITIAL_RETRY_DELAY)
        );
        assert_eq!(
            supervisors.endpoints[&ClientEndpointId::Ssh(profile().id)].next_attempt,
            Some(now)
        );
    }

    #[test]
    fn ssh_recovery_rejects_stale_generations_and_rechecks_attention() {
        let now = Instant::now();
        let mut supervisors = EndpointSupervisors::new(&[profile()], &[], now);
        let endpoint_id = ClientEndpointId::Ssh(profile().id);
        supervisors
            .endpoints
            .get_mut(&endpoint_id)
            .unwrap()
            .generation = Some(4);
        assert!(supervisors.record_status(&endpoint_id, 4, ClientEndpointStatus::Online, now));
        assert!(!supervisors.disconnected(&endpoint_id, 3, now));
        assert!(supervisors.endpoints[&endpoint_id].next_attempt.is_none());
        assert!(supervisors.disconnected(&endpoint_id, 4, now));
        assert_eq!(
            supervisors.endpoints[&endpoint_id].next_attempt,
            Some(now + INITIAL_RETRY_DELAY)
        );
        assert!(supervisors.record_status(&endpoint_id, 4, ClientEndpointStatus::Attention, now));
        assert_eq!(
            supervisors.endpoints[&endpoint_id].next_attempt,
            Some(now + Duration::from_secs(30))
        );
    }
}
