//! Hub side of dial-in SSH agent forwarding: the in-memory lease table behind
//! the `AgentLease` / `AgentTarget` operations on `link.sock`, the hub
//! client's lease request, and the `--mode agent` session that relays
//! filtered agent requests (see `crate::remote::link::agent_filter`) to the
//! most recent live lease.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use interprocess::local_socket::traits::Stream as _;

use super::sockets::respond;
use super::{connect_link_socket, Event, Invocation, LinkHolder, PeerCheck, LOCAL_REQUEST_TIMEOUT};
use crate::ipc::LocalStream;
use crate::remote::link::protocol::{self, local_code, LocalRequest, LocalResponse};
use crate::remote::link::{agent_filter, LinkPaths};

/// Leases held at once per link; hub clients hold one per attached window.
const MAX_AGENT_LEASES: usize = 64;

struct Lease {
    id: u64,
    socket: PathBuf,
    stream: Arc<LocalStream>,
}

/// Agent sockets lent by hub clients, oldest first. A lease lives while its
/// `link.sock` connection stays open.
#[derive(Default)]
pub(super) struct AgentLeases {
    next_id: u64,
    leases: Vec<Lease>,
}

impl AgentLeases {
    /// Ends every lease by closing its connection.
    pub(super) fn close_all(&mut self) {
        for lease in self.leases.drain(..) {
            let _ = crate::platform::shutdown_local_stream(&lease.stream, std::net::Shutdown::Both);
        }
    }
}

impl LinkHolder<'_> {
    /// `AgentLease`: answers, then keeps `stream` as a lease until it closes.
    pub(super) fn agent_lease(&mut self, socket: String, stream: LocalStream) {
        let path = PathBuf::from(socket);
        let refusal = if self.agent.leases.len() >= MAX_AGENT_LEASES {
            Some("too many agent leases")
        } else if !path.is_absolute() || !crate::platform::socket_is_owned_by_current_user(&path) {
            Some("the agent must be an absolute path to a socket owned by the hub user")
        } else {
            None
        };
        if let Some(message) = refusal {
            let _ = respond(
                &stream,
                &LocalResponse::error(local_code::NO_AGENT, message),
            );
            return;
        }
        let ready = respond(&stream, &LocalResponse::ok())
            .and_then(|()| stream.set_recv_timeout(None))
            .and_then(|()| stream.set_send_timeout(None));
        if let Err(error) = ready {
            tracing::debug!("failed to accept an agent lease: {error}");
            return;
        }
        let id = self.agent.next_id;
        self.agent.next_id += 1;
        let stream = Arc::new(stream);
        let watched = Arc::clone(&stream);
        let events = self.events_tx.clone();
        let spawned = thread::Builder::new()
            .name("herdr-link-agent-lease".into())
            .spawn(move || {
                // The client never writes; end-of-file or an error ends the lease.
                let mut buffer = [0_u8; 64];
                loop {
                    match (&*watched).read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let _ = events.send(Event::AgentLeaseEnded(id));
            });
        if let Err(error) = spawned {
            tracing::warn!("failed to watch an agent lease: {error}");
            return;
        }
        self.agent.leases.push(Lease {
            id,
            socket: path,
            stream,
        });
        self.agent_leases_changed();
    }

    pub(super) fn agent_lease_ended(&mut self, id: u64) {
        let before = self.agent.leases.len();
        self.agent.leases.retain(|lease| lease.id != id);
        if self.agent.leases.len() != before {
            self.agent_leases_changed();
        }
    }

    fn agent_leases_changed(&mut self) {
        self.status.agent_leases = u32::try_from(self.agent.leases.len()).unwrap_or(u32::MAX);
        self.status_dirty = true;
    }

    /// `AgentTarget`: the most recent live lease, when forwarding is on.
    pub(super) fn agent_target(&self) -> LocalResponse {
        if !self.machine.agent_forwarding {
            return LocalResponse::error(
                local_code::AGENT_DISABLED,
                "agent forwarding is off for this machine on the hub",
            );
        }
        match self.agent.leases.last() {
            Some(lease) => LocalResponse {
                agent_socket: Some(lease.socket.to_string_lossy().into_owned()),
                ..LocalResponse::ok()
            },
            None => LocalResponse::error(
                local_code::NO_AGENT,
                "no hub window with an SSH agent is attached to this machine",
            ),
        }
    }
}

/// Lends this process's SSH agent (`SSH_AUTH_SOCK`) to the link at `paths`
/// for as long as the returned connection stays open. Failures are logged:
/// the caller works the same without forwarding.
pub(crate) fn lease_agent(paths: &LinkPaths) -> Option<LocalStream> {
    let socket = std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|socket| Path::new(socket).is_absolute())?;
    request_agent_lease(
        paths,
        &socket,
        crate::platform::local_stream_peer_is_current_user,
        LOCAL_REQUEST_TIMEOUT,
    )
    .inspect_err(|error| tracing::info!("dial-in agent forwarding unavailable: {error}"))
    .ok()
}

pub(super) fn request_agent_lease(
    paths: &LinkPaths,
    socket: &str,
    peer_check: PeerCheck,
    timeout: Duration,
) -> io::Result<LocalStream> {
    let stream = connect_link_socket(paths, peer_check)?;
    stream.set_recv_timeout(Some(timeout))?;
    stream.set_send_timeout(Some(timeout))?;
    let request = LocalRequest::AgentLease {
        socket: socket.to_string(),
    };
    protocol::write_local_request(&mut &stream, &request)?;
    match protocol::read_local_response(&mut &stream)? {
        Some(response) if response.ok => Ok(stream),
        Some(response) => Err(io::Error::other(format!(
            "the link holder refused the agent lease ({}): {}",
            response.code.as_deref().unwrap_or("error"),
            response.message.as_deref().unwrap_or("")
        ))),
        None => Err(io::ErrorKind::UnexpectedEof.into()),
    }
}

/// `herdr link-accept --mode agent`: relays filtered agent requests from the
/// dialing machine to the hub agent of the most recent lease. Refusals
/// (forwarding off, no lease) exit quietly with a non-zero status.
pub(super) fn run_agent(invocation: &Invocation) -> io::Result<()> {
    if invocation.link_mismatch {
        super::stderr_line(format_args!(
            "herdr link-accept: the requested link id does not match the link id this key is authorized for"
        ));
        std::process::exit(1);
    }
    let output = crate::platform::take_stdout_unbuffered()?;
    let paths = LinkPaths::for_catalog(&invocation.catalog, &invocation.link_id);
    match serve_agent(
        &paths,
        crate::platform::local_stream_peer_is_current_user,
        LOCAL_REQUEST_TIMEOUT,
        io::stdin(),
        output,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => std::process::exit(1),
        Err(error) => {
            super::stderr_line(format_args!(
                "herdr link-accept: agent session failed: {error}"
            ));
            std::process::exit(1);
        }
    }
}

/// Prints the ready marker, asks the link holder for the agent target, and
/// filters requests between `input`/`output` and that agent. Every forwarded
/// request asks again, so the session ends once the lease, the link, or the
/// machine's forwarding setting is gone. `Ok(false)` when the holder refused.
pub(super) fn serve_agent(
    paths: &LinkPaths,
    peer_check: PeerCheck,
    timeout: Duration,
    mut input: impl Read,
    mut output: impl Write,
) -> io::Result<bool> {
    protocol::write_marker(&mut output)?;
    let Some(socket) = agent_target(paths, peer_check, timeout)? else {
        return Ok(false);
    };
    let agent = crate::ipc::connect_local_stream(Path::new(&socket))?;
    if !peer_check(&agent)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the leased SSH agent is served by another user",
        ));
    }
    let still_leased = || {
        agent_target(paths, peer_check, timeout)
            .is_ok_and(|target| target.as_ref() == Some(&socket))
    };
    agent_filter::filter_requests(&mut input, &mut output, &mut &agent, still_leased)?;
    Ok(true)
}

/// The holder's current agent socket, `None` when it refuses.
fn agent_target(
    paths: &LinkPaths,
    peer_check: PeerCheck,
    timeout: Duration,
) -> io::Result<Option<String>> {
    let link = connect_link_socket(paths, peer_check)?;
    link.set_recv_timeout(Some(timeout))?;
    link.set_send_timeout(Some(timeout))?;
    protocol::write_local_request(&mut &link, &LocalRequest::AgentTarget)?;
    Ok(protocol::read_local_response(&mut &link)?
        .filter(|response| response.ok)
        .and_then(|response| response.agent_socket))
}
