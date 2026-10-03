//! The link holder's listeners: one blocking accept thread per socket,
//! peer-uid checks on every connection, and `link.sock` request reading.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use interprocess::local_socket::traits::{Listener as _, Stream as _};

use super::{ControlOptions, Event, PeerCheck, Refused, HUB_UNAVAILABLE};
use crate::ipc::{LocalListener, LocalStream, SocketFileIdentity};
use crate::remote::link::protocol::{self, error_code, LocalResponse, StreamKind};
use crate::remote::link::LinkPaths;

const LISTENER_STOP_WAIT: Duration = Duration::from_secs(1);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const SOCKET_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketKind {
    Link,
    Client,
    Api,
}

impl SocketKind {
    fn name(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Client => "client",
            Self::Api => "api",
        }
    }
}

struct BoundSocket {
    path: PathBuf,
    identity: SocketFileIdentity,
    accept_thread: Option<JoinHandle<()>>,
}

/// The three listeners of a link holder. Dropping stops them and removes the
/// socket files that are still the ones this holder bound.
pub(super) struct LinkSockets {
    stopping: Arc<AtomicBool>,
    bound: Vec<BoundSocket>,
}

struct AcceptContext {
    kind: SocketKind,
    events: Sender<Event>,
    stopping: Arc<AtomicBool>,
    peer_check: PeerCheck,
    request_timeout: Duration,
}

impl LinkSockets {
    /// Binds `link.sock`, `client.sock` and `api.sock` (mode 0600) and starts
    /// their accept threads. Stale socket files are replaced; a live foreign
    /// listener refuses with `link_busy`.
    pub(super) fn bind(
        paths: &LinkPaths,
        events: &Sender<Event>,
        options: &ControlOptions,
    ) -> Result<Self, Refused> {
        let mut sockets = Self {
            stopping: Arc::new(AtomicBool::new(false)),
            bound: Vec::with_capacity(3),
        };
        for (kind, path) in [
            (SocketKind::Link, &paths.link_socket),
            (SocketKind::Client, &paths.client_socket),
            (SocketKind::Api, &paths.api_socket),
        ] {
            if let Err(error) = sockets.bind_one(kind, path, events, options) {
                // The dialer learns what failed, not where on the hub.
                let (code, message) = if error.kind() == io::ErrorKind::AddrInUse {
                    (
                        error_code::LINK_BUSY,
                        format!(
                            "another process serves this machine's {} socket on the hub",
                            kind.name()
                        ),
                    )
                } else {
                    (
                        HUB_UNAVAILABLE,
                        format!(
                            "the hub could not listen on this machine's {} socket",
                            kind.name()
                        ),
                    )
                };
                return Err(Refused::new(code, message)
                    .with_detail(format!("failed to bind {}: {error}", path.display())));
            }
        }
        Ok(sockets)
    }

    fn bind_one(
        &mut self,
        kind: SocketKind,
        path: &Path,
        events: &Sender<Event>,
        options: &ControlOptions,
    ) -> io::Result<()> {
        crate::ipc::prepare_socket_path(path, |path| {
            format!("another process is serving {}", path.display())
        })?;
        let listener = crate::ipc::bind_private_local_listener(path)?;
        let identity = match crate::ipc::restrict_socket_permissions(path, SOCKET_MODE)
            .and_then(|()| crate::ipc::socket_file_identity(path))
        {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                let _ = std::fs::remove_file(path);
                return Err(error);
            }
        };
        let context = AcceptContext {
            kind,
            events: events.clone(),
            stopping: Arc::clone(&self.stopping),
            peer_check: options.peer_check,
            request_timeout: options.timings.local_request_timeout,
        };
        let spawned = thread::Builder::new()
            .name(format!("herdr-link-accept-{}", kind.name()))
            .spawn(move || accept_loop(listener, context));
        match spawned {
            Ok(accept_thread) => {
                self.bound.push(BoundSocket {
                    path: path.to_path_buf(),
                    identity,
                    accept_thread: Some(accept_thread),
                });
                Ok(())
            }
            Err(error) => {
                let _ = crate::ipc::remove_socket_file_if_owned(path, &identity);
                Err(error)
            }
        }
    }

    /// Stops the accept threads and removes each socket file only if it is
    /// still the one this holder bound.
    pub(super) fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        for socket in &mut self.bound {
            let still_ours = matches!(
                crate::ipc::socket_file_identity(&socket.path),
                Ok(identity) if identity == socket.identity
            );
            if still_ours {
                // Wake the blocking accept so the thread sees the flag and
                // drops its listener.
                let _ = crate::ipc::connect_local_stream(&socket.path);
                if let Some(thread) = socket.accept_thread.take() {
                    join_with_timeout(thread, LISTENER_STOP_WAIT);
                }
            } else {
                tracing::warn!(
                    path = %socket.path.display(),
                    "link socket was replaced; leaving it in place"
                );
            }
            if let Err(error) =
                crate::ipc::remove_socket_file_if_owned(&socket.path, &socket.identity)
            {
                tracing::warn!(
                    path = %socket.path.display(),
                    "failed to remove link socket: {error}"
                );
            }
        }
        self.bound.clear();
    }
}

impl Drop for LinkSockets {
    fn drop(&mut self) {
        if !self.bound.is_empty() {
            self.stop();
        }
    }
}

fn join_with_timeout(thread: JoinHandle<()>, wait: Duration) {
    let deadline = Instant::now() + wait;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = thread.join();
}

fn accept_loop(listener: LocalListener, context: AcceptContext) {
    loop {
        let accepted = listener.accept();
        if context.stopping.load(Ordering::Acquire) {
            return;
        }
        let stream = match accepted {
            Ok(stream) => stream,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                tracing::warn!(
                    socket = context.kind.name(),
                    "failed to accept a link connection: {error}"
                );
                thread::sleep(ACCEPT_RETRY_DELAY);
                continue;
            }
        };
        match (context.peer_check)(&stream) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    socket = context.kind.name(),
                    "refused a link connection from another user"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    socket = context.kind.name(),
                    "refused a link connection whose peer could not be verified: {error}"
                );
                continue;
            }
        }
        let delivered = match context.kind {
            SocketKind::Link => {
                spawn_local_request_reader(stream, &context);
                true
            }
            SocketKind::Client => context
                .events
                .send(Event::Opened {
                    kind: StreamKind::Client,
                    stream,
                })
                .is_ok(),
            SocketKind::Api => context
                .events
                .send(Event::Opened {
                    kind: StreamKind::Api,
                    stream,
                })
                .is_ok(),
        };
        if !delivered {
            return;
        }
    }
}

/// Reads one `link.sock` request (bounded by the request timeout) on its own
/// thread and hands it to the holder loop together with the connection.
fn spawn_local_request_reader(stream: LocalStream, context: &AcceptContext) {
    let events = context.events.clone();
    let timeout = context.request_timeout;
    let spawned = thread::Builder::new()
        .name("herdr-link-local".into())
        .spawn(move || {
            if let Err(error) = stream
                .set_recv_timeout(Some(timeout))
                .and_then(|()| stream.set_send_timeout(Some(timeout)))
            {
                tracing::debug!("failed to configure a link request connection: {error}");
                return;
            }
            match protocol::read_local_request(&mut &stream) {
                Ok(Some(request)) => {
                    let _ = events.send(Event::Local { request, stream });
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    let _ = respond(
                        &stream,
                        &LocalResponse::error(
                            error_code::PROTOCOL_ERROR,
                            format!("invalid link request: {error}"),
                        ),
                    );
                }
                Err(error) => tracing::debug!("failed to read a link request: {error}"),
            }
        });
    if let Err(error) = spawned {
        tracing::warn!("failed to start a link request reader: {error}");
    }
}

/// Writes one `link.sock` response; the connection carries the send timeout
/// set when its request was read.
pub(super) fn respond(stream: &LocalStream, response: &LocalResponse) -> io::Result<()> {
    protocol::write_local_response(&mut &*stream, response)
}
