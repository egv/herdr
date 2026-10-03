//! Byte relays: the holder's hub connection to attached stream relay, and the
//! stream-mode acceptor that attaches through `link.sock` and pumps its stdio.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use interprocess::local_socket::traits::Stream as _;

use super::{connect_link_socket, Event, PeerCheck};
use crate::ipc::LocalStream;
use crate::remote::link::protocol::{self, LocalRequest};
use crate::remote::link::LinkPaths;

const RELAY_BUFFER_BYTES: usize = 64 * 1024;

/// After the hub side of a stream stops sending, how long the slave's
/// remaining output may take before the stream session ends anyway. Closing
/// stdout cannot signal end-of-file to the dialer while the forced-command
/// shell still holds it (shells such as dash do not `exec` the command), so
/// without a bound this process and the dialer would wait for each other.
const UPLOAD_GRACE_AFTER_HUB_EOF: Duration = Duration::from_secs(5);

/// A hub connection relayed to the stream attached for it.
pub(super) struct ActiveRelay {
    hub: Arc<LocalStream>,
    attached: Arc<LocalStream>,
}

impl ActiveRelay {
    /// Relays both directions on two threads; `Event::RelayFinished(id)` is
    /// sent once both have ended.
    pub(super) fn start(
        id: u64,
        hub: LocalStream,
        attached: LocalStream,
        events: Sender<Event>,
    ) -> io::Result<Self> {
        let hub = Arc::new(hub);
        let attached = Arc::new(attached);
        let (relay_hub, relay_attached) = (Arc::clone(&hub), Arc::clone(&attached));
        let spawned = thread::Builder::new()
            .name("herdr-link-relay".into())
            .spawn(move || {
                relay(&relay_hub, &relay_attached);
                let _ = events.send(Event::RelayFinished(id));
            });
        if let Err(error) = spawned {
            abort_streams(&hub, &attached);
            return Err(error);
        }
        Ok(Self { hub, attached })
    }

    /// Tears down both connections; the relay threads then finish.
    pub(super) fn abort(&self) {
        abort_streams(&self.hub, &self.attached);
    }
}

fn relay(hub: &Arc<LocalStream>, attached: &Arc<LocalStream>) {
    let (back_from, back_to) = (Arc::clone(attached), Arc::clone(hub));
    let back = thread::Builder::new()
        .name("herdr-link-relay".into())
        .spawn(move || pump(&back_from, &back_to));
    match back {
        Ok(back) => {
            pump(hub, attached);
            let _ = back.join();
        }
        Err(error) => {
            tracing::warn!("failed to start a dial-in relay direction: {error}");
            abort_streams(hub, attached);
        }
    }
}

/// Copies `from` into `to`. End-of-file half-closes `to` so the peer can
/// still answer; any failure tears down both connections.
fn pump(from: &LocalStream, to: &LocalStream) {
    match copy_stream(&mut &*from, &mut &*to) {
        Ok(()) => {
            let _ = crate::platform::shutdown_local_stream(to, Shutdown::Write);
        }
        Err(_) => abort_streams(from, to),
    }
}

fn abort_streams(first: &LocalStream, second: &LocalStream) {
    let _ = crate::platform::shutdown_local_stream(first, Shutdown::Both);
    let _ = crate::platform::shutdown_local_stream(second, Shutdown::Both);
}

/// Copies until end-of-file with one bounded buffer.
fn copy_stream(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<()> {
    let mut buffer = vec![0_u8; RELAY_BUFFER_BYTES];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        writer.write_all(&buffer[..read])?;
        writer.flush()?;
    }
}

/// The link holder answered an attach with an error. Its text comes from the
/// hub's own holder and carries no paths, so it may be shown to the dialer.
#[derive(Debug)]
pub(super) struct HolderRefused(String);

impl std::fmt::Display for HolderRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for HolderRefused {}

/// Serves one stream session: prints the ready marker, attaches to the
/// pending hub connection for `nonce` through `link.sock`, then pumps raw
/// bytes between `input`/`output` (the SSH session) and that connection until
/// both directions end.
pub(super) fn serve_stream<R, W>(
    paths: &LinkPaths,
    nonce: &str,
    peer_check: PeerCheck,
    request_timeout: Duration,
    input: R,
    mut output: W,
) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write,
{
    protocol::write_marker(&mut output)?;
    let stream = connect_link_socket(paths, peer_check)?;
    stream.set_recv_timeout(Some(request_timeout))?;
    stream.set_send_timeout(Some(request_timeout))?;
    protocol::write_local_request(
        &mut &stream,
        &LocalRequest::Attach {
            nonce: nonce.to_string(),
        },
    )?;
    let response = protocol::read_local_response(&mut &stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the link holder closed the connection without answering",
        )
    })?;
    if !response.ok {
        return Err(io::Error::other(HolderRefused(format!(
            "the link holder refused the stream ({}): {}",
            response.code.as_deref().unwrap_or("error"),
            response.message.as_deref().unwrap_or("")
        ))));
    }
    stream.set_recv_timeout(None)?;
    stream.set_send_timeout(None)?;
    pump_stdio(stream, input, output)
}

/// Pumps `input` into `stream` on a helper thread and `stream` into `output`
/// here. Socket end-of-file closes `output` so the SSH peer sees end-of-file
/// while it may still send; input end-of-file half-closes the socket.
pub(in crate::remote::link) fn pump_stdio<R, W>(
    stream: LocalStream,
    mut input: R,
    mut output: W,
) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write,
{
    let stream = Arc::new(stream);
    let upload_stream = Arc::clone(&stream);
    let (upload_done, upload_result) = mpsc::channel();
    thread::Builder::new()
        .name("herdr-link-upload".into())
        .spawn(move || {
            let result = copy_stream(&mut input, &mut &*upload_stream);
            let how = if result.is_ok() {
                Shutdown::Write
            } else {
                Shutdown::Both
            };
            let _ = crate::platform::shutdown_local_stream(&upload_stream, how);
            let _ = upload_done.send(result);
        })?;
    let download = copy_stream(&mut &*stream, &mut output);
    drop(output);
    match download {
        Ok(()) => match upload_result.recv_timeout(UPLOAD_GRACE_AFTER_HUB_EOF) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                // The upload thread stays blocked on stdin; the caller exits.
                let _ = crate::platform::shutdown_local_stream(&stream, Shutdown::Both);
                Ok(())
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("the stream upload thread panicked"))
            }
        },
        Err(error) => {
            let _ = crate::platform::shutdown_local_stream(&stream, Shutdown::Both);
            Err(error)
        }
    }
}
