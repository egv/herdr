//! Hub side of the hub-driven slave update: validates `link.sock` `Update`
//! requests, asks the dialer to open an update stream whose hub-side
//! connection is the requesting `link.sock` connection, and relays
//! `RestartServer` requests to the dialer. Also the `link.sock` client that
//! `herdr machine update` uses.

use std::collections::HashMap;
use std::io::{self, Read};
use std::time::{Duration, Instant};

use interprocess::local_socket::traits::Stream as _;

use super::sockets::respond;
use super::{connect_link_socket, LinkHolder, LOCAL_REQUEST_TIMEOUT};
use crate::ipc::LocalStream;
use crate::remote::link::protocol::{
    self, feature, local_code, open_failed_code, ControlMessage, LocalRequest, LocalResponse,
    OpenRequest, StreamKind, UpdateResult,
};
use crate::remote::link::status::{sanitize_remote_text, MAX_REMOTE_TEXT_BYTES};
use crate::remote::link::{LinkPaths, MAX_CONTROL_LINE_BYTES};

/// How long a `RestartServer` request waits for the dialer's result.
const RESTART_WAIT: Duration = Duration::from_secs(60);
const MAX_PENDING_RESTARTS: usize = 4;
/// Bounds each write of the executable (until the dialer attaches its
/// stream) and the wait for its result (it verifies and self-tests first).
const UPDATE_IO_TIMEOUT: Duration = Duration::from_secs(120);

impl LinkHolder<'_> {
    fn dialer_supports(&self, name: &str) -> bool {
        self.status
            .slave
            .as_ref()
            .is_some_and(|slave| slave.features.iter().any(|feature| feature == name))
    }

    /// `Update`: once answered `ok`, the requesting connection is the hub
    /// side of an update stream the dialer is asked to open, relayed like
    /// any other hub connection.
    pub(super) fn begin_update(
        &mut self,
        size: u64,
        sha256: String,
        version: Option<String>,
        stream: LocalStream,
    ) {
        let refusal = if let Err(message) =
            protocol::check_update_request(size, &sha256, version.as_deref())
        {
            Some(LocalResponse::error(local_code::UPDATE_REJECTED, message))
        } else if !self.dialer_supports(feature::UPDATE) {
            Some(LocalResponse::error(
                open_failed_code::UPDATE_UNSUPPORTED,
                "this machine's Herdr cannot be updated by the hub",
            ))
        } else if self.streams_full() {
            Some(LocalResponse::error(
                local_code::LINK_BUSY,
                "too many dial-in streams",
            ))
        } else {
            None
        };
        if let Some(response) = refusal {
            let _ = respond(&stream, &response);
            return;
        }
        let ready = respond(&stream, &LocalResponse::ok())
            .and_then(|()| stream.set_recv_timeout(None))
            .and_then(|()| stream.set_send_timeout(None));
        if let Err(error) = ready {
            tracing::debug!("failed to start a dial-in update: {error}");
            return;
        }
        tracing::info!(size, "relaying a hub update to the dial-in machine");
        self.queue_open(stream, |nonce| OpenRequest {
            size: Some(size),
            sha256: Some(sha256),
            version,
            ..OpenRequest::stream(nonce, StreamKind::Update, String::new())
        });
    }

    /// `RestartServer`: relayed to the dialer and answered with its result,
    /// or with `restart_failed` after [`RESTART_WAIT`].
    pub(super) fn begin_restart(&mut self, session: String, stream: LocalStream) {
        let refusal = if crate::session::validate_name(&session).is_err() {
            Some("invalid session name")
        } else if !self.dialer_supports(feature::RESTART_SERVER) {
            Some("this machine's Herdr cannot restart its server for the hub")
        } else if self.restarts.0.len() >= MAX_PENDING_RESTARTS {
            Some("too many server restarts are in progress")
        } else {
            None
        };
        if let Some(message) = refusal {
            let _ = respond(
                &stream,
                &LocalResponse::error(local_code::RESTART_FAILED, message),
            );
            return;
        }
        let request_id = protocol::generate_nonce();
        self.writer.send(ControlMessage::RestartServer {
            request_id: request_id.clone(),
            session,
        });
        self.restarts
            .0
            .insert(request_id, (stream, Instant::now() + RESTART_WAIT));
    }
}

/// `RestartServer` requests waiting for the dialer, by request id: the
/// requesting connection and when to give up on it.
#[derive(Default)]
pub(super) struct PendingRestarts(HashMap<String, (LocalStream, Instant)>);

impl PendingRestarts {
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.0.values().map(|(_, deadline)| *deadline).min()
    }

    /// Answers request `request_id` with the dialer's result.
    pub(super) fn finish(&mut self, request_id: &str, ok: bool, message: &str) {
        let Some((stream, _)) = self.0.remove(request_id) else {
            return;
        };
        let message = sanitize_remote_text(message, MAX_REMOTE_TEXT_BYTES);
        let response = if ok {
            LocalResponse {
                message: Some(message),
                ..LocalResponse::ok()
            }
        } else {
            LocalResponse::error(local_code::RESTART_FAILED, message)
        };
        let _ = respond(&stream, &response);
    }

    pub(super) fn expire(&mut self, now: Instant) {
        self.0.retain(|_, (stream, deadline)| {
            let waiting = now < *deadline;
            if !waiting {
                let _ = respond(
                    stream,
                    &LocalResponse::error(
                        local_code::RESTART_FAILED,
                        "the machine did not answer the restart in time",
                    ),
                );
            }
            waiting
        });
    }
}

/// Sends one `link.sock` request and reads its response line.
fn local_request(
    paths: &LinkPaths,
    request: &LocalRequest,
    wait: Duration,
) -> io::Result<(LocalStream, LocalResponse)> {
    let stream = connect_link_socket(paths, crate::platform::local_stream_peer_is_current_user)?;
    stream.set_send_timeout(Some(LOCAL_REQUEST_TIMEOUT))?;
    stream.set_recv_timeout(Some(wait))?;
    protocol::write_local_request(&mut &stream, request)?;
    let response = protocol::read_local_response(&mut &stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the link holder closed the connection without answering",
        )
    })?;
    Ok((stream, response))
}

/// Sends exactly `size` bytes of `executable` to the machine of `paths` as
/// an update. A refusal by the hub comes back as a failed result.
pub(crate) fn send_update(
    paths: &LinkPaths,
    executable: &mut impl Read,
    size: u64,
    sha256: &str,
    version: Option<&str>,
) -> io::Result<UpdateResult> {
    let request = LocalRequest::Update {
        size,
        sha256: sha256.to_string(),
        version: version.map(str::to_string),
    };
    let (stream, response) = local_request(paths, &request, LOCAL_REQUEST_TIMEOUT)?;
    if !response.ok {
        return Ok(UpdateResult {
            ok: false,
            code: response.code,
            message: response.message,
            version: None,
        });
    }
    stream.set_send_timeout(Some(UPDATE_IO_TIMEOUT))?;
    stream.set_recv_timeout(Some(UPDATE_IO_TIMEOUT))?;
    let sent = io::copy(&mut executable.take(size), &mut &stream);
    // The machine answers even when it stopped reading early.
    match protocol::read_json_line_unbuffered(&mut &stream, MAX_CONTROL_LINE_BYTES) {
        Ok(Some(result)) => Ok(result),
        read => {
            let sent = sent?;
            if sent < size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("the executable ended after {sent} of {size} bytes"),
                ));
            }
            read?;
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the machine closed the update stream without a result",
            ))
        }
    }
}

/// Asks the machine of `paths` to restart its Herdr server for `session`.
pub(crate) fn restart_server(paths: &LinkPaths, session: &str) -> io::Result<LocalResponse> {
    let request = LocalRequest::RestartServer {
        session: session.to_string(),
    };
    local_request(paths, &request, RESTART_WAIT + LOCAL_REQUEST_TIMEOUT)
        .map(|(_, response)| response)
}
