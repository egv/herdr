//! Dial-in link wire formats: control-channel messages and framing, the
//! ready marker, the command grammar the dialer asks sshd to run, stream
//! nonces, and the hub-local operations served on `link.sock`.
//!
//! Every link type tolerates unknown fields and unknown `type`/`op` values so
//! newer peers can extend messages without breaking older ones.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::status::LinkStatus;
use super::{LINK_READY_MARKER, MAX_CONTROL_LINE_BYTES};
use crate::client::endpoint::ProfileId;

/// Maximum accepted length of a requested (SSH_ORIGINAL_COMMAND) command.
pub(crate) const MAX_REQUESTED_COMMAND_BYTES: usize = 512;
/// Length of a stream nonce in lowercase hex characters.
pub(crate) const NONCE_HEX_CHARS: usize = 32;

/// Optional link features a peer advertises in its `Hello.features`. A feature
/// is used only when the peer advertises it; older peers advertise none.
pub(crate) mod feature {
    pub(crate) const AGENT: &str = "agent";
    pub(crate) const UPDATE: &str = "update";
    pub(crate) const RESTART_SERVER: &str = "restart_server";
    /// The features this build implements, advertised by [`super::Hello::local`].
    pub(crate) const SUPPORTED: &[&str] = &[AGENT, UPDATE, RESTART_SERVER];
}

/// Largest executable an update stream may carry.
const MAX_UPDATE_BYTES: u64 = 512 * 1024 * 1024;
/// Longest `version` an update request may name.
const MAX_UPDATE_VERSION_BYTES: usize = 64;

/// Checks the fields of an update request (`LocalRequest::Update` on the hub,
/// an update `Open` on the dialer): a non-empty size within
/// [`MAX_UPDATE_BYTES`], a lowercase hex SHA-256, and a short printable version.
pub(crate) fn check_update_request(
    size: u64,
    sha256: &str,
    version: Option<&str>,
) -> Result<(), String> {
    if size == 0 || size > MAX_UPDATE_BYTES {
        return Err(format!(
            "update size must be between 1 and {MAX_UPDATE_BYTES} bytes"
        ));
    }
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("update sha256 must be 64 lowercase hexadecimal characters".into());
    }
    if version.is_some_and(|version| !is_valid_update_version(version)) {
        return Err("update version must be a short printable version string".into());
    }
    Ok(())
}

/// A non-empty printable ASCII version of at most 64 bytes.
pub(crate) fn is_valid_update_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_UPDATE_VERSION_BYTES
        && version.bytes().all(|byte| byte.is_ascii_graphic())
}

/// `LinkError.code` values.
pub(crate) mod error_code {
    pub(crate) const LINK_UNKNOWN: &str = "link_unknown";
    pub(crate) const LINK_DISABLED: &str = "link_disabled";
    pub(crate) const LINK_ID_MISMATCH: &str = "link_id_mismatch";
    pub(crate) const LINK_VERSION_UNSUPPORTED: &str = "link_version_unsupported";
    pub(crate) const LINK_BUSY: &str = "link_busy";
    pub(crate) const PROTOCOL_ERROR: &str = "protocol_error";
    pub(crate) const SHUTTING_DOWN: &str = "shutting_down";
}

/// `OpenFailed.code` values (and `stream_timeout` recorded by the acceptor).
pub(crate) mod open_failed_code {
    pub(crate) const INVALID_SESSION: &str = "invalid_session";
    pub(crate) const UNSUPPORTED_KIND: &str = "unsupported_kind";
    pub(crate) const SERVER_NEEDS_UPDATE: &str = "server_needs_update";
    pub(crate) const BRIDGE_FAILED: &str = "bridge_failed";
    pub(crate) const SESSION_REFUSED: &str = "session_refused";
    pub(crate) const SSH_FAILED: &str = "ssh_failed";
    pub(crate) const STREAM_TIMEOUT: &str = "stream_timeout";
    /// Also the `LocalResponse.code` of an `Update` the dialer cannot accept.
    pub(crate) const UPDATE_UNSUPPORTED: &str = "update_unsupported";
}

/// `LocalResponse.code` (and `UpdateResult.code`) values for hub-local operations.
pub(crate) mod local_code {
    pub(crate) const UNSUPPORTED_OP: &str = "unsupported_op";
    pub(crate) const UNKNOWN_NONCE: &str = "unknown_nonce";
    pub(crate) const LINK_BUSY: &str = super::error_code::LINK_BUSY;
    pub(crate) const AGENT_DISABLED: &str = "agent_disabled";
    pub(crate) const NO_AGENT: &str = "no_agent";
    pub(crate) const UPDATE_REJECTED: &str = "update_rejected";
    pub(crate) const UPDATE_FAILED: &str = "update_failed";
    pub(crate) const RESTART_FAILED: &str = "restart_failed";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ControlMessage {
    Hello(Hello),
    Error(LinkError),
    Open(OpenRequest),
    OpenFailed(OpenFailed),
    Ping {
        seq: u64,
    },
    Pong {
        seq: u64,
    },
    /// Acceptor to dialer: the hub catalog's agent forwarding setting for
    /// this link changed while the link was up.
    AgentForwarding {
        enabled: bool,
    },
    /// Acceptor to dialer: restart the Herdr server of `session`.
    RestartServer {
        request_id: String,
        session: String,
    },
    /// Dialer to acceptor: the outcome of a [`ControlMessage::RestartServer`].
    RestartServerResult {
        request_id: String,
        ok: bool,
        message: String,
    },
    /// A message type this build does not know; receivers ignore it.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelloRole {
    Dialer,
    Acceptor,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Hello {
    pub(crate) role: HelloRole,
    pub(crate) link_min: u32,
    pub(crate) link_max: u32,
    /// Dialer: the id from its config. Acceptor: the id from its argv.
    pub(crate) link_id: String,
    #[serde(default)]
    pub(crate) herdr_version: Option<String>,
    #[serde(default)]
    pub(crate) protocol_version: Option<u32>,
    #[serde(default)]
    pub(crate) os: Option<String>,
    #[serde(default)]
    pub(crate) arch: Option<String>,
    #[serde(default)]
    pub(crate) hostname: Option<String>,
    /// Acceptor to dialer: sessions to prewarm.
    #[serde(default)]
    pub(crate) sessions: Vec<String>,
    /// Optional features this peer implements (see [`feature`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) features: Vec<String>,
    /// Dialer to acceptor: why its previous attempt failed (sanitized, bounded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_dial_error: Option<String>,
    /// Acceptor to dialer: whether the hub forwards SSH agent access to this link.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) agent_forwarding: bool,
}

impl Hello {
    /// A hello describing this build and host, with no sessions.
    pub(crate) fn local(role: HelloRole, link_id: impl Into<String>) -> Self {
        Self {
            role,
            link_min: super::LINK_VERSION_MIN,
            link_max: super::LINK_VERSION_MAX,
            link_id: link_id.into(),
            herdr_version: Some(crate::build_info::version()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
            os: Some(std::env::consts::OS.to_string()),
            arch: Some(std::env::consts::ARCH.to_string()),
            hostname: crate::platform::hostname(),
            sessions: Vec::new(),
            features: feature::SUPPORTED
                .iter()
                .map(|name| name.to_string())
                .collect(),
            last_dial_error: None,
            agent_forwarding: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkError {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl LinkError {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamKind {
    Client,
    Api,
    /// A new Herdr executable for the dialing machine (see [`UpdateResult`]).
    Update,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpenRequest {
    pub(crate) nonce: String,
    pub(crate) kind: StreamKind,
    pub(crate) session: String,
    /// Update streams: the exact number of executable bytes that follow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    /// Update streams: lowercase hex SHA-256 of those bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sha256: Option<String>,
    /// Update streams: the Herdr version being installed, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
}

impl OpenRequest {
    /// A client or API stream request (no update fields).
    pub(crate) fn stream(nonce: String, kind: StreamKind, session: String) -> Self {
        Self {
            nonce,
            kind,
            session,
            size: None,
            sha256: None,
            version: None,
        }
    }
}

/// The one JSON line a dialer writes back on an update stream after it
/// received (and verified, installed, or refused) the executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UpdateResult {
    pub(crate) ok: bool,
    /// A [`local_code`] value when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    /// The installed version when `ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpenFailed {
    pub(crate) nonce: String,
    pub(crate) code: String,
    pub(crate) message: String,
}

/// The highest link version both ranges support, if any.
pub(crate) fn negotiate_version(a_min: u32, a_max: u32, b_min: u32, b_max: u32) -> Option<u32> {
    if a_min > a_max || b_min > b_max {
        return None;
    }
    let version = a_max.min(b_max);
    (version >= a_min.max(b_min)).then_some(version)
}

/// Writes one JSON value as a single `\n`-terminated line and flushes.
pub(crate) fn write_json_line<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(io::Error::other)?;
    if line.len() > MAX_CONTROL_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("link message exceeds {MAX_CONTROL_LINE_BYTES} bytes"),
        ));
    }
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()
}

pub(crate) fn write_control_message(
    writer: &mut impl Write,
    message: &ControlMessage,
) -> io::Result<()> {
    write_json_line(writer, message)
}

/// Decodes one line (without its `\n`). Blank lines decode to `None`.
fn decode_json_line<T: DeserializeOwned>(line: &[u8]) -> io::Result<Option<T>> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    serde_json::from_slice(line)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Reads newline-delimited control messages from a byte stream with a fixed,
/// bounded line buffer.
pub(crate) struct ControlReader<R> {
    inner: R,
    buffer: Vec<u8>,
    filled: usize,
    scanned: usize,
}

impl<R: Read> ControlReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self::with_leftover(inner, Vec::new())
    }

    /// Starts with bytes already read from `inner`, such as the bytes after
    /// the ready marker returned by [`discard_until_marker`].
    pub(crate) fn with_leftover(inner: R, mut leftover: Vec<u8>) -> Self {
        let filled = leftover.len();
        leftover.resize(filled.max(MAX_CONTROL_LINE_BYTES + 1), 0);
        Self {
            inner,
            buffer: leftover,
            filled,
            scanned: 0,
        }
    }

    /// The next message; `None` on clean EOF at a line boundary. Oversized
    /// lines and undecodable JSON fail with `InvalidData`; EOF in the middle
    /// of a line fails with `UnexpectedEof`. Unknown message types decode to
    /// [`ControlMessage::Unknown`].
    pub(crate) fn read_message(&mut self) -> io::Result<Option<ControlMessage>> {
        loop {
            if let Some(offset) = self.buffer[self.scanned..self.filled]
                .iter()
                .position(|&byte| byte == b'\n')
            {
                let end = self.scanned + offset;
                let decoded = if end > MAX_CONTROL_LINE_BYTES {
                    Err(oversized_line_error())
                } else {
                    decode_json_line(&self.buffer[..end])
                };
                self.buffer.copy_within(end + 1..self.filled, 0);
                self.filled -= end + 1;
                self.scanned = 0;
                match decoded? {
                    Some(message) => return Ok(Some(message)),
                    None => continue,
                }
            }
            self.scanned = self.filled;
            if self.filled > MAX_CONTROL_LINE_BYTES {
                return Err(oversized_line_error());
            }
            let read = match self.inner.read(&mut self.buffer[self.filled..]) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if read == 0 {
                if self.filled == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "link control stream ended in the middle of a message",
                ));
            }
            self.filled += read;
        }
    }
}

fn oversized_line_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("link control line exceeds {MAX_CONTROL_LINE_BYTES} bytes"),
    )
}

/// Writes `"\n" + LINK_READY_MARKER + "\n"` and flushes.
pub(crate) fn write_marker(writer: &mut impl Write) -> io::Result<()> {
    let mut marker = Vec::with_capacity(LINK_READY_MARKER.len() + 2);
    marker.push(b'\n');
    marker.extend_from_slice(LINK_READY_MARKER.as_bytes());
    marker.push(b'\n');
    writer.write_all(&marker)?;
    writer.flush()
}

/// Discards remote output (for example shell rc noise) up to and including a
/// line equal to the ready marker (trailing `\r` tolerated). Returns the bytes
/// already read after the marker line; callers must process them before
/// reading `reader` again. Fails with `InvalidData` once more than `max`
/// bytes were discarded without a marker, and `UnexpectedEof` on EOF. Callers
/// enforce the deadline. Matches `discard_remote_output_preamble` in
/// `remote/attach.rs`.
pub(crate) fn discard_until_marker(reader: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let marker = LINK_READY_MARKER.as_bytes();
    let mut matched = 0;
    let mut matching = true;
    let mut consumed_total = 0usize;
    let mut chunk = [0_u8; 4 * 1024];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "remote command exited before printing the herdr link ready marker",
                ))
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        for (index, &byte) in chunk[..read].iter().enumerate() {
            if consumed_total >= max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "remote output exceeded {max} bytes before the herdr link ready marker"
                    ),
                ));
            }
            consumed_total += 1;
            if byte == b'\n' {
                if matching && matched == marker.len() {
                    return Ok(chunk[index + 1..read].to_vec());
                }
                matched = 0;
                matching = true;
            } else if matching && matched < marker.len() && byte == marker[matched] {
                matched += 1;
            } else if matching && (matched != marker.len() || byte != b'\r') {
                matching = false;
            }
        }
    }
}

/// A random-enough single-use stream nonce: 32 lowercase hex characters.
pub(crate) fn generate_nonce() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher as _, Hasher as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);

    let sequence = NEXT_NONCE.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stack_marker = 0_u8;
    let stack_address = std::ptr::addr_of!(stack_marker) as usize;
    // RandomState keys come from the OS random source.
    let mut keyed = RandomState::new().build_hasher();
    keyed.write_u64(sequence);
    let keyed = keyed.finish();

    let mut digest = Sha256::new();
    digest.update(std::process::id().to_le_bytes());
    digest.update(now.to_le_bytes());
    digest.update(sequence.to_le_bytes());
    digest.update(stack_address.to_le_bytes());
    digest.update(keyed.to_le_bytes());
    let digest = digest.finalize();
    digest[..NONCE_HEX_CHARS / 2]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn is_valid_nonce(value: &str) -> bool {
    value.len() == NONCE_HEX_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The session mode requested by the dialer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RequestedMode {
    Control,
    Stream {
        nonce: String,
    },
    /// An SSH agent relay session for the dialing machine.
    Agent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestedCommand {
    pub(crate) link_id: ProfileId,
    pub(crate) mode: RequestedMode,
}

/// `herdr link-accept --link <id> --mode control`
pub(crate) fn control_command(id: &ProfileId) -> String {
    format!("herdr link-accept --link {id} --mode control")
}

/// `herdr link-accept --link <id> --mode stream --nonce <nonce>`
pub(crate) fn stream_command(id: &ProfileId, nonce: &str) -> String {
    format!("herdr link-accept --link {id} --mode stream --nonce {nonce}")
}

/// `herdr link-accept --link <id> --mode agent`
pub(crate) fn agent_command(id: &ProfileId) -> String {
    format!("herdr link-accept --link {id} --mode agent")
}

/// Parses the command a dialer asked sshd to run (SSH_ORIGINAL_COMMAND under
/// a forced command). The first token is ignored, the second must be
/// `link-accept`, then `--link`, `--mode` and `--nonce` each appear at most
/// once in any order with a value; nothing else is accepted. The caller must
/// still check `link_id` against its argv, which is the identity authority.
pub(crate) fn parse_requested_command(command: &str) -> Result<RequestedCommand, String> {
    if command.len() > MAX_REQUESTED_COMMAND_BYTES {
        return Err(format!(
            "requested command exceeds {MAX_REQUESTED_COMMAND_BYTES} bytes"
        ));
    }
    if command
        .chars()
        .any(|ch| ch.is_control() && ch != ' ' && ch != '\t')
    {
        return Err("requested command contains control characters".into());
    }
    let mut tokens = command.split([' ', '\t']).filter(|token| !token.is_empty());
    if tokens.next().is_none() {
        return Err("requested command is empty".into());
    }
    if tokens.next() != Some("link-accept") {
        return Err("requested command is not link-accept".into());
    }
    let mut link = None;
    let mut mode = None;
    let mut nonce = None;
    while let Some(flag) = tokens.next() {
        let slot = match flag {
            "--link" => &mut link,
            "--mode" => &mut mode,
            "--nonce" => &mut nonce,
            _ => return Err("requested command contains an unexpected argument".into()),
        };
        if slot.is_some() {
            return Err(format!("requested command repeats {flag}"));
        }
        let Some(value) = tokens.next() else {
            return Err(format!("requested command is missing a value for {flag}"));
        };
        *slot = Some(value);
    }
    let link_id = ProfileId::parse(link.ok_or("requested command is missing --link")?)
        .map_err(|_| "requested command has an invalid --link id".to_string())?;
    let mode = match (mode.ok_or("requested command is missing --mode")?, nonce) {
        ("control", None) => RequestedMode::Control,
        ("control", Some(_)) => {
            return Err("requested control session must not carry --nonce".into())
        }
        ("stream", Some(nonce)) if is_valid_nonce(nonce) => RequestedMode::Stream {
            nonce: nonce.to_string(),
        },
        ("stream", Some(_)) => return Err("requested command has an invalid --nonce".into()),
        ("stream", None) => return Err("requested stream session is missing --nonce".into()),
        ("agent", None) => RequestedMode::Agent,
        ("agent", Some(_)) => return Err("requested agent session must not carry --nonce".into()),
        _ => return Err("requested command has an unknown --mode".into()),
    };
    Ok(RequestedCommand { link_id, mode })
}

/// One request line on `link.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum LocalRequest {
    /// On success the connection becomes a raw relay to the pending hub
    /// connection for `nonce`.
    Attach {
        nonce: String,
    },
    Status,
    /// A new link from the dialer at `peer_addr` asks the holder to yield.
    Supersede {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_addr: Option<String>,
    },
    /// A hub client lends its SSH agent at `socket` to this link while the
    /// connection stays open.
    AgentLease {
        socket: String,
    },
    /// The agent socket of the most recent live lease (`agent_socket`).
    AgentTarget,
    /// On `ok` the connection becomes the update data source: the client
    /// writes exactly `size` raw bytes, then reads one [`UpdateResult`] line.
    Update {
        size: u64,
        sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// Restarts the dialing machine's Herdr server for `session`.
    RestartServer {
        session: String,
    },
    #[serde(other)]
    Unknown,
}

/// One response line on `link.sock`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct LocalResponse {
    pub(crate) ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<LinkStatus>,
    /// `AgentTarget`: the leased agent socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent_socket: Option<String>,
}

impl LocalResponse {
    pub(crate) fn ok() -> Self {
        Self {
            ok: true,
            code: None,
            message: None,
            status: None,
            agent_socket: None,
        }
    }

    pub(crate) fn with_status(status: LinkStatus) -> Self {
        Self {
            status: Some(status),
            ..Self::ok()
        }
    }

    pub(crate) fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: Some(code.into()),
            message: Some(message.into()),
            ..Self::ok()
        }
    }
}

/// Reads exactly one `\n`-terminated JSON line without reading past it, so
/// raw bytes that follow (an attached relay) stay in `reader`. Returns `None`
/// on EOF before any byte. Lines longer than `max` fail with `InvalidData`.
pub(crate) fn read_json_line_unbuffered<T: DeserializeOwned>(
    reader: &mut impl Read,
    max: usize,
) -> io::Result<Option<T>> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) if line.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "link peer closed the connection in the middle of a message",
                ))
            }
            Ok(_) if byte[0] == b'\n' => {
                return match decode_json_line(&line)? {
                    Some(value) => Ok(Some(value)),
                    None => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "link peer sent an empty message",
                    )),
                };
            }
            Ok(_) => {
                if line.len() >= max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("link message exceeds {max} bytes"),
                    ));
                }
                line.push(byte[0]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn write_local_request(
    writer: &mut impl Write,
    request: &LocalRequest,
) -> io::Result<()> {
    write_json_line(writer, request)
}

pub(crate) fn read_local_request(reader: &mut impl Read) -> io::Result<Option<LocalRequest>> {
    read_json_line_unbuffered(reader, MAX_CONTROL_LINE_BYTES)
}

pub(crate) fn write_local_response(
    writer: &mut impl Write,
    response: &LocalResponse,
) -> io::Result<()> {
    write_json_line(writer, response)
}

pub(crate) fn read_local_response(reader: &mut impl Read) -> io::Result<Option<LocalResponse>> {
    read_json_line_unbuffered(reader, MAX_CONTROL_LINE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::link::MAX_PREAMBLE_BYTES;
    use std::io::Cursor;

    fn id() -> ProfileId {
        ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    /// Yields its data in fixed-size pieces to exercise split reads.
    struct Chunked {
        data: Vec<u8>,
        offset: usize,
        chunk: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let end = (self.offset + self.chunk.min(buffer.len())).min(self.data.len());
            let count = end - self.offset;
            buffer[..count].copy_from_slice(&self.data[self.offset..end]);
            self.offset = end;
            Ok(count)
        }
    }

    fn sample_messages() -> Vec<ControlMessage> {
        let mut hello = Hello::local(HelloRole::Dialer, id().to_string());
        hello.sessions = vec!["default".into(), "work".into()];
        vec![
            ControlMessage::Hello(hello),
            ControlMessage::Hello(Hello {
                role: HelloRole::Acceptor,
                link_min: 1,
                link_max: 1,
                link_id: id().to_string(),
                herdr_version: None,
                protocol_version: None,
                os: None,
                arch: None,
                hostname: None,
                sessions: Vec::new(),
                features: vec![feature::AGENT.into(), "future".into()],
                last_dial_error: Some("ssh: connection refused".into()),
                agent_forwarding: true,
            }),
            ControlMessage::Error(LinkError::new(error_code::LINK_BUSY, "busy")),
            ControlMessage::Open(OpenRequest::stream(
                NONCE.into(),
                StreamKind::Client,
                "default".into(),
            )),
            ControlMessage::Open(OpenRequest::stream(
                NONCE.into(),
                StreamKind::Api,
                "work".into(),
            )),
            ControlMessage::Open(update_open()),
            ControlMessage::OpenFailed(OpenFailed {
                nonce: NONCE.into(),
                code: open_failed_code::BRIDGE_FAILED.into(),
                message: "bridge exited".into(),
            }),
            ControlMessage::Ping { seq: 7 },
            ControlMessage::Pong { seq: u64::MAX },
            ControlMessage::AgentForwarding { enabled: true },
            ControlMessage::RestartServer {
                request_id: "r1".into(),
                session: "work".into(),
            },
            ControlMessage::RestartServerResult {
                request_id: "r1".into(),
                ok: false,
                message: "stop timed out".into(),
            },
        ]
    }

    fn update_open() -> OpenRequest {
        OpenRequest {
            size: Some(1 << 20),
            sha256: Some("ab".repeat(32)),
            version: Some("0.9.4".into()),
            ..OpenRequest::stream(NONCE.into(), StreamKind::Update, String::new())
        }
    }

    #[test]
    fn control_messages_round_trip_through_framing() {
        let messages = sample_messages();
        let mut wire = Vec::new();
        for message in &messages {
            write_control_message(&mut wire, message).unwrap();
        }
        assert_eq!(
            wire.iter().filter(|&&byte| byte == b'\n').count(),
            messages.len()
        );
        for chunk in [1, 3, 64, 1 << 20] {
            let mut reader = ControlReader::new(Chunked {
                data: wire.clone(),
                offset: 0,
                chunk,
            });
            for expected in &messages {
                assert_eq!(reader.read_message().unwrap().as_ref(), Some(expected));
            }
            assert_eq!(reader.read_message().unwrap(), None);
        }
    }

    #[test]
    fn control_message_wire_shape_is_tagged_snake_case() {
        let mut wire = Vec::new();
        write_control_message(
            &mut wire,
            &ControlMessage::OpenFailed(OpenFailed {
                nonce: NONCE.into(),
                code: "bridge_failed".into(),
                message: "m".into(),
            }),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(value["type"], "open_failed");
        let mut wire = Vec::new();
        write_control_message(&mut wire, &ControlMessage::Ping { seq: 1 }).unwrap();
        assert_eq!(wire, b"{\"type\":\"ping\",\"seq\":1}\n");
        let open = serde_json::to_value(ControlMessage::Open(OpenRequest::stream(
            NONCE.into(),
            StreamKind::Api,
            "s".into(),
        )))
        .unwrap();
        assert_eq!(open["kind"], "api");
        let hello = serde_json::to_value(ControlMessage::Hello(Hello::local(
            HelloRole::Acceptor,
            "x",
        )))
        .unwrap();
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["role"], "acceptor");
        let update = serde_json::to_value(ControlMessage::Open(update_open())).unwrap();
        assert_eq!(update["kind"], "update");
        assert_eq!(update["size"], 1 << 20);
        let restart = serde_json::to_value(ControlMessage::RestartServerResult {
            request_id: "r".into(),
            ok: true,
            message: String::new(),
        })
        .unwrap();
        assert_eq!(restart["type"], "restart_server_result");
        assert_eq!(
            serde_json::to_string(&ControlMessage::AgentForwarding { enabled: false }).unwrap(),
            "{\"type\":\"agent_forwarding\",\"enabled\":false}"
        );
    }

    #[test]
    fn additive_fields_keep_the_old_wire_shape_when_unset() {
        // Old peers wrote (and parse) these shapes; unset new fields add nothing.
        let mut hello = Hello::local(HelloRole::Dialer, "x");
        hello.features.clear();
        let value = serde_json::to_value(&hello).unwrap();
        for key in ["features", "last_dial_error", "agent_forwarding"] {
            assert!(value.get(key).is_none(), "{key} must be omitted: {value}");
        }
        let open = serde_json::to_value(OpenRequest::stream(
            NONCE.into(),
            StreamKind::Client,
            "s".into(),
        ))
        .unwrap();
        assert_eq!(
            open,
            serde_json::json!({"nonce": NONCE, "kind": "client", "session": "s"})
        );
        assert_eq!(
            serde_json::to_string(&LocalResponse::ok()).unwrap(),
            "{\"ok\":true}"
        );

        // An old peer's hello and open decode with the new fields defaulted.
        let old: Hello = serde_json::from_str(
            r#"{"role":"acceptor","link_min":1,"link_max":1,"link_id":"x","sessions":["default"]}"#,
        )
        .unwrap();
        assert!(old.features.is_empty());
        assert_eq!(old.last_dial_error, None);
        assert!(!old.agent_forwarding);
        let old: OpenRequest =
            serde_json::from_str(r#"{"nonce":"n","kind":"api","session":"s"}"#).unwrap();
        assert_eq!((old.size, old.sha256, old.version), (None, None, None));
        assert_eq!(
            Hello::local(HelloRole::Dialer, "x").features,
            feature::SUPPORTED
        );
    }

    #[test]
    fn update_result_line_round_trips_and_tolerates_unknown_fields() {
        for result in [
            UpdateResult {
                ok: true,
                code: None,
                message: None,
                version: Some("0.9.4".into()),
            },
            UpdateResult {
                ok: false,
                code: Some(local_code::UPDATE_REJECTED.into()),
                message: Some("package-managed install".into()),
                version: None,
            },
        ] {
            let mut wire = Vec::new();
            write_json_line(&mut wire, &result).unwrap();
            let decoded: Option<UpdateResult> =
                read_json_line_unbuffered(&mut Cursor::new(wire), MAX_CONTROL_LINE_BYTES).unwrap();
            assert_eq!(decoded, Some(result));
        }
        let decoded: UpdateResult = serde_json::from_str(r#"{"ok":false,"later":[1]}"#).unwrap();
        assert!(!decoded.ok);
        assert_eq!(decoded.code, None);
    }

    #[test]
    fn control_reader_tolerates_unknown_types_fields_crlf_and_blank_lines() {
        let wire = concat!(
            "\n",
            "{\"type\":\"future_thing\",\"payload\":{\"a\":[1,2]}}\n",
            "{\"type\":\"ping\",\"seq\":3,\"extra\":true}\r\n",
            "   \r\n",
            "{\"type\":\"hello\",\"role\":\"relay\",\"link_min\":1,\"link_max\":4,",
            "\"link_id\":\"abc\",\"new_field\":{}}\n",
            "{\"type\":\"open\",\"nonce\":\"n\",\"kind\":\"terminal\",\"session\":\"s\"}\n",
        );
        let mut reader = ControlReader::new(Cursor::new(wire.as_bytes().to_vec()));
        assert_eq!(
            reader.read_message().unwrap(),
            Some(ControlMessage::Unknown)
        );
        assert_eq!(
            reader.read_message().unwrap(),
            Some(ControlMessage::Ping { seq: 3 })
        );
        let Some(ControlMessage::Hello(hello)) = reader.read_message().unwrap() else {
            panic!("expected hello");
        };
        assert_eq!(hello.role, HelloRole::Unknown);
        assert_eq!((hello.link_min, hello.link_max), (1, 4));
        assert_eq!(hello.herdr_version, None);
        assert!(hello.sessions.is_empty());
        let Some(ControlMessage::Open(open)) = reader.read_message().unwrap() else {
            panic!("expected open");
        };
        assert_eq!(open.kind, StreamKind::Unknown);
        assert_eq!(reader.read_message().unwrap(), None);
    }

    #[test]
    fn control_reader_rejects_invalid_json_and_known_types_with_bad_fields() {
        for line in [
            "not json\n",
            "{\"type\":\"ping\"}\n",
            "{\"seq\":1}\n",
            "[1,2]\n",
            "{\"type\":\"ping\",\"seq\":-1}\n",
        ] {
            let mut reader = ControlReader::new(Cursor::new(line.as_bytes().to_vec()));
            assert_eq!(
                reader.read_message().unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{line:?}"
            );
        }
        let mut reader = ControlReader::new(Cursor::new(vec![0xff, 0xfe, b'\n']));
        assert_eq!(
            reader.read_message().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn control_reader_enforces_line_limit_and_reports_truncated_eof() {
        let mut oversized = vec![b' '; MAX_CONTROL_LINE_BYTES + 1];
        oversized.push(b'\n');
        let mut reader = ControlReader::new(Cursor::new(oversized));
        assert_eq!(
            reader.read_message().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let endless = Chunked {
            data: vec![b'a'; MAX_CONTROL_LINE_BYTES * 3],
            offset: 0,
            chunk: 1000,
        };
        let mut reader = ControlReader::new(endless);
        assert_eq!(
            reader.read_message().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut at_limit = Vec::new();
        let ping = b"{\"type\":\"ping\",\"seq\":1}";
        at_limit.extend_from_slice(ping);
        at_limit.resize(MAX_CONTROL_LINE_BYTES, b' ');
        at_limit.push(b'\n');
        let mut reader = ControlReader::new(Cursor::new(at_limit));
        assert_eq!(
            reader.read_message().unwrap(),
            Some(ControlMessage::Ping { seq: 1 })
        );

        let mut reader = ControlReader::new(Cursor::new(b"{\"type\":\"ping\"".to_vec()));
        assert_eq!(
            reader.read_message().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut sink = Vec::new();
        let huge = ControlMessage::Error(LinkError::new("x", "y".repeat(MAX_CONTROL_LINE_BYTES)));
        assert_eq!(
            write_control_message(&mut sink, &huge).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn marker_discard_returns_leftover_bytes_and_tolerates_crlf() {
        let mut marker = Vec::new();
        write_marker(&mut marker).unwrap();
        assert_eq!(marker, b"\nherdr-link-ready:1\n");

        let mut wire =
            b"Welcome!\nlast login: herdr-link-ready:1\r\nherdr-link-ready:10\n".to_vec();
        wire.extend_from_slice(b"motd herdr-link-ready:1");
        wire.extend_from_slice(&marker);
        let mut ping = Vec::new();
        write_control_message(&mut ping, &ControlMessage::Ping { seq: 9 }).unwrap();
        wire.extend_from_slice(&ping);
        for chunk in [1, 2, 7, 4096] {
            let mut reader = Chunked {
                data: wire.clone(),
                offset: 0,
                chunk,
            };
            let leftover = discard_until_marker(&mut reader, MAX_PREAMBLE_BYTES).unwrap();
            let mut control = ControlReader::with_leftover(reader, leftover);
            assert_eq!(
                control.read_message().unwrap(),
                Some(ControlMessage::Ping { seq: 9 }),
                "chunk {chunk}"
            );
            assert_eq!(control.read_message().unwrap(), None);
        }

        let mut crlf = Cursor::new(b"noise\r\nherdr-link-ready:1\r\nrest".to_vec());
        assert_eq!(
            discard_until_marker(&mut crlf, MAX_PREAMBLE_BYTES).unwrap(),
            b"rest"
        );
        let mut first_line = Cursor::new(b"herdr-link-ready:1\n".to_vec());
        assert!(discard_until_marker(&mut first_line, 64)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn marker_discard_rejects_eof_overflow_and_near_misses() {
        for wire in [
            &b""[..],
            b"no marker here\n",
            b"herdr-link-ready:1",
            b"xherdr-link-ready:1\n",
            b"herdr-link-ready:1 \n",
            b"herdr-link-ready:\n",
        ] {
            let mut reader = Cursor::new(wire.to_vec());
            assert_eq!(
                discard_until_marker(&mut reader, MAX_PREAMBLE_BYTES)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof,
                "{:?}",
                String::from_utf8_lossy(wire)
            );
        }
        let mut noisy = b"x".repeat(100);
        noisy.extend_from_slice(b"\nherdr-link-ready:1\n");
        assert_eq!(
            discard_until_marker(&mut Cursor::new(noisy.clone()), 50)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(discard_until_marker(&mut Cursor::new(noisy.clone()), noisy.len()).is_ok());
        assert_eq!(
            discard_until_marker(&mut Cursor::new(noisy.clone()), noisy.len() - 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn requested_command_grammar_accepts_exact_forms() {
        let control = parse_requested_command(&control_command(&id())).unwrap();
        assert_eq!(
            control,
            RequestedCommand {
                link_id: id(),
                mode: RequestedMode::Control
            }
        );
        let stream = parse_requested_command(&stream_command(&id(), NONCE)).unwrap();
        assert_eq!(
            stream.mode,
            RequestedMode::Stream {
                nonce: NONCE.into()
            }
        );
        let agent = parse_requested_command(&agent_command(&id())).unwrap();
        assert_eq!(agent.mode, RequestedMode::Agent);
        assert_eq!(agent.link_id, id());
        for accepted in [
            format!(
                "/opt/herdr/bin/herdr link-accept --mode control --link {}",
                id()
            ),
            format!(
                "x link-accept --nonce {NONCE} --link {} --mode stream",
                id()
            ),
            format!("  herdr\tlink-accept  --link {}   --mode control  ", id()),
            format!("/usr/bin/herdr link-accept --mode agent --link {}", id()),
        ] {
            assert!(
                parse_requested_command(&accepted).is_ok(),
                "{accepted:?} should be accepted"
            );
        }
    }

    #[test]
    fn requested_command_grammar_rejects_everything_else() {
        let id = id();
        let rejected = [
            String::new(),
            "   ".into(),
            "herdr".into(),
            format!("herdr link-accepted --link {id} --mode control"),
            format!("herdr --link {id} --mode control"),
            format!("link-accept --link {id} --mode control"),
            format!("herdr link-accept --link {id}"),
            "herdr link-accept --mode control".into(),
            format!("herdr link-accept --link {id} --mode"),
            format!("herdr link-accept --link {id} --mode control --mode control"),
            format!("herdr link-accept --link {id} --link {id} --mode control"),
            format!("herdr link-accept --link {id} --mode control extra"),
            format!("herdr link-accept --link {id} --mode control --catalog /x"),
            format!("herdr link-accept --link={id} --mode control"),
            format!("herdr link-accept --link {id} --mode shell"),
            format!("herdr link-accept --link {id} --mode control --nonce {NONCE}"),
            format!("herdr link-accept --link {id} --mode stream"),
            format!("herdr link-accept --link {id} --mode agent --nonce {NONCE}"),
            format!("herdr link-accept --link {id} --mode agent --mode agent"),
            format!("herdr link-accept --link {id} --mode Agent"),
            format!(
                "herdr link-accept --link {id} --mode stream --nonce {}",
                &NONCE[1..]
            ),
            format!(
                "herdr link-accept --link {id} --mode stream --nonce {}",
                NONCE.to_uppercase()
            ),
            format!("herdr link-accept --link {id} --mode stream --nonce {NONCE}0"),
            format!("herdr link-accept --link {id} --mode stream --nonce --link"),
            format!(
                "herdr link-accept --link {} --mode control",
                id.as_str().to_uppercase()
            ),
            "herdr link-accept --link 0123 --mode control".into(),
            format!("herdr link-accept --link {id} --mode control\n"),
            format!("herdr link-accept --link {id} --mode control; rm -rf ~"),
            format!("herdr link-accept --link {id} --mode control\u{1b}[2J"),
            format!(
                "herdr link-accept --link {id} --mode control {}",
                "x".repeat(600)
            ),
        ];
        for command in rejected {
            assert!(
                parse_requested_command(&command).is_err(),
                "{command:?} should be rejected"
            );
        }
    }

    #[test]
    fn version_negotiation_picks_highest_common_version() {
        assert_eq!(negotiate_version(1, 1, 1, 1), Some(1));
        assert_eq!(negotiate_version(1, 3, 2, 5), Some(3));
        assert_eq!(negotiate_version(2, 5, 1, 3), Some(3));
        assert_eq!(negotiate_version(1, 1, 2, 2), None);
        assert_eq!(negotiate_version(3, 4, 1, 2), None);
        assert_eq!(negotiate_version(2, 1, 1, 2), None);
        assert_eq!(
            negotiate_version(
                super::super::LINK_VERSION_MIN,
                super::super::LINK_VERSION_MAX,
                1,
                u32::MAX
            ),
            Some(super::super::LINK_VERSION_MAX)
        );
    }

    #[test]
    fn nonces_are_unique_lowercase_hex() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let nonce = generate_nonce();
            assert!(is_valid_nonce(&nonce), "{nonce}");
            assert!(seen.insert(nonce));
        }
        assert!(!is_valid_nonce("0011"));
        assert!(!is_valid_nonce(&NONCE.to_uppercase()));
        assert!(!is_valid_nonce(&format!("{}g", &NONCE[1..])));
    }

    #[test]
    fn local_operations_round_trip_and_leave_relay_bytes_unread() {
        for request in [
            LocalRequest::Attach {
                nonce: NONCE.into(),
            },
            LocalRequest::Status,
            LocalRequest::Supersede { peer_addr: None },
            LocalRequest::Supersede {
                peer_addr: Some("192.0.2.1".into()),
            },
            LocalRequest::AgentLease {
                socket: "/tmp/ssh-x/agent.1".into(),
            },
            LocalRequest::AgentTarget,
            LocalRequest::Update {
                size: 42,
                sha256: "00".repeat(32),
                version: None,
            },
            LocalRequest::RestartServer {
                session: "default".into(),
            },
        ] {
            let mut wire = Vec::new();
            write_local_request(&mut wire, &request).unwrap();
            wire.extend_from_slice(b"RAW RELAY BYTES");
            let mut reader = Cursor::new(wire);
            assert_eq!(read_local_request(&mut reader).unwrap(), Some(request));
            let mut rest = Vec::new();
            reader.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, b"RAW RELAY BYTES");
        }
        assert_eq!(
            serde_json::to_string(&LocalRequest::Attach { nonce: "n".into() }).unwrap(),
            "{\"op\":\"attach\",\"nonce\":\"n\"}"
        );
        assert_eq!(
            serde_json::to_string(&LocalRequest::AgentTarget).unwrap(),
            "{\"op\":\"agent_target\"}"
        );
        // A supersede without an address keeps the old shape, and holders
        // that predate the address ignore it.
        assert_eq!(
            serde_json::to_string(&LocalRequest::Supersede { peer_addr: None }).unwrap(),
            "{\"op\":\"supersede\"}"
        );
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case")]
        enum OlderRequest {
            Supersede,
        }
        assert_eq!(
            serde_json::from_str::<OlderRequest>("{\"op\":\"supersede\",\"peer_addr\":\"x\"}")
                .unwrap(),
            OlderRequest::Supersede
        );
        let mut reader = Cursor::new(b"{\"op\":\"reboot\",\"force\":true}\n".to_vec());
        assert_eq!(
            read_local_request(&mut reader).unwrap(),
            Some(LocalRequest::Unknown)
        );
        assert_eq!(read_local_request(&mut reader).unwrap(), None);

        let status = LinkStatus {
            link_epoch: 4,
            ..LinkStatus::default()
        };
        for response in [
            LocalResponse::ok(),
            LocalResponse::error(local_code::LINK_BUSY, "still alive"),
            LocalResponse::with_status(status),
            LocalResponse {
                agent_socket: Some("/tmp/ssh-x/agent.1".into()),
                ..LocalResponse::ok()
            },
        ] {
            let mut wire = Vec::new();
            write_local_response(&mut wire, &response).unwrap();
            assert_eq!(
                read_local_response(&mut Cursor::new(wire)).unwrap(),
                Some(response)
            );
        }
        let mut reader = Cursor::new(b"{\"ok\":false,\"later\":1}\n".to_vec());
        let response = read_local_response(&mut reader).unwrap().unwrap();
        assert!(!response.ok);
        assert_eq!(response.code, None);
    }

    #[test]
    fn unbuffered_line_reader_rejects_oversize_truncation_and_empty_lines() {
        let mut long = vec![b'{'; 100];
        long.push(b'\n');
        assert_eq!(
            read_json_line_unbuffered::<LocalResponse>(&mut Cursor::new(long), 10)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_local_response(&mut Cursor::new(b"{\"ok\":true}".to_vec()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            read_local_response(&mut Cursor::new(b"\n".to_vec()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
