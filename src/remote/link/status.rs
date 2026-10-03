//! Hub-side `status.json` for one dial-in link: written by the link holder on
//! state transitions, read by the hub TUI and CLI without probing the link.

use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::protocol::Hello;

pub(crate) const LINK_STATUS_VERSION: u32 = 1;
pub(crate) const MAX_STATUS_BYTES: usize = 64 * 1024;
/// Upper bound for any slave-provided string stored in `status.json`.
pub(crate) const MAX_REMOTE_TEXT_BYTES: usize = 512;
/// Upper bounds for the feature names a peer advertises.
const MAX_FEATURES: usize = 32;
const MAX_FEATURE_BYTES: usize = 64;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinkState {
    Connected,
    Disconnected,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SlaveInfo {
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
    /// Optional link features the peer advertised.
    #[serde(default)]
    pub(crate) features: Vec<String>,
    /// Why the dialer's previous attempt failed, as it reported.
    #[serde(default)]
    pub(crate) last_dial_error: Option<String>,
}

impl SlaveInfo {
    /// Peer facts from a hello, sanitized for storage and display.
    pub(crate) fn from_hello(hello: &Hello) -> Self {
        let text = |value: &Option<String>| {
            value
                .as_deref()
                .map(|value| sanitize_remote_text(value, MAX_REMOTE_TEXT_BYTES))
                .filter(|value| !value.is_empty())
        };
        Self {
            herdr_version: text(&hello.herdr_version),
            protocol_version: hello.protocol_version,
            os: text(&hello.os),
            arch: text(&hello.arch),
            hostname: text(&hello.hostname),
            features: hello
                .features
                .iter()
                .take(MAX_FEATURES)
                .map(|name| sanitize_remote_text(name, MAX_FEATURE_BYTES))
                .filter(|name| !name.is_empty())
                .collect(),
            last_dial_error: text(&hello.last_dial_error),
        }
    }
}

/// One claim of the link by another dialer: a takeover, or a claim from
/// another address that the live link refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SupersedeRecord {
    pub(crate) at_ms: u64,
    #[serde(default)]
    pub(crate) peer_addr: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ErrorRecord {
    pub(crate) at_ms: u64,
    pub(crate) code: String,
    pub(crate) message: String,
}

impl ErrorRecord {
    /// A record stamped now, with both strings sanitized.
    pub(crate) fn new(code: &str, message: &str) -> Self {
        Self {
            at_ms: now_ms(),
            code: sanitize_remote_text(code, 64),
            message: sanitize_remote_text(message, MAX_REMOTE_TEXT_BYTES),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkStatus {
    pub(crate) version: u32,
    pub(crate) state: LinkState,
    /// Increments each time a link reaches `connected`.
    #[serde(default)]
    pub(crate) link_epoch: u64,
    #[serde(default)]
    pub(crate) pid: Option<u32>,
    #[serde(default)]
    pub(crate) updated_at_ms: u64,
    #[serde(default)]
    pub(crate) connected_since_ms: Option<u64>,
    #[serde(default)]
    pub(crate) slave: Option<SlaveInfo>,
    /// Link-level error: why the link is disconnected.
    #[serde(default)]
    pub(crate) last_error: Option<ErrorRecord>,
    /// Latest `OpenFailed` or stream timeout.
    #[serde(default)]
    pub(crate) last_stream_error: Option<ErrorRecord>,
    /// The dialer's client address (first field of sshd's `SSH_CONNECTION`).
    #[serde(default)]
    pub(crate) peer_addr: Option<String>,
    /// Recent claims of this link by other dialers, newest last (bounded).
    #[serde(default)]
    pub(crate) recent_supersedes: Vec<SupersedeRecord>,
    /// Set when more than one machine keeps claiming this link.
    #[serde(default)]
    pub(crate) claim_conflict: Option<String>,
    /// Live agent forwarding leases held by hub clients.
    #[serde(default)]
    pub(crate) agent_leases: u32,
}

impl Default for LinkStatus {
    fn default() -> Self {
        Self {
            version: LINK_STATUS_VERSION,
            state: LinkState::Disconnected,
            link_epoch: 0,
            pid: None,
            updated_at_ms: 0,
            connected_since_ms: None,
            slave: None,
            last_error: None,
            last_stream_error: None,
            peer_addr: None,
            recent_supersedes: Vec::new(),
            claim_conflict: None,
            agent_leases: 0,
        }
    }
}

impl LinkStatus {
    pub(crate) fn is_connected(&self) -> bool {
        self.state == LinkState::Connected
    }

    /// Connected, and the holder process that wrote this still runs. A
    /// holder killed without its cleanup (SIGKILL, a crash, power loss)
    /// leaves `connected` behind; its recorded pid tells it apart.
    pub(crate) fn is_live(&self) -> bool {
        self.is_connected() && self.pid.is_none_or(crate::platform::process_exists)
    }
}

/// Reads `status.json`. `Ok(None)` when it does not exist. The file must be
/// owned by the effective user (never followed through a symlink) and at
/// most `MAX_STATUS_BYTES`.
pub(crate) fn read_status(path: &Path) -> io::Result<Option<LinkStatus>> {
    match crate::platform::file_is_owned_by_current_user(path) {
        Ok(true) => {}
        Ok(false) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to read link status not owned by the current user: {}",
                    path.display()
                ),
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let content = match crate::platform::read_limited_reader(file, MAX_STATUS_BYTES)? {
        crate::platform::LimitedRead::Complete(content) => content,
        crate::platform::LimitedRead::Empty => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "link status file is empty",
            ))
        }
        crate::platform::LimitedRead::Oversized => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("link status file exceeds {MAX_STATUS_BYTES} bytes"),
            ))
        }
    };
    serde_json::from_slice(&content)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Atomically replaces `status.json` (private temp file + rename). Runtime
/// state: no fsync. The parent directory must already exist.
pub(crate) fn write_status(path: &Path, status: &LinkStatus) -> io::Result<()> {
    let content = serde_json::to_vec_pretty(status).map_err(io::Error::other)?;
    if content.len() > MAX_STATUS_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("link status exceeds {MAX_STATUS_BYTES} bytes"),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(".status-{}-{sequence}.tmp", std::process::id()));
    let mut temp = crate::platform::create_private_state_file(&temp_path)?;
    if let Err(error) = temp.write_all(&content) {
        drop(temp);
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    drop(temp);
    if let Err(error) = crate::platform::replace_file(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

/// Makes slave-provided text safe for storage and terminal output: newlines
/// and tabs become spaces, other control characters (C0, DEL, C1, including
/// ESC) and bidirectional overrides are removed, surrounding whitespace is
/// trimmed, and the result is at most `max` bytes (truncated on a character
/// boundary, ending in `...` when there is room).
pub(crate) fn sanitize_remote_text(text: &str, max: usize) -> String {
    let mut cleaned = String::with_capacity(text.len().min(max.saturating_add(4)));
    for ch in text.chars() {
        let ch = match ch {
            '\n' | '\r' | '\t' => ' ',
            ch if ch.is_control() || is_bidi_control(ch) => continue,
            ch => ch,
        };
        cleaned.push(ch);
        if cleaned.len() > max.saturating_add(4) {
            break;
        }
    }
    let trimmed = cleaned.trim();
    if trimmed.len() <= max {
        return trimmed.to_string();
    }
    let ellipsis = if max >= 3 { "..." } else { "" };
    let mut end = max - ellipsis.len();
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ellipsis}", trimmed[..end].trim_end())
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Milliseconds since the Unix epoch (0 if the clock is before it).
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::remote::link::protocol::HelloRole;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("herdr-link-status-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::platform::ensure_private_directory(&dir).unwrap();
        dir
    }

    fn connected_status() -> LinkStatus {
        LinkStatus {
            state: LinkState::Connected,
            link_epoch: 3,
            pid: Some(42),
            updated_at_ms: 10,
            connected_since_ms: Some(9),
            slave: Some(SlaveInfo {
                herdr_version: Some("0.9.3".into()),
                protocol_version: Some(22),
                os: Some("linux".into()),
                arch: Some("x86_64".into()),
                hostname: Some("slave".into()),
                features: vec!["update".into()],
                last_dial_error: Some("ssh exited".into()),
            }),
            last_error: None,
            last_stream_error: Some(ErrorRecord {
                at_ms: 8,
                code: "bridge_failed".into(),
                message: "boom".into(),
            }),
            peer_addr: Some("192.0.2.7".into()),
            recent_supersedes: vec![SupersedeRecord {
                at_ms: 7,
                peer_addr: None,
            }],
            claim_conflict: Some("link claimed by more than one machine".into()),
            agent_leases: 2,
            ..LinkStatus::default()
        }
    }

    #[test]
    fn status_round_trips_atomically_with_private_mode() {
        use std::os::unix::fs::MetadataExt;

        let dir = scratch("roundtrip");
        let path = dir.join("status.json");
        assert_eq!(read_status(&path).unwrap(), None);
        let status = connected_status();
        write_status(&path, &status).unwrap();
        assert_eq!(read_status(&path).unwrap(), Some(status.clone()));
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let mut next = status;
        next.state = LinkState::Disconnected;
        next.last_error = Some(ErrorRecord::new("link_dead", "no pong"));
        write_status(&path, &next).unwrap();
        assert_eq!(read_status(&path).unwrap(), Some(next));
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn status_tolerates_unknown_fields_and_states_and_defaults_optional_fields() {
        let dir = scratch("compat");
        let path = dir.join("status.json");
        std::fs::write(
            &path,
            br#"{"version":1,"state":"degraded","future":{"x":1}}"#,
        )
        .unwrap();
        let status = read_status(&path).unwrap().unwrap();
        assert_eq!(status.state, LinkState::Unknown);
        assert_eq!(status.link_epoch, 0);
        assert_eq!(status.slave, None);
        assert_eq!(status.peer_addr, None);
        assert!(status.recent_supersedes.is_empty());
        assert_eq!((&status.claim_conflict, status.agent_leases), (&None, 0));
        assert!(!status.is_connected());
        let slave: SlaveInfo = serde_json::from_str(r#"{"os":"linux"}"#).unwrap();
        assert!(slave.features.is_empty());
        assert_eq!(slave.last_dial_error, None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn connected_status_of_a_dead_holder_is_not_live() {
        let mut status = LinkStatus {
            state: LinkState::Connected,
            pid: Some(std::process::id()),
            ..LinkStatus::default()
        };
        assert!(status.is_live());
        let mut exited = std::process::Command::new("true").spawn().unwrap();
        exited.wait().unwrap();
        status.pid = Some(exited.id());
        assert!(status.is_connected());
        assert!(!status.is_live());
        status.pid = None;
        assert!(status.is_live());
        status.state = LinkState::Disconnected;
        assert!(!status.is_live());
    }

    #[test]
    fn status_reader_rejects_invalid_oversized_empty_and_symlinked_files() {
        use std::os::unix::fs::symlink;

        let dir = scratch("reject");
        let path = dir.join("status.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(
            read_status(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            read_status(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(&path, vec![b' '; MAX_STATUS_BYTES + 1]).unwrap();
        assert_eq!(
            read_status(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        write_status(&path, &connected_status()).unwrap();
        let link = dir.join("link.json");
        symlink(&path, &link).unwrap();
        assert_eq!(
            read_status(&link).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sanitize_strips_controls_and_bounds_length() {
        assert_eq!(
            sanitize_remote_text("  ok\x1b[31mred\x1b[0m\u{9b}2J\x07  ", 100),
            "ok[31mred[0m2J"
        );
        assert_eq!(sanitize_remote_text("a\nb\r\nc\td", 100), "a b  c d");
        assert_eq!(
            sanitize_remote_text("evil\u{202e}txt.exe", 100),
            "eviltxt.exe"
        );
        assert_eq!(sanitize_remote_text("abcdefghij", 10), "abcdefghij");
        assert_eq!(sanitize_remote_text("abcdefghijk", 10), "abcdefg...");
        assert_eq!(sanitize_remote_text("abcdef", 2), "ab");
        assert_eq!(sanitize_remote_text("abc", 0), "");
        let multibyte = sanitize_remote_text(&"é".repeat(100), 11);
        assert!(multibyte.len() <= 11, "{multibyte}");
        assert!(multibyte.ends_with("..."));
        let huge = sanitize_remote_text(&"x".repeat(1 << 20), 64);
        assert_eq!(huge.len(), 64);
    }

    #[test]
    fn slave_info_from_hello_is_sanitized() {
        let mut hello = Hello::local(HelloRole::Dialer, "id");
        hello.hostname = Some("host\x1b]0;pwned\x07".into());
        hello.os = Some("\x1b".into());
        hello.features = vec!["update".into(), "\x1b".into(), "x".repeat(100)];
        hello
            .features
            .extend((0..MAX_FEATURES).map(|index| format!("f{index}")));
        hello.last_dial_error = Some(format!("refused\x1b[2J{}", "e".repeat(1000)));
        let info = SlaveInfo::from_hello(&hello);
        assert_eq!(info.hostname.as_deref(), Some("host]0;pwned"));
        assert_eq!(info.os, None);
        assert_eq!(info.features[0], "update");
        assert_eq!(info.features[1].len(), MAX_FEATURE_BYTES);
        assert_eq!(info.features.len(), MAX_FEATURES - 1);
        let error = info.last_dial_error.unwrap();
        assert!(error.starts_with("refused[2J") && error.len() <= MAX_REMOTE_TEXT_BYTES);
        assert_eq!(info.protocol_version, hello.protocol_version);
        assert!(now_ms() > 1_600_000_000_000);
    }
}
