//! Strict parsing of slave public keys and rendering of restricted hub `authorized_keys` lines.
//!
//! `herdr machine authorize` turns a slave's public key line into one hub
//! `authorized_keys` line that confines the key to `herdr link-accept` for a
//! single dial-in machine. Herdr prints the line, or with `--write` adds it
//! (see `authorized_keys_file`).

use std::fmt;
use std::path::Path;

use crate::client::endpoint::ProfileId;

/// Upper bound for a pasted public key line (a 16384-bit RSA key is ~2.8 KiB).
pub(crate) const MAX_PUBLIC_KEY_LINE_BYTES: usize = 16 * 1024;
/// Comment written on every rendered line; the slave's own comment is dropped.
pub(crate) const LINK_KEY_COMMENT_PREFIX: &str = "herdr-link:";
const MAX_DISPLAYED_TOKEN_CHARS: usize = 64;
/// OpenSSH refuses RSA moduli below 1024 bits.
const MIN_RSA_MODULUS_BYTES: usize = 128;

/// Public key algorithms accepted for dial-in links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyType {
    Ed25519,
    SkEd25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    SkEcdsaP256,
    Rsa,
}

impl KeyType {
    pub(crate) const ALL: [Self; 7] = [
        Self::Ed25519,
        Self::SkEd25519,
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::SkEcdsaP256,
        Self::Rsa,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
            Self::EcdsaP521 => "ecdsa-sha2-nistp521",
            Self::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            Self::Rsa => "ssh-rsa",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|key_type| key_type.name() == name)
    }

    /// Curve identifier and uncompressed point length for ECDSA keys.
    fn ecdsa_curve(self) -> Option<(&'static str, usize)> {
        match self {
            Self::EcdsaP256 | Self::SkEcdsaP256 => Some(("nistp256", 65)),
            Self::EcdsaP384 => Some(("nistp384", 97)),
            Self::EcdsaP521 => Some(("nistp521", 133)),
            Self::Ed25519 | Self::SkEd25519 | Self::Rsa => None,
        }
    }

    fn is_security_key(self) -> bool {
        matches!(self, Self::SkEd25519 | Self::SkEcdsaP256)
    }
}

/// A validated public key: its algorithm and canonical base64 key blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicKey {
    key_type: KeyType,
    base64: String,
}

impl PublicKey {
    #[cfg(test)]
    pub(crate) fn key_type(&self) -> KeyType {
        self.key_type
    }

    pub(crate) fn base64(&self) -> &str {
        &self.base64
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeyLineError {
    Empty,
    TooLong,
    ControlCharacter,
    /// The line starts with `authorized_keys` options instead of a key type.
    Options,
    UnsupportedType(String),
    MissingKeyData,
    /// More than `<type> <base64> [comment]`.
    ExtraFields,
    InvalidBase64,
    MalformedKey(&'static str),
    TypeMismatch {
        declared: &'static str,
        embedded: String,
    },
}

impl fmt::Display for KeyLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("public key line is empty"),
            Self::TooLong => write!(
                formatter,
                "public key line is longer than {MAX_PUBLIC_KEY_LINE_BYTES} bytes"
            ),
            Self::ControlCharacter => formatter.write_str(
                "public key line must be a single line without tabs or control characters",
            ),
            Self::Options => formatter.write_str(
                "public key line must not contain authorized_keys options; pass only `<type> <base64> [comment]`",
            ),
            Self::UnsupportedType(name) => write!(
                formatter,
                "unsupported public key type '{name}'; expected one of: {}",
                KeyType::ALL.map(KeyType::name).join(", ")
            ),
            Self::MissingKeyData => {
                formatter.write_str("public key line is missing the base64 key data")
            }
            Self::ExtraFields => formatter.write_str(
                "public key line has extra fields; expected `<type> <base64> [comment]` with a comment without spaces",
            ),
            Self::InvalidBase64 => formatter.write_str("public key data is not valid base64"),
            Self::MalformedKey(reason) => write!(formatter, "public key data is malformed: {reason}"),
            Self::TypeMismatch { declared, embedded } => write!(
                formatter,
                "public key line declares type '{declared}' but the key data contains '{embedded}'"
            ),
        }
    }
}

impl std::error::Error for KeyLineError {}

/// Parses exactly `<type> <base64> [comment]` on one line, separated by
/// spaces. The key data must decode and embed the declared type with a
/// well-formed blob. Options, control characters (including tabs and
/// newlines), and fields beyond a single comment token are rejected. The
/// comment is discarded.
pub(crate) fn parse_public_key_line(line: &str) -> Result<PublicKey, KeyLineError> {
    if line.len() > MAX_PUBLIC_KEY_LINE_BYTES {
        return Err(KeyLineError::TooLong);
    }
    if line.chars().any(char::is_control) {
        return Err(KeyLineError::ControlCharacter);
    }
    let fields = line
        .split(' ')
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let Some(&type_name) = fields.first() else {
        return Err(KeyLineError::Empty);
    };
    let Some(key_type) = KeyType::from_name(type_name) else {
        return Err(if looks_like_options(&fields) {
            KeyLineError::Options
        } else {
            KeyLineError::UnsupportedType(display_token(type_name))
        });
    };
    let Some(&encoded) = fields.get(1) else {
        return Err(KeyLineError::MissingKeyData);
    };
    if fields.len() > 3 {
        return Err(KeyLineError::ExtraFields);
    }
    let blob = decode_base64(encoded).ok_or(KeyLineError::InvalidBase64)?;
    validate_key_blob(key_type, &blob)?;
    Ok(PublicKey {
        key_type,
        base64: encoded.to_owned(),
    })
}

fn looks_like_options(fields: &[&str]) -> bool {
    const OPTION_NAMES: &[&str] = &[
        "agent-forwarding",
        "cert-authority",
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-pty",
        "no-touch-required",
        "no-user-rc",
        "no-x11-forwarding",
        "port-forwarding",
        "pty",
        "restrict",
        "user-rc",
        "verify-required",
        "x11-forwarding",
    ];
    let first = fields.first().copied().unwrap_or_default();
    first.contains(['=', ',', '"'])
        || OPTION_NAMES.contains(&first.to_ascii_lowercase().as_str())
        || fields
            .get(1)
            .is_some_and(|second| KeyType::from_name(second).is_some())
}

fn display_token(token: &str) -> String {
    let mut shown = token
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_DISPLAYED_TOKEN_CHARS)
        .collect::<String>();
    if token.chars().count() > MAX_DISPLAYED_TOKEN_CHARS {
        shown.push_str("...");
    }
    shown
}

/// Checks the SSH wire-format key blob for `key_type`: the embedded type
/// string must match and every algorithm field must be present, with nothing
/// left over.
fn validate_key_blob(key_type: KeyType, blob: &[u8]) -> Result<(), KeyLineError> {
    let mut reader = WireReader { data: blob };
    let embedded = reader
        .string()
        .ok_or(KeyLineError::MalformedKey("missing key type"))?;
    if embedded != key_type.name().as_bytes() {
        return Err(KeyLineError::TypeMismatch {
            declared: key_type.name(),
            embedded: display_token(&String::from_utf8_lossy(embedded)),
        });
    }
    match key_type {
        KeyType::Ed25519 | KeyType::SkEd25519 => {
            let public = reader
                .string()
                .ok_or(KeyLineError::MalformedKey("missing Ed25519 public key"))?;
            if public.len() != 32 {
                return Err(KeyLineError::MalformedKey(
                    "Ed25519 public key must be 32 bytes",
                ));
            }
        }
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 | KeyType::SkEcdsaP256 => {
            let Some((curve, point_len)) = key_type.ecdsa_curve() else {
                return Err(KeyLineError::MalformedKey("unknown ECDSA curve"));
            };
            let embedded_curve = reader
                .string()
                .ok_or(KeyLineError::MalformedKey("missing ECDSA curve"))?;
            if embedded_curve != curve.as_bytes() {
                return Err(KeyLineError::MalformedKey(
                    "ECDSA curve does not match the key type",
                ));
            }
            let point = reader
                .string()
                .ok_or(KeyLineError::MalformedKey("missing ECDSA public point"))?;
            if point.len() != point_len || point.first() != Some(&0x04) {
                return Err(KeyLineError::MalformedKey(
                    "ECDSA public point is not an uncompressed point on the curve",
                ));
            }
        }
        KeyType::Rsa => {
            let exponent = reader
                .string()
                .ok_or(KeyLineError::MalformedKey("missing RSA exponent"))?;
            let modulus = reader
                .string()
                .ok_or(KeyLineError::MalformedKey("missing RSA modulus"))?;
            if exponent.is_empty() || modulus.len() < MIN_RSA_MODULUS_BYTES {
                return Err(KeyLineError::MalformedKey(
                    "RSA key must have an exponent and a modulus of at least 1024 bits",
                ));
            }
        }
    }
    if key_type.is_security_key() {
        reader.string().ok_or(KeyLineError::MalformedKey(
            "missing security key application",
        ))?;
    }
    if !reader.data.is_empty() {
        return Err(KeyLineError::MalformedKey("trailing bytes after the key"));
    }
    Ok(())
}

struct WireReader<'a> {
    data: &'a [u8],
}

impl<'a> WireReader<'a> {
    /// One SSH `string`: a big-endian u32 length followed by that many bytes.
    fn string(&mut self) -> Option<&'a [u8]> {
        let (length, rest) = self.data.split_first_chunk::<4>()?;
        let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
        if length > rest.len() {
            return None;
        }
        let (value, rest) = rest.split_at(length);
        self.data = rest;
        Some(value)
    }
}

/// Strict standard-alphabet base64 with `=` padding: no whitespace, padding
/// only at the end, and zero bits in the unused tail of the last group.
pub(crate) fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        Some(u32::from(value))
    }

    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let groups = bytes.len() / 4;
    let mut output = Vec::with_capacity(groups * 3);
    for (index, group) in bytes.chunks_exact(4).enumerate() {
        let padding = group.iter().rev().take_while(|&&byte| byte == b'=').count();
        if padding > 2 || (padding > 0 && index + 1 != groups) {
            return None;
        }
        let mut accumulator = 0u32;
        for &byte in &group[..4 - padding] {
            accumulator = (accumulator << 6) | value(byte)?;
        }
        accumulator <<= 6 * padding as u32;
        let unused_mask = match padding {
            0 => 0,
            1 => 0xff,
            _ => 0xffff,
        };
        if accumulator & unused_mask != 0 {
            return None;
        }
        let decoded = accumulator.to_be_bytes();
        output.extend_from_slice(&decoded[1..4 - padding]);
    }
    Some(output)
}

/// The command `sshd` runs for a dial-in key, with both paths quoted for the
/// account's shell.
pub(crate) fn forced_command(
    herdr: &Path,
    catalog: &Path,
    id: &ProfileId,
) -> Result<String, String> {
    let herdr = quotable_path(herdr, "Herdr executable")?;
    let catalog = quotable_path(catalog, "dial-in machine catalog")?;
    Ok(format!(
        "{} link-accept --catalog {} --link {id}",
        sh_single_quote(herdr),
        sh_single_quote(catalog)
    ))
}

/// One hub `authorized_keys` line: `restrict`, a forced `link-accept` command
/// for `id`, the key, and the comment `herdr-link:<id>`.
pub(crate) fn render_authorized_keys_line(
    herdr: &Path,
    catalog: &Path,
    id: &ProfileId,
    key: &PublicKey,
) -> Result<String, String> {
    let command = forced_command(herdr, catalog, id)?;
    Ok(format!(
        "restrict,command=\"{}\" {} {} {LINK_KEY_COMMENT_PREFIX}{id}",
        authorized_keys_escape(&command),
        key.key_type.name(),
        key.base64
    ))
}

/// Paths must be absolute UTF-8 without control characters or backslashes:
/// backslashes are read differently by OpenSSH option dequoting and by
/// shells such as fish, so no single quoting is portable for them.
fn quotable_path<'a>(path: &'a Path, description: &str) -> Result<&'a str, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{description} path is not valid UTF-8: {}", path.display()))?;
    if !path.is_absolute() {
        return Err(format!("{description} path must be absolute: {text}"));
    }
    if text.chars().any(char::is_control) || text.contains('\\') {
        return Err(format!(
            "{description} path contains a backslash or control character, which cannot be quoted safely in authorized_keys: {}",
            text.escape_debug()
        ));
    }
    Ok(text)
}

/// POSIX single quoting; an embedded `'` becomes `'\''`.
fn sh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Escapes `"` for an `authorized_keys` `command="..."` value. OpenSSH
/// unescapes only `\"`; any other backslash is kept literally, so other
/// characters (and backslashes, which quoted paths never contain) pass
/// through unchanged.
fn authorized_keys_escape(value: &str) -> String {
    value.replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiyVkMtB424oOJkudA7Gr13nYvfcpJFBxq2EoLwM5LW herdr-dial:laptop";
    const ECDSA_256: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMlLSol8ZpaJ5wcSKOqup4ifsGRIYdH6z9x3dRp6v8BcPuiZpQ2v9DA1P2FzeqBvZDsnCqrudUIr34VosRgJ7jE= a@b";
    const ECDSA_384: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFgNllXTA5JkXP+GyByLwFeyfDwQai7DnzCEmIi6lX2CDOzygO1puBi8mB24w2kaONnvu5uK727ZmgTjju7XoG9CP2cwtKMdRmAqgrB2j/mhYNURSasUpHQ5xVa5B9HC4A== a@b";
    const ECDSA_521: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAA32CYBBLrLNHkSP5g8MATtoAczVGWRKrcoP8FgdVGev7LocqN/eUcsEvy8JoceEPHngqdstT57UUINXqUWbt6iLgFvHChdFxkzkYpGreTgZ0grPbu6WOot6u+EFFkcsRMmgJyqcs2OW4UlCt/1+SYts+RdNLaMAzHCAmiBZtWXn57gcw== a@b";
    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzyqQ2zPChaVXUk/wl+Or9OjwDThyvfY9ZfTQ42qJBKh7eEVgNse8vSKh0RcZBqtf+wFEdKaIWQb4pI2a0pzPZR5+slcsYBtL4bMc/opF/XxkcuwGE3SRbbgtGF5T5YjLvxDCcP9Vw5MjyUF5y2W7At98kyx9Rt4w8+ppvUoaYQxaVJPTua3kPidnFuaVl26EL3A6R9xDYVLVdhWSzigPNmCBYFJkab5NFUkDgyYuebmjkCiVOoKMaLdT83KmnpVc43rYbO+WQFWbTKdj/t+ElEX7WiArgEpuPR95VJIUPuobAbnyLWhTLtOTkyVRVAT6x2mxTPtEW0VBWcMAKJcOt a@b";

    fn encode_base64(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in data.chunks(3) {
            let mut group = [0u8; 3];
            group[..chunk.len()].copy_from_slice(chunk);
            let value = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(char::from(
                        ALPHABET[((value >> (18 - 6 * index)) & 0x3f) as usize],
                    ));
                } else {
                    output.push('=');
                }
            }
        }
        output
    }

    fn wire(fields: &[&[u8]]) -> Vec<u8> {
        let mut blob = Vec::new();
        for field in fields {
            blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
            blob.extend_from_slice(field);
        }
        blob
    }

    fn key_line(key_type: &str, fields: &[&[u8]]) -> String {
        format!("{key_type} {}", encode_base64(&wire(fields)))
    }

    fn point(len: usize) -> Vec<u8> {
        let mut point = vec![7u8; len];
        point[0] = 0x04;
        point
    }

    fn id() -> ProfileId {
        ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn real_openssh_public_keys_parse_and_drop_their_comment() {
        for (line, key_type) in [
            (ED25519, KeyType::Ed25519),
            (ECDSA_256, KeyType::EcdsaP256),
            (ECDSA_384, KeyType::EcdsaP384),
            (ECDSA_521, KeyType::EcdsaP521),
            (RSA, KeyType::Rsa),
        ] {
            let key = parse_public_key_line(line).unwrap_or_else(|error| panic!("{line}: {error}"));
            assert_eq!(key.key_type(), key_type);
            let fields = line.split(' ').collect::<Vec<_>>();
            assert_eq!(key.base64(), fields[1]);
            let without_comment = format!("{} {}", fields[0], fields[1]);
            assert_eq!(parse_public_key_line(&without_comment).unwrap(), key);
            let padded = format!("  {without_comment}  ");
            assert_eq!(parse_public_key_line(&padded).unwrap(), key);
        }
    }

    #[test]
    fn security_key_types_require_their_application_field() {
        let ed25519 = [7u8; 32];
        let line = key_line(
            "sk-ssh-ed25519@openssh.com",
            &[b"sk-ssh-ed25519@openssh.com", &ed25519, b"ssh:"],
        );
        assert_eq!(
            parse_public_key_line(&line).unwrap().key_type(),
            KeyType::SkEd25519
        );
        let line = key_line(
            "sk-ecdsa-sha2-nistp256@openssh.com",
            &[
                b"sk-ecdsa-sha2-nistp256@openssh.com",
                b"nistp256",
                &point(65),
                b"ssh:",
            ],
        );
        assert_eq!(
            parse_public_key_line(&line).unwrap().key_type(),
            KeyType::SkEcdsaP256
        );
        let missing_application = key_line(
            "sk-ssh-ed25519@openssh.com",
            &[b"sk-ssh-ed25519@openssh.com", &ed25519],
        );
        assert!(matches!(
            parse_public_key_line(&missing_application),
            Err(KeyLineError::MalformedKey(_))
        ));
    }

    #[test]
    fn key_line_parser_rejects_everything_but_type_base64_and_comment() {
        let ed25519_data = ED25519.split(' ').nth(1).unwrap();
        let rsa_data = RSA.split(' ').nth(1).unwrap();
        type Check = fn(&KeyLineError) -> bool;
        fn case(line: impl Into<String>, check: Check) -> (String, Check) {
            (line.into(), check)
        }
        let cases = [
            case(String::new(), |e| *e == KeyLineError::Empty),
            case("   ", |e| *e == KeyLineError::Empty),
            case(format!("restrict {ED25519}"), |e| {
                *e == KeyLineError::Options
            }),
            case(format!("command=\"/bin/sh\" {ED25519}"), |e| {
                *e == KeyLineError::Options
            }),
            case(format!("no-pty,no-port-forwarding {ED25519}"), |e| {
                *e == KeyLineError::Options
            }),
            case(format!("{ED25519}\n"), |e| {
                *e == KeyLineError::ControlCharacter
            }),
            case(format!("{ED25519}\nssh-ed25519 {ed25519_data}"), |e| {
                *e == KeyLineError::ControlCharacter
            }),
            case(format!("{ED25519}\r"), |e| {
                *e == KeyLineError::ControlCharacter
            }),
            case(format!("ssh-ed25519\t{ed25519_data}"), |e| {
                *e == KeyLineError::ControlCharacter
            }),
            case(format!("ssh-ed25519 {ed25519_data} evil\u{1b}[2J"), |e| {
                *e == KeyLineError::ControlCharacter
            }),
            case(format!("ssh-ed25519 {ed25519_data} a\u{0}b"), |e| {
                *e == KeyLineError::ControlCharacter
            }),
            case("ssh-ed25519", |e| *e == KeyLineError::MissingKeyData),
            case(format!("{ED25519} extra"), |e| {
                *e == KeyLineError::ExtraFields
            }),
            case(
                format!("ssh-ed25519 {ed25519_data} user@host and more"),
                |e| *e == KeyLineError::ExtraFields,
            ),
            case("ssh-ed25519 AAAA!!!=", |e| {
                *e == KeyLineError::InvalidBase64
            }),
            case(
                format!("ssh-ed25519 {}", &ed25519_data[..ed25519_data.len() - 1]),
                |e| *e == KeyLineError::InvalidBase64,
            ),
            case(format!("ssh-ed25519 {ed25519_data}===="), |e| {
                *e == KeyLineError::InvalidBase64
            }),
            case(
                format!("ssh-ed25519 {rsa_data}"),
                |e| matches!(e, KeyLineError::TypeMismatch { declared: "ssh-ed25519", embedded } if embedded == "ssh-rsa"),
            ),
            case(format!("ssh-rsa {ed25519_data}"), |e| {
                matches!(
                    e,
                    KeyLineError::TypeMismatch {
                        declared: "ssh-rsa",
                        ..
                    }
                )
            }),
            case(
                format!("ssh-dss {ed25519_data}"),
                |e| matches!(e, KeyLineError::UnsupportedType(name) if name == "ssh-dss"),
            ),
            case(
                format!("ssh-ed25519-cert-v01@openssh.com {ed25519_data}"),
                |e| matches!(e, KeyLineError::UnsupportedType(_)),
            ),
            case(format!("SSH-ED25519 {ed25519_data}"), |e| {
                matches!(e, KeyLineError::UnsupportedType(_))
            }),
            case("x".repeat(MAX_PUBLIC_KEY_LINE_BYTES + 1), |e| {
                *e == KeyLineError::TooLong
            }),
            case(
                key_line("ssh-ed25519", &[b"ssh-ed25519", &[1u8; 31]]),
                |e| matches!(e, KeyLineError::MalformedKey(_)),
            ),
            case(
                key_line("ssh-ed25519", &[b"ssh-ed25519", &[1u8; 32], b"trailing"]),
                |e| matches!(e, KeyLineError::MalformedKey(_)),
            ),
            case(key_line("ssh-ed25519", &[b"ssh-ed25519"]), |e| {
                matches!(e, KeyLineError::MalformedKey(_))
            }),
            case(
                key_line(
                    "ecdsa-sha2-nistp256",
                    &[b"ecdsa-sha2-nistp256", b"nistp384", &point(65)],
                ),
                |e| matches!(e, KeyLineError::MalformedKey(_)),
            ),
            case(
                key_line(
                    "ecdsa-sha2-nistp384",
                    &[b"ecdsa-sha2-nistp384", b"nistp384", &point(65)],
                ),
                |e| matches!(e, KeyLineError::MalformedKey(_)),
            ),
            case(
                key_line("ssh-rsa", &[b"ssh-rsa", b"\x01\x00\x01", &[0xff; 64]]),
                |e| matches!(e, KeyLineError::MalformedKey(_)),
            ),
        ];
        for (line, expected) in cases {
            let error = parse_public_key_line(&line).expect_err(&line);
            assert!(expected(&error), "{line:?}: unexpected {error:?}");
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn base64_decoder_is_strict_and_matches_the_reference_encoding() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            if data.is_empty() {
                continue;
            }
            assert_eq!(decode_base64(&encode_base64(data)).unwrap(), data);
        }
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
        for invalid in [
            "", "Zg", "Zg=", "Zm9=v", "Zh==", "Zm9w=", "Zg==Zg==", "Zm 9v", "Zm9v\n", "Z===",
            "Zm9v_-==",
        ] {
            assert!(decode_base64(invalid).is_none(), "{invalid:?}");
        }
    }

    /// OpenSSH `opt_dequote`: only `\"` is unescaped.
    fn openssh_dequote(value: &str) -> String {
        let mut output = String::new();
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' && chars.peek() == Some(&'"') {
                continue;
            }
            output.push(ch);
        }
        output
    }

    /// Minimal POSIX word splitting for unquoted words and `'...'` quoting.
    fn sh_words(command: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut in_word = false;
        let mut quoted = false;
        let mut chars = command.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\'' if !quoted => {
                    quoted = true;
                    in_word = true;
                }
                '\'' => quoted = false,
                '\\' if !quoted => {
                    word.extend(chars.next());
                    in_word = true;
                }
                ' ' if !quoted => {
                    if in_word {
                        words.push(std::mem::take(&mut word));
                        in_word = false;
                    }
                }
                ch => {
                    word.push(ch);
                    in_word = true;
                }
            }
        }
        assert!(!quoted, "unterminated quote in {command}");
        if in_word {
            words.push(word);
        }
        words
    }

    /// The `command="..."` value as OpenSSH delimits it: `\"` never ends it.
    fn command_value(line: &str) -> &str {
        let rest = line.strip_prefix("restrict,command=\"").unwrap();
        let bytes = rest.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
                return &rest[..index];
            }
            index += 1;
        }
        panic!("unterminated command in {line}");
    }

    #[test]
    fn rendered_line_restricts_the_key_to_link_accept_for_one_machine() {
        let key = parse_public_key_line(ED25519).unwrap();
        let line = render_authorized_keys_line(
            Path::new("/home/u/.local/bin/herdr"),
            Path::new("/home/u/.local/state/herdr/client/dial-in-machines.json"),
            &id(),
            &key,
        )
        .unwrap();
        assert_eq!(
            line,
            "restrict,command=\"'/home/u/.local/bin/herdr' link-accept --catalog '/home/u/.local/state/herdr/client/dial-in-machines.json' --link 0123456789abcdef0123456789abcdef\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiyVkMtB424oOJkudA7Gr13nYvfcpJFBxq2EoLwM5LW herdr-link:0123456789abcdef0123456789abcdef"
        );
        assert!(!line.contains("herdr-dial:laptop"));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn rendered_command_survives_openssh_dequoting_and_shell_splitting() {
        let key = parse_public_key_line(RSA).unwrap();
        for (herdr, catalog) in [
            (
                "/opt/my tools/herdr",
                "/home/u/state dir/client/dial-in-machines.json",
            ),
            (
                "/home/o'brien/bin/herdr",
                "/home/o'brien/.local/state/herdr/client/c.json",
            ),
            ("/tmp/say \"hi\"/herdr", "/tmp/a\"b'c d/c.json"),
            ("/tmp/$HOME/`id`/herdr", "/tmp/*;&|<>!/c.json"),
        ] {
            let line =
                render_authorized_keys_line(Path::new(herdr), Path::new(catalog), &id(), &key)
                    .unwrap();
            let command = openssh_dequote(command_value(&line));
            assert_eq!(
                sh_words(&command),
                [
                    herdr,
                    "link-accept",
                    "--catalog",
                    catalog,
                    "--link",
                    "0123456789abcdef0123456789abcdef"
                ],
                "{line}"
            );
            let suffix = format!(
                "\" ssh-rsa {} herdr-link:0123456789abcdef0123456789abcdef",
                key.base64()
            );
            assert!(line.ends_with(&suffix), "{line}");
        }
    }

    #[test]
    fn unquotable_paths_are_rejected() {
        let catalog = Path::new("/state/c.json");
        for herdr in [
            "relative/herdr",
            "/tmp/new\nline/herdr",
            "/tmp/back\\slash/herdr",
            "/tmp/tab\there",
        ] {
            assert!(
                forced_command(Path::new(herdr), catalog, &id()).is_err(),
                "{herdr:?}"
            );
            assert!(
                forced_command(catalog, Path::new(herdr), &id()).is_err(),
                "{herdr:?}"
            );
        }
    }
}
