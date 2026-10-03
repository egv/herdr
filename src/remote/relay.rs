//! Reaching a relay hub's dial-in machines over SSH: the hub's Herdr
//! executable (discovered once with the saved-machine discovery and cached
//! per relay), the hub's machine list, and streams to one of its machines
//! through `herdr link-connect` on the hub.

use std::io;
use std::path::PathBuf;
use std::process::Output;

use super::attach::{
    discover_remote_api_metadata, posix_remote_output_command, RemoteSsh, SshStdioBridge,
    STALE_API_METADATA,
};
use crate::client::endpoint::{RelayListing, SshMetadataCache};

/// `herdr link-connect` reports a machine without a live link with this phrase.
pub(crate) const VIA_NOT_CONNECTED: &str = "is not connected";
/// Prefix of failures to reach or use the relay hub itself.
pub(crate) const RELAY_UNREACHABLE: &str = "could not reach the relay hub";
const LINK_CONNECT_PREFIX: &str = "herdr link-connect:";

/// Whether `message` is `herdr link-connect` reporting a machine that has
/// not dialed in to the relay hub.
pub(crate) fn via_not_connected(message: &str) -> bool {
    message.contains(LINK_CONNECT_PREFIX) && message.contains(VIA_NOT_CONNECTED)
}

/// `could not reach the relay hub: <detail>. Check `ssh <target>`.`
pub(crate) fn relay_unreachable_message(detail: &str, target: &str) -> String {
    let detail = detail
        .strip_prefix(RELAY_UNREACHABLE)
        .map_or(detail, |rest| rest.trim_start_matches(':').trim_start())
        .trim_end_matches(|ch: char| ch == '.' || ch.is_whitespace());
    format!("{RELAY_UNREACHABLE}: {detail}. Check `ssh {target}`.")
}

pub(super) struct RelayHerdr {
    pub(super) ssh: RemoteSsh,
    pub(super) cache: SshMetadataCache,
    pub(super) executable: String,
    /// The executable came from the cache, which may be stale.
    pub(super) cached: bool,
}

/// The relay hub's Herdr executable: cached per relay, or discovered over
/// the managed noninteractive SSH like a saved machine's and then cached.
pub(super) fn relay_herdr(relay_id: &str, target: &str, use_cache: bool) -> io::Result<RelayHerdr> {
    crate::client::endpoint::validate_relay_target(target)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let session = crate::session::DEFAULT_SESSION_NAME;
    let ssh = RemoteSsh::new_noninteractive(target.to_owned());
    let cache = SshMetadataCache::new(relay_id, target, session)?;
    let cached = if use_cache { cache.load() } else { None };
    let from_cache = cached.is_some();
    let metadata = match cached {
        Some(metadata) => metadata,
        None => {
            let metadata = discover_remote_api_metadata(&ssh, session)?;
            cache.store(&metadata);
            metadata
        }
    };
    if metadata.os == "windows" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "relay hubs must run Linux or macOS",
        ));
    }
    Ok(RelayHerdr {
        ssh,
        cache,
        executable: metadata.executable,
        cached: from_cache,
    })
}

pub(crate) fn relay_herdr_executable(relay_id: &str, target: &str) -> io::Result<String> {
    relay_herdr(relay_id, target, true).map(|herdr| herdr.executable)
}

/// Forgets the relay hub's cached executable (after it moved, or when the
/// relay is removed).
pub(crate) fn invalidate_relay_herdr(relay_id: &str, target: &str) {
    if let Ok(cache) = SshMetadataCache::new(relay_id, target, crate::session::DEFAULT_SESSION_NAME)
    {
        cache.invalidate();
    }
}

/// A `/bin/sh -c` command that runs `<executable> <args>` on the hub after
/// the output marker, or fails with the stale-metadata marker when the
/// cached executable is gone.
pub(super) fn relay_command(executable: &str, args: &[&str]) -> String {
    let path = super::shell_quote(executable);
    let mut command = format!("exec {path}");
    for arg in args {
        command.push(' ');
        command.push_str(&super::shell_quote(arg));
    }
    let script = format!(
        "if [ -x {path} ]; then\n{}\nelse\n    printf '%s\\n' '{STALE_API_METADATA}' >&2\n    exit 78\nfi",
        posix_remote_output_command(&command)
    );
    format!("/bin/sh -c {}", super::shell_quote(&script))
}

pub(super) fn link_connect_command(executable: &str, link_id: &str, kind: &str) -> String {
    relay_command(
        executable,
        &["link-connect", "--link", link_id, "--kind", kind],
    )
}

/// Bridge socket for one via machine; `api` bridges get their own name.
pub(super) fn via_bridge_path(api: bool, via_id: &str) -> PathBuf {
    let pid = std::process::id();
    let (kind, tag) = if api { ("api", 'a') } else { ("client", 'c') };
    let short_id = via_id.get(..16).unwrap_or(via_id);
    crate::platform::remote_bridge_endpoint_path(
        &format!("herdr-via-{kind}-{pid}-{via_id}.sock"),
        &format!("herdr-v{tag}-{pid}-{short_id}.sock"),
    )
}

/// The relay hub's dial-in machines (`herdr link-connect --list` on it).
pub(crate) fn list_relay(relay_id: &str, target: &str) -> io::Result<RelayListing> {
    let mut use_cache = true;
    loop {
        let herdr = relay_herdr(relay_id, target, use_cache)?;
        let output = herdr.ssh.framed_user_shell_output(&relay_command(
            &herdr.executable,
            &["link-connect", "--list"],
        ))?;
        if output.status.success() {
            return RelayListing::parse(&output.stdout)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
        if herdr.cached && String::from_utf8_lossy(&output.stderr).contains(STALE_API_METADATA) {
            herdr.cache.invalidate();
            use_cache = false;
            continue;
        }
        return Err(list_failed(&output));
    }
}

fn list_failed(output: &Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let detail = if stderr.is_empty() {
        output.status.to_string()
    } else {
        stderr.to_owned()
    };
    // OpenSSH itself exits 255; anything else is Herdr on the hub.
    if output.status.code() == Some(255) {
        io::Error::other(detail)
    } else {
        io::Error::other(format!(
            "`herdr link-connect --list` failed on the relay hub (update Herdr there if it is older): {detail}"
        ))
    }
}

/// A client stream to a relay hub's dial-in machine, with the SSH bridge
/// that carries it.
pub(crate) struct ViaStream {
    pub(crate) stream: crate::ipc::LocalStream,
    pub(crate) bridge: ViaBridge,
}

pub(crate) struct ViaBridge(SshStdioBridge);

impl ViaBridge {
    /// Why the SSH session ended, waiting briefly for the report.
    pub(crate) fn reported_failure(&self) -> Option<io::Error> {
        self.0.reported_failure()
    }
}

/// Connects to link `link_id` of relay hub `relay_target` through
/// `herdr link-connect --kind client` over the managed SSH.
pub(crate) fn connect_via(
    relay_id: &str,
    relay_target: &str,
    link_id: &str,
    via_id: &str,
) -> io::Result<ViaStream> {
    let herdr = relay_herdr(relay_id, relay_target, true)
        .map_err(|error| io::Error::new(error.kind(), format!("{RELAY_UNREACHABLE}: {error}")))?;
    let path = via_bridge_path(false, via_id);
    let bridge = SshStdioBridge::start_command(
        relay_target.to_owned(),
        link_connect_command(&herdr.executable, link_id, "client"),
        path.clone(),
        herdr.ssh.options(),
        true,
    )?;
    let stream = crate::ipc::connect_local_stream(&path)?;
    Ok(ViaStream {
        stream,
        bridge: ViaBridge(bridge),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_commands_check_the_cached_executable_before_the_marker() {
        let command = link_connect_command(
            "/home/me/.local/bin/herdr",
            "0123456789abcdef0123456789abcdef",
            "api",
        );
        assert!(command.starts_with("/bin/sh -c '"), "{command}");
        for needle in [
            "if [ -x /home/me/.local/bin/herdr ]",
            "herdr-remote-output-ready:1",
            "exec /home/me/.local/bin/herdr link-connect --link 0123456789abcdef0123456789abcdef --kind api",
            STALE_API_METADATA,
            "exit 78",
        ] {
            assert!(command.contains(needle), "{needle}: {command}");
        }
        // Paths are quoted for the hub shell, inside the quoted script.
        let spaced = relay_command("/opt/my herdr", &["link-connect", "--list"]);
        assert!(
            spaced.contains(r"exec '\''/opt/my herdr'\'' link-connect --list"),
            "{spaced}"
        );
    }

    #[test]
    fn offline_reports_come_only_from_link_connect() {
        assert!(via_not_connected(
            "remote SSH connection failed: herdr link-connect: slave1 is not connected (it has not dialed in)"
        ));
        assert!(!via_not_connected("Transport endpoint is not connected"));
        assert!(!via_not_connected(
            "herdr link-connect: slave1 is disabled on this hub"
        ));
    }

    #[test]
    fn via_bridge_paths_are_per_machine_and_kind() {
        let id = "453bd5bdb09752d6fd93e65be5b5b754";
        assert_ne!(via_bridge_path(false, id), via_bridge_path(true, id));
        assert_ne!(
            via_bridge_path(false, id),
            via_bridge_path(false, "fedcba9876543210fedcba9876543210")
        );
    }
}
