//! Dial-in machine links.
//!
//! A slave without inbound SSH keeps one OpenSSH ControlMaster connection to
//! the hub. Over it, a control session runs `herdr link-accept` on the hub,
//! which binds per-machine local sockets. Every hub-side connection to those
//! sockets becomes a fresh SSH session over the master, bridged on the slave to
//! its own Herdr client or API socket.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::client::endpoint::ProfileId;

pub(crate) mod accept;
pub(crate) mod agent_filter;
pub(crate) mod authorized_keys;
pub(crate) mod authorized_keys_file;
pub(crate) mod connect;
pub(crate) mod dial;
pub(crate) mod dial_config;
pub(crate) mod herdr_path;
pub(crate) mod protocol;
pub(crate) mod status;

pub(crate) use herdr_path::stable_herdr_path;

pub(crate) const LINK_VERSION_MIN: u32 = 1;
pub(crate) const LINK_VERSION_MAX: u32 = 1;
/// Printed by the acceptor as `"\n" + LINK_READY_MARKER + "\n"` before it reads anything.
pub(crate) const LINK_READY_MARKER: &str = "herdr-link-ready:1";
pub(crate) const MAX_PREAMBLE_BYTES: usize = 64 * 1024;
pub(crate) const PREAMBLE_DEADLINE: Duration = Duration::from_secs(10);
pub(crate) const MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
pub(crate) const HELLO_DEADLINE: Duration = Duration::from_secs(10);
/// Send a ping when nothing was sent for this long.
pub(crate) const PING_IDLE: Duration = Duration::from_secs(5);
/// Consider the link dead when nothing was received for this long.
pub(crate) const LINK_DEAD_AFTER: Duration = Duration::from_secs(20);
/// Close a pending hub connection that was not attached within this long.
pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const SUPERSEDE_PROBE: Duration = Duration::from_secs(3);
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(5);
pub(crate) const MAX_PENDING_OPENS: usize = 64;
pub(crate) const MAX_ACTIVE_STREAMS: usize = 256;

/// Directory (next to the dial-in catalog) holding one subdirectory per link.
pub(crate) const LINKS_DIR_NAME: &str = "links";
/// Number of leading profile-id hex characters naming a link directory.
pub(crate) const LINK_DIR_ID_CHARS: usize = 12;
pub(crate) const CLIENT_SOCKET_NAME: &str = "client.sock";
pub(crate) const API_SOCKET_NAME: &str = "api.sock";
pub(crate) const LINK_SOCKET_NAME: &str = "link.sock";
pub(crate) const STATUS_FILE_NAME: &str = "status.json";
pub(crate) const LOCK_FILE_NAME: &str = "link.lock";

/// Hub-side filesystem layout of one dial-in link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinkPaths {
    /// Private (0700) per-link directory: `<catalog dir>/links/<id12>/`.
    pub(crate) dir: PathBuf,
    /// Hub TUI connections; each becomes a slave `remote-client-bridge` stream.
    pub(crate) client_socket: PathBuf,
    /// Hub API connections; each becomes a slave `remote-api-bridge` stream.
    pub(crate) api_socket: PathBuf,
    /// Hub-local operations (attach, status, supersede) on the link holder.
    pub(crate) link_socket: PathBuf,
    pub(crate) status_file: PathBuf,
    pub(crate) lock_file: PathBuf,
}

impl LinkPaths {
    /// Layout for `id` next to the dial-in catalog at `catalog_path`.
    pub(crate) fn for_catalog(catalog_path: &Path, id: &ProfileId) -> Self {
        let base = catalog_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Self::in_dir(base.join(LINKS_DIR_NAME).join(link_dir_name(id)))
    }

    /// Layout for `id` next to the default dial-in catalog.
    pub(crate) fn for_default_catalog(id: &ProfileId) -> Self {
        Self::for_catalog(&crate::client::endpoint::dial_in_catalog_path(), id)
    }

    fn in_dir(dir: PathBuf) -> Self {
        Self {
            client_socket: dir.join(CLIENT_SOCKET_NAME),
            api_socket: dir.join(API_SOCKET_NAME),
            link_socket: dir.join(LINK_SOCKET_NAME),
            status_file: dir.join(STATUS_FILE_NAME),
            lock_file: dir.join(LOCK_FILE_NAME),
            dir,
        }
    }

    /// Fails with `InvalidInput` naming the first socket path that exceeds the
    /// platform's local socket path limit.
    pub(crate) fn ensure_socket_paths_fit(&self) -> std::io::Result<()> {
        for path in [&self.client_socket, &self.api_socket, &self.link_socket] {
            if !crate::platform::local_socket_path_fits(path) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "dial-in link socket path is too long for a Unix socket: {} \
                         (set XDG_STATE_HOME to a shorter directory)",
                        path.display()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Link directory name for a profile id: its first `LINK_DIR_ID_CHARS` hex characters.
pub(crate) fn link_dir_name(id: &ProfileId) -> &str {
    let id = id.as_str();
    id.get(..LINK_DIR_ID_CHARS).unwrap_or(id)
}

/// Entry point for `herdr link-accept ...` (the hub side of a dial-in link).
pub(crate) fn run_link_accept(args: &[String]) -> std::io::Result<()> {
    // The acceptor writes to sockets and pipes whose peers may vanish at any
    // time; it must see EPIPE instead of dying from SIGPIPE.
    crate::platform::end_cli_output();
    accept::run(args)
}

/// Entry point for `herdr link-connect ...` (a relay client reaching one of
/// this hub's dial-in machines over the client's own SSH login).
pub(crate) fn run_link_connect(args: &[String]) -> std::io::Result<()> {
    crate::platform::end_cli_output();
    connect::run(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_paths_live_next_to_the_catalog_under_a_short_id_prefix() {
        let id = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let paths = LinkPaths::for_catalog(Path::new("/state/client/dial-in-machines.json"), &id);
        assert_eq!(paths.dir, Path::new("/state/client/links/0123456789ab"));
        assert_eq!(paths.client_socket, paths.dir.join("client.sock"));
        assert_eq!(paths.api_socket, paths.dir.join("api.sock"));
        assert_eq!(paths.link_socket, paths.dir.join("link.sock"));
        assert_eq!(paths.status_file, paths.dir.join("status.json"));
        assert_eq!(paths.lock_file, paths.dir.join("link.lock"));
        assert_eq!(link_dir_name(&id), "0123456789ab");
        paths.ensure_socket_paths_fit().unwrap();
    }

    #[test]
    fn link_paths_reject_overlong_socket_paths_when_the_platform_limits_them() {
        let id = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let deep = PathBuf::from("/")
            .join("d".repeat(200))
            .join("catalog.json");
        let paths = LinkPaths::for_catalog(&deep, &id);
        if crate::platform::local_socket_path_fits(&paths.client_socket) {
            return;
        }
        let error = paths.ensure_socket_paths_fit().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("client.sock"));
    }
}
