//! `herdr link-connect`: runs on a hub under its user's own SSH login and
//! connects that SSH session to one of the hub's dial-in machines, so a
//! client that reaches the hub over SSH (a relay) reaches the machine too.
//! The bytes are the machine's client or API socket protocol, exactly as a
//! hub-local client sees them on the link's sockets.
//!
//! `--list` prints the hub's dial-in machines for such clients, from the
//! catalog and each link's `status.json`, without probing anything.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::status;
use super::LinkPaths;
use crate::client::endpoint::{
    dial_in_catalog_path, DialInCatalog, ProfileId, RelayListedMachine, RelayListing,
    RELAY_LISTING_VERSION,
};
use crate::ipc::LocalStream;

/// Exit status when the machine has no live link on this hub.
pub(crate) const NOT_CONNECTED_EXIT: i32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Client,
    Api,
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    List {
        catalog: PathBuf,
    },
    Connect {
        catalog: PathBuf,
        link: ProfileId,
        kind: Kind,
    },
}

/// Why a connection was not made.
#[derive(Debug, PartialEq, Eq)]
enum ConnectError {
    /// The machine exists and is enabled, but has no live link.
    NotConnected(String),
    Refused(String),
}

impl ConnectError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::NotConnected(_) => NOT_CONNECTED_EXIT,
            Self::Refused(_) => 1,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::NotConnected(label) => format!("{label} is not connected (it has not dialed in)"),
            Self::Refused(message) => message.clone(),
        }
    }
}

/// Runs `herdr link-connect --link <id> --kind client|api [--catalog <abs path>]`
/// or `herdr link-connect --list [--catalog <abs path>]`.
pub(crate) fn run(args: &[String]) -> io::Result<()> {
    let request = parse_args(args).unwrap_or_else(|message| {
        eprintln!("herdr link-connect: {message}");
        std::process::exit(2);
    });
    match request {
        Request::List { catalog } => {
            let listing = list(&catalog).unwrap_or_else(|message| {
                eprintln!("herdr link-connect: {message}");
                std::process::exit(1);
            });
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, &listing).map_err(io::Error::other)?;
            stdout.write_all(b"\n")?;
            stdout.flush()
        }
        Request::Connect {
            catalog,
            link,
            kind,
        } => {
            let (stream, lease) = connect(&catalog, &link, kind).unwrap_or_else(|error| {
                eprintln!("herdr link-connect: {}", error.message());
                std::process::exit(error.exit_code());
            });
            let output = crate::platform::take_stdout_unbuffered()?;
            let result = super::accept::pump_stdio(stream, io::stdin(), output);
            drop(lease);
            result
        }
    }
}

fn parse_args(args: &[String]) -> Result<Request, String> {
    let mut catalog = None;
    let mut link = None;
    let mut kind = None;
    let mut list = false;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        if flag == "--list" {
            if std::mem::replace(&mut list, true) {
                return Err("--list was given more than once".into());
            }
            continue;
        }
        let slot = match flag.as_str() {
            "--catalog" => &mut catalog,
            "--link" => &mut link,
            "--kind" => &mut kind,
            other => {
                return Err(format!(
                    "unexpected argument '{}'",
                    status::sanitize_remote_text(other, 80)
                ))
            }
        };
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if slot.replace(value.as_str()).is_some() {
            return Err(format!("{flag} was given more than once"));
        }
    }
    let catalog = match catalog {
        Some(path) if Path::new(path).is_absolute() => PathBuf::from(path),
        Some(_) => return Err("--catalog must be an absolute path".into()),
        None => dial_in_catalog_path(),
    };
    if list {
        if link.is_some() || kind.is_some() {
            return Err("--list takes no --link or --kind".into());
        }
        return Ok(Request::List { catalog });
    }
    let link = ProfileId::parse(link.ok_or("missing --link <machine id>")?)
        .map_err(|_| "--link must be a 32-character lowercase hex machine id".to_string())?;
    let kind = match kind.ok_or("missing --kind client|api")? {
        "client" => Kind::Client,
        "api" => Kind::Api,
        _ => return Err("--kind must be client or api".into()),
    };
    Ok(Request::Connect {
        catalog,
        link,
        kind,
    })
}

fn load_catalog(catalog: &Path) -> Result<DialInCatalog, String> {
    DialInCatalog::load_from_trusted_path(catalog)
}

/// Every dial-in machine of this hub; `connected` means its link holder is live.
fn list(catalog: &Path) -> Result<RelayListing, String> {
    let machines = load_catalog(catalog)?
        .machines
        .iter()
        .map(|machine| {
            let paths = LinkPaths::for_catalog(catalog, &machine.id);
            let link = crate::platform::verify_private_directory(&paths.dir)
                .ok()
                .and_then(|()| status::read_status(&paths.status_file).ok().flatten());
            RelayListedMachine {
                id: machine.id.to_string(),
                label: machine.label.clone(),
                session: machine.session.clone(),
                enabled: machine.enabled,
                connected: link.as_ref().is_some_and(status::LinkStatus::is_live),
                link_epoch: link.map_or(0, |link| link.link_epoch),
            }
        })
        .collect();
    Ok(RelayListing {
        version: RELAY_LISTING_VERSION,
        machines,
    })
}

/// Connects to the link socket of `kind`, plus an agent lease when the
/// machine forwards this user's agent. The lease lives as long as the value.
fn connect(
    catalog: &Path,
    link: &ProfileId,
    kind: Kind,
) -> Result<(LocalStream, Option<LocalStream>), ConnectError> {
    let catalog_data = load_catalog(catalog).map_err(ConnectError::Refused)?;
    let machine = catalog_data
        .get(link)
        .ok_or_else(|| ConnectError::Refused(format!("this hub has no dial-in machine {link}")))?;
    if !machine.enabled {
        return Err(ConnectError::Refused(format!(
            "{} is disabled on this hub",
            machine.label
        )));
    }
    let paths = LinkPaths::for_catalog(catalog, link);
    paths
        .ensure_socket_paths_fit()
        .map_err(|error| ConnectError::Refused(error.to_string()))?;
    let socket = match kind {
        Kind::Client => &paths.client_socket,
        Kind::Api => &paths.api_socket,
    };
    let stream = connect_link_socket(&paths, socket).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            ConnectError::NotConnected(machine.label.clone())
        }
        _ => ConnectError::Refused(format!("refusing the link of {}: {error}", machine.label)),
    })?;
    // This login's agent (forwarded by the relay's ssh with `ForwardAgent
    // yes`), lent like a hub-local client lends its own.
    let lease = (kind == Kind::Client && machine.agent_forwarding)
        .then(|| super::accept::lease_agent(&paths))
        .flatten();
    Ok((stream, lease))
}

/// Connects a socket in the private link directory that this user serves.
fn connect_link_socket(paths: &LinkPaths, socket: &Path) -> io::Result<LocalStream> {
    crate::platform::verify_private_directory(&paths.dir)?;
    let stream = crate::ipc::connect_local_stream(socket)?;
    if !crate::platform::local_stream_peer_is_current_user(&stream)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the link socket is served by another user",
        ));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn arguments_select_list_or_one_link_socket() {
        assert_eq!(
            parse_args(&args(&["--list"])).unwrap(),
            Request::List {
                catalog: dial_in_catalog_path()
            }
        );
        assert_eq!(
            parse_args(&args(&["--catalog", "/c/m.json", "--list"])).unwrap(),
            Request::List {
                catalog: PathBuf::from("/c/m.json")
            }
        );
        assert_eq!(
            parse_args(&args(&[
                "--kind",
                "api",
                "--link",
                ID,
                "--catalog",
                "/c/m.json"
            ]))
            .unwrap(),
            Request::Connect {
                catalog: PathBuf::from("/c/m.json"),
                link: ProfileId::parse(ID).unwrap(),
                kind: Kind::Api,
            }
        );
        assert!(matches!(
            parse_args(&args(&["--link", ID, "--kind", "client"])).unwrap(),
            Request::Connect {
                kind: Kind::Client,
                ..
            }
        ));
        for invalid in [
            &[][..],
            &["--link", ID],
            &["--kind", "client"],
            &["--link", "XYZ", "--kind", "client"],
            &["--link", ID, "--kind", "agent"],
            &["--link", ID, "--kind", "client", "--kind", "api"],
            &[
                "--link",
                ID,
                "--kind",
                "client",
                "--catalog",
                "relative.json",
            ],
            &["--link", ID, "--kind", "client", "--extra"],
            &["--list", "--link", ID],
            &["--list", "--list"],
            &["--link"],
        ] {
            assert!(parse_args(&args(invalid)).is_err(), "{invalid:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn offline_machines_exit_not_connected_and_refusals_exit_one() {
        use crate::remote::link::status::{write_status, LinkState, LinkStatus};
        use std::os::unix::fs::PermissionsExt as _;

        // Short root: link socket paths must fit `sun_path` on macOS too.
        let root = PathBuf::from(format!("/tmp/hlc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let catalog_path = root.join("dial-in-machines.json");
        let mut catalog = DialInCatalog::default();
        let online = catalog.add("slave1", "default", &[]).unwrap();
        let disabled = catalog.add("old", "default", &[]).unwrap();
        catalog.set_enabled(&disabled, false);
        catalog.store_to_path(&catalog_path).unwrap();
        let paths = LinkPaths::for_catalog(&catalog_path, &online);

        let attempt = |id: &ProfileId| connect(&catalog_path, id, Kind::Client).map(|_| ());
        let offline = Err(ConnectError::NotConnected("slave1".into()));
        // Never dialed in, then a link directory without a holder, then a
        // stale socket left by a crashed holder.
        assert_eq!(attempt(&online), offline);
        crate::platform::ensure_private_directory(&paths.dir).unwrap();
        assert_eq!(attempt(&online), offline);
        drop(crate::ipc::bind_private_local_listener(&paths.client_socket).unwrap());
        assert_eq!(attempt(&online), offline);
        let error = attempt(&online).unwrap_err();
        assert_eq!(error.exit_code(), NOT_CONNECTED_EXIT);
        assert_eq!(
            error.message(),
            "slave1 is not connected (it has not dialed in)"
        );

        let refused = attempt(&disabled).unwrap_err();
        assert_eq!(refused.exit_code(), 1);
        assert!(refused.message().contains("disabled"), "{refused:?}");
        let unknown = ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap();
        assert!(matches!(attempt(&unknown), Err(ConnectError::Refused(_))));
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(attempt(&online), Err(ConnectError::Refused(_))));
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // A live holder: the connection is made.
        std::fs::remove_file(&paths.client_socket).unwrap();
        let _listener = crate::ipc::bind_private_local_listener(&paths.client_socket).unwrap();
        assert!(attempt(&online).is_ok());

        // The listing reads status.json only.
        let listing = list(&catalog_path).unwrap();
        assert_eq!(listing.version, RELAY_LISTING_VERSION);
        assert_eq!(listing.machines.len(), 2);
        assert!(!listing.machines[0].connected);
        write_status(
            &paths.status_file,
            &LinkStatus {
                state: LinkState::Connected,
                link_epoch: 7,
                pid: Some(std::process::id()),
                ..LinkStatus::default()
            },
        )
        .unwrap();
        let listing = list(&catalog_path).unwrap();
        let first = &listing.machines[0];
        assert_eq!(
            (first.id.as_str(), first.label.as_str(), first.enabled),
            (online.as_str(), "slave1", true)
        );
        assert!(first.connected);
        assert_eq!(first.link_epoch, 7);
        assert!(!listing.machines[1].enabled);
        let round_trip =
            RelayListing::parse(serde_json::to_string(&listing).unwrap().as_bytes()).unwrap();
        assert_eq!(round_trip, listing);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
