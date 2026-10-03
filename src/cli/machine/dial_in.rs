//! Hub-side `herdr machine` commands for dial-in machines: machines that
//! connect to this hub over SSH themselves (see `crate::remote::link`).
//! SSH machine behavior stays in the parent module.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::super::target::SavedMachineRef;
use super::{MachineListRow, MachineStatusRow, SSH_KIND};
use crate::api::client::{ApiClient, ApiClientError};
use crate::client::endpoint::{
    DialInCatalog, DialInMachine, EndpointCatalog, ProfileId, SavedSshEndpoint,
};
use crate::remote::link::authorized_keys::{self, PublicKey};
use crate::remote::link::authorized_keys_file;
use crate::remote::link::status::{self as link_status, ErrorRecord, SlaveInfo};
use crate::remote::LinkPaths;

pub(super) const DIAL_IN_KIND: &str = "dial-in";
/// Placeholder hub in the printed slave setup command when `--hub` is absent.
const HUB_PLACEHOLDER: &str = "USER@THIS-HUB";
/// Dial names on the slave follow `session::validate_name`, which allows 64 bytes.
const MAX_DIAL_SLUG_BYTES: usize = 64;
const DIAL_IN_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_POLL: Duration = Duration::from_millis(500);
const STATUS_CONNECTED: &str = "connected";
const STATUS_OFFLINE: &str = "offline";
const STATUS_SERVER_UNAVAILABLE: &str = "server unavailable";
const STATUS_DISABLED: &str = "disabled";
const STATUS_ERROR: &str = "error";

#[derive(Serialize)]
pub(super) struct DialInListRow<'a> {
    id: &'a str,
    label: &'a str,
    session: &'a str,
    enabled: bool,
    selected: bool,
    /// From the link's `status.json`; not probed.
    connected: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    agent_forwarding: bool,
    kind: &'static str,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum MachineListEntry<'a> {
    Ssh {
        #[serde(flatten)]
        row: MachineListRow<'a>,
        kind: &'static str,
    },
    DialIn(DialInListRow<'a>),
}

#[derive(Debug, Default, PartialEq, Eq)]
struct AuthorizeArgs {
    selector: String,
    key_line: String,
    herdr_path: Option<String>,
    /// Add the line to `authorized_keys` instead of printing it.
    write: bool,
    authorized_keys: Option<String>,
    replace: bool,
}

const AUTHORIZE_USAGE: &str = "usage: herdr machine authorize <label-or-id> '<public key line>' [--herdr-path <path>] [--write [--authorized-keys <path>] [--replace]]";

fn parse_authorize_args(args: &[String]) -> Result<AuthorizeArgs, String> {
    let args = super::super::expand_equals_args(args, &["--herdr-path", "--authorized-keys"]);
    let mut parsed = AuthorizeArgs::default();
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let name = args[index].as_str();
        let slot = match name {
            "--herdr-path" => &mut parsed.herdr_path,
            "--authorized-keys" => &mut parsed.authorized_keys,
            "--write" | "--replace" => {
                let flag = if name == "--write" {
                    &mut parsed.write
                } else {
                    &mut parsed.replace
                };
                if std::mem::replace(flag, true) {
                    return Err(format!("{name} can only be specified once"));
                }
                index += 1;
                continue;
            }
            flag if flag.starts_with("--") => {
                return Err(format!("unknown machine authorize option: {flag}"));
            }
            value => {
                positionals.push(value.to_owned());
                index += 1;
                continue;
            }
        };
        let Some(value) = args.get(index + 1) else {
            return Err(format!("missing value for {name}"));
        };
        if slot.replace(value.clone()).is_some() {
            return Err(format!("{name} can only be specified once"));
        }
        index += 2;
    }
    if !parsed.write && (parsed.authorized_keys.is_some() || parsed.replace) {
        return Err("--authorized-keys and --replace require --write".into());
    }
    match <[String; 2]>::try_from(positionals) {
        Ok([selector, key_line]) => Ok(AuthorizeArgs {
            selector,
            key_line,
            ..parsed
        }),
        Err(positionals) if positionals.len() > 2 => Err(format!(
            "{AUTHORIZE_USAGE}\nquote the public key line so it is a single argument"
        )),
        Err(_) => Err(AUTHORIZE_USAGE.into()),
    }
}

/// Prints the hub `authorized_keys` line for a dial-in machine's key. The
/// line goes to stdout alone, so it can be appended with `>>`; guidance goes
/// to stderr. With `--write`, adds the line to `authorized_keys` instead.
pub(super) fn authorize(args: &[String]) -> std::io::Result<i32> {
    let parsed = match parse_authorize_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let key = match authorized_keys::parse_public_key_line(&parsed.key_line) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let ssh = EndpointCatalog::load_profiles().map_err(std::io::Error::other)?;
    let dial_in = load_catalog()?;
    let machine = match super::super::target::find_saved_machine(
        &ssh,
        &dial_in.machines,
        &parsed.selector,
    ) {
        Ok(SavedMachineRef::DialIn(machine)) => machine,
        Ok(SavedMachineRef::Ssh(profile)) => {
            eprintln!(
                    "error: machine '{}' is an SSH machine; authorize applies only to dial-in machines (see `herdr machine add --dial-in`)",
                    profile.label
                );
            return Ok(2);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let line = match render_line(machine, &key, parsed.herdr_path.as_deref()) {
        Ok(line) => line,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    if parsed.write {
        let written = authorized_keys_path(parsed.authorized_keys.as_deref()).and_then(|path| {
            authorized_keys_file::authorize(&path, &machine.id, key.base64(), &line, parsed.replace)
                .map(|replaced| (path, replaced))
        });
        let (path, replaced) = match written {
            Ok(written) => written,
            Err(error) => {
                eprintln!("error: {error}");
                return Ok(1);
            }
        };
        println!(
            "{} the authorized_keys line for dial-in machine '{}' in {}.",
            if replaced { "Replaced" } else { "Added" },
            machine.label,
            path.display()
        );
        println!(
            "To revoke it, run `herdr machine remove {} --revoke`.",
            machine.id
        );
    } else {
        eprintln!(
            "Append this line to ~/.ssh/authorized_keys (or the file AuthorizedKeysFile names in sshd_config) for the hub account dial-in machine '{}' connects to:",
            machine.label
        );
        println!("{line}");
        eprintln!(
            "The line confines the key to `herdr link-accept` for this machine only: `restrict` disables shells, PTYs, and forwarding, and sshd runs the forced command whatever command the client requests."
        );
        eprintln!(
            "To revoke access, delete the line ending in {}{id} or run `herdr machine remove {id} --revoke`. With --write, Herdr adds the line itself.",
            authorized_keys::LINK_KEY_COMMENT_PREFIX,
            id = machine.id
        );
    }
    if !machine.enabled {
        eprintln!(
            "note: machine '{}' is disabled; run `herdr machine enable {}` so it can connect.",
            machine.label, machine.id
        );
    }
    Ok(0)
}

/// `--herdr-path`, or the running executable unless it lives in a versioned
/// package directory and a stable launcher exists.
fn authorize_herdr_path(explicit: Option<&str>) -> Result<PathBuf, String> {
    let (path, message) =
        crate::remote::link::stable_herdr_path(explicit.map(Path::new)).map_err(|error| {
            match explicit {
                Some(_) => format!("--herdr-path: {error}"),
                None => format!("failed to locate the Herdr executable: {error}"),
            }
        })?;
    if let Some(message) = message {
        eprintln!("{message}");
    }
    Ok(path)
}

/// The restricted `authorized_keys` line for `machine`'s key.
fn render_line(
    machine: &DialInMachine,
    key: &PublicKey,
    herdr_path: Option<&str>,
) -> Result<String, String> {
    let herdr = authorize_herdr_path(herdr_path)?;
    let catalog = std::path::absolute(crate::client::endpoint::dial_in_catalog_path())
        .map_err(|error| format!("failed to locate the dial-in machine catalog: {error}"))?;
    authorized_keys::render_authorized_keys_line(&herdr, &catalog, &machine.id, key)
}

/// `--authorized-keys` made absolute, or `~/.ssh/authorized_keys`.
fn authorized_keys_path(explicit: Option<&str>) -> Result<PathBuf, String> {
    match explicit {
        Some(path) => {
            std::path::absolute(path).map_err(|error| format!("--authorized-keys: {error}"))
        }
        None => authorized_keys_file::default_path(),
    }
}

/// `machine list` rows for dial-in machines; `connected` comes from each
/// link's `status.json` without probing.
pub(super) fn list_rows<'a>(
    catalog: &'a DialInCatalog,
    selected: Option<&ProfileId>,
) -> Vec<DialInListRow<'a>> {
    catalog
        .machines
        .iter()
        .map(|machine| DialInListRow {
            id: machine.id.as_str(),
            label: &machine.label,
            session: &machine.session,
            enabled: machine.enabled,
            selected: selected == Some(&machine.id),
            connected: dial_in_link_connected(&machine.paths()),
            agent_forwarding: machine.agent_forwarding,
            kind: DIAL_IN_KIND,
        })
        .collect()
}

/// Text rows in the SSH column layout: id, label, link, session, state.
pub(super) fn print_list_rows(rows: &[DialInListRow<'_>]) {
    for row in rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        let link = if row.connected {
            "connected"
        } else {
            "offline"
        };
        let agent = if row.agent_forwarding {
            ", agent forwarding"
        } else {
            ""
        };
        println!(
            "{}\t{}\tdial-in ({link}{agent})\t{}\t{}",
            row.id, row.label, row.session, state
        );
    }
}

/// One `machine status` row, probing the machine's server when its link is up.
pub(super) fn status_row(machine: &DialInMachine) -> MachineStatusRow<'_> {
    let report = evaluate_dial_in(machine, &machine.paths(), probe_dial_in_api);
    MachineStatusRow::dial_in(machine, report)
}

pub(super) fn list_entries<'a>(
    ssh: Vec<MachineListRow<'a>>,
    dial_in: Vec<DialInListRow<'a>>,
) -> Vec<MachineListEntry<'a>> {
    ssh.into_iter()
        .map(|row| MachineListEntry::Ssh {
            row,
            kind: SSH_KIND,
        })
        .chain(dial_in.into_iter().map(MachineListEntry::DialIn))
        .collect()
}

/// Whether the link's `status.json` says it is connected and its holder
/// process still runs. Never probes the link.
fn dial_in_link_connected(paths: &LinkPaths) -> bool {
    crate::platform::verify_private_directory(&paths.dir).is_ok()
        && matches!(
            link_status::read_status(&paths.status_file),
            Ok(Some(status)) if status.is_live()
        )
}

impl<'a> MachineStatusRow<'a> {
    fn dial_in(machine: &'a DialInMachine, report: DialInReport) -> Self {
        Self {
            id: machine.id.as_str(),
            label: &machine.label,
            status: report.status,
            error: report.error,
            kind: DIAL_IN_KIND,
            slave: report.slave,
            server_version: report.server_version,
            connected_since_ms: report.connected_since_ms,
            last_error: report.last_error,
            last_stream_error: report.last_stream_error,
            claim_conflict: report.claim_conflict,
            agent_forwarding: Some(machine.agent_forwarding),
            agent_leases: report.agent_leases,
        }
    }

    /// Indented text lines under a dial-in row; every slave string is sanitized.
    pub(super) fn dial_in_details(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(conflict) = &self.claim_conflict {
            lines.push(format!(
                "WARNING: {conflict}; another machine may be using this machine's key"
            ));
        }
        lines.extend(self.error.clone());
        if let Some(slave) = &self.slave {
            let mut machine = format!(
                "machine: herdr {}",
                slave.herdr_version.as_deref().unwrap_or("unknown")
            );
            if let (Some(os), Some(arch)) = (&slave.os, &slave.arch) {
                machine.push_str(&format!(" on {os}/{arch}"));
            }
            if let Some(hostname) = &slave.hostname {
                machine.push_str(&format!(", host {hostname}"));
            }
            lines.push(machine);
            if let Some(error) = &slave.last_dial_error {
                lines.push(format!("slave reported: {error}"));
            }
        }
        if let Some(version) = &self.server_version {
            lines.push(format!("server: herdr {version}"));
        }
        if self.agent_forwarding == Some(true) {
            lines.push(match self.agent_leases {
                Some(leases) => {
                    format!("agent forwarding: on ({leases} hub window(s) lending an agent)")
                }
                None => "agent forwarding: on".into(),
            });
        }
        if self.status != STATUS_CONNECTED {
            if let Some(record) = &self.last_error {
                lines.push(format!(
                    "last link error: {} ({})",
                    record.message, record.code
                ));
            }
            if let Some(record) = &self.last_stream_error {
                lines.push(format!(
                    "last stream error: {} ({})",
                    record.message, record.code
                ));
            }
        }
        lines
    }
}

/// What `status` reports for one dial-in machine.
#[derive(Debug, PartialEq, Eq)]
struct DialInReport {
    status: &'static str,
    error: Option<String>,
    slave: Option<SlaveInfo>,
    server_version: Option<String>,
    connected_since_ms: Option<u64>,
    last_error: Option<ErrorRecord>,
    last_stream_error: Option<ErrorRecord>,
    claim_conflict: Option<String>,
    /// Hub windows lending an agent, while the link is live.
    agent_leases: Option<u32>,
}

impl DialInReport {
    fn new(status: &'static str, error: Option<String>) -> Self {
        Self {
            status,
            error,
            slave: None,
            server_version: None,
            connected_since_ms: None,
            last_error: None,
            last_stream_error: None,
            claim_conflict: None,
            agent_leases: None,
        }
    }
}

/// Outcome of one API ping through a link's `api.sock`.
#[derive(Debug, PartialEq, Eq)]
enum ApiProbe {
    Reachable {
        version: Option<String>,
    },
    /// Nothing listens on the socket: the link holder is gone.
    NoListener,
    /// The link directory or socket is not private to this user.
    Refused(String),
    Failed(String),
}

fn probe_dial_in_api(paths: &LinkPaths) -> ApiProbe {
    let client = ApiClient::for_target(super::super::target::dial_in_api_target(paths));
    match client.status_with_timeout(DIAL_IN_PROBE_TIMEOUT) {
        Ok(status) => ApiProbe::Reachable {
            version: status.version,
        },
        Err(ApiClientError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            ApiProbe::NoListener
        }
        Err(ApiClientError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            ApiProbe::Refused(error.to_string())
        }
        Err(ApiClientError::EmptyResponse) => {
            ApiProbe::Failed("the machine closed the stream without answering".into())
        }
        Err(error) => ApiProbe::Failed(error.to_string()),
    }
}

fn dial_in_offline_message() -> String {
    "not connected (it has not dialed in); on that machine, run `herdr machine dial status`".into()
}

fn sanitize_remote(text: &str) -> String {
    link_status::sanitize_remote_text(text, link_status::MAX_REMOTE_TEXT_BYTES)
}

fn sanitized_slave(slave: &SlaveInfo) -> SlaveInfo {
    let text = |value: &Option<String>| {
        value
            .as_deref()
            .map(sanitize_remote)
            .filter(|value| !value.is_empty())
    };
    SlaveInfo {
        herdr_version: text(&slave.herdr_version),
        protocol_version: slave.protocol_version,
        os: text(&slave.os),
        arch: text(&slave.arch),
        hostname: text(&slave.hostname),
        features: slave
            .features
            .iter()
            .map(|name| link_status::sanitize_remote_text(name, 64))
            .collect(),
        last_dial_error: text(&slave.last_dial_error),
    }
}

fn sanitized_record(record: &ErrorRecord) -> ErrorRecord {
    ErrorRecord {
        at_ms: record.at_ms,
        code: link_status::sanitize_remote_text(&record.code, 64),
        message: sanitize_remote(&record.message),
    }
}

/// Reads a dial-in machine's link state and, when the link says it is
/// connected, pings the machine's server through `api.sock` with `probe`.
fn evaluate_dial_in(
    machine: &DialInMachine,
    paths: &LinkPaths,
    probe: impl FnOnce(&LinkPaths) -> ApiProbe,
) -> DialInReport {
    if !machine.enabled {
        return DialInReport::new(STATUS_DISABLED, None);
    }
    match crate::platform::verify_private_directory(&paths.dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DialInReport::new(STATUS_OFFLINE, Some(dial_in_offline_message()));
        }
        Err(error) => {
            return DialInReport::new(
                STATUS_ERROR,
                Some(format!("refusing dial-in link directory: {error}")),
            );
        }
    }
    let link = match link_status::read_status(&paths.status_file) {
        Ok(Some(link)) => link,
        Ok(None) => return DialInReport::new(STATUS_OFFLINE, Some(dial_in_offline_message())),
        Err(error) => {
            return DialInReport::new(
                STATUS_ERROR,
                Some(format!("failed to read dial-in link status: {error}")),
            );
        }
    };
    let mut report = DialInReport::new(STATUS_OFFLINE, Some(dial_in_offline_message()));
    report.slave = link.slave.as_ref().map(sanitized_slave);
    report.last_error = link.last_error.as_ref().map(sanitized_record);
    report.last_stream_error = link.last_stream_error.as_ref().map(sanitized_record);
    report.claim_conflict = link.claim_conflict.as_deref().map(sanitize_remote);
    // A holder that died without cleanup leaves `connected` behind.
    if !link.is_live() {
        return report;
    }
    report.agent_leases = Some(link.agent_leases);
    let probe_started_ms = link_status::now_ms();
    match probe(paths) {
        ApiProbe::Reachable { version } => {
            report.status = STATUS_CONNECTED;
            report.error = None;
            report.server_version = version.as_deref().map(sanitize_remote);
            report.connected_since_ms = link.connected_since_ms;
        }
        // status.json still says connected, but its holder is gone.
        ApiProbe::NoListener => {}
        ApiProbe::Refused(error) => {
            report.status = STATUS_ERROR;
            report.error = Some(format!("refusing dial-in link socket: {error}"));
        }
        ApiProbe::Failed(error) => {
            report.status = STATUS_SERVER_UNAVAILABLE;
            report.connected_since_ms = link.connected_since_ms;
            let mut message = format!(
                "the link is up, but the machine's Herdr server did not answer: {}",
                sanitize_remote(&error)
            );
            if let Some(reported) =
                super::super::target::await_stream_error(paths, probe_started_ms)
            {
                message.push_str("; the machine reported: ");
                message.push_str(&reported);
            }
            report.error = Some(message);
            if let Ok(Some(link)) = link_status::read_status(&paths.status_file) {
                report.last_stream_error = link.last_stream_error.as_ref().map(sanitized_record);
            }
        }
    }
    report
}

/// A dial-in machine connects by itself: waits up to `wait` for its link
/// and server, then reports its state.
pub(super) fn reconnect(machine: &DialInMachine, wait: Duration) -> std::io::Result<i32> {
    println!(
        "Dial-in machine '{}' connects to this hub by itself; Herdr on this hub cannot start that connection.",
        machine.label
    );
    let paths = machine.paths();
    // A wait too long to represent has no deadline.
    let deadline = Instant::now().checked_add(wait);
    let mut waiting = false;
    let report = loop {
        let report = evaluate_dial_in(machine, &paths, probe_dial_in_api);
        let now = Instant::now();
        if matches!(
            report.status,
            STATUS_CONNECTED | STATUS_DISABLED | STATUS_ERROR
        ) || deadline.is_some_and(|deadline| now >= deadline)
        {
            break report;
        }
        if !std::mem::replace(&mut waiting, true) {
            println!("Waiting up to {}s for it to connect...", wait.as_secs());
        }
        let poll = deadline.map_or(RECONNECT_POLL, |deadline| {
            RECONNECT_POLL.min(deadline - now)
        });
        std::thread::sleep(poll);
    };
    let row = MachineStatusRow::dial_in(machine, report);
    println!("{}\t{}\t{}", row.id, row.label, row.status);
    for line in row.dial_in_details() {
        println!("  {line}");
    }
    if row.status == STATUS_CONNECTED {
        println!("Open Herdr clients use it automatically.");
        return Ok(0);
    }
    println!(
        "On that machine, check `herdr machine dial status` and keep `herdr machine dial run <name>` running; it retries by itself."
    );
    Ok(1)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DialInAddArgs {
    label: String,
    session: Option<String>,
    hub: Option<String>,
    agent_forwarding: bool,
    /// `--authorize-key -`: authorize the public key line read from stdin.
    authorize_key: bool,
    json: bool,
}

const ADD_DIAL_IN_USAGE: &str = "usage: herdr machine add --dial-in --label <label> [--remote-session <name>] [--hub <ssh-target>] [--agent-forwarding] [--authorize-key -] [--json]";

fn parse_add_dial_in_args(args: &[String]) -> Result<DialInAddArgs, String> {
    let args = super::super::expand_equals_args(
        args,
        &["--label", "--remote-session", "--hub", "--authorize-key"],
    );
    let mut dial_in = false;
    let mut json = false;
    let mut agent_forwarding = false;
    let mut label = None;
    let mut session = None;
    let mut hub = None;
    let mut authorize_key = None;
    let mut index = 0;
    while index < args.len() {
        let name = args[index].as_str();
        let slot = match name {
            "--dial-in" | "--json" | "--agent-forwarding" => {
                let flag = match name {
                    "--json" => &mut json,
                    "--agent-forwarding" => &mut agent_forwarding,
                    _ => &mut dial_in,
                };
                if std::mem::replace(flag, true) {
                    return Err(format!("{name} can only be specified once"));
                }
                index += 1;
                continue;
            }
            "--label" => &mut label,
            "--remote-session" => &mut session,
            "--hub" => &mut hub,
            "--authorize-key" => &mut authorize_key,
            positional if !positional.starts_with('-') => {
                return Err(format!(
                    "dial-in machines take no SSH target ('{positional}'); the machine connects to this hub instead"
                ));
            }
            unknown => return Err(format!("unknown machine add option: {unknown}")),
        };
        let Some(value) = args.get(index + 1).filter(|value| !value.starts_with("--")) else {
            return Err(format!("missing value for {name}"));
        };
        if slot.replace(value.clone()).is_some() {
            return Err(format!("{name} can only be specified once"));
        }
        index += 2;
    }
    if !dial_in {
        return Err(ADD_DIAL_IN_USAGE.into());
    }
    let label =
        label.ok_or_else(|| format!("--label is required with --dial-in\n{ADD_DIAL_IN_USAGE}"))?;
    if let Some(hub) = &hub {
        validate_hub(hub)?;
    }
    if authorize_key.as_deref().is_some_and(|value| value != "-") {
        return Err("--authorize-key takes `-` and reads the public key line from stdin".into());
    }
    Ok(DialInAddArgs {
        label,
        session,
        hub,
        agent_forwarding,
        authorize_key: authorize_key.is_some(),
        json,
    })
}

/// The hub target is only echoed into the printed slave command, where the
/// slave validates it again.
fn validate_hub(hub: &str) -> Result<(), String> {
    crate::remote::validate_remote_target(hub).map_err(|_| {
        "--hub must be the SSH target the dial-in machine uses to reach this hub".to_owned()
    })?;
    if hub.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err("--hub must not contain whitespace or control characters".into());
    }
    Ok(())
}

/// Dial name suggested for the slave: the label lowercased, every run of
/// characters outside `[a-z0-9]` (dashes included) replaced by one `-`,
/// trimmed of dashes, and bounded to a valid session-style name; `hub` when
/// nothing usable remains.
fn dial_slug(label: &str) -> String {
    let mut slug = String::with_capacity(label.len());
    for ch in label.chars().map(|ch| ch.to_ascii_lowercase()) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            slug.push(ch);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let mut slug = slug.trim_matches('-').to_owned();
    slug.truncate(MAX_DIAL_SLUG_BYTES);
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() || crate::session::validate_name(slug).is_err() {
        return "hub".into();
    }
    slug.to_owned()
}

/// Adds a dial-in machine whose label and id are unique across both catalogs.
fn add_dial_in_machine(
    ssh: &[SavedSshEndpoint],
    dial_in: &mut DialInCatalog,
    label: &str,
    session: &str,
) -> Result<ProfileId, String> {
    check_label_free_in_ssh(ssh, label)?;
    let taken_ids = ssh
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();
    dial_in.add(label, session, &taken_ids)
}

fn check_label_free_in_ssh(ssh: &[SavedSshEndpoint], label: &str) -> Result<(), String> {
    let label = label.trim();
    if ssh.iter().any(|profile| profile.label.trim() == label) {
        return Err(format!(
            "an SSH machine named '{label}' already exists; choose another label"
        ));
    }
    Ok(())
}

/// Fails when a dial-in machine already uses `label` (compared trimmed),
/// keeping labels unique across both catalogs so every label resolves.
pub(super) fn check_label_free_in_dial_in(
    dial_in: &[DialInMachine],
    label: &str,
) -> Result<(), String> {
    let label = label.trim();
    if dial_in.iter().any(|machine| machine.label.trim() == label) {
        return Err(format!(
            "a dial-in machine named '{label}' already exists; choose another label"
        ));
    }
    Ok(())
}

/// Renames a dial-in machine; the label must stay unique across both catalogs.
fn rename_dial_in_machine(
    ssh: &[SavedSshEndpoint],
    dial_in: &mut DialInCatalog,
    id: &ProfileId,
    label: &str,
) -> Result<bool, String> {
    if dial_in.get(id).is_none() {
        return Ok(false);
    }
    check_label_free_in_ssh(ssh, label)?;
    dial_in.rename(id, label)
}

/// Shell-safe rendering of one argument in a printed command.
fn display_shell_arg(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '@' | '%' | '_' | '+' | '=' | ':' | ',' | '.' | '/' | '-'
                )
        })
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn dial_setup_command(slug: &str, hub: &str, id: &ProfileId) -> String {
    format!(
        "herdr machine dial setup {} --hub {} --link {id}",
        display_shell_arg(slug),
        display_shell_arg(hub)
    )
}

/// What `machine add --dial-in --json` prints; `dial setup --pair` reads it.
#[derive(Serialize)]
struct DialInAdded<'a> {
    id: &'a str,
    label: &'a str,
    session: &'a str,
    authorized_keys_path: Option<String>,
    herdr_version: String,
}

/// One public key line from stdin (`--authorize-key -`), strictly parsed.
fn read_public_key_from_stdin() -> Result<PublicKey, String> {
    use std::io::{BufRead as _, Read as _};
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(authorized_keys::MAX_PUBLIC_KEY_LINE_BYTES as u64 + 2)
        .read_line(&mut line)
        .map_err(|error| format!("failed to read the public key from stdin: {error}"))?;
    let line = line.strip_suffix('\n').unwrap_or(&line);
    authorized_keys::parse_public_key_line(line.strip_suffix('\r').unwrap_or(line))
        .map_err(|error| error.to_string())
}

pub(super) fn add(args: &[String]) -> std::io::Result<i32> {
    let DialInAddArgs {
        label,
        session,
        hub,
        agent_forwarding,
        authorize_key,
        json,
    } = match parse_add_dial_in_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let key = match authorize_key.then(read_public_key_from_stdin).transpose() {
        Ok(key) => key,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    // Link sockets are authorized by peer uid, which only Unix provides.
    if crate::platform::current_uid().is_none() {
        eprintln!("error: dial-in machines need a Unix hub in this version of Herdr");
        return Ok(2);
    }
    let session = session.unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    let ssh = EndpointCatalog::load_profiles().map_err(std::io::Error::other)?;
    let mut dial_in = load_catalog()?;
    let id = match add_dial_in_machine(&ssh, &mut dial_in, &label, &session) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    if let Err(error) = LinkPaths::for_default_catalog(&id).ensure_socket_paths_fit() {
        eprintln!("error: {error}; machine was not saved");
        return Ok(1);
    }
    dial_in.set_agent_forwarding(&id, agent_forwarding);
    store_catalog(&dial_in)?;
    let Some(machine) = dial_in.get(&id) else {
        return Err(std::io::Error::other("the added machine is missing"));
    };
    let authorized_keys_path = match &key {
        Some(key) => {
            let written = render_line(machine, key, None).and_then(|line| {
                let path = authorized_keys_file::default_path()?;
                authorized_keys_file::authorize(&path, &id, key.base64(), &line, false)?;
                Ok(path)
            });
            match written {
                Ok(path) => Some(path),
                Err(error) => {
                    let mut rollback = load_catalog()?;
                    rollback.remove(&id);
                    store_catalog(&rollback)?;
                    eprintln!("error: {error}; machine was not saved");
                    return Ok(1);
                }
            }
        }
        None => None,
    };
    let label = machine.label.as_str();
    if json {
        let added = DialInAdded {
            id: id.as_str(),
            label,
            session: &session,
            authorized_keys_path: authorized_keys_path
                .as_ref()
                .map(|path| path.display().to_string()),
            herdr_version: crate::build_info::version(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&added).map_err(std::io::Error::other)?
        );
        return Ok(0);
    }
    let slug = dial_slug(label);
    println!("Saved dial-in machine {id} ('{label}', session {session}).");
    println!("Next steps:");
    println!("  1. On that machine, run:");
    println!(
        "       {}",
        dial_setup_command(&slug, hub.as_deref().unwrap_or(HUB_PLACEHOLDER), &id)
    );
    if hub.is_none() {
        println!(
            "     Replace {HUB_PLACEHOLDER} with the SSH target that machine uses to reach this hub."
        );
    }
    match &authorized_keys_path {
        Some(path) => println!("  2. Its key is already authorized in {}.", path.display()),
        None => {
            println!(
                "  2. Run the `herdr machine authorize {id} '<public key>' --write` command it prints here, on this hub."
            );
        }
    }
    println!("  3. On that machine, run: herdr machine dial service install {slug}");
    println!("     (or `herdr machine dial run {slug}` in the foreground)");
    println!("Open Herdr clients connect automatically once it dials in.");
    Ok(0)
}

pub(super) fn rename(
    catalog: &EndpointCatalog,
    id: &ProfileId,
    label: &str,
) -> std::io::Result<i32> {
    let mut dial_in = load_catalog()?;
    match rename_dial_in_machine(&catalog.ssh, &mut dial_in, id, label) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("machine profile {id} was not found");
            return Ok(1);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    store_catalog(&dial_in)?;
    println!("Renamed dial-in machine {id}.");
    Ok(0)
}

/// `machine remove --revoke [--authorized-keys <path>]`: also remove the
/// machine's line from `authorized_keys`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Revoke {
    authorized_keys: Option<String>,
}

/// Splits `--revoke [--authorized-keys <path>]` off `machine remove` arguments.
pub(super) fn split_revoke_args(args: &[String]) -> Result<(Vec<String>, Option<Revoke>), String> {
    let mut rest = Vec::new();
    let mut revoke = false;
    let mut authorized_keys = None;
    let mut args = super::super::expand_equals_args(args, &["--authorized-keys"]).into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--revoke" if !revoke => revoke = true,
            "--authorized-keys" if authorized_keys.is_none() => {
                authorized_keys = Some(args.next().ok_or("missing value for --authorized-keys")?);
            }
            "--revoke" | "--authorized-keys" => {
                return Err(format!("{arg} can only be specified once"));
            }
            _ => rest.push(arg),
        }
    }
    if authorized_keys.is_some() && !revoke {
        return Err("--authorized-keys requires --revoke".into());
    }
    Ok((rest, revoke.then_some(Revoke { authorized_keys })))
}

/// `catalog` has already dropped `id` from its in-memory selection. With
/// `revoke`, the machine's `authorized_keys` line goes first; the machine is
/// kept when that fails.
pub(super) fn remove(
    catalog: &EndpointCatalog,
    previous_selection: Option<&ProfileId>,
    id: &ProfileId,
    revoke: Option<&Revoke>,
) -> std::io::Result<i32> {
    let mut dial_in = load_catalog()?;
    let Some(paths) = dial_in.get(id).map(DialInMachine::paths) else {
        eprintln!("machine profile {id} was not found");
        return Ok(1);
    };
    if let Some(revoke) = revoke {
        let revoked = authorized_keys_path(revoke.authorized_keys.as_deref()).and_then(|path| {
            authorized_keys_file::revoke(&path, id).map(|removed| (path, removed))
        });
        match revoked {
            Ok((path, 0)) => println!(
                "{} has no authorized_keys line for this machine; nothing to revoke.",
                path.display()
            ),
            Ok((path, _)) => println!("Revoked its key in {}.", path.display()),
            Err(error) => {
                eprintln!("error: {error}; machine was not removed");
                return Ok(1);
            }
        }
    }
    dial_in.remove(id);
    store_catalog(&dial_in)?;
    if previous_selection == Some(id) {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    remove_idle_link_state(&paths);
    println!("Removed dial-in machine {id}.");
    if revoke.is_none() {
        println!(
            "Delete the line ending in {}{id} from ~/.ssh/authorized_keys on this hub to revoke its key.",
            authorized_keys::LINK_KEY_COMMENT_PREFIX
        );
    }
    Ok(0)
}

/// Best-effort cleanup of a removed machine's link directory. A running link
/// holder keeps its lock, notices the removal, and cleans up after itself.
fn remove_idle_link_state(paths: &LinkPaths) {
    if crate::platform::verify_private_directory(&paths.dir).is_err() {
        return;
    }
    let Ok(Some(lock)) = crate::platform::try_lock_exclusive(&paths.lock_file) else {
        return;
    };
    let _ = std::fs::remove_file(&paths.status_file);
    let _ = std::fs::remove_file(&paths.lock_file);
    drop(lock);
    // Fails, and keeps the directory, while anything else is left in it.
    let _ = std::fs::remove_dir(&paths.dir);
}

pub(super) fn set_enabled(
    catalog: &mut EndpointCatalog,
    id: &ProfileId,
    enabled: bool,
) -> std::io::Result<i32> {
    let mut dial_in = load_catalog()?;
    if !dial_in.set_enabled(id, enabled) {
        eprintln!("machine profile {id} was not found");
        return Ok(1);
    }
    store_catalog(&dial_in)?;
    if !enabled && catalog.selected_profile.as_ref() == Some(id) {
        catalog.selected_profile = None;
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    if enabled {
        println!("Enabled dial-in machine {id}. It connects the next time it dials in.");
    } else {
        println!("Disabled dial-in machine {id}. Its link closes within a few seconds.");
    }
    Ok(0)
}

fn load_catalog() -> std::io::Result<DialInCatalog> {
    DialInCatalog::load().map_err(std::io::Error::other)
}

fn store_catalog(catalog: &DialInCatalog) -> std::io::Result<()> {
    catalog.store().map_err(std::io::Error::other)
}

/// For read-only commands: a broken dial-in catalog is reported on stderr
/// (the bool is true) and treated as empty, so SSH machines stay usable.
pub(super) fn load_catalog_or_warn() -> (DialInCatalog, bool) {
    match DialInCatalog::load() {
        Ok(catalog) => (catalog, false),
        Err(error) => {
            eprintln!("warning: {error}");
            (DialInCatalog::default(), true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::MAX_LABEL_BYTES;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn dial_in_add_parser_requires_a_label_and_no_ssh_target() {
        assert_eq!(
            parse_add_dial_in_args(&strings(&["--dial-in", "--label", "Laptop"])).unwrap(),
            DialInAddArgs {
                label: "Laptop".into(),
                ..DialInAddArgs::default()
            }
        );
        assert_eq!(
            parse_add_dial_in_args(&strings(&[
                "--hub=me@hub.example",
                "--remote-session",
                "agents",
                "--label=Build box",
                "--dial-in",
                "--agent-forwarding",
            ]))
            .unwrap(),
            DialInAddArgs {
                label: "Build box".into(),
                session: Some("agents".into()),
                hub: Some("me@hub.example".into()),
                agent_forwarding: true,
                ..DialInAddArgs::default()
            }
        );
        let paired = parse_add_dial_in_args(&strings(&[
            "--dial-in",
            "--label",
            "a",
            "--authorize-key",
            "-",
            "--json",
        ]))
        .unwrap();
        assert!(paired.authorize_key && paired.json, "{paired:?}");
        for args in [
            &[
                "--dial-in",
                "--label",
                "a",
                "--authorize-key",
                "ssh-ed25519 AAAA",
            ][..],
            &["--dial-in", "--label", "a", "--authorize-key"],
            &["--dial-in", "--label", "a", "--json", "--json"],
            &["--dial-in"][..],
            &["--label", "Laptop"],
            &["--dial-in", "--label"],
            &["--dial-in", "--label", "--hub", "me@hub"],
            &["--dial-in", "--label", "a", "--label", "b"],
            &["--dial-in", "--dial-in", "--label", "a"],
            &[
                "--dial-in",
                "--label",
                "a",
                "--agent-forwarding",
                "--agent-forwarding",
            ],
            &["--dial-in", "--label", "a", "workstation.coder"],
            &["--dial-in", "--label", "a", "--hub", "-oProxyCommand=x"],
            &["--dial-in", "--label", "a", "--hub", "me@hub extra"],
            &["--dial-in", "--label", "a", "--unknown"],
        ] {
            assert!(parse_add_dial_in_args(&strings(args)).is_err(), "{args:?}");
        }
        let error =
            parse_add_dial_in_args(&strings(&["--dial-in", "--label", "a", "box"])).unwrap_err();
        assert!(error.contains("no SSH target"), "{error}");
    }

    #[test]
    fn dial_slug_derives_a_valid_dial_name_from_the_label() {
        for (label, slug) in [
            ("Laptop", "laptop"),
            ("Build Box!", "build-box"),
            ("UPPER-case_09", "upper-case-09"),
            ("  --Ünïcode__Host--  ", "n-code-host"),
            ("a--b", "a-b"),
            ("!!!", "hub"),
            ("...", "hub"),
            ("Ü", "hub"),
            ("", "hub"),
        ] {
            assert_eq!(dial_slug(label), slug, "{label:?}");
        }
        assert_eq!(dial_slug(&"a".repeat(128)), "a".repeat(MAX_DIAL_SLUG_BYTES));
        assert_eq!(
            dial_slug(&format!("{} b", "a".repeat(MAX_DIAL_SLUG_BYTES - 1))),
            "a".repeat(MAX_DIAL_SLUG_BYTES - 1)
        );
        for label in ["Laptop", "Build Box!", &"x".repeat(MAX_LABEL_BYTES)] {
            assert!(crate::session::validate_name(&dial_slug(label)).is_ok());
        }
    }

    #[test]
    fn dial_in_labels_and_ids_are_unique_across_catalogs() {
        let mut ssh = EndpointCatalog::default();
        ssh.add_ssh("Build", "build", "default").unwrap();
        let mut dial_in = DialInCatalog::default();

        for taken in ["Build", " Build "] {
            let error = add_dial_in_machine(&ssh.ssh, &mut dial_in, taken, "default").unwrap_err();
            assert!(error.contains("SSH machine named 'Build'"), "{error}");
        }
        let id = add_dial_in_machine(&ssh.ssh, &mut dial_in, "Laptop", "agents").unwrap();
        assert!(ssh.ssh.iter().all(|profile| profile.id != id));
        assert_eq!(dial_in.get(&id).unwrap().session, "agents");
        assert!(add_dial_in_machine(&ssh.ssh, &mut dial_in, "Laptop", "default").is_err());
        assert!(add_dial_in_machine(&ssh.ssh, &mut dial_in, "Desk", "not valid").is_err());
        assert_eq!(dial_in.machines.len(), 1);

        assert!(rename_dial_in_machine(&ssh.ssh, &mut dial_in, &id, "Build").is_err());
        assert!(rename_dial_in_machine(&ssh.ssh, &mut dial_in, &id, "Desk").unwrap());
        assert_eq!(dial_in.get(&id).unwrap().label, "Desk");
        let missing = ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap();
        assert!(!rename_dial_in_machine(&ssh.ssh, &mut dial_in, &missing, "Build").unwrap());
        assert!(!rename_dial_in_machine(&ssh.ssh, &mut dial_in, &missing, "Other").unwrap());
    }

    #[test]
    fn dial_setup_command_quotes_only_what_needs_quoting() {
        let id = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            dial_setup_command("laptop", "me@hub.example", &id),
            "herdr machine dial setup laptop --hub me@hub.example --link 0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            dial_setup_command("laptop", HUB_PLACEHOLDER, &id),
            "herdr machine dial setup laptop --hub USER@THIS-HUB --link 0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            dial_setup_command("laptop", "ssh://me@[::1]:2222", &id),
            "herdr machine dial setup laptop --hub 'ssh://me@[::1]:2222' --link 0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn authorize_parser_takes_a_selector_and_one_quoted_key_line() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== herdr-dial:laptop";
        assert_eq!(
            parse_authorize_args(&strings(&["laptop", key])).unwrap(),
            AuthorizeArgs {
                selector: "laptop".into(),
                key_line: key.into(),
                ..AuthorizeArgs::default()
            }
        );
        let written = parse_authorize_args(&strings(&[
            "laptop",
            "--write",
            key,
            "--authorized-keys=/tmp/keys",
            "--replace",
        ]))
        .unwrap();
        assert!(written.write && written.replace, "{written:?}");
        assert_eq!(written.authorized_keys.as_deref(), Some("/tmp/keys"));
        for args in [
            strings(&["--herdr-path", "/usr/local/bin/herdr", "laptop", key]),
            strings(&["laptop", key, "--herdr-path=/usr/local/bin/herdr"]),
        ] {
            let parsed = parse_authorize_args(&args).unwrap();
            assert_eq!(parsed.key_line, key);
            assert_eq!(parsed.herdr_path.as_deref(), Some("/usr/local/bin/herdr"));
        }
        let unquoted = parse_authorize_args(&strings(&[
            "laptop",
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIA==",
        ]))
        .unwrap_err();
        assert!(unquoted.contains("quote"), "{unquoted}");
        for args in [
            &[][..],
            &["laptop"],
            &["laptop", key, "--herdr-path"],
            &["laptop", key, "--herdr-path", "/a", "--herdr-path", "/b"],
            &["laptop", key, "--force"],
            &["laptop", key, "--replace"],
            &["laptop", key, "--authorized-keys", "/tmp/keys"],
            &["laptop", key, "--write", "--write"],
        ] {
            assert!(parse_authorize_args(&strings(args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn remove_splits_off_revoke_and_its_authorized_keys_path() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            split_revoke_args(&strings(&[id])).unwrap(),
            (strings(&[id]), None)
        );
        assert_eq!(
            split_revoke_args(&strings(&["--revoke", id, "--authorized-keys=/k"])).unwrap(),
            (
                strings(&[id]),
                Some(Revoke {
                    authorized_keys: Some("/k".into())
                })
            )
        );
        for args in [
            &[id, "--authorized-keys", "/k"][..],
            &[id, "--revoke", "--revoke"],
            &[id, "--revoke", "--authorized-keys"],
        ] {
            assert!(split_revoke_args(&strings(args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn list_entries_keep_ssh_fields_and_tag_each_kind() {
        let entries = list_entries(
            vec![MachineListRow {
                id: "0123456789abcdef0123456789abcdef",
                label: "Build",
                target: "dev@build",
                session: "agents",
                enabled: true,
                selected: true,
            }],
            vec![DialInListRow {
                id: "fedcba9876543210fedcba9876543210",
                label: "Laptop",
                session: "default",
                enabled: true,
                selected: false,
                connected: true,
                agent_forwarding: false,
                kind: DIAL_IN_KIND,
            }],
        );
        let value = serde_json::to_value(&entries).unwrap();
        assert_eq!(
            value,
            serde_json::json!([
                {
                    "id": "0123456789abcdef0123456789abcdef",
                    "label": "Build",
                    "target": "dev@build",
                    "session": "agents",
                    "enabled": true,
                    "selected": true,
                    "kind": "ssh"
                },
                {
                    "id": "fedcba9876543210fedcba9876543210",
                    "label": "Laptop",
                    "session": "default",
                    "enabled": true,
                    "selected": false,
                    "connected": true,
                    "kind": "dial-in"
                }
            ])
        );
    }

    #[cfg(unix)]
    struct LinkScratch {
        root: PathBuf,
        paths: LinkPaths,
    }

    #[cfg(unix)]
    impl LinkScratch {
        fn new(machine: &DialInMachine) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = PathBuf::from(format!(
                "/tmp/hcm-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let paths = LinkPaths::for_catalog(&root.join("dial-in-machines.json"), &machine.id);
            Self { root, paths }
        }

        fn write_status(&self, status: &link_status::LinkStatus) {
            crate::platform::ensure_private_directory(&self.paths.dir).unwrap();
            link_status::write_status(&self.paths.status_file, status).unwrap();
        }
    }

    #[cfg(unix)]
    impl Drop for LinkScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn unexpected_probe(_: &LinkPaths) -> ApiProbe {
        panic!("the API socket must not be probed")
    }

    #[cfg(unix)]
    fn connected_status() -> link_status::LinkStatus {
        link_status::LinkStatus {
            state: link_status::LinkState::Connected,
            link_epoch: 3,
            connected_since_ms: Some(1_000),
            slave: Some(SlaveInfo {
                herdr_version: Some("0.9.3\u{1b}[31m".into()),
                protocol_version: Some(7),
                os: Some("linux".into()),
                arch: Some("aarch64".into()),
                hostname: Some("pi\u{7}".into()),
                ..SlaveInfo::default()
            }),
            ..link_status::LinkStatus::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn dial_in_status_reads_the_link_before_probing_its_server() {
        use std::os::unix::fs::PermissionsExt;

        let mut machine = DialInMachine::new("Laptop", "default").unwrap();
        let scratch = LinkScratch::new(&machine);
        let paths = &scratch.paths;

        machine.enabled = false;
        assert_eq!(
            evaluate_dial_in(&machine, paths, unexpected_probe),
            DialInReport::new(STATUS_DISABLED, None)
        );
        machine.enabled = true;

        let report = evaluate_dial_in(&machine, paths, unexpected_probe);
        assert_eq!(report.status, STATUS_OFFLINE);
        assert!(report.error.unwrap().contains("herdr machine dial status"));
        assert!(!dial_in_link_connected(paths));

        crate::platform::ensure_private_directory(&paths.dir).unwrap();
        assert_eq!(
            evaluate_dial_in(&machine, paths, unexpected_probe).status,
            STATUS_OFFLINE
        );

        let disconnected = link_status::LinkStatus {
            last_error: Some(ErrorRecord {
                at_ms: 5,
                code: "link_dead".into(),
                message: "no pong\u{1b}[2J for 20s".into(),
            }),
            ..link_status::LinkStatus::default()
        };
        scratch.write_status(&disconnected);
        let report = evaluate_dial_in(&machine, paths, unexpected_probe);
        assert_eq!(report.status, STATUS_OFFLINE);
        assert_eq!(
            report.last_error.as_ref().unwrap().message,
            "no pong[2J for 20s"
        );
        let details = MachineStatusRow::dial_in(&machine, report).dial_in_details();
        assert!(details
            .iter()
            .any(|line| line.starts_with("last link error: no pong")));
        assert!(details.iter().all(|line| !line.contains('\u{1b}')));

        scratch.write_status(&connected_status());
        assert!(dial_in_link_connected(paths));
        let report = evaluate_dial_in(&machine, paths, |link| {
            assert_eq!(link, paths);
            ApiProbe::Reachable {
                version: Some("0.9.3".into()),
            }
        });
        assert_eq!(report.status, STATUS_CONNECTED);
        assert_eq!(report.error, None);
        assert_eq!(report.server_version.as_deref(), Some("0.9.3"));
        assert_eq!(report.connected_since_ms, Some(1_000));
        let slave = report.slave.clone().unwrap();
        assert_eq!(slave.herdr_version.as_deref(), Some("0.9.3[31m"));
        assert_eq!(slave.hostname.as_deref(), Some("pi"));
        let row = MachineStatusRow::dial_in(&machine, report);
        assert_eq!(
            row.dial_in_details(),
            [
                "machine: herdr 0.9.3[31m on linux/aarch64, host pi",
                "server: herdr 0.9.3"
            ]
        );
        let value = serde_json::to_value(&row).unwrap();
        assert_eq!(value["kind"], "dial-in");
        assert_eq!(value["status"], "connected");
        assert_eq!(value["slave"]["protocol_version"], 7);

        // A claim conflict leads the details; the slave's own report follows its line.
        let mut conflicted = connected_status();
        conflicted.claim_conflict = Some("link claimed by more than one machine (a, b)".into());
        if let Some(slave) = &mut conflicted.slave {
            slave.last_dial_error = Some("hello timed out\u{1b}[2J (hello_timeout)".into());
        }
        scratch.write_status(&conflicted);
        let report = evaluate_dial_in(&machine, paths, |_| ApiProbe::Reachable { version: None });
        let row = MachineStatusRow::dial_in(&machine, report);
        let details = row.dial_in_details();
        assert!(details[0].starts_with("WARNING: link claimed by more than one machine (a, b)"));
        assert_eq!(
            details[2],
            "slave reported: hello timed out[2J (hello_timeout)"
        );
        assert_eq!(
            serde_json::to_value(&row).unwrap()["claim_conflict"],
            "link claimed by more than one machine (a, b)"
        );
        scratch.write_status(&connected_status());

        // status.json says connected, but nothing listens on the socket.
        let report = evaluate_dial_in(&machine, paths, |_| ApiProbe::NoListener);
        assert_eq!(report.status, STATUS_OFFLINE);

        // The socket is served by another user: refused, not "unavailable".
        let report = evaluate_dial_in(&machine, paths, |_| {
            ApiProbe::Refused("refusing api.sock: it is served by another user".into())
        });
        assert_eq!(report.status, STATUS_ERROR);
        assert!(report.error.unwrap().contains("served by another user"));

        // A holder that died without cleanup left `connected` behind.
        let mut stale = connected_status();
        let mut exited = std::process::Command::new("true").spawn().unwrap();
        exited.wait().unwrap();
        stale.pid = Some(exited.id());
        scratch.write_status(&stale);
        assert_eq!(
            evaluate_dial_in(&machine, paths, unexpected_probe).status,
            STATUS_OFFLINE
        );
        assert!(!dial_in_link_connected(paths));
        scratch.write_status(&connected_status());

        let report = evaluate_dial_in(&machine, paths, |_| {
            let mut status = connected_status();
            status.last_stream_error = Some(ErrorRecord::new(
                "server_needs_update",
                "remote herdr needs one final update",
            ));
            link_status::write_status(&paths.status_file, &status).unwrap();
            ApiProbe::Failed("the machine closed the stream without answering".into())
        });
        assert_eq!(report.status, STATUS_SERVER_UNAVAILABLE);
        let error = report.error.clone().unwrap();
        assert!(error.contains("closed the stream"), "{error}");
        assert!(error.contains("needs one final update"), "{error}");
        assert_eq!(
            report.last_stream_error.as_ref().unwrap().code,
            "server_needs_update"
        );

        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let report = evaluate_dial_in(&machine, paths, unexpected_probe);
        assert_eq!(report.status, STATUS_ERROR);
        assert!(report
            .error
            .unwrap()
            .contains("refusing dial-in link directory"));
        assert!(!dial_in_link_connected(paths));
    }

    #[cfg(unix)]
    #[test]
    fn removing_a_dial_in_machine_cleans_only_an_idle_link_directory() {
        let machine = DialInMachine::new("Laptop", "default").unwrap();
        let scratch = LinkScratch::new(&machine);
        let paths = &scratch.paths;

        remove_idle_link_state(paths);
        assert!(!paths.dir.exists());

        scratch.write_status(&connected_status());
        let held = crate::platform::try_lock_exclusive(&paths.lock_file)
            .unwrap()
            .unwrap();
        remove_idle_link_state(paths);
        assert!(paths.status_file.exists());
        drop(held);

        std::fs::write(&paths.api_socket, b"").unwrap();
        remove_idle_link_state(paths);
        assert!(!paths.status_file.exists());
        assert!(!paths.lock_file.exists());
        assert!(paths.dir.exists(), "unknown entries keep the directory");

        std::fs::remove_file(&paths.api_socket).unwrap();
        remove_idle_link_state(paths);
        assert!(!paths.dir.exists());
    }
}
