use std::io::IsTerminal as _;

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, SetAttribute};
use crossterm::{cursor, execute, terminal};
use serde::Serialize;

use super::target::SavedMachineRef;
use crate::client::endpoint::{EndpointCatalog, ProfileId, SavedSshEndpoint, MAX_LABEL_BYTES};
use crate::remote::link::status::{ErrorRecord, SlaveInfo};
use dial_in::{authorize, DIAL_IN_KIND};

mod agent;
mod dial_in;
pub(super) mod relay;
mod update;

const HELP: &str = "Usage:
  herdr machine list [--json]
  herdr machine status [<label-or-id>] [--json]
  herdr machine reconnect <label-or-id> [--wait <seconds>]
  herdr machine add <ssh-target> [--label <label>] [--remote-session <name>]
  herdr machine add --dial-in --label <label> [--remote-session <name>] [--hub <ssh-target>] [--agent-forwarding] [--authorize-key -] [--json]
  herdr machine authorize <label-or-id> '<public key line>' [--herdr-path <path>] [--write [--authorized-keys <path>] [--replace]]
  herdr machine agent-forwarding <label-or-id> on|off
  herdr machine update <label-or-id> [--yes] [--restart-server]
  herdr machine rename <profile-id> --label <label>
  herdr machine remove <profile-id> [--revoke [--authorized-keys <path>]]
  herdr machine enable <profile-id>
  herdr machine disable <profile-id>
  herdr machine dial setup|run|list|status|remove|service ...
  herdr machine relay add <ssh-target> [--label <label>]
  herdr machine relay list|remove|rename|enable|disable ...

Add prepares the remote Herdr installation and starts its server before saving.
Missing or incompatible installations require approval in an interactive terminal.
Changes apply automatically to open local Herdr clients.
Removing or disabling a machine leaves its remote sessions running.
Saved machines contain only a label, SSH target, explicit Herdr session, and enabled state.
SSH credentials and key material remain owned by OpenSSH.

Dial-in machines connect to this hub over SSH themselves, for machines this hub
cannot reach. Add one here, run the printed `herdr machine dial setup` command on
that machine, then run the `herdr machine authorize` command it prints here and
append the printed line to ~/.ssh/authorized_keys, or pass --write to let Herdr
add it. `herdr machine dial setup --pair` on that machine does all of this over
your own SSH login to this hub.

Relay hubs: when the hub that dial-in machines connect to is reachable over SSH
from here, `herdr machine relay add <hub>` makes its dial-in machines available
here as <relay>/<machine>. Management commands on such a machine run on the hub.";

const SSH_KIND: &str = "ssh";

#[derive(Serialize)]
struct MachineListRow<'a> {
    id: &'a str,
    label: &'a str,
    target: &'a str,
    session: &'a str,
    enabled: bool,
    selected: bool,
}

pub(super) fn run_machine_command(args: &[String]) -> std::io::Result<i32> {
    if let Some(verb) = args
        .first()
        .map(String::as_str)
        .filter(|verb| relay::FORWARDED_VERBS.contains(verb))
    {
        if let Some(code) = relay::forward(verb, &args[1..])? {
            return Ok(code);
        }
    }
    match args.first().map(String::as_str) {
        Some("list") => list(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("reconnect") => reconnect(&args[1..]),
        Some("add") => add(&args[1..]),
        Some("rename") => rename(&args[1..]),
        Some("remove") => remove(&args[1..]),
        Some("enable") => set_enabled(&args[1..], true),
        Some("disable") => set_enabled(&args[1..], false),
        Some("dial") => super::machine_dial::run_dial_command(&args[1..]),
        Some("relay") => relay::run_relay_command(&args[1..]),
        Some("authorize") => authorize(&args[1..]),
        Some("agent-forwarding") => agent::agent_forwarding(&args[1..]),
        Some("update") => update::update(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            Ok(0)
        }
        _ => {
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

fn list(args: &[String]) -> std::io::Result<i32> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => {
            eprintln!("usage: herdr machine list [--json]");
            return Ok(2);
        }
    };
    let catalog = load_catalog()?;
    // A broken dial-in catalog is reported on stderr only: listing keeps the
    // exit status it had before dial-in machines existed.
    let (dial_in, _) = dial_in::load_catalog_or_warn();
    let rows = catalog
        .ssh
        .iter()
        .map(|profile| MachineListRow {
            id: profile.id.as_str(),
            label: &profile.label,
            target: &profile.target,
            session: &profile.session,
            enabled: profile.enabled,
            selected: catalog.selected_profile.as_ref() == Some(&profile.id),
        })
        .collect::<Vec<_>>();
    let dial_in_rows = dial_in::list_rows(&dial_in, catalog.selected_profile.as_ref());
    // Asks each enabled relay hub once; none saved means no SSH at all.
    let via_rows = relay::via_list_rows(
        catalog
            .selected_profile
            .as_ref()
            .or(catalog.pending_selection.as_ref()),
    );
    if json {
        let mut entries = serde_json::to_value(dial_in::list_entries(rows, dial_in_rows))
            .map_err(std::io::Error::other)?;
        if let serde_json::Value::Array(entries) = &mut entries {
            for row in &via_rows {
                entries.push(serde_json::to_value(row).map_err(std::io::Error::other)?);
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).map_err(std::io::Error::other)?
        );
        return Ok(0);
    }
    if rows.is_empty() && dial_in_rows.is_empty() && via_rows.is_empty() {
        println!("No saved SSH machines.");
        return Ok(0);
    }
    for row in rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        println!(
            "{}\t{}\t{}\t{}\t{}",
            row.id, row.label, row.target, row.session, state
        );
    }
    dial_in::print_list_rows(&dial_in_rows);
    relay::print_via_rows(&via_rows);
    Ok(0)
}

#[derive(Serialize)]
struct MachineStatusRow<'a> {
    id: &'a str,
    label: &'a str,
    status: &'static str,
    error: Option<String>,
    kind: &'static str,
    // Dial-in facts; absent from SSH rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    slave: Option<SlaveInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_since_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<ErrorRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_stream_error: Option<ErrorRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_conflict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_leases: Option<u32>,
}

impl<'a> MachineStatusRow<'a> {
    fn ssh(profile: &'a SavedSshEndpoint, status: &'static str, error: Option<String>) -> Self {
        Self {
            id: profile.id.as_str(),
            label: &profile.label,
            status,
            error,
            kind: SSH_KIND,
            slave: None,
            server_version: None,
            connected_since_ms: None,
            last_error: None,
            last_stream_error: None,
            claim_conflict: None,
            agent_forwarding: None,
            agent_leases: None,
        }
    }
}

fn status(args: &[String]) -> std::io::Result<i32> {
    let mut json = false;
    let mut selector = None;
    for arg in args {
        if arg == "--json" && !json {
            json = true;
        } else if !arg.starts_with('-') && selector.is_none() {
            selector = Some(arg.as_str());
        } else {
            eprintln!("usage: herdr machine status [<label-or-id>] [--json]");
            return Ok(2);
        }
    }
    let catalog = load_catalog()?;
    let (dial_in, dial_in_failed) = dial_in::load_catalog_or_warn();
    let (profiles, machines) = match selector {
        Some(selector) => {
            match super::target::resolve_saved_machine(&catalog.ssh, &dial_in.machines, selector) {
                Ok(SavedMachineRef::Ssh(profile)) => (vec![profile], Vec::new()),
                Ok(SavedMachineRef::DialIn(machine)) => (Vec::new(), vec![machine]),
                Err(error) => {
                    eprintln!("{error}");
                    return Ok(2);
                }
            }
        }
        None => (
            catalog.ssh.iter().collect(),
            dial_in.machines.iter().collect(),
        ),
    };
    let mut rows = profiles
        .into_iter()
        .map(|profile| {
            let (status, error) = if !profile.enabled {
                ("disabled", None)
            } else {
                match crate::remote::check_saved_ssh(&profile.target, &profile.session) {
                    Ok(()) => ("reachable", None),
                    Err(error) => {
                        let message = error.to_string();
                        let status = if crate::remote::ssh_error_requires_authentication(&message) {
                            "auth required"
                        } else {
                            "error"
                        };
                        (status, Some(message))
                    }
                }
            };
            MachineStatusRow::ssh(profile, status, error)
        })
        .collect::<Vec<_>>();
    rows.extend(machines.into_iter().map(dial_in::status_row));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
    } else {
        for row in &rows {
            println!("{}\t{}\t{}", row.id, row.label, row.status);
            if row.kind == DIAL_IN_KIND {
                for line in row.dial_in_details() {
                    println!("  {line}");
                }
            } else if let Some(error) = &row.error {
                println!("  {}", error.escape_debug());
            }
        }
        if rows.is_empty() {
            println!("No saved SSH machines.");
        }
    }
    Ok(status_exit_code(
        selector.is_some(),
        dial_in_failed,
        rows.iter().any(|row| row.error.is_some()),
    ))
}

/// 1 when a reported machine has an error. A broken dial-in catalog counts
/// only for the whole-list status: a selector that resolved (necessarily to
/// an SSH machine then) keeps the SSH-only result.
fn status_exit_code(selector_given: bool, dial_in_failed: bool, any_row_error: bool) -> i32 {
    i32::from(any_row_error || (dial_in_failed && !selector_given))
}

/// How long `reconnect` waits for a dial-in machine without `--wait`.
const DIAL_IN_RECONNECT_WAIT: u64 = 30;

fn reconnect(args: &[String]) -> std::io::Result<i32> {
    use std::io::IsTerminal;
    const USAGE: &str = "usage: herdr machine reconnect <label-or-id> [--wait <seconds>]";
    let args = super::expand_equals_args(args, &["--wait"]);
    let (selector, wait) = match args.as_slice() {
        [selector] if !selector.starts_with('-') => (selector, None),
        [selector, flag, seconds] | [flag, seconds, selector] if flag == "--wait" => {
            match seconds.parse::<u64>() {
                Ok(seconds) => (selector, Some(seconds)),
                Err(_) => {
                    eprintln!("--wait takes a number of seconds\n{USAGE}");
                    return Ok(2);
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            return Ok(2);
        }
    };
    let catalog = load_catalog()?;
    let (dial_in, _) = dial_in::load_catalog_or_warn();
    let profile =
        match super::target::resolve_saved_machine(&catalog.ssh, &dial_in.machines, selector) {
            Ok(SavedMachineRef::Ssh(_)) if wait.is_some() => {
                eprintln!("error: --wait applies only to dial-in machines");
                return Ok(2);
            }
            Ok(SavedMachineRef::Ssh(profile)) => profile,
            Ok(SavedMachineRef::DialIn(machine)) => {
                let wait = wait.unwrap_or(DIAL_IN_RECONNECT_WAIT);
                return dial_in::reconnect(machine, std::time::Duration::from_secs(wait));
            }
            Err(error) => {
                eprintln!("{error}");
                return Ok(2);
            }
        };
    if !std::io::stdin().is_terminal() {
        eprintln!("reconnect requires an interactive terminal; use herdr machine status for noninteractive checks");
        return Ok(2);
    }
    let mut authentication = crate::remote::ssh_authentication_command(&profile.target)?;
    if !authentication.command.status()?.success() {
        eprintln!("SSH authentication failed; the saved machine was not changed.");
        return Ok(1);
    }
    crate::remote::check_saved_ssh(&profile.target, &profile.session)?;
    println!(
        "Machine {} is reachable. Open Herdr clients retry within 30 seconds.",
        profile.id
    );
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
struct AddArgs {
    target: String,
    label: Option<String>,
    session: Option<String>,
}

fn parse_add_args(args: &[String]) -> Result<AddArgs, String> {
    let args = super::expand_equals_args(args, &["--label", "--remote-session"]);
    let mut target = None;
    let mut label = None;
    let mut session = None;
    let mut index = 0;
    while index < args.len() {
        let (name, value) = match args[index].as_str() {
            "--label" | "--remote-session" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(format!("missing value for {}", args[index]));
                };
                index += 2;
                (args[index - 2].as_str(), value.clone())
            }
            positional if !positional.starts_with('-') && target.is_none() => {
                target = Some(positional.to_owned());
                index += 1;
                continue;
            }
            unknown => {
                return Err(format!("unknown machine add option: {unknown}"));
            }
        };
        match name {
            "--label" if label.is_none() => label = Some(value),
            "--remote-session" if session.is_none() => session = Some(value),
            "--remote-session" => {
                return Err("--remote-session can only be specified once".into());
            }
            "--label" => {
                return Err("--label can only be specified once".into());
            }
            _ => unreachable!("validated machine add option"),
        }
    }
    let target = target.ok_or_else(|| {
        "usage: herdr machine add <ssh-target> [--label <label>] [--remote-session <name>]"
            .to_owned()
    })?;
    Ok(AddArgs {
        target,
        label,
        session,
    })
}

/// Names the machine after the SSH host, plus the session when it is not the default.
fn default_label(target: &str, session: &str) -> String {
    let url = target
        .strip_prefix("ssh://")
        .map(|authority| authority.trim_end_matches('/'));
    let authority = url.unwrap_or(target);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match (url, host.strip_prefix('[')) {
        (Some(_), Some(bracketed)) => bracketed.split_once(']').map_or(host, |(ip, _)| ip),
        (Some(_), None) => host.split_once(':').map_or(host, |(host, _)| host),
        (None, _) => host,
    };
    if session == crate::session::DEFAULT_SESSION_NAME {
        host.to_owned()
    } else {
        format!("{host}/{session}")
    }
}

fn check_default_label(catalog: &EndpointCatalog, label: &str) -> Result<(), String> {
    if label.len() > MAX_LABEL_BYTES {
        return Err(format!(
            "default machine name '{label}' is longer than {MAX_LABEL_BYTES} bytes; pass --label to choose a name"
        ));
    }
    if catalog.ssh.iter().any(|profile| profile.label == label)
        || dial_in::check_label_free_in_dial_in(&catalog.dial_in, label).is_err()
    {
        return Err(format!(
            "a machine named '{label}' already exists; pass --label to choose another name"
        ));
    }
    Ok(())
}

/// Default labels must be unique; explicit labels may repeat among SSH
/// machines (as before dial-in machines existed) but never a dial-in label.
fn check_add_label(
    catalog: &EndpointCatalog,
    label: &str,
    label_is_default: bool,
) -> Result<(), String> {
    if label_is_default {
        check_default_label(catalog, label)
    } else {
        dial_in::check_label_free_in_dial_in(&catalog.dial_in, label)
    }
}

fn add(args: &[String]) -> std::io::Result<i32> {
    if args.iter().any(|arg| arg == "--dial-in") {
        return dial_in::add(args);
    }
    let AddArgs {
        target,
        label,
        session,
    } = match parse_add_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let mut setup = None;
    let session =
        if session.is_none() && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            let discovered = (|| {
                let connection = crate::remote::SavedSshSetup::connect(&target)?;
                let sessions = connection.running_sessions()?;
                let session = select_remote_session(&sessions, &target)?;
                setup = Some(connection);
                Ok::<_, std::io::Error>(session)
            })();
            match discovered {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("error: {error}; machine was not saved");
                    crate::remote::print_saved_ssh_error_hint(&error, &target);
                    return Ok(1);
                }
            }
        } else {
            session.unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned())
        };
    let label_is_default = label.is_none();
    let label = label.unwrap_or_else(|| default_label(&target, &session));
    let mut catalog = load_catalog()?;
    if let Err(error) = check_add_label(&catalog, &label, label_is_default) {
        eprintln!("error: {error}");
        return Ok(2);
    }
    match catalog.add_ssh(label.clone(), &target, session.clone()) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    let metadata = match setup
        .map(Ok)
        .unwrap_or_else(|| crate::remote::SavedSshSetup::connect(&target))
        .and_then(|setup| setup.prepare(&session))
    {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("error: {error}; machine was not saved");
            crate::remote::print_saved_ssh_error_hint(&error, &target);
            return Ok(1);
        }
    };
    // Setup can wait for human approval. Do not overwrite catalog edits made meanwhile.
    let mut catalog = load_catalog().map_err(|error| {
        std::io::Error::other(format!(
            "remote prepared, but machine was not saved: {error}"
        ))
    })?;
    if let Err(error) = check_add_label(&catalog, &label, label_is_default) {
        eprintln!("error: {error}; machine was not saved");
        return Ok(2);
    }
    let id = match catalog.add_ssh(label, &target, &session) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    store_catalog(&catalog).map_err(|error| {
        std::io::Error::other(format!(
            "remote prepared, but machine was not saved: {error}"
        ))
    })?;
    if let Some(metadata) = metadata {
        crate::client::endpoint::SshMetadataCache::new(id.as_str(), &target, &session)?
            .store(&metadata);
    }
    println!("Saved SSH machine {id}. Remote server is ready.");
    println!("Open Herdr clients connect automatically.");
    Ok(0)
}

fn select_remote_session(sessions: &[String], target: &str) -> std::io::Result<String> {
    match sessions {
        [] => return Ok(crate::session::DEFAULT_SESSION_NAME.to_owned()),
        [session] => return Ok(session.clone()),
        _ => {}
    }

    let _raw_mode = RawModeGuard::enable()?;
    let mut output = std::io::stderr();
    let mut selected = 0;
    render_remote_session_picker(&mut output, target, sessions, selected, false)?;
    loop {
        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        match key.code {
            KeyCode::Up => selected = selected.checked_sub(1).unwrap_or(sessions.len() - 1),
            KeyCode::Down => selected = (selected + 1) % sessions.len(),
            KeyCode::Enter => return Ok(sessions[selected].clone()),
            KeyCode::Esc => break,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
            _ => continue,
        }
        render_remote_session_picker(&mut output, target, sessions, selected, true)?;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "remote session selection cancelled",
    ))
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn render_remote_session_picker(
    output: &mut impl std::io::Write,
    target: &str,
    sessions: &[String],
    selected: usize,
    redraw: bool,
) -> std::io::Result<()> {
    if redraw {
        execute!(output, cursor::MoveUp((sessions.len() + 2) as u16))?;
    }
    execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
    write!(output, "Running sessions on {target}:\r\n")?;
    for (index, session) in sessions.iter().enumerate() {
        execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
        if index == selected {
            execute!(output, SetAttribute(Attribute::Bold))?;
            write!(output, "> {session}")?;
            execute!(output, SetAttribute(Attribute::Reset))?;
            write!(output, "\r\n")?;
        } else {
            write!(output, "  {session}\r\n")?;
        }
    }
    execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
    write!(output, "↑/↓ select · Enter confirm · Esc cancel\r\n")?;
    output.flush()
}

fn rename(args: &[String]) -> std::io::Result<i32> {
    let args = super::expand_equals_args(args, &["--label"]);
    let [raw_id, flag, label] = args.as_slice() else {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    };
    if flag != "--label" {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    }
    let id = match ProfileId::parse(raw_id.clone()) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let mut catalog = load_catalog()?;
    if catalog.ssh.iter().any(|profile| profile.id == id) {
        // Labels stay unique across SSH and dial-in machines so each resolves.
        if let Err(error) = dial_in::check_label_free_in_dial_in(&catalog.dial_in, label) {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    match catalog.rename_ssh(&id, label) {
        Ok(true) => {}
        Ok(false) => return dial_in::rename(&catalog, &id, label),
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    store_catalog(&catalog)?;
    println!("Renamed SSH machine {id}.");
    Ok(0)
}

fn remove(args: &[String]) -> std::io::Result<i32> {
    const USAGE: &str =
        "usage: herdr machine remove <profile-id> [--revoke [--authorized-keys <path>]]";
    let (args, revoke) = match dial_in::split_revoke_args(args) {
        Ok(split) => split,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return Ok(2);
        }
    };
    let Some(id) = one_profile_id(&args, USAGE)? else {
        return Ok(2);
    };
    let mut catalog = load_catalog()?;
    if revoke.is_some() && catalog.ssh.iter().any(|profile| profile.id == id) {
        eprintln!("error: --revoke applies only to dial-in machines");
        return Ok(2);
    }
    let previous_selection = catalog.selected_profile.clone();
    let metadata_cache = catalog
        .ssh
        .iter()
        .find(|profile| profile.id == id)
        .map(|profile| {
            crate::client::endpoint::SshMetadataCache::new(
                id.as_str(),
                &profile.target,
                &profile.session,
            )
        })
        .transpose()?;
    if !catalog.remove_ssh(&id) {
        return dial_in::remove(&catalog, previous_selection.as_ref(), &id, revoke.as_ref());
    }
    store_catalog(&catalog)?;
    if let Some(cache) = metadata_cache {
        cache.invalidate();
    }
    if catalog.selected_profile != previous_selection {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    println!("Removed SSH machine {id}.");
    Ok(0)
}

fn set_enabled(args: &[String], enabled: bool) -> std::io::Result<i32> {
    let action = if enabled { "enable" } else { "disable" };
    let usage = format!("usage: herdr machine {action} <profile-id>");
    let Some(id) = one_profile_id(args, &usage)? else {
        return Ok(2);
    };
    let mut catalog = load_catalog()?;
    let previous_selection = catalog.selected_profile.clone();
    if !catalog.set_enabled(&id, enabled) {
        return dial_in::set_enabled(&mut catalog, &id, enabled);
    }
    store_catalog(&catalog)?;
    if catalog.selected_profile != previous_selection {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    println!(
        "{} SSH machine {id}.",
        if enabled { "Enabled" } else { "Disabled" }
    );
    Ok(0)
}

fn one_profile_id(args: &[String], usage: &str) -> std::io::Result<Option<ProfileId>> {
    let [raw] = args else {
        eprintln!("{usage}");
        return Ok(None);
    };
    match ProfileId::parse(raw.clone()) {
        Ok(id) => Ok(Some(id)),
        Err(error) => {
            eprintln!("error: {error}");
            Ok(None)
        }
    }
}

fn load_catalog() -> std::io::Result<EndpointCatalog> {
    EndpointCatalog::load().map_err(std::io::Error::other)
}

fn store_catalog(catalog: &EndpointCatalog) -> std::io::Result<()> {
    catalog.store_profiles().map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parser_preserves_values_across_argument_orders() {
        for (args, session) in [
            (vec!["--label", "coder", "workstation.coder"], None),
            (vec!["workstation.coder", "--label", "coder"], None),
            (
                vec![
                    "--remote-session",
                    "agents",
                    "workstation.coder",
                    "--label",
                    "coder",
                ],
                Some("agents"),
            ),
            (
                vec![
                    "--label=coder",
                    "--remote-session=agents",
                    "workstation.coder",
                ],
                Some("agents"),
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                parse_add_args(&args).unwrap(),
                AddArgs {
                    target: "workstation.coder".into(),
                    label: Some("coder".into()),
                    session: session.map(str::to_owned),
                },
                "{args:?}"
            );
        }
    }

    #[test]
    fn add_parser_leaves_label_unset_without_flag() {
        let parsed = parse_add_args(&["workstation.coder".to_owned()]).unwrap();
        assert_eq!(parsed.label, None);
        assert_eq!(parsed.session, None);
    }

    #[test]
    fn default_label_uses_ssh_host_and_non_default_session() {
        for (target, session, label) in [
            ("workbox", "default", "workbox"),
            ("dev@workbox", "default", "workbox"),
            ("workbox", "agents", "workbox/agents"),
            ("ssh://workbox", "default", "workbox"),
            ("ssh://dev@workbox:2222", "default", "workbox"),
            ("ssh://dev@[::1]:2222", "agents", "::1/agents"),
            ("ssh://dev@workbox/", "default", "workbox"),
            ("ssh://dev@workbox:2222/", "agents", "workbox/agents"),
        ] {
            assert_eq!(default_label(target, session), label, "{target} {session}");
        }
    }

    #[test]
    fn default_label_must_be_unique_and_fit() {
        let mut catalog = EndpointCatalog::default();
        catalog.add_ssh("workbox", "workbox", "default").unwrap();

        assert!(check_default_label(&catalog, "workbox/agents").is_ok());
        let duplicate = check_default_label(&catalog, "workbox").unwrap_err();
        assert!(duplicate.contains("--label"), "{duplicate}");
        let long = check_default_label(&catalog, &"h".repeat(MAX_LABEL_BYTES + 1)).unwrap_err();
        assert!(long.contains("--label"), "{long}");
    }

    #[test]
    fn ssh_labels_never_repeat_a_dial_in_label() {
        let mut catalog = EndpointCatalog::default();
        catalog.add_ssh("workbox", "workbox", "default").unwrap();
        catalog.dial_in =
            vec![crate::client::endpoint::DialInMachine::new("build", "default").unwrap()];

        let taken = check_default_label(&catalog, "build").unwrap_err();
        assert!(taken.contains("--label"), "{taken}");
        let explicit = check_add_label(&catalog, " build ", false).unwrap_err();
        assert!(
            explicit.contains("dial-in machine named 'build'"),
            "{explicit}"
        );
        // Explicit SSH duplicates keep their upstream behavior.
        assert!(check_add_label(&catalog, "workbox", false).is_ok());
        assert!(check_add_label(&catalog, "workbox", true).is_err());
        assert!(check_add_label(&catalog, "desk", true).is_ok());
    }

    #[test]
    fn add_parser_rejects_incomplete_duplicate_and_extra_arguments() {
        for args in [
            vec![],
            vec!["--label", "coder"],
            vec!["workstation.coder", "--label"],
            vec!["workstation.coder", "--label", "coder", "--remote-session"],
            vec!["--label", "coder", "--label", "other", "workstation.coder"],
            vec![
                "workstation.coder",
                "--label",
                "coder",
                "--remote-session",
                "a",
                "--remote-session",
                "b",
            ],
            vec!["--label", "coder", "workstation.coder", "other-host"],
            vec!["--unknown", "workstation.coder", "--label", "coder"],
            vec!["--label", "--remote-session", "agents", "workstation.coder"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(parse_add_args(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn profile_id_parser_rejects_target_text() {
        assert!(one_profile_id(&["build.example".into()], "usage")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_broken_dial_in_catalog_fails_only_the_whole_list_status() {
        assert_eq!(status_exit_code(false, false, false), 0);
        assert_eq!(status_exit_code(false, true, false), 1);
        assert_eq!(status_exit_code(true, true, false), 0);
        assert_eq!(status_exit_code(true, true, true), 1);
        assert_eq!(status_exit_code(true, false, true), 1);
    }

    #[test]
    fn ssh_status_rows_only_gain_a_kind_field() {
        let profile = SavedSshEndpoint::new("Build", "build", "default").unwrap();
        let value = serde_json::to_value(MachineStatusRow::ssh(
            &profile,
            "error",
            Some("boom".into()),
        ))
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "id": profile.id.as_str(),
                "label": "Build",
                "status": "error",
                "error": "boom",
                "kind": "ssh"
            })
        );
    }

    #[test]
    fn list_rows_do_not_have_credential_fields() {
        let encoded = serde_json::to_string(&MachineListRow {
            id: "0123456789abcdef0123456789abcdef",
            label: "Build",
            target: "dev@build",
            session: "agents",
            enabled: true,
            selected: false,
        })
        .unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("key"));
    }
}
