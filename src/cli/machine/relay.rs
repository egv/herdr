//! `herdr machine relay ...`: relay hubs, machines reached over SSH whose own
//! dial-in machines this client reaches through them as `<relay>/<machine>`
//! (`herdr link-connect` on the hub), plus the via-machine parts of `machine
//! list`, `--machine`, and the management commands forwarded to the hub.

use std::io::{self, IsTerminal as _};

use serde::Serialize;

use crate::client::endpoint::{
    DialInCatalog, EndpointCatalog, ListedVia, ProfileId, RelayCatalog, RelayHub,
};

const VIA_KIND: &str = "via";

const RELAY_HELP: &str = "Usage:
  herdr machine relay add <ssh-target> [--label <label>]
  herdr machine relay list [--json]
  herdr machine relay remove <relay>
  herdr machine relay rename <relay> --label <label>
  herdr machine relay enable <relay>
  herdr machine relay disable <relay>

A relay hub is a machine you reach over SSH that has dial-in machines of its own
(`herdr machine add --dial-in` there). Herdr here reaches them through the hub as
<relay>/<machine>, with `herdr --machine <relay>/<machine> ...` and in the sidebar.
`herdr machine status|reconnect|update|agent-forwarding|rename|enable|disable|remove|authorize`
on such a machine runs on the hub over your SSH. Agent forwarding through the
relay needs `ForwardAgent yes` for the hub in your SSH config.";

/// Management commands that run on the relay hub for a via machine.
pub(super) const FORWARDED_VERBS: &[&str] = &[
    "status",
    "reconnect",
    "update",
    "agent-forwarding",
    "rename",
    "enable",
    "disable",
    "remove",
    "authorize",
];

/// Options of forwarded commands that take a value, which is never the machine.
const VALUE_OPTIONS: &[&str] = &["--label", "--herdr-path", "--wait", "--authorized-keys"];

pub(super) fn run_relay_command(args: &[String]) -> io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("add") => add(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("remove") => remove(&args[1..]),
        Some("rename") => rename(&args[1..]),
        Some("enable") => set_enabled(&args[1..], true),
        Some("disable") => set_enabled(&args[1..], false),
        Some("help" | "--help" | "-h") => {
            println!("{RELAY_HELP}");
            Ok(0)
        }
        _ => {
            eprintln!("{RELAY_HELP}");
            Ok(2)
        }
    }
}

fn parse_add_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let usage = "usage: herdr machine relay add <ssh-target> [--label <label>]";
    let args = super::super::expand_equals_args(args, &["--label"]);
    let (mut target, mut label) = (None, None);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--label" {
            let value = args.next().ok_or("missing value for --label")?;
            if label.replace(value).is_some() {
                return Err("--label can only be specified once".into());
            }
        } else if arg.starts_with('-') || target.is_some() {
            return Err(usage.into());
        } else {
            target = Some(arg);
        }
    }
    Ok((target.ok_or(usage)?, label))
}

/// Checks that the hub has a Herdr that lists its dial-in machines over
/// the same noninteractive SSH open clients use, then saves it.
fn add(args: &[String]) -> io::Result<i32> {
    let (target, label) = match parse_add_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let label = label
        .unwrap_or_else(|| super::default_label(&target, crate::session::DEFAULT_SESSION_NAME));
    let taken = EndpointCatalog::load_profiles()
        .map_err(io::Error::other)?
        .into_iter()
        .map(|profile| profile.id)
        .collect::<Vec<_>>();
    let mut catalog = load_relays()?;
    let id = match catalog.add(&label, &target, &taken) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let listing = match crate::remote::list_relay(id.as_str(), &target) {
        Ok(listing) => listing,
        Err(error) => {
            crate::remote::invalidate_relay_herdr(id.as_str(), &target);
            eprintln!("error: {error}; relay hub was not saved");
            crate::remote::print_saved_ssh_error_hint(&error, &target);
            eprintln!(
                "hint: the hub needs a Herdr with dial-in support that noninteractive SSH finds; set it up with `herdr --remote {target}` or `herdr machine add {target}`, then retry."
            );
            return Ok(1);
        }
    };
    catalog.store().map_err(io::Error::other)?;
    let via = catalog
        .find(id.as_str())
        .map(|relay| listing.via_machines(relay))
        .unwrap_or_default();
    println!(
        "Saved relay hub {id} ('{}'). It exposes {} dial-in machine{}:",
        label.trim(),
        via.len(),
        if via.len() == 1 { "" } else { "s" }
    );
    for item in &via {
        println!("  {} ({})", item.machine.display_label(), state_word(item));
    }
    println!("Open Herdr clients connect to them automatically.");
    Ok(0)
}

#[derive(Serialize)]
struct RelayListRow<'a> {
    id: &'a str,
    label: &'a str,
    target: &'a str,
    enabled: bool,
}

fn list(args: &[String]) -> io::Result<i32> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => {
            eprintln!("usage: herdr machine relay list [--json]");
            return Ok(2);
        }
    };
    let catalog = load_relays()?;
    let rows = catalog
        .relays
        .iter()
        .map(|relay| RelayListRow {
            id: relay.id.as_str(),
            label: &relay.label,
            target: &relay.target,
            enabled: relay.enabled,
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(io::Error::other)?
        );
        return Ok(0);
    }
    if rows.is_empty() {
        println!("No relay hubs.");
    }
    for row in &rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        println!("{}\t{}\t{}\t{state}", row.id, row.label, row.target);
    }
    Ok(0)
}

/// Resolves `<relay>` (id or label) in the relay catalog.
fn with_relay(
    selector: &str,
    change: impl FnOnce(&mut RelayCatalog, &RelayHub) -> Result<String, String>,
) -> io::Result<i32> {
    let mut catalog = load_relays()?;
    let relay = match catalog.find(selector) {
        Ok(relay) => relay.clone(),
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    match change(&mut catalog, &relay) {
        Ok(message) => {
            catalog.store().map_err(io::Error::other)?;
            println!("{message}");
            Ok(0)
        }
        Err(error) => {
            eprintln!("error: {error}");
            Ok(2)
        }
    }
}

fn remove(args: &[String]) -> io::Result<i32> {
    let [selector] = args else {
        eprintln!("usage: herdr machine relay remove <relay>");
        return Ok(2);
    };
    with_relay(selector, |catalog, relay| {
        catalog.remove(&relay.id);
        crate::remote::invalidate_relay_herdr(relay.id.as_str(), &relay.target);
        Ok(format!(
            "Removed relay hub {}. Its dial-in machines stay connected to that hub.",
            relay.id
        ))
    })
}

fn rename(args: &[String]) -> io::Result<i32> {
    let args = super::super::expand_equals_args(args, &["--label"]);
    let [selector, flag, label] = args.as_slice() else {
        eprintln!("usage: herdr machine relay rename <relay> --label <label>");
        return Ok(2);
    };
    if flag != "--label" {
        eprintln!("usage: herdr machine relay rename <relay> --label <label>");
        return Ok(2);
    }
    with_relay(selector, |catalog, relay| {
        catalog.rename(&relay.id, label)?;
        Ok(format!("Renamed relay hub {}.", relay.id))
    })
}

fn set_enabled(args: &[String], enabled: bool) -> io::Result<i32> {
    let [selector] = args else {
        let action = if enabled { "enable" } else { "disable" };
        eprintln!("usage: herdr machine relay {action} <relay>");
        return Ok(2);
    };
    with_relay(selector, |catalog, relay| {
        catalog.set_enabled(&relay.id, enabled);
        Ok(format!(
            "{} relay hub {}.",
            if enabled { "Enabled" } else { "Disabled" },
            relay.id
        ))
    })
}

fn load_relays() -> io::Result<RelayCatalog> {
    RelayCatalog::load().map_err(io::Error::other)
}

fn connection_word(connected: bool) -> &'static str {
    if connected {
        "connected"
    } else {
        "offline"
    }
}

fn state_word(item: &ListedVia) -> &'static str {
    if item.enabled {
        connection_word(item.machine.connected)
    } else {
        "disabled"
    }
}

/// The enabled relay hubs that can list `selector`: the one its
/// `<relay>/` prefix names, or all of them. A broken catalog is a warning.
fn relays_for(selector: &str) -> Vec<RelayHub> {
    let catalog = match RelayCatalog::load() {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("warning: {error}");
            return Vec::new();
        }
    };
    let named = selector.split_once('/').and_then(|(relay, _)| {
        catalog
            .enabled()
            .find(|candidate| candidate.label.trim() == relay.trim())
    });
    match named {
        Some(relay) => vec![relay.clone()],
        None => catalog.enabled().cloned().collect(),
    }
}

/// Lists each relay once; a relay that cannot be listed is a warning.
fn fetch_via(relays: &[RelayHub]) -> Vec<ListedVia> {
    let mut via = Vec::new();
    for relay in relays {
        match crate::remote::list_relay(relay.id.as_str(), &relay.target) {
            Ok(listing) => via.extend(listing.via_machines(relay)),
            Err(error) => eprintln!(
                "warning: relay hub '{}': {}",
                relay.label.trim(),
                crate::remote::relay_unreachable_message(&error.to_string(), &relay.target)
            ),
        }
    }
    via
}

/// A via machine by derived id, by `<relay>/<machine>`, or by a machine
/// label that only one relay hub lists.
fn resolve_via<'a>(via: &'a [ListedVia], selector: &str) -> Result<Option<&'a ListedVia>, String> {
    let selector = selector.trim();
    if let Some(item) = via
        .iter()
        .find(|item| item.machine.id.as_str() == selector)
        .or_else(|| {
            via.iter()
                .find(|item| item.machine.display_label() == selector)
        })
    {
        return Ok(Some(item));
    }
    // `<relay>/<machine>` names a relay: a hub listing a label with `/`
    // never claims another relay's name.
    if selector.contains('/') {
        return Ok(None);
    }
    let mut matches = via
        .iter()
        .filter(|item| item.machine.label.trim() == selector);
    match (matches.next(), matches.next()) {
        (Some(_), Some(_)) => Err(format!(
            "machine '{selector}' is on more than one relay hub; use <relay>/{selector}"
        )),
        (machine, _) => Ok(machine),
    }
}

/// The via machine `selector` names, enabled or not, asking only the relay
/// hubs that can list it; `None` without enabled relays (and then without
/// any SSH).
pub(in crate::cli) fn find_via_machine(selector: &str) -> Result<Option<ListedVia>, String> {
    let relays = relays_for(selector);
    if relays.is_empty() {
        return Ok(None);
    }
    resolve_via(&fetch_via(&relays), selector).map(Option::<&ListedVia>::cloned)
}

#[derive(Serialize)]
pub(super) struct ViaListRow {
    id: String,
    label: String,
    session: String,
    enabled: bool,
    selected: bool,
    connected: bool,
    kind: &'static str,
    relay: String,
    relay_id: String,
    link_id: String,
}

/// `machine list` rows for every enabled relay hub's machines.
pub(super) fn via_list_rows(selected: Option<&ProfileId>) -> Vec<ViaListRow> {
    let relays = match RelayCatalog::load() {
        Ok(catalog) => catalog.enabled().cloned().collect::<Vec<_>>(),
        Err(error) => {
            eprintln!("warning: {error}");
            Vec::new()
        }
    };
    fetch_via(&relays)
        .into_iter()
        .map(|item| ViaListRow {
            id: item.machine.id.to_string(),
            label: item.machine.display_label(),
            session: item.machine.session.clone(),
            enabled: item.enabled,
            selected: selected == Some(&item.machine.id),
            connected: item.machine.connected,
            kind: VIA_KIND,
            relay: item.machine.relay_label.clone(),
            relay_id: item.machine.relay_id.to_string(),
            link_id: item.machine.link_id.to_string(),
        })
        .collect()
}

/// Text rows in the SSH column layout: id, label, link, session, state.
pub(super) fn print_via_rows(rows: &[ViaListRow]) {
    for row in rows {
        println!(
            "{}\t{}\tvia {} ({})\t{}\t{}",
            row.id,
            row.label,
            row.relay,
            connection_word(row.connected),
            row.session,
            if row.enabled { "enabled" } else { "disabled" }
        );
    }
}

/// Index of the machine argument of a forwarded command: its first
/// positional argument.
fn selector_index(args: &[String]) -> Option<usize> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if VALUE_OPTIONS.contains(&arg.as_str()) {
            index += 2;
        } else if arg.starts_with('-') {
            index += 1;
        } else {
            return Some(index);
        }
    }
    None
}

/// POSIX shell single quoting.
fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// `ssh [-t] <relay target> '<herdr>' 'machine' '<verb>' ...`.
fn forwarded_ssh_args(target: &str, tty: bool, herdr: &str, remote_args: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(3);
    if tty {
        argv.push("-t".to_string());
    }
    argv.push(target.to_string());
    argv.push(
        std::iter::once(herdr)
            .chain(remote_args.iter().map(String::as_str))
            .map(sh_quote)
            .collect::<Vec<_>>()
            .join(" "),
    );
    argv
}

/// Runs `herdr machine <verb> ...` on the relay hub when the command's
/// machine is a via machine (and not a saved machine here), over the user's
/// interactive SSH. `None` leaves the command to this machine.
pub(super) fn forward(verb: &str, args: &[String]) -> io::Result<Option<i32>> {
    let Some(index) = selector_index(args) else {
        return Ok(None);
    };
    let selector = &args[index];
    // Only when both catalogs load and neither names the machine: the
    // local command reports a broken catalog instead.
    let (Ok(ssh), Ok(dial_in)) = (EndpointCatalog::load_profiles(), DialInCatalog::load()) else {
        return Ok(None);
    };
    if super::super::target::names_saved_machine(&ssh, &dial_in.machines, selector) {
        return Ok(None);
    }
    // Disabled machines too: `enable` must reach them.
    let machine = match find_via_machine(selector) {
        Ok(Some(listed)) => listed.machine,
        Ok(None) => return Ok(None),
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(Some(2));
        }
    };
    let herdr = match crate::remote::relay_herdr_executable(
        machine.relay_id.as_str(),
        &machine.relay_target,
    ) {
        Ok(herdr) => herdr,
        Err(error) => {
            eprintln!(
                "error: {}",
                crate::remote::relay_unreachable_message(&error.to_string(), &machine.relay_target)
            );
            return Ok(Some(1));
        }
    };
    let mut remote_args = vec!["machine".to_string(), verb.to_string()];
    remote_args.extend(args.iter().enumerate().map(|(position, arg)| {
        if position == index {
            machine.link_id.to_string()
        } else {
            arg.clone()
        }
    }));
    // Stderr keeps forwarded `--json` output parseable.
    eprintln!(
        "running on {}: herdr {}",
        machine.relay_label,
        remote_args.join(" ")
    );
    // A remote terminal merges the hub's stderr into stdout: only for an
    // interactive terminal (prompts), never for redirected output.
    let tty = io::stdin().is_terminal() && io::stdout().is_terminal();
    let status = std::process::Command::new("ssh")
        .args(forwarded_ssh_args(
            &machine.relay_target,
            tty,
            &herdr,
            &remote_args,
        ))
        .status()?;
    Ok(Some(status.code().unwrap_or(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn via(relay: &str, relay_id: &str, label: &str, link: &str) -> ListedVia {
        let relay_id = ProfileId::parse(relay_id).unwrap();
        let link_id = ProfileId::parse(link).unwrap();
        ListedVia {
            machine: crate::client::endpoint::ViaMachine {
                id: crate::client::endpoint::via_id(&relay_id, &link_id),
                relay_id,
                relay_label: relay.into(),
                relay_target: format!("me@{relay}"),
                link_id,
                label: label.into(),
                session: "default".into(),
                connected: true,
            },
            enabled: true,
            link_epoch: 1,
        }
    }

    #[test]
    fn via_names_resolve_by_id_relay_path_or_unique_label() {
        let vps_one = via(
            "vps",
            "11111111111111111111111111111111",
            "slave1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        // Disabled machines resolve too (for `machine enable`).
        let mut vps_two = via(
            "vps",
            "11111111111111111111111111111111",
            "mac",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        vps_two.enabled = false;
        let lab_one = via(
            "lab",
            "22222222222222222222222222222222",
            "slave1",
            "cccccccccccccccccccccccccccccccc",
        );
        let machines = vec![vps_one.clone(), vps_two.clone(), lab_one.clone()];
        assert_eq!(
            resolve_via(&machines, vps_one.machine.id.as_str()).unwrap(),
            Some(&vps_one)
        );
        assert_eq!(
            resolve_via(&machines, "lab/slave1").unwrap(),
            Some(&lab_one)
        );
        assert_eq!(resolve_via(&machines, " vps/mac ").unwrap(), Some(&vps_two));
        assert_eq!(resolve_via(&machines, "mac").unwrap(), Some(&vps_two));
        assert!(resolve_via(&machines, "slave1")
            .unwrap_err()
            .contains("<relay>/slave1"));
        assert_eq!(resolve_via(&machines, "missing").unwrap(), None);
        assert_eq!(resolve_via(&machines, "vps/missing").unwrap(), None);
        // The hub's own link id is not this client's id for the machine.
        assert_eq!(
            resolve_via(&machines, vps_one.machine.link_id.as_str()).unwrap(),
            None
        );
        assert_eq!(resolve_via(&[], "slave1").unwrap(), None);

        // A label with `/` never claims another relay's `<relay>/<machine>`
        // name (asked of every relay when that relay is disabled).
        let claiming = via(
            "vps",
            "11111111111111111111111111111111",
            "lab/prod",
            "dddddddddddddddddddddddddddddddd",
        );
        let machines = vec![claiming.clone()];
        assert_eq!(resolve_via(&machines, "lab/prod").unwrap(), None);
        assert_eq!(
            resolve_via(&machines, "vps/lab/prod").unwrap(),
            Some(&claiming)
        );
    }

    #[test]
    fn forwarded_commands_replace_only_the_machine_and_quote_every_argument() {
        for (args, index) in [
            (&["vps/slave1"][..], Some(0)),
            (&["--json", "vps/slave1"], Some(1)),
            (&["vps/slave1", "--label", "new name"], Some(0)),
            (&["--label", "x", "vps/slave1"], Some(2)),
            (&["--wait", "10", "vps/slave1"], Some(2)),
            (
                &[
                    "--herdr-path",
                    "/bin/herdr",
                    "vps/slave1",
                    "ssh-ed25519 AAAA c",
                ],
                Some(2),
            ),
            (&["--json"], None),
            (&[], None),
        ] {
            assert_eq!(selector_index(&strings(args)), index, "{args:?}");
        }
        let remote_args = strings(&[
            "machine",
            "rename",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--label",
            "it's mine",
        ]);
        assert_eq!(
            forwarded_ssh_args("me@vps", true, "/home/me/.local/bin/herdr", &remote_args),
            strings(&[
                "-t",
                "me@vps",
                r"'/home/me/.local/bin/herdr' 'machine' 'rename' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' '--label' 'it'\''s mine'",
            ])
        );
        assert_eq!(
            forwarded_ssh_args(
                "vps",
                false,
                "/opt/herdr",
                &strings(&["machine", "status", "$(id)"])
            ),
            strings(&["vps", "'/opt/herdr' 'machine' 'status' '$(id)'"])
        );
    }

    #[test]
    fn relay_add_takes_one_target_and_an_optional_label() {
        assert_eq!(
            parse_add_args(&strings(&["me@vps", "--label=hub"])).unwrap(),
            ("me@vps".to_string(), Some("hub".to_string()))
        );
        assert_eq!(
            parse_add_args(&strings(&["--label", "hub", "me@vps"])).unwrap(),
            ("me@vps".to_string(), Some("hub".to_string()))
        );
        assert_eq!(
            parse_add_args(&strings(&["vps"])).unwrap(),
            ("vps".to_string(), None)
        );
        for invalid in [
            &[][..],
            &["--label", "hub"],
            &["vps", "other"],
            &["vps", "--label"],
            &["vps", "--label", "a", "--label", "b"],
            &["vps", "--unknown"],
        ] {
            assert!(parse_add_args(&strings(invalid)).is_err(), "{invalid:?}");
        }
    }
}
