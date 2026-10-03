//! `herdr machine update <label-or-id> [--yes] [--restart-server]`: installs
//! this hub's Herdr version on a connected dial-in machine over its link.

use std::io::{self, IsTerminal as _, Write as _};
use std::time::{Duration, Instant};

use super::super::target::{await_stream_error, find_saved_machine, SavedMachineRef};
use crate::client::endpoint::{DialInCatalog, DialInMachine, EndpointCatalog};
use crate::remote::link::accept::update as link_update;
use crate::remote::link::protocol::feature;
use crate::remote::link::status::{self, LinkStatus, SlaveInfo, MAX_REMOTE_TEXT_BYTES};
use crate::remote::{InstallSource, LinkPaths};

const USAGE: &str = "usage: herdr machine update <label-or-id> [--yes] [--restart-server]";
/// How long the machine may take to come back after installing the update.
const RECONNECT_WAIT: Duration = Duration::from_secs(60);
const RECONNECT_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, PartialEq, Eq)]
struct UpdateArgs {
    selector: String,
    yes: bool,
    restart_server: bool,
}

fn parse_update_args(args: &[String]) -> Result<UpdateArgs, String> {
    let mut selector = None;
    let mut yes = false;
    let mut restart_server = false;
    for arg in args {
        match arg.as_str() {
            "--yes" if !yes => yes = true,
            "--restart-server" if !restart_server => restart_server = true,
            value if !value.starts_with('-') && selector.is_none() => {
                selector = Some(value.to_owned());
            }
            _ => return Err(USAGE.into()),
        }
    }
    Ok(UpdateArgs {
        selector: selector.ok_or(USAGE)?,
        yes,
        restart_server,
    })
}

pub(super) fn update(args: &[String]) -> io::Result<i32> {
    let parsed = match parse_update_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    if !parsed.yes && !io::stdin().is_terminal() {
        eprintln!("error: machine update asks for confirmation; pass --yes without an interactive terminal");
        return Ok(2);
    }
    let ssh = EndpointCatalog::load_profiles().map_err(io::Error::other)?;
    let dial_in = DialInCatalog::load().map_err(io::Error::other)?;
    let machine = match find_saved_machine(&ssh, &dial_in.machines, &parsed.selector) {
        Ok(SavedMachineRef::DialIn(machine)) => machine,
        Ok(SavedMachineRef::Ssh(profile)) => {
            eprintln!(
                "error: machine '{}' is an SSH machine; Herdr installs its version there when it connects, so update applies only to dial-in machines",
                profile.label
            );
            return Ok(2);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let paths = machine.paths();
    let Some(link) = live_status(&paths) else {
        eprintln!(
            "error: dial-in machine '{}' is not connected; it must be dialed in to be updated",
            machine.label
        );
        return Ok(1);
    };
    let slave = link.slave.clone().unwrap_or_default();
    let from = slave.herdr_version.as_deref().unwrap_or("unknown");
    if !slave.features.iter().any(|name| name == feature::UPDATE) {
        match stale_link_hint(machine, &slave) {
            Some(hint) => eprintln!("error: {hint}"),
            None => eprintln!(
                "error: dial-in machine '{}' runs herdr {from}, which the hub cannot update; update Herdr on that machine once, and later updates can come from the hub",
                machine.label
            ),
        }
        return Ok(1);
    }
    let (Some(os), Some(arch)) = (slave.os.as_deref(), slave.arch.as_deref()) else {
        eprintln!(
            "error: dial-in machine '{}' did not report its platform",
            machine.label
        );
        return Ok(1);
    };
    let to = crate::build_info::version();
    let (source, origin) = match crate::remote::resolve_dial_in_update_source(os, arch) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("error: cannot get herdr {to} for {os}/{arch}: {error}");
            return Ok(1);
        }
    };
    let question = format!(
        "Update dial-in machine '{}' from herdr {from} to herdr {to}, sending {origin}?",
        machine.label
    );
    let confirmed = confirm(&question, parsed.yes).inspect_err(|_| source.cleanup())?;
    if !confirmed {
        source.cleanup();
        eprintln!("Update cancelled.");
        return Ok(1);
    }
    if parsed.yes {
        eprintln!("Sending {origin}.");
    }
    let result = send(machine, &paths, &source, &to);
    source.cleanup();
    let Some(installed) = result? else {
        return Ok(1);
    };
    if !wait_for_reconnect(&paths, link.link_epoch, &installed) {
        eprintln!(
            "error: dial-in machine '{}' did not reconnect with herdr {installed} within {}s; on that machine, check `herdr machine dial status`. If the new version runs but cannot connect, the machine restores the previous executable within 5 minutes; if its dialer does not start at all, restore `<herdr path>.prev` there",
            machine.label,
            RECONNECT_WAIT.as_secs()
        );
        return Ok(1);
    }
    println!(
        "Dial-in machine '{}' reconnected with herdr {installed}.",
        machine.label
    );
    if parsed.restart_server {
        return restart_server(machine, &paths, parsed.yes);
    }
    println!(
        "Its running Herdr server (session {}) keeps running the previous version until it restarts; restarting stops its panes. Pass --restart-server next time, or run `herdr server stop` on that machine.",
        machine.session
    );
    Ok(0)
}

/// Checksums the executable and sends it. Returns the version the machine
/// installed, or `None` (reported) when it did not install it.
fn send(
    machine: &DialInMachine,
    paths: &LinkPaths,
    source: &InstallSource,
    to: &str,
) -> io::Result<Option<String>> {
    let path = &source.path;
    let sha256 = crate::checksum::file_sha256(path)?;
    if source
        .expected_sha256
        .as_deref()
        .is_some_and(|expected| !expected.trim().eq_ignore_ascii_case(&sha256))
    {
        eprintln!(
            "error: the herdr {to} executable does not match its published SHA-256; nothing was sent"
        );
        return Ok(None);
    }
    let size = std::fs::metadata(path)?.len();
    // The link socket may close under us; report EPIPE instead of dying.
    crate::platform::end_cli_output();
    let started_ms = status::now_ms();
    let sent = std::fs::File::open(path).and_then(|mut executable| {
        link_update::send_update(paths, &mut executable, size, &sha256, Some(to))
    });
    let result = match sent {
        Ok(result) => result,
        Err(error) => {
            let mut message = format!("error: the update did not complete: {error}");
            if let Some(reported) = await_stream_error(paths, started_ms) {
                message.push_str("; the machine reported: ");
                message.push_str(&reported);
            }
            eprintln!("{message}");
            return Ok(None);
        }
    };
    if !result.ok {
        eprintln!(
            "error: dial-in machine '{}' did not install the update: {} ({})",
            machine.label,
            remote_text(result.message.as_deref().unwrap_or("no reason given")),
            remote_text(result.code.as_deref().unwrap_or("error"))
        );
        return Ok(None);
    }
    let installed = remote_text(result.version.as_deref().unwrap_or(to));
    println!(
        "Installed herdr {installed} on dial-in machine '{}'; its link restarts.",
        machine.label
    );
    Ok(Some(installed))
}

fn restart_server(machine: &DialInMachine, paths: &LinkPaths, yes: bool) -> io::Result<i32> {
    eprintln!(
        "Restarting the Herdr server of session {} on '{}' stops every pane and agent running in it.",
        machine.session, machine.label
    );
    if !confirm("Restart it now?", yes)? {
        println!("The server was not restarted.");
        return Ok(0);
    }
    match link_update::restart_server(paths, &machine.session) {
        Ok(response) if response.ok => {
            println!(
                "Restarted the Herdr server of session {} on '{}'.",
                machine.session, machine.label
            );
            Ok(0)
        }
        Ok(response) => {
            eprintln!(
                "error: the server was not restarted: {}",
                remote_text(response.message.as_deref().unwrap_or("no reason given"))
            );
            Ok(1)
        }
        Err(error) => {
            eprintln!("error: restarting the server failed: {error}");
            Ok(1)
        }
    }
}

fn remote_text(text: &str) -> String {
    status::sanitize_remote_text(text, MAX_REMOTE_TEXT_BYTES)
}

/// A machine that reports none of the link features although it runs this
/// hub's own version: the link holder on this hub started before Herdr here
/// was upgraded, and does not record them. How to make it reconnect.
pub(super) fn stale_link_hint(machine: &DialInMachine, slave: &SlaveInfo) -> Option<String> {
    (slave.features.is_empty()
        && slave.herdr_version.as_deref() == Some(crate::build_info::version().as_str()))
    .then(|| {
        format!(
            "the link of dial-in machine '{}' started before Herdr on this hub was upgraded; make it reconnect with `herdr machine disable {id}` and `herdr machine enable {id}` (it redials within 5 minutes)",
            machine.label,
            id = machine.id
        )
    })
}

/// `yes`, or the terminal's answer (default No).
fn confirm(question: &str, yes: bool) -> io::Result<bool> {
    if yes {
        return Ok(true);
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// The link's status when it is connected and its holder still runs.
fn live_status(paths: &LinkPaths) -> Option<LinkStatus> {
    crate::platform::verify_private_directory(&paths.dir).ok()?;
    status::read_status(&paths.status_file)
        .ok()
        .flatten()
        .filter(LinkStatus::is_live)
}

/// Waits until a link newer than `epoch` is up and reports herdr `version`.
fn wait_for_reconnect(paths: &LinkPaths, epoch: u64, version: &str) -> bool {
    let deadline = Instant::now() + RECONNECT_WAIT;
    loop {
        let back = live_status(paths).is_some_and(|link| {
            link.link_epoch > epoch
                && link
                    .slave
                    .is_some_and(|slave| slave.herdr_version.as_deref() == Some(version))
        });
        if back {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(RECONNECT_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn update_parser_takes_one_machine_and_optional_flags() {
        assert_eq!(
            parse_update_args(&strings(&["laptop"])).unwrap(),
            UpdateArgs {
                selector: "laptop".into(),
                yes: false,
                restart_server: false,
            }
        );
        assert_eq!(
            parse_update_args(&strings(&["--restart-server", "laptop", "--yes"])).unwrap(),
            UpdateArgs {
                selector: "laptop".into(),
                yes: true,
                restart_server: true,
            }
        );
        for args in [
            &[][..],
            &["--yes"],
            &["laptop", "desk"],
            &["laptop", "--yes", "--yes"],
            &["laptop", "--force"],
        ] {
            assert!(parse_update_args(&strings(args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn missing_features_blame_the_hub_link_only_when_the_versions_match() {
        let machine = DialInMachine::new("laptop", "default").unwrap();
        let slave = |version: &str, features: &[&str]| SlaveInfo {
            herdr_version: Some(version.into()),
            features: strings(features),
            ..SlaveInfo::default()
        };
        let current = crate::build_info::version();
        let hint = stale_link_hint(&machine, &slave(&current, &[])).unwrap();
        assert!(
            hint.contains(&format!("herdr machine enable {}", machine.id)),
            "{hint}"
        );
        assert_eq!(stale_link_hint(&machine, &slave("0.0.1", &[])), None);
        assert_eq!(
            stale_link_hint(&machine, &slave(&current, &["agent"])),
            None
        );
    }
}
