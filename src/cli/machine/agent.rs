//! `herdr machine agent-forwarding <label-or-id> on|off`: whether hub
//! clients lend their SSH agent to a dial-in machine's link.

use super::super::target::{find_saved_machine, SavedMachineRef};
use crate::client::endpoint::{DialInCatalog, EndpointCatalog};
use crate::remote::link::protocol::feature;
use crate::remote::link::status;

const USAGE: &str = "usage: herdr machine agent-forwarding <label-or-id> on|off";

pub(super) fn agent_forwarding(args: &[String]) -> std::io::Result<i32> {
    let (selector, enabled) = match args {
        [selector, setting] if setting == "on" => (selector, true),
        [selector, setting] if setting == "off" => (selector, false),
        _ => {
            eprintln!("{USAGE}");
            return Ok(2);
        }
    };
    let ssh = EndpointCatalog::load_profiles().map_err(std::io::Error::other)?;
    let mut dial_in = DialInCatalog::load().map_err(std::io::Error::other)?;
    let machine = match find_saved_machine(&ssh, &dial_in.machines, selector) {
        Ok(SavedMachineRef::DialIn(machine)) => machine.clone(),
        Ok(SavedMachineRef::Ssh(profile)) => {
            eprintln!(
                "error: machine '{}' is an SSH machine; forward your agent to it with `ForwardAgent yes` for its host in ~/.ssh/config",
                profile.label
            );
            return Ok(2);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    dial_in.set_agent_forwarding(&machine.id, enabled);
    dial_in.store().map_err(std::io::Error::other)?;
    if !enabled {
        println!(
            "Agent forwarding is off for dial-in machine '{}'.",
            machine.label
        );
        return Ok(0);
    }
    println!(
        "Agent forwarding is on for dial-in machine '{}'.",
        machine.label
    );
    println!(
        "Hub Herdr windows with SSH_AUTH_SOCK lend that agent (key listing and signing only) while they show this machine; windows already showing it start when they next connect to it."
    );
    let slave = status::read_status(&machine.paths().status_file)
        .ok()
        .flatten()
        .and_then(|link| link.slave);
    if let Some(slave) =
        slave.filter(|slave| !slave.features.iter().any(|name| name == feature::AGENT))
    {
        let note = super::update::stale_link_hint(&machine, &slave).unwrap_or_else(|| {
            "the Herdr on that machine cannot forward the agent yet; update it there.".into()
        });
        println!("note: {note}");
    }
    Ok(0)
}
