use clap::{Arg, Command};

use super::{flag, json_flag, option, path_option};

pub(super) fn command() -> Command {
    Command::new("machine")
        .about("Manage saved SSH and dial-in machines")
        .after_help(
            "A relay hub's dial-in machines are named <relay>/<machine>; status, reconnect, update, agent-forwarding, rename, enable, disable, remove and authorize on them run on the hub.",
        )
        .subcommand(
            Command::new("list")
                .about("List saved SSH and dial-in machines")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("status")
                .about("Check saved machines without prompting for authentication")
                .arg(Arg::new("machine").value_name("LABEL_OR_ID"))
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("reconnect")
                .about(
                    "Authenticate a saved SSH machine in this terminal and verify connectivity, or show a dial-in machine's link",
                )
                .arg(Arg::new("machine").value_name("LABEL_OR_ID").required(true))
                .arg(
                    option("wait", "SECONDS")
                        .help("How long to wait for a dial-in machine to connect (default: 30)"),
                ),
        )
        .subcommand(
            Command::new("add")
                .about("Prepare the remote Herdr server and save an SSH machine, or save a dial-in machine")
                .arg(
                    Arg::new("ssh-target")
                        .value_name("SSH_TARGET")
                        .required_unless_present("dial-in"),
                )
                .arg(
                    flag("dial-in")
                        .conflicts_with("ssh-target")
                        .requires("label")
                        .help("Save a machine that connects to this hub over SSH itself; prints its setup command"),
                )
                .arg(
                    option("label", "LABEL").help(
                        "Set the machine label shown in the sidebar (defaults to the SSH host, or host/session; required with --dial-in)",
                    ),
                )
                .arg(
                    option("remote-session", "NAME")
                        .help("Select a session explicitly (default without an interactive terminal)"),
                )
                .arg(
                    option("hub", "SSH_TARGET")
                        .requires("dial-in")
                        .help("SSH target the dial-in machine uses to reach this hub, used in the printed setup command"),
                )
                .arg(
                    option("authorize-key", "-")
                        .requires("dial-in")
                        .help("Read the dial-in machine's public key line from stdin and add it to ~/.ssh/authorized_keys"),
                )
                .arg(
                    json_flag()
                        .requires("dial-in")
                        .help("Print the saved dial-in machine as JSON"),
                )
                .arg(
                    flag("agent-forwarding")
                        .requires("dial-in")
                        .help("Lend hub windows' SSH agent to the dial-in machine (key listing and signing only)"),
                ),
        )
        .subcommand(
            Command::new("agent-forwarding")
                .about("Turn SSH agent forwarding from hub windows to a dial-in machine on or off")
                .arg(Arg::new("machine").value_name("LABEL_OR_ID").required(true))
                .arg(
                    Arg::new("setting")
                        .value_parser(["on", "off"])
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("authorize")
                .about("Print, or with --write add, the restricted authorized_keys line for a dial-in machine's public key")
                .arg(
                    Arg::new("machine")
                        .value_name("LABEL_OR_ID")
                        .required(true),
                )
                .arg(
                    Arg::new("public-key")
                        .value_name("PUBLIC_KEY_LINE")
                        .required(true)
                        .help("The machine's public key line, quoted as one argument"),
                )
                .arg(
                    path_option("herdr-path", "PATH")
                        .help("Herdr executable for sshd to run (default: this one, or a stable launcher when this one is in a versioned install directory)"),
                )
                .arg(flag("write").help("Add the line to authorized_keys instead of printing it"))
                .arg(
                    path_option("authorized-keys", "PATH")
                        .requires("write")
                        .help("File to edit (default: ~/.ssh/authorized_keys)"),
                )
                .arg(
                    flag("replace")
                        .requires("write")
                        .help("Replace this machine's existing line"),
                ),
        )
        .subcommand(
            Command::new("update")
                .about("Install this hub's Herdr version on a connected dial-in machine")
                .arg(
                    Arg::new("machine")
                        .value_name("LABEL_OR_ID")
                        .required(true),
                )
                .arg(flag("yes").help("Skip the confirmation prompts"))
                .arg(flag("restart-server").help(
                    "After updating, restart the machine's Herdr server, stopping its panes",
                )),
        )
        .subcommand(
            profile_command("rename", "Rename a saved machine").arg(
                option("label", "LABEL")
                    .required(true)
                    .help("Set the machine label shown in the sidebar"),
            ),
        )
        .subcommand(
            profile_command("remove", "Remove a saved machine")
                .arg(flag("revoke").help(
                    "Also delete a dial-in machine's line from authorized_keys",
                ))
                .arg(
                    path_option("authorized-keys", "PATH")
                        .requires("revoke")
                        .help("File to edit (default: ~/.ssh/authorized_keys)"),
                ),
        )
        .subcommand(profile_command("enable", "Enable a saved machine"))
        .subcommand(profile_command("disable", "Disable a saved machine"))
        .subcommand(dial_command())
        .subcommand(relay_command())
}

fn relay_command() -> Command {
    let relay = || {
        Arg::new("relay")
            .value_name("RELAY")
            .required(true)
            .help("Relay hub label or ID")
    };
    Command::new("relay")
        .about("Reach the dial-in machines of a hub you reach over SSH (relay hubs)")
        .subcommand(
            Command::new("add")
                .about("Check the hub's Herdr over SSH, then save it as a relay hub")
                .arg(
                    Arg::new("ssh-target")
                        .value_name("SSH_TARGET")
                        .required(true),
                )
                .arg(option("label", "LABEL").help(
                    "Relay label, the prefix of its machines' names (defaults to the SSH host)",
                )),
        )
        .subcommand(
            Command::new("list")
                .about("List relay hubs")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a relay hub")
                .arg(relay()),
        )
        .subcommand(
            Command::new("rename")
                .about("Rename a relay hub")
                .arg(relay())
                .arg(
                    option("label", "LABEL")
                        .required(true)
                        .help("New relay label"),
                ),
        )
        .subcommand(
            Command::new("enable")
                .about("Enable a relay hub")
                .arg(relay()),
        )
        .subcommand(
            Command::new("disable")
                .about("Disable a relay hub")
                .arg(relay()),
        )
}

fn profile_command(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about).arg(
        Arg::new("profile-id")
            .value_name("PROFILE_ID")
            .required(true),
    )
}

fn dial_command() -> Command {
    Command::new("dial")
        .about("Keep this machine connected to a hub that cannot reach it (dial-in)")
        .subcommand(
            Command::new("setup")
                .about("Save a dial-in link to a hub and print the hub's authorize command, or pair with the hub over ssh")
                .arg(dial_name().required(true))
                .arg(
                    option("hub", "SSH_TARGET")
                        .required(true)
                        .help("SSH target of the hub"),
                )
                .arg(
                    option("link", "LINK_ID")
                        .required_unless_present("pair")
                        .conflicts_with("pair")
                        .help("Machine ID printed by `herdr machine add --dial-in` on the hub"),
                )
                .arg(flag("pair").help(
                    "Register this machine on the hub through your own ssh login and authorize its key there",
                ))
                .arg(
                    option("label", "LABEL")
                        .requires("pair")
                        .help("Label on the hub (default: the link name)"),
                )
                .arg(
                    option("remote-session", "NAME")
                        .requires("pair")
                        .help("Herdr session the hub shows (default: default)"),
                )
                .arg(
                    flag("agent-forwarding")
                        .requires("pair")
                        .help("Have the hub lend hub windows' SSH agent to this machine (key listing and signing only)"),
                )
                .arg(
                    path_option("hub-herdr", "PATH")
                        .requires("pair")
                        .help("Herdr executable on the hub (default: herdr on its PATH)"),
                )
                .arg(
                    path_option("identity", "PATH")
                        .help("SSH private key to use (default: generate one for this link)"),
                )
                .arg(flag("no-compression").help("Disable SSH compression")),
        )
        .subcommand(
            Command::new("run")
                .about("Keep the dial-in link to the hub open in the foreground")
                .arg(dial_name().required(true)),
        )
        .subcommand(
            Command::new("list")
                .about("List dial-in links on this machine")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("status")
                .about("Show dial-in link configuration and state")
                .arg(dial_name().help("Dial-in link name (default: the only link on this machine)"))
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a dial-in link and its generated key")
                .arg(dial_name().required(true)),
        )
        .subcommand(
            Command::new("service")
                .about("Keep a dial-in link running as a user service (systemd or launchd)")
                .subcommand(
                    Command::new("install")
                        .about("Install, enable, and start the service for a dial-in link")
                        .arg(dial_name().required(true))
                        .arg(flag("no-start").help("Enable the service without starting it now"))
                        .arg(
                            path_option("herdr-path", "PATH")
                                .help("Herdr executable the service runs (default: a stable launcher for this one)"),
                        ),
                )
                .subcommand(
                    Command::new("uninstall")
                        .about("Stop and remove the service for a dial-in link")
                        .arg(dial_name().required(true)),
                )
                .subcommand(
                    Command::new("status")
                        .about("Show whether the service for a dial-in link is installed and running")
                        .arg(dial_name().required(true))
                        .arg(json_flag()),
                ),
        )
}

fn dial_name() -> Arg {
    Arg::new("name")
        .value_name("NAME")
        .help("Dial-in link name on this machine")
}

#[cfg(test)]
mod tests {
    fn parse(args: &[&str]) -> Result<clap::ArgMatches, clap::Error> {
        let mut argv = vec!["herdr"];
        argv.extend_from_slice(args);
        super::super::command().try_get_matches_from(argv)
    }

    #[test]
    fn add_accepts_either_an_ssh_target_or_a_labeled_dial_in_machine() {
        for valid in [
            &["machine", "add", "workbox"][..],
            &["machine", "add", "workbox", "--label", "box"],
            &["machine", "add", "--dial-in", "--label", "laptop"],
            &[
                "machine",
                "add",
                "--dial-in",
                "--label",
                "laptop",
                "--hub",
                "me@hub",
                "--remote-session",
                "agents",
            ],
        ] {
            assert!(parse(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            &["machine", "add"][..],
            &["machine", "add", "--dial-in"],
            &[
                "machine",
                "add",
                "workbox",
                "--dial-in",
                "--label",
                "laptop",
            ],
            &["machine", "add", "workbox", "--hub", "me@hub"],
        ] {
            assert!(parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn relay_subcommands_are_described() {
        for args in [
            &["machine", "relay", "add", "me@vps"][..],
            &["machine", "relay", "add", "me@vps", "--label", "vps"],
            &["machine", "relay", "list", "--json"],
            &["machine", "relay", "remove", "vps"],
            &["machine", "relay", "rename", "vps", "--label", "hub"],
            &["machine", "relay", "enable", "vps"],
            &["machine", "relay", "disable", "vps"],
        ] {
            assert!(parse(args).is_ok(), "{args:?}");
        }
        for args in [
            &["machine", "relay", "add"][..],
            &["machine", "relay", "rename", "vps"],
            &["machine", "relay", "remove"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn authorize_and_dial_subcommands_are_described() {
        assert!(parse(&["machine", "authorize", "laptop", "ssh-ed25519 AAAA c"]).is_ok());
        assert!(parse(&[
            "machine",
            "authorize",
            "laptop",
            "ssh-ed25519 AAAA c",
            "--herdr-path",
            "/usr/local/bin/herdr"
        ])
        .is_ok());
        assert!(parse(&["machine", "authorize", "laptop"]).is_err());
        assert!(parse(&["machine", "update", "laptop", "--yes", "--restart-server"]).is_ok());
        assert!(parse(&["machine", "update"]).is_err());
        assert!(
            parse(&["machine", "dial", "setup", "hub", "--hub", "me@hub", "--link", "0123"])
                .is_ok()
        );
        assert!(parse(&["machine", "dial", "setup", "hub", "--hub", "me@hub"]).is_err());
        for args in [
            &[
                "machine", "dial", "setup", "hub", "--hub", "me@hub", "--pair", "--label", "Box",
            ][..],
            &[
                "machine",
                "dial",
                "setup",
                "hub",
                "--hub",
                "me@hub",
                "--pair",
                "--agent-forwarding",
            ],
            &[
                "machine",
                "authorize",
                "box",
                "ssh-ed25519 AAAA c",
                "--write",
                "--replace",
            ],
            &[
                "machine",
                "add",
                "--dial-in",
                "--label",
                "box",
                "--authorize-key",
                "-",
                "--json",
            ],
            &[
                "machine",
                "remove",
                "0123",
                "--revoke",
                "--authorized-keys",
                "/k",
            ],
            &["machine", "reconnect", "box", "--wait", "5"],
        ] {
            assert!(parse(args).is_ok(), "{args:?}");
        }
        // The runtime parser enforces flag dependencies; clap checks conflicts.
        assert!(parse(&[
            "machine", "dial", "setup", "hub", "--hub", "h", "--pair", "--link", "0123"
        ])
        .is_err());
        for args in [
            &["machine", "dial", "run", "hub"][..],
            &["machine", "dial", "list", "--json"],
            &["machine", "dial", "status"],
            &["machine", "dial", "status", "hub", "--json"],
            &["machine", "dial", "remove", "hub"],
            &["machine", "dial", "service", "install", "hub", "--no-start"],
            &["machine", "dial", "service", "status", "hub", "--json"],
        ] {
            assert!(parse(args).is_ok(), "{args:?}");
        }
    }
}
