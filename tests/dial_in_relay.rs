//! End-to-end tests for dial-in machines reached through a relay hub: a
//! laptop reaches the hub's dial-in machine over its own ssh to the hub
//! (harness in `support::dial_in`).

#![cfg(all(unix, not(target_os = "macos")))]

pub mod support;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::dial_in::*;
use support::{client_shell_handshake, wait_for_client_shell_bootstrap};

const MARKER: &str = "herdr-remote-output-ready:1";

fn via_label() -> String {
    format!("{HUB_TARGET}/{LABEL}")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Copies until end-of-file or an error, forwarding each read at once
/// (`std::io::copy` splices socket-to-pipe copies on Linux and stalls here).
fn copy_until_eof(reader: &mut impl Read, writer: &mut impl Write) {
    let mut buffer = [0_u8; 64 * 1024];
    while let Ok(read @ 1..) = reader.read(&mut buffer) {
        if writer.write_all(&buffer[..read]).is_err() {
            return;
        }
    }
}

/// One connection through `herdr link-connect --kind client` on the hub,
/// over the laptop's ssh, carried by a socket pair like the laptop's bridge.
struct ViaClient {
    stream: UnixStream,
    ssh: Child,
    pumps: Vec<thread::JoinHandle<()>>,
}

impl ViaClient {
    fn open(laptop: &Laptop, link_id: &str, agent: &Path) -> Self {
        let command = format!(
            "printf '\\n%s\\n' '{MARKER}'; exec herdr link-connect --link {link_id} --kind client"
        );
        let mut ssh = laptop
            .ssh(&["-T", HUB_TARGET, &command])
            .env("FAKE_HUB_AUTH_SOCK", agent)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let (stream, carried) = UnixStream::pair().unwrap();
        let mut input = ssh.stdin.take().unwrap();
        let mut output = ssh.stdout.take().unwrap();
        let mut upload = carried.try_clone().unwrap();
        let mut download = carried;
        let pumps = vec![
            thread::spawn(move || {
                // Like the bridge: everything before the marker is login noise.
                let mut seen = Vec::new();
                let mut byte = [0_u8; 1];
                while !seen.ends_with(format!("{MARKER}\n").as_bytes()) {
                    match output.read(&mut byte) {
                        Ok(1) => seen.push(byte[0]),
                        _ => return,
                    }
                }
                copy_until_eof(&mut output, &mut download);
                let _ = download.shutdown(std::net::Shutdown::Write);
            }),
            // Dropping stdin at the end half-closes the connection.
            thread::spawn(move || copy_until_eof(&mut upload, &mut input)),
        ];
        Self { stream, ssh, pumps }
    }

    /// Closes the connection; link-connect must then exit successfully.
    fn close(mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.ssh.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "link-connect outlived its closed connection"
            );
            thread::sleep(Duration::from_millis(25));
        };
        assert!(status.success(), "link-connect exited with {status}");
        for pump in std::mem::take(&mut self.pumps) {
            pump.join().unwrap();
        }
    }
}

impl Drop for ViaClient {
    fn drop(&mut self) {
        let _ = self.ssh.kill();
        let _ = self.ssh.wait();
    }
}

#[test]
fn relay_hub_reaches_its_dial_in_machine_from_a_laptop() {
    let mut harness = Harness::new();
    let id = set_up_link(&mut harness);
    let laptop = Laptop::new(&harness);
    let dialer = harness.spawn_dialer();
    let first_epoch = harness.wait_connected_epoch_above(0);

    // The hub is saved as a relay; it lists its dial-in machine.
    let added = run_ok(laptop.command(&["machine", "relay", "add", HUB_TARGET]));
    let text = stdout(&added);
    assert!(text.contains("It exposes 1 dial-in machine:"), "{text}");
    assert!(
        text.contains(&format!("{} (connected)", via_label())),
        "{text}"
    );
    let relays = run_ok(laptop.command(&["machine", "relay", "list", "--json"]));
    let relays: Value = serde_json::from_slice(&relays.stdout).unwrap();
    assert_eq!(relays[0]["label"], HUB_TARGET, "{relays}");
    assert_eq!(relays[0]["target"], HUB_TARGET, "{relays}");
    assert_eq!(relays[0]["enabled"], true, "{relays}");

    let rows = laptop.via_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row["label"], via_label(), "{row}");
    assert_eq!(row["relay"], HUB_TARGET, "{row}");
    assert_eq!(row["link_id"], id.as_str(), "{row}");
    assert_eq!(row["connected"], true, "{row}");
    let via_id = row["id"].as_str().unwrap().to_owned();
    assert_ne!(via_id, id, "the laptop derives its own id for the machine");

    // A client-shell handshake through link-connect reaches the slave server.
    // The machine forwards agents and the laptop forwarded one: link-connect
    // lends it to the link like a hub window, without holding anything up.
    run_ok(harness.hub_command(&["machine", "agent-forwarding", LABEL, "on"]));
    let agent = harness.root.join("agent.sock");
    let _agent = UnixListener::bind(&agent).unwrap();
    assert_eq!(harness.status_field("agent_leases"), 0);
    let mut client = ViaClient::open(&laptop, &id, &agent);
    client
        .stream
        .set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let (generation, error) = client_shell_handshake(&mut client.stream, 1, 80, 24)
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    assert_eq!((generation, error), (1, None));
    wait_for_client_shell_bootstrap(&mut client.stream, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    assert_eq!(harness.slave_client_bridges(), 1);
    harness.wait_for("the relay's agent lease", LINK_TIMEOUT, || {
        harness.status_field("agent_leases") == 1
    });
    drain_until_idle(&mut client.stream);
    client.close();
    harness.wait_streams_closed();
    assert!(laptop.link_connect_processes().is_empty());
    harness.wait_for("the lease to end with the connection", LINK_TIMEOUT, || {
        harness.status_field("agent_leases") == 0
    });

    // `--machine` API commands from the laptop: by relay path, derived id,
    // and a label only one relay lists.
    for selector in [via_label().as_str(), via_id.as_str(), LABEL] {
        let output = run(laptop.command(&["--machine", selector, "pane", "list"]));
        assert!(
            output.status.success(),
            "{selector}: {}\n{}\n{}",
            stderr(&output),
            laptop.ssh_log(),
            harness.diagnostics()
        );
        let panes: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(panes["result"].is_object(), "{panes}");
    }
    let workspaces = run_ok(laptop.command(&["--machine", &via_id, "workspace", "list"]));
    let workspaces: Value = serde_json::from_slice(&workspaces.stdout).unwrap();
    assert!(workspaces["result"].is_object(), "{workspaces}");
    assert!(laptop
        .ssh_log()
        .contains(&format!("link-connect --link {id} --kind api")));

    // Management commands run on the hub, for the hub's machine id.
    let status = run_ok(laptop.command(&["machine", "status", &via_label(), "--json"]));
    assert!(
        stderr(&status).contains(&format!(
            "running on {HUB_TARGET}: herdr machine status {id} --json"
        )),
        "{}",
        stderr(&status)
    );
    let text = stdout(&status);
    let json = &text[text.find('[').unwrap_or_else(|| panic!("{text}"))..];
    let rows: Value = serde_json::from_str(json).unwrap_or_else(|error| panic!("{error}: {text}"));
    assert_eq!(rows[0]["id"], id.as_str(), "{rows}");
    assert_eq!(rows[0]["status"], "connected", "{rows}");
    harness.wait_streams_closed();

    // The machine stops dialing in: it is offline from the laptop.
    harness.signal_dialer(dialer, libc::SIGKILL);
    assert!(harness
        .wait_dialer_exit(dialer, Duration::from_secs(5))
        .is_some());
    harness.wait_disconnected();
    harness.wait_for("link sockets to be removed", LINK_TIMEOUT, || {
        harness.sockets_present().is_empty()
    });
    let offline = run(laptop.command(&["--machine", &via_label(), "pane", "list"]));
    assert!(!offline.status.success());
    assert!(
        stderr(&offline).contains(&format!(
            "machine '{}' is not connected (it has not dialed in to {HUB_TARGET})",
            via_label()
        )),
        "{}",
        stderr(&offline)
    );
    assert_eq!(laptop.via_rows()[0]["connected"], false);
    assert!(laptop.link_connect_processes().is_empty());

    // It dials in again: the laptop reaches it again.
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(first_epoch);
    assert_eq!(laptop.via_rows()[0]["connected"], true);
    let output = run(laptop.command(&["--machine", &via_label(), "pane", "list"]));
    assert!(
        output.status.success(),
        "{}\n{}",
        stderr(&output),
        harness.diagnostics()
    );

    // An unreachable relay is a warning for the machine list, not a failure.
    laptop.set_relay_down(true);
    let listed = run_ok(laptop.command(&["machine", "list", "--json"]));
    let rows: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(
        !rows
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "via"),
        "{rows}"
    );
    assert!(
        stderr(&listed).contains("could not reach the relay hub")
            && stderr(&listed).contains(&format!("Check `ssh {HUB_TARGET}`")),
        "{}",
        stderr(&listed)
    );
    let unreachable = run(laptop.command(&["--machine", &via_label(), "pane", "list"]));
    assert!(!unreachable.status.success());
    assert!(
        stderr(&unreachable).contains("could not reach the relay hub"),
        "{}",
        stderr(&unreachable)
    );
    laptop.set_relay_down(false);
}

#[test]
fn relay_laptop_tui_attaches_through_the_hub_and_follows_redials() {
    let mut harness = Harness::new();
    let id = set_up_link(&mut harness);
    let laptop = Laptop::new(&harness);
    let dialer = harness.spawn_dialer();
    assert_eq!(harness.wait_connected_epoch_above(0), 1);
    run_ok(laptop.command(&["machine", "relay", "add", HUB_TARGET]));

    // No laptop server runs: the TUI federates the relay's machine.
    let tui = laptop.tui();
    harness.wait_for(
        "the laptop TUI to attach through the relay",
        LINK_TIMEOUT,
        || harness.slave_client_bridges() >= 1,
    );
    let processes = laptop.link_connect_processes();
    assert!(
        processes
            .iter()
            .any(|process| process.contains(&format!("--link {id} --kind client"))),
        "{processes:?}\n{}",
        laptop.ssh_log()
    );
    thread::sleep(Duration::from_secs(1));
    assert!(
        harness.slave_client_bridges() >= 1,
        "the laptop TUI stream must stay attached\n{}",
        harness.diagnostics()
    );

    harness.signal_dialer(dialer, libc::SIGKILL);
    assert!(harness
        .wait_dialer_exit(dialer, Duration::from_secs(5))
        .is_some());
    harness.wait_disconnected();
    harness.wait_for("the TUI stream to end", LINK_TIMEOUT, || {
        harness.slave_client_bridges() == 0
    });
    // Let the TUI notice the failure and retry while the machine is offline;
    // meanwhile the hub's Herdr moves, which the laptop has to notice.
    thread::sleep(Duration::from_secs(3));
    laptop.move_hub_herdr();

    harness.spawn_dialer();
    assert_eq!(harness.wait_connected_epoch_above(1), 2);
    harness.wait_for(
        "the laptop TUI to reattach after the machine dialed in again",
        Duration::from_secs(45),
        || harness.slave_client_bridges() >= 1,
    );
    assert!(
        laptop
            .ssh_log()
            .contains(".local/bin/herdr link-connect --link"),
        "{}",
        laptop.ssh_log()
    );

    drop(tui);
    harness.wait_for("link-connect to end with the TUI", LINK_TIMEOUT, || {
        laptop.link_connect_processes().is_empty()
    });
    harness.wait_streams_closed();
}

#[test]
fn relay_laptop_manages_the_relay_and_its_machine() {
    let mut harness = Harness::new();
    let id = set_up_link(&mut harness);
    let laptop = Laptop::new(&harness);
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);

    // A hub that cannot be reached, or has no usable Herdr, is not saved.
    laptop.set_relay_down(true);
    let down = run(laptop.command(&["machine", "relay", "add", HUB_TARGET]));
    laptop.set_relay_down(false);
    let mut missing = laptop.command(&["machine", "relay", "add", HUB_TARGET]);
    missing.env("FAKE_HUB_PATH", "/usr/bin:/bin");
    let missing = run(missing);
    for output in [&down, &missing] {
        assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
        assert!(
            stderr(output).contains("relay hub was not saved")
                && stderr(output).contains(&format!("herdr machine add {HUB_TARGET}")),
            "{}",
            stderr(output)
        );
    }
    let relays = run_ok(laptop.command(&["machine", "relay", "list", "--json"]));
    assert_eq!(stdout(&relays).trim(), "[]");

    run_ok(laptop.command(&["machine", "relay", "add", HUB_TARGET, "--label", "vps"]));
    assert_eq!(laptop.via_rows()[0]["label"], format!("vps/{LABEL}"));

    // Relay settings are the laptop's own.
    run_ok(laptop.command(&["machine", "relay", "rename", "vps", "--label", "hub"]));
    run_ok(laptop.command(&["--machine", &format!("hub/{LABEL}"), "pane", "list"]));
    run_ok(laptop.command(&["machine", "relay", "disable", "hub"]));
    assert!(laptop.via_rows().is_empty());
    let hidden = run(laptop.command(&["--machine", &format!("hub/{LABEL}"), "pane", "list"]));
    assert_eq!(hidden.status.code(), Some(2), "{}", stderr(&hidden));
    run_ok(laptop.command(&["machine", "relay", "enable", "hub"]));
    assert_eq!(laptop.via_rows().len(), 1);

    // Management commands for the machine run on the hub.
    let forwarded = |args: &[&str]| {
        let output = run_ok(laptop.command(args));
        let verb = args[1];
        assert!(
            stderr(&output).contains(&format!("running on hub: herdr machine {verb} {id}")),
            "{}",
            stderr(&output)
        );
    };
    forwarded(&[
        "machine",
        "rename",
        &format!("hub/{LABEL}"),
        "--label",
        "mac",
    ]);
    assert_eq!(harness.hub_list_row()["label"], "mac");
    run_ok(laptop.command(&["--machine", "hub/mac", "pane", "list"]));
    forwarded(&["machine", "reconnect", "hub/mac", "--wait", "10"]);
    forwarded(&["machine", "agent-forwarding", "hub/mac", "on"]);
    assert_eq!(harness.hub_list_row()["agent_forwarding"], true);
    forwarded(&["machine", "agent-forwarding", "hub/mac", "off"]);
    assert_eq!(harness.hub_list_row()["agent_forwarding"], Value::Null);

    forwarded(&["machine", "disable", "hub/mac"]);
    assert_eq!(harness.hub_list_row()["enabled"], false);
    harness.wait_disconnected();
    let rows = laptop.via_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["enabled"], false, "{rows:?}");
    let disabled = run(laptop.command(&["--machine", "hub/mac", "pane", "list"]));
    assert!(!disabled.status.success());
    assert!(
        stderr(&disabled).contains("machine 'hub/mac' is disabled on hub"),
        "{}",
        stderr(&disabled)
    );
    // The hub's update refuses a machine that is not dialed in.
    let update = run(laptop.command(&["machine", "update", "hub/mac", "--yes"]));
    assert_eq!(update.status.code(), Some(1), "{}", stderr(&update));
    assert!(
        stderr(&update).contains(&format!("running on hub: herdr machine update {id} --yes"))
            && stderr(&update).contains("is not connected"),
        "{}",
        stderr(&update)
    );

    // The same name re-enables it from the laptop.
    forwarded(&["machine", "enable", "hub/mac"]);
    assert_eq!(harness.hub_list_row()["enabled"], true);
    assert_eq!(laptop.via_rows()[0]["enabled"], true);
}

#[test]
fn relay_lends_the_laptops_forwarded_agent_to_the_slave() {
    if !agent_tools_available() {
        eprintln!("skipping: ssh-agent, ssh-add or ssh-keygen is not installed");
        return;
    }
    let mut harness = Harness::new();
    set_up_link_with(&mut harness, &["--agent-forwarding"]);
    // The laptop's agent, as `ForwardAgent yes` exposes it to hub logins.
    let agent = start_hub_agent(&harness);
    let laptop = Laptop::new(&harness);
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);
    let relay = harness.agent_relay();
    harness.wait_for("the agent relay socket", LINK_TIMEOUT, || relay.exists());
    run_ok(laptop.command(&["machine", "relay", "add", HUB_TARGET]));
    assert!(!agent_lists_key(&relay), "nothing lends an agent yet");

    // The laptop TUI attaches through the hub; its link-connect lends the
    // forwarded agent, so a slave pane's `ssh-add -l` reaches the laptop.
    let mut client = laptop.command(&["client"]);
    client.env("FAKE_HUB_AUTH_SOCK", &agent.socket);
    let tui = HubTui::spawn_from(&client);
    harness.wait_for("the relay's agent lease", LINK_TIMEOUT, || {
        harness.status_field("agent_leases") == 1 && harness.slave_client_bridges() >= 1
    });
    assert!(
        agent_lists_key(&relay),
        "{}\n{}",
        laptop.ssh_log(),
        harness.diagnostics()
    );
    let (status, _) = harness.hub_machine_status();
    assert_eq!(status["agent_leases"], 1, "{status}");

    drop(tui);
    harness.wait_for("the lease to end with the TUI", LINK_TIMEOUT, || {
        harness.status_field("agent_leases") == 0
    });
    assert!(!agent_lists_key(&relay));
    harness.wait_streams_closed();
}
