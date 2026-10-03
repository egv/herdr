//! End-to-end test for dial-in SSH agent forwarding with a real `ssh-agent`
//! on the hub (harness in `support::dial_in`). Skipped when OpenSSH's agent
//! tools are missing.

#![cfg(all(unix, not(target_os = "macos")))]

pub mod support;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use support::dial_in::*;

/// Holds a hub client's agent lease on `link.sock`, as a hub window does.
fn lease(harness: &Harness, socket: &Path) -> UnixStream {
    let mut stream = UnixStream::connect(harness.link_dir().join("link.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = serde_json::json!({"op": "agent_lease", "socket": socket});
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["ok"], true, "{line}");
    stream
}

fn agent_sessions(harness: &Harness) -> usize {
    harness
        .ssh_log()
        .lines()
        .filter(|line| line.starts_with("session ") && line.contains("--mode agent"))
        .count()
}

#[test]
fn dial_in_agent_forwarding_end_to_end() {
    if !agent_tools_available() {
        eprintln!("skipping: ssh-agent, ssh-add or ssh-keygen is not installed");
        return;
    }
    let mut harness = Harness::new();
    set_up_link_with(&mut harness, &["--agent-forwarding"]);
    let agent = start_hub_agent(&harness);
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);
    let relay = harness.agent_relay();
    harness.wait_for("the agent relay socket", LINK_TIMEOUT, || relay.exists());
    assert_eq!(harness.hub_list_row()["agent_forwarding"], true);

    // Liveness probes (connect and close) never cost a hub session; without
    // a lease the hub refuses.
    drop(UnixStream::connect(&relay).unwrap());
    thread::sleep(Duration::from_millis(300));
    assert_eq!(agent_sessions(&harness), 0, "{}", harness.ssh_log());
    assert!(!agent_lists_key(&relay));
    assert_eq!(agent_sessions(&harness), 1);

    // A hub window with an agent leases it; its bridge hands the relay to the
    // slave server, whose periodic probes stay free.
    let tui = HubTui::spawn_with_env(
        &harness,
        &[("SSH_AUTH_SOCK", agent.socket.display().to_string())],
    );
    harness.wait_for("the hub window's lease", LINK_TIMEOUT, || {
        harness.status_field("agent_leases") == 1 && harness.slave_client_bridges() >= 1
    });
    let bridge = harness
        .stream_processes()
        .into_iter()
        .find(|process| process.ends_with(" remote-client-bridge"))
        .unwrap_or_else(|| panic!("no slave bridge\n{}", harness.diagnostics()));
    let pid = bridge.split(':').next().unwrap();
    let environ = fs::read(format!("/proc/{pid}/environ")).unwrap();
    let expected = format!("SSH_AUTH_SOCK={}", relay.display());
    assert!(
        environ
            .split(|byte| *byte == 0)
            .any(|entry| entry == expected.as_bytes()),
        "{bridge} lacks {expected}"
    );
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(agent_sessions(&harness), 1, "{}", harness.ssh_log());

    // Listing and signing pass; removal does not.
    assert!(agent_lists_key(&relay), "{}", harness.diagnostics());
    let data = harness.root.join("signed");
    fs::write(&data, "data").unwrap();
    run_ok(with_agent(
        &relay,
        "ssh-keygen",
        &[
            "-Y",
            "sign",
            "-n",
            "file",
            "-f",
            agent.public_key.to_str().unwrap(),
            data.to_str().unwrap(),
        ],
    ));
    assert!(harness.root.join("signed.sig").exists());
    assert!(!run(with_agent(&relay, "ssh-add", &["-D"])).status.success());
    assert!(
        agent_lists_key(&agent.socket),
        "the hub agent must keep its key"
    );
    let (status, _) = harness.hub_machine_status();
    assert_eq!(status["agent_forwarding"], true, "{status}");
    assert_eq!(status["agent_leases"], 1, "{status}");

    // Closing the window ends its lease.
    drop(tui);
    harness.wait_for("the lease to end", LINK_TIMEOUT, || {
        harness.status_field("agent_leases") == 0
    });
    assert!(!agent_lists_key(&relay));

    // Turning forwarding off on the hub unbinds the relay; on binds it again.
    let _held = lease(&harness, &agent.socket);
    run_ok(harness.hub_command(&["machine", "agent-forwarding", LABEL, "off"]));
    harness.wait_for("the relay to be removed", LINK_TIMEOUT, || !relay.exists());
    assert!(!agent_lists_key(&relay));
    assert_eq!(harness.hub_list_row()["agent_forwarding"], Value::Null);
    run_ok(harness.hub_command(&["machine", "agent-forwarding", LABEL, "on"]));
    harness.wait_for("the relay to return", LINK_TIMEOUT, || relay.exists());
    assert!(agent_lists_key(&relay), "{}", harness.diagnostics());
}
