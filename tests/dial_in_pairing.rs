//! End-to-end tests for dial-in pairing and hub-side operations (harness in
//! `support::dial_in`).

#![cfg(all(unix, not(target_os = "macos")))]

pub mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::dial_in::*;

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn dial_in_pairing_over_the_users_ssh_then_the_dialer_connects() {
    let mut harness = Harness::new();
    let (key_line, key_base64) = test_public_key_line();
    let identity = harness.slave.home.join("id_test");
    fs::write(&identity, "dummy private key\n").unwrap();
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        harness.slave.home.join("id_test.pub"),
        format!("{key_line}\n"),
    )
    .unwrap();
    let pair = |extra: &[&str]| {
        let mut args = vec![
            "machine",
            "dial",
            "setup",
            DIAL_NAME,
            "--hub",
            HUB_TARGET,
            "--pair",
            "--identity",
            identity.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        run(harness.slave_command(&args))
    };

    // herdr is not on the hub's non-interactive PATH: a hint, nothing saved.
    let failed = pair(&[]);
    assert_eq!(failed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("--hub-herdr"),
        "{failed:?}"
    );
    assert!(!harness.catalog_path().exists());

    let paired = pair(&["--hub-herdr", herdr_bin(), "--agent-forwarding"]);
    assert!(
        paired.status.success(),
        "{}\n{}",
        stdout(&paired),
        String::from_utf8_lossy(&paired.stderr)
    );
    let text = stdout(&paired);
    assert!(text.contains("as dial-in machine 'slave1'"), "{text}");
    assert!(
        harness.ssh_log().contains("plain ")
            && harness.ssh_log().contains("--authorize-key - --json"),
        "{}",
        harness.ssh_log()
    );
    harness.link_id = harness.slave_dial_status()["link_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id = harness.link_id.clone();
    assert_eq!(harness.hub_list_row()["label"], LABEL);
    assert_eq!(harness.hub_list_row()["agent_forwarding"], true);

    // The hub wrote exactly one restricted line for the key, privately.
    let authorized_keys = harness.hub.home.join(".ssh/authorized_keys");
    let content = fs::read_to_string(&authorized_keys).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 1, "{content}");
    assert!(
        lines[0].ends_with(&format!(" ssh-ed25519 {key_base64} herdr-link:{id}")),
        "{content}"
    );
    assert_eq!(mode(&authorized_keys), 0o600);
    assert_eq!(mode(&harness.hub.home.join(".ssh")), 0o700);
    let command = forced_command(lines[0]);
    assert_eq!(
        command,
        format!(
            "'{}' link-accept --catalog '{}' --link {id}",
            herdr_bin(),
            harness.catalog_path().display()
        )
    );

    // Nothing dialed in yet: reconnect waits, then reports the machine offline.
    let started = Instant::now();
    let waited = run(harness.hub_command(&["machine", "reconnect", LABEL, "--wait", "1"]));
    assert_eq!(waited.status.code(), Some(1), "{waited:?}");
    assert!(stdout(&waited).contains("offline"), "{}", stdout(&waited));
    assert!(started.elapsed() < Duration::from_secs(15));

    // The dialer fails until sshd runs the forced command, and reports that
    // failure once it connects.
    let dialer = harness.spawn_dialer();
    harness.wait_for("a failed dial attempt", LINK_TIMEOUT, || {
        harness
            .dial_state()
            .is_some_and(|state| state["last_error"]["code"] == "preamble_failed")
    });
    fs::write(harness.root.join("forced-command"), &command).unwrap();
    let reconnected = run(harness.hub_command(&["machine", "reconnect", LABEL, "--wait", "30"]));
    assert!(
        reconnected.status.success(),
        "{}\n{}",
        stdout(&reconnected),
        harness.diagnostics()
    );
    assert!(
        stdout(&reconnected).contains("\tconnected"),
        "{}",
        stdout(&reconnected)
    );
    let (status, _) = harness.hub_machine_status();
    let reported = status["slave"]["last_dial_error"]
        .as_str()
        .unwrap_or_default();
    assert!(reported.ends_with("(preamble_failed)"), "{status}");
    let text = stdout(&run_ok(harness.hub_command(&["machine", "status", LABEL])));
    assert!(text.contains("  slave reported: "), "{text}");

    // Agent forwarding requested while pairing reaches the dialer.
    harness.wait_for("the agent relay socket", LINK_TIMEOUT, || {
        harness.agent_relay().exists()
    });

    // The hub heard that failure once: the next run does not report it again.
    let epoch = harness.status_field("link_epoch").as_u64().unwrap();
    harness.signal_dialer(dialer, libc::SIGTERM);
    assert!(harness
        .wait_dialer_exit(dialer, Duration::from_secs(10))
        .is_some());
    assert_eq!(harness.dial_state().unwrap()["last_error"], Value::Null);
    harness.wait_disconnected();
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(epoch);
    let (status, _) = harness.hub_machine_status();
    assert_eq!(status["slave"]["last_dial_error"], Value::Null, "{status}");
    let text = stdout(&run_ok(harness.hub_command(&["machine", "status", LABEL])));
    assert!(!text.contains("slave reported:"), "{text}");
}

#[test]
fn dial_in_authorize_write_and_remove_revoke_edit_only_herdr_lines() {
    let harness = Harness::new();
    let added = run_ok(harness.hub_command(&["machine", "add", "--dial-in", "--label", LABEL]));
    let id = stdout(&added)
        .split_whitespace()
        .find(|word| word.len() == 32 && word.chars().all(|ch| ch.is_ascii_hexdigit()))
        .unwrap()
        .to_string();
    let keys = harness.root.join("keys").join("authorized_keys");
    let keys_arg = keys.to_str().unwrap();
    let (key_line, key_base64) = test_public_key_line();
    let authorize = |extra: &[&str]| {
        let mut args = vec![
            "machine",
            "authorize",
            &id,
            &key_line,
            "--herdr-path",
            herdr_bin(),
            "--write",
            "--authorized-keys",
            keys_arg,
        ];
        args.extend_from_slice(extra);
        run(harness.hub_command(&args))
    };

    // A missing directory and file are created private.
    let written = authorize(&[]);
    assert!(written.status.success(), "{written:?}");
    assert_eq!(mode(&keys), 0o600);
    assert_eq!(mode(keys.parent().unwrap()), 0o700);
    let line = fs::read_to_string(&keys).unwrap();
    assert!(
        line.ends_with(&format!(" ssh-ed25519 {key_base64} herdr-link:{id}\n")),
        "{line}"
    );

    // Other lines are kept byte for byte, including CRLF endings.
    let existing = "# managed by hand\r\nssh-rsa AAAAexisting user@host\r\n";
    fs::write(&keys, format!("{existing}{}", line.replace('\n', "\r\n"))).unwrap();
    let again = authorize(&[]);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("--replace"),
        "{again:?}"
    );
    let replaced = authorize(&["--replace"]);
    assert!(replaced.status.success(), "{replaced:?}");
    assert_eq!(
        fs::read_to_string(&keys).unwrap(),
        format!("{existing}{}", line.replace('\n', "\r\n"))
    );

    run_ok(harness.hub_command(&[
        "machine",
        "remove",
        &id,
        "--revoke",
        "--authorized-keys",
        keys_arg,
    ]));
    assert_eq!(fs::read_to_string(&keys).unwrap(), existing);
    let listed = stdout(&run_ok(harness.hub_command(&["machine", "list", "--json"])));
    assert!(!listed.contains(&id), "{listed}");
}
