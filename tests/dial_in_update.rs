//! End-to-end test of hub-driven updates of a dial-in machine (harness in
//! `support::dial_in`).

#![cfg(all(unix, not(target_os = "macos")))]

pub mod support;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use support::dial_in::*;

/// The machine update: hashing, sending and verifying a debug build of
/// up to several hundred MB, then waiting for the link to return.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(240);

/// What the hub sends: the test binary without its debug info when `strip`
/// is available (hashing it twice dominates the test), else the binary.
fn update_payload(harness: &Harness) -> PathBuf {
    let stripped = harness.root.join("herdr-update");
    let status = Command::new("strip")
        .arg("--strip-debug")
        .arg("-o")
        .arg(&stripped)
        .arg(herdr_bin())
        .status();
    if status.is_ok_and(|status| status.success()) {
        stripped
    } else {
        PathBuf::from(herdr_bin())
    }
}

/// Starts the slave dialer from `exe` instead of the test binary.
fn spawn_dialer_from(harness: &mut Harness, exe: &Path) -> usize {
    let log = harness
        .root
        .join(format!("dialer-{}.log", harness.dialer_logs.len()));
    let template = harness.slave_command(&["machine", "dial", "run", DIAL_NAME]);
    let mut command = Command::new(exe);
    command.args(template.get_args()).env_clear();
    for (name, value) in template.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    harness.dialers.push(child);
    harness.dialer_logs.push(log);
    harness.dialers.len() - 1
}

/// A raw `link.sock` update whose checksum does not match `payload`;
/// returns the machine's result line.
fn send_corrupted_update(harness: &Harness, payload: &[u8]) -> Value {
    let mut stream = UnixStream::connect(harness.link_dir().join("link.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    writeln!(
        stream,
        r#"{{"op":"update","size":{},"sha256":"{}"}}"#,
        payload.len(),
        "0".repeat(64)
    )
    .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["ok"],
        true,
        "{line}"
    );
    stream.write_all(payload).unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|error| panic!("{error}: {line:?}"))
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::metadata(path).unwrap();
    (metadata.ino(), metadata.len())
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn hub_updates_a_dial_in_machine_over_its_link() {
    let mut harness = Harness::new();
    set_up_link_with(&mut harness, &["--agent-forwarding"]);
    // The dialer runs from its own copy of herdr, which updates replace.
    let bin = harness.root.join("slave-bin");
    fs::create_dir(&bin).unwrap();
    let exe = bin.join("herdr");
    fs::copy(herdr_bin(), &exe).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let dialer = spawn_dialer_from(&mut harness, &exe);
    let epoch = harness.wait_connected_epoch_above(0);
    harness.wait_for("the agent relay socket", LINK_TIMEOUT, || {
        harness.agent_relay().exists()
    });
    let slave = harness.status_field("slave");
    assert!(
        slave["features"]
            .as_array()
            .is_some_and(|features| features.iter().any(|name| name == "update")),
        "{slave}"
    );

    // An executable that fails verification changes nothing.
    let original = identity(&exe);
    let result = send_corrupted_update(&harness, b"not a herdr executable");
    assert_eq!(result["ok"], false, "{result}\n{}", harness.diagnostics());
    assert_eq!(result["code"], "update_rejected", "{result}");
    assert_eq!(identity(&exe), original);
    assert_eq!(entries(&bin), ["herdr"]);
    assert_eq!(harness.status_field("link_epoch"), epoch);

    // The hub sends its herdr; the dialer installs it, re-execs, and the
    // link comes back.
    let payload = update_payload(&harness);
    let mut update = harness.hub_command(&["machine", "update", LABEL, "--yes"]);
    update.env("HERDR_REMOTE_BINARY", &payload);
    let output = output_with_timeout(&mut update, UPDATE_TIMEOUT)
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    let text = stdout(&output);
    assert!(
        output.status.success(),
        "{text}\n{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        harness.diagnostics()
    );
    assert!(text.contains("Installed herdr"), "{text}");
    assert!(text.contains("reconnected with herdr"), "{text}");
    assert!(harness.status_field("link_epoch").as_u64().unwrap() > epoch);
    // The same process re-executed itself into the new file.
    assert!(harness.dialers[dialer].try_wait().unwrap().is_none());
    let running = fs::read_link(format!("/proc/{}/exe", harness.dialers[dialer].id())).unwrap();
    assert_eq!(running, fs::canonicalize(&exe).unwrap());
    let log = fs::read_to_string(&harness.dialer_logs[dialer]).unwrap();
    assert!(log.contains("restarting (updated by hub)"), "{log}");
    assert_eq!(entries(&bin), ["herdr", "herdr.prev"]);
    assert_eq!(identity(&bin.join("herdr.prev")), original);
    assert_ne!(identity(&exe).0, original.0);
    assert_eq!(fs::read(&exe).unwrap(), fs::read(&payload).unwrap());
    // The re-executed dialer serves the agent relay again.
    harness.wait_for("the agent relay to accept", LINK_TIMEOUT, || {
        UnixStream::connect(harness.agent_relay()).is_ok()
    });
}
