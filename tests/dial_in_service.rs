//! End-to-end tests for unattended dial-in operation (harness in
//! `support::dial_in`): restarting into a replaced binary and stopping ssh
//! masters that a killed dialer left behind.

#![cfg(all(unix, not(target_os = "macos")))]

pub mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use support::dial_in::*;

/// `herdr machine dial run` from `exe` with the slave environment.
fn spawn_dialer_from(harness: &mut Harness, exe: &Path) -> usize {
    let template = harness.slave_command(&[]);
    let mut command = Command::new(exe);
    command
        .args(["machine", "dial", "run", DIAL_NAME])
        .env_clear();
    for (name, value) in template.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    let log = harness
        .root
        .join(format!("dialer-{}.log", harness.dialer_logs.len()));
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

/// Puts the test binary at `path` the way upgrades do: a new file (inode)
/// renamed over the old one. Hard-links when possible to save disk space.
fn install_herdr(path: &Path, copy: bool) {
    let staged = path.with_extension("new");
    if copy || fs::hard_link(herdr_bin(), &staged).is_err() {
        fs::copy(herdr_bin(), &staged).unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::rename(&staged, path).unwrap();
}

fn exe_of(pid: u32) -> PathBuf {
    fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default()
}

/// Drops the hub side of the link: the redial must first notice the new
/// binary and replace the dialer (same pid) with `expected`, then dial in.
fn redial_into(harness: &Harness, pid: u32, epoch: u64, expected: &Path) -> u64 {
    let holder = harness.status_field("pid").as_u64().expect("holder pid") as libc::pid_t;
    unsafe {
        libc::kill(holder, libc::SIGTERM);
    }
    let epoch = harness.wait_connected_epoch_above(epoch);
    harness.wait_for("the dialer to run the new binary", LINK_TIMEOUT, || {
        exe_of(pid) == expected
    });
    epoch
}

#[test]
fn dial_in_dialer_restarts_into_a_replaced_binary() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    // The dialer runs through a stable launcher symlink, as Homebrew, Nix,
    // and the service units start it.
    let bin = harness.root.join("slave-bin");
    fs::create_dir_all(&bin).unwrap();
    install_herdr(&bin.join("herdr-1"), false);
    let launcher = bin.join("herdr");
    std::os::unix::fs::symlink("herdr-1", &launcher).unwrap();
    let dialer = spawn_dialer_from(&mut harness, &launcher);
    let pid = harness.dialers[dialer].id();
    let epoch = harness.wait_connected_epoch_above(0);
    assert_eq!(exe_of(pid), bin.join("herdr-1"));

    // A package upgrade points the launcher at a new version.
    install_herdr(&bin.join("herdr-2"), true);
    std::os::unix::fs::symlink("herdr-2", bin.join("herdr.new")).unwrap();
    fs::rename(bin.join("herdr.new"), &launcher).unwrap();
    let epoch = redial_into(&harness, pid, epoch, &bin.join("herdr-2"));

    // An in-place upgrade replaces the file: the running image is deleted.
    install_herdr(&bin.join("herdr-2"), false);
    assert!(exe_of(pid).to_string_lossy().ends_with(" (deleted)"));
    redial_into(&harness, pid, epoch, &bin.join("herdr-2"));

    assert!(
        matches!(harness.dialers[dialer].try_wait(), Ok(None)),
        "the dialer must keep running\n{}",
        harness.diagnostics()
    );
    let log = fs::read_to_string(&harness.dialer_logs[dialer]).unwrap();
    assert_eq!(log.matches("was updated").count(), 2, "{log}");
    assert_eq!(
        log.matches("restarting (binary updated)").count(),
        2,
        "{log}"
    );
    assert_eq!(
        log.matches("dialing fakehub").count(),
        3,
        "one start per process image: {log}"
    );
}

#[test]
fn dial_in_dialer_stops_ssh_masters_a_killed_run_left_behind() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    // A master as a SIGKILLed dialer leaves it: connected, owned by nobody.
    let ctl = harness
        .slave
        .state()
        .join(app_dir())
        .join("dial")
        .join(DIAL_NAME)
        .join("ctl-1");
    let control_path = format!("ControlPath={}", ctl.display());
    let mut orphan = harness
        .slave_ssh(&[
            "-o",
            "ControlMaster=yes",
            "-o",
            &control_path,
            "-N",
            HUB_TARGET,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    harness.wait_for("the orphan master", COMMAND_TIMEOUT, || ctl.exists());

    let dialer = harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);
    harness.wait_for("the orphan master to exit", COMMAND_TIMEOUT, || {
        matches!(orphan.try_wait(), Ok(Some(_)))
    });
    assert!(!ctl.exists());
    let ssh_log = harness.ssh_log();
    let lines: Vec<&str> = ssh_log.lines().collect();
    assert_eq!(
        lines[..3],
        ["master fakehub", "exit fakehub", "master fakehub"],
        "the orphan is stopped before the first attempt:\n{ssh_log}"
    );
    let log = fs::read_to_string(&harness.dialer_logs[dialer]).unwrap();
    assert!(
        log.contains("stopped 1 ssh master connection(s) left by an earlier run"),
        "{log}"
    );
    let _ = orphan.kill();
    let _ = orphan.wait();
}
