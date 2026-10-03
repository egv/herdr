//! End-to-end tests for dial-in machines (harness in `support::dial_in`).

#![cfg(all(unix, not(target_os = "macos")))]

pub mod support;

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::dial_in::*;
use support::wait_for_client_shell_bootstrap;

#[test]
fn dial_in_link_end_to_end() {
    let mut harness = Harness::new();
    let id = set_up_link(&mut harness);

    // (a) The slave dials in; the hub sees it connected.
    let dialer = harness.spawn_dialer();
    let first_epoch = harness.wait_connected_epoch_above(0);
    assert_eq!(first_epoch, 1);
    assert_eq!(harness.sockets_present().len(), 3);
    let row = harness.hub_list_row();
    assert_eq!(row["kind"], "dial-in", "{row}");
    assert_eq!(row["label"], LABEL, "{row}");
    assert_eq!(row["connected"], true, "{row}");
    assert_eq!(row["enabled"], true, "{row}");
    let (status, output) = harness.hub_machine_status();
    assert_eq!(
        status["status"],
        "connected",
        "{status}\n{}",
        harness.diagnostics()
    );
    assert!(output.status.success(), "{status}");
    assert!(status["server_version"].is_string(), "{status}");
    assert_eq!(status["slave"]["os"], "linux", "{status}");
    let dial_status = harness.slave_dial_status();
    assert_eq!(dial_status["state"], "connected", "{dial_status}");

    // (b) Client-shell handshakes through client.sock reach the slave server.
    let mut stream = harness
        .client_handshake()
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    wait_for_client_shell_bootstrap(&mut stream, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    // Closing an idle stream must still end its processes on both sides.
    drain_until_idle(&mut stream);
    drop(stream);
    harness.wait_streams_closed();
    assert_concurrent_handshakes(&harness, 6);

    // (c) `--machine` API commands route through api.sock.
    let panes = run_ok(harness.hub_command(&["--machine", LABEL, "pane", "list"]));
    let panes: Value = serde_json::from_slice(&panes.stdout).unwrap();
    assert!(panes["result"].is_object(), "{panes}");
    let by_id = run_ok(harness.hub_command(&["--machine", &id, "workspace", "list"]));
    let by_id: Value = serde_json::from_slice(&by_id.stdout).unwrap();
    assert!(by_id["result"].is_object(), "{by_id}");
    run_ok(harness.hub_command(&["machine", "rename", &id, "--label", "renamed"]));
    run_ok(harness.hub_command(&["--machine", "renamed", "pane", "list"]));
    let stale = run(harness.hub_command(&["--machine", LABEL, "pane", "list"]));
    assert_eq!(
        stale.status.code(),
        Some(2),
        "the old label must not resolve"
    );
    run_ok(harness.hub_command(&["machine", "rename", &id, "--label", LABEL]));
    harness.wait_streams_closed();

    // (d) A crashed dialer ends the hub link; a new one reconnects.
    harness.signal_dialer(dialer, libc::SIGKILL);
    assert!(harness
        .wait_dialer_exit(dialer, Duration::from_secs(5))
        .is_some());
    harness.wait_disconnected();
    harness.wait_for("link sockets to be removed", LINK_TIMEOUT, || {
        harness.sockets_present().is_empty()
    });
    assert_eq!(harness.status_field("last_error")["code"], "link_closed");
    assert_eq!(harness.hub_list_row()["connected"], false);
    let (status, output) = harness.hub_machine_status();
    assert_eq!(status["status"], "offline", "{status}");
    assert!(!output.status.success());
    assert_eq!(status["last_error"]["code"], "link_closed", "{status}");
    let offline = run(harness.hub_command(&["--machine", LABEL, "pane", "list"]));
    assert!(!offline.status.success());
    assert!(
        String::from_utf8_lossy(&offline.stderr).contains("is not connected"),
        "{}",
        String::from_utf8_lossy(&offline.stderr)
    );

    let dialer = harness.spawn_dialer();
    let second_epoch = harness.wait_connected_epoch_above(first_epoch);
    assert_eq!(second_epoch, first_epoch + 1);
    assert_concurrent_handshakes(&harness, 2);
    harness.wait_streams_closed();

    // (e) Disabling the machine on the hub closes the link; the dialer backs off.
    let sessions_before = harness.control_sessions();
    run_ok(harness.hub_command(&["machine", "disable", &id]));
    harness.wait_disconnected();
    assert_eq!(harness.status_field("last_error")["code"], "link_disabled");
    harness.wait_for("the dialer to back off", LINK_TIMEOUT, || {
        harness
            .dial_state()
            .is_some_and(|state| state["state"] == "backoff")
    });
    let state = harness.dial_state().unwrap();
    assert_eq!(state["last_error"]["code"], "link_disabled", "{state}");
    let next_attempt = state["next_attempt_ms"].as_u64().unwrap();
    let since = state["since_ms"].as_u64().unwrap();
    assert!(
        next_attempt >= since + 60_000,
        "a disabled link must back off for minutes: {state}"
    );
    thread::sleep(Duration::from_secs(2));
    assert_eq!(harness.control_sessions(), sessions_before);
    assert_eq!(harness.status_field("state"), "disconnected");
    assert!(harness.sockets_present().is_empty());

    // A graceful stop tears the dialer down.
    harness.signal_dialer(dialer, libc::SIGTERM);
    let exit = harness.wait_dialer_exit(dialer, Duration::from_secs(10));
    assert!(
        exit.is_some_and(|status| status.success()),
        "{exit:?}\n{}",
        harness.diagnostics()
    );
    assert_eq!(harness.dial_state().unwrap()["state"], "stopped");
    assert_eq!(harness.slave_dial_status()["state"], "stopped");
}

#[test]
fn dial_in_live_link_refuses_a_second_dialer_and_a_frozen_one_is_superseded() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    setup_dial(&harness, "other");

    let first = harness.spawn_dialer();
    assert_eq!(harness.wait_connected_epoch_above(0), 1);
    let holder_pid = harness.status_field("pid");

    // A second dialer for the same link is refused while the first answers.
    let second = harness.spawn_dialer_named("other");
    harness.wait_for("the second dialer to be refused", LINK_TIMEOUT, || {
        harness
            .dial_state_of("other")
            .is_some_and(|state| state["state"] == "backoff")
    });
    let state = harness.dial_state_of("other").unwrap();
    assert_eq!(state["last_error"]["code"], "link_busy", "{state}");
    assert_eq!(harness.status_field("state"), "connected");
    assert_eq!(harness.status_field("link_epoch"), 1);
    assert_eq!(harness.status_field("pid"), holder_pid);
    harness
        .client_handshake()
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    harness.signal_dialer(second, libc::SIGTERM);
    assert!(harness
        .wait_dialer_exit(second, Duration::from_secs(10))
        .is_some());

    // A frozen dialer no longer answers; a new dialer takes the link over.
    harness.signal_dialer(first, libc::SIGSTOP);
    let replacement = harness.spawn_dialer_named("other");
    assert_eq!(harness.wait_connected_epoch_above(1), 2);
    assert_ne!(harness.status_field("pid"), holder_pid);
    assert_eq!(harness.sockets_present().len(), 3);
    harness
        .client_handshake()
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));

    // The thawed dialer learns it was replaced and cannot take the link back.
    harness.signal_dialer(first, libc::SIGCONT);
    harness.wait_for(
        "the replaced dialer to be refused as busy",
        Duration::from_secs(45),
        || {
            harness.dial_state().is_some_and(|state| {
                state["state"] == "backoff" && state["last_error"]["code"] == "link_busy"
            })
        },
    );
    assert_eq!(harness.status_field("state"), "connected");
    assert_eq!(harness.status_field("link_epoch"), 2);
    assert!(harness.dialers[replacement].try_wait().unwrap().is_none());
    harness
        .client_handshake()
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
}

#[test]
fn dial_in_api_works_as_soon_as_the_link_is_connected() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    // No slave server runs yet: the first API stream races its startup.
    harness.spawn_dialer();
    let deadline = Instant::now() + LINK_TIMEOUT;
    while harness.status_field("state") != "connected" {
        assert!(Instant::now() < deadline, "{}", harness.diagnostics());
        thread::sleep(Duration::from_millis(2));
    }
    let response = raw_api_request(&harness, r#"{"id":"first","method":"ping","params":{}}"#)
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    assert_eq!(response["result"]["type"], "pong", "{response}");
    let output = run(harness.hub_command(&["--machine", LABEL, "pane", "list"]));
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        harness.diagnostics()
    );
}

#[test]
fn dial_in_hub_tui_federates_the_machine_and_reconnects_when_it_dials_in_again() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    let dialer = harness.spawn_dialer();
    assert_eq!(harness.wait_connected_epoch_above(0), 1);

    // No hub server runs: the TUI keeps saved machines available without Local.
    let tui = HubTui::spawn(&harness);
    harness.wait_for(
        "the hub TUI to attach to the dial-in machine",
        LINK_TIMEOUT,
        || harness.slave_client_bridges() >= 1,
    );
    thread::sleep(Duration::from_secs(1));
    assert!(
        harness.slave_client_bridges() >= 1,
        "the hub TUI stream must stay attached\n{}",
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
    // Let the TUI notice the failure and fall into its retry backoff.
    thread::sleep(Duration::from_secs(3));

    harness.spawn_dialer();
    assert_eq!(harness.wait_connected_epoch_above(1), 2);
    let reconnect_started = Instant::now();
    harness.wait_for(
        "the hub TUI to reattach after the machine dialed in again",
        LINK_TIMEOUT,
        || harness.slave_client_bridges() >= 1,
    );
    let reconnect = reconnect_started.elapsed();
    assert!(
        reconnect < Duration::from_secs(5),
        "the TUI must reconnect on the new link epoch, not on its retry timer: {reconnect:?}\n{}",
        harness.diagnostics()
    );
    drop(tui);
}

#[test]
fn dial_in_reports_why_the_machine_refused_a_stream() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);
    run_ok(harness.hub_command(&["--machine", LABEL, "pane", "list"]));

    // The link stays up, but the machine's server is gone: API streams fail
    // on the slave and the hub reports the slave's reason.
    run_ok(harness.slave_command(&["server", "stop"]));
    harness.wait_for("the slave server to stop", LINK_TIMEOUT, || {
        !harness
            .slave
            .config()
            .join(app_dir())
            .join("herdr.sock")
            .exists()
    });
    let output = run(harness.hub_command(&["--machine", LABEL, "pane", "list"]));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the machine reported") && stderr.contains("remote Herdr API socket"),
        "{stderr}\n{}",
        harness.diagnostics()
    );
    harness.wait_for("the stream error to be recorded", LINK_TIMEOUT, || {
        harness.status_field("last_stream_error")["code"] == "bridge_failed"
    });

    let (status, output) = harness.hub_machine_status();
    assert!(!output.status.success());
    assert_eq!(status["status"], "server unavailable", "{status}");
    let error = status["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("the machine reported") && error.contains("remote Herdr API socket"),
        "{status}"
    );
    assert_eq!(harness.status_field("state"), "connected");
}

#[test]
fn dial_in_reports_streams_the_hub_could_not_attach_without_starting_a_bridge() {
    use std::io::Write as _;

    let mut harness = Harness::new();
    set_up_link(&mut harness);
    harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);

    // The link holder keeps serving, but the hub's stream acceptor refuses
    // a link directory that is no longer private, so the attach fails on
    // the hub after its ready marker.
    let link_dir = harness.link_dir();
    fs::set_permissions(&link_dir, fs::Permissions::from_mode(0o750)).unwrap();
    let mut stream = UnixStream::connect(link_dir.join("client.sock")).unwrap();
    // Hub clients speak first.
    stream.write_all(b"hello").unwrap();
    harness.wait_for("the refused attach to be recorded", LINK_TIMEOUT, || {
        harness.status_field("last_stream_error")["code"] == "ssh_failed"
    });
    let message = harness.status_field("last_stream_error")["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    fs::set_permissions(&link_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        message.contains("not private"),
        "{message}\n{}",
        harness.diagnostics()
    );
    assert!(
        !message.contains(&*link_dir.to_string_lossy()),
        "hub paths must not reach the dialing machine: {message}"
    );
    // The slave never started a bridge for the refused stream.
    assert_eq!(harness.slave_client_bridges(), 0);
    drop(stream);
    assert_eq!(harness.status_field("state"), "connected");
}

#[test]
fn dial_in_hub_acceptor_stopped_by_a_signal_records_the_disconnect() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    harness.spawn_dialer();
    let epoch = harness.wait_connected_epoch_above(0);
    let pid = harness.status_field("pid").as_u64().expect("holder pid") as libc::pid_t;

    // A hub shutdown terminates the acceptor: it must not leave a stale
    // `connected` status or socket files behind.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    harness.wait_for("the stopped acceptor to record it", LINK_TIMEOUT, || {
        harness.status_field("state") == "disconnected"
            && harness.status_field("last_error")["code"] == "acceptor_stopped"
            && harness.sockets_present().is_empty()
    });
    // The machine dials in again by itself.
    harness.wait_connected_epoch_above(epoch);
}

#[test]
fn dial_in_named_session_and_graceful_stop_with_open_streams() {
    let mut harness = Harness::new();
    set_up_link_with(&mut harness, &["--remote-session", "work"]);
    let dialer = harness.spawn_dialer();
    harness.wait_connected_epoch_above(0);

    let panes = run_ok(harness.hub_command(&["--machine", LABEL, "pane", "list"]));
    let panes: Value = serde_json::from_slice(&panes.stdout).unwrap();
    assert!(panes["result"].is_object(), "{panes}");
    let work_socket = harness
        .slave
        .config()
        .join(app_dir())
        .join("sessions/work/herdr.sock");
    assert!(work_socket.exists(), "the work session server must run");
    assert!(!harness
        .slave
        .config()
        .join(app_dir())
        .join("herdr.sock")
        .exists());

    let mut stream = harness
        .client_handshake()
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));
    wait_for_client_shell_bootstrap(&mut stream, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("{error}\n{}", harness.diagnostics()));

    // A graceful stop with a stream open ends every process on both sides.
    harness.signal_dialer(dialer, libc::SIGTERM);
    let exit = harness.wait_dialer_exit(dialer, Duration::from_secs(15));
    assert!(
        exit.is_some_and(|status| status.success()),
        "{exit:?}\n{}",
        harness.diagnostics()
    );
    harness.wait_disconnected();
    assert!(harness.sockets_present().is_empty());
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(_) => assert!(Instant::now() < deadline, "the hub stream stayed open"),
        }
    }
    harness.wait_streams_closed();
    harness.wait_for("fake ssh processes to exit", LINK_TIMEOUT, || {
        fake_ssh_processes(&harness).is_empty()
    });
    assert_eq!(harness.dial_state().unwrap()["state"], "stopped");
    assert!(
        work_socket.exists(),
        "the dialer must leave the server running"
    );
}

#[test]
fn dial_in_refusals_back_off_with_actionable_errors() {
    let mut harness = Harness::new();
    let id = set_up_link(&mut harness);
    let wait_refused = |harness: &mut Harness, dialer: usize, code: &str| {
        harness.wait_for(
            &format!("the dialer to back off with {code}"),
            LINK_TIMEOUT,
            || {
                harness.dial_state().is_some_and(|state| {
                    state["state"] == "backoff" && state["last_error"]["code"] == code
                })
            },
        );
        let state = harness.dial_state().unwrap();
        let next_attempt = state["next_attempt_ms"].as_u64().unwrap();
        let since = state["since_ms"].as_u64().unwrap();
        assert!(
            next_attempt >= since + 60_000,
            "{code} must back off for minutes: {state}"
        );
        harness.signal_dialer(dialer, libc::SIGTERM);
        assert!(harness
            .wait_dialer_exit(dialer, Duration::from_secs(10))
            .is_some_and(|status| status.success()));
        fs::read_to_string(&harness.dialer_logs[dialer]).unwrap()
    };

    // The hub does not accept the key yet.
    fs::write(harness.root.join("refuse-key"), "").unwrap();
    let dialer = harness.spawn_dialer();
    let log = wait_refused(&mut harness, dialer, "authentication_failed");
    let (key_line, _) = test_public_key_line();
    assert!(
        log.contains(&format!(
            "herdr machine authorize {id} '{key_line}' --write"
        )) && log.contains(&format!(
            "herdr machine dial setup {DIAL_NAME} --hub {HUB_TARGET} --pair"
        )),
        "{log}"
    );
    fs::remove_file(harness.root.join("refuse-key")).unwrap();

    // The key is authorized for another machine's link.
    let forced = fs::read_to_string(harness.root.join("forced-command")).unwrap();
    let other_id = "0123456789abcdef0123456789abcdef";
    assert_ne!(id, other_id);
    fs::write(
        harness.root.join("forced-command"),
        forced.replace(&id, other_id),
    )
    .unwrap();
    let dialer = harness.spawn_dialer();
    wait_refused(&mut harness, dialer, "link_id_mismatch");
    fs::write(harness.root.join("forced-command"), &forced).unwrap();

    // The machine was removed on the hub.
    run_ok(harness.hub_command(&["machine", "remove", &id]));
    let dialer = harness.spawn_dialer();
    let log = wait_refused(&mut harness, dialer, "link_unknown");
    assert!(log.contains("herdr machine list"), "{log}");
    assert!(harness.read_status().is_none());
    assert!(harness.sockets_present().is_empty());
}

#[test]
fn dial_in_adds_ssh_masters_when_the_hub_refuses_more_sessions() {
    let mut harness = Harness::new();
    set_up_link(&mut harness);
    // Three sessions per master: the control session and two streams.
    harness.spawn_dialer_with(DIAL_NAME, &[("FAKE_MAX_SESSIONS", "3")]);
    harness.wait_connected_epoch_above(0);
    run_ok(harness.hub_command(&["--machine", LABEL, "pane", "list"]));

    let mut streams = Vec::new();
    for index in 0..6 {
        let stream = harness.client_handshake().unwrap_or_else(|error| {
            panic!(
                "held stream {index} failed: {error}\n{}",
                harness.diagnostics()
            )
        });
        streams.push(stream);
    }
    let log = harness.ssh_log();
    let masters = log
        .lines()
        .filter(|line| line.starts_with("master "))
        .count();
    assert!(masters >= 3, "expected extra masters:\n{log}");
    assert!(log.contains("refused "), "{log}");
    assert_eq!(harness.status_field("state"), "connected");
    drop(streams);
    harness.wait_streams_closed();
    // Freed sessions are reused.
    assert_concurrent_handshakes(&harness, 2);
}

#[test]
fn dial_in_fake_ssh_runs_plain_sessions_on_the_hub() {
    use std::io::Write as _;

    let mut harness = Harness::new();
    let id = set_up_link(&mut harness);
    let herdr_dir = Path::new(herdr_bin()).parent().unwrap();
    let mut list = harness.slave_ssh(&["-T", HUB_TARGET, "herdr", "machine", "list", "--json"]);
    list.env(
        "FAKE_HUB_PATH",
        format!("{}:/usr/bin:/bin", herdr_dir.display()),
    );
    let listed = stdout(&run_ok(list));
    assert!(listed.contains(&id), "{listed}");
    assert!(harness
        .ssh_log()
        .contains("plain herdr machine list --json"));

    let mut cat = harness
        .slave_ssh(&[HUB_TARGET, "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    cat.stdin.take().unwrap().write_all(b"key line\n").unwrap();
    assert_eq!(cat.wait_with_output().unwrap().stdout, b"key line\n");
}
