//! Slave side of the hub-driven update: receives an update stream into a
//! temporary file next to the launch executable, verifies and self-tests it,
//! installs it (keeping `<exe>.prev` for probation rollback), and asks the
//! dialer to re-exec; also serves `RestartServer`.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::control::LoopEvent;
use super::process::{
    kill_and_reap, prewarm_sessions, run_quick, wait_child_until, CLEARED_CHILD_ENV,
};
use super::reexec::ReexecRequest;
use super::stderr_line;
use crate::remote::link::dial_config;
use crate::remote::link::herdr_path::path_looks_versioned;
use crate::remote::link::protocol::{self, local_code, ControlMessage, OpenRequest, UpdateResult};
use crate::remote::link::status::{now_ms, ErrorRecord};

/// The probation record in the dial directory (see [`ProbationRecord`]).
const PROBATION_FILE: &str = "probation.json";
/// Set for the dialer re-executed after a rollback: what happened, kept as
/// its last error. Never passed on to the dialer's children.
pub(super) const ROLLED_BACK_ENV: &str = "HERDR_DIAL_ROLLED_BACK";
const ROLLED_BACK_CODE: &str = "update_rolled_back";
/// Prefix of the temporary file an update is received into.
const UPDATE_TEMP_PREFIX: &str = ".herdr-update-";
const PROBATION: Duration = Duration::from_secs(5 * 60);
const PROBATION_POLL: Duration = Duration::from_secs(1);
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_VERSION_OUTPUT_BYTES: u64 = 256;
const MAX_PROBE_OUTPUT_BYTES: u64 = 64 * 1024;

/// The dial-in link an update is for: the received executable must be able
/// to run it.
pub(super) struct DialLink<'a> {
    pub(super) name: &'a str,
    pub(super) link_id: &'a str,
}

/// An installed update: the backup of the replaced executable and the
/// SHA-256 of the executable that replaced it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Installed {
    backup: PathBuf,
    sha256: String,
}

/// Why an update was not installed.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    code: &'static str,
    message: String,
}

fn rejected(message: impl Into<String>) -> Refusal {
    Refusal {
        code: local_code::UPDATE_REJECTED,
        message: message.into(),
    }
}

fn failed(message: impl Into<String>) -> Refusal {
    Refusal {
        code: local_code::UPDATE_FAILED,
        message: message.into(),
    }
}

/// Removes the temporary update file on every way out of an update.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Removes update files next to `exe` that a dialer exiting mid-update left
/// behind (its [`TempFile`] was never dropped). Another dialer's update in
/// progress at that moment fails and can be retried. Only names of the
/// update file shape match (`herdr update` stages other names there).
pub(super) fn remove_stale_update_files(exe: &Path) {
    let Some(entries) = exe.parent().and_then(|dir| fs::read_dir(dir).ok()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix(UPDATE_TEMP_PREFIX))
            .is_some_and(protocol::is_valid_nonce)
            && entry.file_type().is_ok_and(|kind| kind.is_file())
            && crate::platform::file_is_owned_by_current_user(&path).unwrap_or(false);
        if stale && fs::remove_file(&path).is_ok() {
            tracing::info!(path = %path.display(), "dial removed an interrupted update");
        }
    }
}

/// Serves one update stream: installs the executable that follows (after
/// `leftover`) over `exe`, then writes the result line to `output` and
/// closes it. Returns what was installed.
pub(super) fn serve_update(
    exe: &Path,
    link: &DialLink<'_>,
    request: &OpenRequest,
    input: &mut impl Read,
    leftover: &[u8],
    mut output: impl Write,
) -> Option<Installed> {
    let installed = install_update(exe, link, request, input, leftover);
    let result = match &installed {
        Ok((version, _)) => {
            stderr_line(format_args!(
                "herdr dial: the hub installed herdr {version}; restarting"
            ));
            UpdateResult {
                ok: true,
                code: None,
                message: None,
                version: Some(version.clone()),
            }
        }
        Err(refusal) => {
            tracing::warn!(
                code = refusal.code,
                "dial refused a hub update: {}",
                refusal.message
            );
            UpdateResult {
                ok: false,
                code: Some(refusal.code.to_string()),
                message: Some(refusal.message.clone()),
                version: None,
            }
        }
    };
    if let Err(error) = protocol::write_json_line(&mut output, &result) {
        tracing::warn!(%error, "dial could not report the update result to the hub");
    }
    installed.ok().map(|(_, installed)| installed)
}

/// Receives, verifies, self-tests and installs the update; returns the
/// version it reports and what was installed.
fn install_update(
    exe: &Path,
    link: &DialLink<'_>,
    request: &OpenRequest,
    input: &mut impl Read,
    leftover: &[u8],
) -> Result<(String, Installed), Refusal> {
    let (Some(size), Some(sha256)) = (request.size, request.sha256.as_deref()) else {
        return Err(rejected("the update carries no size or checksum"));
    };
    protocol::check_update_request(size, sha256, request.version.as_deref()).map_err(rejected)?;
    check_install_target(exe)?;
    let temp = TempFile(exe.with_file_name(format!("{UPDATE_TEMP_PREFIX}{}", request.nonce)));
    receive(&temp.0, input, leftover, size)?;
    crate::checksum::verify_sha256(&temp.0, sha256)
        .map_err(|error| rejected(format!("the received executable is corrupt: {error}")))?;
    let permissions = fs::metadata(exe)
        .map_err(|error| failed(format!("cannot inspect {}: {error}", exe.display())))?
        .permissions();
    fs::set_permissions(&temp.0, permissions)
        .map_err(|error| failed(format!("cannot make the update executable: {error}")))?;
    let version = reported_version(&temp.0)
        .ok_or_else(|| failed("the received executable failed its `--version` self-test"))?;
    // Probation and rollback live in the new executable's dialer: one that
    // cannot run this link would exit before them and never roll back.
    if !runs_dial_link(&temp.0, link) {
        return Err(rejected(format!(
            "the received executable cannot run this dial-in link (`herdr machine dial status {} --json` failed); it may be a Herdr build without dial-in support",
            link.name
        )));
    }
    let backup = backup_path(exe);
    let _ = fs::remove_file(&backup);
    if fs::hard_link(exe, &backup).is_err() {
        fs::copy(exe, &backup).map_err(|error| {
            failed(format!(
                "cannot back up {} to {}: {error}",
                exe.display(),
                backup.display()
            ))
        })?;
    }
    crate::platform::replace_file(&temp.0, exe)
        .map_err(|error| failed(format!("cannot replace {}: {error}", exe.display())))?;
    Ok((
        version,
        Installed {
            backup,
            sha256: sha256.to_ascii_lowercase(),
        },
    ))
}

/// Refuses executables a package manager owns, and anything but a file.
fn check_install_target(exe: &Path) -> Result<(), Refusal> {
    if path_looks_versioned(exe) || crate::update::is_package_manager_managed_exe_path(exe) {
        return Err(rejected(format!(
            "{} is managed by a package manager; update Herdr on that machine with it",
            exe.display()
        )));
    }
    match fs::symlink_metadata(exe) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(rejected(format!("{} is not a regular file", exe.display()))),
        Err(error) => Err(rejected(format!(
            "cannot inspect {}: {error}",
            exe.display()
        ))),
    }
}

/// Writes exactly `size` bytes (`leftover` first) to a new private `path`.
fn receive(path: &Path, input: &mut impl Read, leftover: &[u8], size: u64) -> Result<(), Refusal> {
    if leftover.len() as u64 > size {
        return Err(failed("the hub sent more bytes than the update announced"));
    }
    let mut file = crate::platform::create_private_state_file(path).map_err(|error| {
        rejected(format!(
            "cannot write next to the Herdr executable ({}): {error}",
            path.parent().unwrap_or(path).display()
        ))
    })?;
    let received = io::copy(&mut leftover.chain(input).take(size), &mut file)
        .map_err(|error| failed(format!("receiving the update failed: {error}")))?;
    if received < size {
        return Err(failed(format!(
            "the update stream ended after {received} of {size} bytes"
        )));
    }
    file.sync_all()
        .map_err(|error| failed(format!("cannot store the update: {error}")))
}

fn backup_path(exe: &Path) -> PathBuf {
    let mut path = exe.as_os_str().to_owned();
    path.push(".prev");
    PathBuf::from(path)
}

/// The stdout (at most `max_bytes`) of `command` when it succeeds within
/// the self-test timeout.
fn self_test_output(mut command: Command, max_bytes: u64) -> Option<Vec<u8>> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().ok()?;
    let Some(status) = wait_child_until(&mut child, Instant::now() + SELF_TEST_TIMEOUT) else {
        kill_and_reap(&mut child);
        return None;
    };
    let mut output = Vec::new();
    child
        .stdout
        .take()?
        .take(max_bytes)
        .read_to_end(&mut output)
        .ok()?;
    status.success().then_some(output)
}

/// What `<path> --version` reports (`herdr <version>`) within the self-test
/// timeout, if it succeeds.
fn reported_version(path: &Path) -> Option<String> {
    let mut command = Command::new(path);
    command.arg("--version");
    let output = String::from_utf8(self_test_output(command, MAX_VERSION_OUTPUT_BYTES)?).ok()?;
    let version = output.trim().strip_prefix("herdr ")?;
    protocol::is_valid_update_version(version).then(|| version.to_string())
}

/// Whether the executable at `path` can run `link`: its `machine dial status
/// <name> --json` must report this link, read from this machine's dial-in
/// configuration and state, without errors. This refuses builds without
/// dial-in support and builds that cannot read the link's configuration.
fn runs_dial_link(path: &Path, link: &DialLink<'_>) -> bool {
    #[derive(Deserialize)]
    struct Probe {
        name: String,
        link_id: Option<String>,
        error: Option<String>,
    }
    let mut command = Command::new(path);
    command.args(["machine", "dial", "status", link.name, "--json"]);
    for name in CLEARED_CHILD_ENV {
        command.env_remove(name);
    }
    let Some(output) = self_test_output(command, MAX_PROBE_OUTPUT_BYTES) else {
        return false;
    };
    serde_json::from_slice::<Probe>(&output).is_ok_and(|probe| {
        probe.name == link.name
            && probe.link_id.as_deref() == Some(link.link_id)
            && probe.error.is_none()
    })
}

/// Whether `exe` is still the executable an update installed with
/// `sha256`; not after something else (`herdr update`) replaced it.
fn is_installed_update(exe: &Path, sha256: &str) -> bool {
    crate::checksum::file_sha256(exe).is_ok_and(|actual| actual.eq_ignore_ascii_case(sha256))
}

/// An installed update on probation, recorded in the dial directory so that
/// it outlives the dialer: unless a dialer reaches `connected` by
/// `deadline_ms`, `backup` is restored over the executable, also when the
/// update exited or crashed and was started again. Only while the
/// executable is still that update (`sha256`).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProbationRecord {
    backup: PathBuf,
    sha256: String,
    deadline_ms: u64,
}

/// Records the probation of `installed` in `file`, then re-execs the dialer
/// into that update.
pub(super) fn restart_into_update(reexec: &ReexecRequest, file: &Path, installed: &Installed) {
    let record = ProbationRecord {
        backup: installed.backup.clone(),
        sha256: installed.sha256.clone(),
        deadline_ms: now_ms().saturating_add(PROBATION.as_millis() as u64),
    };
    let written = serde_json::to_vec(&record)
        .map_err(io::Error::other)
        .and_then(|content| dial_config::write_private_file(file, &content, true));
    if let Err(error) = written {
        tracing::warn!(%error, "dial could not record the update probation");
    }
    reexec.request("updated by hub", Vec::new());
}

/// The environment of a re-exec: `requested`, and the rollback note removed
/// unless requested, so it never outlives the process it was for.
pub(super) fn reexec_env(requested: &[(String, Option<String>)]) -> Vec<(String, Option<String>)> {
    let mut env = requested.to_vec();
    if !env.iter().any(|(set, _)| set == ROLLED_BACK_ENV) {
        env.push((ROLLED_BACK_ENV.to_string(), None));
    }
    env
}

/// The rollback this process was re-executed after, as its last error.
pub(super) fn rolled_back_error() -> Option<ErrorRecord> {
    let note = std::env::var_os(ROLLED_BACK_ENV)?;
    Some(ErrorRecord::new(ROLLED_BACK_CODE, &note.to_string_lossy()))
}

/// The probation recorded in `file` and its remaining time: the record must
/// name `<exe>.prev`, that file must exist, and `exe` must still be the
/// update the record is for.
fn probation_backup(exe: &Path, file: &Path, now_ms: u64) -> Option<(ProbationRecord, Duration)> {
    let content = dial_config::read_private_file(file).ok().flatten()?;
    let record: ProbationRecord = serde_json::from_slice(&content).ok()?;
    (record.backup == backup_path(exe)
        && record.backup.is_file()
        && is_installed_update(exe, &record.sha256))
    .then(|| {
        let remaining = Duration::from_millis(record.deadline_ms.saturating_sub(now_ms));
        (record, remaining.min(PROBATION))
    })
}

/// The probation of an installed hub update: unless the link reaches
/// `connected` in time, the backup is restored over the executable and the
/// dialer re-execs into it.
pub(super) struct Probation {
    /// The record in the dial directory, removed once connected.
    file: PathBuf,
    connected: Arc<AtomicBool>,
}

impl Probation {
    /// Resumes the probation recorded in the dial directory `dir`, if any.
    pub(super) fn start(exe: &Path, dir: &Path, reexec: ReexecRequest) -> Self {
        let file = dir.join(PROBATION_FILE);
        let connected = Arc::new(AtomicBool::new(false));
        match probation_backup(exe, &file, now_ms()) {
            Some((record, remaining)) => {
                let (exe, flag) = (exe.to_path_buf(), Arc::clone(&connected));
                let record_file = file.clone();
                let spawned = thread::Builder::new()
                    .name("herdr-dial-probation".into())
                    .spawn(move || {
                        watch_probation(&exe, &record, &record_file, remaining, &flag, &reexec)
                    });
                if let Err(error) = spawned {
                    tracing::warn!(%error, "dial could not start its update probation");
                }
            }
            // A stale or foreign record, or the update was replaced since.
            None => {
                let _ = fs::remove_file(&file);
            }
        }
        Self { file, connected }
    }

    /// Where an update installed by this dialer records its probation.
    pub(super) fn file(&self) -> &Path {
        &self.file
    }

    /// The link reached `connected`: an installed update stays.
    pub(super) fn connected(&self) {
        if !self.connected.swap(true, Ordering::SeqCst) {
            let _ = fs::remove_file(&self.file);
        }
    }
}

fn watch_probation(
    exe: &Path,
    record: &ProbationRecord,
    record_file: &Path,
    remaining: Duration,
    connected: &AtomicBool,
    reexec: &ReexecRequest,
) {
    let deadline = Instant::now() + remaining;
    while !connected.load(Ordering::SeqCst) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // Something else replaced the update meanwhile: it stays.
            if !is_installed_update(exe, &record.sha256) {
                let _ = fs::remove_file(record_file);
                return;
            }
            roll_back(exe, &record.backup, record_file, reexec);
            return;
        }
        thread::sleep(remaining.min(PROBATION_POLL));
    }
}

fn roll_back(exe: &Path, backup: &Path, record: &Path, reexec: &ReexecRequest) {
    let _ = fs::remove_file(record);
    let note = format!(
        "herdr {} installed by the hub did not connect within {} minutes; the previous executable was restored",
        crate::build_info::version(),
        PROBATION.as_secs() / 60
    );
    if let Err(error) = crate::platform::replace_file(backup, exe) {
        tracing::warn!(%error, "dial could not roll back the hub update");
        stderr_line(format_args!(
            "herdr dial: the hub update did not connect, and restoring {} failed: {error}",
            backup.display()
        ));
        return;
    }
    stderr_line(format_args!("herdr dial: {note}"));
    reexec.request(
        "update rolled back",
        vec![(ROLLED_BACK_ENV.to_string(), Some(note))],
    );
}

/// Serves `RestartServer` on a worker thread: stops the server of `session`
/// (bounded) and starts it again like the prewarm, with the agent relay when
/// one is bound; the result goes to the hub through `events`.
pub(super) fn spawn_restart(
    exe: PathBuf,
    agent: Option<PathBuf>,
    request_id: String,
    session: String,
    events: SyncSender<LoopEvent>,
) {
    let failure_id = request_id.clone();
    let failure_events = events.clone();
    let spawned = thread::Builder::new()
        .name("herdr-dial-restart".into())
        .spawn(move || {
            let (ok, message) = restart_server(&exe, agent.as_deref(), &session);
            let _ = events.send(LoopEvent::Send(ControlMessage::RestartServerResult {
                request_id,
                ok,
                message,
            }));
        });
    if let Err(error) = spawned {
        // On the control loop thread, which drains the queue: never block.
        let _ = failure_events.try_send(LoopEvent::Send(ControlMessage::RestartServerResult {
            request_id: failure_id,
            ok: false,
            message: format!("the dialing machine could not start the restart: {error}"),
        }));
    }
}

fn restart_server(exe: &Path, agent: Option<&Path>, session: &str) -> (bool, String) {
    if crate::session::validate_name(session).is_err() {
        return (false, "invalid session name".into());
    }
    let mut stop = Command::new(exe);
    if session != crate::session::DEFAULT_SESSION_NAME {
        stop.args(["--session", session]);
    }
    stop.args(["server", "stop"]);
    for name in CLEARED_CHILD_ENV {
        stop.env_remove(name);
    }
    let stopped = run_quick(stop, SERVER_STOP_TIMEOUT);
    prewarm_sessions(exe, &[session.to_string()], agent, &AtomicBool::new(false));
    tracing::info!(%session, stopped, "dial restarted a server for the hub");
    if stopped {
        (true, format!("restarted the server of session {session}"))
    } else {
        let message = format!("could not stop the server of session {session} (it may not have been running); it was started again");
        (false, message)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn scratch(name: &str) -> PathBuf {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "herdr-dial-update-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const LINK_ID: &str = "0123456789abcdef0123456789abcdef";
    const LINK: DialLink<'static> = DialLink {
        name: "work",
        link_id: LINK_ID,
    };

    /// A stand-in executable running `body`.
    fn script(body: &str) -> Vec<u8> {
        format!("#!/bin/sh\n{body}\n").into_bytes()
    }

    /// A stand-in Herdr `version` that answers `machine dial status work
    /// --json` with `status`.
    fn herdr_script(version: &str, status: &str) -> Vec<u8> {
        script(&format!(
            "if [ \"$*\" = '--version' ]; then echo 'herdr {version}'; \
             elif [ \"$*\" = 'machine dial status work --json' ]; then echo '{status}'; \
             else exit 2; fi"
        ))
    }

    fn status_json(link_id: &str) -> String {
        format!(
            r#"{{"name":"work","dir":"/d","link_id":"{link_id}","running":true,"state":"connected"}}"#
        )
    }

    /// A stand-in for this version of Herdr, which can run the link.
    fn dial_script(version: &str) -> Vec<u8> {
        herdr_script(version, &status_json(LINK_ID))
    }

    fn install(exe: &Path, payload: &[u8], sha256: &str) -> Result<(String, Installed), Refusal> {
        let request = OpenRequest {
            size: Some(payload.len() as u64),
            sha256: Some(sha256.to_string()),
            version: Some("9.9.9".into()),
            ..OpenRequest::stream(NONCE.into(), protocol::StreamKind::Update, String::new())
        };
        // Some bytes arrive with the marker, the rest from the stream.
        let (leftover, rest) = payload.split_at(payload.len().min(5));
        install_update(
            exe,
            &LINK,
            &request,
            &mut io::Cursor::new(rest.to_vec()),
            leftover,
        )
    }

    fn sha256_of(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn installed_exe(dir: &Path) -> PathBuf {
        let exe = dir.join("herdr");
        fs::write(&exe, script("echo 'herdr 1.0.0'")).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        exe
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
    fn a_verified_update_replaces_the_executable_and_keeps_a_backup() {
        let dir = scratch("ok");
        let exe = installed_exe(&dir);
        let old = fs::read(&exe).unwrap();
        let new = dial_script("9.9.9");
        let (version, installed) = install(&exe, &new, &sha256_of(&new)).unwrap();
        assert_eq!(version, "9.9.9");
        assert_eq!(
            installed,
            Installed {
                backup: dir.join("herdr.prev"),
                sha256: sha256_of(&new),
            }
        );
        let backup = installed.backup;
        assert_eq!(fs::read(&exe).unwrap(), new);
        assert_eq!(fs::read(&backup).unwrap(), old);
        assert_eq!(
            fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(entries(&dir), ["herdr", "herdr.prev"]);
        assert_eq!(reported_version(&exe).as_deref(), Some("9.9.9"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_updates_leave_the_executable_and_no_temporary_files() {
        let dir = scratch("refused");
        let exe = installed_exe(&dir);
        let old = fs::read(&exe).unwrap();
        let new = dial_script("9.9.9");
        let broken = script("exit 3");
        let silent = script("echo 'not herdr'");
        // Version checks pass, but the link cannot run: a build without
        // dial-in support, one that does not know this link, one that
        // reports a problem with it, and one that prints no status.
        let no_dial = script("if [ \"$1\" = --version ]; then echo 'herdr 9.9.9'; else exit 2; fi");
        let other_link = herdr_script("9.9.9", &status_json("ffeeddccbbaa99887766554433221100"));
        let problem = herdr_script(
            "9.9.9",
            &format!(
                r#"{{"name":"work","link_id":"{LINK_ID}","error":"config.json is unreadable"}}"#
            ),
        );
        let garbage = herdr_script("9.9.9", "herdr dial");
        for (payload, sha256, code, text) in [
            (
                &new,
                "00".repeat(32),
                local_code::UPDATE_REJECTED,
                "corrupt",
            ),
            (
                &broken,
                sha256_of(&broken),
                local_code::UPDATE_FAILED,
                "self-test",
            ),
            (
                &silent,
                sha256_of(&silent),
                local_code::UPDATE_FAILED,
                "self-test",
            ),
            (
                &no_dial,
                sha256_of(&no_dial),
                local_code::UPDATE_REJECTED,
                "cannot run this dial-in link",
            ),
            (
                &other_link,
                sha256_of(&other_link),
                local_code::UPDATE_REJECTED,
                "cannot run this dial-in link",
            ),
            (
                &problem,
                sha256_of(&problem),
                local_code::UPDATE_REJECTED,
                "cannot run this dial-in link",
            ),
            (
                &garbage,
                sha256_of(&garbage),
                local_code::UPDATE_REJECTED,
                "cannot run this dial-in link",
            ),
        ] {
            let refusal = install(&exe, payload, &sha256).unwrap_err();
            assert_eq!(refusal.code, code, "{refusal:?}");
            assert!(refusal.message.contains(text), "{refusal:?}");
            assert_eq!(fs::read(&exe).unwrap(), old);
            assert_eq!(entries(&dir), ["herdr"]);
        }

        // A stream that ends early.
        let request = OpenRequest {
            size: Some(new.len() as u64 + 10),
            sha256: Some(sha256_of(&new)),
            ..OpenRequest::stream(NONCE.into(), protocol::StreamKind::Update, String::new())
        };
        let refusal = install_update(
            &exe,
            &LINK,
            &request,
            &mut io::Cursor::new(new.clone()),
            &[],
        )
        .unwrap_err();
        assert!(refusal.message.contains("ended after"), "{refusal:?}");
        // More bytes before the stream than announced, and invalid fields.
        let request = OpenRequest {
            size: Some(2),
            ..request
        };
        assert!(install_update(&exe, &LINK, &request, &mut io::empty(), b"abc").is_err());
        for (size, sha256) in [
            (0, sha256_of(&new)),
            (512 * 1024 * 1024 + 1, sha256_of(&new)),
            (1, "AB".repeat(32)),
            (1, "ab".into()),
        ] {
            let request = OpenRequest {
                size: Some(size),
                sha256: Some(sha256),
                ..request.clone()
            };
            let refusal = install_update(&exe, &LINK, &request, &mut io::empty(), &[]).unwrap_err();
            assert_eq!(refusal.code, local_code::UPDATE_REJECTED, "{refusal:?}");
        }
        assert_eq!(fs::read(&exe).unwrap(), old);
        assert_eq!(entries(&dir), ["herdr"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn package_managed_or_unwritable_installs_are_refused() {
        for exe in [
            "/nix/store/abc-herdr/bin/herdr",
            "/opt/homebrew/Cellar/herdr/1.0/bin/herdr",
            "/home/u/.local/share/mise/installs/herdr/1.0/herdr",
            "/home/u/.cargo/registry/herdr",
        ] {
            let refusal = check_install_target(Path::new(exe)).unwrap_err();
            assert_eq!(refusal.code, local_code::UPDATE_REJECTED);
            assert!(refusal.message.contains("package manager"), "{refusal:?}");
        }
        let dir = scratch("target");
        assert!(check_install_target(&dir).is_err());
        let exe = installed_exe(&dir);
        assert_eq!(check_install_target(&exe), Ok(()));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        assert!(check_install_target(&link).is_err());

        // An install directory this user cannot write to.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let new = dial_script("9.9.9");
        let refusal = install(&exe, &new, &sha256_of(&new));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // Root may write anyway; everyone else is refused.
        if let Err(refusal) = refusal {
            assert_eq!(refusal.code, local_code::UPDATE_REJECTED, "{refusal:?}");
            assert!(refusal.message.contains("cannot write"), "{refusal:?}");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn probation_is_recorded_for_the_matching_backup_only() {
        let dir = scratch("probation");
        let exe = installed_exe(&dir);
        let backup = dir.join("herdr.prev");
        let file = dir.join(PROBATION_FILE);
        assert_eq!(probation_backup(&exe, &file, now_ms()), None);

        let reexec = ReexecRequest::new(Arc::new(AtomicBool::new(false)));
        let installed = Installed {
            backup: backup.clone(),
            sha256: sha256_of(&fs::read(&exe).unwrap()),
        };
        restart_into_update(&reexec, &file, &installed);
        let pending = reexec.take().unwrap();
        assert_eq!(pending.reason, "updated by hub");
        assert!(pending.env.is_empty());
        // The backup must exist, and belong to this executable.
        assert_eq!(probation_backup(&exe, &file, now_ms()), None);
        fs::write(&backup, b"old").unwrap();
        let (found, remaining) = probation_backup(&exe, &file, now_ms()).unwrap();
        assert_eq!(found.backup, backup);
        assert_eq!(found.sha256, installed.sha256);
        assert!(
            remaining > PROBATION - Duration::from_secs(60),
            "{remaining:?}"
        );
        let later = now_ms() + PROBATION.as_millis() as u64;
        assert_eq!(
            probation_backup(&exe, &file, later).unwrap().1,
            Duration::ZERO
        );
        assert_eq!(probation_backup(&dir.join("other"), &file, now_ms()), None);

        // Connecting ends the probation.
        let probation = Probation::start(&exe, &dir, reexec.clone());
        assert!(file.exists());
        probation.connected();
        assert!(!file.exists());
        assert_eq!(reexec.take(), None);

        // Once something else (`herdr update`) replaced the update, the
        // record no longer applies, and a starting dialer drops it.
        restart_into_update(&reexec, &file, &installed);
        let _ = reexec.take();
        fs::write(&exe, script("echo 'herdr 3.0.0'")).unwrap();
        assert_eq!(probation_backup(&exe, &file, now_ms()), None);
        let _probation = Probation::start(&exe, &dir, reexec.clone());
        assert!(!file.exists());
        assert_eq!(reexec.take(), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_update_replaced_during_its_probation_is_not_rolled_back() {
        let dir = scratch("replaced");
        let exe = installed_exe(&dir);
        let backup = dir.join("herdr.prev");
        let file = dir.join(PROBATION_FILE);
        fs::write(&backup, b"old").unwrap();
        fs::write(&file, b"{}").unwrap();
        let record = ProbationRecord {
            backup: backup.clone(),
            sha256: "00".repeat(32),
            deadline_ms: now_ms() - 1,
        };
        let reexec = ReexecRequest::new(Arc::new(AtomicBool::new(false)));
        watch_probation(
            &exe,
            &record,
            &file,
            Duration::ZERO,
            &AtomicBool::new(false),
            &reexec,
        );
        assert_ne!(fs::read(&exe).unwrap(), b"old");
        assert!(backup.exists() && !file.exists());
        assert_eq!(reexec.take(), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_expired_probation_rolls_back_when_the_dialer_starts_again() {
        let dir = scratch("rollback");
        let exe = installed_exe(&dir);
        let backup = dir.join("herdr.prev");
        let file = dir.join(PROBATION_FILE);
        fs::write(&backup, b"old").unwrap();
        let record = ProbationRecord {
            backup: backup.clone(),
            sha256: sha256_of(&fs::read(&exe).unwrap()),
            deadline_ms: now_ms() - 1,
        };
        fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();

        let shutdown = Arc::new(AtomicBool::new(false));
        let reexec = ReexecRequest::new(Arc::clone(&shutdown));
        let _probation = Probation::start(&exe, &dir, reexec.clone());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !shutdown.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read(&exe).unwrap(), b"old");
        assert!(!backup.exists() && !file.exists());
        let pending = reexec.take().unwrap();
        assert_eq!(pending.env.len(), 1);
        assert_eq!(pending.env[0].0, ROLLED_BACK_ENV);
        let note = pending.env[0].1.clone().unwrap();
        assert!(note.contains("did not connect"), "{note}");
        // The note is for the next process only.
        assert_eq!(reexec_env(&pending.env), pending.env);
        assert_eq!(reexec_env(&[]), [(ROLLED_BACK_ENV.to_string(), None)]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn interrupted_update_files_are_removed() {
        let dir = scratch("stale");
        let exe = installed_exe(&dir);
        fs::write(dir.join(format!("{UPDATE_TEMP_PREFIX}{NONCE}")), b"partial").unwrap();
        // A directory, and the staging file of a running `herdr update`, stay.
        let other_nonce = "ffeeddccbbaa99887766554433221100";
        fs::create_dir(dir.join(format!("{UPDATE_TEMP_PREFIX}{other_nonce}"))).unwrap();
        fs::write(dir.join(".herdr-update-4242.tmp"), b"self-update").unwrap();
        remove_stale_update_files(&exe);
        assert_eq!(
            entries(&dir),
            [
                ".herdr-update-4242.tmp",
                &format!("{UPDATE_TEMP_PREFIX}{other_nonce}"),
                "herdr"
            ]
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
