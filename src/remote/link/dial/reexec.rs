//! Replacing the running dialer with a fresh copy of its executable, for
//! example after the hub installed an update or the binary on disk changed.
//! Any component may request it; the supervisor tears the current link
//! attempt down, self-tests the executable, and execs it with the same
//! arguments (see `Dialer::run`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use super::lock;
use super::process::run_quick;

/// How long `<exe> --version` may take before a re-exec is abandoned.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a running dialer checks whether its executable was replaced
/// (it also checks before every redial).
pub(crate) const BINARY_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// The executable the dialer watches and re-execs: the absolute path it was
/// started as (for a service, the stable launcher that an upgrade may point
/// at a new version), else `running`, the executable it runs from.
pub(crate) fn restart_executable(running: &Path) -> PathBuf {
    std::env::args_os()
        .next()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file())
        .unwrap_or_else(|| running.to_path_buf())
}

/// Notices when the executable the dialer was started from is replaced on
/// disk (an upgrade) and requests a re-exec into the new version.
pub(crate) struct BinaryWatch {
    path: PathBuf,
    /// The identity last seen; each new one is self-tested at most once.
    seen: Mutex<Option<[u64; 5]>>,
}

impl BinaryWatch {
    pub(crate) fn new(path: PathBuf) -> Self {
        let seen = crate::platform::file_identity(&path).ok();
        Self {
            path,
            seen: Mutex::new(seen),
        }
    }

    /// Requests a re-exec when the executable changed since the last check
    /// and the new one passes its self-test. Returns a line to report.
    pub(crate) fn check(&self, reexec: &ReexecRequest) -> Option<String> {
        let mut seen = lock(&self.seen);
        let current = crate::platform::file_identity(&self.path).ok()?;
        if *seen == Some(current) {
            return None;
        }
        *seen = Some(current);
        if !self_test(&self.path) {
            return Some(format!(
                "{} changed but `--version` failed; keeping the running version",
                self.path.display()
            ));
        }
        reexec.request("binary updated", Vec::new());
        Some(format!("{} was updated", self.path.display()))
    }

    /// Checks every `interval` on a background thread until `watch` is
    /// dropped, passing each line to `report`.
    pub(crate) fn spawn(
        watch: Weak<Self>,
        reexec: ReexecRequest,
        interval: Duration,
        report: impl Fn(&str) + Send + 'static,
    ) {
        let spawned = thread::Builder::new()
            .name("herdr-dial-binary-watch".into())
            .spawn(move || loop {
                thread::sleep(interval);
                let Some(watch) = watch.upgrade() else {
                    return;
                };
                if let Some(line) = watch.check(&reexec) {
                    report(&line);
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "dial could not start its binary watch");
        }
    }
}

/// A requested re-exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reexec {
    pub(crate) reason: String,
    /// Environment changes for the new process: `Some` sets, `None` removes.
    pub(crate) env: Vec<(String, Option<String>)>,
}

/// A shared re-exec request; clones share it.
#[derive(Clone)]
pub(crate) struct ReexecRequest {
    pending: Arc<Mutex<Option<Reexec>>>,
    /// The dialer's shutdown flag, which ends the current attempt.
    shutdown: Arc<AtomicBool>,
}

impl ReexecRequest {
    pub(crate) fn new(shutdown: Arc<AtomicBool>) -> Self {
        Self {
            pending: Arc::default(),
            shutdown,
        }
    }

    /// Asks the dialer to end the current link attempt and re-exec. The
    /// first request until the next re-exec wins, except that one carrying
    /// environment (a rollback) replaces a plain one
    /// (the same file change, noticed by the binary watch first).
    pub(crate) fn request(&self, reason: impl Into<String>, env: Vec<(String, Option<String>)>) {
        let mut pending = lock(&self.pending);
        if pending
            .as_ref()
            .is_none_or(|pending| pending.env.is_empty() && !env.is_empty())
        {
            *pending = Some(Reexec {
                reason: reason.into(),
                env,
            });
        }
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// The pending request, if any, clearing it.
    pub(crate) fn take(&self) -> Option<Reexec> {
        lock(&self.pending).take()
    }
}

/// Whether `<exe> --version` succeeds within the self-test timeout.
pub(crate) fn self_test(exe: &Path) -> bool {
    let mut command = Command::new(exe);
    command.arg("--version");
    run_quick(command, SELF_TEST_TIMEOUT)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_first_request_wins_and_ends_the_attempt() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let request = ReexecRequest::new(Arc::clone(&shutdown));
        assert_eq!(request.take(), None);
        request
            .clone()
            .request("updated by hub", vec![("A".into(), None)]);
        request.request("binary updated", Vec::new());
        request.request("update rolled back", vec![("B".into(), None)]);
        assert!(shutdown.load(Ordering::SeqCst));
        let pending = request.take().unwrap();
        assert_eq!(pending.reason, "updated by hub");
        assert_eq!(pending.env, [("A".to_string(), None)]);
        assert_eq!(request.take(), None);

        // A rollback's request replaces the binary watch's for the same file.
        request.request("binary updated", Vec::new());
        request.request("update rolled back", vec![("A".into(), None)]);
        assert_eq!(request.take().unwrap().reason, "update rolled back");
    }

    #[test]
    fn self_test_requires_a_runnable_executable() {
        assert!(self_test(Path::new("true")));
        assert!(!self_test(Path::new("false")));
        assert!(!self_test(&std::env::temp_dir().join("herdr-no-such-exe")));
    }

    /// Replaces `path` the way installers do: a new file renamed over it.
    fn install_script(path: &Path, exit_code: u8) {
        use std::os::unix::fs::PermissionsExt;
        let staged = path.with_extension("new");
        std::fs::write(&staged, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&staged, path).unwrap();
    }

    fn scratch_exe(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("herdr-dial-reexec-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("herdr");
        install_script(&exe, 0);
        exe
    }

    #[test]
    fn a_replaced_binary_is_self_tested_once_and_requests_a_reexec() {
        let exe = scratch_exe("check");
        let shutdown = Arc::new(AtomicBool::new(false));
        let request = ReexecRequest::new(Arc::clone(&shutdown));
        let watch = BinaryWatch::new(exe.clone());
        assert_eq!(watch.check(&request), None);

        // A broken replacement keeps the running version, and is not retried.
        install_script(&exe, 1);
        let line = watch.check(&request).unwrap();
        assert!(line.contains("`--version` failed"), "{line}");
        assert!(!shutdown.load(Ordering::SeqCst));
        assert_eq!(watch.check(&request), None);

        install_script(&exe, 0);
        let line = watch.check(&request).unwrap();
        assert!(line.ends_with("was updated"), "{line}");
        assert!(shutdown.load(Ordering::SeqCst));
        assert_eq!(request.take().unwrap().reason, "binary updated");
        assert_eq!(watch.check(&request), None);
        assert_eq!(request.take(), None);
    }

    #[test]
    fn the_background_watch_requests_a_reexec_and_stops_with_the_dialer() {
        let exe = scratch_exe("spawn");
        let shutdown = Arc::new(AtomicBool::new(false));
        let request = ReexecRequest::new(Arc::clone(&shutdown));
        let watch = Arc::new(BinaryWatch::new(exe.clone()));
        let (lines, received) = std::sync::mpsc::channel();
        BinaryWatch::spawn(
            Arc::downgrade(&watch),
            request.clone(),
            Duration::from_millis(10),
            move |line| {
                let _ = lines.send(line.to_string());
            },
        );
        install_script(&exe, 0);
        let line = received.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(line.ends_with("was updated"), "{line}");
        assert_eq!(request.take().unwrap().reason, "binary updated");
        drop(watch);
        // The thread exits (dropping its sender) once the watch is gone.
        assert_eq!(
            received.recv_timeout(Duration::from_secs(10)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        );
    }
}
