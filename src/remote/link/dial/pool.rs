//! The OpenSSH master connections of one link attempt.

use std::io;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::failure::{classify_ssh_failure, failure_code, LinkFailure};
use super::lock;
use super::process::{kill_and_reap, run_quick, StderrTail, STDERR_SETTLE};
use super::ssh::{DialTools, SshArgs};
use crate::remote::link::dial_config::ControlSockets;

pub(crate) const MASTER_READY_TIMEOUT: Duration = Duration::from_secs(15);

const MASTER_CHECK_POLL: Duration = Duration::from_millis(100);

const MASTER_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Masters in the pool; extra masters absorb sshd `MaxSessions` refusals.
pub(crate) const MAX_MASTERS: usize = 4;

/// Pids of the master processes that are running, so a second shutdown
/// signal can kill them before the dialer exits without its normal teardown.
#[derive(Clone, Default)]
pub(crate) struct MasterPids(Arc<Mutex<Vec<u32>>>);

impl MasterPids {
    fn add(&self, pid: u32) {
        lock(&self.0).push(pid);
    }

    /// Kills and reaps `child`, forgetting its pid under the same lock so
    /// [`Self::kill_all`] never signals a pid that was reaped and reused.
    fn reap(&self, child: &mut Child) {
        let mut pids = lock(&self.0);
        let pid = child.id();
        kill_and_reap(child);
        pids.retain(|known| *known != pid);
    }

    /// Forgets a child that `try_wait` already reaped.
    fn forget(&self, pid: u32) {
        lock(&self.0).retain(|known| *known != pid);
    }

    /// SIGKILLs every running master.
    pub(super) fn kill_all(&self) {
        let pids = lock(&self.0);
        crate::platform::signal_processes(&pids, crate::platform::Signal::Kill);
    }
}

pub(super) struct Master {
    index: usize,
    pub(super) ctl: PathBuf,
    child: Mutex<Child>,
    active: AtomicUsize,
}

impl Master {
    fn is_alive(&self, pids: &MasterPids) -> bool {
        let mut child = lock(&self.child);
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => {
                pids.forget(child.id());
                false
            }
            Err(_) => false,
        }
    }
}

#[derive(Default)]
struct PoolState {
    masters: Vec<Arc<Master>>,
    closed: bool,
}

/// The OpenSSH masters of one link attempt. Master 0 carries the control
/// session; more are added (up to `MAX_MASTERS`) when the hub refuses
/// further sessions on the existing ones.
pub(crate) struct MasterPool {
    tools: DialTools,
    ssh: SshArgs,
    sockets: ControlSockets,
    shutdown: Arc<AtomicBool>,
    pids: MasterPids,
    state: Mutex<PoolState>,
    grow: Mutex<()>,
}

impl MasterPool {
    pub(super) fn new(
        tools: DialTools,
        ssh: SshArgs,
        sockets: ControlSockets,
        shutdown: Arc<AtomicBool>,
        pids: MasterPids,
    ) -> Self {
        Self {
            tools,
            ssh,
            sockets,
            shutdown,
            pids,
            state: Mutex::new(PoolState::default()),
            grow: Mutex::new(()),
        }
    }

    fn start_master(&self, index: usize) -> Result<Arc<Master>, LinkFailure> {
        let local = |error: io::Error| {
            LinkFailure::new(
                failure_code::LOCAL_ERROR,
                format!("cannot prepare the ssh master: {error}"),
            )
        };
        self.sockets.remove(index);
        let ctl = self.sockets.path(index);
        let args = self.ssh.master(&ctl).map_err(local)?;
        let check = self.ssh.check(&ctl).map_err(local)?;
        let mut child = self
            .tools
            .ssh_command(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                LinkFailure::new(
                    failure_code::SSH_FAILED,
                    format!(
                        "failed to run {}: {error}",
                        self.tools.ssh.to_string_lossy()
                    ),
                )
            })?;
        self.pids.add(child.id());
        let stderr = StderrTail::capture(child.stderr.take());
        let started = Instant::now();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                self.pids.forget(child.id());
                self.sockets.remove(index);
                return Err(classify_ssh_failure(
                    &format!("ssh connection to the hub failed ({status})"),
                    &stderr.text_after_exit(STDERR_SETTLE),
                ));
            }
            if self.shutdown.load(Ordering::SeqCst) {
                self.pids.reap(&mut child);
                self.sockets.remove(index);
                return Err(LinkFailure::new(failure_code::LOCAL_ERROR, "shutting down"));
            }
            if run_quick(self.tools.ssh_command(&check), MASTER_COMMAND_TIMEOUT) {
                break;
            }
            if started.elapsed() >= MASTER_READY_TIMEOUT {
                self.pids.reap(&mut child);
                self.sockets.remove(index);
                return Err(LinkFailure::new(
                    failure_code::MASTER_TIMEOUT,
                    format!(
                        "ssh master connection was not ready within {}s",
                        MASTER_READY_TIMEOUT.as_secs()
                    ),
                )
                .with_detail(&stderr.text()));
            }
            thread::sleep(MASTER_CHECK_POLL);
        }
        tracing::debug!(index, ctl = %ctl.display(), "dial ssh master ready");
        Ok(Arc::new(Master {
            index,
            ctl,
            child: Mutex::new(child),
            active: AtomicUsize::new(0),
        }))
    }

    pub(super) fn start_first(&self) -> Result<Arc<Master>, LinkFailure> {
        let master = self.start_master(0)?;
        let mut state = lock(&self.state);
        if state.closed {
            drop(state);
            self.stop_master(&master);
            return Err(LinkFailure::new(failure_code::LOCAL_ERROR, "shutting down"));
        }
        state.masters.push(Arc::clone(&master));
        Ok(master)
    }

    /// The live master with the fewest streams, and the pool size seen.
    pub(super) fn least_loaded(&self) -> Option<(Arc<Master>, usize)> {
        let state = lock(&self.state);
        let observed = state.masters.len();
        state
            .masters
            .iter()
            .filter(|master| master.is_alive(&self.pids))
            .min_by_key(|master| master.active.load(Ordering::SeqCst))
            .map(|master| (Arc::clone(master), observed))
    }

    /// After a session refusal on a pool of `observed` masters: the master
    /// another stream added meanwhile, or a new one, or `None` when full.
    pub(super) fn grow(&self, observed: usize) -> Option<Arc<Master>> {
        let _growing = lock(&self.grow);
        let index = {
            let state = lock(&self.state);
            if state.closed {
                return None;
            }
            if state.masters.len() > observed {
                return state.masters.last().cloned();
            }
            if state.masters.len() >= MAX_MASTERS {
                return None;
            }
            state.masters.len()
        };
        let master = match self.start_master(index) {
            Ok(master) => master,
            Err(failure) => {
                tracing::warn!(%failure, index, "dial could not add an ssh master");
                return None;
            }
        };
        let mut state = lock(&self.state);
        if state.closed {
            drop(state);
            self.stop_master(&master);
            return None;
        }
        tracing::info!(index, "dial added an ssh master after a session refusal");
        state.masters.push(Arc::clone(&master));
        Some(master)
    }

    fn stop_master(&self, master: &Master) {
        if let Ok(args) = self.ssh.exit(&master.ctl) {
            run_quick(self.tools.ssh_command(&args), MASTER_COMMAND_TIMEOUT);
        }
        self.pids.reap(&mut lock(&master.child));
        self.sockets.remove(master.index);
    }

    /// `ssh -O exit`, kill, and remove the control socket of every master.
    pub(super) fn shutdown(&self) {
        let masters = {
            let mut state = lock(&self.state);
            state.closed = true;
            std::mem::take(&mut state.masters)
        };
        for master in masters.iter().rev() {
            self.stop_master(master);
        }
    }
}

/// Stops the ssh masters an earlier dialer for this link left behind when it
/// was killed before its teardown (OpenSSH masters outlive their parent),
/// and removes their control sockets. Returns how many masters answered.
pub(super) fn stop_orphan_masters(
    tools: &DialTools,
    ssh: &SshArgs,
    locations: &[ControlSockets],
) -> usize {
    let mut stopped = 0;
    for sockets in locations {
        for index in 0..MAX_MASTERS {
            let ctl = sockets.path(index);
            if std::fs::symlink_metadata(&ctl).is_err() {
                continue;
            }
            if let Ok(args) = ssh.exit(&ctl) {
                if run_quick(tools.ssh_command(&args), MASTER_COMMAND_TIMEOUT) {
                    stopped += 1;
                }
            }
            sockets.remove(index);
        }
    }
    stopped
}

/// Counts a stream against a master while it lives.
pub(super) struct MasterLease(pub(super) Arc<Master>);

impl MasterLease {
    pub(super) fn acquire(master: Arc<Master>) -> Self {
        master.active.fetch_add(1, Ordering::SeqCst);
        Self(master)
    }
}

impl Drop for MasterLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Command;

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn master_pids_kill_running_masters_and_forget_reaped_ones() {
        let pids = MasterPids::default();
        let mut running = sleeper();
        let mut reaped = sleeper();
        pids.add(running.id());
        pids.add(reaped.id());

        pids.reap(&mut reaped);
        assert_eq!(*lock(&pids.0), [running.id()]);

        pids.kill_all();
        let status = running.wait().unwrap();
        assert_eq!(status.code(), None, "the master must be killed by a signal");
        pids.forget(running.id());
        assert!(lock(&pids.0).is_empty());
    }

    #[test]
    fn orphan_masters_are_asked_to_exit_and_their_sockets_removed() {
        use crate::remote::link::dial_config::DialPaths;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("herdr-dial-orphans-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = DialPaths::new(&dir, "work");
        crate::platform::ensure_private_directory(&paths.dir).unwrap();
        // Logs its arguments; the master behind ctl-2 is already gone.
        let log = dir.join("ssh.log");
        let ssh = dir.join("ssh");
        std::fs::write(
            &ssh,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in *ctl-2*) exit 255 ;; esac\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sockets = ControlSockets::for_dial(&paths).unwrap();
        for index in [0, 2] {
            std::fs::write(sockets.path(index), b"").unwrap();
        }
        let tools = DialTools {
            ssh: ssh.into(),
            exe: PathBuf::from("/unused"),
        };
        let ssh_args = SshArgs::new("hub", None, true);
        let stopped = stop_orphan_masters(&tools, &ssh_args, std::slice::from_ref(&sockets));
        assert_eq!(stopped, 1);
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            format!(
                "-o ControlPath={} -O exit hub\n-o ControlPath={} -O exit hub\n",
                sockets.path(0).display(),
                sockets.path(2).display()
            )
        );
        assert!(!sockets.path(0).exists() && !sockets.path(2).exists());
        assert_eq!(stop_orphan_masters(&tools, &ssh_args, &[sockets]), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
