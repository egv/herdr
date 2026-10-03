//! Dial-in end-to-end harness: a hub and a slave with separate homes,
//! connected by a fake `ssh` that emulates OpenSSH ControlMaster semantics
//! and runs the hub's forced command (from the line printed by `herdr machine
//! authorize`) the way sshd would. Shared by the `dial_in*` test files.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde_json::Value;

use super::{
    client_shell_handshake, read_server_message, register_runtime_dir,
    CURRENT_ENDPOINT_PROTOCOL_GENERATION,
};

pub const LABEL: &str = "slave1";
pub const DIAL_NAME: &str = "slave1";
pub const HUB_TARGET: &str = "fakehub";
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
pub const LINK_TIMEOUT: Duration = Duration::from_secs(30);

/// Emulates the OpenSSH client for the dialer:
/// - master (`ControlMaster=yes`, `-N`): creates a marker at the ControlPath
///   and stays up until `-O exit` removes it or its parent (the dialer) dies;
/// - `-O check` succeeds iff the marker exists, `-O exit` removes it;
/// - a session over the master runs the hub's forced command through
///   `/bin/sh -c` (dash does not `exec` it, like some login shells) with the
///   hub's environment and `SSH_ORIGINAL_COMMAND`. Its output goes through a
///   pipe so killing this process does not kill the hub-side acceptor; like
///   ssh, this process exits once the remote command has exited;
/// - a plain session (no ControlPath, like the user's own interactive ssh)
///   runs the requested command in a hub shell with stdin forwarded and
///   `PATH=$FAKE_HUB_PATH` (default `/usr/bin:/bin`).
pub const FAKE_SSH: &str = r#"#!/bin/sh
ctl=
master=no
op=
host=
cmd=
while [ $# -gt 0 ]; do
    if [ -n "$host" ]; then
        # Like ssh: every argument after the host is part of the command.
        cmd="${cmd:+$cmd }$1"
        shift
        continue
    fi
    case "$1" in
        -o)
            shift
            case "$1" in
                ControlPath=*) ctl=${1#ControlPath=} ;;
                ControlMaster=yes) master=yes ;;
            esac ;;
        -O) shift; op=$1 ;;
        -i|-p|-l|-F|-S|-E|-b|-c|-m) shift ;;
        -*) ;;
        *) host=$1 ;;
    esac
    shift
done
log() { printf '%s\n' "$*" >> "$FAKE_SSH_LOG"; }
if [ -n "$op" ]; then
    case "$op" in
        check) [ -e "$ctl" ] && exit 0 ;;
        exit) log "exit $host"; [ -e "$ctl" ] && rm -f "$ctl" && exit 0 ;;
    esac
    echo "Control socket connect($ctl): No such file or directory" >&2
    exit 255
fi
if [ "$master" = yes ]; then
    log "master $host"
    if [ -e "$FAKE_SSH_REFUSE" ]; then
        echo "$host: Permission denied (publickey)." >&2
        exit 255
    fi
    parent=$PPID
    printf '%s\n' "$$" > "$ctl"
    ours() { [ "$(cat "$ctl" 2>/dev/null)" = "$$" ]; }
    trap 'ours && rm -f "$ctl"; exit 0' TERM INT HUP
    while ours && kill -0 "$parent" 2>/dev/null; do sleep 0.1; done
    ours && rm -f "$ctl"
    exit 0
fi
if [ -z "$ctl" ]; then
    log "plain $cmd"
    exec env -i HOME="$FAKE_HUB_HOME" XDG_CONFIG_HOME="$FAKE_HUB_CONFIG" \
        XDG_STATE_HOME="$FAKE_HUB_STATE" XDG_RUNTIME_DIR="$FAKE_HUB_RUNTIME" \
        PATH="${FAKE_HUB_PATH:-/usr/bin:/bin}" SHELL=/bin/sh HERDR_LOG="$HERDR_LOG" \
        /bin/sh -c "$cmd"
fi
log "session $cmd"
if [ ! -e "$ctl" ]; then
    echo "Control socket connect($ctl): No such file or directory" >&2
    exit 255
fi
if [ -n "$FAKE_MAX_SESSIONS" ]; then
    # sshd MaxSessions: refuse more live sessions than allowed on one master.
    dir="$FAKE_SSH_SESSIONS/$(printf '%s' "$ctl" | tr / _)"
    mkdir -p "$dir"
    while ! mkdir "$dir.lock" 2>/dev/null; do sleep 0.01; done
    live=0
    for f in "$dir"/*; do
        [ -e "$f" ] || continue
        if kill -0 "${f##*/}" 2>/dev/null; then live=$((live + 1)); else rm -f "$f"; fi
    done
    if [ "$live" -ge "$FAKE_MAX_SESSIONS" ]; then
        rmdir "$dir.lock"
        log "refused $cmd"
        echo "mux_client_request_session: session request failed: Session open refused by peer" >&2
        exit 255
    fi
    : > "$dir/$$"
    rmdir "$dir.lock"
fi
forced=$(cat "$FAKE_FORCED_COMMAND")
# Shell startup files on the hub may print before the forced command runs.
printf 'hub login banner\n'
env -i HOME="$FAKE_HUB_HOME" XDG_CONFIG_HOME="$FAKE_HUB_CONFIG" \
    XDG_STATE_HOME="$FAKE_HUB_STATE" XDG_RUNTIME_DIR="$FAKE_HUB_RUNTIME" \
    PATH=/usr/bin:/bin SHELL=/bin/sh HERDR_LOG="$HERDR_LOG" SSH_ORIGINAL_COMMAND="$cmd" \
    /bin/sh -c "$forced" | cat
"#;

pub fn app_dir() -> &'static str {
    if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    }
}

pub fn herdr_bin() -> &'static str {
    env!("CARGO_BIN_EXE_herdr")
}

/// One machine's isolated home and XDG roots.
pub struct Side {
    pub home: PathBuf,
}

impl Side {
    pub fn config(&self) -> PathBuf {
        self.home.join("c")
    }

    pub fn state(&self) -> PathBuf {
        self.home.join("s")
    }

    pub fn runtime(&self) -> PathBuf {
        self.home.join("r")
    }

    pub fn create(&self) {
        for dir in [self.config(), self.state(), self.runtime()] {
            fs::create_dir_all(dir.join(app_dir())).unwrap();
        }
        fs::write(
            self.config().join(app_dir()).join("config.toml"),
            "onboarding = false\n",
        )
        .unwrap();
        register_runtime_dir(&self.runtime());
    }

    pub fn command(&self, path: &str, args: &[&str]) -> Command {
        let mut command = Command::new(herdr_bin());
        command
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.config())
            .env("XDG_STATE_HOME", self.state())
            .env("XDG_RUNTIME_DIR", self.runtime())
            .env("SHELL", "/bin/sh")
            .env("TERM", "xterm-256color")
            .env("HERDR_DISABLE_SOUND", "1")
            .env("HERDR_LOG", "herdr=debug");
        for name in ["USER", "LOGNAME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }
}

pub struct Harness {
    pub root: PathBuf,
    pub hub: Side,
    pub slave: Side,
    pub dialers: Vec<Child>,
    pub dialer_logs: Vec<PathBuf>,
    pub link_id: String,
}

impl Harness {
    #[allow(clippy::new_without_default)] // Creates directories on disk; not a plain value.
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // Short root: link and server sockets must fit in sun_path.
        let root = PathBuf::from(format!(
            "/var/tmp/hdi-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("bin/ssh"), FAKE_SSH).unwrap();
        fs::set_permissions(root.join("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        let hub = Side {
            home: root.join("h"),
        };
        let slave = Side {
            home: root.join("s"),
        };
        hub.create();
        slave.create();
        Self {
            root,
            hub,
            slave,
            dialers: Vec::new(),
            dialer_logs: Vec::new(),
            link_id: String::new(),
        }
    }

    pub fn hub_command(&self, args: &[&str]) -> Command {
        self.hub.command("/usr/bin:/bin", args)
    }

    pub fn slave_command(&self, args: &[&str]) -> Command {
        let path = format!("{}:/usr/bin:/bin", self.root.join("bin").display());
        let mut command = self.slave.command(&path, args);
        command
            .env("FAKE_SSH_LOG", self.root.join("ssh.log"))
            .env("FAKE_FORCED_COMMAND", self.root.join("forced-command"))
            .env("FAKE_SSH_REFUSE", self.root.join("refuse-key"))
            .env("FAKE_SSH_SESSIONS", self.root.join("sessions"))
            .env("FAKE_HUB_HOME", &self.hub.home)
            .env("FAKE_HUB_CONFIG", self.hub.config())
            .env("FAKE_HUB_STATE", self.hub.state())
            .env("FAKE_HUB_RUNTIME", self.hub.runtime());
        command
    }

    /// The fake `ssh` run by hand on the slave, with the slave environment.
    pub fn slave_ssh(&self, args: &[&str]) -> Command {
        let template = self.slave_command(&[]);
        let mut command = Command::new(self.root.join("bin/ssh"));
        command.args(args).env_clear();
        for (name, value) in template.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            }
        }
        command
    }

    pub fn catalog_path(&self) -> PathBuf {
        self.hub
            .state()
            .join(app_dir())
            .join("client")
            .join("dial-in-machines.json")
    }

    pub fn link_dir(&self) -> PathBuf {
        self.catalog_path()
            .parent()
            .unwrap()
            .join("links")
            .join(&self.link_id[..12])
    }

    pub fn read_status(&self) -> Option<Value> {
        let text = fs::read_to_string(self.link_dir().join("status.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn status_field(&self, field: &str) -> Value {
        self.read_status()
            .map(|status| status[field].clone())
            .unwrap_or(Value::Null)
    }

    pub fn dial_state(&self) -> Option<Value> {
        self.dial_state_of(DIAL_NAME)
    }

    pub fn dial_state_of(&self, name: &str) -> Option<Value> {
        let path = self.slave_dial_dir(name).join("state.json");
        serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
    }

    pub fn slave_dial_dir(&self, name: &str) -> PathBuf {
        self.slave.state().join(app_dir()).join("dial").join(name)
    }

    /// The slave dialer's agent relay socket, bound while forwarding is on.
    pub fn agent_relay(&self) -> PathBuf {
        self.slave_dial_dir(DIAL_NAME).join("agent.sock")
    }

    pub fn ssh_log(&self) -> String {
        fs::read_to_string(self.root.join("ssh.log")).unwrap_or_default()
    }

    pub fn control_sessions(&self) -> usize {
        self.ssh_log()
            .lines()
            .filter(|line| line.starts_with("session ") && line.contains("--mode control"))
            .count()
    }

    pub fn spawn_dialer(&mut self) -> usize {
        self.spawn_dialer_named(DIAL_NAME)
    }

    pub fn spawn_dialer_named(&mut self, name: &str) -> usize {
        self.spawn_dialer_with(name, &[])
    }

    pub fn spawn_dialer_with(&mut self, name: &str, env: &[(&str, &str)]) -> usize {
        let log = self
            .root
            .join(format!("dialer-{}.log", self.dialer_logs.len()));
        let mut command = self.slave_command(&["machine", "dial", "run", name]);
        command.envs(env.iter().copied());
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        self.dialers.push(child);
        self.dialer_logs.push(log);
        self.dialers.len() - 1
    }

    pub fn diagnostics(&self) -> String {
        let mut text = String::new();
        for log in &self.dialer_logs {
            text.push_str(&format!(
                "--- {}\n{}\n",
                log.display(),
                fs::read_to_string(log).unwrap_or_default()
            ));
        }
        text.push_str(&format!("--- ssh.log\n{}\n", self.ssh_log()));
        text.push_str(&format!("--- status.json\n{:?}\n", self.read_status()));
        text.push_str(&format!("--- dial state.json\n{:?}\n", self.dial_state()));
        for (side, logs) in [
            ("hub", self.hub.config().join(app_dir())),
            ("slave", self.slave.config().join(app_dir())),
        ] {
            if let Ok(entries) = fs::read_dir(&logs) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "log") {
                        let content = fs::read_to_string(&path).unwrap_or_default();
                        let tail: Vec<&str> = content.lines().rev().take(40).collect();
                        text.push_str(&format!("--- {side} {}\n", path.display()));
                        for line in tail.into_iter().rev() {
                            text.push_str(line);
                            text.push('\n');
                        }
                    }
                }
            }
        }
        text
    }

    pub fn wait_for(&self, what: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            predicate(),
            "timed out waiting for {what}\n{}",
            self.diagnostics()
        );
    }

    pub fn wait_connected_epoch_above(&self, previous: u64) -> u64 {
        self.wait_for("the hub link status to be connected", LINK_TIMEOUT, || {
            self.status_field("state") == "connected"
                && self.status_field("link_epoch").as_u64().unwrap_or(0) > previous
        });
        self.status_field("link_epoch").as_u64().unwrap()
    }

    pub fn wait_disconnected(&self) {
        self.wait_for(
            "the hub link status to be disconnected",
            LINK_TIMEOUT,
            || self.status_field("state") == "disconnected",
        );
    }

    pub fn sockets_present(&self) -> Vec<&'static str> {
        ["client.sock", "api.sock", "link.sock"]
            .into_iter()
            .filter(|name| self.link_dir().join(name).exists())
            .collect()
    }

    pub fn signal_dialer(&self, index: usize, signal: libc::c_int) {
        let pid = self.dialers[index].id() as libc::pid_t;
        unsafe {
            libc::kill(pid, signal);
        }
    }

    pub fn wait_dialer_exit(&mut self, index: usize, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.dialers[index].try_wait() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    /// Client-shell endpoint handshake through the hub's `client.sock`.
    pub fn client_handshake(&self) -> Result<UnixStream, String> {
        let mut stream = UnixStream::connect(self.link_dir().join("client.sock"))
            .map_err(|error| format!("connect client.sock: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(20)))
            .map_err(|error| error.to_string())?;
        // The stream is opened over ssh on demand: the welcome arrives only
        // after both sides started their stream processes.
        let (generation, error) =
            client_shell_handshake(&mut stream, CURRENT_ENDPOINT_PROTOCOL_GENERATION, 80, 24)?;
        if generation != CURRENT_ENDPOINT_PROTOCOL_GENERATION {
            return Err(format!("unexpected endpoint generation {generation}"));
        }
        if let Some(error) = error {
            return Err(format!("endpoint handshake failed: {error}"));
        }
        Ok(stream)
    }

    /// Stream processes still alive on either side: slave bridges, fake ssh
    /// stream sessions, and hub stream-mode acceptors.
    pub fn stream_processes(&self) -> Vec<String> {
        let slave_home = format!("HOME={}", self.slave.home.display());
        let hub_home = format!("HOME={}", self.hub.home.display());
        let mut found = Vec::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return found;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let split = |name: &str| -> Vec<String> {
                fs::read(format!("/proc/{pid}/{name}"))
                    .unwrap_or_default()
                    .split(|byte| *byte == 0)
                    .filter(|chunk| !chunk.is_empty())
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect()
            };
            let environ = split("environ");
            let cmdline = split("cmdline");
            let has_env = |wanted: &str| environ.iter().any(|entry| entry == wanted);
            let stream_command = environ.iter().any(|entry| {
                entry.starts_with("SSH_ORIGINAL_COMMAND=") && entry.contains("--mode stream")
            });
            // Prewarm bridges run with null stdin; stream bridges read a pipe.
            let prewarm = fs::read_link(format!("/proc/{pid}/fd/0"))
                .is_ok_and(|target| target == std::path::Path::new("/dev/null"));
            let is_bridge = !prewarm
                && cmdline
                    .iter()
                    .any(|arg| arg == "remote-client-bridge" || arg == "remote-api-bridge");
            let is_stream_ssh = cmdline.iter().any(|arg| arg.contains("--mode stream"));
            if (has_env(&slave_home) && (is_bridge || is_stream_ssh))
                || (has_env(&hub_home) && stream_command)
            {
                found.push(format!("{pid}: {}", cmdline.join(" ")));
            }
        }
        found
    }

    /// Live `remote-client-bridge` processes on the slave.
    pub fn slave_client_bridges(&self) -> usize {
        self.stream_processes()
            .iter()
            .filter(|process| process.ends_with(" remote-client-bridge"))
            .count()
    }

    pub fn wait_streams_closed(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let remaining = self.stream_processes();
            if remaining.is_empty() {
                return;
            }
            if Instant::now() >= deadline {
                let forest = Command::new("ps")
                    .args(["-eo", "pid,ppid,stat,args", "--forest"])
                    .output()
                    .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
                    .unwrap_or_default();
                let tree: Vec<&str> = forest
                    .lines()
                    .filter(|line| {
                        line.contains(self.root.to_str().unwrap_or("-"))
                            || line.contains(" cat")
                            || line.contains("herdr")
                    })
                    .collect();
                panic!(
                    "stream processes outlived their connections:\n{}\n{}\n{}",
                    remaining.join("\n"),
                    tree.join("\n"),
                    self.diagnostics()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn hub_machine_status(&self) -> (Value, Output) {
        let output = run(self.hub_command(&["machine", "status", LABEL, "--json"]));
        let rows: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}: {}\n{}",
                String::from_utf8_lossy(&output.stderr),
                self.diagnostics()
            )
        });
        (rows[0].clone(), output)
    }

    pub fn hub_list_row(&self) -> Value {
        let listed = run_ok(self.hub_command(&["machine", "list", "--json"]));
        let rows: Value = serde_json::from_slice(&listed.stdout).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == self.link_id.as_str())
            .unwrap_or_else(|| panic!("dial-in machine missing from list: {rows}"))
            .clone()
    }

    pub fn slave_dial_status(&self) -> Value {
        let output =
            run_ok(self.slave_command(&["machine", "dial", "status", DIAL_NAME, "--json"]));
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for child in &mut self.dialers {
            if let Ok(None) = child.try_wait() {
                unsafe {
                    libc::kill(child.id() as libc::pid_t, libc::SIGCONT);
                    libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
                }
            }
        }
        for child in &mut self.dialers {
            let deadline = Instant::now() + Duration::from_secs(10);
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(25));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        // Stop the slave servers the bridges started.
        for session in ["default", "work"] {
            let mut stop = self.slave_command(&["--session", session, "server", "stop"]);
            let _ = output_with_timeout(&mut stop, Duration::from_secs(15));
        }
        // Give hub acceptors a moment to notice their closed stdin.
        thread::sleep(Duration::from_millis(300));
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Reads server frames until none arrived for a while (bounded).
pub fn drain_until_idle(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && read_server_message(stream).is_ok() {}
    stream.set_read_timeout(None).unwrap();
}

pub fn output_with_timeout(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn: {error}"))?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout.read_to_end(&mut buffer);
        buffer
    });
    let err = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr.read_to_end(&mut buffer);
        buffer
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("command timed out after {timeout:?}"));
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

pub fn run(mut command: Command) -> Output {
    let description = format!("{command:?}");
    output_with_timeout(&mut command, COMMAND_TIMEOUT)
        .unwrap_or_else(|error| panic!("{description}: {error}"))
}

pub fn run_ok(command: Command) -> Output {
    let description = format!("{command:?}");
    let output = run(command);
    assert!(
        output.status.success(),
        "{description} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A syntactically valid ed25519 public key line (the key itself is never used).
pub fn test_public_key_line() -> (String, String) {
    let mut blob = Vec::new();
    for field in [b"ssh-ed25519".as_slice(), &[7_u8; 32]] {
        blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
        blob.extend_from_slice(field);
    }
    let encoded = base64(&blob);
    (
        format!("ssh-ed25519 {encoded} slave-comment@example"),
        encoded,
    )
}

/// Extracts the forced command from `restrict,command="..." <type> <b64> <comment>`,
/// undoing the `\"` escaping as sshd does.
pub fn forced_command(line: &str) -> String {
    let rest = line
        .strip_prefix("restrict,command=\"")
        .unwrap_or_else(|| panic!("not a restricted forced-command line: {line}"));
    let mut command = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next() {
            Some('\\') => match chars.next() {
                Some('"') => command.push('"'),
                Some(other) => {
                    command.push('\\');
                    command.push(other);
                }
                None => panic!("unterminated command in {line}"),
            },
            Some('"') => break,
            Some(other) => command.push(other),
            None => panic!("unterminated command in {line}"),
        }
    }
    assert!(
        chars.as_str().starts_with(' '),
        "key must follow the options: {line}"
    );
    command
}

/// Hub `machine add --dial-in`, slave `dial setup`, hub `authorize`; installs
/// the authorized forced command for the fake sshd.
pub fn set_up_link(harness: &mut Harness) -> String {
    set_up_link_with(harness, &[])
}

pub fn set_up_link_with(harness: &mut Harness, extra_add_args: &[&str]) -> String {
    let mut add_args = vec![
        "machine",
        "add",
        "--dial-in",
        "--label",
        LABEL,
        "--hub",
        HUB_TARGET,
    ];
    add_args.extend_from_slice(extra_add_args);
    let added = run_ok(harness.hub_command(&add_args));
    let text = stdout(&added);
    let id = text
        .split_whitespace()
        .find(|word| word.len() == 32 && word.chars().all(|ch| ch.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("machine add printed no id:\n{text}"))
        .to_string();
    assert!(
        text.contains(&format!(
            "herdr machine dial setup {DIAL_NAME} --hub {HUB_TARGET} --link {id}"
        )),
        "{text}"
    );
    harness.link_id = id.clone();

    let (key_line, key_base64) = test_public_key_line();
    let identity = harness.slave.home.join("id_test");
    fs::write(&identity, "dummy private key\n").unwrap();
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        harness.slave.home.join("id_test.pub"),
        format!("{key_line}\n"),
    )
    .unwrap();
    let setup_text = setup_dial(harness, DIAL_NAME);
    assert!(
        setup_text.contains(&format!("herdr machine authorize {id} '{key_line}'")),
        "{setup_text}"
    );

    let authorized = run_ok(harness.hub_command(&[
        "machine",
        "authorize",
        &id,
        &key_line,
        "--herdr-path",
        herdr_bin(),
    ]));
    let line = stdout(&authorized);
    let lines: Vec<&str> = line.lines().collect();
    assert_eq!(lines.len(), 1, "authorize must print one line:\n{line}");
    let line = lines[0];
    let catalog = harness.catalog_path();
    let command = forced_command(line);
    assert_eq!(
        command,
        format!(
            "'{}' link-accept --catalog '{}' --link {id}",
            herdr_bin(),
            catalog.display()
        )
    );
    assert!(
        line.ends_with(&format!(" ssh-ed25519 {key_base64} herdr-link:{id}")),
        "{line}"
    );
    assert!(!line.contains("slave-comment"), "{line}");
    fs::write(harness.root.join("forced-command"), &command).unwrap();
    id
}

/// `herdr machine dial setup <name>` on the slave for the harness link.
pub fn setup_dial(harness: &Harness, name: &str) -> String {
    let identity = harness.slave.home.join("id_test");
    let setup = run_ok(harness.slave_command(&[
        "machine",
        "dial",
        "setup",
        name,
        "--hub",
        HUB_TARGET,
        "--link",
        &harness.link_id,
        "--identity",
        identity.to_str().unwrap(),
    ]));
    stdout(&setup)
}

pub fn assert_concurrent_handshakes(harness: &Harness, count: usize) {
    thread::scope(|scope| {
        let handles: Vec<_> = (0..count)
            .map(|_| scope.spawn(|| harness.client_handshake()))
            .collect();
        for (index, handle) in handles.into_iter().enumerate() {
            let result = handle.join().unwrap();
            if let Err(error) = result {
                panic!(
                    "concurrent handshake {index} failed: {error}\n{}",
                    harness.diagnostics()
                );
            }
        }
    });
}

/// One JSON API request through the hub's `api.sock` for the link.
pub fn raw_api_request(harness: &Harness, request: &str) -> Result<Value, String> {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = UnixStream::connect(harness.link_dir().join("api.sock"))
        .map_err(|error| format!("connect api.sock: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|error| error.to_string())?;
    writeln!(stream, "{request}").map_err(|error| format!("write: {error}"))?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| format!("read: {error}"))?;
    serde_json::from_str(&line).map_err(|error| format!("{error}: {line:?}"))
}

/// A hub TUI client in a PTY whose output is drained.
pub struct HubTui {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl HubTui {
    pub fn spawn(harness: &Harness) -> Self {
        Self::spawn_with_env(harness, &[])
    }

    /// Like [`Self::spawn`], with extra environment variables.
    pub fn spawn_with_env(harness: &Harness, env: &[(&str, String)]) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 30,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut command = CommandBuilder::new(herdr_bin());
        command.arg("client");
        command.env_clear();
        for (key, value) in [
            ("PATH", "/usr/bin:/bin".into()),
            ("HOME", harness.hub.home.display().to_string()),
            (
                "XDG_CONFIG_HOME",
                harness.hub.config().display().to_string(),
            ),
            ("XDG_STATE_HOME", harness.hub.state().display().to_string()),
            (
                "XDG_RUNTIME_DIR",
                harness.hub.runtime().display().to_string(),
            ),
            ("SHELL", "/bin/sh".into()),
            ("TERM", "xterm-256color".into()),
            ("HERDR_DISABLE_SOUND", "1".into()),
            ("HERDR_LOG", "herdr=debug".into()),
        ] {
            command.env(key, value);
        }
        for (key, value) in env {
            command.env(key, value);
        }
        let child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        thread::spawn(move || {
            let mut buffer = [0_u8; 16 * 1024];
            while matches!(reader.read(&mut buffer), Ok(read) if read > 0) {}
        });
        Self {
            child,
            _master: pair.master,
        }
    }
}

impl Drop for HubTui {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Live fake ssh processes (masters and sessions) started by slave dialers.
pub fn fake_ssh_processes(harness: &Harness) -> Vec<String> {
    let script = harness.root.join("bin/ssh");
    let script = script.to_string_lossy();
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if cmdline.contains(script.as_ref()) {
            found.push(format!("{pid}: {cmdline}"));
        }
    }
    found
}

/// The laptop's OpenSSH client reaching the hub as the hub user (a relay
/// client). Options may follow the destination, as with OpenSSH; the
/// remaining arguments are the command, which a hub shell runs with the
/// hub's environment, `PATH=$FAKE_HUB_PATH`, and stdin forwarded. A file at
/// `$FAKE_RELAY_DOWN` makes the hub unreachable; `$FAKE_HUB_AUTH_SOCK` is the
/// hub's `SSH_AUTH_SOCK`, as with `ForwardAgent yes`.
pub const LAPTOP_SSH: &str = r#"#!/bin/sh
host=
while [ $# -gt 0 ]; do
    case "$1" in
        -[BbcDEeFIiJLlmOoPpQRSWw]) shift; [ $# -gt 0 ] && shift ;;
        -*) shift ;;
        *) [ -n "$host" ] && break; host=$1; shift ;;
    esac
done
printf '%s %s\n' "$host" "$*" >> "$FAKE_SSH_LOG"
if [ -e "$FAKE_RELAY_DOWN" ]; then
    echo "ssh: connect to host $host port 22: Connection refused" >&2
    exit 255
fi
printf 'hub login banner\n'
exec env -i HOME="$FAKE_HUB_HOME" XDG_CONFIG_HOME="$FAKE_HUB_CONFIG" \
    XDG_STATE_HOME="$FAKE_HUB_STATE" XDG_RUNTIME_DIR="$FAKE_HUB_RUNTIME" \
    PATH="$FAKE_HUB_PATH" SHELL=/bin/sh HERDR_LOG="$HERDR_LOG" \
    ${FAKE_HUB_AUTH_SOCK:+"SSH_AUTH_SOCK=$FAKE_HUB_AUTH_SOCK"} \
    /bin/sh -c "$*"
"#;

/// A third machine (a laptop) that reaches the harness hub over its own ssh
/// ([`LAPTOP_SSH`]), where `herdr` is on the PATH of the hub user.
pub struct Laptop {
    pub root: PathBuf,
    pub side: Side,
    hub: Side,
}

impl Laptop {
    pub fn new(harness: &Harness) -> Self {
        let root = harness.root.clone();
        for dir in ["laptop-bin", "hub-bin"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("laptop-bin/ssh"), LAPTOP_SSH).unwrap();
        fs::set_permissions(
            root.join("laptop-bin/ssh"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::os::unix::fs::symlink(herdr_bin(), root.join("hub-bin/herdr")).unwrap();
        let side = Side {
            home: root.join("l"),
        };
        side.create();
        fs::create_dir_all(side.home.join("t")).unwrap();
        Self {
            hub: Side {
                home: harness.hub.home.clone(),
            },
            root,
            side,
        }
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.root.join("laptop-bin").display())
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = self.side.command(&self.path(), args);
        command
            // Bridge sockets of a killed TUI stay inside the harness.
            .env("TMPDIR", self.side.home.join("t"))
            .env("FAKE_SSH_LOG", self.root.join("laptop-ssh.log"))
            .env("FAKE_RELAY_DOWN", self.root.join("relay-down"))
            .env("FAKE_HUB_HOME", &self.hub.home)
            .env("FAKE_HUB_CONFIG", self.hub.config())
            .env("FAKE_HUB_STATE", self.hub.state())
            .env("FAKE_HUB_RUNTIME", self.hub.runtime())
            .env(
                "FAKE_HUB_PATH",
                format!("{}:/usr/bin:/bin", self.root.join("hub-bin").display()),
            );
        command
    }

    /// The laptop's own `ssh`, with the laptop environment.
    pub fn ssh(&self, args: &[&str]) -> Command {
        let template = self.command(&[]);
        let mut command = Command::new(self.root.join("laptop-bin/ssh"));
        command.args(args).env_clear();
        for (name, value) in template.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            }
        }
        command
    }

    pub fn ssh_log(&self) -> String {
        fs::read_to_string(self.root.join("laptop-ssh.log")).unwrap_or_default()
    }

    /// Moves the hub user's `herdr` from the PATH to `~/.local/bin`.
    pub fn move_hub_herdr(&self) {
        let bin = self.hub.home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::remove_file(self.root.join("hub-bin/herdr")).unwrap();
        std::os::unix::fs::symlink(herdr_bin(), bin.join("herdr")).unwrap();
    }

    pub fn set_relay_down(&self, down: bool) {
        let marker = self.root.join("relay-down");
        if down {
            fs::write(marker, "").unwrap();
        } else {
            let _ = fs::remove_file(marker);
        }
    }

    /// `herdr machine list --json` rows of kind `via`.
    pub fn via_rows(&self) -> Vec<Value> {
        let output = run_ok(self.command(&["machine", "list", "--json"]));
        let rows: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
        rows.as_array()
            .unwrap()
            .iter()
            .filter(|row| row["kind"] == "via")
            .cloned()
            .collect()
    }

    /// `herdr link-connect` processes the laptop started on the hub.
    pub fn link_connect_processes(&self) -> Vec<String> {
        let hub_home = format!("HOME={}", self.hub.home.display());
        let mut found = Vec::new();
        for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let environ = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
            let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            let on_hub = environ
                .split(|byte| *byte == 0)
                .any(|entry| entry == hub_home.as_bytes());
            if on_hub && cmdline.contains(" link-connect ") {
                found.push(format!("{pid}: {cmdline}"));
            }
        }
        found
    }

    /// The laptop TUI client, in a PTY.
    pub fn tui(&self) -> HubTui {
        HubTui::spawn_from(&self.command(&["client"]))
    }
}

impl Drop for Laptop {
    fn drop(&mut self) {
        let mut stop = self.command(&["server", "stop"]);
        let _ = output_with_timeout(&mut stop, Duration::from_secs(15));
    }
}

impl HubTui {
    /// A TUI client running `command` (program, arguments and environment).
    pub fn spawn_from(template: &Command) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 30,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut command = CommandBuilder::new(template.get_program());
        command.args(template.get_args());
        command.env_clear();
        for (name, value) in template.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            }
        }
        let child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        thread::spawn(move || {
            let mut buffer = [0_u8; 16 * 1024];
            while matches!(reader.read(&mut buffer), Ok(read) if read > 0) {}
        });
        Self {
            child,
            _master: pair.master,
        }
    }
}

/// The comment of the key in [`start_hub_agent`]'s agent.
pub const AGENT_KEY_COMMENT: &str = "herdr-agent-test";

/// A hub `ssh-agent` holding one generated ed25519 key; killed on drop.
pub struct HubAgent {
    child: Child,
    pub socket: PathBuf,
    pub public_key: PathBuf,
}

impl Drop for HubAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn agent_tools_available() -> bool {
    ["ssh-agent", "ssh-add", "ssh-keygen"].iter().all(|tool| {
        Command::new(tool)
            .arg("-?")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    })
}

/// `program args...` talking to the agent at `socket`.
pub fn with_agent(socket: &Path, program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SSH_AUTH_SOCK", socket);
    command
}

pub fn start_hub_agent(harness: &Harness) -> HubAgent {
    let key = harness.root.join("hub-key");
    let key_path = key.to_str().unwrap();
    run_ok({
        let mut command = Command::new("ssh-keygen");
        command.args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            AGENT_KEY_COMMENT,
            "-f",
            key_path,
        ]);
        command
    });
    let socket = harness.root.join("hub-agent.sock");
    let child = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&socket)
        .env("HOME", &harness.hub.home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let agent = HubAgent {
        child,
        socket,
        public_key: harness.root.join("hub-key.pub"),
    };
    harness.wait_for("the hub ssh-agent", LINK_TIMEOUT, || agent.socket.exists());
    run_ok(with_agent(&agent.socket, "ssh-add", &[key_path]));
    agent
}

/// Whether `ssh-add -l` through `socket` lists the test key.
pub fn agent_lists_key(socket: &Path) -> bool {
    let output = run(with_agent(socket, "ssh-add", &["-l"]));
    output.status.success() && stdout(&output).contains(AGENT_KEY_COMMENT)
}
