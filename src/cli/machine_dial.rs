//! `herdr machine dial ...`: slave-side dial-in link management.
//!
//! These commands run on the machine that dials in (it has no inbound SSH);
//! the hub side is `herdr machine add --dial-in` / `herdr machine authorize`.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;

use crate::client::endpoint::ProfileId;
use crate::remote::link::dial;
use crate::remote::link::dial_config::{self, DialConfig, DialPaths, DialRunState, DialState};
use crate::remote::link::status::{now_ms, sanitize_remote_text, ErrorRecord, SlaveInfo};

mod pair;
mod service;

const HELP: &str = "Usage:
  herdr machine dial setup <name> --hub <ssh-target> --link <id> [--identity <path>] [--no-compression]
  herdr machine dial setup <name> --hub <ssh-target> --pair [--label <label>] [--remote-session <name>] [--agent-forwarding] [--hub-herdr <path>] [--identity <path>] [--no-compression]
  herdr machine dial run <name>
  herdr machine dial list [--json]
  herdr machine dial status [<name>] [--json]
  herdr machine dial remove <name>
  herdr machine dial service install <name> [--no-start] [--herdr-path <path>]
  herdr machine dial service uninstall <name>
  herdr machine dial service status <name> [--json]

Run these on a machine without inbound SSH so it can join a hub's sidebar.
On the hub, `herdr machine add --dial-in --label <label>` prints the setup
command with the link id. Setup generates an ed25519 key unless --identity is
given and prints the `herdr machine authorize` command to run on the hub.
With --pair instead of --link, setup does the hub side itself over your own
interactive ssh login to the hub (password and host key prompts work).
Run keeps one outbound OpenSSH connection to the hub in the foreground and
reconnects with backoff; stop it with Ctrl-C. Service keeps `run` going as a
user service (systemd on Linux, launchd on macOS) across logins and reboots.";

const SETUP_USAGE: &str = "usage: herdr machine dial setup <name> --hub <ssh-target> --link <id> [--identity <path>] [--no-compression]";

pub(super) fn run_dial_command(args: &[String]) -> io::Result<i32> {
    let root = dial_config::dial_root();
    let mut out = io::stdout();
    let mut err = io::stderr();
    match args.first().map(String::as_str) {
        Some("setup") if args.iter().any(|arg| arg == "--pair") => {
            pair::setup_pair(&root, &args[1..], &mut out, &mut err)
        }
        Some("setup") => setup(
            &root,
            &args[1..],
            &OsString::from("ssh-keygen"),
            &mut out,
            &mut err,
        ),
        Some("run") => run(&root, &args[1..]),
        Some("list") => list(&root, &args[1..], &mut out, &mut err),
        Some("status") => status(&root, &args[1..], &mut out, &mut err),
        Some("remove") => remove(
            &root,
            &args[1..],
            &crate::platform::dial_service_installed,
            &mut out,
            &mut err,
        ),
        Some("service") => service::run_service_command(&root, &args[1..], &mut out, &mut err),
        Some("help" | "--help" | "-h") => {
            writeln!(out, "{HELP}")?;
            Ok(0)
        }
        _ => {
            writeln!(err, "{HELP}")?;
            Ok(2)
        }
    }
}

/// Quotes `value` for a POSIX shell command line the user copies.
fn sh_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '@' | '%' | '_' | '+' | '=' | ':' | ',' | '.' | '/' | '-'
                )
        })
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// `ssh-keygen` arguments generating the default identity for `name`.
fn keygen_args(name: &str, path: &Path) -> Vec<OsString> {
    vec![
        "-q".into(),
        "-t".into(),
        "ed25519".into(),
        "-N".into(),
        "".into(),
        "-C".into(),
        format!("herdr-dial:{name}").into(),
        "-f".into(),
        path.as_os_str().to_owned(),
    ]
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Paths for a validated name, or a usage error printed to `err`.
fn named_paths(root: &Path, name: &str, err: &mut impl Write) -> io::Result<Option<DialPaths>> {
    if let Err(error) = dial_config::validate_dial_name(name) {
        writeln!(err, "herdr machine dial: {error}")?;
        return Ok(None);
    }
    Ok(Some(DialPaths::new(root, name)))
}

#[derive(Default)]
struct SetupArgs<'a> {
    name: Option<&'a str>,
    hub: Option<&'a str>,
    link: Option<&'a str>,
    identity: Option<&'a str>,
    no_compression: bool,
}

fn parse_setup_args(args: &[String]) -> Result<SetupArgs<'_>, String> {
    let mut parsed = SetupArgs::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let slot = match arg.as_str() {
            "--hub" => &mut parsed.hub,
            "--link" => &mut parsed.link,
            "--identity" => &mut parsed.identity,
            "--no-compression" if !parsed.no_compression => {
                parsed.no_compression = true;
                continue;
            }
            flag if flag.starts_with('-') => return Err(format!("unexpected argument {flag}")),
            name if parsed.name.is_none() => {
                parsed.name = Some(name);
                continue;
            }
            extra => return Err(format!("unexpected argument {extra}")),
        };
        if slot.is_some() {
            return Err(format!("{arg} given more than once"));
        }
        let Some(value) = iter.next() else {
            return Err(format!("missing value for {arg}"));
        };
        *slot = Some(value.as_str());
    }
    Ok(parsed)
}

/// Creates the private dial directory and returns the link's identity:
/// `explicit` made absolute and checked, or the default key, generated with
/// `keygen` when missing. `Err` carries the exit code after printing why.
fn prepare_identity(
    paths: &DialPaths,
    explicit: Option<&str>,
    keygen: &OsString,
    err: &mut impl Write,
) -> io::Result<Result<PathBuf, i32>> {
    let explicit = match explicit.map(Path::new).map(absolute).transpose() {
        Ok(identity) => identity,
        Err(error) => {
            writeln!(err, "herdr machine dial setup: {error}")?;
            return Ok(Err(1));
        }
    };
    if let Some(identity) = &explicit {
        if let Err(error) = dial_config::validate_identity_path(identity) {
            writeln!(err, "herdr machine dial setup: {error}")?;
            return Ok(Err(2));
        }
        if !identity.is_file() {
            writeln!(
                err,
                "herdr machine dial setup: identity file not found: {}",
                identity.display()
            )?;
            return Ok(Err(1));
        }
    }
    if let Err(error) = crate::platform::ensure_private_directory(&paths.dir) {
        writeln!(
            err,
            "herdr machine dial setup: cannot prepare {}: {error}",
            paths.dir.display()
        )?;
        return Ok(Err(1));
    }
    if let Some(identity) = explicit {
        return Ok(Ok(identity));
    }
    let generated = absolute(&paths.identity_file)?;
    if generated.exists() {
        return Ok(Ok(generated));
    }
    let output = Command::new(keygen)
        .args(keygen_args(&paths.name, &generated))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(output) if output.status.success() => Ok(Ok(generated)),
        Ok(output) => {
            writeln!(
                err,
                "herdr machine dial setup: ssh-keygen failed ({}): {}",
                output.status,
                sanitize_remote_text(&String::from_utf8_lossy(&output.stderr), 512)
            )?;
            Ok(Err(1))
        }
        Err(error) => {
            writeln!(
                err,
                "herdr machine dial setup: failed to run {}: {error}",
                keygen.to_string_lossy()
            )?;
            Ok(Err(1))
        }
    }
}

fn setup(
    root: &Path,
    args: &[String],
    keygen: &OsString,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let parsed = match parse_setup_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            writeln!(err, "herdr machine dial setup: {error}\n{SETUP_USAGE}")?;
            return Ok(2);
        }
    };
    let (Some(name), Some(hub), Some(link)) = (parsed.name, parsed.hub, parsed.link) else {
        writeln!(err, "{SETUP_USAGE}")?;
        return Ok(2);
    };
    let Some(paths) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    if let Err(error) = dial_config::validate_hub(hub) {
        writeln!(err, "herdr machine dial setup: {error}")?;
        return Ok(2);
    }
    let link_id = match ProfileId::parse(link) {
        Ok(link_id) => link_id,
        Err(_) => {
            writeln!(
                err,
                "herdr machine dial setup: --link must be the 32-character id printed by `herdr machine add --dial-in` on the hub"
            )?;
            return Ok(2);
        }
    };
    let identity = match prepare_identity(&paths, parsed.identity, keygen, err)? {
        Ok(identity) => identity,
        Err(code) => return Ok(code),
    };
    let existing = match dial_config::load_config(&paths.config_file) {
        Ok(existing) => existing,
        Err(error) => {
            writeln!(err, "herdr machine dial setup: {error}")?;
            return Ok(1);
        }
    };

    let mut config = match DialConfig::new(
        name,
        hub,
        link_id,
        Some(identity.clone()),
        !parsed.no_compression,
    ) {
        Ok(config) => config,
        Err(error) => {
            writeln!(err, "herdr machine dial setup: {error}")?;
            return Ok(2);
        }
    };
    if let Some(existing) = &existing {
        config.extra = existing.extra.clone();
    }
    if let Err(error) = dial_config::store_config(&paths.config_file, &config) {
        writeln!(err, "herdr machine dial setup: {error}")?;
        return Ok(1);
    }

    let verb = if existing.is_some() {
        "Updated"
    } else {
        "Configured"
    };
    writeln!(
        out,
        "{verb} dial-in link '{name}' to {hub} (link {}).",
        config.link_id
    )?;
    writeln!(out, "Identity: {}", identity.display())?;
    writeln!(out)?;
    writeln!(out, "1. On the hub, authorize this machine's key:")?;
    match dial_config::read_public_key_line(&identity) {
        Some(public_key) => writeln!(
            out,
            "     herdr machine authorize {} {} --write",
            config.link_id,
            sh_quote(&public_key)
        )?,
        None => writeln!(
            out,
            "     herdr machine authorize {} '<contents of {}>' --write",
            config.link_id,
            DialPaths::public_key_file(&identity).display()
        )?,
    }
    writeln!(
        out,
        "   (`--pair` instead of `--link` registers and authorizes a machine over your own ssh login to the hub.)"
    )?;
    writeln!(
        out,
        "2. The hub's SSH host key must already be trusted here; check once with:"
    )?;
    writeln!(out, "     ssh {} true", sh_quote(hub))?;
    writeln!(
        out,
        "3. Keep the link running on this machine as a user service (recommended):"
    )?;
    writeln!(
        out,
        "     herdr machine dial service install {}",
        sh_quote(name)
    )?;
    writeln!(out, "   or run it in the foreground:")?;
    writeln!(out, "     herdr machine dial run {}", sh_quote(name))?;
    Ok(0)
}

fn run(root: &Path, args: &[String]) -> io::Result<i32> {
    let mut err = io::stderr();
    let [name] = args else {
        writeln!(err, "usage: herdr machine dial run <name>")?;
        return Ok(2);
    };
    let Some(paths) = named_paths(root, name, &mut err)? else {
        return Ok(2);
    };
    let config = match dial_config::load_config(&paths.config_file) {
        Ok(Some(config)) => config,
        Ok(None) => {
            writeln!(
                err,
                "herdr machine dial run: no dial-in link named '{name}'; run `herdr machine dial setup` first"
            )?;
            return Ok(1);
        }
        Err(error) => {
            writeln!(err, "herdr machine dial run: {error}")?;
            return Ok(1);
        }
    };
    crate::logging::init_file_logging(&format!("dial-{name}.log"));
    // CLI output may have restored the default SIGPIPE action; the dialer
    // writes to ssh and bridge pipes that can close at any time and must see
    // EPIPE instead of dying.
    crate::platform::end_cli_output();
    match dial::run_foreground(&paths, config) {
        Ok(()) => Ok(0),
        Err(error) => {
            tracing::error!(%error, dial = %name, "dial run failed");
            writeln!(err, "herdr machine dial run: {error}")?;
            Ok(1)
        }
    }
}

#[derive(Serialize)]
struct DialRow {
    name: String,
    dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compression: Option<bool>,
    running: bool,
    /// `connecting|connected|backoff|stopped` (stopped when no dialer runs).
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    since_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_attempt_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<ErrorRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hub_info: Option<SlaveInfo>,
    /// Why the config or state could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn effective_state(running: bool, state: Option<&DialState>) -> &'static str {
    if !running {
        return DialRunState::Stopped.as_str();
    }
    state.map_or("starting", |state| state.state.as_str())
}

fn dial_row(paths: &DialPaths) -> DialRow {
    let mut errors = Vec::new();
    let config = dial_config::load_config(&paths.config_file).unwrap_or_else(|error| {
        errors.push(error);
        None
    });
    if config.is_none() && errors.is_empty() {
        errors.push("config.json is missing".into());
    }
    let state = dial_config::read_state(&paths.state_file).unwrap_or_else(|error| {
        errors.push(format!("state.json is unreadable: {error}"));
        None
    });
    let running = dial::dialer_is_running(paths).unwrap_or_else(|error| {
        errors.push(format!("cannot tell whether a dialer runs: {error}"));
        false
    });
    let shown_state = state.as_ref().filter(|_| running);
    DialRow {
        name: paths.name.clone(),
        dir: paths.dir.display().to_string(),
        hub: config.as_ref().map(|config| config.hub.clone()),
        link_id: config.as_ref().map(|config| config.link_id.to_string()),
        identity_file: config
            .as_ref()
            .and_then(|config| config.identity_file.as_ref())
            .map(|path| path.display().to_string()),
        compression: config.as_ref().map(|config| config.compression),
        running,
        state: effective_state(running, state.as_ref()),
        since_ms: shown_state.map(|state| state.since_ms),
        next_attempt_ms: shown_state.and_then(|state| state.next_attempt_ms),
        last_error: state.as_ref().and_then(|state| state.last_error.clone()),
        hub_info: shown_state.and_then(|state| state.hub.clone()),
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

/// Parses `[<name>] [--json]` (the name only when `accepts_name`); `None` on
/// a usage error.
fn parse_json_flag(args: &[String], accepts_name: bool) -> Option<(Option<&str>, bool)> {
    let mut json = false;
    let mut name = None;
    for arg in args {
        if arg == "--json" && !json {
            json = true;
        } else if accepts_name && !arg.starts_with('-') && name.is_none() {
            name = Some(arg.as_str());
        } else {
            return None;
        }
    }
    Some((name, json))
}

fn list(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let Some((_, json)) = parse_json_flag(args, false) else {
        writeln!(err, "usage: herdr machine dial list [--json]")?;
        return Ok(2);
    };
    let names = match dial_config::list_dial_names(root) {
        Ok(names) => names,
        Err(error) => {
            writeln!(err, "herdr machine dial list: {error}")?;
            return Ok(1);
        }
    };
    let rows = names
        .iter()
        .map(|name| dial_row(&DialPaths::new(root, name)))
        .collect::<Vec<_>>();
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&rows).map_err(io::Error::other)?
        )?;
        return Ok(0);
    }
    if rows.is_empty() {
        writeln!(
            out,
            "No dial-in links. Set one up with `herdr machine dial setup`."
        )?;
        return Ok(0);
    }
    for row in rows {
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            row.name,
            row.hub.as_deref().unwrap_or("-"),
            row.link_id.as_deref().unwrap_or("-"),
            row.state
        )?;
    }
    Ok(0)
}

fn format_duration_ms(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m", seconds / 60),
        3600..=86_399 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

fn status(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let Some((name, json)) = parse_json_flag(args, true) else {
        writeln!(err, "usage: herdr machine dial status [<name>] [--json]")?;
        return Ok(2);
    };
    // Without a name, the only dial-in link is meant (hub notices suggest
    // `herdr machine dial status` without knowing the local name).
    let only_name;
    let name = match name {
        Some(name) => name,
        None => {
            let names = match dial_config::list_dial_names(root) {
                Ok(names) => names,
                Err(error) => {
                    writeln!(err, "herdr machine dial status: {error}")?;
                    return Ok(1);
                }
            };
            match names.as_slice() {
                [] => {
                    writeln!(
                        err,
                        "No dial-in links. Set one up with `herdr machine dial setup`."
                    )?;
                    return Ok(1);
                }
                [single] => {
                    only_name = single.clone();
                    only_name.as_str()
                }
                several => {
                    writeln!(
                        err,
                        "herdr machine dial status: several dial-in links exist; name one of: {}",
                        several.join(", ")
                    )?;
                    return Ok(2);
                }
            }
        }
    };
    let Some(paths) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    if !paths.dir.is_dir() {
        writeln!(
            err,
            "herdr machine dial status: no dial-in link named '{name}'"
        )?;
        return Ok(1);
    }
    let row = dial_row(&paths);
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&row).map_err(io::Error::other)?
        )?;
        return Ok(0);
    }
    let now = now_ms();
    let clean = |text: &str| sanitize_remote_text(text, 512);
    writeln!(out, "name:         {}", row.name)?;
    writeln!(out, "hub:          {}", row.hub.as_deref().unwrap_or("-"))?;
    writeln!(
        out,
        "link:         {}",
        row.link_id.as_deref().unwrap_or("-")
    )?;
    writeln!(
        out,
        "identity:     {}",
        row.identity_file.as_deref().unwrap_or("OpenSSH defaults")
    )?;
    if let Some(compression) = row.compression {
        writeln!(
            out,
            "compression:  {}",
            if compression { "on" } else { "off" }
        )?;
    }
    let mut state_line = row.state.to_string();
    if let Some(since) = row.since_ms.filter(|since| *since > 0) {
        state_line.push_str(&format!(
            " for {}",
            format_duration_ms(now.saturating_sub(since))
        ));
    }
    if let Some(next) = row.next_attempt_ms {
        state_line.push_str(&format!(
            ", next attempt in {}",
            format_duration_ms(next.saturating_sub(now))
        ));
    }
    if !row.running {
        state_line.push_str(&format!(
            " (start it with `herdr machine dial run {}`)",
            sh_quote(&row.name)
        ));
    }
    writeln!(out, "state:        {state_line}")?;
    if let Some(hub) = &row.hub_info {
        let mut line = hub
            .herdr_version
            .as_deref()
            .map(|version| format!("herdr {}", clean(version)))
            .unwrap_or_else(|| "herdr (unknown version)".into());
        if let Some(hostname) = &hub.hostname {
            line.push_str(&format!(" on {}", clean(hostname)));
        }
        writeln!(out, "hub runtime:  {line}")?;
    }
    if let Some(error) = &row.last_error {
        writeln!(
            out,
            "last error:   {} [{}] {} ago",
            clean(&error.message),
            clean(&error.code),
            format_duration_ms(now.saturating_sub(error.at_ms))
        )?;
    }
    if let Some(error) = &row.error {
        writeln!(out, "problem:      {}", clean(error))?;
    }
    Ok(0)
}

/// `service_installed` tells whether a user service runs the link `name`.
fn remove(
    root: &Path,
    args: &[String],
    service_installed: &dyn Fn(&str) -> io::Result<bool>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let [name] = args else {
        writeln!(err, "usage: herdr machine dial remove <name>")?;
        return Ok(2);
    };
    let Some(paths) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    match std::fs::symlink_metadata(&paths.dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            writeln!(
                err,
                "herdr machine dial remove: refusing to remove {}: not a directory",
                paths.dir.display()
            )?;
            return Ok(1);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            writeln!(
                err,
                "herdr machine dial remove: no dial-in link named '{name}'"
            )?;
            return Ok(1);
        }
        Err(error) => return Err(error),
    }
    // The service would keep restarting a dialer without its link.
    match service_installed(name) {
        Ok(false) => {}
        Ok(true) => {
            writeln!(
                err,
                "herdr machine dial remove: a user service runs '{name}'; remove it first with `herdr machine dial service uninstall {name}`"
            )?;
            return Ok(1);
        }
        Err(error) => {
            writeln!(err, "herdr machine dial remove: {error}")?;
            return Ok(1);
        }
    }
    match dial::dialer_is_running(&paths) {
        Ok(false) => {}
        Ok(true) => {
            writeln!(
                err,
                "herdr machine dial remove: the dialer for '{name}' is running; stop it first (if it runs as a service: `herdr machine dial service uninstall {name}`)"
            )?;
            return Ok(1);
        }
        Err(error) => {
            writeln!(err, "herdr machine dial remove: {error}")?;
            return Ok(1);
        }
    }
    let config = dial_config::load_config(&paths.config_file).ok().flatten();
    let mut entries = std::fs::read_dir(&paths.dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    writeln!(out, "Removing {}:", paths.dir.display())?;
    for entry in &entries {
        writeln!(out, "  {entry}")?;
    }
    std::fs::remove_dir_all(&paths.dir)?;
    writeln!(out, "Removed dial-in link '{name}'.")?;
    if let Some(config) = config {
        if let Some(identity) = config
            .identity_file
            .as_ref()
            .filter(|identity| !identity.starts_with(&paths.dir))
        {
            writeln!(
                out,
                "Kept the identity file {}; it is not owned by this link.",
                identity.display()
            )?;
        }
        writeln!(
            out,
            "On the hub, remove the machine and its authorized_keys line with `herdr machine remove {} --revoke`.",
            config.link_id
        )?;
    }
    Ok(0)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "herdr-dial-cli-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        crate::platform::ensure_private_directory(&dir).unwrap();
        dir
    }

    const LINK: &str = "0123456789abcdef0123456789abcdef";

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn run_setup(root: &Path, values: &[&str]) -> (i32, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = setup(
            root,
            &args(values),
            &OsString::from("/nonexistent/ssh-keygen"),
            &mut out,
            &mut err,
        )
        .unwrap();
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn identity(dir: &Path) -> PathBuf {
        let key = dir.join("id_test");
        std::fs::write(&key, b"PRIVATE").unwrap();
        std::fs::write(
            dir.join("id_test.pub"),
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user's key\n",
        )
        .unwrap();
        key
    }

    #[test]
    fn setup_writes_config_and_prints_the_authorize_command() {
        let root = scratch("setup");
        let key = identity(&root);
        let key_arg = key.to_str().unwrap();
        let (code, out, err) = run_setup(
            &root.join("dial"),
            &[
                "laptop",
                "--hub",
                "me@hub.example",
                "--link",
                LINK,
                "--identity",
                key_arg,
                "--no-compression",
            ],
        );
        assert_eq!(code, 0, "{err}");
        assert!(out.starts_with("Configured dial-in link 'laptop'"), "{out}");
        assert!(
            out.contains(&format!(
                "herdr machine authorize {LINK} 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user'\\''s key'"
            )),
            "{out}"
        );
        assert!(out.contains("--write"), "{out}");
        assert!(out.contains("`--pair` instead of `--link`"), "{out}");
        assert!(out.contains("ssh me@hub.example true"), "{out}");
        assert!(out.contains("herdr machine dial run laptop"), "{out}");
        assert!(
            out.contains("herdr machine dial service install laptop"),
            "{out}"
        );

        let paths = DialPaths::new(&root.join("dial"), "laptop");
        let config = dial_config::load_config(&paths.config_file)
            .unwrap()
            .unwrap();
        assert_eq!(config.hub, "me@hub.example");
        assert_eq!(config.link_id.as_str(), LINK);
        assert_eq!(config.identity_file.as_deref(), Some(key.as_path()));
        assert!(!config.compression);
        crate::platform::verify_private_directory(&paths.dir).unwrap();

        // Re-running setup updates the config and keeps unknown fields.
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&paths.config_file).unwrap()).unwrap();
        value["future"] = serde_json::json!(true);
        std::fs::write(&paths.config_file, serde_json::to_vec(&value).unwrap()).unwrap();
        let (code, out, _) = run_setup(
            &root.join("dial"),
            &[
                "laptop",
                "--link",
                LINK,
                "--hub",
                "other",
                "--identity",
                key_arg,
            ],
        );
        assert_eq!(code, 0);
        assert!(out.starts_with("Updated"), "{out}");
        let config = dial_config::load_config(&paths.config_file)
            .unwrap()
            .unwrap();
        assert_eq!(config.hub, "other");
        assert!(config.compression);
        assert_eq!(config.extra["future"], serde_json::json!(true));
    }

    #[test]
    fn setup_rejects_bad_arguments() {
        let root = scratch("setup-bad");
        let key = identity(&root);
        let key_arg = key.to_str().unwrap();
        for values in [
            vec![],
            vec!["laptop"],
            vec!["laptop", "--hub", "hub"],
            vec!["laptop", "--hub", "hub", "--link"],
            vec!["laptop", "--hub", "hub", "--link", "nothex"],
            vec!["bad name", "--hub", "hub", "--link", LINK],
            vec!["laptop", "--hub", "-oProxyCommand=x", "--link", LINK],
            vec!["laptop", "extra", "--hub", "hub", "--link", LINK],
            vec!["laptop", "--hub", "a", "--hub", "b", "--link", LINK],
            vec!["laptop", "--hub", "hub", "--link", LINK, "--bogus"],
        ] {
            let (code, _, err) = run_setup(&root, &values);
            assert_eq!(code, 2, "{values:?}: {err}");
        }
        // Operational failures: missing identity, ssh-keygen unavailable.
        let (code, _, err) = run_setup(
            &root,
            &[
                "laptop",
                "--hub",
                "hub",
                "--link",
                LINK,
                "--identity",
                "/no/such/key",
            ],
        );
        assert_eq!(code, 1, "{err}");
        assert!(err.contains("identity file not found"));
        let (code, _, err) = run_setup(&root, &["laptop", "--hub", "hub", "--link", LINK]);
        assert_eq!(code, 1);
        assert!(err.contains("ssh-keygen"), "{err}");
        assert!(!DialPaths::new(&root, "laptop").config_file.exists());
        let (code, _, _) = run_setup(
            &root,
            &[
                "laptop",
                "--hub",
                "hub",
                "--link",
                LINK,
                "--identity",
                key_arg,
            ],
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn keygen_arguments_and_shell_quoting() {
        assert_eq!(
            keygen_args("work", Path::new("/s/dial/work/id_ed25519")),
            [
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "herdr-dial:work",
                "-f",
                "/s/dial/work/id_ed25519"
            ]
            .map(OsString::from)
        );
        assert_eq!(sh_quote("me@hub.example"), "me@hub.example");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        assert_eq!(sh_quote(""), "''");
    }

    fn no_service(_name: &str) -> io::Result<bool> {
        Ok(false)
    }

    fn capture(
        command: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>) -> io::Result<i32>,
    ) -> (i32, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = command(&mut out, &mut err).unwrap();
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn status_without_a_name_reports_the_only_link() {
        let root = scratch("status-default");
        let key = identity(&root);
        let dial_root = root.join("dial");
        let setup_link = |name: &str| {
            let (code, _, err) = run_setup(
                &dial_root,
                &[
                    name,
                    "--hub",
                    "me@hub",
                    "--link",
                    LINK,
                    "--identity",
                    key.to_str().unwrap(),
                ],
            );
            assert_eq!(code, 0, "{err}");
        };

        setup_link("work");
        let (code, out, err) = capture(|out, err| status(&dial_root, &[], out, err));
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("name:         work"), "{out}");
        let (code, out, _) = capture(|out, err| status(&dial_root, &args(&["--json"]), out, err));
        assert_eq!(code, 0);
        let row: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(row["name"], "work");

        setup_link("play");
        let (code, out, err) = capture(|out, err| status(&dial_root, &[], out, err));
        assert_eq!(code, 2);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("play, work"), "{err}");
    }

    #[test]
    fn list_status_and_remove_report_configured_links() {
        let root = scratch("manage");
        let key = identity(&root);
        let dial_root = root.join("dial");

        let (code, out, _) = capture(|out, err| list(&dial_root, &[], out, err));
        assert_eq!(code, 0);
        assert!(out.contains("No dial-in links"));

        let (code, _, err) = run_setup(
            &dial_root,
            &[
                "work",
                "--hub",
                "me@hub",
                "--link",
                LINK,
                "--identity",
                key.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 0, "{err}");
        let paths = DialPaths::new(&dial_root, "work");

        let (code, out, _) = capture(|out, err| list(&dial_root, &[], out, err));
        assert_eq!(code, 0);
        assert_eq!(out, format!("work\tme@hub\t{LINK}\tstopped\n"));

        // A stale state file from a dead dialer still reads as stopped.
        let mut state = DialState::new(DialRunState::Connected);
        state.last_error = Some(ErrorRecord::new("link_lost", "the hub closed the link"));
        dial_config::write_state(&paths.state_file, &state).unwrap();
        let (code, out, _) = capture(|out, err| list(&dial_root, &args(&["--json"]), out, err));
        assert_eq!(code, 0);
        let rows: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(rows[0]["name"], "work");
        assert_eq!(rows[0]["state"], "stopped");
        assert_eq!(rows[0]["running"], false);
        assert_eq!(rows[0]["last_error"]["code"], "link_lost");

        // While a dialer holds the run lock, its state is reported.
        let held = crate::platform::try_lock_exclusive(&paths.lock_file)
            .unwrap()
            .unwrap();
        let (code, out, _) =
            capture(|out, err| status(&dial_root, &args(&["work", "--json"]), out, err));
        assert_eq!(code, 0);
        let row: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(row["running"], true);
        assert_eq!(row["state"], "connected");
        assert_eq!(row["link_id"], LINK);
        let (code, out, _) = capture(|out, err| status(&dial_root, &args(&["work"]), out, err));
        assert_eq!(code, 0);
        assert!(out.contains("state:        connected for"), "{out}");
        assert!(
            out.contains("last error:   the hub closed the link [link_lost]"),
            "{out}"
        );

        let (code, _, err) =
            capture(|out, err| remove(&dial_root, &args(&["work"]), &no_service, out, err));
        assert_eq!(code, 1);
        assert!(err.contains("running"), "{err}");
        drop(held);

        // An installed service would restart the dialer: removal waits for it.
        let (code, _, err) =
            capture(|out, err| remove(&dial_root, &args(&["work"]), &|_| Ok(true), out, err));
        assert_eq!(code, 1);
        assert!(
            err.contains("herdr machine dial service uninstall work"),
            "{err}"
        );
        assert!(paths.dir.exists());

        let (code, out, _) = capture(|out, err| status(&dial_root, &args(&["work"]), out, err));
        assert_eq!(code, 0);
        assert!(out.contains("state:        stopped"), "{out}");

        let (code, out, _) =
            capture(|out, err| remove(&dial_root, &args(&["work"]), &no_service, out, err));
        assert_eq!(code, 0);
        assert!(out.contains("config.json"), "{out}");
        assert!(
            out.contains(&format!("herdr machine remove {LINK}")),
            "{out}"
        );
        assert!(out.contains("Kept the identity file"), "{out}");
        assert!(!paths.dir.exists());
        assert!(key.exists(), "external identity must be kept");

        let (code, _, _) =
            capture(|out, err| remove(&dial_root, &args(&["work"]), &no_service, out, err));
        assert_eq!(code, 1);
        let (code, _, _) = capture(|out, err| status(&dial_root, &args(&["work"]), out, err));
        assert_eq!(code, 1);
        for bad in [vec!["a", "b"], vec!["--json", "--json"], vec!["-x"]] {
            let (code, _, _) = capture(|out, err| status(&dial_root, &args(&bad), out, err));
            assert_eq!(code, 2, "{bad:?}");
        }
        // Without a name and without links there is nothing to show.
        for empty in [vec![], vec!["--json"]] {
            let (code, _, err) = capture(|out, err| status(&dial_root, &args(&empty), out, err));
            assert_eq!(code, 1, "{empty:?}");
            assert!(err.contains("No dial-in links"), "{err}");
        }
        let (code, _, _) = capture(|out, err| list(&dial_root, &args(&["x"]), out, err));
        assert_eq!(code, 2);
    }

    #[test]
    fn durations_are_compact() {
        assert_eq!(format_duration_ms(0), "0s");
        assert_eq!(format_duration_ms(59_999), "59s");
        assert_eq!(format_duration_ms(60_000), "1m");
        assert_eq!(format_duration_ms(7_200_000), "2h");
        assert_eq!(format_duration_ms(3 * 86_400_000), "3d");
    }
}
