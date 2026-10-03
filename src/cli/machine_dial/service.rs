//! `herdr machine dial service install|uninstall|status <name>`: keeps a
//! dial-in link running unattended as a user service (systemd user unit on
//! Linux, launchd agent on macOS; see `crate::platform::dial_service_*`).

use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use super::{named_paths, parse_json_flag};
use crate::platform::{DialServiceReport, DialServiceSpec};
use crate::remote::link::dial_config;

const USAGE: &str = "usage:
  herdr machine dial service install <name> [--no-start] [--herdr-path <path>]
  herdr machine dial service uninstall <name>
  herdr machine dial service status <name> [--json]";

/// Herdr's config and state roots: the service must find the link and the
/// server where the shell that set the link up does.
const SERVICE_ENV: [&str; 2] = ["XDG_CONFIG_HOME", "XDG_STATE_HOME"];

/// Also kept from the installing shell when a service unit can hold them:
/// the locale, which the server the service starts passes on to its panes,
/// and `PATH`, for programs the user's ssh config runs (launchd starts
/// agents with neither).
const SHELL_ENV: [&str; 4] = ["LANG", "LC_ALL", "LC_CTYPE", "PATH"];

/// The service environment from `var`: every set [`SERVICE_ENV`] variable,
/// and the set [`SHELL_ENV`] variables that a unit file can hold literally.
fn service_env(var: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    let literal = |value: &str| {
        !value
            .chars()
            .any(|ch| ch.is_control() || ch == '"' || ch == '\\')
    };
    SERVICE_ENV
        .iter()
        .map(|key| (key, true))
        .chain(SHELL_ENV.iter().map(|key| (key, false)))
        .filter_map(|(key, required)| {
            let value = var(key).filter(|value| !value.is_empty())?;
            (required || literal(&value)).then(|| (key.to_string(), value))
        })
        .collect()
}

pub(super) fn run_service_command(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("install") => install(root, &args[1..], out, err),
        Some("uninstall") => uninstall(root, &args[1..], out, err),
        Some("status") => status(root, &args[1..], out, err),
        _ => {
            writeln!(err, "{USAGE}")?;
            Ok(2)
        }
    }
}

fn failed(err: &mut impl Write, error: impl std::fmt::Display) -> io::Result<i32> {
    writeln!(err, "herdr machine dial service: {error}")?;
    Ok(1)
}

fn print_report(out: &mut impl Write, report: &DialServiceReport) -> io::Result<()> {
    if let Some(path) = &report.unit_path {
        writeln!(out, "  unit: {}", path.display())?;
    }
    for note in &report.notes {
        writeln!(out, "  {note}")?;
    }
    Ok(())
}

/// `<name> [--no-start] [--herdr-path <path>]`; `None` on a usage error.
fn parse_install_args(args: &[String]) -> Option<(&str, bool, Option<&Path>)> {
    let mut name = None;
    let mut start = true;
    let mut herdr_path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--no-start" if start => start = false,
            "--herdr-path" if herdr_path.is_none() => herdr_path = Some(Path::new(iter.next()?)),
            other if !other.starts_with('-') && name.is_none() => name = Some(other),
            _ => return None,
        }
    }
    Some((name?, start, herdr_path))
}

fn install(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let Some((name, start, herdr_path)) = parse_install_args(args) else {
        writeln!(err, "{USAGE}")?;
        return Ok(2);
    };
    let Some(paths) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    match dial_config::load_config(&paths.config_file) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return failed(
                err,
                format!("no dial-in link named '{name}'; run `herdr machine dial setup` first"),
            )
        }
        Err(error) => return failed(err, error),
    }
    let (herdr_path, note) = match crate::remote::link::stable_herdr_path(herdr_path) {
        Ok(choice) => choice,
        Err(error) => return failed(err, error),
    };
    if let Some(note) = note {
        writeln!(err, "{note}")?;
    }
    let spec = DialServiceSpec {
        name: name.to_string(),
        herdr_path,
        log_path: paths.dir.join("service.log"),
        env: service_env(|key| std::env::var(key).ok()),
    };
    let report = match crate::platform::dial_service_install(&spec, start) {
        Ok(report) => report,
        Err(error) => return failed(err, error),
    };
    let verb = if start {
        "Installed and started"
    } else {
        "Installed"
    };
    writeln!(out, "{verb} the dial-in service for '{name}'.")?;
    print_report(out, &report)?;
    Ok(0)
}

fn uninstall(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let [name] = args else {
        writeln!(err, "{USAGE}")?;
        return Ok(2);
    };
    let Some(_) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    match crate::platform::dial_service_uninstall(name) {
        Ok(report) => {
            writeln!(out, "Stopped and removed the dial-in service for '{name}'.")?;
            print_report(out, &report)?;
            Ok(0)
        }
        Err(error) => failed(err, error),
    }
}

#[derive(Serialize)]
struct StatusRow<'a> {
    name: &'a str,
    installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    notes: &'a [String],
}

fn status(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let Some((Some(name), json)) = parse_json_flag(args, true) else {
        writeln!(err, "{USAGE}")?;
        return Ok(2);
    };
    let Some(_) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    let report = match crate::platform::dial_service_status(name) {
        Ok(report) => report,
        Err(error) => return failed(err, error),
    };
    if json {
        let row = StatusRow {
            name,
            installed: report.unit_path.is_some(),
            unit_path: report
                .unit_path
                .as_ref()
                .map(|path| path.display().to_string()),
            active: report.active,
            notes: &report.notes,
        };
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&row).map_err(io::Error::other)?
        )?;
        return Ok(0);
    }
    match &report.unit_path {
        Some(_) => writeln!(out, "service '{name}': installed")?,
        None => writeln!(
            out,
            "service '{name}': not installed (install it with `herdr machine dial service install {name}`)"
        )?,
    }
    let running = match report.active {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };
    writeln!(out, "  running: {running}")?;
    print_report(out, &report)?;
    Ok(0)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn run(root: &Path, values: &[&str]) -> (i32, String, String) {
        let args = values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_service_command(root, &args, &mut out, &mut err).unwrap();
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn the_service_keeps_the_state_roots_locale_and_path() {
        let env = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            service_env(move |key| {
                pairs
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
            })
        };
        let pairs = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<Vec<_>>()
        };
        assert!(env(&[]).is_empty());
        assert_eq!(
            env(&[
                ("PATH", "/opt/homebrew/bin:/usr/bin"),
                ("HOME", "/Users/me"),
                ("LANG", "en_US.UTF-8"),
                ("LC_CTYPE", ""),
                ("XDG_STATE_HOME", "/Users/me/state"),
            ]),
            pairs(&[
                ("XDG_STATE_HOME", "/Users/me/state"),
                ("LANG", "en_US.UTF-8"),
                ("PATH", "/opt/homebrew/bin:/usr/bin"),
            ])
        );
        // A unit cannot hold these literally: dropped, except the state
        // roots, which the install must refuse instead.
        assert_eq!(
            env(&[
                ("PATH", "/a\"b:/usr/bin"),
                ("LC_ALL", "C\nx"),
                ("XDG_CONFIG_HOME", "/c\\d"),
            ]),
            pairs(&[("XDG_CONFIG_HOME", "/c\\d")])
        );
    }

    // Only paths that stop before the service manager: tests never run
    // systemctl or launchctl.
    #[test]
    fn service_commands_validate_before_touching_the_service_manager() {
        let root =
            std::env::temp_dir().join(format!("herdr-dial-service-cli-{}", std::process::id()));
        for usage in [
            &[][..],
            &["start", "work"],
            &["install"],
            &["install", "work", "--no-start", "--no-start"],
            &["install", "work", "--herdr-path"],
            &["install", "work", "extra"],
            &["install", "work", "--bogus"],
            &["uninstall"],
            &["uninstall", "a", "b"],
            &["status"],
            &["status", "--json"],
            &["install", "bad name"],
            &["status", "bad/name"],
        ] {
            let (code, out, err) = run(&root, usage);
            assert_eq!(code, 2, "{usage:?}: {err}");
            assert!(out.is_empty(), "{usage:?}: {out}");
        }
        let (code, _, err) = run(&root, &["install", "work", "--herdr-path", "/x/herdr"]);
        assert_eq!(code, 1);
        assert!(
            err.contains("no dial-in link named 'work'; run `herdr machine dial setup` first"),
            "{err}"
        );
    }
}
