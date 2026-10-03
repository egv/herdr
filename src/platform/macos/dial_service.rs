//! `herdr machine dial service` on macOS: a launchd agent
//! `~/Library/LaunchAgents/dev.herdr.dial.<name>.plist` in the user's GUI
//! domain.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use crate::platform::unix_common::{checked_service_command, run_service_command};
use crate::platform::{DialServiceReport, DialServiceSpec};

type Runner<'a> = &'a mut dyn FnMut(Command) -> io::Result<Output>;

/// launchd can refuse a bootstrap right after a bootout (EIO) while it still
/// tears the old job down.
const BOOTSTRAP_RETRY_DELAY: Duration = Duration::from_secs(1);
/// `bootout` returns before the old dialer exits; launchd kills it after
/// its exit timeout (20 seconds by default).
const UNLOAD_POLL: Duration = Duration::from_millis(250);
const UNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn dial_service_install(
    spec: &DialServiceSpec,
    start: bool,
) -> io::Result<DialServiceReport> {
    install(&Launchd::from_env()?, spec, start, &mut run_service_command)
}

pub(crate) fn dial_service_uninstall(name: &str) -> io::Result<DialServiceReport> {
    uninstall(&Launchd::from_env()?, name, &mut run_service_command)
}

pub(crate) fn dial_service_status(name: &str) -> io::Result<DialServiceReport> {
    status(&Launchd::from_env()?, name, &mut run_service_command)
}

/// Whether the agent plist for `name` exists (launchd is not asked).
pub(crate) fn dial_service_installed(name: &str) -> io::Result<bool> {
    Ok(Launchd::from_env()?.plist(name).exists())
}

struct Launchd {
    home: PathBuf,
    agents_dir: PathBuf,
    /// `gui/<uid>`.
    domain: String,
    bootstrap_retry_delay: Duration,
    unload_poll: Duration,
    unload_timeout: Duration,
}

impl Launchd {
    fn from_env() -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        let uid = crate::platform::current_uid()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no user id"))?;
        Ok(Self {
            agents_dir: home.join("Library/LaunchAgents"),
            home,
            domain: format!("gui/{uid}"),
            bootstrap_retry_delay: BOOTSTRAP_RETRY_DELAY,
            unload_poll: UNLOAD_POLL,
            unload_timeout: UNLOAD_TIMEOUT,
        })
    }

    fn plist(&self, name: &str) -> PathBuf {
        self.agents_dir.join(format!("{}.plist", label(name)))
    }

    /// `gui/<uid>/<label>`.
    fn target(&self, name: &str) -> String {
        format!("{}/{}", self.domain, label(name))
    }

    fn bootstrap_hint(&self, plist: &Path) -> String {
        format!(
            "it starts at your next login, or now with `launchctl bootstrap {} '{}'`",
            self.domain,
            plist.display()
        )
    }
}

fn label(name: &str) -> String {
    format!("dev.herdr.dial.{name}")
}

fn launchctl(run: Runner<'_>, args: &[&str]) -> io::Result<String> {
    let mut command = Command::new("launchctl");
    command.args(args);
    checked_service_command(run, command)
}

/// `text` escaped for XML; control characters (invalid in XML 1.0) are
/// refused.
fn xml(text: &str) -> io::Result<String> {
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a launchd plist cannot contain {text:?}"),
        ));
    }
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            ch => escaped.push(ch),
        }
    }
    Ok(escaped)
}

fn xml_path(path: &Path) -> io::Result<String> {
    xml(path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not valid UTF-8: {}", path.display()),
        )
    })?)
}

/// The agent for `spec`, started in `home` like a login shell (launchd
/// starts agents in `/`, where the server would open its first panes).
fn render_plist(spec: &DialServiceSpec, home: &Path) -> io::Result<String> {
    let mut env = String::new();
    if !spec.env.is_empty() {
        env.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
        for (key, value) in &spec.env {
            env.push_str(&format!(
                "    <key>{}</key>\n    <string>{}</string>\n",
                xml(key)?,
                xml(value)?
            ));
        }
        env.push_str("  </dict>\n");
    }
    let log = xml_path(&spec.log_path)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{herdr}</string>
    <string>machine</string>
    <string>dial</string>
    <string>run</string>
    <string>{name}</string>
  </array>
{env}  <key>WorkingDirectory</key>
  <string>{home}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>AbandonProcessGroup</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        label = xml(&label(&spec.name))?,
        herdr = xml_path(&spec.herdr_path)?,
        name = xml(&spec.name)?,
        home = xml_path(home)?,
    ))
}

/// Writes the agent plist; launchd refuses one that others can write.
fn write_plist(plist: &Path, content: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(plist, content)?;
    std::fs::set_permissions(plist, std::fs::Permissions::from_mode(0o644))
}

/// The service's panes run under the herdr executable's macOS privacy
/// identity, not the Terminal's: what to grant it.
fn privacy_note(herdr: &Path) -> String {
    format!(
        "macOS attributes this service's panes to {}: grant it Full Disk Access (or Files and Folders) in System Settings > Privacy & Security for projects in Desktop, Documents, Downloads, iCloud Drive or network volumes, and again after it is updated",
        herdr.display()
    )
}

fn install(
    launchd: &Launchd,
    spec: &DialServiceSpec,
    start: bool,
    run: Runner<'_>,
) -> io::Result<DialServiceReport> {
    let content = render_plist(spec, &launchd.home)?;
    std::fs::create_dir_all(&launchd.agents_dir)?;
    let plist = launchd.plist(&spec.name);
    let previous = match std::fs::read(&plist) {
        Ok(previous) => Some(previous),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    write_plist(&plist, content.as_bytes())?;
    let target = launchd.target(&spec.name);
    // launchd refuses a disabled agent (`launchctl disable`, `unload -w`),
    // now and at login. Fails without a GUI domain, which is reported below.
    let _ = launchctl(run, &["enable", &target]);
    let mut notes = vec![
        format!("logs: {}", spec.log_path.display()),
        privacy_note(&spec.herdr_path),
    ];
    if start {
        let replaced = unload(launchd, &target, run);
        if let Err(error) = bootstrap(launchd, &spec.name, &plist, run) {
            restore_plist(&plist, previous.as_deref());
            if !replaced || previous.is_none() {
                return Err(error);
            }
            // Keep the link that was running before this install.
            let outcome = match bootstrap_once(launchd, &plist, run) {
                Ok(()) => "the previous dial-in service was put back and started again".to_string(),
                Err(restart) => format!(
                    "the previous dial-in service was put back but did not start again ({restart}); {}",
                    launchd.bootstrap_hint(&plist)
                ),
            };
            return Err(io::Error::new(error.kind(), format!("{error}; {outcome}")));
        }
    } else {
        notes.push(launchd.bootstrap_hint(&plist));
    }
    Ok(DialServiceReport {
        unit_path: Some(plist),
        active: start.then_some(true),
        notes,
    })
}

/// Boots out the loaded agent `target`, which keeps its old definition
/// otherwise, and waits until launchd no longer lists it. Whether one was
/// loaded.
fn unload(launchd: &Launchd, target: &str, run: Runner<'_>) -> bool {
    // Fails when the agent is not loaded, which is fine here.
    if launchctl(run, &["bootout", target]).is_err() {
        return false;
    }
    let deadline = Instant::now() + launchd.unload_timeout;
    while launchctl(run, &["print", target]).is_ok() {
        if Instant::now() >= deadline {
            tracing::warn!(%target, "launchd still lists the dial service after its bootout");
            break;
        }
        std::thread::sleep(launchd.unload_poll);
    }
    true
}

/// Loads the agent from `plist`.
fn bootstrap(launchd: &Launchd, name: &str, plist: &Path, run: Runner<'_>) -> io::Result<()> {
    if bootstrap_once(launchd, plist, run).is_ok() {
        return Ok(());
    }
    // Without a GUI login (a headless Mac reached over ssh) there is no
    // `gui/<uid>` domain to load user agents into.
    if launchctl(run, &["print", &launchd.domain]).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "launchd has no {domain} domain because this user is not logged in to the Mac's desktop; log in there and install again, or install with --no-start so it starts at the next desktop login. On a Mac nobody logs in to, keep `herdr machine dial run {name}` running under another supervisor",
                domain = launchd.domain
            ),
        ));
    }
    std::thread::sleep(launchd.bootstrap_retry_delay);
    bootstrap_once(launchd, plist, run).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{error}; check that the agent is not disabled (`launchctl print-disabled {}`) and that herdr may run in the background (System Settings > General > Login Items)",
                launchd.domain
            ),
        )
    })
}

fn bootstrap_once(launchd: &Launchd, plist: &Path, run: Runner<'_>) -> io::Result<()> {
    let mut command = Command::new("launchctl");
    command.arg("bootstrap").arg(&launchd.domain).arg(plist);
    checked_service_command(run, command).map(drop)
}

/// Puts back the plist an install replaced, or removes the one it wrote.
fn restore_plist(plist: &Path, previous: Option<&[u8]>) {
    let restored = match previous {
        Some(previous) => std::fs::write(plist, previous),
        None => std::fs::remove_file(plist),
    };
    if let Err(error) = restored {
        tracing::warn!(%error, path = %plist.display(), "could not restore the dial service plist");
    }
}

fn uninstall(launchd: &Launchd, name: &str, run: Runner<'_>) -> io::Result<DialServiceReport> {
    // Fails when the agent is not loaded, which is fine here.
    let unloaded = launchctl(run, &["bootout", &launchd.target(name)]).is_ok();
    let plist = launchd.plist(name);
    let mut report = DialServiceReport {
        active: Some(false),
        ..DialServiceReport::default()
    };
    match std::fs::remove_file(&plist) {
        Ok(()) => report.notes.push(format!("removed {}", plist.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if !unloaded {
                report
                    .notes
                    .push("no dial-in service is installed".to_string());
            }
        }
        Err(error) => return Err(error),
    }
    Ok(report)
}

fn status(launchd: &Launchd, name: &str, run: Runner<'_>) -> io::Result<DialServiceReport> {
    let plist = launchd.plist(name);
    let installed = plist.exists();
    // `launchctl print` fails when the agent is not loaded.
    let printed = launchctl(run, &["print", &launchd.target(name)]);
    let active = printed
        .as_deref()
        .is_ok_and(|text| text.lines().any(|line| line.trim() == "state = running"));
    let mut notes = Vec::new();
    if installed && printed.is_err() {
        notes.push(format!("not loaded; {}", launchd.bootstrap_hint(&plist)));
    }
    Ok(DialServiceReport {
        unit_path: installed.then_some(plist),
        active: Some(active),
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn scratch(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "herdr-launchd-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn launchd(root: &Path) -> Launchd {
        Launchd {
            home: root.to_path_buf(),
            agents_dir: root.join("Library/LaunchAgents"),
            domain: "gui/501".into(),
            bootstrap_retry_delay: Duration::ZERO,
            unload_poll: Duration::ZERO,
            unload_timeout: Duration::ZERO,
        }
    }

    fn command_line(command: &Command) -> String {
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn exited(code: i32) -> io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: b"Bootstrap failed: 5: Input/output error\n".to_vec(),
        })
    }

    fn spec(herdr: &str) -> DialServiceSpec {
        DialServiceSpec {
            name: "work".into(),
            herdr_path: PathBuf::from(herdr),
            log_path: PathBuf::from("/Users/me/state/dial/work/service.log"),
            env: Vec::new(),
        }
    }

    /// Records each command line; answers with `stdout`, failing commands
    /// that contain `fail`.
    fn fake<'a>(
        calls: &'a mut Vec<String>,
        stdout: &'a str,
        fail: Option<&'a str>,
    ) -> impl FnMut(Command) -> io::Result<Output> + 'a {
        move |command| {
            let line = std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            let failed = fail.is_some_and(|fail| line.contains(fail));
            calls.push(line);
            Ok(Output {
                status: ExitStatus::from_raw(if failed { 1 << 8 } else { 0 }),
                stdout: stdout.as_bytes().to_vec(),
                stderr: b"Bootstrap failed: 5: Input/output error\n".to_vec(),
            })
        }
    }

    #[test]
    fn plist_runs_the_dial_name_and_keeps_the_server_on_stop() {
        let mut spec = spec("/opt/homebrew/bin/herdr");
        spec.env = vec![("XDG_STATE_HOME".into(), "/Users/me/s&s".into())];
        assert_eq!(
            render_plist(&spec, Path::new("/Users/me")).unwrap(),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.herdr.dial.work</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/herdr</string>
    <string>machine</string>
    <string>dial</string>
    <string>run</string>
    <string>work</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>XDG_STATE_HOME</key>
    <string>/Users/me/s&amp;s</string>
  </dict>
  <key>WorkingDirectory</key>
  <string>/Users/me</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>AbandonProcessGroup</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/me/state/dial/work/service.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/me/state/dial/work/service.log</string>
</dict>
</plist>
"#
        );
    }

    #[test]
    fn plist_strings_are_escaped_or_refused() {
        assert_eq!(
            xml(r#"<a href="x">'&'</a>"#).unwrap(),
            "&lt;a href=&quot;x&quot;&gt;&apos;&amp;&apos;&lt;/a&gt;"
        );
        let home = Path::new("/Users/me");
        let plist = render_plist(&spec("/Apps/R&D <1>/herdr"), home).unwrap();
        assert!(
            plist.contains("<string>/Apps/R&amp;D &lt;1&gt;/herdr</string>"),
            "{plist}"
        );
        assert_eq!(
            render_plist(&spec("/a\nb/herdr"), home).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn install_replaces_a_loaded_agent() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = scratch("install");
        let launchd = launchd(&root);
        let plist = launchd.plist("work");
        // A group-writable leftover, which launchd would refuse.
        std::fs::create_dir_all(&launchd.agents_dir).unwrap();
        std::fs::write(&plist, b"old").unwrap();
        std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o664)).unwrap();
        let mut calls = Vec::new();
        let report = install(
            &launchd,
            &spec("/usr/local/bin/herdr"),
            true,
            &mut fake(&mut calls, "", Some("bootout")),
        )
        .unwrap();
        assert_eq!(
            calls,
            [
                "launchctl enable gui/501/dev.herdr.dial.work".to_string(),
                "launchctl bootout gui/501/dev.herdr.dial.work".to_string(),
                format!("launchctl bootstrap gui/501 {}", plist.display()),
            ]
        );
        assert_eq!(report.unit_path.as_deref(), Some(plist.as_path()));
        assert_eq!(report.active, Some(true));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("Full Disk Access")
                    && note.contains("/usr/local/bin/herdr"))
        );
        let content = std::fs::read_to_string(&plist).unwrap();
        assert!(content.contains("<string>dev.herdr.dial.work</string>"));
        assert!(content.contains(&format!("<string>{}</string>", root.display())));
        assert_eq!(
            std::fs::metadata(&plist).unwrap().permissions().mode() & 0o777,
            0o644
        );

        let mut calls = Vec::new();
        let report = install(
            &launchd,
            &spec("/usr/local/bin/herdr"),
            false,
            &mut fake(&mut calls, "", None),
        )
        .unwrap();
        assert_eq!(calls, ["launchctl enable gui/501/dev.herdr.dial.work"]);
        assert_eq!(report.active, None);
        assert!(report.notes.iter().any(|note| note.contains("next login")));

        // The agent was not loaded: the old plist is put back, not started.
        let installed = std::fs::read(&plist).unwrap();
        let mut calls = Vec::new();
        let error = install(
            &launchd,
            &spec("/opt/herdr"),
            true,
            &mut fake(&mut calls, "", Some("boot")),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("Input/output error"), "{message}");
        assert!(message.contains("print-disabled gui/501"), "{message}");
        assert!(message.contains("Login Items"), "{message}");
        // Retried once in the existing domain.
        assert_eq!(
            calls,
            [
                "launchctl enable gui/501/dev.herdr.dial.work".to_string(),
                "launchctl bootout gui/501/dev.herdr.dial.work".to_string(),
                format!("launchctl bootstrap gui/501 {}", plist.display()),
                "launchctl print gui/501".to_string(),
                format!("launchctl bootstrap gui/501 {}", plist.display()),
            ]
        );
        assert_eq!(std::fs::read(&plist).unwrap(), installed);
    }

    #[test]
    fn reinstalling_waits_for_the_old_agent_and_restarts_it_on_failure() {
        let root = scratch("reinstall");
        let mut launchd = launchd(&root);
        launchd.unload_timeout = Duration::from_secs(60);
        let plist = launchd.plist("work");
        std::fs::create_dir_all(&launchd.agents_dir).unwrap();
        std::fs::write(&plist, b"previous").unwrap();

        // launchd lists the old agent until it has exited; bootstraps fail
        // until then.
        let mut calls = Vec::new();
        let mut prints = 0;
        let mut exiting = |command: Command| {
            let line = command_line(&command);
            calls.push(line.clone());
            if line.ends_with("print gui/501/dev.herdr.dial.work") {
                prints += 1;
                return exited(if prints < 3 { 0 } else { 113 });
            }
            exited(if line.contains("bootstrap") && prints < 3 {
                5
            } else {
                0
            })
        };
        install(&launchd, &spec("/usr/local/bin/herdr"), true, &mut exiting).unwrap();
        assert_eq!(
            calls,
            [
                "launchctl enable gui/501/dev.herdr.dial.work".to_string(),
                "launchctl bootout gui/501/dev.herdr.dial.work".to_string(),
                "launchctl print gui/501/dev.herdr.dial.work".to_string(),
                "launchctl print gui/501/dev.herdr.dial.work".to_string(),
                "launchctl print gui/501/dev.herdr.dial.work".to_string(),
                format!("launchctl bootstrap gui/501 {}", plist.display()),
            ]
        );

        // The new agent does not load: the previous one is put back and
        // started again, so the link keeps running.
        launchd.unload_timeout = Duration::ZERO;
        std::fs::write(&plist, b"previous").unwrap();
        let mut calls = Vec::new();
        let mut bootstraps = 0;
        let mut refusing = |command: Command| {
            let line = command_line(&command);
            calls.push(line.clone());
            let failed = line.contains("bootstrap") && {
                bootstraps += 1;
                bootstraps <= 2
            };
            exited(if failed { 5 } else { 0 })
        };
        let error =
            install(&launchd, &spec("/usr/local/bin/herdr"), true, &mut refusing).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("previous dial-in service was put back and started again"),
            "{message}"
        );
        assert_eq!(std::fs::read(&plist).unwrap(), b"previous");
        assert_eq!(bootstraps, 3, "{calls:?}");

        // It does not start either: said so, with how to start it.
        std::fs::write(&plist, b"previous").unwrap();
        let mut calls = Vec::new();
        let error = install(
            &launchd,
            &spec("/usr/local/bin/herdr"),
            true,
            &mut fake(&mut calls, "", Some("bootstrap")),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("did not start again"), "{message}");
        assert!(message.contains("launchctl bootstrap gui/501"), "{message}");
        assert_eq!(std::fs::read(&plist).unwrap(), b"previous");
    }

    #[test]
    fn bootstrap_is_retried_once_and_a_missing_gui_domain_is_explained() {
        let root = scratch("bootstrap");
        let launchd = launchd(&root);
        let plist = launchd.plist("work");

        // The EIO quirk: the first bootstrap after a bootout fails.
        let mut calls = Vec::new();
        let mut bootstraps = 0;
        let mut flaky = |command: Command| -> io::Result<Output> {
            let line = std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            let failed = line.contains("bootstrap") && {
                bootstraps += 1;
                bootstraps == 1
            };
            calls.push(line);
            Ok(Output {
                status: ExitStatus::from_raw(if failed { 5 << 8 } else { 0 }),
                stdout: Vec::new(),
                stderr: b"Bootstrap failed: 5: Input/output error\n".to_vec(),
            })
        };
        let report = install(&launchd, &spec("/usr/local/bin/herdr"), true, &mut flaky).unwrap();
        assert_eq!(report.active, Some(true));
        // enable, bootout, print (the old agent), bootstrap, print, bootstrap.
        assert_eq!(calls.len(), 6, "{calls:?}");
        assert!(plist.exists());

        // No desktop login: no retry, a clear message, and no plist left.
        std::fs::remove_file(&plist).unwrap();
        let mut calls = Vec::new();
        let error = install(
            &launchd,
            &spec("/usr/local/bin/herdr"),
            true,
            &mut fake(&mut calls, "", Some("gui/501")),
        )
        .unwrap_err();
        assert_eq!(
            calls,
            [
                "launchctl enable gui/501/dev.herdr.dial.work".to_string(),
                "launchctl bootout gui/501/dev.herdr.dial.work".to_string(),
                format!("launchctl bootstrap gui/501 {}", plist.display()),
                "launchctl print gui/501".to_string(),
            ]
        );
        let message = error.to_string();
        assert!(
            message.contains("not logged in") && message.contains("--no-start"),
            "{message}"
        );
        assert!(message.contains("herdr machine dial run work"), "{message}");
        assert!(!plist.exists(), "the written plist is removed");
    }

    #[test]
    fn uninstall_unloads_and_removes_the_plist() {
        let root = scratch("uninstall");
        let launchd = launchd(&root);
        let mut calls = Vec::new();
        let report =
            uninstall(&launchd, "work", &mut fake(&mut calls, "", Some("bootout"))).unwrap();
        assert_eq!(calls, ["launchctl bootout gui/501/dev.herdr.dial.work"]);
        assert!(report.notes[0].contains("no dial-in service"));

        std::fs::create_dir_all(&launchd.agents_dir).unwrap();
        std::fs::write(launchd.plist("work"), b"plist").unwrap();
        let mut calls = Vec::new();
        let report = uninstall(&launchd, "work", &mut fake(&mut calls, "", None)).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(!launchd.plist("work").exists());
        assert!(report.notes[0].starts_with("removed"), "{:?}", report.notes);
    }

    #[test]
    fn status_parses_the_running_state() {
        let root = scratch("status");
        let launchd = launchd(&root);
        std::fs::create_dir_all(&launchd.agents_dir).unwrap();
        std::fs::write(launchd.plist("work"), b"plist").unwrap();
        let mut calls = Vec::new();
        let report = status(
            &launchd,
            "work",
            &mut fake(
                &mut calls,
                "gui/501/dev.herdr.dial.work = {\n\tactive count = 1\n\tstate = running\n}\n",
                None,
            ),
        )
        .unwrap();
        assert_eq!(calls, ["launchctl print gui/501/dev.herdr.dial.work"]);
        assert_eq!(report.unit_path, Some(launchd.plist("work")));
        assert_eq!(report.active, Some(true));
        assert!(report.notes.is_empty());

        let mut calls = Vec::new();
        let report = status(&launchd, "work", &mut fake(&mut calls, "", Some("print"))).unwrap();
        assert_eq!(report.active, Some(false));
        assert!(
            report.notes[0].starts_with("not loaded"),
            "{:?}",
            report.notes
        );

        let mut calls = Vec::new();
        let report = status(
            &launchd,
            "other",
            &mut fake(&mut calls, "state = waiting\n", None),
        )
        .unwrap();
        assert_eq!(report.unit_path, None);
        assert_eq!(report.active, Some(false));
    }
}
