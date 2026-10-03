//! `herdr machine dial service` on Linux: one systemd user template unit,
//! `herdr-dial@.service`, with an enabled instance per dial-in link.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::platform::unix_common::{checked_service_command, run_service_command};
use crate::platform::{DialServiceReport, DialServiceSpec};

const TEMPLATE: &str = "herdr-dial@.service";

type Runner<'a> = &'a mut dyn FnMut(Command) -> io::Result<Output>;

pub(crate) fn dial_service_install(
    spec: &DialServiceSpec,
    start: bool,
) -> io::Result<DialServiceReport> {
    install(&Systemd::from_env()?, spec, start, &mut run_service_command)
}

pub(crate) fn dial_service_uninstall(name: &str) -> io::Result<DialServiceReport> {
    uninstall(&Systemd::from_env()?, name, &mut run_service_command)
}

pub(crate) fn dial_service_status(name: &str) -> io::Result<DialServiceReport> {
    status(&Systemd::from_env()?, name, &mut run_service_command)
}

/// Whether the instance for `name` is enabled, from the unit directory
/// alone (systemd is not asked).
pub(crate) fn dial_service_installed(name: &str) -> io::Result<bool> {
    Ok(Systemd::from_env()?.instance_enabled(name))
}

/// The user's systemd unit directory and linger flag.
struct Systemd {
    unit_dir: PathBuf,
    /// `/var/lib/systemd/linger/<user>` exists when user services run
    /// without a login session.
    linger_flag: Option<PathBuf>,
}

impl Systemd {
    fn from_env() -> io::Result<Self> {
        let absolute = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        let config = match absolute("XDG_CONFIG_HOME") {
            Some(config) => config,
            None => absolute("HOME")
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?
                .join(".config"),
        };
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()
            .filter(|user| !user.is_empty() && !user.contains('/'));
        Ok(Self {
            unit_dir: config.join("systemd/user"),
            linger_flag: user.map(|user| Path::new("/var/lib/systemd/linger").join(user)),
        })
    }

    fn template(&self) -> PathBuf {
        self.unit_dir.join(TEMPLATE)
    }

    fn wants_dir(&self) -> PathBuf {
        self.unit_dir.join("default.target.wants")
    }

    fn instance_enabled(&self, name: &str) -> bool {
        std::fs::symlink_metadata(self.wants_dir().join(instance(name))).is_ok()
    }

    fn linger_note(&self) -> Option<String> {
        if self.linger_flag.as_ref().is_some_and(|flag| flag.exists()) {
            return None;
        }
        Some("user services stop when you log out; on a headless machine run `loginctl enable-linger $USER`".into())
    }
}

fn instance(name: &str) -> String {
    format!("herdr-dial@{name}.service")
}

fn systemctl(run: Runner<'_>, args: &[&str]) -> io::Result<String> {
    let mut command = Command::new("systemctl");
    command.arg("--user").args(args);
    checked_service_command(run, command)
}

/// `text` as one double-quoted systemd word with `%` specifiers escaped;
/// text that would need C escapes is refused.
fn quoted(text: &str) -> io::Result<String> {
    if text
        .chars()
        .any(|ch| ch.is_control() || ch == '"' || ch == '\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a systemd unit cannot contain {text:?} literally"),
        ));
    }
    Ok(format!("\"{}\"", text.replace('%', "%%")))
}

/// The template unit; `%i` is the dial name.
fn render_unit(spec: &DialServiceSpec) -> io::Result<String> {
    let herdr = spec
        .herdr_path
        .to_str()
        .filter(|_| spec.herdr_path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the Herdr path must be absolute UTF-8: {}",
                    spec.herdr_path.display()
                ),
            )
        })?;
    // `$` is expanded in command lines (not in `Environment=`).
    let mut unit = format!(
        "[Unit]\n\
         Description=herdr dial-in link %i\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={} machine dial run %i\n",
        quoted(herdr)?.replace('$', "$$")
    );
    for (key, value) in &spec.env {
        unit.push_str(&format!(
            "Environment={}\n",
            quoted(&format!("{key}={value}"))?
        ));
    }
    unit.push_str(
        "Restart=always\n\
         RestartSec=5\n\
         # The herdr server started by the link must survive link restarts and service stops.\n\
         KillMode=process\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
    );
    Ok(unit)
}

fn install(
    systemd: &Systemd,
    spec: &DialServiceSpec,
    start: bool,
    run: Runner<'_>,
) -> io::Result<DialServiceReport> {
    let unit = render_unit(spec)?;
    std::fs::create_dir_all(&systemd.unit_dir)?;
    let template = systemd.template();
    let previous = match std::fs::read(&template) {
        Ok(previous) => Some(previous),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    std::fs::write(&template, unit)?;
    let instance = instance(&spec.name);
    // A failure leaves the template as it was: other links may use it.
    if let Err(error) = systemctl(run, &["daemon-reload"]) {
        restore_template(&template, previous.as_deref());
        return Err(error);
    }
    if let Err(error) = systemctl(run, &["enable", &instance]) {
        restore_template(&template, previous.as_deref());
        let _ = systemctl(run, &["daemon-reload"]);
        return Err(error);
    }
    // A restart (not `enable --now`) also applies a changed unit.
    if start {
        systemctl(run, &["restart", &instance])?;
    }
    let mut notes = vec![format!("logs: journalctl --user -u {instance}")];
    if !start {
        notes.push(format!("start it with `systemctl --user start {instance}`"));
    }
    notes.extend(systemd.linger_note());
    Ok(DialServiceReport {
        unit_path: Some(template),
        active: start.then_some(true),
        notes,
    })
}

/// Puts back the template an install replaced, or removes the one it wrote.
fn restore_template(template: &Path, previous: Option<&[u8]>) {
    let restored = match previous {
        Some(previous) => std::fs::write(template, previous),
        None => std::fs::remove_file(template),
    };
    if let Err(error) = restored {
        tracing::warn!(%error, path = %template.display(), "could not restore the dial service unit");
    }
}

/// Whether any instance of the template is still enabled.
fn instances_enabled(systemd: &Systemd) -> bool {
    std::fs::read_dir(systemd.wants_dir())
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("herdr-dial@") && name.ends_with(".service"))
        })
}

fn uninstall(systemd: &Systemd, name: &str, run: Runner<'_>) -> io::Result<DialServiceReport> {
    let template = systemd.template();
    if !template.exists() {
        return Ok(DialServiceReport {
            notes: vec!["no dial-in service is installed".into()],
            ..DialServiceReport::default()
        });
    }
    systemctl(run, &["disable", "--now", &instance(name)])?;
    let mut report = DialServiceReport {
        active: Some(false),
        ..DialServiceReport::default()
    };
    if instances_enabled(systemd) {
        report.notes.push(format!(
            "kept {} for the other dial-in links",
            template.display()
        ));
        report.unit_path = Some(template);
    } else {
        std::fs::remove_file(&template)?;
        systemctl(run, &["daemon-reload"])?;
        report.notes.push(format!("removed {}", template.display()));
    }
    Ok(report)
}

fn status(systemd: &Systemd, name: &str, run: Runner<'_>) -> io::Result<DialServiceReport> {
    let template = systemd.template();
    if !template.exists() {
        return Ok(DialServiceReport::default());
    }
    let instance = instance(name);
    let shown = systemctl(
        run,
        &[
            "show",
            "-p",
            "ActiveState",
            "-p",
            "UnitFileState",
            &instance,
        ],
    )?;
    let property = |key: &str| {
        shown
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_default()
            .to_string()
    };
    let enabled = property("UnitFileState") == "enabled";
    let mut notes = Vec::new();
    if enabled {
        notes.push(format!("logs: journalctl --user -u {instance}"));
        notes.extend(systemd.linger_note());
    }
    Ok(DialServiceReport {
        unit_path: enabled.then_some(template),
        active: Some(property("ActiveState") == "active"),
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
            "herdr-systemd-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn systemd(root: &Path) -> Systemd {
        Systemd {
            unit_dir: root.join("config/systemd/user"),
            linger_flag: Some(root.join("linger/me")),
        }
    }

    fn spec(herdr: &str) -> DialServiceSpec {
        DialServiceSpec {
            name: "work".into(),
            herdr_path: PathBuf::from(herdr),
            log_path: PathBuf::from("/unused.log"),
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
                stderr: b"Failed to connect to bus\n".to_vec(),
            })
        }
    }

    #[test]
    fn unit_runs_the_dial_name_and_keeps_the_server_on_stop() {
        let mut spec = spec("/home/me/.local/bin/herdr");
        spec.env = vec![("XDG_STATE_HOME".into(), "/home/me/state 100%".into())];
        assert_eq!(
            render_unit(&spec).unwrap(),
            "[Unit]\n\
             Description=herdr dial-in link %i\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             ExecStart=\"/home/me/.local/bin/herdr\" machine dial run %i\n\
             Environment=\"XDG_STATE_HOME=/home/me/state 100%%\"\n\
             Restart=always\n\
             RestartSec=5\n\
             # The herdr server started by the link must survive link restarts and service stops.\n\
             KillMode=process\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        );
    }

    #[test]
    fn exec_paths_are_quoted_or_refused() {
        let unit = render_unit(&spec("/opt/my apps/100%/$HOME/it's/herdr")).unwrap();
        assert!(
            unit.contains(
                "ExecStart=\"/opt/my apps/100%%/$$HOME/it's/herdr\" machine dial run %i\n"
            ),
            "{unit}"
        );
        for bad in [
            "relative/herdr",
            "/a\"b/herdr",
            "/a\\b/herdr",
            "/a\nb/herdr",
        ] {
            assert_eq!(
                render_unit(&spec(bad)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn install_enables_and_restarts_the_instance() {
        let root = scratch("install");
        let systemd = systemd(&root);
        let mut calls = Vec::new();
        let report = install(
            &systemd,
            &spec("/usr/bin/herdr"),
            true,
            &mut fake(&mut calls, "", None),
        )
        .unwrap();
        assert_eq!(
            calls,
            [
                "systemctl --user daemon-reload",
                "systemctl --user enable herdr-dial@work.service",
                "systemctl --user restart herdr-dial@work.service",
            ]
        );
        let template = root.join("config/systemd/user/herdr-dial@.service");
        assert_eq!(report.unit_path.as_deref(), Some(template.as_path()));
        assert_eq!(report.active, Some(true));
        assert!(std::fs::read_to_string(&template)
            .unwrap()
            .contains("ExecStart=\"/usr/bin/herdr\""));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("enable-linger")),
            "{:?}",
            report.notes
        );

        // With linger and --no-start: enabled only, no linger hint.
        std::fs::create_dir_all(root.join("linger")).unwrap();
        std::fs::write(root.join("linger/me"), b"").unwrap();
        let mut calls = Vec::new();
        let report = install(
            &systemd,
            &spec("/usr/bin/herdr"),
            false,
            &mut fake(&mut calls, "", None),
        )
        .unwrap();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(report.active, None);
        assert!(!report.notes.iter().any(|note| note.contains("linger")));
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("systemctl --user start herdr-dial@work.service")));

        let mut calls = Vec::new();
        let error = install(
            &systemd,
            &spec("/usr/bin/herdr"),
            true,
            &mut fake(&mut calls, "", Some("daemon-reload")),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("Failed to connect to bus"),
            "{error}"
        );
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn failed_installs_leave_the_template_as_it_was() {
        let root = scratch("install-failed");
        let systemd = systemd(&root);
        let mut calls = Vec::new();
        let error = install(
            &systemd,
            &spec("/usr/bin/herdr"),
            true,
            &mut fake(&mut calls, "", Some("enable")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("enable"), "{error}");
        assert_eq!(
            calls,
            [
                "systemctl --user daemon-reload",
                "systemctl --user enable herdr-dial@work.service",
                "systemctl --user daemon-reload",
            ]
        );
        assert!(!systemd.template().exists(), "the written unit is removed");

        // Another link's template is put back unchanged.
        std::fs::write(systemd.template(), b"other links' unit").unwrap();
        for fail in ["daemon-reload", "enable"] {
            let mut calls = Vec::new();
            install(
                &systemd,
                &spec("/usr/bin/herdr"),
                false,
                &mut fake(&mut calls, "", Some(fail)),
            )
            .unwrap_err();
            assert_eq!(
                std::fs::read(systemd.template()).unwrap(),
                b"other links' unit",
                "{fail}"
            );
        }
    }

    #[test]
    fn installed_means_the_instance_is_enabled() {
        let root = scratch("installed");
        let systemd = systemd(&root);
        assert!(!systemd.instance_enabled("work"));
        std::fs::create_dir_all(systemd.wants_dir()).unwrap();
        std::os::unix::fs::symlink(
            systemd.template(),
            systemd.wants_dir().join("herdr-dial@work.service"),
        )
        .unwrap();
        assert!(systemd.instance_enabled("work"), "even when dangling");
        assert!(!systemd.instance_enabled("play"));
    }

    #[test]
    fn uninstall_keeps_the_template_while_other_links_use_it() {
        let root = scratch("uninstall");
        let systemd = systemd(&root);
        let mut calls = Vec::new();
        let report = uninstall(&systemd, "work", &mut fake(&mut calls, "", None)).unwrap();
        assert!(calls.is_empty(), "nothing installed: {calls:?}");
        assert!(report.notes[0].contains("no dial-in service"));

        let wants = systemd.unit_dir.join("default.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        std::fs::write(systemd.template(), b"unit").unwrap();
        std::fs::write(wants.join("herdr-dial@play.service"), b"").unwrap();
        let mut calls = Vec::new();
        let report = uninstall(&systemd, "work", &mut fake(&mut calls, "", None)).unwrap();
        assert_eq!(
            calls,
            ["systemctl --user disable --now herdr-dial@work.service"]
        );
        assert!(systemd.template().exists());
        assert_eq!(report.unit_path, Some(systemd.template()));

        std::fs::remove_file(wants.join("herdr-dial@play.service")).unwrap();
        let mut calls = Vec::new();
        let report = uninstall(&systemd, "play", &mut fake(&mut calls, "", None)).unwrap();
        assert_eq!(
            calls,
            [
                "systemctl --user disable --now herdr-dial@play.service",
                "systemctl --user daemon-reload",
            ]
        );
        assert!(!systemd.template().exists());
        assert_eq!(report.unit_path, None);
    }

    #[test]
    fn status_reads_the_instance_state() {
        let root = scratch("status");
        let systemd = systemd(&root);
        let mut calls = Vec::new();
        let report = status(&systemd, "work", &mut fake(&mut calls, "", None)).unwrap();
        assert!(calls.is_empty());
        assert_eq!(report, DialServiceReport::default());

        std::fs::create_dir_all(&systemd.unit_dir).unwrap();
        std::fs::write(systemd.template(), b"unit").unwrap();
        let mut calls = Vec::new();
        let report = status(
            &systemd,
            "work",
            &mut fake(
                &mut calls,
                "ActiveState=active\nUnitFileState=enabled\n",
                None,
            ),
        )
        .unwrap();
        assert_eq!(
            calls,
            ["systemctl --user show -p ActiveState -p UnitFileState herdr-dial@work.service"]
        );
        assert_eq!(report.unit_path, Some(systemd.template()));
        assert_eq!(report.active, Some(true));

        let mut calls = Vec::new();
        let report = status(
            &systemd,
            "other",
            &mut fake(
                &mut calls,
                "ActiveState=inactive\nUnitFileState=disabled\n",
                None,
            ),
        )
        .unwrap();
        assert_eq!(report.unit_path, None, "not enabled is not installed");
        assert_eq!(report.active, Some(false));
    }
}
