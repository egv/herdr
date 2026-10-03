//! `herdr machine dial setup <name> --hub <target> --pair`: generates the
//! dial key, then registers this machine on the hub through the user's own
//! interactive ssh (`herdr machine add --dial-in ... --authorize-key -
//! --json` on the hub) and saves the returned link id. That ssh login also
//! records the hub's host key, which the dialer's strict checking needs.

use std::ffi::OsString;
use std::io::{self, Read as _, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use serde::Deserialize;

use super::{named_paths, prepare_identity, setup, sh_quote};
use crate::client::endpoint::ProfileId;
use crate::remote::link::authorized_keys;
use crate::remote::link::dial_config::{self, DialPaths};
use crate::remote::link::status::sanitize_remote_text;

const PAIR_USAGE: &str = "usage: herdr machine dial setup <name> --hub <ssh-target> --pair [--label <label>] [--remote-session <name>] [--agent-forwarding] [--hub-herdr <path>] [--identity <path>] [--no-compression]";
/// Exit status of a POSIX shell that did not find the command.
const COMMAND_NOT_FOUND: i32 = 127;
const MAX_HUB_OUTPUT_BYTES: u64 = 64 * 1024;

/// What `herdr machine add --dial-in ... --json` prints on the hub.
#[derive(Debug, Deserialize)]
struct Added {
    id: String,
    label: String,
    session: String,
    #[serde(default)]
    authorized_keys_path: Option<String>,
    #[serde(default)]
    herdr_version: Option<String>,
}

#[derive(Default)]
struct PairArgs<'a> {
    name: Option<&'a str>,
    hub: Option<&'a str>,
    label: Option<&'a str>,
    session: Option<&'a str>,
    hub_herdr: Option<&'a str>,
    identity: Option<&'a str>,
    agent_forwarding: bool,
    no_compression: bool,
}

fn parse_pair_args(args: &[String]) -> Result<PairArgs<'_>, String> {
    let mut parsed = PairArgs::default();
    let mut pair = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let slot = match arg.as_str() {
            "--hub" => &mut parsed.hub,
            "--label" => &mut parsed.label,
            "--remote-session" => &mut parsed.session,
            "--hub-herdr" => &mut parsed.hub_herdr,
            "--identity" => &mut parsed.identity,
            "--pair" | "--agent-forwarding" | "--no-compression" => {
                let flag = match arg.as_str() {
                    "--pair" => &mut pair,
                    "--agent-forwarding" => &mut parsed.agent_forwarding,
                    _ => &mut parsed.no_compression,
                };
                if std::mem::replace(flag, true) {
                    return Err(format!("{arg} given more than once"));
                }
                continue;
            }
            "--link" => return Err("--pair gets the link id from the hub; drop --link".into()),
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

/// The command run on the hub, quoted for its POSIX shell. A leading `~/`
/// in `herdr` stays unquoted so the hub's shell expands it.
fn remote_command(
    herdr: &str,
    label: &str,
    session: Option<&str>,
    agent_forwarding: bool,
) -> String {
    let mut command = match herdr.strip_prefix("~/") {
        Some(rest) => format!("~/{}", sh_quote(rest)),
        None => sh_quote(herdr),
    };
    let mut args = vec!["machine", "add", "--dial-in", "--label", label];
    if let Some(session) = session {
        args.extend(["--remote-session", session]);
    }
    if agent_forwarding {
        args.push("--agent-forwarding");
    }
    args.extend(["--authorize-key", "-", "--json"]);
    for arg in args {
        command.push(' ');
        command.push_str(&sh_quote(arg));
    }
    command
}

/// The hub's JSON answer; shell startup files may print before it.
fn parse_added(stdout: &[u8]) -> Option<Added> {
    let text = String::from_utf8_lossy(stdout);
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .filter(|&start| text[start..].starts_with('{'))
        .find_map(|start| serde_json::from_str(text[start..].trim_end()).ok())
}

/// Runs `command` on the hub through the user's normal ssh (no BatchMode,
/// so password and host key prompts work), with `public_key` on its stdin.
/// Returns its exit status and bounded stdout; stderr goes to the terminal.
fn run_on_hub(
    ssh: &OsString,
    hub: &str,
    command: &str,
    public_key: &str,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let mut child = Command::new(ssh)
        .args(["-T", hub, command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        // The hub command may exit without reading it (herdr missing there).
        let _ = writeln!(stdin, "{public_key}");
    }
    let mut stdout = Vec::new();
    if let Some(pipe) = child.stdout.take() {
        pipe.take(MAX_HUB_OUTPUT_BYTES).read_to_end(&mut stdout)?;
    }
    Ok((child.wait()?, stdout))
}

pub(super) fn setup_pair(
    root: &Path,
    args: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    pair(
        root,
        args,
        &OsString::from("ssh-keygen"),
        &OsString::from("ssh"),
        out,
        err,
    )
}

fn pair(
    root: &Path,
    args: &[String],
    keygen: &OsString,
    ssh: &OsString,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<i32> {
    let parsed = match parse_pair_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            writeln!(err, "herdr machine dial setup: {error}\n{PAIR_USAGE}")?;
            return Ok(2);
        }
    };
    let (Some(name), Some(hub)) = (parsed.name, parsed.hub) else {
        writeln!(err, "{PAIR_USAGE}")?;
        return Ok(2);
    };
    let Some(paths) = named_paths(root, name, err)? else {
        return Ok(2);
    };
    if let Err(error) = dial_config::validate_hub(hub) {
        writeln!(err, "herdr machine dial setup: {error}")?;
        return Ok(2);
    }
    let identity = match prepare_identity(&paths, parsed.identity, keygen, err)? {
        Ok(identity) => identity,
        Err(code) => return Ok(code),
    };
    let Some(public_key) = dial_config::read_public_key_line(&identity)
        .filter(|line| authorized_keys::parse_public_key_line(line).is_ok())
    else {
        writeln!(
            err,
            "herdr machine dial setup: {} does not hold a supported public key line",
            DialPaths::public_key_file(&identity).display()
        )?;
        return Ok(1);
    };

    let command = remote_command(
        parsed.hub_herdr.unwrap_or("herdr"),
        parsed.label.unwrap_or(name),
        parsed.session,
        parsed.agent_forwarding,
    );
    writeln!(out, "Registering this machine on {hub} over ssh...")?;
    out.flush()?;
    let (status, stdout) = match run_on_hub(ssh, hub, &command, &public_key) {
        Ok(result) => result,
        Err(error) => {
            writeln!(err, "herdr machine dial setup: failed to run ssh: {error}")?;
            return Ok(1);
        }
    };
    let manual = format!(
        "To pair by hand instead, run `herdr machine add --dial-in --label <label>` on the hub, then `herdr machine dial setup {} --hub {} --link <id>` here.",
        sh_quote(name),
        sh_quote(hub)
    );
    if status.code() == Some(COMMAND_NOT_FOUND) {
        writeln!(
            err,
            "herdr machine dial setup: herdr was not found on {hub} for non-interactive ssh commands; pass its path with --hub-herdr (for example --hub-herdr '~/.local/bin/herdr').\n{manual}"
        )?;
        return Ok(1);
    }
    let Some(added) = parse_added(&stdout).filter(|_| status.success()) else {
        writeln!(
            err,
            "herdr machine dial setup: pairing on {hub} failed ({status}); see the messages above. The hub needs this Herdr version or newer.\n{manual}"
        )?;
        return Ok(1);
    };
    let Ok(link_id) = ProfileId::parse(added.id.as_str()) else {
        writeln!(
            err,
            "herdr machine dial setup: the hub answered with an invalid machine id"
        )?;
        return Ok(1);
    };

    // Write the config exactly as `setup --link` does; its guidance is replaced below.
    let identity_arg = identity.to_string_lossy();
    let mut setup_args = vec![
        name,
        "--hub",
        hub,
        "--link",
        link_id.as_str(),
        "--identity",
        &identity_arg,
    ];
    if parsed.no_compression {
        setup_args.push("--no-compression");
    }
    let setup_args = setup_args.into_iter().map(String::from).collect::<Vec<_>>();
    if setup(root, &setup_args, keygen, &mut io::sink(), err)? != 0 {
        writeln!(
            err,
            "herdr machine dial setup: the hub saved machine {link_id}, but the link config here was not written; rerun `herdr machine dial setup {} --hub {} --link {link_id}`",
            sh_quote(name),
            sh_quote(hub)
        )?;
        return Ok(1);
    }

    let clean = |text: &str| sanitize_remote_text(text, 256);
    let version = added
        .herdr_version
        .as_deref()
        .map(|version| format!(" (herdr {})", clean(version)))
        .unwrap_or_default();
    writeln!(
        out,
        "Paired with {hub}{version} as dial-in machine '{}' (link {link_id}, session {}).",
        clean(&added.label),
        clean(&added.session)
    )?;
    if let Some(path) = &added.authorized_keys_path {
        writeln!(
            out,
            "The hub authorized this machine's key in {}.",
            clean(path)
        )?;
    }
    if parsed.agent_forwarding {
        writeln!(
            out,
            "Agent forwarding is on: hub windows with an SSH agent lend it to this machine's panes."
        )?;
    }
    writeln!(out, "Identity: {}", identity.display())?;
    writeln!(out, "Keep the link running on this machine with one of:")?;
    writeln!(
        out,
        "     herdr machine dial service install {}",
        sh_quote(name)
    )?;
    writeln!(out, "     herdr machine dial run {}", sh_quote(name))?;
    Ok(0)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const LINK: &str = "0123456789abcdef0123456789abcdef";
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiyVkMtB424oOJkudA7Gr13nYvfcpJFBxq2EoLwM5LW me@slave";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("herdr-pair-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::platform::ensure_private_directory(&dir).unwrap();
        dir
    }

    /// A fake `ssh` that records its arguments and stdin, then runs `body`.
    fn fake_ssh(dir: &Path, body: &str) -> OsString {
        let path = dir.join("ssh");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{0}/args'\ncat > '{0}/stdin'\n{body}\n",
            dir.display()
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.into_os_string()
    }

    fn identity(dir: &Path) -> String {
        let key = dir.join("id_test");
        std::fs::write(&key, b"PRIVATE").unwrap();
        std::fs::write(dir.join("id_test.pub"), format!("{KEY}\n")).unwrap();
        key.display().to_string()
    }

    fn run(root: &Path, ssh: &OsString, args: &[&str]) -> (i32, String, String) {
        let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = pair(
            root,
            &args,
            &OsString::from("/nonexistent/ssh-keygen"),
            ssh,
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

    #[test]
    fn pairing_sends_the_key_to_the_hub_and_saves_the_returned_link() {
        let dir = scratch("ok");
        let key = identity(&dir);
        let ssh = fake_ssh(
            &dir,
            &format!(
                "echo 'hub motd'\necho '{{'\necho '  \"id\": \"{LINK}\", \"label\": \"My box\", \"session\": \"agents\",'\necho '  \"authorized_keys_path\": \"/h/.ssh/authorized_keys\", \"herdr_version\": \"9.9.9\", \"future\": 1'\necho '}}'"
            ),
        );
        let root = dir.join("dial");
        let (code, out, err) = run(
            &root,
            &ssh,
            &[
                "box",
                "--pair",
                "--hub",
                "me@hub",
                "--label",
                "My box",
                "--remote-session",
                "agents",
                "--hub-herdr",
                "~/bin/my herdr",
                "--agent-forwarding",
                "--identity",
                &key,
            ],
        );
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("Agent forwarding is on"), "{out}");
        assert!(out.contains("as dial-in machine 'My box'"), "{out}");
        assert!(out.contains("herdr 9.9.9"), "{out}");
        assert!(out.contains("herdr machine dial run box"), "{out}");
        assert_eq!(
            std::fs::read_to_string(dir.join("args")).unwrap(),
            "-T\nme@hub\n~/'bin/my herdr' machine add --dial-in --label 'My box' --remote-session agents --agent-forwarding --authorize-key - --json\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("stdin")).unwrap(),
            format!("{KEY}\n")
        );
        let config = dial_config::load_config(&DialPaths::new(&root, "box").config_file)
            .unwrap()
            .unwrap();
        assert_eq!(config.link_id.as_str(), LINK);
        assert_eq!(config.hub, "me@hub");
        assert_eq!(config.identity_file.unwrap().display().to_string(), key);
    }

    #[test]
    fn pairing_failures_explain_the_next_step_and_save_nothing() {
        let dir = scratch("fail");
        let key = identity(&dir);
        let root = dir.join("dial");
        let args = [
            "box",
            "--hub",
            "me@hub",
            "--pair",
            "--identity",
            key.as_str(),
        ];
        for (body, expected) in [
            ("exit 127", "--hub-herdr"),
            (
                "echo 'unknown option' >&2; exit 2",
                "pairing on me@hub failed",
            ),
            ("echo not json", "pairing on me@hub failed"),
            (
                "echo '{\"id\": \"nothex\", \"label\": \"x\", \"session\": \"default\"}'",
                "invalid machine id",
            ),
        ] {
            let (code, _, err) = run(&root, &fake_ssh(&dir, body), &args);
            assert_eq!(code, 1, "{body}");
            assert!(err.contains(expected), "{body}: {err}");
            assert!(!DialPaths::new(&root, "box").config_file.exists());
        }
        for bad in [
            &["box", "--pair"][..],
            &["box", "--pair", "--hub", "me@hub", "--link", LINK],
            &["bad name", "--pair", "--hub", "me@hub"],
            &["box", "--pair", "--hub", "-oProxyCommand=x"],
            &[
                "box",
                "--pair",
                "--hub",
                "me@hub",
                "--agent-forwarding",
                "--agent-forwarding",
            ],
        ] {
            let (code, _, _) = run(&root, &fake_ssh(&dir, "exit 0"), bad);
            assert_eq!(code, 2, "{bad:?}");
        }
    }
}
