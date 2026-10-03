//! The OpenSSH command lines the dialer runs.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::client::endpoint::ProfileId;
use crate::remote::link::dial_config::DialConfig;
use crate::remote::link::protocol;

/// Common OpenSSH options for every dialer ssh invocation that connects.
const COMMON_SSH_OPTIONS: [&str; 14] = [
    "BatchMode=yes",
    "NumberOfPasswordPrompts=0",
    "StrictHostKeyChecking=yes",
    "ConnectTimeout=10",
    "ConnectionAttempts=1",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=4",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "RequestTTY=no",
    "EscapeChar=none",
];

/// Escapes `%` for OpenSSH options that expand `%` tokens. `${` (environment
/// expansion) has no escape and is refused.
pub(crate) fn escape_ssh_tokens(value: &str) -> io::Result<String> {
    if value.contains("${") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path cannot contain '${{' for OpenSSH: {value}"),
        ));
    }
    Ok(value.replace('%', "%%"))
}

fn ssh_path_value(path: &Path) -> io::Result<String> {
    let text = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not valid UTF-8: {}", path.display()),
        )
    })?;
    escape_ssh_tokens(text)
}

/// `ControlPath=<path>` with `%` escaped.
pub(crate) fn control_path_option(ctl: &Path) -> io::Result<OsString> {
    Ok(format!("ControlPath={}", ssh_path_value(ctl)?).into())
}

/// Builds the argv (without the program) of every ssh invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshArgs {
    hub: String,
    identity_file: Option<PathBuf>,
    compression: bool,
}

impl SshArgs {
    pub(crate) fn new(
        hub: impl Into<String>,
        identity_file: Option<PathBuf>,
        compression: bool,
    ) -> Self {
        Self {
            hub: hub.into(),
            identity_file,
            compression,
        }
    }

    pub(crate) fn from_config(config: &DialConfig) -> Self {
        Self::new(
            config.hub.clone(),
            config.identity_file.clone(),
            config.compression,
        )
    }

    pub(crate) fn common(&self) -> io::Result<Vec<OsString>> {
        let mut args: Vec<OsString> = vec!["-T".into()];
        for option in COMMON_SSH_OPTIONS {
            args.push("-o".into());
            args.push(option.into());
        }
        if let Some(identity) = &self.identity_file {
            args.push("-i".into());
            args.push(ssh_path_value(identity)?.into());
            args.push("-o".into());
            args.push("IdentitiesOnly=yes".into());
        }
        if self.compression {
            args.push("-C".into());
        }
        Ok(args)
    }

    /// `ssh -o ControlMaster=yes -o ControlPath=<ctl> -o ControlPersist=no -N <common> <hub>`
    pub(crate) fn master(&self, ctl: &Path) -> io::Result<Vec<OsString>> {
        let mut args: Vec<OsString> = vec![
            "-o".into(),
            "ControlMaster=yes".into(),
            "-o".into(),
            control_path_option(ctl)?,
            "-o".into(),
            "ControlPersist=no".into(),
            "-N".into(),
        ];
        args.extend(self.common()?);
        args.push(self.hub.clone().into());
        Ok(args)
    }

    /// `ssh -o ControlPath=<ctl> -O check <hub>`
    pub(crate) fn check(&self, ctl: &Path) -> io::Result<Vec<OsString>> {
        self.mux_operation(ctl, "check")
    }

    /// `ssh -o ControlPath=<ctl> -O exit <hub>`
    pub(crate) fn exit(&self, ctl: &Path) -> io::Result<Vec<OsString>> {
        self.mux_operation(ctl, "exit")
    }

    fn mux_operation(&self, ctl: &Path, operation: &str) -> io::Result<Vec<OsString>> {
        Ok(vec![
            "-o".into(),
            control_path_option(ctl)?,
            "-O".into(),
            operation.into(),
            self.hub.clone().into(),
        ])
    }

    /// `ssh -o ControlMaster=no -o ControlPath=<ctl> <common> <hub> <command>`
    pub(crate) fn session(&self, ctl: &Path, remote_command: String) -> io::Result<Vec<OsString>> {
        let mut args: Vec<OsString> = vec![
            "-o".into(),
            "ControlMaster=no".into(),
            "-o".into(),
            control_path_option(ctl)?,
        ];
        args.extend(self.common()?);
        args.push(self.hub.clone().into());
        args.push(remote_command.into());
        Ok(args)
    }

    pub(crate) fn control(&self, ctl: &Path, link_id: &ProfileId) -> io::Result<Vec<OsString>> {
        self.session(ctl, protocol::control_command(link_id))
    }

    pub(crate) fn stream(
        &self,
        ctl: &Path,
        link_id: &ProfileId,
        nonce: &str,
    ) -> io::Result<Vec<OsString>> {
        self.session(ctl, protocol::stream_command(link_id, nonce))
    }
}

/// External programs the dialer runs. `ssh` defaults to `ssh` from `PATH`;
/// tests substitute a fake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DialTools {
    pub(crate) ssh: OsString,
    /// This Herdr executable, used for the local bridge children.
    pub(crate) exe: PathBuf,
}

impl DialTools {
    pub(crate) fn new(exe: PathBuf) -> Self {
        Self {
            ssh: "ssh".into(),
            exe,
        }
    }

    pub(crate) fn ssh_command(&self, args: &[OsString]) -> Command {
        let mut command = Command::new(&self.ssh);
        command.args(args);
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> ProfileId {
        ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn option_values(args: &[String]) -> Vec<&str> {
        args.windows(2)
            .filter(|pair| pair[0] == "-o")
            .map(|pair| pair[1].as_str())
            .collect()
    }

    #[test]
    fn ssh_argv_for_master_check_exit_control_and_stream() {
        let ssh = SshArgs::new("me@hub", None, true);
        let ctl = Path::new("/state/dial/work/ctl-0");

        let master = strings(&ssh.master(ctl).unwrap());
        assert_eq!(
            &master[..7],
            [
                "-o",
                "ControlMaster=yes",
                "-o",
                "ControlPath=/state/dial/work/ctl-0",
                "-o",
                "ControlPersist=no",
                "-N"
            ]
        );
        assert_eq!(master.last().unwrap(), "me@hub");
        assert!(master.contains(&"-T".to_string()));
        assert!(master.contains(&"-C".to_string()));
        let options = option_values(&master);
        for expected in COMMON_SSH_OPTIONS {
            assert!(options.contains(&expected), "missing {expected}");
        }
        assert!(!master.contains(&"-i".to_string()));
        assert!(!options.contains(&"IdentitiesOnly=yes"));

        assert_eq!(
            strings(&ssh.check(ctl).unwrap()),
            [
                "-o",
                "ControlPath=/state/dial/work/ctl-0",
                "-O",
                "check",
                "me@hub"
            ]
        );
        assert_eq!(
            strings(&ssh.exit(ctl).unwrap()),
            [
                "-o",
                "ControlPath=/state/dial/work/ctl-0",
                "-O",
                "exit",
                "me@hub"
            ]
        );

        let control = strings(&ssh.control(ctl, &id()).unwrap());
        assert_eq!(
            &control[..4],
            [
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=/state/dial/work/ctl-0"
            ]
        );
        assert!(!control.contains(&"-N".to_string()));
        let n = control.len();
        assert_eq!(control[n - 2], "me@hub");
        assert_eq!(control[n - 1], protocol::control_command(&id()));
        assert_eq!(
            control[n - 1],
            "herdr link-accept --link 0123456789abcdef0123456789abcdef --mode control"
        );

        let stream = strings(&ssh.stream(ctl, &id(), NONCE).unwrap());
        assert_eq!(
            stream[stream.len() - 1],
            protocol::stream_command(&id(), NONCE)
        );
        assert_eq!(&stream[..4], &control[..4]);
        assert_eq!(&stream[4..stream.len() - 1], &control[4..n - 1]);
    }

    #[test]
    fn ssh_argv_identity_and_compression_toggles() {
        let with_identity = SshArgs::new("hub", Some(PathBuf::from("/keys/id_herdr")), false);
        let args = strings(&with_identity.common().unwrap());
        let position = args.iter().position(|arg| arg == "-i").unwrap();
        assert_eq!(args[position + 1], "/keys/id_herdr");
        assert!(option_values(&args).contains(&"IdentitiesOnly=yes"));
        assert!(!args.contains(&"-C".to_string()));

        let compressed = SshArgs::new("hub", None, true);
        let args = strings(&compressed.common().unwrap());
        assert_eq!(args.iter().filter(|arg| *arg == "-C").count(), 1);
        assert!(!args.contains(&"-i".to_string()));
    }

    #[test]
    fn ssh_argv_escapes_percent_tokens_in_paths() {
        let ssh = SshArgs::new("hub", Some(PathBuf::from("/home/100%/key%h")), true);
        let ctl = Path::new("/tmp/a%b/ctl-%C");
        let master = strings(&ssh.master(ctl).unwrap());
        assert!(master.contains(&"ControlPath=/tmp/a%%b/ctl-%%C".to_string()));
        assert!(master.contains(&"/home/100%%/key%%h".to_string()));
        assert_eq!(
            control_path_option(Path::new("/x/%%")).unwrap(),
            OsString::from("ControlPath=/x/%%%%")
        );
        assert_eq!(
            ssh.master(Path::new("/tmp/${HOME}/ctl"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let dollar_identity = SshArgs::new("hub", Some(PathBuf::from("/k/${X}")), true);
        assert!(dollar_identity.common().is_err());
    }
}
