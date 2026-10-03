use std::cell::RefCell;
use std::io;

use crate::api::client::{ApiClient, ConnectionTarget};
use crate::client::endpoint::{
    DialInCatalog, DialInMachine, EndpointCatalog, ProfileId, SavedSshEndpoint, ViaMachine,
};
use crate::remote::LinkPaths;

thread_local! {
    // CLI dispatch is synchronous. Scope routing to this command, never the runtime or TUI.
    static TARGET: RefCell<Option<MachineTarget>> = const { RefCell::new(None) };
}

struct MachineTarget {
    profile: MachineProfile,
    bridge: Option<crate::remote::SavedSshApiBridge>,
    #[cfg(test)]
    client_override: Option<ApiClient>,
}

/// The saved machine a `--machine` command runs against.
enum MachineProfile {
    /// Reached through an SSH API bridge started on demand.
    Ssh(SavedSshEndpoint),
    /// Reached through the hub-local API socket of its dial-in link (no SSH from here).
    DialIn {
        machine: DialInMachine,
        paths: LinkPaths,
        started_at_ms: u64,
    },
    /// A relay hub's dial-in machine, through an SSH API bridge to the hub
    /// running `herdr link-connect`.
    Via { machine: ViaMachine, label: String },
}

impl MachineProfile {
    fn id(&self) -> &ProfileId {
        match self {
            Self::Ssh(profile) => &profile.id,
            Self::DialIn { machine, .. } => &machine.id,
            Self::Via { machine, .. } => &machine.id,
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Ssh(profile) => &profile.label,
            Self::DialIn { machine, .. } => &machine.label,
            Self::Via { label, .. } => label,
        }
    }

    fn session(&self) -> &str {
        match self {
            Self::Ssh(profile) => &profile.session,
            Self::DialIn { machine, .. } => &machine.session,
            Self::Via { machine, .. } => &machine.session,
        }
    }

    fn start_bridge(
        &self,
        use_cached_metadata: bool,
    ) -> io::Result<crate::remote::SavedSshApiBridge> {
        match self {
            Self::Via { machine, .. } => crate::remote::SavedSshApiBridge::start_via(
                machine.relay_id.as_str(),
                &machine.relay_target,
                machine.link_id.as_str(),
                machine.id.as_str(),
                use_cached_metadata,
            ),
            Self::Ssh(profile) => crate::remote::SavedSshApiBridge::start(
                profile.id.as_str(),
                &profile.target,
                &profile.session,
                use_cached_metadata,
            ),
            Self::DialIn { .. } => Err(io::Error::other("dial-in machines need no bridge")),
        }
    }
}

/// A saved machine found in either catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SavedMachineRef<'a> {
    Ssh(&'a SavedSshEndpoint),
    DialIn(&'a DialInMachine),
}

impl SavedMachineRef<'_> {
    pub(super) fn enabled(&self) -> bool {
        match self {
            Self::Ssh(profile) => profile.enabled,
            Self::DialIn(machine) => machine.enabled,
        }
    }
}

struct TargetScope(Option<MachineTarget>);

impl Drop for TargetScope {
    fn drop(&mut self) {
        TARGET.with(|target| *target.borrow_mut() = self.0.take());
    }
}

pub(super) fn maybe_run(args: &[String]) -> Option<io::Result<super::CommandOutcome>> {
    let (selector, args) = match parse_machine_prefix(args) {
        Ok(Some(target)) => target,
        Ok(None) => return None,
        Err(error) => return Some(usage_error(error)),
    };
    Some((|| {
        if let Err(error) = validate_machine_command(&args) {
            return usage_error(error);
        }
        if super::spec::print_requested_help(&args)? {
            return Ok(super::CommandOutcome::Handled(0));
        }
        let profiles = EndpointCatalog::load_profiles().map_err(io::Error::other)?;
        // A broken dial-in catalog must not stop SSH machines from resolving.
        let (dial_in, dial_in_error) = match DialInCatalog::load() {
            Ok(catalog) => (catalog.machines, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        let profile = match resolve_saved_machine(&profiles, &dial_in, &selector) {
            Ok(SavedMachineRef::Ssh(profile)) => MachineProfile::Ssh(profile.clone()),
            Ok(SavedMachineRef::DialIn(machine)) => MachineProfile::DialIn {
                paths: machine.paths(),
                machine: machine.clone(),
                started_at_ms: crate::remote::link::status::now_ms(),
            },
            // Neither catalog names it: maybe a relay hub's machine. Not
            // while the dial-in catalog is unreadable: it may name it.
            Err(error)
                if dial_in_error.is_none()
                    && !names_saved_machine(&profiles, &dial_in, &selector) =>
            {
                match super::machine::relay::find_via_machine(&selector) {
                    Ok(Some(listed)) if !listed.enabled => {
                        return usage_error(format!(
                            "machine '{}' is disabled on {}",
                            listed.machine.display_label(),
                            listed.machine.relay_label
                        ))
                    }
                    Ok(Some(listed)) => MachineProfile::Via {
                        label: listed.machine.display_label(),
                        machine: listed.machine,
                    },
                    Ok(None) => {
                        return usage_error(match dial_in_error {
                            Some(dial_in_error) => format!("{error} ({dial_in_error})"),
                            None => error,
                        })
                    }
                    Err(error) => return usage_error(error),
                }
            }
            Err(error) => {
                return usage_error(match dial_in_error {
                    Some(dial_in_error) => format!("{error} ({dial_in_error})"),
                    None => error,
                })
            }
        };
        let _scope = TARGET.with(|target| {
            TargetScope(target.replace(Some(MachineTarget {
                profile,
                bridge: None,
                #[cfg(test)]
                client_override: None,
            })))
        });
        super::maybe_run(&args)
    })())
}

fn usage_error(error: String) -> io::Result<super::CommandOutcome> {
    eprintln!("error: {error}");
    Ok(super::CommandOutcome::Handled(2))
}

pub(super) fn is_remote() -> bool {
    TARGET.with(|target| target.borrow().is_some())
}

pub(super) fn api_client() -> io::Result<ApiClient> {
    TARGET.with(|target| {
        let mut target = target.borrow_mut();
        let Some(target) = target.as_mut() else {
            return Ok(ApiClient::local());
        };
        #[cfg(test)]
        if let Some(client) = &target.client_override {
            return Ok(client.clone());
        }
        if let MachineProfile::DialIn { machine, paths, .. } = &target.profile {
            return dial_in_api_client(machine, paths);
        }
        if target.bridge.is_none() {
            target.bridge = Some(target.profile.start_bridge(true).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("machine '{}': {error}", target.profile.label()),
                )
            })?);
        }
        let bridge = target
            .bridge
            .as_ref()
            .ok_or_else(|| io::Error::other("machine bridge unavailable"))?;
        Ok(ApiClient::for_target(ConnectionTarget::SocketPath(
            bridge.socket_path().to_owned(),
        )))
    })
}

pub(super) fn server_status(
    client: &ApiClient,
) -> Result<crate::api::RuntimeStatus, crate::api::client::ApiClientError> {
    let probe = || {
        if is_remote() {
            client.status_with_timeout(std::time::Duration::from_secs(15))
        } else {
            client.status()
        }
    };
    let error = match probe() {
        Ok(status) => return Ok(status),
        Err(error) => error,
    };
    // Only this read-only probe may rediscover and retry. Requests that follow
    // the probe must never be replayed after an ambiguous SSH failure.
    TARGET.with(|target| {
        let mut target = target.borrow_mut();
        let Some(target) = target.as_mut() else {
            return Err(error);
        };
        let Some(bridge) = target.bridge.as_ref() else {
            return Err(error);
        };
        let Some(failure) = bridge.reported_failure() else {
            return Err(error);
        };
        if !bridge.used_cached_metadata
            || !crate::remote::SavedSshApiBridge::stale_metadata_failure(&failure)
        {
            return Err(failure.into());
        }
        bridge.invalidate_metadata();
        target.bridge.take();
        target.bridge = Some(target.profile.start_bridge(false)?);
        Ok(())
    })?;
    probe()
}

pub(super) fn remote_error(error: io::Error) -> io::Error {
    TARGET.with(|target| {
        let target = target.borrow();
        let Some(target) = target.as_ref() else {
            return error;
        };
        if let MachineProfile::DialIn {
            machine,
            paths,
            started_at_ms,
        } = &target.profile
        {
            return dial_in_remote_error(machine, paths, *started_at_ms, error);
        }
        let error = target
            .bridge
            .as_ref()
            .and_then(|bridge| bridge.reported_failure())
            .unwrap_or(error);
        if let MachineProfile::Via { machine, label } = &target.profile {
            if crate::remote::via_not_connected(&error.to_string()) {
                return io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "machine '{label}' is not connected (it has not dialed in to {})",
                        machine.relay_label
                    ),
                );
            }
        }
        io::Error::new(
            error.kind(),
            format!(
                "machine '{}' (session {}): {error}",
                target.profile.label(),
                target.profile.session()
            ),
        )
    })
}

/// The error for a dial-in machine whose link is not up.
fn dial_in_not_connected_error(machine: &DialInMachine) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        format!(
            "machine '{}' is not connected (it has not dialed in)",
            machine.label
        ),
    )
}

/// An API client for a dial-in machine: its link's hub-local `api.sock`,
/// after checking that the link directory is private to this user and that
/// the link is listening. Every connection the client makes re-checks the
/// directory and that the socket is served by this user. Each connection
/// becomes a stream over the machine's own SSH connection to this hub;
/// nothing here runs `ssh`.
pub(super) fn dial_in_api_client(
    machine: &DialInMachine,
    paths: &LinkPaths,
) -> io::Result<ApiClient> {
    let context = |error: io::Error| {
        io::Error::new(
            error.kind(),
            format!("machine '{}': {error}", machine.label),
        )
    };
    paths.ensure_socket_paths_fit().map_err(context)?;
    match crate::platform::verify_private_directory(&paths.dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(dial_in_not_connected_error(machine));
        }
        Err(error) => {
            return Err(context(io::Error::new(
                error.kind(),
                format!("refusing dial-in link directory: {error}"),
            )));
        }
    }
    match std::fs::symlink_metadata(&paths.api_socket) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(dial_in_not_connected_error(machine));
        }
        Err(error) => return Err(context(error)),
    }
    Ok(ApiClient::for_target(dial_in_api_target(paths)))
}

/// The peer-checked API target of a dial-in link.
pub(super) fn dial_in_api_target(paths: &LinkPaths) -> ConnectionTarget {
    ConnectionTarget::PrivateSocketPath {
        socket: paths.api_socket.clone(),
        private_dir: paths.dir.clone(),
    }
}

fn dial_in_remote_error(
    machine: &DialInMachine,
    paths: &LinkPaths,
    started_at_ms: u64,
    error: io::Error,
) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused | io::ErrorKind::NotConnected
    ) {
        return dial_in_not_connected_error(machine);
    }
    let closed = matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<crate::api::client::ApiClientError>()),
        Some(crate::api::client::ApiClientError::EmptyResponse)
    );
    let mut message = if closed {
        format!(
            "machine '{}' (session {}): the machine closed the stream without answering",
            machine.label, machine.session
        )
    } else {
        format!(
            "machine '{}' (session {}): {error}",
            machine.label, machine.session
        )
    };
    // The link records why the machine refused or dropped a stream.
    if let Some(reported) = await_stream_error(paths, started_at_ms) {
        message.push_str("; the machine reported: ");
        message.push_str(&reported);
    }
    io::Error::new(error.kind(), message)
}

/// How long a failed dial-in request waits for the machine's reason. The
/// dialer reports a failed stream only after both of its processes ended,
/// which is after the hub client saw the stream close, and the link holder
/// writes `status.json` at most once per second.
const STREAM_ERROR_GRACE: std::time::Duration = std::time::Duration::from_millis(2000);
const STREAM_ERROR_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// [`recent_stream_error`], waiting up to [`STREAM_ERROR_GRACE`] for it.
pub(super) fn await_stream_error(paths: &LinkPaths, since_ms: u64) -> Option<String> {
    let deadline = std::time::Instant::now() + STREAM_ERROR_GRACE;
    loop {
        let reported = recent_stream_error(paths, since_ms);
        if reported.is_some() || std::time::Instant::now() >= deadline {
            return reported;
        }
        std::thread::sleep(STREAM_ERROR_POLL);
    }
}

/// The sanitized `last_stream_error` message the link recorded at or after
/// `since_ms`, if any.
pub(super) fn recent_stream_error(paths: &LinkPaths, since_ms: u64) -> Option<String> {
    use crate::remote::link::status;

    let record = status::read_status(&paths.status_file)
        .ok()
        .flatten()?
        .last_stream_error
        .filter(|record| record.at_ms >= since_ms)?;
    Some(status::sanitize_remote_text(
        &record.message,
        status::MAX_REMOTE_TEXT_BYTES,
    ))
}

pub(super) fn restart_guidance() -> String {
    TARGET.with(|target| match target.borrow().as_ref() {
        Some(target) => format!("Update Herdr and restart the server on machine '{}' (session {}). Stopping the server exits its pane processes.", target.profile.label(), target.profile.session()),
        None => crate::session::active_restart_after_update_guidance(),
    })
}

pub(super) fn remote_identity() -> Option<(String, String)> {
    TARGET.with(|target| {
        target.borrow().as_ref().map(|target| {
            (
                target.profile.id().to_string(),
                target.profile.session().to_owned(),
            )
        })
    })
}

pub(super) fn socket_label() -> String {
    match remote_identity() {
        Some((id, session)) => format!("machine:{id}/{session}"),
        None => crate::api::socket_path().display().to_string(),
    }
}

pub(super) fn remote_path_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

pub(super) fn caller_pane_id() -> Option<String> {
    if is_remote() {
        return None;
    }
    std::env::var("HERDR_PANE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn parse_machine_prefix(args: &[String]) -> Result<Option<(String, Vec<String>)>, String> {
    let mut index = 1;
    let mut machine = None;
    let mut other_prefix = false;
    while let Some(arg) = args.get(index) {
        if arg == "--machine" || arg.starts_with("--machine=") {
            if machine.is_some() {
                return Err("--machine can only be specified once".into());
            }
            let value = if let Some(value) = arg.strip_prefix("--machine=") {
                value.to_owned()
            } else {
                index += 1;
                args.get(index)
                    .cloned()
                    .ok_or("missing value for --machine")?
            };
            if value.trim().is_empty() || value.starts_with('-') {
                return Err("--machine requires a saved machine label or profile ID".into());
            }
            machine = Some(value);
        } else if arg.starts_with('-') && arg != "--" {
            other_prefix = true;
            if matches!(
                arg.as_str(),
                "--session" | "--remote" | "--remote-keybindings"
            ) {
                index += 1;
            }
        } else {
            break;
        }
        index += 1;
    }
    let Some(machine) = machine else {
        return Ok(None);
    };
    if other_prefix {
        return Err("--machine cannot be combined with other launch options; it uses the saved machine's session".into());
    }
    if index >= args.len() || args[index] == "--" {
        return Err("usage: herdr --machine <label-or-id> <command>".into());
    }
    let mut cleaned = vec![args[0].clone()];
    cleaned.extend_from_slice(&args[index..]);
    Ok(Some((machine, cleaned)))
}

/// SSH-only resolution, kept for the SSH resolution tests.
#[cfg(test)]
pub(super) fn resolve_machine<'a>(
    profiles: &'a [SavedSshEndpoint],
    selector: &str,
) -> Result<&'a SavedSshEndpoint, String> {
    match resolve_saved_machine(profiles, &[], selector)? {
        SavedMachineRef::Ssh(profile) => Ok(profile),
        SavedMachineRef::DialIn(_) => Err(format!("unknown machine '{selector}'")),
    }
}

/// Resolves an enabled saved machine across the SSH and dial-in catalogs:
/// a profile ID first, then a label naming exactly one machine.
pub(super) fn resolve_saved_machine<'a>(
    ssh: &'a [SavedSshEndpoint],
    dial_in: &'a [DialInMachine],
    selector: &str,
) -> Result<SavedMachineRef<'a>, String> {
    let machine = find_saved_machine(ssh, dial_in, selector)?;
    if !machine.enabled() {
        return Err(format!("machine '{selector}' is disabled"));
    }
    Ok(machine)
}

/// Whether `selector` is the id or label of a saved SSH or dial-in machine
/// (enabled or not), which relay hubs are then never asked about.
pub(super) fn names_saved_machine(
    ssh: &[SavedSshEndpoint],
    dial_in: &[DialInMachine],
    selector: &str,
) -> bool {
    ssh.iter()
        .any(|profile| profile.id.as_str() == selector || profile.label == selector)
        || dial_in
            .iter()
            .any(|machine| machine.id.as_str() == selector || machine.label == selector)
}

/// Like [`resolve_saved_machine`], but also finds disabled machines.
pub(super) fn find_saved_machine<'a>(
    ssh: &'a [SavedSshEndpoint],
    dial_in: &'a [DialInMachine],
    selector: &str,
) -> Result<SavedMachineRef<'a>, String> {
    if let Some(profile) = ssh.iter().find(|profile| profile.id.as_str() == selector) {
        return Ok(SavedMachineRef::Ssh(profile));
    }
    if let Some(machine) = dial_in
        .iter()
        .find(|machine| machine.id.as_str() == selector)
    {
        return Ok(SavedMachineRef::DialIn(machine));
    }
    let mut matches = ssh
        .iter()
        .filter(|profile| profile.label == selector)
        .map(SavedMachineRef::Ssh)
        .chain(
            dial_in
                .iter()
                .filter(|machine| machine.label == selector)
                .map(SavedMachineRef::DialIn),
        );
    let machine = matches
        .next()
        .ok_or_else(|| format!("unknown machine '{selector}'; use `herdr machine list`"))?;
    if matches.next().is_some() {
        return Err(format!(
            "machine label '{selector}' is ambiguous; use its profile ID"
        ));
    }
    Ok(machine)
}

fn validate_machine_command(args: &[String]) -> Result<(), String> {
    let command = args.get(1).map(String::as_str).unwrap_or_default();
    let subcommand = args.get(2).map(String::as_str).unwrap_or_default();
    let supported = match command {
        "workspace" | "worktree" | "tab" | "pane" | "notification" => true,
        "agent" => {
            subcommand != "attach"
                && !(subcommand == "explain"
                    && args[3..]
                        .iter()
                        .any(|arg| arg == "--file" || arg.starts_with("--file=")))
        }
        "api" => subcommand == "snapshot",
        "status" => subcommand == "server",
        "plugin" => matches!(
            subcommand,
            "link" | "unlink" | "enable" | "disable" | "list" | "action" | "log" | "logs" | "pane"
        ),
        "server" => matches!(
            subcommand,
            "stop" | "reload-config" | "agent-manifests" | "reload-agent-manifests"
        ),
        _ => false,
    };
    if supported {
        Ok(())
    } else {
        Err(format!("`{command} {subcommand}` is not an API-backed machine command; --machine does not run local management commands or attach a TUI"))
    }
}

#[cfg(test)]
pub(super) fn with_test_client<T>(client: ApiClient, run: impl FnOnce() -> T) -> T {
    let _scope = TARGET.with(|target| {
        TargetScope(
            target.replace(Some(MachineTarget {
                profile: MachineProfile::Ssh(
                    SavedSshEndpoint::new("test-machine", "unused", "remote-session")
                        .expect("valid test profile"),
                ),
                bridge: None,
                client_override: Some(client),
            })),
        )
    });
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn machine_prefix_routes_without_consuming_command_payload() {
        for prefix in [args(&["--machine", "mac"]), args(&["--machine=mac"])] {
            let mut input = args(&["herdr"]);
            input.extend(prefix);
            input.extend(args(&["agent", "prompt", "w4:p1", "--machine"]));
            assert_eq!(
                parse_machine_prefix(&input).unwrap(),
                Some((
                    "mac".into(),
                    args(&["herdr", "agent", "prompt", "w4:p1", "--machine"])
                ))
            );
        }
        assert_eq!(
            parse_machine_prefix(&args(&[
                "herdr",
                "agent",
                "prompt",
                "w4:p1",
                "--machine=mac"
            ]))
            .unwrap(),
            None
        );
    }

    #[test]
    fn machine_prefix_rejects_missing_target_and_conflicting_global_options() {
        for input in [
            args(&["herdr", "--machine"]),
            args(&["herdr", "--machine="]),
            args(&["herdr", "--machine", "--help"]),
            args(&["herdr", "--machine", "mac"]),
            args(&[
                "herdr",
                "--machine",
                "mac",
                "--machine",
                "other",
                "agent",
                "list",
            ]),
            args(&[
                "herdr",
                "--machine",
                "mac",
                "--session",
                "other",
                "agent",
                "list",
            ]),
            args(&[
                "herdr",
                "--session",
                "other",
                "--machine",
                "mac",
                "agent",
                "list",
            ]),
            args(&[
                "herdr",
                "--remote",
                "other",
                "--machine",
                "mac",
                "agent",
                "list",
            ]),
        ] {
            assert!(parse_machine_prefix(&input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn machine_resolution_requires_a_unique_enabled_saved_machine() {
        let mac = SavedSshEndpoint::new("mac", "mac-ssh", "agents").unwrap();
        let other = SavedSshEndpoint::new("build", "builder", "default").unwrap();
        let profiles = vec![mac.clone(), other];
        assert_eq!(resolve_machine(&profiles, "mac").unwrap(), &mac);
        assert_eq!(resolve_machine(&profiles, mac.id.as_str()).unwrap(), &mac);
        let shadow = SavedSshEndpoint::new(mac.id.as_str(), "shadow", "default").unwrap();
        assert_eq!(
            resolve_machine(&[mac.clone(), shadow], mac.id.as_str()).unwrap(),
            &mac
        );
        assert!(resolve_machine(&profiles, "mac-ssh").is_err());
        assert!(resolve_machine(&profiles, "missing").is_err());
        let duplicate = SavedSshEndpoint::new("mac", "other", "default").unwrap();
        assert!(resolve_machine(&[mac.clone(), duplicate], "mac").is_err());
        let mut disabled = mac;
        disabled.enabled = false;
        assert!(resolve_machine(&[disabled], "mac").is_err());
    }

    fn dial_in_machine(label: &str, session: &str) -> DialInMachine {
        DialInMachine::new(label, session).unwrap()
    }

    #[test]
    fn machine_resolution_spans_ssh_and_dial_in_catalogs() {
        let ssh = vec![SavedSshEndpoint::new("mac", "mac-ssh", "agents").unwrap()];
        let laptop = dial_in_machine("laptop", "default");
        let mut disabled = dial_in_machine("old box", "default");
        disabled.enabled = false;
        let dial_in = vec![laptop.clone(), disabled.clone()];

        assert_eq!(
            resolve_saved_machine(&ssh, &dial_in, "laptop").unwrap(),
            SavedMachineRef::DialIn(&laptop)
        );
        assert_eq!(
            resolve_saved_machine(&ssh, &dial_in, laptop.id.as_str()).unwrap(),
            SavedMachineRef::DialIn(&laptop)
        );
        assert_eq!(
            resolve_saved_machine(&ssh, &dial_in, "mac").unwrap(),
            SavedMachineRef::Ssh(&ssh[0])
        );
        assert!(resolve_saved_machine(&ssh, &dial_in, "missing")
            .unwrap_err()
            .contains("unknown machine"));
        let error = resolve_saved_machine(&ssh, &dial_in, "old box").unwrap_err();
        assert!(error.contains("disabled"), "{error}");
        assert!(resolve_saved_machine(&ssh, &dial_in, disabled.id.as_str()).is_err());
        assert_eq!(
            find_saved_machine(&ssh, &dial_in, "old box").unwrap(),
            SavedMachineRef::DialIn(&disabled)
        );

        // A label shared across catalogs is ambiguous; ids still resolve.
        let shared = dial_in_machine("mac", "default");
        let both = vec![shared.clone()];
        assert!(resolve_saved_machine(&ssh, &both, "mac")
            .unwrap_err()
            .contains("ambiguous"));
        assert_eq!(
            resolve_saved_machine(&ssh, &both, shared.id.as_str()).unwrap(),
            SavedMachineRef::DialIn(&shared)
        );
        // An id beats a label equal to it, in either catalog.
        let shadow = dial_in_machine(ssh[0].id.as_str(), "default");
        assert_eq!(
            resolve_saved_machine(&ssh, &[shadow], ssh[0].id.as_str()).unwrap(),
            SavedMachineRef::Ssh(&ssh[0])
        );
        let shadow = SavedSshEndpoint::new(laptop.id.as_str(), "shadow", "default").unwrap();
        assert_eq!(
            resolve_saved_machine(&[shadow], &dial_in, laptop.id.as_str()).unwrap(),
            SavedMachineRef::DialIn(&laptop)
        );
    }

    #[cfg(unix)]
    struct LinkScratch {
        root: std::path::PathBuf,
        paths: LinkPaths,
    }

    #[cfg(unix)]
    impl LinkScratch {
        fn new(machine: &DialInMachine) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::path::PathBuf::from(format!(
                "/tmp/hct-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let paths = LinkPaths::for_catalog(&root.join("dial-in-machines.json"), &machine.id);
            Self { root, paths }
        }

        fn create_link_dir(&self) {
            crate::platform::ensure_private_directory(&self.paths.dir).unwrap();
        }
    }

    #[cfg(unix)]
    impl Drop for LinkScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn dial_in_target_connects_to_the_link_api_socket_only_when_private_and_listening() {
        use std::os::unix::fs::PermissionsExt;

        let machine = dial_in_machine("laptop", "agents");
        let scratch = LinkScratch::new(&machine);
        let paths = &scratch.paths;

        let error = dial_in_api_client(&machine, paths).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(
            error.to_string(),
            "machine 'laptop' is not connected (it has not dialed in)"
        );

        scratch.create_link_dir();
        let error = dial_in_api_client(&machine, paths).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);

        std::fs::write(&paths.api_socket, b"").unwrap();
        let client = dial_in_api_client(&machine, paths).unwrap();
        assert_eq!(client.socket_path(), paths.api_socket);

        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = dial_in_api_client(&machine, paths).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let message = error.to_string();
        assert!(
            message.contains("machine 'laptop'")
                && message.contains("refusing dial-in link directory"),
            "{message}"
        );
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        std::fs::remove_dir_all(&paths.dir).unwrap();
        let elsewhere = scratch.root.join("elsewhere");
        crate::platform::ensure_private_directory(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &paths.dir).unwrap();
        let error = dial_in_api_client(&machine, paths).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn dial_in_target_scope_is_remote_and_reports_offline_links_clearly() {
        let machine = dial_in_machine("laptop", "agents");
        let scratch = LinkScratch::new(&machine);
        scratch.create_link_dir();
        std::fs::write(&scratch.paths.api_socket, b"").unwrap();
        let _scope = TARGET.with(|target| {
            TargetScope(target.replace(Some(MachineTarget {
                profile: MachineProfile::DialIn {
                    machine: machine.clone(),
                    paths: scratch.paths.clone(),
                    started_at_ms: 0,
                },
                bridge: None,
                client_override: None,
            })))
        });

        assert!(is_remote());
        assert_eq!(caller_pane_id(), None);
        assert_eq!(
            remote_identity(),
            Some((machine.id.to_string(), "agents".to_owned()))
        );
        assert_eq!(
            api_client().unwrap().socket_path(),
            scratch.paths.api_socket
        );
        assert!(restart_guidance().contains("machine 'laptop' (session agents)"));

        for kind in [io::ErrorKind::ConnectionRefused, io::ErrorKind::NotFound] {
            let error = remote_error(io::Error::from(kind));
            assert_eq!(
                error.to_string(),
                "machine 'laptop' is not connected (it has not dialed in)"
            );
        }

        let error = remote_error(io::Error::other(
            crate::api::client::ApiClientError::EmptyResponse,
        ));
        assert_eq!(
            error.to_string(),
            "machine 'laptop' (session agents): the machine closed the stream without answering"
        );

        let mut status = crate::remote::link::status::LinkStatus::default();
        status.last_stream_error = Some(crate::remote::link::status::ErrorRecord::new(
            "server_needs_update",
            "herdr needs one final update\u{1b}[2J",
        ));
        crate::remote::link::status::write_status(&scratch.paths.status_file, &status).unwrap();
        let error = remote_error(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stream closed",
        ));
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let message = error.to_string();
        assert!(
            message.starts_with("machine 'laptop' (session agents): stream closed"),
            "{message}"
        );
        assert!(message.contains("needs one final update"), "{message}");
        assert!(!message.contains('\u{1b}'), "{message}");
    }

    #[test]
    fn machine_commands_reject_local_side_effects_and_tui_attach() {
        for command in [
            &["update"][..],
            &["config", "reset-keys"],
            &["machine", "remove", "mac"],
            &["session", "delete", "default"],
            &["server", "live-handoff"],
            &["agent", "attach", "w4:p1"],
            &["terminal", "attach", "w4:p1"],
            &["terminal", "session", "control", "w4:p1"],
            &["plugin", "install", "./plugin"],
            &["integration", "install", "pi"],
            &["api", "schema", "--output", "schema.json"],
            &["status", "client"],
        ] {
            let mut input = args(&["herdr"]);
            input.extend(args(command));
            assert!(validate_machine_command(&input).is_err(), "{input:?}");
        }
        for command in [
            &["agent", "list"][..],
            &["agent", "wait", "w4:p1"],
            &["pane", "split", "w4:p1", "--direction", "right"],
            &["workspace", "list"],
            &["worktree", "create", "--branch", "feature"],
            &["tab", "list"],
            &["api", "snapshot"],
            &["server", "stop"],
        ] {
            let mut input = args(&["herdr"]);
            input.extend(args(command));
            assert!(validate_machine_command(&input).is_ok(), "{input:?}");
        }
    }
}
