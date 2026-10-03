use super::*;
use crate::remote::link::status::{read_status, LinkState};

/// One reading of both saved-machine catalogs. Each file fails independently:
/// an unusable file keeps that catalog's current machines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SavedMachinesReload {
    pub(super) ssh: Result<Vec<endpoint::SavedSshEndpoint>, String>,
    pub(super) dial_in: Result<Vec<endpoint::DialInMachine>, String>,
    /// As last listed by the relay hubs (see `relay_reload`).
    pub(super) via: Vec<endpoint::ViaMachine>,
}

impl SavedMachinesReload {
    fn load(via: &super::relay_reload::SharedViaMachines) -> Self {
        Self {
            ssh: endpoint::EndpointCatalog::load_profiles(),
            dial_in: endpoint::EndpointCatalog::load_dial_in_machines(),
            via: via.lock().map(|via| via.clone()).unwrap_or_default(),
        }
    }

    /// The machines to apply, falling back to `catalog`'s current lists for a
    /// file that could not be read, plus the errors to report.
    pub(super) fn resolve(
        self,
        catalog: &endpoint::EndpointCatalog,
    ) -> (
        Vec<endpoint::SavedSshEndpoint>,
        Vec<endpoint::DialInMachine>,
        Vec<endpoint::ViaMachine>,
        Vec<String>,
    ) {
        let mut errors = Vec::new();
        let ssh = self.ssh.unwrap_or_else(|error| {
            errors.push(error);
            catalog.ssh.clone()
        });
        let dial_in = self.dial_in.unwrap_or_else(|error| {
            errors.push(error);
            catalog.dial_in.clone()
        });
        (ssh, dial_in, self.via, errors)
    }
}

pub(super) fn watch_profiles(
    event_tx: tokio::sync::mpsc::Sender<ClientLoopEvent>,
    should_quit: Arc<AtomicBool>,
) {
    // Per client and second: two bounded catalog reads plus one stat per enabled
    // dial-in machine, independent of rendering and pane count.
    let via = super::relay_reload::spawn_relay_poller(event_tx.clone(), should_quit.clone());
    std::thread::spawn(move || {
        let mut previous = None;
        let mut presence = DialInPresence::default();
        let mut watched: Vec<(endpoint::ProfileId, std::path::PathBuf)> = Vec::new();
        let mut watched_from: Option<Vec<endpoint::DialInMachine>> = None;
        while !should_quit.load(Ordering::Acquire) {
            let current = SavedMachinesReload::load(&via);
            if let Ok(machines) = &current.dial_in {
                if watched_from.as_ref() != Some(machines) {
                    watched = machines
                        .iter()
                        .filter(|machine| machine.enabled)
                        .map(|machine| (machine.id.clone(), machine.paths().status_file))
                        .collect();
                    watched_from = Some(machines.clone());
                }
            }
            if previous.as_ref() != Some(&current) {
                previous = Some(current.clone());
                if event_tx
                    .blocking_send(ClientLoopEvent::EndpointCatalog(current))
                    .is_err()
                {
                    break;
                }
            }
            let woken = presence.poll(watched.iter().map(|(id, path)| (id, path.as_path())));
            for id in woken {
                if event_tx
                    .blocking_send(ClientLoopEvent::DialInPresence { id })
                    .is_err()
                {
                    return;
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

/// Watches dial-in link status files and reports machines whose link just
/// (re)connected, so their reconnect skips its backoff. Only a `connected`
/// state with a higher `link_epoch` than previously seen counts; other
/// rewrites (stream errors, disconnects) never wake, which avoids retry storms.
#[derive(Default)]
pub(super) struct DialInPresence {
    seen: HashMap<endpoint::ProfileId, PresenceSeen>,
}

struct PresenceSeen {
    /// Modification time and length of the status file when last read.
    stamp: Option<(std::time::SystemTime, u64)>,
    /// Link epoch when last read; 0 while the file is absent.
    epoch: u64,
}

impl PresenceSeen {
    const ABSENT: Self = Self {
        stamp: None,
        epoch: 0,
    };
}

impl DialInPresence {
    /// Stats each target's status file, reads it only when it changed, and
    /// returns the ids to wake. The first sighting of a machine only records a
    /// baseline. Targets that are no longer passed are forgotten.
    pub(super) fn poll<'a>(
        &mut self,
        targets: impl IntoIterator<Item = (&'a endpoint::ProfileId, &'a std::path::Path)>,
    ) -> Vec<endpoint::ProfileId> {
        let mut woken = Vec::new();
        let mut current = HashMap::with_capacity(self.seen.len());
        for (id, status_file) in targets {
            let previous = self.seen.remove(id);
            let next = match std::fs::symlink_metadata(status_file) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => PresenceSeen::ABSENT,
                Err(error) => {
                    debug!(%error, path = %status_file.display(), "dial-in link status unavailable");
                    match previous {
                        Some(previous) => previous,
                        None => continue,
                    }
                }
                Ok(metadata) => {
                    let stamp = metadata.modified().ok().map(|time| (time, metadata.len()));
                    match previous {
                        Some(previous) if stamp.is_some() && previous.stamp == stamp => previous,
                        previous => match read_status(status_file) {
                            Ok(None) => PresenceSeen::ABSENT,
                            Ok(Some(status)) => {
                                if previous.as_ref().is_some_and(|previous| {
                                    status.state == LinkState::Connected
                                        && status.link_epoch > previous.epoch
                                }) {
                                    woken.push(id.clone());
                                }
                                PresenceSeen {
                                    stamp,
                                    epoch: status.link_epoch,
                                }
                            }
                            Err(error) => {
                                debug!(%error, path = %status_file.display(), "dial-in link status unreadable");
                                PresenceSeen {
                                    stamp,
                                    epoch: previous.map_or(0, |previous| previous.epoch),
                                }
                            }
                        },
                    }
                }
            };
            current.insert(id.clone(), next);
        }
        self.seen = current;
        woken
    }
}

// Only called between surface handoffs: removing a source must not invalidate an in-flight
// rollback. Connection attempts are independent and fenced by supervisor generations.
#[allow(clippy::too_many_arguments)] // the loop's owned pieces of client state, borrowed once
pub(super) fn apply_profiles(
    state: &mut ClientState,
    endpoints: &mut endpoint::EndpointRegistry,
    commands: &mut endpoint_commands::EndpointCommands,
    supervisors: &mut endpoint::EndpointSupervisors,
    catalog: &mut endpoint::EndpointCatalog,
    profiles: Vec<endpoint::SavedSshEndpoint>,
    dial_in: Vec<endpoint::DialInMachine>,
    mut via: Vec<endpoint::ViaMachine>,
    now: std::time::Instant,
) -> bool {
    let dial_in = endpoint::dial_in_without_id_collisions(&profiles, dial_in);
    // Saved machines keep an id that collides with a derived via id.
    via.retain(|machine| {
        !profiles.iter().any(|profile| profile.id == machine.id)
            && !dial_in.iter().any(|saved| saved.id == machine.id)
    });
    if catalog.ssh == profiles && catalog.dial_in == dial_in && catalog.via == via {
        return false;
    }
    let previous_size = state
        .shell
        .as_ref()
        .map(|shell| shell.surface_size(state.reported_size.0, state.reported_size.1));
    let mut retired = supervisors.reconcile_profiles(&profiles, &dial_in, now);
    retired.extend(supervisors.reconcile_via(&via, now));
    let active_removed = retired.contains(endpoints.active_id());
    for endpoint_id in retired {
        endpoints.disconnect(&endpoint_id);
        let cancelled = commands.disconnect(&endpoint_id);
        #[cfg(unix)]
        state.forget_endpoint_graphics(&endpoint_id);
        if let Some(shell) = state.shell.as_mut() {
            for request_id in cancelled {
                shell.cancel_endpoint_request(&request_id);
            }
            shell.retire_endpoint(&endpoint_id);
        }
    }
    catalog.ssh = profiles;
    catalog.dial_in = dial_in;
    catalog.set_via(via);
    if active_removed {
        endpoints.select_unavailable_local();
        catalog.select_local();
        state.freeze_presentation();
        if let Some(shell) = state.shell.as_mut() {
            shell.select_unavailable_local();
        }
    } else if catalog
        .selected_profile
        .as_ref()
        .is_some_and(|selected| !catalog.machine_is_enabled(selected))
    {
        catalog.select_local();
    }
    if let Some(shell) = state.shell.as_mut() {
        shell.set_endpoint_machines(&catalog.machine_summaries());
        if endpoints.active_surface_available()
            && previous_size
                != Some(shell.surface_size(state.reported_size.0, state.reported_size.1))
        {
            shell.invalidate_pane_surface();
            endpoints.send(&client_shell_resize_message(
                shell,
                state.reported_size.0,
                state.reported_size.1,
                state.reported_cell_size.0,
                state.reported_cell_size.1,
                state.pixel_geometry_exact,
            ));
        }
    }
    active_removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use endpoint::{ClientEndpointId, EndpointCatalog, EndpointRegistry, EndpointSupervisors};
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    struct Transport(Arc<AtomicUsize>);

    impl endpoint::EndpointTransport for Transport {
        fn send(&mut self, _: &ClientMessage) -> io::Result<()> {
            Ok(())
        }

        fn disconnect(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn state() -> ClientState {
        ClientState::test_new()
    }

    #[test]
    fn live_catalog_add_and_rename_keep_local_connection_and_selection() {
        let now = Instant::now();
        let mut state = state();
        let disconnected = Arc::new(AtomicUsize::new(0));
        let mut endpoints =
            EndpointRegistry::new(Transport(disconnected.clone()), 1, Default::default());
        let mut supervisors = EndpointSupervisors::new(&[], &[], now);
        let mut commands = endpoint_commands::EndpointCommands::default();
        let mut catalog = EndpointCatalog::default();
        let mut profile = endpoint::SavedSshEndpoint::new("Build", "build", "main").unwrap();
        for label in ["Build", "Renamed"] {
            profile.label = label.into();
            assert!(!apply_profiles(
                &mut state,
                &mut endpoints,
                &mut commands,
                &mut supervisors,
                &mut catalog,
                vec![profile.clone()],
                Vec::new(),
                Vec::new(),
                now
            ));
            assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
            assert!(endpoints.active_surface_available());
            assert_eq!(
                endpoints
                    .connection(&ClientEndpointId::Local)
                    .unwrap()
                    .generation,
                1
            );
            assert_eq!(catalog.selected_profile, None);
            assert_eq!(
                state
                    .shell
                    .as_ref()
                    .unwrap()
                    .endpoint_label(&ClientEndpointId::Ssh(profile.id.clone())),
                label
            );
        }
        assert_eq!(disconnected.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn live_catalog_remove_or_disable_active_machine_selects_local_without_input() {
        for local_online in [false, true] {
            for disable in [false, true] {
                let now = Instant::now();
                let mut state = state();
                let mut catalog = EndpointCatalog::default();
                let id = catalog.add_ssh("Build", "build", "main").unwrap();
                let remote = ClientEndpointId::Ssh(id.clone());
                catalog.select_ssh(&id);
                state
                    .shell
                    .as_mut()
                    .unwrap()
                    .set_endpoint_catalog(&catalog.ssh);
                let mut supervisors = EndpointSupervisors::new(&catalog.ssh, &[], now);
                let mut endpoints = EndpointRegistry::empty();
                let local_disconnects = Arc::new(AtomicUsize::new(0));
                if local_online {
                    endpoints.insert(
                        ClientEndpointId::Local,
                        Transport(local_disconnects.clone()),
                        1,
                        Default::default(),
                        false,
                    );
                }
                let remote_disconnects = Arc::new(AtomicUsize::new(0));
                endpoints.insert(
                    remote.clone(),
                    Transport(remote_disconnects.clone()),
                    2,
                    Default::default(),
                    true,
                );
                endpoints.set_active(&remote);
                endpoints.unfreeze_input();
                let mut commands = endpoint_commands::EndpointCommands::default();
                let profiles = if disable {
                    let mut profiles = catalog.ssh.clone();
                    profiles[0].enabled = false;
                    profiles
                } else {
                    Vec::new()
                };
                assert!(apply_profiles(
                    &mut state,
                    &mut endpoints,
                    &mut commands,
                    &mut supervisors,
                    &mut catalog,
                    profiles,
                    Vec::new(),
                    Vec::new(),
                    now
                ));
                assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
                assert!(!endpoints.active_surface_available());
                assert!(endpoints.connection(&remote).is_none());
                assert_eq!(
                    endpoints.connection(&ClientEndpointId::Local).is_some(),
                    local_online
                );
                assert!(state
                    .shell
                    .as_ref()
                    .unwrap()
                    .endpoint_is_active(&ClientEndpointId::Local));
                assert!(!state.shell.as_ref().unwrap().has_presented_surface());
                assert!(state.presentation_frozen);
                assert_eq!(catalog.selected_profile, None);
                assert_eq!(remote_disconnects.load(Ordering::Relaxed), 1);
                assert_eq!(local_disconnects.load(Ordering::Relaxed), 0);
                assert!(!supervisors.record_status(
                    &remote,
                    2,
                    endpoint::ClientEndpointStatus::Online,
                    now
                ));
            }
        }
    }

    #[test]
    fn live_catalog_dial_in_machines_join_and_leave_like_ssh_machines() {
        let now = Instant::now();
        let mut state = state();
        let mut endpoints = EndpointRegistry::empty();
        let mut commands = endpoint_commands::EndpointCommands::default();
        let mut catalog = EndpointCatalog::default();
        let mut supervisors = EndpointSupervisors::new(&[], &[], now);
        let ssh = endpoint::SavedSshEndpoint::new("Build", "build", "main").unwrap();
        let mut laptop = endpoint::DialInMachine::new("Laptop", "default").unwrap();
        let laptop_id = ClientEndpointId::Ssh(laptop.id.clone());

        assert!(!apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            vec![ssh.clone()],
            vec![laptop.clone()],
            Vec::new(),
            now
        ));
        assert!(catalog.has_enabled_machines());
        let shell = state.shell.as_ref().unwrap();
        assert_eq!(shell.endpoint_label(&laptop_id), "Laptop");
        assert_eq!(
            shell.endpoint_status(&laptop_id),
            Some(endpoint::ClientEndpointStatus::Connecting)
        );
        assert!(catalog.select_endpoint(&laptop_id));
        assert!(supervisors.wake(&laptop_id, now));

        // Renaming keeps the selection; disabling the active machine selects Local.
        laptop.label = "Renamed".into();
        assert!(!apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            vec![ssh.clone()],
            vec![laptop.clone()],
            Vec::new(),
            now
        ));
        assert_eq!(catalog.selected_profile.as_ref(), Some(&laptop.id));
        assert_eq!(
            state.shell.as_ref().unwrap().endpoint_label(&laptop_id),
            "Renamed"
        );
        let disconnects = Arc::new(AtomicUsize::new(0));
        endpoints.insert(
            laptop_id.clone(),
            Transport(disconnects.clone()),
            2,
            Default::default(),
            true,
        );
        endpoints.set_active(&laptop_id);
        laptop.enabled = false;
        assert!(apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            vec![ssh.clone()],
            vec![laptop.clone()],
            Vec::new(),
            now
        ));
        assert_eq!(disconnects.load(Ordering::Relaxed), 1);
        assert_eq!(catalog.selected_profile, None);
        assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
        assert!(!supervisors.wake(&laptop_id, now));
        assert_eq!(
            state.shell.as_ref().unwrap().endpoint_status(&laptop_id),
            Some(endpoint::ClientEndpointStatus::Disabled)
        );

        // An unreadable catalog file keeps that catalog's current machines only.
        let reload = SavedMachinesReload {
            ssh: Err("broken endpoints.json".into()),
            dial_in: Ok(Vec::new()),
            via: Vec::new(),
        };
        let (profiles, dial_in, _, errors) = reload.resolve(&catalog);
        assert_eq!(profiles, vec![ssh.clone()]);
        assert!(dial_in.is_empty());
        assert_eq!(errors, vec!["broken endpoints.json".to_string()]);
        let reload = SavedMachinesReload {
            ssh: Ok(Vec::new()),
            dial_in: Err("broken dial-in-machines.json".into()),
            via: Vec::new(),
        };
        let (profiles, dial_in, _, errors) = reload.resolve(&catalog);
        assert!(profiles.is_empty());
        assert_eq!(dial_in, vec![laptop]);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn live_catalog_via_machines_follow_relay_listings() {
        let now = Instant::now();
        let mut state = state();
        let mut endpoints = EndpointRegistry::empty();
        let mut commands = endpoint_commands::EndpointCommands::default();
        let mut catalog = EndpointCatalog::default();
        let mut supervisors = EndpointSupervisors::new(&[], &[], now);
        let relay = endpoint::ProfileId::generate();
        let link = endpoint::ProfileId::generate();
        let via = endpoint::ViaMachine {
            id: endpoint::via_id(&relay, &link),
            relay_id: relay,
            relay_label: "vps".into(),
            relay_target: "me@vps".into(),
            link_id: link,
            label: "slave1".into(),
            session: "default".into(),
            connected: true,
        };
        let id = ClientEndpointId::Ssh(via.id.clone());
        let mut apply = |state: &mut ClientState,
                         endpoints: &mut EndpointRegistry,
                         catalog: &mut EndpointCatalog,
                         ssh: Vec<endpoint::SavedSshEndpoint>,
                         via: Vec<endpoint::ViaMachine>| {
            apply_profiles(
                state,
                endpoints,
                &mut commands,
                &mut supervisors,
                catalog,
                ssh,
                Vec::new(),
                via,
                now,
            )
        };

        assert!(!apply(
            &mut state,
            &mut endpoints,
            &mut catalog,
            Vec::new(),
            vec![via.clone()]
        ));
        assert!(catalog.has_enabled_machines());
        let shell = state.shell.as_ref().unwrap();
        assert_eq!(shell.endpoint_label(&id), "vps/slave1");
        assert_eq!(
            shell.endpoint_status(&id),
            Some(endpoint::ClientEndpointStatus::Connecting)
        );
        assert!(catalog.select_endpoint(&id));

        // A saved SSH machine keeps a colliding id.
        let mut colliding = endpoint::SavedSshEndpoint::new("Build", "build", "main").unwrap();
        colliding.id = via.id.clone();
        apply(
            &mut state,
            &mut endpoints,
            &mut catalog,
            vec![colliding],
            vec![via.clone()],
        );
        assert!(catalog.via.is_empty());
        assert_eq!(state.shell.as_ref().unwrap().endpoint_label(&id), "Build");

        // A machine the relay no longer lists leaves; when active, Local takes over.
        apply(
            &mut state,
            &mut endpoints,
            &mut catalog,
            Vec::new(),
            vec![via.clone()],
        );
        let disconnects = Arc::new(AtomicUsize::new(0));
        endpoints.insert(
            id.clone(),
            Transport(disconnects.clone()),
            2,
            Default::default(),
            true,
        );
        endpoints.set_active(&id);
        assert!(catalog.select_endpoint(&id));
        assert!(apply(
            &mut state,
            &mut endpoints,
            &mut catalog,
            Vec::new(),
            Vec::new()
        ));
        assert_eq!(disconnects.load(Ordering::Relaxed), 1);
        assert_eq!(catalog.selected_profile, None);
        assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
        assert_eq!(state.shell.as_ref().unwrap().endpoint_status(&id), None);
    }

    #[cfg(unix)]
    #[test]
    fn dial_in_presence_wakes_only_when_a_link_reaches_a_new_connected_epoch() {
        use crate::remote::link::status::{write_status, LinkStatus};

        let root =
            std::env::temp_dir().join(format!("herdr-dial-in-presence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let laptop = endpoint::ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let desktop = endpoint::ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap();
        let laptop_status = root.join("laptop.json");
        let desktop_status = root.join("desktop.json");
        let write = |path: &std::path::Path, state: LinkState, epoch: u64, stream_error: bool| {
            // Distinct mtimes even on coarse filesystem clocks.
            std::thread::sleep(Duration::from_millis(15));
            write_status(
                path,
                &LinkStatus {
                    state,
                    link_epoch: epoch,
                    last_stream_error: stream_error.then(|| {
                        crate::remote::link::status::ErrorRecord::new("bridge_failed", "boom")
                    }),
                    ..LinkStatus::default()
                },
            )
            .unwrap();
        };
        let mut presence = DialInPresence::default();
        let poll = |presence: &mut DialInPresence| {
            presence.poll([
                (&laptop, laptop_status.as_path()),
                (&desktop, desktop_status.as_path()),
            ])
        };

        // First sightings only record baselines, even when already connected.
        write(&desktop_status, LinkState::Connected, 4, false);
        assert!(poll(&mut presence).is_empty());
        assert!(poll(&mut presence).is_empty(), "unchanged files never wake");

        // The laptop dials in for the first time after being seen absent.
        write(&laptop_status, LinkState::Connected, 1, false);
        assert_eq!(poll(&mut presence), vec![laptop.clone()]);
        assert!(poll(&mut presence).is_empty());

        // Rewrites without a new connected epoch never wake.
        write(&laptop_status, LinkState::Connected, 1, true);
        write(&desktop_status, LinkState::Disconnected, 4, false);
        assert!(poll(&mut presence).is_empty());
        write(&desktop_status, LinkState::Disconnected, 5, false);
        assert!(
            poll(&mut presence).is_empty(),
            "a disconnected epoch is not presence"
        );
        write(&desktop_status, LinkState::Unknown, 6, false);
        assert!(poll(&mut presence).is_empty());

        // A reconnect bumps the epoch and wakes exactly once.
        write(&desktop_status, LinkState::Connected, 7, false);
        write(&laptop_status, LinkState::Connected, 2, false);
        let mut woken = poll(&mut presence);
        woken.sort();
        assert_eq!(woken, vec![laptop.clone(), desktop.clone()]);
        assert!(poll(&mut presence).is_empty());

        // A machine that is no longer watched is forgotten, so re-adding it
        // starts from a fresh baseline instead of waking.
        assert!(presence
            .poll([(&laptop, laptop_status.as_path())])
            .is_empty());
        write(&desktop_status, LinkState::Connected, 8, false);
        assert!(poll(&mut presence).is_empty());
        write(&desktop_status, LinkState::Connected, 9, false);
        assert_eq!(poll(&mut presence), vec![desktop.clone()]);

        // A status file that disappears resets the baseline; a fresh link wakes.
        std::fs::remove_file(&laptop_status).unwrap();
        assert!(poll(&mut presence).is_empty());
        write(&laptop_status, LinkState::Connected, 1, false);
        assert_eq!(poll(&mut presence), vec![laptop.clone()]);

        // Unreadable content never wakes.
        std::thread::sleep(Duration::from_millis(15));
        std::fs::write(&laptop_status, b"{not json").unwrap();
        assert!(poll(&mut presence).is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
