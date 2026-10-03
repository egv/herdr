//! Polls relay hubs for their dial-in machines, beside the catalog watcher
//! and never on the render path. Each enabled relay is listed at startup,
//! every [`RELAY_POLL_INTERVAL`], and soon after a via connection fails. A
//! relay that cannot be reached keeps its last list.

use super::*;
use std::sync::Mutex;
use std::time::Instant;

/// Per client: one SSH command per enabled relay hub and interval.
const RELAY_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// The earliest relisting after a failed via connection asked for one.
const REQUESTED_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The via machines most recently listed by all enabled relay hubs.
pub(super) type SharedViaMachines = Arc<Mutex<Vec<endpoint::ViaMachine>>>;

pub(super) fn spawn_relay_poller(
    event_tx: tokio::sync::mpsc::Sender<ClientLoopEvent>,
    should_quit: Arc<AtomicBool>,
) -> SharedViaMachines {
    let shared = SharedViaMachines::default();
    let published = shared.clone();
    std::thread::spawn(move || {
        let mut poller = RelayPoller::default();
        let mut relays = Vec::new();
        let mut requested = false;
        while !should_quit.load(Ordering::Acquire) {
            match endpoint::RelayCatalog::load() {
                Ok(catalog) => relays = catalog.relays,
                Err(error) => {
                    debug!(%error, "relay hubs could not be reloaded; keeping the current ones")
                }
            }
            // A request waits until a listing actually runs.
            requested |= endpoint::take_relay_poll_request();
            let outcome = poller.poll(&relays, Instant::now(), requested, |relay| {
                crate::remote::list_relay(relay.id.as_str(), &relay.target)
            });
            requested &= !outcome.listed;
            if let Ok(mut machines) = published.lock() {
                *machines = outcome.machines;
            }
            let events = outcome
                .notices
                .into_iter()
                .map(ClientLoopEvent::RelayNotice)
                .chain(
                    outcome
                        .woken
                        .into_iter()
                        .map(|id| ClientLoopEvent::DialInPresence { id }),
                );
            for event in events {
                if event_tx.blocking_send(event).is_err() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    shared
}

#[derive(Default)]
pub(super) struct RelayPoller {
    relays: HashMap<endpoint::ProfileId, RelayState>,
}

struct RelayState {
    target: String,
    polled_at: Option<Instant>,
    machines: Vec<endpoint::ViaMachine>,
    /// Last listed presence (connected, link epoch) per via id.
    presence: HashMap<endpoint::ProfileId, (bool, u64)>,
    unreachable: bool,
}

#[derive(Default)]
pub(super) struct RelayPollOutcome {
    pub(super) machines: Vec<endpoint::ViaMachine>,
    /// Via machines that just dialed in to their relay (again).
    pub(super) woken: Vec<endpoint::ProfileId>,
    pub(super) notices: Vec<String>,
    /// Whether any relay was listed (successfully or not).
    pub(super) listed: bool,
}

impl RelayPoller {
    /// Lists the enabled relays that are due with `list` and returns every
    /// enabled relay's machines. A machine wakes when a listing shows it
    /// connected after it was not, or with a higher link epoch; its first
    /// listing only records a baseline. Relays no longer enabled are forgotten.
    pub(super) fn poll(
        &mut self,
        relays: &[endpoint::RelayHub],
        now: Instant,
        requested: bool,
        mut list: impl FnMut(&endpoint::RelayHub) -> io::Result<endpoint::RelayListing>,
    ) -> RelayPollOutcome {
        let mut outcome = RelayPollOutcome::default();
        let mut current = HashMap::with_capacity(self.relays.len());
        for relay in relays.iter().filter(|relay| relay.enabled) {
            let mut state = match self.relays.remove(&relay.id) {
                Some(state) if state.target == relay.target => state,
                _ => RelayState {
                    target: relay.target.clone(),
                    polled_at: None,
                    machines: Vec::new(),
                    presence: HashMap::new(),
                    unreachable: false,
                },
            };
            let due = state.polled_at.is_none_or(|polled_at| {
                let age = now.saturating_duration_since(polled_at);
                age >= RELAY_POLL_INTERVAL || (requested && age >= REQUESTED_POLL_INTERVAL)
            });
            if due {
                state.polled_at = Some(now);
                outcome.listed = true;
                match list(relay) {
                    Ok(listing) => {
                        // The hub refuses connections to disabled machines.
                        let listed: Vec<_> = listing
                            .via_machines(relay)
                            .into_iter()
                            .filter(|item| item.enabled)
                            .collect();
                        let mut presence = HashMap::with_capacity(listed.len());
                        for item in &listed {
                            let machine = &item.machine;
                            if machine.connected
                                && state.presence.get(&machine.id).is_some_and(
                                    |&(was_connected, epoch)| {
                                        !was_connected || item.link_epoch > epoch
                                    },
                                )
                            {
                                outcome.woken.push(machine.id.clone());
                            }
                            presence
                                .insert(machine.id.clone(), (machine.connected, item.link_epoch));
                        }
                        state.presence = presence;
                        state.machines = listed.into_iter().map(|item| item.machine).collect();
                        state.unreachable = false;
                    }
                    Err(error) => {
                        warn!(relay = %relay.id, %error, "relay hub could not be listed; keeping its machines");
                        // Stale: presence is unknown until the relay answers again.
                        for machine in &mut state.machines {
                            machine.connected = false;
                        }
                        for (connected, _) in state.presence.values_mut() {
                            *connected = false;
                        }
                        if !std::mem::replace(&mut state.unreachable, true) {
                            outcome.notices.push(format!(
                                "{}: {}",
                                relay.label.trim(),
                                crate::remote::relay_unreachable_message(
                                    &error.to_string(),
                                    &relay.target
                                )
                            ));
                        }
                    }
                }
            }
            for machine in &mut state.machines {
                machine.relay_label = relay.label.trim().to_string();
            }
            outcome.machines.extend(state.machines.iter().cloned());
            current.insert(relay.id.clone(), state);
        }
        self.relays = current;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use endpoint::{ProfileId, RelayHub, RelayListedMachine, RelayListing};

    const LINK: &str = "fedcba9876543210fedcba9876543210";

    fn relay() -> RelayHub {
        RelayHub {
            id: ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            label: "vps".into(),
            target: "me@vps".into(),
            enabled: true,
            extra: Default::default(),
        }
    }

    fn listing(connected: bool, link_epoch: u64) -> io::Result<RelayListing> {
        Ok(RelayListing {
            version: 1,
            machines: vec![RelayListedMachine {
                id: LINK.into(),
                label: "slave1".into(),
                session: "default".into(),
                enabled: true,
                connected,
                link_epoch,
            }],
        })
    }

    #[test]
    fn relay_poller_wakes_machines_that_dial_in_and_keeps_unreachable_relays() {
        let relay = relay();
        let id = endpoint::via_id(&relay.id, &ProfileId::parse(LINK).unwrap());
        let mut poller = RelayPoller::default();
        let start = Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let poll = |poller: &mut RelayPoller,
                    now: Instant,
                    requested: bool,
                    result: io::Result<RelayListing>| {
            let mut result = Some(result);
            let mut calls = 0;
            let outcome = poller.poll(std::slice::from_ref(&relay), now, requested, |_| {
                calls += 1;
                result.take().unwrap()
            });
            (outcome, calls)
        };

        // The first listing is a baseline, even when already connected.
        let (outcome, calls) = poll(&mut poller, at(0), false, listing(false, 1));
        assert_eq!(calls, 1);
        assert_eq!(outcome.machines.len(), 1);
        assert_eq!(outcome.machines[0].display_label(), "vps/slave1");
        assert!(outcome.woken.is_empty());
        // Not due yet: the last list stays, nothing runs.
        let (outcome, calls) = poll(&mut poller, at(1), true, listing(true, 2));
        assert_eq!(
            (calls, outcome.machines.len(), outcome.listed),
            (0, 1, false)
        );
        // A failed via connection asks for a listing sooner; it dialed in.
        let (outcome, calls) = poll(&mut poller, at(6), true, listing(true, 2));
        assert_eq!(calls, 1);
        assert_eq!(outcome.woken, vec![id.clone()]);
        assert!(outcome.machines[0].connected);
        // Same epoch: no wake; a new epoch (reconnected in between) wakes.
        let (outcome, _) = poll(&mut poller, at(21), false, listing(true, 2));
        assert!(outcome.woken.is_empty());
        let (outcome, _) = poll(&mut poller, at(36), false, listing(true, 3));
        assert_eq!(outcome.woken, vec![id.clone()]);

        // Unreachable: the machine stays (not connected) with one notice.
        let failure = || {
            Err(io::Error::other(
                "ssh: connect to host vps port 22: Connection refused",
            ))
        };
        let (outcome, _) = poll(&mut poller, at(51), false, failure());
        assert_eq!(outcome.machines.len(), 1);
        assert!(!outcome.machines[0].connected);
        assert_eq!(outcome.notices.len(), 1);
        assert!(outcome.notices[0].starts_with("vps: could not reach the relay hub: ssh:"));
        assert!(outcome.notices[0].ends_with("Check `ssh me@vps`."));
        let (outcome, _) = poll(&mut poller, at(66), false, failure());
        assert!(outcome.notices.is_empty());
        // Back, still connected: wake, since presence was unknown.
        let (outcome, _) = poll(&mut poller, at(81), false, listing(true, 3));
        assert_eq!(outcome.woken, vec![id.clone()]);

        // A machine disabled on the hub leaves the TUI.
        let mut disabled_machine = listing(true, 3).unwrap();
        disabled_machine.machines[0].enabled = false;
        let (outcome, _) = poll(&mut poller, at(96), false, Ok(disabled_machine));
        assert!(outcome.machines.is_empty());

        // Disabled relays are dropped; re-enabled ones start a new baseline.
        let mut disabled = relay.clone();
        disabled.enabled = false;
        let outcome = poller.poll(&[disabled], at(97), false, |_| unreachable!());
        assert!(outcome.machines.is_empty());
        let (outcome, calls) = poll(&mut poller, at(98), false, listing(true, 9));
        assert_eq!(calls, 1);
        assert!(outcome.woken.is_empty());
    }
}
