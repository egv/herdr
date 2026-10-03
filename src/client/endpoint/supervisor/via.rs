//! Machines reached through a relay hub: connecting, classifying failures,
//! and keeping supervisors in step with the relays' listings.

use std::collections::hash_map::Entry;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{
    ClientEndpointId, ClientEndpointStatus, ConnectTarget, EndpointSupervisors, ReconnectState,
    DIAL_IN_OFFLINE_MESSAGE,
};
use crate::client::endpoint::ViaMachine;
use crate::remote::RELAY_UNREACHABLE;

/// Each attempt costs an SSH session on the relay hub; presence wakes from
/// the relay poller cover a machine that dials in again.
pub(super) const MAX_VIA_RETRY_DELAY: Duration = Duration::from_secs(30);

static RELAY_POLL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Whether a via connection failed since the last call: the relay poller
/// then lists the relays again without waiting for its interval.
pub(crate) fn take_relay_poll_request() -> bool {
    RELAY_POLL_REQUESTED.swap(false, Ordering::AcqRel)
}

impl EndpointSupervisors {
    /// Applies the relays' latest listings. Machines that disappeared or now
    /// lead elsewhere (relay target or session) are retired so their late
    /// connections are fenced; other changes keep the connection.
    pub(crate) fn reconcile_via(
        &mut self,
        via: &[ViaMachine],
        now: Instant,
    ) -> Vec<ClientEndpointId> {
        let mut retired = Vec::new();
        self.endpoints.retain(|endpoint_id, state| {
            let ConnectTarget::Via(previous) = &state.target else {
                return true;
            };
            let keep = via.iter().any(|machine| {
                machine.id == previous.id
                    && machine.relay_target == previous.relay_target
                    && machine.session == previous.session
            });
            if !keep {
                retired.push(endpoint_id.clone());
            }
            keep
        });
        for machine in via {
            match self
                .endpoints
                .entry(ClientEndpointId::Ssh(machine.id.clone()))
            {
                // A saved machine keeps an id that collides with a via id.
                Entry::Occupied(mut entry) => {
                    if matches!(entry.get().target, ConnectTarget::Via(_)) {
                        entry.get_mut().target = ConnectTarget::Via(machine.clone());
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(ReconnectState::new(
                        ConnectTarget::Via(machine.clone()),
                        now,
                    ));
                }
            }
        }
        retired
    }
}

pub(super) fn connect(machine: &ViaMachine) -> io::Result<crate::remote::ViaStream> {
    crate::remote::connect_via(
        machine.relay_id.as_str(),
        &machine.relay_target,
        machine.link_id.as_str(),
        machine.id.as_str(),
    )
}

/// Classifies a failed attempt, forgets a moved relay executable, and asks
/// the relay poller for a fresh listing.
pub(super) fn classify(machine: &ViaMachine, error: &io::Error) -> (ClientEndpointStatus, String) {
    RELAY_POLL_REQUESTED.store(true, Ordering::Release);
    if crate::remote::SavedSshApiBridge::stale_metadata_failure(error) {
        crate::remote::invalidate_relay_herdr(machine.relay_id.as_str(), &machine.relay_target);
    }
    via_failure(&machine.relay_label, &machine.relay_target, error)
}

/// - the machine has not dialed in to the relay: keep retrying, quietly;
/// - SSH to the relay failed: say so, and need attention for authentication
///   or host keys like a saved SSH machine;
/// - anything else (the machine's own server): the saved SSH machine rules.
fn via_failure(
    relay_label: &str,
    relay_target: &str,
    error: &io::Error,
) -> (ClientEndpointStatus, String) {
    let message = error.to_string();
    if crate::remote::via_not_connected(&message) {
        return (
            ClientEndpointStatus::Reconnecting,
            format!("{DIAL_IN_OFFLINE_MESSAGE} to {relay_label}"),
        );
    }
    if crate::remote::SavedSshApiBridge::stale_metadata_failure(error) {
        return (
            ClientEndpointStatus::Reconnecting,
            format!("{RELAY_UNREACHABLE}: its Herdr executable moved; looking for it again"),
        );
    }
    let status = if crate::remote::saved_ssh_failure_needs_attention(error) {
        ClientEndpointStatus::Attention
    } else {
        ClientEndpointStatus::Reconnecting
    };
    if message.starts_with(RELAY_UNREACHABLE) || relay_ssh_failure(&message) {
        return (
            status,
            crate::remote::relay_unreachable_message(&message, relay_target),
        );
    }
    (status, message)
}

/// Diagnostics of OpenSSH itself, as opposed to Herdr on the relay hub.
fn relay_ssh_failure(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    crate::remote::ssh_error_requires_authentication(message)
        || [
            "host key verification failed",
            "remote host identification has changed",
            "ssh: ",
            "kex_exchange_identification",
            "connection closed by",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::ProfileId;
    use io::ErrorKind;

    fn machine(link: &str) -> ViaMachine {
        let relay = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let link_id = ProfileId::parse(link).unwrap();
        ViaMachine {
            id: crate::client::endpoint::via_id(&relay, &link_id),
            relay_id: relay,
            relay_label: "vps".into(),
            relay_target: "me@vps".into(),
            link_id,
            label: "slave1".into(),
            session: "default".into(),
            connected: true,
        }
    }

    #[test]
    fn via_failure_classification_table() {
        use ClientEndpointStatus::{Attention, Reconnecting};
        let relay_hint = ". Check `ssh me@vps`.";
        for (kind, message, status, expected) in [
            (
                ErrorKind::ConnectionAborted,
                "remote SSH connection failed: herdr link-connect: slave1 is not connected (it has not dialed in)",
                Reconnecting,
                "offline; waiting for it to dial in to vps".to_string(),
            ),
            (
                ErrorKind::ConnectionAborted,
                "remote SSH connection failed: me@vps: Permission denied (publickey).",
                Attention,
                format!("{RELAY_UNREACHABLE}: remote SSH connection failed: me@vps: Permission denied (publickey){relay_hint}"),
            ),
            (
                ErrorKind::Other,
                "could not reach the relay hub: Host key verification failed.",
                Attention,
                format!("{RELAY_UNREACHABLE}: Host key verification failed{relay_hint}"),
            ),
            (
                ErrorKind::Other,
                "could not reach the relay hub: ssh: connect to host vps port 22: Connection timed out",
                Reconnecting,
                format!("{RELAY_UNREACHABLE}: ssh: connect to host vps port 22: Connection timed out{relay_hint}"),
            ),
            (
                ErrorKind::ConnectionAborted,
                "remote SSH connection failed: ssh: Could not resolve hostname vps",
                Reconnecting,
                format!("{RELAY_UNREACHABLE}: remote SSH connection failed: ssh: Could not resolve hostname vps{relay_hint}"),
            ),
            (
                ErrorKind::Other,
                "remote SSH connection failed: herdr-machine-metadata-stale-v1",
                Reconnecting,
                format!("{RELAY_UNREACHABLE}: its Herdr executable moved; looking for it again"),
            ),
            // The machine's own server: saved SSH rules, no relay wording.
            (
                ErrorKind::Unsupported,
                "this machine needs a server update before it can participate in multi-machine viewing",
                Attention,
                "this machine needs a server update before it can participate in multi-machine viewing".to_string(),
            ),
            (
                ErrorKind::UnexpectedEof,
                "connection closed during handshake read",
                Attention,
                "connection closed during handshake read".to_string(),
            ),
            (
                ErrorKind::ConnectionAborted,
                "remote SSH connection failed: herdr link-connect: slave1 is disabled on this hub",
                Reconnecting,
                "remote SSH connection failed: herdr link-connect: slave1 is disabled on this hub".to_string(),
            ),
            (
                ErrorKind::TimedOut,
                "Transport endpoint is not connected",
                Reconnecting,
                "Transport endpoint is not connected".to_string(),
            ),
        ] {
            assert_eq!(
                via_failure("vps", "me@vps", &io::Error::new(kind, message)),
                (status, expected),
                "{message}"
            );
        }
    }

    #[test]
    fn relay_listings_add_update_and_retire_via_supervisors() {
        let now = Instant::now();
        let first = machine("fedcba9876543210fedcba9876543210");
        let second = machine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let id = ClientEndpointId::Ssh(first.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[], &[], now);
        assert!(supervisors
            .reconcile_via(&[first.clone(), second.clone()], now)
            .is_empty());
        assert_eq!(supervisors.endpoints[&id].next_attempt, Some(now));
        // SSH and dial-in reconciliation leave via machines alone.
        assert!(supervisors.reconcile_profiles(&[], &[], now).is_empty());
        assert!(supervisors.endpoints.contains_key(&id));

        // A relabel or presence change keeps the connection.
        supervisors.endpoints.get_mut(&id).unwrap().generation = Some(4);
        let mut renamed = first.clone();
        renamed.relay_label = "hub".into();
        renamed.connected = false;
        assert!(supervisors
            .reconcile_via(&[renamed.clone(), second.clone()], now)
            .is_empty());
        assert_eq!(supervisors.endpoints[&id].generation, Some(4));

        // Another session or relay target is another destination.
        let mut moved = renamed.clone();
        moved.session = "work".into();
        assert_eq!(
            supervisors.reconcile_via(&[moved.clone(), second.clone()], now),
            vec![id.clone()]
        );
        assert_eq!(supervisors.endpoints[&id].generation, None);
        assert!(!supervisors.record_status(&id, 4, ClientEndpointStatus::Online, now));
        assert_eq!(
            supervisors.reconcile_via(std::slice::from_ref(&second), now),
            vec![id.clone()]
        );
        assert!(!supervisors.endpoints.contains_key(&id));

        // Failures retry at most every 30 seconds.
        let second_id = ClientEndpointId::Ssh(second.id.clone());
        supervisors
            .endpoints
            .get_mut(&second_id)
            .unwrap()
            .generation = Some(9);
        for _ in 0..12 {
            supervisors.record_status(&second_id, 9, ClientEndpointStatus::Reconnecting, now);
        }
        assert_eq!(
            supervisors.endpoints[&second_id].next_attempt,
            Some(now + MAX_VIA_RETRY_DELAY)
        );
        assert!(supervisors.wake(&second_id, now));
        assert_eq!(supervisors.endpoints[&second_id].next_attempt, Some(now));
    }
}
