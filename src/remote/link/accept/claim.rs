//! Detecting a link that more than one machine keeps claiming (for example a
//! copied dial key or config): each takes the link over from the other, or
//! the live link keeps refusing the other one.

use std::time::Duration;

use super::super::status::{sanitize_remote_text, LinkStatus, SupersedeRecord};

/// Claims kept in `status.json`.
const MAX_SUPERSEDES: usize = 8;
/// A conflict is this many takeovers within the window from two or more addresses.
const CONFLICT_SUPERSEDES: usize = 3;
const CONFLICT_WINDOW_MS: u64 = 60_000;
/// A link that stays up this long without another claim clears a recorded conflict.
pub(super) const CONFLICT_CLEAR_AFTER: Duration = Duration::from_secs(10 * 60);

/// The dialer's address: the first field of sshd's `SSH_CONNECTION`
/// (`client_ip client_port server_ip server_port`).
pub(super) fn peer_addr(ssh_connection: Option<&str>) -> Option<String> {
    let addr = sanitize_remote_text(ssh_connection?.split_whitespace().next()?, 64);
    (!addr.is_empty()).then_some(addr)
}

/// Carries the takeover history of `previous` into a new link's `status`.
/// When this link `superseded` another, records the takeover from
/// `status.peer_addr` and flags a conflict after repeated takeovers from
/// different addresses.
pub(super) fn note_claim(
    status: &mut LinkStatus,
    previous: Option<&LinkStatus>,
    superseded: bool,
    now_ms: u64,
) {
    if let Some(previous) = previous {
        status
            .recent_supersedes
            .clone_from(&previous.recent_supersedes);
        status.claim_conflict.clone_from(&previous.claim_conflict);
    }
    if !superseded {
        return;
    }
    let claimant = status.peer_addr.clone();
    record(status, claimant, now_ms);
    let recent = status
        .recent_supersedes
        .iter()
        .filter(|record| now_ms.saturating_sub(record.at_ms) <= CONFLICT_WINDOW_MS)
        .collect::<Vec<_>>();
    let mut addrs = recent
        .iter()
        .filter_map(|record| record.peer_addr.as_deref())
        .collect::<Vec<_>>();
    addrs.sort_unstable();
    addrs.dedup();
    if recent.len() >= CONFLICT_SUPERSEDES && addrs.len() >= 2 {
        status.claim_conflict = Some(conflict(&addrs));
    }
}

/// Records a claim from `peer_addr` that this live link refused (its dialer
/// answered the probe). A claimant at another address than this link's is a
/// second machine with this link's key; refused dialers retry only every few
/// minutes, so one such claim flags the conflict. True when recorded.
pub(super) fn note_refused_claim(
    status: &mut LinkStatus,
    peer_addr: Option<String>,
    now_ms: u64,
) -> bool {
    let (Some(holder), Some(claimant)) = (status.peer_addr.clone(), peer_addr) else {
        return false;
    };
    if holder == claimant {
        return false;
    }
    record(status, Some(claimant.clone()), now_ms);
    let mut addrs = [holder.as_str(), claimant.as_str()];
    addrs.sort_unstable();
    status.claim_conflict = Some(conflict(&addrs));
    true
}

fn record(status: &mut LinkStatus, peer_addr: Option<String>, now_ms: u64) {
    let records = &mut status.recent_supersedes;
    records.push(SupersedeRecord {
        at_ms: now_ms,
        peer_addr,
    });
    records.drain(..records.len().saturating_sub(MAX_SUPERSEDES));
}

fn conflict(addrs: &[&str]) -> String {
    format!(
        "link claimed by more than one machine ({})",
        addrs.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(at_ms: u64, addr: &str) -> SupersedeRecord {
        SupersedeRecord {
            at_ms,
            peer_addr: Some(addr.into()),
        }
    }

    fn takeover(previous: &LinkStatus, addr: &str, now_ms: u64) -> LinkStatus {
        let mut status = LinkStatus {
            peer_addr: peer_addr(Some(&format!("{addr} 50022 192.0.2.100 22"))),
            ..LinkStatus::default()
        };
        note_claim(&mut status, Some(previous), true, now_ms);
        status
    }

    #[test]
    fn peer_address_is_the_first_ssh_connection_field() {
        assert_eq!(
            peer_addr(Some("2001:db8::7 50022 2001:db8::1 22")).as_deref(),
            Some("2001:db8::7")
        );
        assert_eq!(peer_addr(Some("\x1b[2J 1 2 3")).as_deref(), Some("[2J"));
        assert_eq!(peer_addr(Some("   ")), None);
        assert_eq!(peer_addr(None), None);
    }

    #[test]
    fn repeated_takeovers_from_two_addresses_are_a_conflict() {
        let start = 1_000_000;
        let mut status = LinkStatus::default();
        // One machine reconnecting over and over is not a conflict.
        for step in 0..4 {
            status = takeover(&status, "192.0.2.1", start + step);
        }
        assert_eq!(status.recent_supersedes.len(), 4);
        assert_eq!(status.claim_conflict, None);

        status = takeover(&status, "192.0.2.2", start + 10);
        assert_eq!(
            status.claim_conflict.as_deref(),
            Some("link claimed by more than one machine (192.0.2.1, 192.0.2.2)")
        );
        // A link without a takeover keeps the history and the conflict.
        let mut next = LinkStatus::default();
        note_claim(&mut next, Some(&status), false, start + 20);
        assert_eq!(next.recent_supersedes, status.recent_supersedes);
        assert_eq!(next.claim_conflict, status.claim_conflict);
    }

    #[test]
    fn a_refused_claim_from_another_address_is_a_conflict() {
        let mut status = LinkStatus {
            peer_addr: Some("192.0.2.1".into()),
            ..LinkStatus::default()
        };
        // The same machine, or an unknown address, proves nothing.
        assert!(!note_refused_claim(
            &mut status,
            Some("192.0.2.1".into()),
            5
        ));
        assert!(!note_refused_claim(&mut status, None, 5));
        assert!(status.recent_supersedes.is_empty() && status.claim_conflict.is_none());

        assert!(note_refused_claim(&mut status, Some("192.0.2.0".into()), 7));
        assert_eq!(status.recent_supersedes, [record(7, "192.0.2.0")]);
        assert_eq!(
            status.claim_conflict.as_deref(),
            Some("link claimed by more than one machine (192.0.2.0, 192.0.2.1)")
        );
        let mut unknown = LinkStatus::default();
        assert!(!note_refused_claim(
            &mut unknown,
            Some("192.0.2.0".into()),
            7
        ));
    }

    #[test]
    fn old_takeovers_do_not_count_and_the_history_is_bounded() {
        let now = 10_000_000;
        let previous = LinkStatus {
            recent_supersedes: vec![
                record(now - CONFLICT_WINDOW_MS - 1, "192.0.2.1"),
                record(now - 1, "192.0.2.1"),
            ],
            ..LinkStatus::default()
        };
        let status = takeover(&previous, "192.0.2.2", now);
        assert_eq!(status.claim_conflict, None);

        let mut status = LinkStatus::default();
        for step in 0..20 {
            status = takeover(&status, "192.0.2.1", now + step);
        }
        assert_eq!(status.recent_supersedes.len(), MAX_SUPERSEDES);
        assert_eq!(status.recent_supersedes[0].at_ms, now + 12);
    }
}
