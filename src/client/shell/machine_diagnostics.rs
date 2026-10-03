use super::*;
use crate::raw_input::RawInputEvent;
use crossterm::event::{MouseButton, MouseEventKind};

#[derive(Default)]
pub(super) struct MachineDiagnostics {
    errors: HashMap<ClientEndpointId, String>,
    hover: Option<ClientEndpointId>,
}

impl MachineDiagnostics {
    /// Whether the machine needs interactive SSH authentication. Never true for
    /// a dial-in machine: this client does not authenticate to it. A machine
    /// reached through a relay hub needs it only for SSH to the relay itself.
    pub(super) fn required_for(&self, endpoint: &ClientShellEndpoint) -> bool {
        let Some(message) = self.errors.get(&endpoint.endpoint_id) else {
            return false;
        };
        match endpoint.machine_kind {
            Some(SavedMachineKind::Ssh) => {
                crate::remote::ssh_error_requires_authentication(message)
            }
            Some(SavedMachineKind::Via) => via_relay_requires_authentication(message),
            _ => false,
        }
    }

    pub(super) fn badge_style(
        &self,
        endpoint: &ClientShellEndpoint,
        palette: &Palette,
        style: Style,
    ) -> Style {
        if self.hover.as_ref() == Some(&endpoint.endpoint_id)
            && self.errors.contains_key(&endpoint.endpoint_id)
        {
            style
                .bg(palette.active_row_bg)
                .add_modifier(Modifier::REVERSED)
        } else {
            style
        }
    }
}

impl ClientShellState {
    pub(crate) fn set_machine_diagnostic(&mut self, id: &ClientEndpointId, message: String) {
        if !id.is_local() {
            self.machine_diagnostics.errors.insert(
                id.clone(),
                message
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\n')
                    .take(4096)
                    .collect(),
            );
        }
    }

    pub(super) fn clear_machine_diagnostic(&mut self, id: &ClientEndpointId) {
        self.machine_diagnostics.errors.remove(id);
    }

    pub(super) fn handle_machine_badge_event(
        &mut self,
        event: &RawInputEvent,
        outcome: &mut ClientShellInput,
    ) -> bool {
        let RawInputEvent::Mouse(mouse) = event else {
            return false;
        };
        if self.overlay.is_some()
            || self.popup_pending
            || self.hits.popup.is_some()
            || contains(self.hits.notification_toast, (mouse.column, mouse.row))
        {
            return false;
        }
        let hit = self
            .hits
            .machines
            .iter()
            .find(|hit| {
                contains(hit.status_badge, (mouse.column, mouse.row))
                    && self
                        .machine_diagnostics
                        .errors
                        .contains_key(&hit.endpoint_id)
            })
            .map(|hit| hit.endpoint_id.clone());
        if mouse.kind == MouseEventKind::Moved {
            if self.machine_diagnostics.hover != hit {
                self.machine_diagnostics.hover = hit;
                outcome.repaint = true;
            }
            return false;
        }
        let Some(id) = hit else {
            return false;
        };
        if mouse.kind == MouseEventKind::Up(MouseButton::Left) {
            return true;
        }
        if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
            return false;
        }
        let Some(error) = self.machine_diagnostics.errors.get(&id) else {
            return true;
        };
        let ClientEndpointId::Ssh(profile_id) = &id else {
            return true;
        };
        let label = self.endpoint_label(&id);
        let kind = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == id)
            .and_then(|endpoint| endpoint.machine_kind);
        let title = if kind == Some(SavedMachineKind::DialIn) {
            dial_in_diagnostic_title(label, &profile_id.to_string(), error)
        } else if kind == Some(SavedMachineKind::Via) {
            via_diagnostic_title(label, error)
        } else if crate::remote::ssh_error_requires_authentication(error) {
            format!("{label}: herdr machine reconnect {profile_id}")
        } else {
            format!("{label}: herdr machine status {profile_id}")
        };
        let code = format!("machine-diagnostic:{}", profile_id);
        // An explicit click can reopen its diagnostic, but must not replace another notice.
        if self
            .visible_endpoint_notice
            .as_ref()
            .is_some_and(|notice| notice.key.code != code)
        {
            return true;
        }
        self.visible_endpoint_notice = Some(ClientVisibleEndpointNotice {
            key: ClientEndpointNoticeKey {
                boot_id: "machine".into(),
                kind: ClientEndpointNoticeKind::Unavailable,
                code,
            },
            title,
            body: error.clone(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(15),
        });
        outcome.repaint = true;
        true
    }
}

/// A dial-in machine connects to this hub on its own, so the next step
/// usually happens on that machine; only refusals by this hub itself (an
/// unsafe link directory or socket, an overlong socket path) are fixed here.
fn dial_in_diagnostic_title(label: &str, profile_id: &str, error: &str) -> String {
    if dial_in_error_is_hub_side(error) {
        format!("{label}: this hub refused the link. Run `herdr machine status {profile_id}` here.")
    } else if dial_in_error_needs_update(error) {
        format!(
            "{label}: its Herdr server needs an update. On that machine run `herdr update`, then `herdr machine dial status`."
        )
    } else {
        format!(
            "{label}: waiting for it to dial in. On that machine run `herdr machine dial status`."
        )
    }
}

/// A machine reached through a relay hub (labeled `<relay>/<machine>`):
/// either SSH to the relay failed, which is fixed here, or the machine has
/// not dialed in to the relay, which is fixed on that machine.
fn via_diagnostic_title(label: &str, error: &str) -> String {
    let relay = label.split_once('/').map_or(label, |(relay, _)| relay);
    if error.contains(crate::remote::RELAY_UNREACHABLE) {
        format!("{relay}: {error}")
    } else if dial_in_error_needs_update(error) {
        format!(
            "{label}: its Herdr server needs an update. On that machine run `herdr update`, then `herdr machine dial status`."
        )
    } else {
        format!(
            "{label}: waiting for it to dial in to {relay}. On that machine run `herdr machine dial status`."
        )
    }
}

fn via_relay_requires_authentication(error: &str) -> bool {
    error.contains(crate::remote::RELAY_UNREACHABLE)
        && crate::remote::ssh_error_requires_authentication(error)
}

fn dial_in_error_is_hub_side(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    ["refusing dial-in link", "too long for a unix socket"]
        .iter()
        .any(|needle| error.contains(needle))
}

fn dial_in_error_needs_update(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    ["server update", "needs one final update", "herdr update"]
        .iter()
        .any(|needle| error.contains(needle))
}

#[cfg(test)]
mod via_tests {
    use super::*;

    #[test]
    fn via_diagnostics_blame_the_relay_only_for_its_own_ssh() {
        let relay_auth = "could not reach the relay hub: me@vps: Permission denied (publickey). Check `ssh me@vps`.";
        assert_eq!(
            via_diagnostic_title("vps/slave1", relay_auth),
            format!("vps: {relay_auth}")
        );
        assert!(via_relay_requires_authentication(relay_auth));
        let offline = "offline; waiting for it to dial in to vps";
        assert_eq!(
            via_diagnostic_title("vps/slave1", offline),
            "vps/slave1: waiting for it to dial in to vps. On that machine run `herdr machine dial status`."
        );
        assert!(!via_relay_requires_authentication(offline));
        // The machine's own problems never show `! auth`.
        assert!(!via_relay_requires_authentication(
            "that machine reported: Permission denied (publickey)"
        ));
        assert!(via_diagnostic_title(
            "vps/slave1",
            "this machine needs a server update before it can participate"
        )
        .contains("needs an update"));
    }
}
