use super::*;

/// Internal events for the client event loop.
pub(super) enum ClientLoopEvent {
    #[cfg(unix)]
    StdinInput(Vec<u8>),
    #[cfg(unix)]
    PixelMouse(Vec<u8>, crate::input::mouse::HostGeometry),
    #[cfg(unix)]
    DirectGraphicsResponse(direct_graphics::Response),
    #[cfg(windows)]
    StdinEvents(Vec<crate::protocol::ClientInputEvent>),
    #[cfg(windows)]
    NotificationActivated(shell::ClientSystemNotificationTarget),
    Resize(u16, u16, u32, u32, bool),
    TerminalUnavailable(io::Error),
    ServerMessage {
        endpoint_id: endpoint::ClientEndpointId,
        generation: u64,
        message: Box<ServerMessage>,
    },
    ServerDisconnected {
        endpoint_id: endpoint::ClientEndpointId,
        generation: u64,
    },
    EndpointSupervisor(endpoint::EndpointSupervisorEvent),
    EndpointCatalog(catalog_reload::SavedMachinesReload),
    /// A dial-in machine's link reached `connected` with a newer epoch.
    DialInPresence {
        id: endpoint::ProfileId,
    },
    /// A relay hub could not be listed; its machines keep their last list.
    RelayNotice(String),
    ActivateEndpoint {
        endpoint_id: endpoint::ClientEndpointId,
        target: Option<shell::ClientEndpointFocusTarget>,
        /// A superseded handoff deliberately starts a fresh target-on epoch even when source and
        /// latest target have the same identity after restoration.
        force: bool,
    },
    Timer,
}
