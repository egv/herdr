//! Why a link attempt failed, and how long to wait before the next one.

use std::fmt;
use std::time::Duration;

use crate::remote::link::protocol::{error_code, LinkError};
use crate::remote::link::status::{sanitize_remote_text, MAX_REMOTE_TEXT_BYTES};

pub(crate) const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Backoff after failures that retrying soon cannot fix (authentication,
/// host key, or the hub refusing the link).
pub(crate) const BACKOFF_PERSISTENT: Duration = Duration::from_secs(5 * 60);

/// A link that stayed connected this long resets the backoff.
pub(crate) const STABLE_LINK_RESET: Duration = Duration::from_secs(60);

/// Dialer-side failure codes (link-level codes from the hub are used as is).
pub(crate) mod failure_code {
    pub(crate) const AUTHENTICATION_FAILED: &str = "authentication_failed";
    pub(crate) const HOST_KEY_UNVERIFIED: &str = "host_key_unverified";
    pub(crate) const SSH_FAILED: &str = "ssh_failed";
    pub(crate) const MASTER_TIMEOUT: &str = "master_timeout";
    pub(crate) const PREAMBLE_FAILED: &str = "preamble_failed";
    pub(crate) const HELLO_TIMEOUT: &str = "hello_timeout";
    pub(crate) const LINK_LOST: &str = "link_lost";
    pub(crate) const LINK_DEAD: &str = "link_dead";
    pub(crate) const LOCAL_ERROR: &str = "local_error";
    pub(crate) const PROTOCOL_ERROR: &str = super::error_code::PROTOCOL_ERROR;
}

/// Why one link attempt ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinkFailure {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl LinkFailure {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// A failure reported by the hub, sanitized for display and storage.
    pub(crate) fn from_link_error(error: &LinkError) -> Self {
        Self::new(
            sanitize_remote_text(&error.code, 64),
            sanitize_remote_text(&error.message, MAX_REMOTE_TEXT_BYTES),
        )
    }

    pub(crate) fn is_persistent(&self) -> bool {
        is_persistent_failure(&self.code)
    }

    pub(crate) fn with_detail(mut self, detail: &str) -> Self {
        let detail = remote_text_tail(detail);
        if !detail.is_empty() && !self.message.contains(&detail) {
            self.message = format!("{} ({detail})", self.message);
        }
        self
    }
}

impl fmt::Display for LinkFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} [{}]", self.message, self.code)
    }
}

/// Failures that retrying soon cannot fix get the long backoff.
pub(crate) fn is_persistent_failure(code: &str) -> bool {
    matches!(
        code,
        failure_code::AUTHENTICATION_FAILED
            | failure_code::HOST_KEY_UNVERIFIED
            | error_code::LINK_UNKNOWN
            | error_code::LINK_DISABLED
            | error_code::LINK_ID_MISMATCH
            | error_code::LINK_VERSION_UNSUPPORTED
            | error_code::LINK_BUSY
    )
}

/// Reconnect delays: exponential from 1 s to 60 s for transient failures, a
/// fixed 5 minutes for persistent ones, reset after a stable link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Backoff {
    next_transient: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next_transient: BACKOFF_INITIAL,
        }
    }
}

impl Backoff {
    /// The delay before the next attempt after `failure`. `connected_for` is
    /// how long the failed attempt's link was up, if it connected at all.
    pub(crate) fn delay_after(
        &mut self,
        failure: &LinkFailure,
        connected_for: Option<Duration>,
    ) -> Duration {
        if connected_for.is_some_and(|connected| connected >= STABLE_LINK_RESET) {
            *self = Self::default();
        }
        if failure.is_persistent() {
            return BACKOFF_PERSISTENT;
        }
        let delay = self.next_transient;
        self.next_transient = (delay * 2).min(BACKOFF_MAX);
        delay
    }
}

/// The last few non-empty lines of diagnostic output, sanitized and bounded.
pub(crate) fn remote_text_tail(text: &str) -> String {
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let start = lines.len().saturating_sub(3);
    sanitize_remote_text(&lines[start..].join(" | "), MAX_REMOTE_TEXT_BYTES)
}

pub(crate) fn is_host_key_failure(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
        || lower.contains("you have requested strict checking")
}

pub(crate) fn is_authentication_failure(stderr: &str) -> bool {
    !is_host_key_failure(stderr)
        && (crate::remote::ssh_error_requires_authentication(stderr)
            || stderr
                .to_ascii_lowercase()
                .contains("too many authentication failures"))
}

/// Whether ssh stderr reports that the hub refused another session on an
/// existing master (sshd `MaxSessions`, default 10).
pub(crate) fn is_session_refusal(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("open failed")
        || lower.contains("session open refused")
        || lower.contains("administratively prohibited")
        || lower.contains("session request failed")
}

/// Classifies a failed ssh connection from its stderr.
pub(crate) fn classify_ssh_failure(context: &str, stderr: &str) -> LinkFailure {
    let code = if is_host_key_failure(stderr) {
        failure_code::HOST_KEY_UNVERIFIED
    } else if is_authentication_failure(stderr) {
        failure_code::AUTHENTICATION_FAILED
    } else {
        failure_code::SSH_FAILED
    };
    LinkFailure::new(code, context).with_detail(stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(code: &str) -> LinkFailure {
        LinkFailure::new(code, "m")
    }

    #[test]
    fn backoff_classification_table() {
        for code in [
            failure_code::AUTHENTICATION_FAILED,
            failure_code::HOST_KEY_UNVERIFIED,
            error_code::LINK_UNKNOWN,
            error_code::LINK_DISABLED,
            error_code::LINK_ID_MISMATCH,
            error_code::LINK_VERSION_UNSUPPORTED,
            error_code::LINK_BUSY,
        ] {
            assert!(is_persistent_failure(code), "{code}");
            let mut backoff = Backoff::default();
            assert_eq!(
                backoff.delay_after(&failure(code), None),
                BACKOFF_PERSISTENT
            );
        }
        for code in [
            failure_code::SSH_FAILED,
            failure_code::MASTER_TIMEOUT,
            failure_code::PREAMBLE_FAILED,
            failure_code::HELLO_TIMEOUT,
            failure_code::LINK_LOST,
            failure_code::LINK_DEAD,
            failure_code::PROTOCOL_ERROR,
            error_code::SHUTTING_DOWN,
            "something_new",
        ] {
            assert!(!is_persistent_failure(code), "{code}");
        }

        let mut backoff = Backoff::default();
        let transient = failure(failure_code::LINK_LOST);
        let delays = (0..9)
            .map(|_| backoff.delay_after(&transient, None).as_secs())
            .collect::<Vec<_>>();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60]);

        // A short-lived link does not reset; a stable one does.
        assert_eq!(
            backoff.delay_after(&transient, Some(Duration::from_secs(59))),
            BACKOFF_MAX
        );
        assert_eq!(
            backoff.delay_after(&transient, Some(STABLE_LINK_RESET)),
            BACKOFF_INITIAL
        );
        assert_eq!(
            backoff.delay_after(&transient, None),
            Duration::from_secs(2)
        );
        // Persistent failures keep their delay even right after a reset.
        assert_eq!(
            backoff.delay_after(
                &failure(error_code::LINK_BUSY),
                Some(Duration::from_secs(600))
            ),
            BACKOFF_PERSISTENT
        );
        assert_eq!(backoff.delay_after(&transient, None), BACKOFF_INITIAL);
    }

    #[test]
    fn ssh_stderr_classification() {
        let auth = classify_ssh_failure(
            "ssh connection to the hub failed",
            "Warning: something\nme@hub: Permission denied (publickey).\n",
        );
        assert_eq!(auth.code, failure_code::AUTHENTICATION_FAILED);
        assert!(auth.message.contains("Permission denied (publickey)."));
        assert!(auth.is_persistent());

        for host_key in [
            "Host key verification failed.\n",
            "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nPermission denied (publickey).",
            "No ED25519 host key is known for hub and you have requested strict checking.\nHost key verification failed.",
        ] {
            assert_eq!(
                classify_ssh_failure("x", host_key).code,
                failure_code::HOST_KEY_UNVERIFIED,
                "{host_key}"
            );
        }
        assert_eq!(
            classify_ssh_failure("x", "Received disconnect: Too many authentication failures").code,
            failure_code::AUTHENTICATION_FAILED
        );
        let transient = classify_ssh_failure(
            "ssh connection to the hub failed",
            "ssh: connect to host hub port 22: Connection refused\n",
        );
        assert_eq!(transient.code, failure_code::SSH_FAILED);
        assert!(!transient.is_persistent());
        assert_eq!(
            classify_ssh_failure("ctx", "").message,
            "ctx",
            "no detail without stderr"
        );
        let noisy = classify_ssh_failure("ctx", "\u{1b}[31mbad\u{7}\n");
        assert!(!noisy.message.contains('\u{1b}'));
    }

    #[test]
    fn session_refusal_detection() {
        for refused in [
            "channel 3: open failed: administratively prohibited: open failed\n",
            "mux_client_request_session: session request failed: Session open refused by peer\n",
            "Session open refused by peer",
            "ADMINISTRATIVELY PROHIBITED",
        ] {
            assert!(is_session_refusal(refused), "{refused}");
        }
        for other in [
            "",
            "Connection to hub closed by remote host.",
            "Control socket connect(/x/ctl-0): No such file or directory",
            "Permission denied (publickey).",
        ] {
            assert!(!is_session_refusal(other), "{other}");
        }
    }
}
