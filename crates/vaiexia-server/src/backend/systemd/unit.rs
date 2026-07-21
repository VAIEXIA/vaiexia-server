//! Portable helpers for systemd unit names and D-Bus active-state mapping.
//! Compiled on ALL platforms; unit-tested cross-platform.

use crate::backend::ServiceState;

// ── SystemdUnitName ───────────────────────────────────────────────────────────

/// A validated systemd unit name.
///
/// Enforces systemd-specific rules on top of the generic platform-neutral
/// hygiene enforced by [`crate::backend::UnitName`]:
/// - Charset: `[A-Za-z0-9._@-]` only.
/// - No `..` (path traversal).
/// - Length 1–256.
/// - If the name contains a `.`, the portion after the last `.` must be one
///   of the recognised systemd suffixes (`.service`, `.socket`, `.timer`,
///   `.target`, `.path`, `.mount`).
/// - Bare names (no `.`) are accepted and treated as `.service` semantics.
///
/// Returned by [`validate`] and consumed inside the systemd backend before
/// any D-Bus / journalctl call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitName(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid systemd unit name")]
pub struct InvalidSystemdUnitName;

const ALLOWED_SUFFIXES: &[&str] = &[
    ".service", ".socket", ".timer", ".target", ".path", ".mount",
];

impl SystemdUnitName {
    /// Parse and validate a systemd unit name.
    pub fn parse(s: &str) -> Result<Self, InvalidSystemdUnitName> {
        // Length checks
        if s.is_empty() || s.len() > 256 {
            return Err(InvalidSystemdUnitName);
        }

        // No path traversal
        if s.contains("..") {
            return Err(InvalidSystemdUnitName);
        }

        // Charset: [A-Za-z0-9._@-]
        if !s.bytes().all(|b| {
            matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'@' | b'-')
        }) {
            return Err(InvalidSystemdUnitName);
        }

        // Check suffix
        let has_dot = s.contains('.');
        if has_dot {
            let has_allowed = ALLOWED_SUFFIXES.iter().any(|suf| s.ends_with(suf));
            if !has_allowed {
                return Err(InvalidSystemdUnitName);
            }
        }
        // Bare name (no dot) is allowed — treated as .service semantics

        Ok(SystemdUnitName(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ── active_state_from_dbus ────────────────────────────────────────────────────

/// Map a D-Bus `ActiveState` string to our `ServiceState` enum.
///
/// Known values: "active", "inactive", "failed", "activating", "deactivating".
/// Anything else → `Unknown`.
pub fn active_state_from_dbus(s: &str) -> ServiceState {
    match s {
        "active" => ServiceState::Active,
        "inactive" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        "activating" => ServiceState::Activating,
        "deactivating" => ServiceState::Deactivating,
        _ => ServiceState::Unknown,
    }
}

/// Validate a unit name against systemd-specific rules, returning an error on failure.
///
/// Called at the systemd-backend boundary (before D-Bus / journalctl) to
/// ensure only well-formed systemd names reach the system bus.
pub fn validate(s: &str) -> Result<SystemdUnitName, InvalidSystemdUnitName> {
    SystemdUnitName::parse(s)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ServiceState;

    // ── active_state_from_dbus ────────────────────────────────────────────────

    #[test]
    fn active_state_active() {
        assert_eq!(active_state_from_dbus("active"), ServiceState::Active);
    }

    #[test]
    fn active_state_inactive() {
        assert_eq!(active_state_from_dbus("inactive"), ServiceState::Inactive);
    }

    #[test]
    fn active_state_failed() {
        assert_eq!(active_state_from_dbus("failed"), ServiceState::Failed);
    }

    #[test]
    fn active_state_activating() {
        assert_eq!(active_state_from_dbus("activating"), ServiceState::Activating);
    }

    #[test]
    fn active_state_deactivating() {
        assert_eq!(active_state_from_dbus("deactivating"), ServiceState::Deactivating);
    }

    #[test]
    fn active_state_unknown_for_unrecognized() {
        assert_eq!(active_state_from_dbus("reloading"), ServiceState::Unknown);
        assert_eq!(active_state_from_dbus(""), ServiceState::Unknown);
        assert_eq!(active_state_from_dbus("bogus"), ServiceState::Unknown);
    }

    // ── SystemdUnitName / validate ────────────────────────────────────────────

    #[test]
    fn validate_nginx_service_ok() {
        assert!(validate("nginx.service").is_ok());
    }

    #[test]
    fn validate_sshd_bare_ok() {
        assert!(validate("sshd").is_ok());
    }

    #[test]
    fn validate_path_traversal_err() {
        assert!(validate("../etc").is_err());
    }

    #[test]
    fn validate_space_err() {
        assert!(validate("a b.service").is_err());
    }

    #[test]
    fn validate_unknown_suffix_err() {
        assert!(validate("x.evil").is_err());
    }

    #[test]
    fn validate_timer_ok() {
        assert!(validate("x.timer").is_ok());
    }

    #[test]
    fn validate_socket_ok() {
        assert!(validate("sshd.socket").is_ok());
    }

    #[test]
    fn validate_target_ok() {
        assert!(validate("multi-user.target").is_ok());
    }

    #[test]
    fn validate_at_sign_ok() {
        assert!(validate("user@1000.service").is_ok());
    }

    #[test]
    fn validate_empty_err() {
        assert!(validate("").is_err());
    }

    #[test]
    fn validate_too_long_err() {
        assert!(validate(&"x".repeat(257)).is_err());
    }

    /// A Windows SCM name — valid at the generic API layer, but rejected by
    /// systemd rules because `$` is outside the `[A-Za-z0-9._@-]` charset.
    #[test]
    fn validate_dollar_sign_err() {
        assert!(validate("MSSQL$SQLEXPRESS").is_err());
    }
}
