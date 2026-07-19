//! Portable helpers for systemd unit names and D-Bus active-state mapping.
//! Compiled on ALL platforms; unit-tested cross-platform.

use crate::backend::{ServiceState, UnitName};
use crate::backend::unit_name::InvalidUnitName;

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

/// Validate a unit name using the `UnitName` newtype, returning `Err(InvalidUnitName)` on failure.
pub fn validate(s: &str) -> Result<UnitName, InvalidUnitName> {
    UnitName::parse(s)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ServiceState;

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
}
