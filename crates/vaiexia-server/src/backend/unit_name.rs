use serde::{Deserialize, Serialize};

/// A platform-neutral service name.
///
/// Enforces hygiene that applies to ANY backend (systemd, Windows SCM, etc.):
/// - Non-empty, length ≤ 256 bytes.
/// - No NUL, control characters (bytes 0x00–0x1F, 0x7F).
/// - No path separators (`/` or `\`).
///
/// Systemd-specific rules (charset `[A-Za-z0-9._@-]`, known suffixes) live
/// in `backend::systemd::unit::SystemdUnitName` and are applied at the
/// systemd-backend boundary — not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitName(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid service name")]
pub struct InvalidUnitName;

impl UnitName {
    /// Parse and validate a platform-neutral service name.
    ///
    /// Rejects: empty, length > 256, NUL, control chars (0x00–0x1F, 0x7F),
    /// forward slash `/`, back slash `\`.
    ///
    /// Accepts names valid on any platform, e.g. `MSSQL$SQLEXPRESS`.
    pub fn parse(s: impl Into<String>) -> Result<Self, InvalidUnitName> {
        let s = s.into();

        // Length checks
        if s.is_empty() || s.len() > 256 {
            return Err(InvalidUnitName);
        }

        // No path separators or NUL / control chars
        if s.bytes().any(|b| {
            matches!(b, 0x00..=0x1F | 0x7F | b'/' | b'\\')
        }) {
            return Err(InvalidUnitName);
        }

        Ok(UnitName(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic sanity ─────────────────────────────────────────────────────────

    #[test]
    fn parse_nginx_service_ok() {
        assert!(UnitName::parse("nginx.service").is_ok());
    }

    #[test]
    fn parse_sshd_bare_ok() {
        assert!(UnitName::parse("sshd").is_ok());
    }

    #[test]
    fn parse_timer_ok() {
        assert!(UnitName::parse("x.timer").is_ok());
    }

    #[test]
    fn parse_socket_ok() {
        assert!(UnitName::parse("sshd.socket").is_ok());
    }

    #[test]
    fn parse_target_ok() {
        assert!(UnitName::parse("multi-user.target").is_ok());
    }

    #[test]
    fn parse_at_sign_ok() {
        assert!(UnitName::parse("user@1000.service").is_ok());
    }

    // ── Cross-platform names now accepted ────────────────────────────────────

    /// A Windows SCM name with `$` — valid on any platform but rejected by
    /// systemd charset rules. The generic API layer must accept it.
    #[test]
    fn parse_windows_scm_dollar_sign_ok() {
        assert!(UnitName::parse("MSSQL$SQLEXPRESS").is_ok());
    }

    #[test]
    fn parse_unknown_suffix_ok() {
        // `.evil` suffix is not a systemd thing, but the generic layer doesn't care.
        assert!(UnitName::parse("x.evil").is_ok());
    }

    // ── Hygiene rejections (must still hold) ────────────────────────────────

    #[test]
    fn parse_path_traversal_with_slash_err() {
        // Contains '/' — rejected by path-separator rule.
        assert_eq!(UnitName::parse("../etc"), Err(InvalidUnitName));
    }

    #[test]
    fn parse_backslash_err() {
        assert_eq!(UnitName::parse("foo\\bar"), Err(InvalidUnitName));
    }

    // Space (0x20) is above the control-char range (0x00–0x1F) so the generic
    // hygiene layer accepts it. The systemd backend will reject it via
    // SystemdUnitName (space is outside `[A-Za-z0-9._@-]`).
    #[test]
    fn parse_space_passes_generic_hygiene() {
        assert!(UnitName::parse("a b.service").is_ok());
    }

    #[test]
    fn parse_empty_err() {
        assert_eq!(UnitName::parse(""), Err(InvalidUnitName));
    }

    #[test]
    fn parse_too_long_err() {
        assert_eq!(UnitName::parse("x".repeat(257)), Err(InvalidUnitName));
    }

    #[test]
    fn parse_nul_byte_err() {
        assert_eq!(UnitName::parse("foo\x00bar"), Err(InvalidUnitName));
    }

    #[test]
    fn parse_control_char_err() {
        assert_eq!(UnitName::parse("foo\x01bar"), Err(InvalidUnitName));
    }

    #[test]
    fn parse_slash_err() {
        assert_eq!(UnitName::parse("foo/bar"), Err(InvalidUnitName));
    }
}
