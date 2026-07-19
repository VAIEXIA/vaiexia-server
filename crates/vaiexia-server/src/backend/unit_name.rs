use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitName(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid unit name")]
pub struct InvalidUnitName;

const ALLOWED_SUFFIXES: &[&str] = &[
    ".service", ".socket", ".timer", ".target", ".path", ".mount",
];

impl UnitName {
    /// Parse and validate a systemd unit name.
    ///
    /// Allowed charset: `[A-Za-z0-9._@-]`. No `..` path traversal. Length ≤ 256.
    /// Must end in one of the allowed suffixes (.service .socket .timer .target .path .mount)
    /// OR be a bare name (no dot-suffix), which is treated as `.service` semantics.
    pub fn parse(s: impl Into<String>) -> Result<Self, InvalidUnitName> {
        let s = s.into();

        // Length checks
        if s.is_empty() || s.len() > 256 {
            return Err(InvalidUnitName);
        }

        // No path traversal
        if s.contains("..") {
            return Err(InvalidUnitName);
        }

        // Charset: [A-Za-z0-9._@-]
        if !s.bytes().all(|b| {
            matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'@' | b'-')
        }) {
            return Err(InvalidUnitName);
        }

        // Check suffix
        let has_dot = s.contains('.');
        if has_dot {
            // Must have a known suffix
            let has_allowed = ALLOWED_SUFFIXES.iter().any(|suf| s.ends_with(suf));
            if !has_allowed {
                return Err(InvalidUnitName);
            }
        }
        // Bare name (no dot) is allowed — treated as .service semantics

        Ok(UnitName(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nginx_service_ok() {
        assert!(UnitName::parse("nginx.service").is_ok());
    }

    #[test]
    fn parse_sshd_bare_ok() {
        assert!(UnitName::parse("sshd").is_ok());
    }

    #[test]
    fn parse_path_traversal_err() {
        assert_eq!(UnitName::parse("../etc"), Err(InvalidUnitName));
    }

    #[test]
    fn parse_space_err() {
        assert_eq!(UnitName::parse("a b.service"), Err(InvalidUnitName));
    }

    #[test]
    fn parse_timer_ok() {
        assert!(UnitName::parse("x.timer").is_ok());
    }

    #[test]
    fn parse_unknown_suffix_err() {
        assert_eq!(UnitName::parse("x.evil"), Err(InvalidUnitName));
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
}
