use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageName(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid package name")]
pub struct InvalidPackageName;

impl PackageName {
    pub fn parse(s: impl Into<String>) -> Result<Self, InvalidPackageName> {
        let s = s.into();
        let ok = !s.is_empty()
            && s.len() <= 128
            && !s.starts_with('-')
            && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-'));
        if ok { Ok(Self(s)) } else { Err(InvalidPackageName) }
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_simple_name() {
        assert!(PackageName::parse("nginx").is_ok());
    }

    #[test]
    fn valid_complex_name() {
        assert!(PackageName::parse("lib.foo_bar+baz-1.2").is_ok());
    }

    #[test]
    fn rejects_leading_dash() {
        assert_eq!(PackageName::parse("-rf"), Err(InvalidPackageName));
    }

    #[test]
    fn rejects_space() {
        assert_eq!(PackageName::parse("a b"), Err(InvalidPackageName));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(PackageName::parse(""), Err(InvalidPackageName));
    }

    #[test]
    fn rejects_too_long() {
        assert_eq!(PackageName::parse("x".repeat(129)), Err(InvalidPackageName));
    }

    #[test]
    fn accepts_exactly_128_chars() {
        assert!(PackageName::parse("x".repeat(128)).is_ok());
    }

    #[test]
    fn rejects_uppercase() {
        assert_eq!(PackageName::parse("Nginx"), Err(InvalidPackageName));
    }

    #[test]
    fn rejects_invalid_charset() {
        assert_eq!(PackageName::parse("foo@bar"), Err(InvalidPackageName));
        assert_eq!(PackageName::parse("foo/bar"), Err(InvalidPackageName));
    }
}
