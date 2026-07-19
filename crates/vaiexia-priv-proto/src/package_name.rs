use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageName(String);

// Custom `Deserialize` that funnels every deserialized value through `parse`.
//
// SECURITY: a `#[derive(Deserialize)]` on the tuple struct would accept ANY
// JSON string and wrap it verbatim, bypassing the charset/length/leading-dash
// checks. That would let a hostile RPC peer smuggle a name like `-rf` or
// `--config=…` past the newtype's invariant. Deserializing through `parse`
// keeps "a `PackageName` value is always valid" true no matter how it was
// constructed (literal, serde frame, or otherwise).
impl<'de> Deserialize<'de> for PackageName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PackageName::parse(s).map_err(serde::de::Error::custom)
    }
}

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

    // ── serde validation bypass regression tests ──────────────────────────────
    //
    // The newtype MUST NOT be deserializable around its `parse` validator.
    // A crafted JSON string that would be rejected by `parse` must also be
    // rejected by serde deserialization.

    #[test]
    fn deserialize_valid_name_ok() {
        let pn: PackageName = serde_json::from_str("\"nginx\"").expect("valid name");
        assert_eq!(pn.as_str(), "nginx");
    }

    #[test]
    fn deserialize_rejects_leading_dash() {
        // Without a custom Deserialize this would happily produce PackageName("-rf").
        let r: Result<PackageName, _> = serde_json::from_str("\"-rf\"");
        assert!(r.is_err(), "leading-dash name must not deserialize");
    }

    #[test]
    fn deserialize_rejects_flag_lookalike() {
        let r: Result<PackageName, _> = serde_json::from_str("\"--config=/etc/evil\"");
        assert!(r.is_err(), "flag-lookalike name must not deserialize");
    }

    #[test]
    fn deserialize_rejects_space_and_metachars() {
        assert!(serde_json::from_str::<PackageName>("\"a b\"").is_err());
        assert!(serde_json::from_str::<PackageName>("\"foo;rm -rf /\"").is_err());
        assert!(serde_json::from_str::<PackageName>("\"foo/../bar\"").is_err());
        assert!(serde_json::from_str::<PackageName>("\"$(id)\"").is_err());
    }

    #[test]
    fn deserialize_rejects_empty_and_oversized() {
        assert!(serde_json::from_str::<PackageName>("\"\"").is_err());
        let big = format!("\"{}\"", "x".repeat(129));
        assert!(serde_json::from_str::<PackageName>(&big).is_err());
    }

    #[test]
    fn serialize_then_deserialize_roundtrips() {
        let pn = PackageName::parse("lib.foo_bar+baz-1.2").unwrap();
        let s = serde_json::to_string(&pn).unwrap();
        let back: PackageName = serde_json::from_str(&s).unwrap();
        assert_eq!(pn, back);
    }
}
