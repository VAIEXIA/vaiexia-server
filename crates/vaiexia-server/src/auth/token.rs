use base64::Engine as _;
use subtle::ConstantTimeEq;
use vaiexia_core::auth::Capability;

pub const CAP_PREFIX: &str = "vxs1";

pub struct MintedCapability {
    pub capability: Capability,
    pub key_id: String,
    pub secret_hash: [u8; 32],
}

pub fn mint() -> MintedCapability {
    // 10 bytes → 16 base32 chars (10 * 8 bits / 5 bits-per-char = 16, no padding needed)
    let mut key_id_raw = [0u8; 10];
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut key_id_raw).expect("os rng");
    getrandom::getrandom(&mut secret).expect("os rng");
    let key_id = base32::encode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        &key_id_raw,
    ); // 16 chars
    let secret_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    let token = format!("{CAP_PREFIX}.{key_id}.{secret_b64}");
    let secret_hash = *blake3::hash(&secret).as_bytes();
    MintedCapability {
        capability: Capability::new(token),
        key_id,
        secret_hash,
    }
}

/// Returns `(key_id, secret_bytes)`. Returns `None` on any malformed input
/// (panic-free on arbitrary/hostile input).
pub fn parse(cap: &Capability) -> Option<(String, Vec<u8>)> {
    let s = cap.reveal();
    let mut it = s.splitn(3, '.');
    if it.next()? != CAP_PREFIX {
        return None;
    }
    let key_id = it.next()?.to_string();
    let secret_b64 = it.next()?;
    if key_id.len() != 16
        || !key_id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return None;
    }
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret_b64)
        .ok()?;
    if secret.len() != 32 {
        return None;
    }
    Some((key_id, secret))
}

pub fn hash_secret(secret: &[u8]) -> [u8; 32] {
    *blake3::hash(secret).as_bytes()
}

pub fn verify_secret(presented: &[u8], stored_hash: &[u8; 32]) -> bool {
    hash_secret(presented).ct_eq(stored_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_produces_correct_format() {
        let m = mint();
        let raw = m.capability.reveal();
        // Must match vxs1.<16-char-base32>.<base64url-44-char-no-pad>
        let parts: Vec<&str> = raw.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], CAP_PREFIX);
        assert_eq!(parts[1].len(), 16);
        assert!(
            parts[1]
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')),
            "key_id must be lowercase base32"
        );
        // 32-byte secret → 43 chars base64url no-pad
        assert_eq!(parts[2].len(), 43);
        assert_eq!(m.key_id.len(), 16);
    }

    #[test]
    fn parse_recovers_key_id_and_secret() {
        let m = mint();
        let parsed = parse(&m.capability).expect("parse should succeed on minted cap");
        assert_eq!(parsed.0, m.key_id);
        assert_eq!(parsed.1.len(), 32);
    }

    #[test]
    fn parse_returns_none_on_garbage() {
        assert!(parse(&Capability::new("garbage")).is_none());
        assert!(parse(&Capability::new("vxs1.x")).is_none());
        assert!(parse(&Capability::new("wrong.prefix.stuff")).is_none());
        assert!(parse(&Capability::new("")).is_none());
        // valid prefix but key_id too short
        assert!(parse(&Capability::new("vxs1.abc.secret")).is_none());
    }

    #[test]
    fn parse_returns_none_on_invalid_key_id_chars() {
        // key_id with uppercase chars — not valid base32lower
        let bad = format!("vxs1.AAAAAAAAAAAAAAAA.{}", "A".repeat(43));
        assert!(parse(&Capability::new(bad)).is_none());
    }

    #[test]
    fn hash_secret_matches_mint_secret_hash() {
        let m = mint();
        // recover the raw secret bytes from the capability
        let (_, secret_bytes) = parse(&m.capability).unwrap();
        let computed = hash_secret(&secret_bytes);
        assert_eq!(computed, m.secret_hash);
    }

    #[test]
    fn hash_secret_different_for_different_inputs() {
        let h1 = hash_secret(b"secret1");
        let h2 = hash_secret(b"secret2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_secret_true_for_matching_secret() {
        let m = mint();
        let (_, secret_bytes) = parse(&m.capability).unwrap();
        assert!(verify_secret(&secret_bytes, &m.secret_hash));
    }

    #[test]
    fn verify_secret_false_for_different_secret() {
        let m = mint();
        let mut bad_secret = [0u8; 32];
        bad_secret[0] = 0xFF;
        let (_, mut secret_bytes) = parse(&m.capability).unwrap();
        // flip one byte
        secret_bytes[0] ^= 0xFF;
        assert!(!verify_secret(&secret_bytes, &m.secret_hash));
    }

    #[test]
    fn verify_secret_uses_constant_time_compare() {
        // Structural check: verify_secret uses hash_secret + ct_eq, not direct byte compare.
        // The implementation guarantees: compute hash of presented, then ct_eq with stored.
        // We verify false-on-1-byte-difference:
        let m = mint();
        let (_, mut secret_bytes) = parse(&m.capability).unwrap();
        // 1-byte difference in last position
        let last = secret_bytes.len() - 1;
        secret_bytes[last] ^= 1;
        assert!(
            !verify_secret(&secret_bytes, &m.secret_hash),
            "1-byte-different secret must not verify"
        );
    }
}
