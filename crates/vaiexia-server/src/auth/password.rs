use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

/// Current argon2id parameters: m=65536 KiB (64 MiB), t=3, p=1.
const M_COST: u32 = 65536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

fn argon2() -> Argon2<'static> {
    let params = Params::new(M_COST, T_COST, P_COST, None)
        .expect("argon2 params are valid constants");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password hash error: {0}")]
    Hash(String),
    #[error("malformed PHC string: {0}")]
    Malformed(String),
}

/// Hash a plaintext password, returning a PHC string (e.g. `$argon2id$...`).
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    // Generate 16 random bytes via getrandom and encode as a SaltString.
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).expect("os rng");
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| PasswordError::Hash(e.to_string()))?;
    let hash = argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC string.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, `Err` on malformed PHC.
pub fn verify_password(password: &str, phc: &str) -> Result<bool, PasswordError> {
    let hash = PasswordHash::new(phc).map_err(|e| PasswordError::Malformed(e.to_string()))?;
    match argon2().verify_password(password.as_bytes(), &hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::Hash(e.to_string())),
    }
}

/// Returns `true` if the stored PHC was created with different (older) parameters
/// and should be re-hashed on the next successful login.
pub fn needs_rehash(phc: &str) -> bool {
    let Ok(hash) = PasswordHash::new(phc) else {
        return true; // malformed → must rehash
    };
    // Check algorithm
    if hash.algorithm.as_str() != "argon2id" {
        return true;
    }
    // Extract the embedded params via the Argon2 type's extract method.
    // `PasswordHash::params` is a `ParamsString`; we convert it through Argon2's
    // `PasswordHasher` trait to get back a typed `Params`.
    let embedded = match argon2::Params::try_from(&hash) {
        Ok(p) => p,
        Err(_) => return true,
    };
    embedded.m_cost() != M_COST
        || embedded.t_cost() != T_COST
        || embedded.p_cost() != P_COST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_argon2id_phc_string() {
        let phc = hash_password("hunter2").unwrap();
        assert!(phc.starts_with("$argon2id$"), "PHC must start with $argon2id$");
    }

    #[test]
    fn verify_correct_password_returns_true() {
        let phc = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &phc).unwrap());
    }

    #[test]
    fn verify_wrong_password_returns_false() {
        let phc = hash_password("hunter2").unwrap();
        assert!(!verify_password("wrongpassword", &phc).unwrap());
    }

    #[test]
    fn verify_malformed_phc_returns_err() {
        let result = verify_password("anything", "not-a-valid-phc");
        assert!(result.is_err(), "malformed PHC must return Err");
    }

    #[test]
    fn needs_rehash_false_for_current_params() {
        let phc = hash_password("password").unwrap();
        assert!(
            !needs_rehash(&phc),
            "freshly hashed password should not need rehash"
        );
    }

    #[test]
    fn needs_rehash_true_for_different_params() {
        // Construct a PHC with different memory cost (lower than current)
        let old_params = Params::new(8192, 1, 1, None).unwrap();
        let old_argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, old_params);
        let mut salt_bytes = [0u8; 16];
        getrandom::getrandom(&mut salt_bytes).unwrap();
        let salt = argon2::password_hash::SaltString::encode_b64(&salt_bytes).unwrap();
        let old_phc = old_argon2
            .hash_password(b"password", &salt)
            .unwrap()
            .to_string();
        assert!(
            needs_rehash(&old_phc),
            "old-params PHC should need rehash"
        );
    }

    #[test]
    fn different_hashes_for_same_password() {
        // Salts should differ → different PHC strings
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        assert_ne!(h1, h2, "different salts must produce different PHCs");
    }
}
