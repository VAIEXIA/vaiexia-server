use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use vaiexia_core::auth::Capability;

use crate::auth::password::hash_password;
use crate::auth::store::{AccountRecord, CapabilityRecord, IdentityStore, now_secs};
use crate::auth::token;

// ── Constants ──────────────────────────────────────────────────────────────────

/// Admin scopes granted on first-run claim.
pub const ADMIN_SCOPES: &[&str] = &[
    "server.read",
    "server.logs.read",
    "server.services.write",
    "server.packages.write",
    "auth.admin",
];

/// Maximum failed attempts before regenerating the bootstrap code.
const MAX_ATTEMPTS: u32 = 5;

/// Default TTL for the bootstrap window (30 minutes).
const DEFAULT_TTL_SECS: u64 = 30 * 60;

// ── Error / Result ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("bootstrap is disabled (store already has accounts/capabilities)")]
    Disabled,
    #[error("incorrect bootstrap code")]
    BadCode,
    #[error("too many failed attempts; bootstrap code regenerated — check the log for the new path")]
    RateLimited,
    #[error("store error: {0}")]
    StoreError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("password error: {0}")]
    Password(String),
}

// ── ClaimResult ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ClaimResult {
    pub capability: Capability,
    pub subject_id: String,
    pub scopes: Vec<String>,
}

// ── BootstrapState ────────────────────────────────────────────────────────────

/// Clock abstraction for testing.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

struct SystemClock;
impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        now_secs()
    }
}

pub enum BootstrapState {
    /// First-run bootstrap is active.
    Active {
        /// Path to the file holding the bootstrap code.
        code_path: PathBuf,
        /// The actual code (kept in memory for constant-time comparison).
        code: String,
        /// Number of failed attempts since last code generation.
        attempts: u32,
        /// Timestamp (seconds) when this code was generated.
        window_start: u64,
        /// TTL in seconds for the bootstrap window.
        ttl_secs: u64,
        /// Clock (injectable for tests).
        clock: Box<dyn Clock>,
    },
    /// Bootstrap has been claimed or the store was not empty on startup.
    Disabled,
}

impl BootstrapState {
    /// Initialise bootstrap state.
    ///
    /// If the store is empty, generates a random 32-byte code, encodes it as
    /// base32, writes it to `code_path` at mode 0600, and returns `Active`.
    /// Logs the *path* (never the code).
    ///
    /// If the store already has data, returns `Disabled`.
    pub fn begin(store_is_empty: bool, code_path: PathBuf) -> Self {
        if !store_is_empty {
            return Self::Disabled;
        }
        let clock = Box::new(SystemClock);
        let window_start = clock.now_secs();
        let code = generate_code();
        match write_code(&code_path, &code) {
            Ok(()) => {
                tracing::info!(
                    path = %code_path.display(),
                    "bootstrap code written — read it to claim admin access"
                );
            }
            Err(e) => {
                tracing::error!(
                    path = %code_path.display(),
                    err = %e,
                    "failed to write bootstrap code file"
                );
            }
        }
        Self::Active {
            code_path,
            code,
            attempts: 0,
            window_start,
            ttl_secs: DEFAULT_TTL_SECS,
            clock,
        }
    }

    /// Test-only constructor that accepts an injectable clock.
    #[cfg(test)]
    pub fn begin_with_clock(
        store_is_empty: bool,
        code_path: PathBuf,
        clock: Box<dyn Clock>,
        ttl_secs: u64,
    ) -> Self {
        if !store_is_empty {
            return Self::Disabled;
        }
        let window_start = clock.now_secs();
        let code = generate_code();
        let _ = write_code(&code_path, &code);
        Self::Active {
            code_path,
            code,
            attempts: 0,
            window_start,
            ttl_secs,
            clock,
        }
    }

    /// Attempt to claim the bootstrap.
    ///
    /// On success:
    /// - Adds admin account + first capability to `store`.
    /// - Deletes the code file.
    /// - Transitions self to `Disabled`.
    /// - Returns `Ok(ClaimResult)` with the raw capability string.
    ///
    /// On failure:
    /// - Increments attempt counter.
    /// - At `MAX_ATTEMPTS`, regenerates the code and returns `RateLimited`.
    pub fn claim(
        &mut self,
        code: &str,
        admin_name: &str,
        password: &str,
        store: &Arc<dyn IdentityStore>,
    ) -> Result<ClaimResult, BootstrapError> {
        let (code_path_owned, stored_code, _attempts, _window_start, _ttl_secs) = match self {
            Self::Disabled => return Err(BootstrapError::Disabled),
            Self::Active {
                code_path,
                code: stored_code,
                attempts,
                window_start,
                ttl_secs,
                clock,
            } => {
                // TTL check
                let elapsed = clock.now_secs().saturating_sub(*window_start);
                if elapsed >= *ttl_secs {
                    // Regenerate on expiry.
                    let new_code = generate_code();
                    let _ = write_code(code_path, &new_code);
                    *stored_code = new_code;
                    *attempts = 0;
                    *window_start = clock.now_secs();
                    tracing::info!(
                        path = %code_path.display(),
                        "bootstrap code expired and regenerated"
                    );
                }
                (code_path.clone(), stored_code.clone(), attempts, window_start, ttl_secs)
            }
        };

        // Constant-time comparison.
        let code_matches = constant_time_eq(code.as_bytes(), stored_code.as_bytes());

        if !code_matches {
            // Increment attempt counter.
            if let Self::Active { attempts, code_path, code: stored_code, window_start, clock, .. } = self {
                *attempts += 1;
                if *attempts >= MAX_ATTEMPTS {
                    // Regenerate code.
                    let new_code = generate_code();
                    let _ = write_code(code_path, &new_code);
                    *stored_code = new_code;
                    *attempts = 0;
                    *window_start = clock.now_secs();
                    tracing::warn!(
                        path = %code_path.display(),
                        "too many bootstrap attempts; code regenerated"
                    );
                    return Err(BootstrapError::RateLimited);
                }
            }
            return Err(BootstrapError::BadCode);
        }

        // Success path.
        let subject_id = format!("user:{}", admin_name);
        let scopes: Vec<String> = ADMIN_SCOPES.iter().map(|s| s.to_string()).collect();

        // Hash password.
        let phc = hash_password(password).map_err(|e| BootstrapError::Password(e.to_string()))?;

        // Add account.
        store
            .add_account(AccountRecord {
                name: admin_name.to_string(),
                password_phc: phc,
                subject_id: subject_id.clone(),
                scopes: scopes.clone(),
            })
            .map_err(|e| BootstrapError::StoreError(e.to_string()))?;

        // Mint capability.
        let minted = token::mint();
        store
            .add_capability(CapabilityRecord {
                key_id: minted.key_id.clone(),
                secret_hash: minted.secret_hash,
                subject_id: subject_id.clone(),
                scopes: scopes.clone(),
                label: format!("bootstrap-{}", admin_name),
                created_at: now_secs(),
                expires_at: None,
                revoked: false,
                last_used: None,
            })
            .map_err(|e| BootstrapError::StoreError(e.to_string()))?;

        // Delete code file — best-effort.
        let _ = fs::remove_file(&code_path_owned);

        // Transition to Disabled.
        *self = Self::Disabled;

        tracing::info!(subject_id = %subject_id, "bootstrap claimed successfully");

        Ok(ClaimResult {
            capability: minted.capability,
            subject_id,
            scopes,
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a 32-byte random code encoded as lowercase base32 (no padding).
fn generate_code() -> String {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).expect("os rng");
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &raw)
}

/// Write `code` to `path` with mode 0600 (best-effort on Windows).
fn write_code(path: &Path, code: &str) -> std::io::Result<()> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let mut f = opts.open(path)?;
    set_file_mode_0600(&f)?;
    f.write_all(code.as_bytes())?;
    f.flush()?;
    Ok(())
}

#[cfg(unix)]
fn set_file_mode_0600(f: &fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0600(_f: &fs::File) -> std::io::Result<()> {
    Ok(())
}

/// Constant-time byte-slice comparison (zero-padded to the longer length).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    // Pad to equal length to avoid length-based timing leaks.
    let max_len = a.len().max(b.len());
    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);
    a_padded.ct_eq(&b_padded).into()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::auth::store::{FileStore, IdentityStore};

    struct FakeClock {
        secs: std::sync::atomic::AtomicU64,
    }
    impl FakeClock {
        fn new(t: u64) -> Self { Self { secs: t.into() } }
        fn advance(&self, by: u64) {
            self.secs.fetch_add(by, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Clock for FakeClock {
        fn now_secs(&self) -> u64 { self.secs.load(std::sync::atomic::Ordering::SeqCst) }
    }

    // We can't easily inject the Arc<FakeClock> into begin_with_clock because
    // Box<dyn Clock> is not Clone.  Use a helper that wraps raw ptr.
    struct SharedFakeClock(Arc<FakeClock>);
    impl Clock for SharedFakeClock {
        fn now_secs(&self) -> u64 { self.0.now_secs() }
    }

    fn temp_store_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "vaiexia-boot-store-{}-{}.json",
            suffix,
            now_secs()
        ));
        p
    }

    fn temp_code_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vaiexia-boot-code-{}-{}", suffix, now_secs()));
        p
    }

    fn make_store(path: &PathBuf) -> Arc<dyn IdentityStore> {
        Arc::new(FileStore::open(path).unwrap()) as Arc<dyn IdentityStore>
    }

    #[test]
    fn begin_on_empty_store_creates_active_state_and_writes_file() {
        let store_path = temp_store_path("begin-empty");
        let code_path = temp_code_path("begin-empty");
        let store = make_store(&store_path);
        assert!(store.is_empty());
        let state = BootstrapState::begin(store.is_empty(), code_path.clone());
        assert!(matches!(state, BootstrapState::Active { .. }));
        assert!(code_path.exists(), "code file should have been created");
        let content = fs::read_to_string(&code_path).unwrap();
        assert!(!content.is_empty());
        let _ = fs::remove_file(&code_path);
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn begin_on_nonempty_store_returns_disabled() {
        let store_path = temp_store_path("begin-nonempty");
        let code_path = temp_code_path("begin-nonempty");
        let store = make_store(&store_path);
        // Seed store so is_empty() == false
        store.add_account(AccountRecord {
            name: "admin".into(),
            password_phc: "$argon2id$placeholder".into(),
            subject_id: "user:admin".into(),
            scopes: vec!["auth.admin".into()],
        }).unwrap();
        let state = BootstrapState::begin(store.is_empty(), code_path.clone());
        // is_empty() == false → disabled path
        assert!(matches!(state, BootstrapState::Disabled));
        assert!(!code_path.exists(), "code file must NOT be created when disabled");
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn claim_succeeds_with_correct_code() {
        let store_path = temp_store_path("claim-ok");
        let code_path = temp_code_path("claim-ok");
        let store = make_store(&store_path);
        let clock = Arc::new(FakeClock::new(1000));
        let mut state = BootstrapState::begin_with_clock(
            true, code_path.clone(),
            Box::new(SharedFakeClock(Arc::clone(&clock))), DEFAULT_TTL_SECS,
        );
        let code = fs::read_to_string(&code_path).unwrap();
        let result = state.claim(&code, "admin", "hunter2", &store).unwrap();
        assert!(!result.capability.reveal().is_empty());
        assert_eq!(result.subject_id, "user:admin");
        assert!(result.scopes.contains(&"auth.admin".to_string()));
        // State must now be Disabled
        assert!(matches!(state, BootstrapState::Disabled));
        // Code file must be deleted
        assert!(!code_path.exists());
        // Store must have the account
        let snap = store.snapshot();
        assert!(snap.lookup_account("admin").is_some());
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn claim_fails_with_wrong_code() {
        let store_path = temp_store_path("claim-bad");
        let code_path = temp_code_path("claim-bad");
        let store = make_store(&store_path);
        let mut state = BootstrapState::begin(true, code_path.clone());
        let err = state.claim("wrong-code-here", "admin", "pass", &store).unwrap_err();
        assert!(matches!(err, BootstrapError::BadCode));
        let _ = fs::remove_file(&code_path);
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn claim_returns_disabled_when_already_claimed() {
        let mut state = BootstrapState::Disabled;
        let store_path = temp_store_path("disabled");
        let store = make_store(&store_path);
        let err = state.claim("code", "admin", "pass", &store).unwrap_err();
        assert!(matches!(err, BootstrapError::Disabled));
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn claim_rate_limited_after_max_attempts() {
        let store_path = temp_store_path("rate-limit");
        let code_path = temp_code_path("rate-limit");
        let store = make_store(&store_path);
        let mut state = BootstrapState::begin(true, code_path.clone());
        // Exhaust attempts (MAX_ATTEMPTS - 1 BadCode, then RateLimited on 5th)
        for i in 0..MAX_ATTEMPTS - 1 {
            let err = state.claim("wrong", "admin", "pass", &store).unwrap_err();
            assert!(matches!(err, BootstrapError::BadCode), "attempt {i} should be BadCode");
        }
        let err = state.claim("wrong", "admin", "pass", &store).unwrap_err();
        assert!(
            matches!(err, BootstrapError::RateLimited),
            "5th attempt should be RateLimited, got: {err:?}"
        );
        // Code should have been regenerated
        assert!(code_path.exists());
        let _ = fs::remove_file(&code_path);
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn claim_regenerates_on_ttl_expiry() {
        let store_path = temp_store_path("ttl");
        let code_path = temp_code_path("ttl");
        let store = make_store(&store_path);
        let clock = Arc::new(FakeClock::new(1000));
        let mut state = BootstrapState::begin_with_clock(
            true, code_path.clone(),
            Box::new(SharedFakeClock(Arc::clone(&clock))),
            60, // 60-second TTL
        );
        let original_code = fs::read_to_string(&code_path).unwrap();
        // Advance past TTL
        clock.advance(120);
        // Wrong code triggers regeneration via TTL check
        let err = state.claim("any-wrong-code", "admin", "pass", &store).unwrap_err();
        // After TTL expiry, code is regenerated and comparison fails
        assert!(matches!(err, BootstrapError::BadCode));
        let new_code = fs::read_to_string(&code_path).unwrap();
        assert_ne!(original_code, new_code, "code must be regenerated after TTL expiry");
        let _ = fs::remove_file(&code_path);
        let _ = fs::remove_file(&store_path);
    }
}
