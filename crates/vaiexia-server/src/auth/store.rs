// A4 placeholder — implemented below
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ── hex_bytes serde helper ────────────────────────────────────────────────────

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        hex.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s: String = String::deserialize(de)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex chars for [u8;32]"));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]).map_err(serde::de::Error::custom)?;
            let lo = hex_nibble(chunk[1]).map_err(serde::de::Error::custom)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn hex_nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

// ── Records ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRecord {
    pub key_id: String,
    #[serde(with = "hex_bytes")]
    pub secret_hash: [u8; 32],
    pub subject_id: String,
    pub scopes: Vec<String>,
    pub label: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub last_used: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub name: String,
    pub password_phc: String,
    pub subject_id: String,
    pub scopes: Vec<String>,
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct IdentitySnapshot {
    pub capabilities: HashMap<String, CapabilityRecord>,
    pub accounts: HashMap<String, AccountRecord>,
}

impl IdentitySnapshot {
    pub fn lookup_capability(&self, key_id: &str) -> Option<&CapabilityRecord> {
        self.capabilities.get(key_id)
    }

    pub fn lookup_account(&self, name: &str) -> Option<&AccountRecord> {
        self.accounts.get(name)
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

pub trait IdentityStore: Send + Sync {
    fn snapshot(&self) -> Arc<IdentitySnapshot>;
    fn add_capability(&self, record: CapabilityRecord) -> Result<(), StoreError>;
    fn revoke_capability(&self, key_id: &str) -> Result<(), StoreError>;
    fn touch_last_used(&self, key_id: &str) -> Result<(), StoreError>;
    fn add_account(&self, record: AccountRecord) -> Result<(), StoreError>;
    fn is_empty(&self) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialize error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("key not found: {0}")]
    NotFound(String),
}

// ── FileStore ─────────────────────────────────────────────────────────────────

pub struct FileStore {
    path: PathBuf,
    snap: Arc<ArcSwap<IdentitySnapshot>>,
}

impl FileStore {
    /// Open (or create) a store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let snap = if path.exists() {
            let data = fs::read(&path)?;
            let s: IdentitySnapshot = serde_json::from_slice(&data)?;
            s
        } else {
            IdentitySnapshot::default()
        };
        Ok(Self {
            path,
            snap: Arc::new(ArcSwap::from_pointee(snap)),
        })
    }

    fn persist(&self, snap: &IdentitySnapshot) -> Result<(), StoreError> {
        write_atomic(&self.path, snap)
    }

    fn mutate(&self, f: impl FnOnce(&mut IdentitySnapshot)) -> Result<(), StoreError> {
        let current = self.snap.load_full();
        let mut next = (*current).clone();
        f(&mut next);
        let next = Arc::new(next);
        self.persist(&next)?;
        self.snap.store(next);
        Ok(())
    }
}

impl IdentityStore for FileStore {
    fn snapshot(&self) -> Arc<IdentitySnapshot> {
        self.snap.load_full()
    }

    fn add_capability(&self, record: CapabilityRecord) -> Result<(), StoreError> {
        self.mutate(|s| {
            s.capabilities.insert(record.key_id.clone(), record);
        })
    }

    fn revoke_capability(&self, key_id: &str) -> Result<(), StoreError> {
        self.mutate(|s| {
            if let Some(rec) = s.capabilities.get_mut(key_id) {
                rec.revoked = true;
            }
        })
    }

    fn touch_last_used(&self, key_id: &str) -> Result<(), StoreError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.mutate(|s| {
            if let Some(rec) = s.capabilities.get_mut(key_id) {
                rec.last_used = Some(now);
            }
        })
    }

    fn add_account(&self, record: AccountRecord) -> Result<(), StoreError> {
        self.mutate(|s| {
            s.accounts.insert(record.name.clone(), record);
        })
    }

    fn is_empty(&self) -> bool {
        let s = self.snap.load();
        s.capabilities.is_empty() && s.accounts.is_empty()
    }
}

// ── Atomic write ──────────────────────────────────────────────────────────────

fn write_atomic(path: &Path, snap: &IdentitySnapshot) -> Result<(), StoreError> {
    let json = serde_json::to_vec_pretty(snap)?;

    // Write to a temp file in the same directory (so rename is atomic on same fs).
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp_path = dir.join(format!(
        ".identity.tmp.{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));

    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        set_file_mode_0600(&f)?;
        f.write_all(&json)?;
        f.flush()?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_mode_0600(f: &fs::File) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0600(_f: &fs::File) -> Result<(), StoreError> {
    // On Windows, file ACLs are handled differently; skip chmod.
    Ok(())
}

// ── Timestamp helper ──────────────────────────────────────────────────────────

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "vaiexia-store-test-{}.json",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        p
    }

    fn make_cap_record(key_id: &str) -> CapabilityRecord {
        CapabilityRecord {
            key_id: key_id.to_string(),
            secret_hash: [0u8; 32],
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string()],
            label: "test".to_string(),
            created_at: now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        }
    }

    #[test]
    fn snapshot_capability_lookup() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        let rec = make_cap_record("aaaaaaaaaaaaaabb");
        store.add_capability(rec.clone()).unwrap();
        let snap = store.snapshot();
        assert!(snap.lookup_capability("aaaaaaaaaaaaaabb").is_some());
        assert!(snap.lookup_capability("does-not-exist").is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn snapshot_account_lookup() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        let acc = AccountRecord {
            name: "admin".to_string(),
            password_phc: "$argon2id$placeholder".to_string(),
            subject_id: "user:admin".to_string(),
            scopes: vec!["auth.admin".to_string()],
        };
        store.add_account(acc).unwrap();
        let snap = store.snapshot();
        assert!(snap.lookup_account("admin").is_some());
        assert!(snap.lookup_account("nobody").is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_and_load_round_trips() {
        let path = temp_path();
        {
            let store = FileStore::open(&path).unwrap();
            store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
            store.add_account(AccountRecord {
                name: "admin".to_string(),
                password_phc: "phc".to_string(),
                subject_id: "user:admin".to_string(),
                scopes: vec!["auth.admin".to_string()],
            }).unwrap();
        }
        // Re-open from disk
        let store2 = FileStore::open(&path).unwrap();
        let snap = store2.snapshot();
        assert!(snap.lookup_capability("aaaaaaaaaaaaaabb").is_some());
        assert!(snap.lookup_account("admin").is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn revoke_capability_marks_revoked() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
        store.revoke_capability("aaaaaaaaaaaaaabb").unwrap();
        let snap = store.snapshot();
        let rec = snap.lookup_capability("aaaaaaaaaaaaaabb").unwrap();
        assert!(rec.revoked, "capability must be marked revoked");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn is_empty_true_on_fresh_store() {
        let path = temp_path();
        // Don't write the file — simulate fresh
        let store = FileStore::open(&path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn is_empty_false_after_add() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
        assert!(!store.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn mutations_swap_and_persist() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
        // Revoke
        store.revoke_capability("aaaaaaaaaaaaaabb").unwrap();
        // Re-open from disk to verify persistence
        let store2 = FileStore::open(&path).unwrap();
        let snap = store2.snapshot();
        assert!(snap.lookup_capability("aaaaaaaaaaaaaabb").unwrap().revoked);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn touch_last_used_updates_timestamp() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
        store.touch_last_used("aaaaaaaaaaaaaabb").unwrap();
        let snap = store.snapshot();
        let rec = snap.lookup_capability("aaaaaaaaaaaaaabb").unwrap();
        assert!(rec.last_used.is_some());
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_is_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "file must be 0600");
        let _ = fs::remove_file(&path);
    }
}
