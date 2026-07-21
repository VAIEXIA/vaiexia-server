// A4 placeholder — implemented below
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
    /// Buffer the `last_used` timestamp for `key_id`. MUST NOT write to disk
    /// (hot-path guarantee: one call per authenticated request). The persister
    /// task periodically calls [`flush_last_used`] to commit the buffer.
    fn touch_last_used(&self, key_id: &str) -> Result<(), StoreError>;
    /// Apply buffered `touch_last_used` timestamps to the snapshot and disk.
    /// Returns the number of records updated. A no-op MUST NOT persist.
    fn flush_last_used(&self) -> Result<usize, StoreError>;
    /// Remove revoked capabilities and capabilities expired for longer than
    /// `grace_secs`. Returns the number removed. A no-op MUST NOT persist.
    fn prune_capabilities(&self, now_secs: u64, grace_secs: u64) -> Result<usize, StoreError>;
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
    /// Serializes read-modify-write mutations so concurrent mutators cannot
    /// clobber each other (e.g. a `touch_last_used` racing a `revoke_capability`
    /// and silently un-revoking a token). Reads via `snapshot()` stay lock-free.
    write_lock: Mutex<()>,
    /// Buffered last_used timestamps: key_id → unix-secs. Written by
    /// `touch_last_used` (hot path — no disk I/O), flushed periodically by the
    /// persister task via `flush_last_used`.
    pending_touch: Mutex<HashMap<String, u64>>,
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
            write_lock: Mutex::new(()),
            pending_touch: Mutex::new(HashMap::new()),
        })
    }

    fn persist(&self, snap: &IdentitySnapshot) -> Result<(), StoreError> {
        write_atomic(&self.path, snap)
    }

    /// Read-modify-write against the current snapshot, persist, then publish.
    ///
    /// The whole cycle is serialized by `write_lock`, so two concurrent
    /// mutations can never both branch off the same base snapshot and drop one
    /// another's change (lost-update). `f` may signal failure by returning
    /// `Err`, in which case neither disk nor the in-memory snapshot is touched.
    fn mutate<F>(&self, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(&mut IdentitySnapshot) -> Result<(), StoreError>,
    {
        // Held across load→apply→persist→store to serialize writers. Recover
        // from a poisoned lock rather than propagating the panic.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.snap.load_full();
        let mut next = (*current).clone();
        f(&mut next)?;
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
            Ok(())
        })
    }

    fn revoke_capability(&self, key_id: &str) -> Result<(), StoreError> {
        self.mutate(|s| match s.capabilities.get_mut(key_id) {
            Some(rec) => {
                rec.revoked = true;
                Ok(())
            }
            // Fail closed & honest: revoking an unknown key is NOT a silent
            // success (the handler maps this to NOT_FOUND).
            None => Err(StoreError::NotFound(key_id.to_string())),
        })
    }

    fn touch_last_used(&self, key_id: &str) -> Result<(), StoreError> {
        // Hot-path guarantee: buffer only, zero disk I/O. The persister task
        // calls `flush_last_used` periodically to commit touches to disk.
        self.pending_touch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key_id.to_string(), now_secs());
        Ok(())
    }

    fn flush_last_used(&self) -> Result<usize, StoreError> {
        let pending: HashMap<String, u64> = {
            let mut guard = self.pending_touch.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let mut updated = 0usize;
        self.mutate(|s| {
            for (key, ts) in &pending {
                if let Some(rec) = s.capabilities.get_mut(key) {
                    rec.last_used = Some(*ts);
                    updated += 1;
                }
                // Key absent = already pruned; silently ignore (not an error).
            }
            Ok(())
        })?;
        Ok(updated)
    }

    fn prune_capabilities(&self, now: u64, grace: u64) -> Result<usize, StoreError> {
        let removable = |rec: &CapabilityRecord| {
            rec.revoked || rec.expires_at.is_some_and(|e| now >= e.saturating_add(grace))
        };
        // Cheap pre-scan on the lock-free snapshot: the common case (nothing to
        // prune) takes no lock and writes nothing.
        if !self.snap.load().capabilities.values().any(removable) {
            return Ok(0);
        }
        let mut removed = 0usize;
        self.mutate(|s| {
            let before = s.capabilities.len();
            s.capabilities.retain(|_, rec| !removable(rec));
            removed = before - s.capabilities.len();
            Ok(())
        })?;
        // Drop pending touches for pruned keys so a later flush can't resurrect them.
        self.pending_touch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| self.snap.load().capabilities.contains_key(k));
        Ok(removed)
    }

    fn add_account(&self, record: AccountRecord) -> Result<(), StoreError> {
        self.mutate(|s| {
            s.accounts.insert(record.name.clone(), record);
            Ok(())
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
        store.flush_last_used().unwrap();
        let snap = store.snapshot();
        let rec = snap.lookup_capability("aaaaaaaaaaaaaabb").unwrap();
        assert!(rec.last_used.is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn revoke_unknown_key_returns_not_found() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        let err = store.revoke_capability("nope").unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
        let _ = fs::remove_file(&path);
    }

    /// Concurrent mutations must not drop one another (lost-update).
    ///
    /// Without serialization of the read-modify-write cycle, many of these
    /// distinct inserts would branch off the same base snapshot and clobber
    /// each other, leaving far fewer than `N` capabilities behind.
    #[test]
    fn concurrent_add_capability_no_lost_updates() {
        use std::sync::Arc;
        use std::thread;

        let path = temp_path();
        let store = Arc::new(FileStore::open(&path).unwrap());
        const N: usize = 64;
        let mut handles = Vec::new();
        for i in 0..N {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                // 16-char base32-ish unique key_id.
                let key = format!("k{i:015}");
                store.add_capability(make_cap_record(&key)).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let snap = store.snapshot();
        assert_eq!(
            snap.capabilities.len(),
            N,
            "every concurrent add_capability must survive (no lost updates)"
        );
        let _ = fs::remove_file(&path);
    }

    /// A `touch_last_used` racing a `revoke_capability` must never un-revoke.
    #[test]
    fn concurrent_touch_does_not_clobber_revoke() {
        use std::sync::Arc;
        use std::thread;

        let path = temp_path();
        let store = Arc::new(FileStore::open(&path).unwrap());
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    let _ = store.touch_last_used("aaaaaaaaaaaaaabb");
                }
            }));
        }
        // Revoke concurrently with the touch storm.
        {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store.revoke_capability("aaaaaaaaaaaaaabb").unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        store.flush_last_used().unwrap();
        let snap = store.snapshot();
        assert!(
            snap.lookup_capability("aaaaaaaaaaaaaabb").unwrap().revoked,
            "revoke must survive concurrent touch_last_used"
        );
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

    // ── S4-A3 helpers + tests ────────────────────────────────────────────────

    fn rec(key_id: &str, created: u64, expires_at: Option<u64>, revoked: bool) -> CapabilityRecord {
        CapabilityRecord {
            key_id: key_id.to_string(),
            secret_hash: [0u8; 32],
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string()],
            label: "test".to_string(),
            created_at: created,
            expires_at,
            revoked,
            last_used: None,
        }
    }

    #[test]
    fn prune_removes_revoked_and_long_expired_keeps_live() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        let now = 1_000_000u64;
        store.add_capability(rec("live000000000000", now, None, false)).unwrap();
        store.add_capability(rec("revoked000000000", now, None, true)).unwrap();
        store.add_capability(rec("old0000000000000", now, Some(now - 10_000), false)).unwrap();
        store.add_capability(rec("freshexp00000000", now, Some(now - 10), false)).unwrap();

        let removed = store.prune_capabilities(now, 3_600).unwrap();
        assert_eq!(removed, 2);
        let snap = store.snapshot();
        assert!(snap.lookup_capability("live000000000000").is_some());
        assert!(snap.lookup_capability("freshexp00000000").is_some(), "within grace → kept");
        assert!(snap.lookup_capability("revoked000000000").is_none());
        assert!(snap.lookup_capability("old0000000000000").is_none());
        // Pruning persisted: survives re-open.
        let store2 = FileStore::open(&path).unwrap();
        assert!(store2.snapshot().lookup_capability("revoked000000000").is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn prune_with_nothing_to_do_does_not_rewrite_the_file() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(rec("live000000000000", 100, None, false)).unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(store.prune_capabilities(200, 3_600).unwrap(), 0);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before, "no-op prune must not persist");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn touch_last_used_is_buffered_not_persisted() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(make_cap_record("aaaaaaaaaaaaaabb")).unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        for _ in 0..100 {
            store.touch_last_used("aaaaaaaaaaaaaabb").unwrap();
        }
        // ZERO disk writes on the touch path (verifier hot-path guarantee).
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
        // Flush applies and persists.
        assert_eq!(store.flush_last_used().unwrap(), 1);
        let store2 = FileStore::open(&path).unwrap();
        assert!(store2.snapshot().lookup_capability("aaaaaaaaaaaaaabb").unwrap().last_used.is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn flush_last_used_ignores_keys_pruned_meanwhile() {
        let path = temp_path();
        let store = FileStore::open(&path).unwrap();
        store.add_capability(rec("gone000000000000", 100, None, true)).unwrap();
        store.touch_last_used("gone000000000000").unwrap();
        store.prune_capabilities(200, 0).unwrap();
        // Flush of a since-pruned key must not resurrect or error.
        assert_eq!(store.flush_last_used().unwrap(), 0);
        assert!(store.snapshot().lookup_capability("gone000000000000").is_none());
        let _ = fs::remove_file(&path);
    }
}
