use std::sync::Arc;

use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::error::{CoreError, Result};
use vaiexia_core::protocol::{Method, Topic};

use crate::auth::policy::{method_requirement, topic_scope, Requirement};
use crate::auth::store::{now_secs, IdentityStore};
use crate::auth::token;

// TODO(audit-sink): thread a WriteAheadSink into DaemonVerifier so every
// successful authentication emits an audit record (key_id, subject_id,
// method/topic, ts_us). Seam is ready; sink implementation is deferred.

/// Production verifier: authenticate + anonymous-gate (verify) +
/// authenticate + topic-scope check (verify_topic).
///
/// Does NOT enforce method scopes — that is `register_scoped`'s job.
pub struct DaemonVerifier {
    store: Arc<dyn IdentityStore>,
}

impl DaemonVerifier {
    pub fn new(store: Arc<dyn IdentityStore>) -> Self {
        Self { store }
    }

    /// Authenticate the presented capability.
    ///
    /// Returns `Ok(Subject)` on success.  Any authentication failure (missing
    /// cap, bad format, unknown key, revoked, wrong secret, expired) returns
    /// `Err(CoreError::Auth(UNAUTHENTICATED))`.
    fn authenticate(&self, cap: Option<&Capability>) -> Result<Subject> {
        let cap = match cap {
            Some(c) => c,
            None => {
                return Err(CoreError::Auth(Diagnostic::error(
                    codes::UNAUTHENTICATED,
                    "authentication required",
                )));
            }
        };

        // Parse format — panic-free on malformed input.
        let (key_id, secret_bytes) = match token::parse(cap) {
            Some(v) => v,
            None => {
                return Err(CoreError::Auth(Diagnostic::error(
                    codes::UNAUTHENTICATED,
                    "malformed capability token",
                )));
            }
        };

        // Snapshot lookup (atomic, no lock).
        let snap = self.store.snapshot();
        let rec = match snap.lookup_capability(&key_id) {
            Some(r) => r,
            None => {
                return Err(CoreError::Auth(Diagnostic::error(
                    codes::UNAUTHENTICATED,
                    "unknown capability",
                )));
            }
        };

        // Revoked check before secret verification (fail fast, constant-time
        // is not required for the boolean flag — only for the secret compare).
        if rec.revoked {
            return Err(CoreError::Auth(Diagnostic::error(
                codes::UNAUTHENTICATED,
                "capability has been revoked",
            )));
        }

        // Constant-time secret verification.
        if !token::verify_secret(&secret_bytes, &rec.secret_hash) {
            return Err(CoreError::Auth(Diagnostic::error(
                codes::UNAUTHENTICATED,
                "invalid capability secret",
            )));
        }

        // Expiry check.
        if rec.expires_at.is_some_and(|exp| now_secs() >= exp) {
            return Err(CoreError::Auth(Diagnostic::error(
                codes::UNAUTHENTICATED,
                "capability has expired",
            )));
        }

        // Build subject.  Encode key_id so whoami can look up expires_at.
        let subject = Subject {
            id: SubjectId::new(format!("cap:{}", rec.key_id)),
            scopes: ScopeSet::from_iter(rec.scopes.iter().cloned()),
        };

        // Best-effort last-used touch (ignore errors).
        let _ = self.store.touch_last_used(&key_id);

        Ok(subject)
    }

    fn anonymous_subject() -> Subject {
        Subject {
            id: SubjectId::new("anonymous"),
            scopes: ScopeSet::from_iter::<[&str; 0]>([]),
        }
    }
}

impl Verifier for DaemonVerifier {
    /// Authenticate + anonymous-gate only.
    ///
    /// Method-scope enforcement is intentionally absent — that is done by
    /// `register_scoped` inside each handler, so the FORBIDDEN diagnostic
    /// passes through dispatch verbatim (not overwritten by UNAUTHENTICATED).
    fn verify(&self, cap: Option<&Capability>, method: &Method) -> Result<Subject> {
        let requirement = match method_requirement(method) {
            Some(r) => r,
            None => {
                // Unknown method — safe default: require authentication.
                return self.authenticate(cap);
            }
        };

        match requirement {
            Requirement::Anonymous => Ok(Self::anonymous_subject()),
            Requirement::Authenticated | Requirement::Scope(_) => self.authenticate(cap),
        }
    }

    /// Authenticate + topic-scope check.
    ///
    /// Returns `Err(CoreError::Auth(FORBIDDEN))` when the subject lacks the
    /// required scope for the topic.  This error is preserved verbatim by the
    /// subscribe path (http.rs / tls.rs).
    fn verify_topic(&self, cap: Option<&Capability>, topic: &Topic) -> Result<Subject> {
        let subject = self.authenticate(cap)?;

        // Fail closed: a topic with no policy entry is FORBIDDEN, not allowed.
        // (Prevents a future event source added without a scope from becoming
        // world-readable to any authenticated subject.)
        let required_scope = match topic_scope(topic) {
            Some(s) => s,
            None => {
                return Err(CoreError::Auth(Diagnostic::error(
                    codes::FORBIDDEN,
                    format!("no subscription policy for topic {}", topic.as_str()),
                )));
            }
        };

        if !subject.scopes.contains(&required_scope) {
            return Err(CoreError::Auth(Diagnostic::error(
                codes::FORBIDDEN,
                format!("missing scope {}", required_scope.as_str()),
            )));
        }

        Ok(subject)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use vaiexia_core::auth::{Capability, Scope};

    use crate::auth::store::{CapabilityRecord, FileStore, IdentityStore};
    use crate::auth::token::{MintedCapability, mint};

    fn temp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "vaiexia-verifier-test-{}-{}.json",
            suffix,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        p
    }

    struct TestCtx {
        store: Arc<dyn IdentityStore>,
        #[allow(dead_code)]
        path: PathBuf,
    }

    fn make_store(scopes: &[&str]) -> (TestCtx, MintedCapability) {
        let path = temp_path("daemon");
        let store = Arc::new(FileStore::open(&path).unwrap()) as Arc<dyn IdentityStore>;
        let minted = mint();
        let rec = CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            label: "test".to_string(),
            created_at: now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        };
        store.add_capability(rec).unwrap();
        (TestCtx { store, path }, minted)
    }

    fn verifier(ctx: &TestCtx) -> DaemonVerifier {
        DaemonVerifier::new(Arc::clone(&ctx.store))
    }

    // ── verify() tests ────────────────────────────────────────────────────────

    #[test]
    fn verify_none_on_anonymous_method_ok() {
        let (ctx, _) = make_store(&["server.read"]);
        let v = verifier(&ctx);
        let method = Method::new("auth.login").unwrap();
        let subj = v.verify(None, &method).unwrap();
        assert_eq!(subj.id.as_str(), "anonymous");
    }

    #[test]
    fn verify_none_on_authenticated_method_err() {
        let (ctx, _) = make_store(&["server.read"]);
        let v = verifier(&ctx);
        let method = Method::new("server.host.info").unwrap();
        let err = v.verify(None, &method).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
            _ => panic!("expected Auth error"),
        }
    }

    #[test]
    fn verify_valid_cap_on_scoped_method_ok() {
        let (ctx, minted) = make_store(&["server.read"]);
        let v = verifier(&ctx);
        let method = Method::new("server.host.info").unwrap();
        let subj = v.verify(Some(&minted.capability), &method).unwrap();
        assert!(subj.scopes.contains(&Scope::new("server.read")));
    }

    #[test]
    fn verify_expired_cap_err() {
        let path = temp_path("expired");
        let store = Arc::new(FileStore::open(&path).unwrap()) as Arc<dyn IdentityStore>;
        let minted = mint();
        // expires_at in the past
        let rec = CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string()],
            label: "test".to_string(),
            created_at: 1,
            expires_at: Some(1), // expired
            revoked: false,
            last_used: None,
        };
        store.add_capability(rec).unwrap();
        let v = DaemonVerifier::new(Arc::clone(&store));
        let method = Method::new("server.host.info").unwrap();
        let err = v.verify(Some(&minted.capability), &method).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
            _ => panic!("expected Auth error"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_revoked_cap_err() {
        let (ctx, minted) = make_store(&["server.read"]);
        ctx.store.revoke_capability(&minted.key_id).unwrap();
        let v = verifier(&ctx);
        let method = Method::new("server.host.info").unwrap();
        let err = v.verify(Some(&minted.capability), &method).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
            _ => panic!("expected Auth error"),
        }
    }

    #[test]
    fn verify_wrong_secret_err() {
        let (ctx, minted) = make_store(&["server.read"]);
        // Tamper with the token's secret segment
        let raw = minted.capability.reveal();
        let parts: Vec<&str> = raw.splitn(3, '.').collect();
        // Replace last char of secret with a different char
        let mut bad_secret = parts[2].to_string();
        let last = bad_secret.len() - 1;
        let c = bad_secret.as_bytes()[last];
        let replacement = if c == b'A' { b'B' } else { b'A' };
        bad_secret.replace_range(last..=last, &(replacement as char).to_string());
        let bad_raw = format!("{}.{}.{}", parts[0], parts[1], bad_secret);
        let bad_cap = Capability::new(bad_raw);
        let v = verifier(&ctx);
        let method = Method::new("server.host.info").unwrap();
        let err = v.verify(Some(&bad_cap), &method).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
            _ => panic!("expected Auth error"),
        }
    }

    // ── verify_topic() tests ──────────────────────────────────────────────────

    #[test]
    fn verify_topic_read_only_cap_on_logs_forbidden() {
        let (ctx, minted) = make_store(&["server.read"]);
        let v = verifier(&ctx);
        let topic = Topic::new("server.logs");
        let err = v.verify_topic(Some(&minted.capability), &topic).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::FORBIDDEN),
            _ => panic!("expected Auth FORBIDDEN error"),
        }
    }

    #[test]
    fn verify_topic_logs_cap_on_logs_ok() {
        let (ctx, minted) = make_store(&["server.read", "server.logs.read"]);
        let v = verifier(&ctx);
        let topic = Topic::new("server.logs");
        let subj = v.verify_topic(Some(&minted.capability), &topic).unwrap();
        assert!(subj.scopes.contains(&Scope::new("server.logs.read")));
    }

    #[test]
    fn verify_topic_read_cap_on_metrics_ok() {
        let (ctx, minted) = make_store(&["server.read"]);
        let v = verifier(&ctx);
        let topic = Topic::new("server.metrics");
        let subj = v.verify_topic(Some(&minted.capability), &topic).unwrap();
        assert!(subj.scopes.contains(&Scope::new("server.read")));
    }

    #[test]
    fn verify_topic_unknown_topic_forbidden() {
        // Even a fully-scoped subject must be denied a topic with no policy entry.
        let (ctx, minted) = make_store(&["server.read", "server.logs.read"]);
        let v = verifier(&ctx);
        let topic = Topic::new("server.unmapped");
        let err = v.verify_topic(Some(&minted.capability), &topic).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::FORBIDDEN),
            _ => panic!("expected Auth FORBIDDEN error"),
        }
    }

    #[test]
    fn verify_topic_no_cap_err() {
        let (ctx, _) = make_store(&["server.read"]);
        let v = verifier(&ctx);
        let topic = Topic::new("server.metrics");
        let err = v.verify_topic(None, &topic).unwrap_err();
        match err {
            CoreError::Auth(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
            _ => panic!("expected Auth error"),
        }
    }

    // Clean up temp files after tests
    impl Drop for TestCtx {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
