use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiDeps, ScopeAudit, register_scoped};
use crate::audit::{AuditDecision, AuditEvent, AuditKind, DynAuditSink, reason};
use crate::auth::bootstrap::BootstrapState;
use crate::auth::password::verify_password;
use crate::auth::ratelimit::{RateLimiter, RateLimited};
use crate::auth::store::{CapabilityRecord, IdentityStore, now_secs};
use crate::auth::token;
use crate::diag::domain_codes;

// ── AuthModule ────────────────────────────────────────────────────────────────

pub struct AuthModule {
    pub store: Arc<dyn IdentityStore>,
    pub ratelimit: Arc<RateLimiter>,
    pub bootstrap: Arc<Mutex<BootstrapState>>,
}

impl crate::api::ApiModule for AuthModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, deps: &ApiDeps) -> ServiceBuilder {
        let store = Arc::clone(&self.store);
        let ratelimit = Arc::clone(&self.ratelimit);
        let bootstrap = Arc::clone(&self.bootstrap);
        let audit = deps.audit.clone();

        // auth.bootstrap.claim  (Anonymous)
        let store1 = Arc::clone(&store);
        let boot1 = Arc::clone(&bootstrap);
        let audit1 = audit.clone();
        let claim_method = Method::new("auth.bootstrap.claim").expect("valid method");
        let builder = register_scoped(
            builder,
            claim_method,
            audit.clone(),
            ScopeAudit::DenyOnly,
            move |p: BootstrapClaimParams, _subject: Subject| {
                let store = Arc::clone(&store1);
                let bootstrap = Arc::clone(&boot1);
                let audit = audit1.clone();
                async move { bootstrap_claim(p, store, bootstrap, audit).await }
            },
        );

        // auth.login  (Anonymous)
        let store2 = Arc::clone(&store);
        let rl2 = Arc::clone(&ratelimit);
        let audit2 = audit.clone();
        let login_method = Method::new("auth.login").expect("valid method");
        let builder = register_scoped(
            builder,
            login_method,
            audit.clone(),
            ScopeAudit::DenyOnly,
            move |p: LoginParams, _subject: Subject| {
                let store = Arc::clone(&store2);
                let rl = Arc::clone(&rl2);
                let audit = audit2.clone();
                async move { login(p, store, rl, audit).await }
            },
        );

        // auth.whoami  (Authenticated)
        let store3 = Arc::clone(&store);
        let whoami_method = Method::new("auth.whoami").expect("valid method");
        let builder = register_scoped(
            builder,
            whoami_method,
            audit.clone(),
            ScopeAudit::DenyOnly,
            move |_p: WhoamiParams, subject: Subject| {
                let store = Arc::clone(&store3);
                async move { whoami(subject, store).await }
            },
        );

        // auth.token.create  (auth.admin scope)
        let store4 = Arc::clone(&store);
        let audit4 = audit.clone();
        let token_create_method = Method::new("auth.token.create").expect("valid method");
        let builder = register_scoped(
            builder,
            token_create_method,
            audit.clone(),
            ScopeAudit::DenyOnly,
            move |p: TokenCreateParams, subject: Subject| {
                let store = Arc::clone(&store4);
                let audit = audit4.clone();
                async move { token_create(p, subject, store, audit).await }
            },
        );

        // auth.token.list  (auth.admin scope)
        let store5 = Arc::clone(&store);
        let token_list_method = Method::new("auth.token.list").expect("valid method");
        let builder = register_scoped(
            builder,
            token_list_method,
            audit.clone(),
            ScopeAudit::DenyOnly,
            move |_p: TokenListParams, _subject: Subject| {
                let store = Arc::clone(&store5);
                async move { token_list(store).await }
            },
        );

        // auth.token.revoke  (auth.admin scope)
        let store6 = Arc::clone(&store);
        let audit6 = audit.clone();
        let token_revoke_method = Method::new("auth.token.revoke").expect("valid method");
        register_scoped(
            builder,
            token_revoke_method,
            audit,
            ScopeAudit::DenyOnly,
            move |p: TokenRevokeParams, subject: Subject| {
                let store = Arc::clone(&store6);
                let audit = audit6.clone();
                async move { token_revoke(p, subject, store, audit).await }
            },
        )
    }
}

// ── Params / Responses ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BootstrapClaimParams {
    pub code: String,
    pub admin_name: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct BootstrapClaimResponse {
    pub capability: String,
    pub subject_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginParams {
    pub name: String,
    pub password: String,
    pub requested_scopes: Option<Vec<String>>,
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub capability: String,
    pub expires_at: Option<u64>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WhoamiParams {}

#[derive(Debug, Serialize)]
pub struct WhoamiResponse {
    pub subject_id: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TokenCreateParams {
    pub label: String,
    pub scopes: Vec<String>,
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TokenCreateResponse {
    pub capability: String,
    pub key_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenListParams {}

#[derive(Debug, Serialize)]
pub struct TokenMetadata {
    pub key_id: String,
    pub label: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub last_used: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRevokeParams {
    pub key_id: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn bootstrap_claim(
    p: BootstrapClaimParams,
    store: Arc<dyn IdentityStore>,
    bootstrap: Arc<Mutex<BootstrapState>>,
    audit: DynAuditSink,
) -> Result<BootstrapClaimResponse, Diagnostic> {
    let mut guard = bootstrap.lock().map_err(|_| {
        Diagnostic::error(codes::INTERNAL, "bootstrap lock poisoned")
    })?;
    let result = guard
        .claim(&p.code, &p.admin_name, &p.password, &store)
        .map_err(|e| {
            use crate::auth::bootstrap::BootstrapError;
            match e {
                BootstrapError::Disabled => {
                    audit.emit(
                        AuditEvent::new(AuditKind::Bootstrap, AuditDecision::Deny, "anonymous")
                            .with_detail("bootstrap is disabled; server already initialised"),
                    );
                    Diagnostic::error("BOOTSTRAP_DISABLED", "bootstrap is disabled; server already initialised")
                }
                BootstrapError::BadCode => {
                    audit.emit(
                        AuditEvent::new(AuditKind::Bootstrap, AuditDecision::Deny, "anonymous")
                            .with_detail("incorrect bootstrap code"),
                    );
                    Diagnostic::error(codes::FORBIDDEN, "incorrect bootstrap code")
                }
                BootstrapError::RateLimited => {
                    // Rate limit trip: emit RateLimit (security) instead of Bootstrap deny.
                    audit.emit(
                        AuditEvent::new(AuditKind::RateLimit, AuditDecision::Deny, "anonymous")
                            .with_method("auth.bootstrap.claim")
                            .with_reason(reason::RATE_LIMITED),
                    );
                    Diagnostic::error("RATE_LIMIT", "too many failed attempts; bootstrap code regenerated")
                }
                e => {
                    audit.emit(
                        AuditEvent::new(AuditKind::Bootstrap, AuditDecision::Err, "anonymous")
                            .with_detail(format!("internal: {e}")),
                    );
                    Diagnostic::error(codes::INTERNAL, e.to_string())
                }
            }
        })?;

    // Success — emit Bootstrap Allow (NEVER include the returned capability/secret).
    audit.emit(
        AuditEvent::new(AuditKind::Bootstrap, AuditDecision::Allow, &result.subject_id)
            .with_detail(format!("admin={} scopes={:?}", p.admin_name, result.scopes)),
    );

    Ok(BootstrapClaimResponse {
        capability: result.capability.reveal().to_string(),
        subject_id: result.subject_id,
        scopes: result.scopes,
    })
}

async fn login(
    p: LoginParams,
    store: Arc<dyn IdentityStore>,
    ratelimit: Arc<RateLimiter>,
    audit: DynAuditSink,
) -> Result<LoginResponse, Diagnostic> {
    let t0 = Instant::now();

    // Rate limit by account name.
    ratelimit.check(&p.name).map_err(|RateLimited { retry_after_secs }| {
        // Rate-limit trip: emit RateLimit (security) instead of AuthDecision deny.
        audit.emit(
            AuditEvent::new(AuditKind::RateLimit, AuditDecision::Deny, "anonymous")
                .with_method("auth.login")
                .with_reason(reason::RATE_LIMITED),
        );
        Diagnostic::error("RATE_LIMIT", format!("too many attempts; retry after {retry_after_secs}s"))
    })?;

    let snap = store.snapshot();
    let acc = snap.lookup_account(&p.name).ok_or_else(|| {
        // Return same error as wrong password (avoid user enumeration).
        audit.emit(
            AuditEvent::new(AuditKind::AuthDecision, AuditDecision::Deny, "anonymous")
                .with_method("auth.login")
                .with_reason(reason::UNKNOWN_ACCOUNT)
                .with_latency_us(t0.elapsed().as_micros() as u64),
        );
        Diagnostic::error(codes::UNAUTHENTICATED, "invalid credentials")
    })?;

    let ok = verify_password(&p.password, &acc.password_phc).map_err(|e| {
        Diagnostic::error(codes::INTERNAL, format!("password verify error: {e}"))
    })?;

    if !ok {
        audit.emit(
            AuditEvent::new(AuditKind::AuthDecision, AuditDecision::Deny, "anonymous")
                .with_method("auth.login")
                .with_reason(reason::BAD_PASSWORD)
                .with_latency_us(t0.elapsed().as_micros() as u64),
        );
        return Err(Diagnostic::error(codes::UNAUTHENTICATED, "invalid credentials"));
    }

    // Compute effective scopes: intersection of requested and account scopes.
    let account_scopes: std::collections::HashSet<&String> = acc.scopes.iter().collect();
    let effective_scopes: Vec<String> = match &p.requested_scopes {
        None => acc.scopes.clone(),
        Some(requested) => requested
            .iter()
            .filter(|s| account_scopes.contains(s))
            .cloned()
            .collect(),
    };

    let expires_at = p.ttl.map(|ttl| now_secs() + ttl);

    let minted = token::mint();
    store
        .add_capability(CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: acc.subject_id.clone(),
            scopes: effective_scopes.clone(),
            label: format!("login-{}", p.name),
            created_at: now_secs(),
            expires_at,
            revoked: false,
            last_used: None,
        })
        .map_err(|e| Diagnostic::error(codes::INTERNAL, e.to_string()))?;

    // Reset rate limit on success.
    ratelimit.reset(&p.name);

    // Emit AuthDecision Allow. The audit record carries key_id (handle) and
    // subject_id (human), NEVER the secret portion of the capability.
    let latency = t0.elapsed().as_micros() as u64;
    audit.emit(
        AuditEvent::new(AuditKind::AuthDecision, AuditDecision::Allow, &acc.subject_id)
            .with_method("auth.login")
            .with_cap_key_id(&minted.key_id)
            .with_reason(reason::OK)
            .with_latency_us(latency),
    );

    Ok(LoginResponse {
        capability: minted.capability.reveal().to_string(),
        expires_at,
        scopes: effective_scopes,
    })
}

async fn whoami(
    subject: Subject,
    store: Arc<dyn IdentityStore>,
) -> Result<WhoamiResponse, Diagnostic> {
    // For capability-authenticated subjects (SubjectId = "cap:<key_id>"),
    // look up the record to get the account identity, scopes, and expires_at.
    // The response reports the *account* subject_id (stable across a subject's
    // tokens), never the internal "cap:<key_id>" credential handle.
    let key_id_opt = subject.id.as_str().strip_prefix("cap:");
    let (subject_id, scopes, expires_at) = if let Some(key_id) = key_id_opt {
        let snap = store.snapshot();
        match snap.lookup_capability(key_id) {
            Some(r) => (r.subject_id.clone(), r.scopes.clone(), r.expires_at),
            None => (subject.id.as_str().to_string(), vec![], None),
        }
    } else {
        (subject.id.as_str().to_string(), vec![], None)
    };

    Ok(WhoamiResponse {
        subject_id,
        scopes,
        expires_at,
    })
}

async fn token_create(
    p: TokenCreateParams,
    subject: Subject,
    store: Arc<dyn IdentityStore>,
    audit: DynAuditSink,
) -> Result<TokenCreateResponse, Diagnostic> {
    let t0 = Instant::now();

    // Validate scopes are non-empty.
    if p.scopes.is_empty() {
        return Err(Diagnostic::error(codes::INVALID_PARAMS, "scopes must not be empty"));
    }

    // No privilege escalation: a caller may only mint tokens whose scopes are a
    // subset of its own. Otherwise an `auth.admin`-scoped-but-otherwise-limited
    // token could mint itself a broader capability (e.g. server.services.write).
    if let Some(missing) = p.scopes.iter().find(|s| {
        !subject
            .scopes
            .contains(&vaiexia_core::auth::Scope::new((*s).clone()))
    }) {
        return Err(Diagnostic::error(
            codes::FORBIDDEN,
            format!("cannot grant scope you do not hold: {missing}"),
        ));
    }

    // Owner of the new token is the caller's *account* identity, resolved from
    // the caller's capability record — not the raw "cap:<key_id>" handle.
    let subject_id = resolve_owner_subject_id(&subject, &store);

    let expires_at = p.ttl.map(|ttl| now_secs() + ttl);
    let minted = token::mint();
    store
        .add_capability(CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: subject_id.clone(),
            scopes: p.scopes.clone(),
            label: p.label.clone(),
            created_at: now_secs(),
            expires_at,
            revoked: false,
            last_used: None,
        })
        .map_err(|e| Diagnostic::error(codes::INTERNAL, e.to_string()))?;

    let latency = t0.elapsed().as_micros() as u64;
    // NEVER include the secret in the audit detail — key_id is the loggable handle.
    audit.emit(
        AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, &subject_id)
            .with_method("auth.token.create")
            .with_cap_key_id(&minted.key_id)
            .with_detail(format!(
                "created={} label={} scopes={:?}",
                minted.key_id, p.label, p.scopes
            ))
            .with_latency_us(latency),
    );

    Ok(TokenCreateResponse {
        capability: minted.capability.reveal().to_string(),
        key_id: minted.key_id,
        scopes: p.scopes,
    })
}

/// Resolve the caller's stable account `subject_id`.
///
/// Capability subjects carry `SubjectId = "cap:<key_id>"` (an internal
/// credential handle); the account identity lives on the capability record.
/// Falls back to the raw subject id if the handle can't be resolved.
fn resolve_owner_subject_id(subject: &Subject, store: &Arc<dyn IdentityStore>) -> String {
    if let Some(key_id) = subject.id.as_str().strip_prefix("cap:")
        && let Some(rec) = store.snapshot().lookup_capability(key_id)
    {
        return rec.subject_id.clone();
    }
    subject.id.as_str().to_string()
}

async fn token_list(store: Arc<dyn IdentityStore>) -> Result<Vec<TokenMetadata>, Diagnostic> {
    let snap = store.snapshot();
    let mut tokens: Vec<TokenMetadata> = snap
        .capabilities
        .values()
        .map(|r| TokenMetadata {
            key_id: r.key_id.clone(),
            label: r.label.clone(),
            scopes: r.scopes.clone(),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked: r.revoked,
            last_used: r.last_used,
        })
        .collect();
    // Stable order.
    tokens.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.key_id.cmp(&b.key_id)));
    Ok(tokens)
}

async fn token_revoke(
    p: TokenRevokeParams,
    subject: Subject,
    store: Arc<dyn IdentityStore>,
    audit: DynAuditSink,
) -> Result<serde_json::Value, Diagnostic> {
    let t0 = Instant::now();
    let key_id = p.key_id.clone();
    let result = store.revoke_capability(&key_id).map_err(|e| {
        use crate::auth::store::StoreError;
        match e {
            StoreError::NotFound(k) => Diagnostic::error(domain_codes::NOT_FOUND, format!("capability not found: {k}")),
            e => Diagnostic::error(codes::INTERNAL, e.to_string()),
        }
    });

    let latency = t0.elapsed().as_micros() as u64;
    match &result {
        Ok(_) => {
            let subject_id = resolve_owner_subject_id(&subject, &store);
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, &subject_id)
                    .with_method("auth.token.revoke")
                    .with_cap_key_id(&key_id)
                    .with_reason(reason::REVOKED)
                    .with_detail(format!("revoked={key_id}"))
                    .with_latency_us(latency),
            );
        }
        Err(_) => {
            let subject_id = resolve_owner_subject_id(&subject, &store);
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, &subject_id)
                    .with_method("auth.token.revoke")
                    .with_detail(format!("revoke_failed={key_id}"))
                    .with_latency_us(latency),
            );
        }
    }

    result?;
    Ok(serde_json::json!({}))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use crate::auth::store::{AccountRecord, FileStore, IdentityStore};
    use crate::auth::password::hash_password;
    use crate::auth::ratelimit::RateLimiter;
    use crate::auth::bootstrap::BootstrapState;

    fn temp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vaiexia-auth-meth-{}-{}.json", suffix, now_secs()));
        p
    }

    fn make_store(path: &PathBuf) -> Arc<dyn IdentityStore> {
        Arc::new(FileStore::open(path).unwrap()) as Arc<dyn IdentityStore>
    }

    fn make_admin_account(store: &Arc<dyn IdentityStore>) {
        let phc = hash_password("hunter2").unwrap();
        store.add_account(AccountRecord {
            name: "admin".to_string(),
            password_phc: phc,
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string(), "auth.admin".to_string()],
        }).unwrap();
    }

    #[tokio::test]
    async fn login_succeeds_with_correct_credentials() {
        let path = temp_path("login-ok");
        let store = make_store(&path);
        make_admin_account(&store);
        let rl = Arc::new(RateLimiter::new(5, Duration::from_secs(60)));
        let params = LoginParams {
            name: "admin".into(),
            password: "hunter2".into(),
            requested_scopes: None,
            ttl: None,
        };
        let resp = login(params, Arc::clone(&store), rl, crate::audit::noop()).await.unwrap();
        assert!(!resp.capability.is_empty());
        assert!(resp.scopes.contains(&"server.read".to_string()));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn login_fails_with_wrong_password() {
        let path = temp_path("login-bad-pw");
        let store = make_store(&path);
        make_admin_account(&store);
        let rl = Arc::new(RateLimiter::new(5, Duration::from_secs(60)));
        let params = LoginParams {
            name: "admin".into(),
            password: "wrong".into(),
            requested_scopes: None,
            ttl: None,
        };
        let err = login(params, store, rl, crate::audit::noop()).await.unwrap_err();
        assert_eq!(err.code, codes::UNAUTHENTICATED);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn login_scopes_intersected_with_account() {
        let path = temp_path("login-scopes");
        let store = make_store(&path);
        make_admin_account(&store);
        let rl = Arc::new(RateLimiter::new(5, Duration::from_secs(60)));
        let params = LoginParams {
            name: "admin".into(),
            password: "hunter2".into(),
            requested_scopes: Some(vec!["server.read".into(), "vpn.admin".into()]),
            ttl: None,
        };
        let resp = login(params, store, rl, crate::audit::noop()).await.unwrap();
        // vpn.admin not in account scopes → filtered out
        assert!(!resp.scopes.contains(&"vpn.admin".to_string()));
        assert!(resp.scopes.contains(&"server.read".to_string()));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn token_create_returns_capability() {
        let path = temp_path("token-create");
        let store = make_store(&path);
        let subject = Subject {
            id: vaiexia_core::auth::SubjectId::new("cap:testkey"),
            // Caller must itself hold what it delegates (no escalation).
            scopes: vaiexia_core::auth::ScopeSet::from_iter(["auth.admin", "server.read"]),
        };
        let params = TokenCreateParams {
            label: "test-token".into(),
            scopes: vec!["server.read".into()],
            ttl: Some(3600),
        };
        let resp = token_create(params, subject, Arc::clone(&store), crate::audit::noop()).await.unwrap();
        assert!(!resp.capability.is_empty());
        assert_eq!(resp.scopes, vec!["server.read"]);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn whoami_reports_account_identity_not_cap_handle() {
        let path = temp_path("whoami-id");
        let store = make_store(&path);
        let caller = token::mint();
        store.add_capability(CapabilityRecord {
            key_id: caller.key_id.clone(),
            secret_hash: caller.secret_hash,
            subject_id: "user:admin".into(),
            scopes: vec!["auth.admin".into()],
            label: "caller".into(),
            created_at: now_secs(),
            expires_at: Some(now_secs() + 3600),
            revoked: false,
            last_used: None,
        }).unwrap();
        let subject = Subject {
            id: vaiexia_core::auth::SubjectId::new(format!("cap:{}", caller.key_id)),
            scopes: vaiexia_core::auth::ScopeSet::from_iter(["auth.admin"]),
        };
        let resp = whoami(subject, Arc::clone(&store)).await.unwrap();
        assert_eq!(resp.subject_id, "user:admin");
        assert!(resp.expires_at.is_some(), "per-token expiry still surfaced");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn token_create_rejects_scopes_beyond_caller() {
        let path = temp_path("token-escalate");
        let store = make_store(&path);
        // Caller holds ONLY auth.admin — not server.services.write.
        let subject = Subject {
            id: vaiexia_core::auth::SubjectId::new("cap:limitedadmin"),
            scopes: vaiexia_core::auth::ScopeSet::from_iter(["auth.admin"]),
        };
        let params = TokenCreateParams {
            label: "escalation".into(),
            scopes: vec!["server.services.write".into()],
            ttl: None,
        };
        let err = token_create(params, subject, Arc::clone(&store), crate::audit::noop()).await.unwrap_err();
        assert_eq!(err.code, codes::FORBIDDEN, "must not mint scope caller lacks");
        // Nothing was persisted.
        assert!(store.snapshot().capabilities.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn token_create_records_account_owner_not_cap_handle() {
        let path = temp_path("token-owner");
        let store = make_store(&path);
        // Seed the caller's own capability so the "cap:<key_id>" handle resolves.
        let caller = token::mint();
        store.add_capability(CapabilityRecord {
            key_id: caller.key_id.clone(),
            secret_hash: caller.secret_hash,
            subject_id: "user:alice".into(),
            scopes: vec!["auth.admin".into(), "server.read".into()],
            label: "caller".into(),
            created_at: now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        }).unwrap();
        let subject = Subject {
            id: vaiexia_core::auth::SubjectId::new(format!("cap:{}", caller.key_id)),
            scopes: vaiexia_core::auth::ScopeSet::from_iter(["auth.admin", "server.read"]),
        };
        let params = TokenCreateParams {
            label: "delegated".into(),
            scopes: vec!["server.read".into()],
            ttl: None,
        };
        let resp = token_create(params, subject, Arc::clone(&store), crate::audit::noop()).await.unwrap();
        let snap = store.snapshot();
        let rec = snap.lookup_capability(&resp.key_id).unwrap();
        assert_eq!(
            rec.subject_id, "user:alice",
            "new token must record the caller's account identity, not the cap handle"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn token_list_returns_metadata_no_secrets() {
        let path = temp_path("token-list");
        let store = make_store(&path);
        let minted = token::mint();
        store.add_capability(crate::auth::store::CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".into(),
            scopes: vec!["server.read".into()],
            label: "my-token".into(),
            created_at: now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        }).unwrap();
        let list = token_list(Arc::clone(&store)).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key_id, minted.key_id);
        assert_eq!(list[0].label, "my-token");
        // Ensure no secret_hash in the response (it's not in TokenMetadata)
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn token_revoke_marks_revoked() {
        let path = temp_path("token-revoke");
        let store = make_store(&path);
        let minted = token::mint();
        store.add_capability(crate::auth::store::CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".into(),
            scopes: vec!["server.read".into()],
            label: "to-revoke".into(),
            created_at: now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        }).unwrap();
        let subject = Subject {
            id: vaiexia_core::auth::SubjectId::new("cap:dummy"),
            scopes: vaiexia_core::auth::ScopeSet::from_iter::<[&str; 0]>([]),
        };
        let params = TokenRevokeParams { key_id: minted.key_id.clone() };
        token_revoke(params, subject, Arc::clone(&store), crate::audit::noop()).await.unwrap();
        let snap = store.snapshot();
        assert!(snap.lookup_capability(&minted.key_id).unwrap().revoked);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn bootstrap_claim_creates_admin_and_returns_cap() {
        let store_path = temp_path("boot-claim");
        let code_path = {
            let mut p = std::env::temp_dir();
            p.push(format!("vaiexia-auth-boot-code-{}", now_secs()));
            p
        };
        let store = make_store(&store_path);
        let boot = Arc::new(Mutex::new(BootstrapState::begin(true, code_path.clone())));
        let code = std::fs::read_to_string(&code_path).unwrap();
        let params = BootstrapClaimParams {
            code,
            admin_name: "admin".into(),
            password: "hunter2".into(),
        };
        let resp = bootstrap_claim(params, Arc::clone(&store), boot, crate::audit::noop()).await.unwrap();
        assert!(!resp.capability.is_empty());
        assert_eq!(resp.subject_id, "user:admin");
        assert!(resp.scopes.contains(&"auth.admin".to_string()));
        let _ = std::fs::remove_file(&store_path);
    }
}
