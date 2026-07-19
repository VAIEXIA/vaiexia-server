use std::sync::{Arc, Mutex};
use std::time::Duration;

use vaiexia_core::server::{Service, ServiceBuilder};

use crate::api::{ApiModule, jobs::JobRegistry, server_module::ServerModule, auth_methods::AuthModule};
use crate::auth::bootstrap::BootstrapState;
use crate::auth::ratelimit::RateLimiter;
use crate::auth::store::IdentityStore;
use crate::auth::{DaemonVerifier, SkeletonVerifier};
use crate::backend::SystemBackend;
use crate::events::{
    PumpHandle, SeqCounter, spawn_supervised,
    jobs_pump, logs_pump, metrics_pump, status_pump, topics,
};

const METRICS_INTERVAL_SECS: u64 = 2;

/// Login rate-limiter: 10 attempts per 5-minute window.
const LOGIN_MAX_ATTEMPTS: u32 = 10;
const LOGIN_WINDOW_SECS: u64 = 300;

/// Build a production service with DaemonVerifier + AuthModule.
///
/// `store` holds the identity snapshot; `bootstrap` is the first-run claim
/// state machine (may already be `Disabled` if the store is non-empty).
pub fn build_service(
    backend: Arc<SystemBackend>,
    store: Arc<dyn IdentityStore>,
    bootstrap: Arc<Mutex<BootstrapState>>,
) -> (Arc<Service>, Vec<PumpHandle>) {
    let registry = Arc::new(JobRegistry::new());
    let ratelimit = Arc::new(RateLimiter::new(
        LOGIN_MAX_ATTEMPTS,
        Duration::from_secs(LOGIN_WINDOW_SECS),
    ));

    let verifier = DaemonVerifier::new(Arc::clone(&store));
    let mut builder = ServiceBuilder::new().verifier(verifier);

    let metrics_sender = builder.event_source_sender(topics::metrics());
    let status_sender = builder.event_source_sender(topics::services_status());
    let jobs_sender = builder.event_source_sender(topics::jobs());
    let logs_sender = builder.event_source_sender(topics::logs());

    let modules: Vec<Box<dyn ApiModule>> = vec![
        Box::new(ServerModule {
            registry: Arc::clone(&registry),
        }),
        Box::new(AuthModule {
            store: Arc::clone(&store),
            ratelimit,
            bootstrap,
        }),
    ];
    let builder = modules
        .into_iter()
        .fold(builder, |b, m| m.register(b, Arc::clone(&backend)));

    let service = Arc::new(builder.build());

    let seq = SeqCounter::new();
    let mut handles: Vec<PumpHandle> = Vec::new();

    {
        let sender = metrics_sender.clone();
        let provider = Arc::clone(&backend.metrics);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("metrics", move || {
            let sender = sender.clone();
            let provider = Arc::clone(&provider);
            let seq = seq2.clone_arc();
            Box::pin(metrics_pump::run(
                sender,
                provider,
                seq,
                Duration::from_secs(METRICS_INTERVAL_SECS),
            ))
        }));
    }

    if let Some(mgr) = &backend.services {
        let sender = status_sender.clone();
        let mgr = Arc::clone(mgr);
        handles.push(spawn_supervised("status", move || {
            let sender = sender.clone();
            let mgr = Arc::clone(&mgr);
            Box::pin(status_pump::run(sender, mgr))
        }));
    }

    {
        let sender = jobs_sender.clone();
        let registry2 = Arc::clone(&registry);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("jobs", move || {
            let sender = sender.clone();
            let registry = Arc::clone(&registry2);
            let seq = seq2.clone_arc();
            Box::pin(jobs_pump::run(sender, registry, seq))
        }));
    }

    if let Some(logs) = &backend.logs {
        let sender = logs_sender.clone();
        let provider = Arc::clone(logs);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("logs", move || {
            let sender = sender.clone();
            let provider = Arc::clone(&provider);
            let seq = seq2.clone_arc();
            Box::pin(logs_pump::run(sender, provider, seq))
        }));
    }

    (service, handles)
}

/// Build a permissive service that accepts all requests without authentication.
///
/// Used by legacy integration tests that were written before auth was wired.
/// DO NOT USE in production code paths.
pub fn build_service_permissive(backend: Arc<SystemBackend>) -> (Arc<Service>, Vec<PumpHandle>) {
    let registry = Arc::new(JobRegistry::new());

    let mut builder = ServiceBuilder::new().verifier(SkeletonVerifier);

    let metrics_sender = builder.event_source_sender(topics::metrics());
    let status_sender = builder.event_source_sender(topics::services_status());
    let jobs_sender = builder.event_source_sender(topics::jobs());
    let logs_sender = builder.event_source_sender(topics::logs());

    let modules: Vec<Box<dyn ApiModule>> = vec![Box::new(ServerModule {
        registry: Arc::clone(&registry),
    })];
    let builder = modules
        .into_iter()
        .fold(builder, |b, m| m.register(b, Arc::clone(&backend)));

    let service = Arc::new(builder.build());

    let seq = SeqCounter::new();
    let mut handles: Vec<PumpHandle> = Vec::new();

    {
        let sender = metrics_sender.clone();
        let provider = Arc::clone(&backend.metrics);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("metrics", move || {
            let sender = sender.clone();
            let provider = Arc::clone(&provider);
            let seq = seq2.clone_arc();
            Box::pin(metrics_pump::run(
                sender,
                provider,
                seq,
                Duration::from_secs(METRICS_INTERVAL_SECS),
            ))
        }));
    }

    if let Some(mgr) = &backend.services {
        let sender = status_sender.clone();
        let mgr = Arc::clone(mgr);
        handles.push(spawn_supervised("status", move || {
            let sender = sender.clone();
            let mgr = Arc::clone(&mgr);
            Box::pin(status_pump::run(sender, mgr))
        }));
    }

    {
        let sender = jobs_sender.clone();
        let registry2 = Arc::clone(&registry);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("jobs", move || {
            let sender = sender.clone();
            let registry = Arc::clone(&registry2);
            let seq = seq2.clone_arc();
            Box::pin(jobs_pump::run(sender, registry, seq))
        }));
    }

    if let Some(logs) = &backend.logs {
        let sender = logs_sender.clone();
        let provider = Arc::clone(logs);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("logs", move || {
            let sender = sender.clone();
            let provider = Arc::clone(&provider);
            let seq = seq2.clone_arc();
            Box::pin(logs_pump::run(sender, provider, seq))
        }));
    }

    (service, handles)
}

/// Resolves when a shutdown signal (SIGTERM or Ctrl-C) arrives.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::backend::{mock::MockBackend, SystemBackend};

    fn make_backend() -> Arc<SystemBackend> {
        let mock = Arc::new(MockBackend::new());
        Arc::new(SystemBackend::from_mock(mock))
    }

    // ── Permissive (legacy) tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn build_service_assembles_without_panic() {
        let backend = make_backend();
        let (service, handles) = build_service_permissive(backend);
        for h in handles { h.abort(); }
        drop(service);
    }

    #[tokio::test]
    async fn build_service_registers_event_sources_without_panic() {
        let backend = make_backend();
        let (service, handles) = build_service_permissive(backend);
        assert_eq!(handles.len(), 4, "expected 4 pump handles");
        for h in handles { h.abort(); }
        drop(service);
    }

    // ── B5: DaemonVerifier integration tests ──────────────────────────────────

    fn make_temp_store() -> Arc<dyn IdentityStore> {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "vaiexia-lifecycle-test-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        Arc::new(crate::auth::store::FileStore::open(&p).unwrap()) as Arc<dyn IdentityStore>
    }

    /// build_service (auth-enabled) assembles without panic on an empty store.
    #[tokio::test]
    async fn build_service_with_auth_assembles() {
        let backend = make_backend();
        let store = make_temp_store();
        let bootstrap = Arc::new(Mutex::new(
            BootstrapState::begin(store.is_empty(), std::env::temp_dir().join("bootstrap-test.code")),
        ));
        let (service, handles) = build_service(backend, store, bootstrap);
        assert_eq!(handles.len(), 4, "expected 4 pump handles");
        for h in handles { h.abort(); }
        drop(service);
    }

    /// Calling server.host.info without a capability → UNAUTHENTICATED.
    #[tokio::test]
    async fn daemon_verifier_rejects_unauthenticated_call() {
        use vaiexia_core::protocol::{Method, Request, RequestId};
        use vaiexia_core::server::serve;
        use vaiexia_core::version::ProtoVersion;

        let backend = make_backend();
        let store = make_temp_store();
        let bootstrap = Arc::new(Mutex::new(BootstrapState::Disabled));
        let (service, handles) = build_service(backend, store, bootstrap);

        let serve_handle = serve(service, "127.0.0.1:0").await.unwrap();
        let addr = serve_handle.addr();
        let base_url = format!("http://{}", addr);

        let client = reqwest::Client::new();
        let req = Request {
            id: RequestId::new(),
            version: ProtoVersion::CURRENT,
            method: Method::new("server.host.info").unwrap(),
            params: serde_json::json!({}),
            capability: None,
        };
        let resp: vaiexia_core::protocol::Response = client
            .post(format!("{}/rpc", base_url))
            .json(&req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(!resp.is_ok(), "must be rejected without cap");
        let outcome = resp.outcome;
        let code = match &outcome {
            vaiexia_core::protocol::Outcome::Err(d) => d.code.as_str(),
            _ => panic!("expected Err outcome"),
        };
        assert_eq!(code, vaiexia_core::diagnostic::codes::UNAUTHENTICATED);

        for h in handles { h.abort(); }
        serve_handle.shutdown();
    }

    /// Calling server.host.info with a valid admin cap → Ok.
    #[tokio::test]
    async fn daemon_verifier_accepts_valid_admin_cap() {
        use vaiexia_core::protocol::{Method, Request, RequestId};
        use vaiexia_core::server::serve;
        use vaiexia_core::version::ProtoVersion;

        let backend = make_backend();
        let store = make_temp_store();

        // Mint and seed admin capability in the store.
        let minted = crate::auth::token::mint();
        store.add_capability(crate::auth::store::CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string(), "auth.admin".to_string()],
            label: "test-admin".to_string(),
            created_at: crate::auth::store::now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        }).unwrap();

        let bootstrap = Arc::new(Mutex::new(BootstrapState::Disabled));
        let (service, handles) = build_service(backend, store, bootstrap);

        let serve_handle = serve(service, "127.0.0.1:0").await.unwrap();
        let addr = serve_handle.addr();
        let base_url = format!("http://{}", addr);

        let client = reqwest::Client::new();
        let req = Request {
            id: RequestId::new(),
            version: ProtoVersion::CURRENT,
            method: Method::new("server.host.info").unwrap(),
            params: serde_json::json!({}),
            capability: Some(minted.capability),
        };
        let resp: vaiexia_core::protocol::Response = client
            .post(format!("{}/rpc", base_url))
            .json(&req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(resp.is_ok(), "admin cap should access server.host.info: {:?}", resp.outcome);
        let v = resp.value().unwrap();
        assert_eq!(v["hostname"], "mock-host");

        for h in handles { h.abort(); }
        serve_handle.shutdown();
    }

    /// read-only cap calling server.services.start → FORBIDDEN.
    #[tokio::test]
    async fn register_scoped_enforces_scope_forbidden() {
        use vaiexia_core::protocol::{Method, Request, RequestId};
        use vaiexia_core::server::serve;
        use vaiexia_core::version::ProtoVersion;

        let backend = make_backend();
        let store = make_temp_store();

        // Mint read-only cap.
        let minted = crate::auth::token::mint();
        store.add_capability(crate::auth::store::CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string()],  // no server.services.write
            label: "read-only".to_string(),
            created_at: crate::auth::store::now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        }).unwrap();

        let bootstrap = Arc::new(Mutex::new(BootstrapState::Disabled));
        let (service, handles) = build_service(backend, store, bootstrap);

        let serve_handle = serve(service, "127.0.0.1:0").await.unwrap();
        let addr = serve_handle.addr();
        let base_url = format!("http://{}", addr);

        let client = reqwest::Client::new();
        let req = Request {
            id: RequestId::new(),
            version: ProtoVersion::CURRENT,
            method: Method::new("server.services.start").unwrap(),
            params: serde_json::json!({ "name": "nginx.service" }),
            capability: Some(minted.capability),
        };
        let resp: vaiexia_core::protocol::Response = client
            .post(format!("{}/rpc", base_url))
            .json(&req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(!resp.is_ok(), "read-only cap must not call services.start");
        let code = match &resp.outcome {
            vaiexia_core::protocol::Outcome::Err(d) => d.code.as_str(),
            _ => panic!("expected Err outcome"),
        };
        assert_eq!(code, vaiexia_core::diagnostic::codes::FORBIDDEN);

        for h in handles { h.abort(); }
        serve_handle.shutdown();
    }
}
