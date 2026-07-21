/// auth_e2e: Full end-to-end authentication flow.
///
/// 1. Empty store → bootstrap Active → read code from file
/// 2. auth.bootstrap.claim → admin capability
/// 3. auth.login → scoped session capability
/// 4. server.host.info with admin cap → Ok
/// 5. auth.token.create with scopes=["server.read"] → read-only cap
/// 6. server.services.start with read-only cap → FORBIDDEN
/// 7. server.host.info with read-only cap → Ok
/// 8. auth.token.revoke(read-only cap key_id) → Ok
/// 9. server.host.info with revoked cap → UNAUTHENTICATED
/// 10. auth.whoami with admin cap → returns subject_id and scopes
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vaiexia_core::{
    diagnostic::codes,
    protocol::{Method, Outcome, Request, RequestId, Response},
    server::serve,
    version::ProtoVersion,
};
use vaiexia_server::{
    auth::{
        bootstrap::BootstrapState,
        store::{FileStore, IdentityStore},
    },
    backend::{mock::MockBackend, SystemBackend},
    lifecycle::build_service,
};

fn make_backend() -> Arc<SystemBackend> {
    let mock = Arc::new(MockBackend::new());
    Arc::new(SystemBackend::from_mock(mock))
}

async fn rpc(
    client: &reqwest::Client,
    base_url: &str,
    method: &str,
    params: serde_json::Value,
    cap: Option<&str>,
) -> Response {
    let req = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new(method).unwrap(),
        params,
        capability: cap.map(vaiexia_core::auth::Capability::new),
    };
    client
        .post(format!("{}/rpc", base_url))
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn temp_dir_path(suffix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "vaiexia-auth-e2e-{}",
        suffix,
    ));
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_e2e_full_flow() {
    // Use unique temp paths per test run to avoid conflicts.
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    let store_path = temp_dir_path(&format!("{}-identity.json", run_id));
    let code_path = temp_dir_path(&format!("{}-bootstrap.code", run_id));

    // 1. Create empty store, enter bootstrap.
    let store = Arc::new(FileStore::open(&store_path).unwrap()) as Arc<dyn IdentityStore>;
    assert!(store.is_empty(), "store must be empty at start");

    let bootstrap = Arc::new(Mutex::new(BootstrapState::begin(
        store.is_empty(),
        code_path.clone(),
    )));

    // Bootstrap code file should exist now.
    assert!(code_path.exists(), "bootstrap code file must be created");
    let bootstrap_code = std::fs::read_to_string(&code_path).unwrap();
    assert!(!bootstrap_code.is_empty());

    // Build the auth-enabled service.
    let backend = make_backend();
    let (service, pump_handles) = build_service(backend, Arc::clone(&store), bootstrap, vaiexia_server::audit::noop());

    let serve_handle = serve(service, "127.0.0.1:0").await.unwrap();
    let addr = serve_handle.addr();
    let base_url = format!("http://{}", addr);
    // argon2id in debug mode is slow (~3s per hash); use a generous timeout.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // ── 2. auth.bootstrap.claim → admin capability ────────────────────────────
    let resp = rpc(
        &client, &base_url,
        "auth.bootstrap.claim",
        serde_json::json!({
            "code": bootstrap_code,
            "admin_name": "admin",
            "password": "hunter2"
        }),
        None,
    ).await;
    assert!(resp.is_ok(), "bootstrap.claim must succeed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    let admin_cap = v["capability"].as_str().unwrap().to_string();
    let admin_subject_id = v["subject_id"].as_str().unwrap().to_string();
    assert!(!admin_cap.is_empty());
    assert_eq!(admin_subject_id, "user:admin");
    // Code file should be deleted after claim.
    assert!(!code_path.exists(), "bootstrap code file must be deleted after claim");

    // ── 3. auth.login → session capability ───────────────────────────────────
    let resp = rpc(
        &client, &base_url,
        "auth.login",
        serde_json::json!({
            "name": "admin",
            "password": "hunter2",
            "requested_scopes": ["server.read", "server.services.write"],
            "ttl": 3600
        }),
        None,
    ).await;
    assert!(resp.is_ok(), "auth.login must succeed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    let session_cap = v["capability"].as_str().unwrap().to_string();
    assert!(!session_cap.is_empty());
    let session_scopes = v["scopes"].as_array().unwrap();
    assert!(session_scopes.iter().any(|s| s == "server.read"));
    // vpn.admin not in account scopes → must be absent
    assert!(!session_scopes.iter().any(|s| s == "vpn.admin"));

    // ── 4. server.host.info with admin cap → Ok ───────────────────────────────
    let resp = rpc(
        &client, &base_url,
        "server.host.info",
        serde_json::json!({}),
        Some(&admin_cap),
    ).await;
    assert!(resp.is_ok(), "server.host.info must succeed with admin cap: {:?}", resp.outcome);
    assert_eq!(resp.value().unwrap()["hostname"], "mock-host");

    // ── 5. auth.token.create → read-only cap ─────────────────────────────────
    let resp = rpc(
        &client, &base_url,
        "auth.token.create",
        serde_json::json!({
            "label": "read-only-test",
            "scopes": ["server.read"],
            "ttl": null
        }),
        Some(&admin_cap),
    ).await;
    assert!(resp.is_ok(), "auth.token.create must succeed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    let ro_cap = v["capability"].as_str().unwrap().to_string();
    let ro_key_id = v["key_id"].as_str().unwrap().to_string();
    assert!(!ro_cap.is_empty());
    assert!(!ro_key_id.is_empty());

    // ── 6. server.services.start with read-only cap → FORBIDDEN ──────────────
    let resp = rpc(
        &client, &base_url,
        "server.services.start",
        serde_json::json!({ "name": "nginx.service" }),
        Some(&ro_cap),
    ).await;
    assert!(!resp.is_ok(), "services.start with read-only cap must be FORBIDDEN");
    match &resp.outcome {
        Outcome::Err(d) => assert_eq!(d.code, codes::FORBIDDEN, "expected FORBIDDEN, got {:?}", d.code),
        _ => panic!("expected Err outcome"),
    }

    // ── 7. server.host.info with read-only cap → Ok ───────────────────────────
    let resp = rpc(
        &client, &base_url,
        "server.host.info",
        serde_json::json!({}),
        Some(&ro_cap),
    ).await;
    assert!(resp.is_ok(), "server.host.info must succeed with read-only cap: {:?}", resp.outcome);

    // ── 8. auth.token.revoke(read-only key_id) → Ok ──────────────────────────
    let resp = rpc(
        &client, &base_url,
        "auth.token.revoke",
        serde_json::json!({ "key_id": ro_key_id }),
        Some(&admin_cap),
    ).await;
    assert!(resp.is_ok(), "auth.token.revoke must succeed: {:?}", resp.outcome);

    // ── 9. server.host.info with revoked cap → UNAUTHENTICATED ───────────────
    let resp = rpc(
        &client, &base_url,
        "server.host.info",
        serde_json::json!({}),
        Some(&ro_cap),
    ).await;
    assert!(!resp.is_ok(), "revoked cap must be rejected");
    match &resp.outcome {
        Outcome::Err(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
        _ => panic!("expected Err outcome"),
    }

    // ── 10. auth.whoami with admin cap ────────────────────────────────────────
    let resp = rpc(
        &client, &base_url,
        "auth.whoami",
        serde_json::json!({}),
        Some(&admin_cap),
    ).await;
    assert!(resp.is_ok(), "auth.whoami must succeed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    let whoami_subject = v["subject_id"].as_str().unwrap();
    // whoami reports the stable account identity, not the "cap:<key_id>" handle.
    assert_eq!(
        whoami_subject, "user:admin",
        "whoami must report the account subject_id, not the cap handle"
    );
    let whoami_scopes = v["scopes"].as_array().unwrap();
    assert!(whoami_scopes.iter().any(|s| s == "auth.admin"), "admin cap must have auth.admin scope");

    // ── Cleanup ───────────────────────────────────────────────────────────────
    for h in pump_handles { h.abort(); }
    serve_handle.shutdown();
    let _ = std::fs::remove_file(&store_path);
}

/// auth.login without a prior account → UNAUTHENTICATED (no account enum).
#[tokio::test(flavor = "multi_thread")]
async fn auth_login_nonexistent_user_unauthenticated() {
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    let store_path = temp_dir_path(&format!("{}-no-user.json", run_id));
    let store = Arc::new(FileStore::open(&store_path).unwrap()) as Arc<dyn IdentityStore>;
    let bootstrap = Arc::new(Mutex::new(BootstrapState::Disabled));
    let backend = make_backend();
    let (service, pump_handles) = build_service(backend, store, bootstrap, vaiexia_server::audit::noop());

    let serve_handle = serve(service, "127.0.0.1:0").await.unwrap();
    let addr = serve_handle.addr();
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let resp = rpc(
        &client, &base_url,
        "auth.login",
        serde_json::json!({ "name": "nobody", "password": "anything" }),
        None,
    ).await;

    assert!(!resp.is_ok());
    match &resp.outcome {
        Outcome::Err(d) => assert_eq!(d.code, codes::UNAUTHENTICATED),
        _ => panic!("expected Err outcome"),
    }

    for h in pump_handles { h.abort(); }
    serve_handle.shutdown();
    let _ = std::fs::remove_file(&store_path);
}
