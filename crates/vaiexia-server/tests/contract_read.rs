use std::path::PathBuf;
use std::sync::Arc;

use vaiexia_core::protocol::{Method, Request, RequestId, Response};
use vaiexia_core::version::ProtoVersion;
use vaiexia_server::{
    backend::{SystemBackend, mock::MockBackend},
    config::{Listener, ListenerKind, ServerConfig},
    lifecycle::build_service,
    transport::start_listeners,
};

fn make_config(bind: &str) -> ServerConfig {
    ServerConfig {
        state_dir: PathBuf::from("/var/lib/vaiexia"),
        listeners: vec![Listener {
            kind: ListenerKind::Http,
            bind: bind.into(),
            cert: None,
            key: None,
        }],
    }
}

fn make_backend() -> Arc<SystemBackend> {
    Arc::new(SystemBackend::from_mock(Arc::new(MockBackend::new())))
}

async fn rpc(client: &reqwest::Client, base_url: &str, method: &str, params: serde_json::Value) -> Response {
    let rpc_request = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new(method).unwrap(),
        params,
        capability: None,
    };
    let resp = client
        .post(format!("{}/rpc", base_url))
        .json(&rpc_request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "HTTP 200 for {}", method);
    resp.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn read_surface_contract() {
    let backend = make_backend();
    let service = build_service(backend);
    let cfg = make_config("127.0.0.1:0");
    let handles = start_listeners(&cfg, service).await.unwrap();
    let addr = handles[0].local_addr();
    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // 1. server.host.info — should still work (Step 0 method)
    let resp = rpc(&client, &base_url, "server.host.info", serde_json::json!({})).await;
    assert!(resp.is_ok(), "host.info failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    assert_eq!(v["hostname"], "mock-host");

    // 2. server.services.list — returns PageDto<UnitDto>
    let resp = rpc(&client, &base_url, "server.services.list", serde_json::json!({})).await;
    assert!(resp.is_ok(), "services.list failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    assert!(v["items"].is_array(), "services.list should return items array");
    let items = v["items"].as_array().unwrap();
    assert!(!items.is_empty(), "services.list should have units");
    assert!(items.iter().any(|u| u["name"] == "nginx.service"), "nginx.service should be in list");

    // 3. server.services.status for scripted unit
    let resp = rpc(
        &client,
        &base_url,
        "server.services.status",
        serde_json::json!({ "name": "nginx.service" }),
    )
    .await;
    assert!(resp.is_ok(), "services.status failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    assert_eq!(v["name"], "nginx.service");
    assert_eq!(v["active_state"], "active");

    // 4. server.packages.list with installed_only=true
    let resp = rpc(
        &client,
        &base_url,
        "server.packages.list",
        serde_json::json!({ "installed_only": true }),
    )
    .await;
    assert!(resp.is_ok(), "packages.list failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    let pkgs = v["items"].as_array().unwrap();
    assert!(pkgs.iter().all(|p| p["installed"] == true), "all packages should be installed");

    // 5. server.logs.query with limit=5 — returns entries with cursors
    let resp = rpc(
        &client,
        &base_url,
        "server.logs.query",
        serde_json::json!({ "limit": 5 }),
    )
    .await;
    assert!(resp.is_ok(), "logs.query failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    let entries = v["items"].as_array().unwrap();
    assert!(entries.len() <= 5);
    for e in entries {
        assert!(!e["cursor"].as_str().unwrap_or("").is_empty(), "entry should have cursor");
    }

    handles.into_iter().for_each(|h| h.shutdown());
}
