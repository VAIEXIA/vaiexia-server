use std::path::PathBuf;
use std::sync::Arc;

use vaiexia_core::protocol::{Method, Request, RequestId, Response, ServerHello};
use vaiexia_core::version::ProtoVersion;
use vaiexia_server::{
    backend::{SystemBackend, mock::MockBackend},
    config::{Listener, ListenerKind, ServerConfig},
    lifecycle::build_service_permissive as build_service,
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
        ..Default::default()
    }
}

fn make_backend() -> Arc<SystemBackend> {
    let mock = Arc::new(MockBackend::new());
    Arc::new(SystemBackend::from_mock(mock))
}

#[tokio::test(flavor = "multi_thread")]
async fn host_info_and_hello_integration() {
    // 1. Build service and start listener on an ephemeral port.
    let backend = make_backend();
    let (service, pump_handles) = build_service(backend);
    let cfg = make_config("127.0.0.1:0");
    let handles = start_listeners(&cfg, service).await.unwrap();
    let addr = handles[0].local_addr();

    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // 2. GET /hello — must return 200 with server_version field.
    let hello_resp = client
        .get(format!("{}/hello", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(hello_resp.status(), 200);
    let hello: ServerHello = hello_resp.json().await.unwrap();
    // Just assert the field exists (non-empty check: version has major=1)
    assert_eq!(hello.server_version.major, 1);

    // 3. POST /rpc — call server.host.info
    let rpc_request = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new("server.host.info").unwrap(),
        params: serde_json::json!({}),
        capability: None,
    };

    let rpc_resp = client
        .post(format!("{}/rpc", base_url))
        .json(&rpc_request)
        .send()
        .await
        .unwrap();
    assert_eq!(rpc_resp.status(), 200);

    let response: Response = rpc_resp.json().await.unwrap();
    assert!(response.is_ok(), "expected ok outcome, got: {:?}", response.outcome);

    let value = response.value().unwrap();
    assert_eq!(value["hostname"], "mock-host");
    assert_eq!(value["capabilities"]["metrics"], true);

    // 4. Shutdown and verify it completes cleanly.
    pump_handles.into_iter().for_each(|h| h.abort());
    handles.into_iter().for_each(|h| h.shutdown());
}
