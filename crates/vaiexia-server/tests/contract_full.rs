use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use vaiexia_core::{
    client::Client,
    protocol::{Method, Request, RequestId, Response},
    server::serve,
    transport::impls::ws::WsTransport,
    version::ProtoVersion,
};
use vaiexia_server::{
    api::dto::{LogEntryDto, MetricsDto},
    backend::{mock::MockBackend, LogEntry, SystemBackend},
    events::topics,
    lifecycle::build_service_permissive as build_service,
};

async fn rpc(
    client: &reqwest::Client,
    base_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Response {
    let req = Request {
        id: RequestId::new(),
        version: ProtoVersion::CURRENT,
        method: Method::new(method).unwrap(),
        params,
        capability: None,
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

#[tokio::test(flavor = "multi_thread")]
async fn full_contract() {
    let mock = Arc::new(MockBackend::new());
    let backend = Arc::new(SystemBackend::from_mock(Arc::clone(&mock)));
    let (service, pump_handles) = build_service(backend);

    // Start server on ephemeral port using vaiexia-core's serve()
    let serve_handle = serve(service, "127.0.0.1:0").await.unwrap();
    let addr = serve_handle.addr();
    let base_url = format!("http://{}", addr);
    let ws_url = format!("ws://{}/ws", addr);

    let http_client = reqwest::Client::new();

    // ── 1. Read methods ───────────────────────────────────────────────────────

    // host.info
    let resp = rpc(&http_client, &base_url, "server.host.info", serde_json::json!({})).await;
    assert!(resp.is_ok(), "host.info failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    assert_eq!(v["hostname"], "mock-host");

    // services.list
    let resp = rpc(&http_client, &base_url, "server.services.list", serde_json::json!({})).await;
    assert!(resp.is_ok(), "services.list failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    assert!(v["items"].is_array());

    // services.status
    let resp = rpc(
        &http_client,
        &base_url,
        "server.services.status",
        serde_json::json!({ "name": "nginx.service" }),
    )
    .await;
    assert!(resp.is_ok(), "services.status failed");
    let v = resp.value().unwrap();
    assert_eq!(v["name"], "nginx.service");

    // packages.list (installed_only=true)
    let resp = rpc(
        &http_client,
        &base_url,
        "server.packages.list",
        serde_json::json!({ "installed_only": true }),
    )
    .await;
    assert!(resp.is_ok(), "packages.list failed");
    let v = resp.value().unwrap();
    assert!(v["items"].is_array());

    // logs.query (limit=5)
    let resp = rpc(
        &http_client,
        &base_url,
        "server.logs.query",
        serde_json::json!({ "limit": 5 }),
    )
    .await;
    assert!(resp.is_ok(), "logs.query failed");

    // ── 2. Mutation: packages.install → job → succeeded ───────────────────────

    let resp = rpc(
        &http_client,
        &base_url,
        "server.packages.install",
        serde_json::json!({ "name": "nginx" }),
    )
    .await;
    assert!(resp.is_ok(), "packages.install failed: {:?}", resp.outcome);
    let job_id = resp.value().unwrap()["job_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Poll jobs.status until succeeded (max 5s)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut job_succeeded = false;
    while tokio::time::Instant::now() < deadline {
        let r = rpc(
            &http_client,
            &base_url,
            "server.jobs.status",
            serde_json::json!({ "job_id": &job_id }),
        )
        .await;
        if r.is_ok() {
            let v = r.value().unwrap();
            if v["state"] == "succeeded" {
                job_succeeded = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(job_succeeded, "install job should have succeeded within 5s");

    // ── 3. services.start ─────────────────────────────────────────────────────

    let resp = rpc(
        &http_client,
        &base_url,
        "server.services.start",
        serde_json::json!({ "name": "nginx.service" }),
    )
    .await;
    assert!(resp.is_ok(), "services.start failed: {:?}", resp.outcome);
    let v = resp.value().unwrap();
    assert_eq!(v["outcome"], "ok");

    // ── 4. Subscribe server.metrics via WsTransport ───────────────────────────

    let ws_transport = WsTransport::connect(&ws_url).await.unwrap();
    let core_client = Client::builder().connect(ws_transport);
    let topic = topics::metrics();
    let mut metrics_stream = core_client.subscribe_typed::<MetricsDto>(&topic).await.unwrap();

    let metrics_event = tokio::time::timeout(
        Duration::from_secs(8),
        metrics_stream.next(),
    )
    .await;
    assert!(metrics_event.is_ok(), "metrics event should arrive within 8s");
    let dto = metrics_event.unwrap().unwrap().unwrap();
    assert!(dto.mem_total > 0, "mem_total should be positive");

    // ── 5. Subscribe server.logs, push entry, receive event ──────────────────

    let log_topic = topics::logs();
    let mut log_stream = core_client.subscribe_typed::<LogEntryDto>(&log_topic).await.unwrap();

    // Give the subscription a moment to register with the server
    tokio::time::sleep(Duration::from_millis(100)).await;

    mock.push_log(LogEntry {
        cursor: "test-cursor-b6".into(),
        ts_us: 99999,
        unit: None,
        priority: 6,
        message: "b6-test-log".into(),
    });

    let log_event = tokio::time::timeout(Duration::from_secs(3), log_stream.next()).await;
    assert!(log_event.is_ok(), "log event should arrive within 3s");
    let log_dto = log_event.unwrap().unwrap().unwrap();
    assert_eq!(log_dto.message, "b6-test-log");

    // ── Cleanup ───────────────────────────────────────────────────────────────

    for h in pump_handles {
        h.abort();
    }
    serve_handle.shutdown();
}
