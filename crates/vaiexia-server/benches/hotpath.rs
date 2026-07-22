//! Criterion benches for the two hot paths every request touches: audit
//! emission and capability verification.
//!
//! Deliberately NO absolute-time assertions — those would be machine-dependent
//! lies. The regression gate is the baseline recorded in the commit message
//! plus the `verify_does_no_disk_io` invariant test in the lib suite; these
//! benches exist to make a regression *visible* when someone reruns them.

use std::path::PathBuf;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use vaiexia_core::auth::Verifier;
use vaiexia_core::protocol::Method;

use vaiexia_server::audit::{
    reason, AuditDecision, AuditEvent, AuditKind, AuditSink, FileAuditSink,
};
use vaiexia_server::auth::store::{now_secs, CapabilityRecord, FileStore, IdentityStore};
use vaiexia_server::auth::token::{mint, MintedCapability};
use vaiexia_server::auth::DaemonVerifier;

/// Unique temp path per fixture — benches may run alongside the test suite.
fn temp_path(suffix: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "vaiexia-bench-{suffix}-{}-{}.{ext}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    p
}

/// The realistic per-request event shape: kind + decision + subject, plus the
/// three fields every method-dispatch record carries.
fn request_event() -> AuditEvent {
    AuditEvent::new(AuditKind::ScopeDecision, AuditDecision::Deny, "user:admin")
        .with_method("server.services.restart")
        .with_reason(reason::MISSING_SCOPE)
        .with_cap_key_id("abcdefghij123456")
}

/// Event construction alone (no sink). Splits the builder cost — timestamp,
/// severity derivation and the per-field `sanitize` allocations — away from
/// submission, so a regression in either is attributable.
fn bench_audit_event_build(c: &mut Criterion) {
    c.bench_function("audit_event_build", |b| {
        b.iter(|| std::hint::black_box(request_event()))
    });
}

/// Emission into a live sink whose writer thread is draining the queue — the
/// normal production path.
fn bench_audit_emit(c: &mut Criterion) {
    let path = temp_path("audit-emit", "jsonl");
    let (sink, writer) = FileAuditSink::new(1024, path.clone(), 64 * 1024 * 1024, 2);
    let handle = writer.spawn();

    c.bench_function("audit_emit", |b| {
        b.iter(|| sink.emit(std::hint::black_box(request_event())))
    });

    sink.shutdown();
    let _ = handle.join();
    let _ = std::fs::remove_file(&path);
}

/// Emission into a tiny sink with NO writer draining it: the queue is full
/// from the second event onward, so this measures the overflow/drop path.
/// Proves overflow is cheap, not merely non-blocking.
fn bench_audit_emit_saturated(c: &mut Criterion) {
    let path = temp_path("audit-saturated", "jsonl");
    let (sink, _writer) = FileAuditSink::new(4, path.clone(), 64 * 1024 * 1024, 2);
    // `_writer` is never spawned: the channel never drains.

    c.bench_function("audit_emit_saturated", |b| {
        b.iter(|| sink.emit(std::hint::black_box(request_event())))
    });

    assert!(sink.dropped() > 0, "saturated bench must exercise the drop path");
    let _ = std::fs::remove_file(&path);
}

/// A store holding one valid capability, plus the minted token to present.
fn store_with_cap(path: &PathBuf) -> (Arc<dyn IdentityStore>, MintedCapability) {
    let store = Arc::new(FileStore::open(path).unwrap()) as Arc<dyn IdentityStore>;
    let minted = mint();
    store
        .add_capability(CapabilityRecord {
            key_id: minted.key_id.clone(),
            secret_hash: minted.secret_hash,
            subject_id: "user:admin".to_string(),
            scopes: vec!["server.read".to_string(), "server.manage".to_string()],
            label: "bench".to_string(),
            created_at: now_secs(),
            expires_at: None,
            revoked: false,
            last_used: None,
        })
        .unwrap();
    (store, minted)
}

/// Token parse + snapshot lookup + BLAKE3 secret compare + scope-set build.
/// After the retention work this path does ZERO disk I/O (the `last_used`
/// write is debounced) — the bench exists to keep it that way.
fn bench_verifier_verify(c: &mut Criterion) {
    let path = temp_path("verifier", "json");
    let (store, minted) = store_with_cap(&path);
    let verifier = DaemonVerifier::new(store, vaiexia_server::audit::noop());
    let method = Method::new("server.host.info").unwrap();

    c.bench_function("verifier_verify", |b| {
        b.iter(|| {
            verifier
                .verify(Some(std::hint::black_box(&minted.capability)), &method)
                .expect("valid capability must verify")
        })
    });

    let _ = std::fs::remove_file(&path);
}

criterion_group!(
    hotpath,
    bench_audit_event_build,
    bench_audit_emit,
    bench_audit_emit_saturated,
    bench_verifier_verify
);
criterion_main!(hotpath);
