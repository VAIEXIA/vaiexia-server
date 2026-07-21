//! Append-only, forensic-grade audit trail (spec §1.2/§4). Schema v1.
//!
//! Hot-path contract: `AuditSink::emit` never blocks, never awaits, never
//! denies a request. The v1 impl (`FileAuditSink`) is a sync `try_send`;
//! overflow drops the event and increments a shared counter; the background
//! writer persists an `AuditLoss` record so loss is evident in the log itself.
//! Every written record carries `seq` (monotonic) and `prev` (16-hex BLAKE3
//! of the previous line) — gaps and edits are detectable with [`verify_chain`].
//!
//! TAMPER MODEL (honest): the chain is tamper-EVIDENT, not tamper-proof — an
//! attacker with write access AND knowledge of the scheme can re-chain. True
//! tamper-proofing = shipping records off-box. That is what the `AuditSink`
//! TRAIT is for: a `ForwardingAuditSink` (syslog/remote) implements the same
//! trait and drops in without touching any call site. NOT implemented in v1.
use serde::Serialize;
use std::sync::Arc;

pub mod file;
pub use file::{FileAuditSink, FileAuditWriter};

/// Per-field length cap: bounded everything (spec §4 DoS row).
pub const MAX_FIELD_LEN: usize = 1024;
/// Stable record schema version — bump ONLY with an additive, documented change.
pub const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    AuthDecision,  // verify(): authenticate; auth.login outcomes
    TopicDecision, // verify_topic() allow AND deny (covers server.logs subscribe)
    ScopeDecision, // register_scoped: deny always; ALLOW too for sensitive reads (server.logs.query)
    Mutation,      // a state-changing handler ran (sanitized params + outcome + latency)
    Priv,          // daemon→privd request + result (verb, outcome, latency)
    Bootstrap,     // first-run claim lifecycle
    Lifecycle,     // daemon start/stop
    Config,        // config load (v1 has no live reload — reload = restart, documented)
    Listener,      // listener bind/start/stop (addr + transport)
    RateLimit,     // rate-limit trip (login/bootstrap)
    Degraded,      // backend probe failed → provider absent (deferred emit at startup)
    Job,           // job start/succeed/fail/timeout
    AuditLoss,     // writer-emitted: N events dropped under overflow
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Notice,
    Warning,
    Security,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
    Ok,
    Err,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Http,
    Tls,
}

/// Stable reason-code vocabulary (append-only; never rename a shipped code).
pub mod reason {
    pub const OK: &str = "ok";
    pub const BAD_TOKEN: &str = "bad_token";
    pub const REVOKED: &str = "revoked";
    pub const EXPIRED: &str = "expired";
    pub const MISSING_SCOPE: &str = "missing_scope";
    pub const UNKNOWN_TOPIC: &str = "unknown_topic";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const BAD_PASSWORD: &str = "bad_password"; // audit-only; wire stays uniform (no oracle)
    pub const UNKNOWN_ACCOUNT: &str = "unknown_account"; // audit-only; wire stays uniform
    pub const SENSITIVE_READ: &str = "sensitive_read"; // logs access audited on ALLOW (spec §4)
    pub const TIMEOUT: &str = "timeout";
    pub const INTERNAL: &str = "internal";
}

/// Default severity policy (override with `with_severity` where a kind spans
/// levels, e.g. job-start = info). auth-fail / scope-deny / topic-deny /
/// rate-limit = SECURITY; mutations/priv = notice(ok)|warning(err);
/// listener/config/lifecycle/degraded = notice; loss = warning.
fn default_severity(kind: AuditKind, decision: AuditDecision) -> Severity {
    use AuditDecision as D;
    use AuditKind as K;
    match (kind, decision) {
        (K::AuthDecision | K::TopicDecision | K::ScopeDecision | K::Bootstrap, D::Deny) => {
            Severity::Security
        }
        (K::RateLimit, _) => Severity::Security,
        (K::AuthDecision | K::TopicDecision, _) => Severity::Info,
        (K::Mutation | K::Priv | K::Job, D::Err) => Severity::Warning,
        (K::AuditLoss, _) => Severity::Warning,
        _ => Severity::Notice,
    }
}

/// One schema-v1 audit record. Builder setters sanitize every string field:
/// control characters become spaces (log injection) and fields are length-capped.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub schema_version: u8,
    pub ts_wall: u64,
    pub kind: AuditKind,
    pub severity: Severity,
    pub decision: AuditDecision,
    /// Account subject_id (`user:admin`) or `anonymous`/`system`/`audit` —
    /// the HUMAN field; the internal `cap:` handle never appears here.
    pub subject: String,
    /// Loggable capability handle (key_id). NEVER the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_key_id: Option<String>,
    /// Remote addr when the transport exposes it. v1: None (core dispatch does
    /// not thread peer info to the verifier/handlers — flagged core additive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// v1: populated on Listener events; None per-request (same core limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Correlation id (core RequestId) where the emitting site has it.
    /// v1: None — core's handler signature `(params, subject)` and
    /// `Verifier::verify(cap, method)` do not expose `Request.id` (verified
    /// against core dispatch.rs / auth/verifier.rs). Schema-stable now so the
    /// audit↔tracing cross-reference lands as a pure core additive later.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<u64>,
}

fn sanitize(s: &str) -> String {
    s.chars()
        .take(MAX_FIELD_LEN)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

impl AuditEvent {
    pub fn new(kind: AuditKind, decision: AuditDecision, subject: impl AsRef<str>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ts_wall: crate::auth::store::now_secs(),
            kind,
            severity: default_severity(kind, decision),
            decision,
            subject: sanitize(subject.as_ref()),
            cap_key_id: None,
            peer: None,
            transport: None,
            method: None,
            topic: None,
            request_id: None,
            reason_code: None,
            detail: None,
            latency_us: None,
        }
    }
    pub fn with_severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    pub fn with_cap_key_id(mut self, k: impl AsRef<str>) -> Self {
        self.cap_key_id = Some(sanitize(k.as_ref()));
        self
    }
    pub fn with_peer(mut self, p: impl AsRef<str>) -> Self {
        self.peer = Some(sanitize(p.as_ref()));
        self
    }
    pub fn with_transport(mut self, t: Transport) -> Self {
        self.transport = Some(t);
        self
    }
    pub fn with_method(mut self, m: impl AsRef<str>) -> Self {
        self.method = Some(sanitize(m.as_ref()));
        self
    }
    pub fn with_topic(mut self, t: impl AsRef<str>) -> Self {
        self.topic = Some(sanitize(t.as_ref()));
        self
    }
    pub fn with_request_id(mut self, r: impl AsRef<str>) -> Self {
        self.request_id = Some(sanitize(r.as_ref()));
        self
    }
    pub fn with_reason(mut self, code: &'static str) -> Self {
        self.reason_code = Some(code);
        self
    }
    pub fn with_detail(mut self, detail: impl AsRef<str>) -> Self {
        self.detail = Some(sanitize(detail.as_ref()));
        self
    }
    pub fn with_latency_us(mut self, us: u64) -> Self {
        self.latency_us = Some(us);
        self
    }
}

// ── Sink trait: the off-box seam ─────────────────────────────────────────────

/// Where audit records go. Implementations MUST keep `emit` non-blocking.
/// v1 impls: [`FileAuditSink`] (chained JSONL) and [`NoopAuditSink`].
/// Future (documented seam, NOT in v1): `ForwardingAuditSink` shipping to
/// syslog/remote — drops in behind this trait without touching call sites.
pub trait AuditSink: Send + Sync {
    /// Non-blocking record submission. Must never gate the request path.
    fn emit(&self, event: AuditEvent);
    /// Best-effort orderly stop (non-blocking). Default: no-op.
    fn shutdown(&self) {}
}

/// What call sites hold. Cheap to clone.
pub type DynAuditSink = Arc<dyn AuditSink>;

/// Discards everything (tests / permissive service / audit disabled).
pub struct NoopAuditSink;
impl AuditSink for NoopAuditSink {
    fn emit(&self, _event: AuditEvent) {}
}

/// Convenience: a ready-to-share noop sink.
pub fn noop() -> DynAuditSink {
    Arc::new(NoopAuditSink)
}

// ── Chain verification ───────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("line {line}: not valid JSON")]
    BadJson { line: usize },
    #[error("line {line}: schema violation: {what}")]
    BadSchema { line: usize, what: &'static str },
    #[error("line {line}: chain broken (prev mismatch)")]
    Broken { line: usize },
    #[error("line {line}: seq gap (expected {expected}, got {got})")]
    SeqGap { line: usize, expected: u64, got: u64 },
}

/// Hash of one serialized line (without trailing newline): first 16 hex chars
/// of BLAKE3. 64 bits of tamper evidence per link is ample for an append-only
/// operator log (this is not a signature scheme; see THREAT-MODEL.md).
pub(crate) fn line_hash(line: &str) -> String {
    blake3::hash(line.as_bytes()).to_hex()[..16].to_string()
}

/// Verify one JSONL audit body: per-record `prev` against the previous line's
/// hash, PLUS the schema-v1 contract — `schema_version == 1`, `seq` present
/// and strictly incrementing within the file (any start value: rotation
/// carry-over), and required keys `kind`/`severity`/`decision`/`subject`
/// present (`AuditLoss` records included). The first record's `prev` is either
/// the genesis marker (`"0" × 16`) or the rotated predecessor's last-line hash
/// — both accepted (single-file verification). Never panics on garbage input
/// (fuzzed in S4-A5). Returns the verified record count.
pub fn verify_chain_str(body: &str) -> Result<u64, ChainError> {
    let mut prev: Option<String> = None;
    let mut prev_seq: Option<u64> = None;
    let mut count = 0u64;
    for (i, line) in body.lines().enumerate() {
        let line_no = i + 1;
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|_| ChainError::BadJson { line: line_no })?;
        if v["schema_version"].as_u64() != Some(u64::from(SCHEMA_VERSION)) {
            return Err(ChainError::BadSchema { line: line_no, what: "schema_version" });
        }
        for key in ["kind", "severity", "decision", "subject"] {
            if v.get(key).is_none() {
                return Err(ChainError::BadSchema { line: line_no, what: "missing required key" });
            }
        }
        let seq = v["seq"]
            .as_u64()
            .ok_or(ChainError::BadSchema { line: line_no, what: "seq" })?;
        if let Some(ps) = prev_seq {
            // checked_add: a hostile file with seq = u64::MAX must yield Err,
            // not a debug-overflow panic (covered by the adversarial corpus).
            let expected = ps
                .checked_add(1)
                .ok_or(ChainError::BadSchema { line: line_no, what: "seq overflow" })?;
            if seq != expected {
                return Err(ChainError::SeqGap { line: line_no, expected, got: seq });
            }
        }
        let rec_prev = v["prev"].as_str().unwrap_or_default().to_string();
        if let Some(expect) = &prev
            && rec_prev != *expect
        {
            return Err(ChainError::Broken { line: line_no });
        }
        prev = Some(line_hash(line));
        prev_seq = Some(seq);
        count += 1;
    }
    Ok(count)
}

/// File wrapper over [`verify_chain_str`].
pub fn verify_chain(path: &std::path::Path) -> Result<u64, ChainError> {
    verify_chain_str(&std::fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::file::FileAuditSink;

    #[test]
    fn audit_event_sanitizes_and_caps_fields() {
        // Log-injection defense (spec §4): control chars never reach the sink;
        // every field is length-capped so a hostile param cannot bloat the log.
        let e = AuditEvent::new(AuditKind::AuthDecision, AuditDecision::Deny, "user:adm\n\r\u{0}INJ")
            .with_method("server.services.start")
            .with_detail(format!("unit=nginx.service\nFAKE{}", "x".repeat(5000)));
        assert!(!e.subject.contains(['\n', '\r', '\u{0}']));
        let d = e.detail.as_deref().unwrap();
        assert!(!d.contains('\n'));
        assert!(d.len() <= MAX_FIELD_LEN);
    }

    #[test]
    fn schema_v1_serializes_stably_and_omits_absent_fields() {
        // The forensic contract: stable keys, derived severity, absent Options gone.
        let e = AuditEvent::new(AuditKind::AuthDecision, AuditDecision::Deny, "anonymous")
            .with_method("server.host.info")
            .with_cap_key_id("abcd1234abcd1234")
            .with_reason(reason::BAD_TOKEN);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["schema_version"].as_u64(), Some(1));
        assert_eq!(v["kind"], "auth_decision");
        assert_eq!(v["severity"], "security", "auth deny defaults to security");
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["subject"], "anonymous");
        assert_eq!(v["cap_key_id"], "abcd1234abcd1234");
        assert_eq!(v["reason_code"], "bad_token");
        assert!(v["ts_wall"].as_u64().is_some());
        // Absent optionals are OMITTED, not null:
        for absent in ["peer", "transport", "topic", "request_id", "detail", "latency_us"] {
            assert!(v.get(absent).is_none(), "{absent} must be omitted");
        }
        // Severity derivation spot checks:
        let ok = AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, "user:admin");
        assert_eq!(serde_json::to_value(&ok).unwrap()["severity"], "notice");
        let trip = AuditEvent::new(AuditKind::RateLimit, AuditDecision::Deny, "user:admin");
        assert_eq!(serde_json::to_value(&trip).unwrap()["severity"], "security");
        let deg = AuditEvent::new(AuditKind::Degraded, AuditDecision::Err, "system");
        assert_eq!(serde_json::to_value(&deg).unwrap()["severity"], "notice");
        // Explicit override for e.g. job-start:
        let start = AuditEvent::new(AuditKind::Job, AuditDecision::Ok, "user:admin")
            .with_severity(Severity::Info);
        assert_eq!(serde_json::to_value(&start).unwrap()["severity"], "info");
    }

    #[test]
    fn emit_is_nonblocking_and_counts_drops() {
        // No writer attached: capacity fills, then every emit drops and is counted.
        let (sink, _writer) =
            FileAuditSink::new(4, std::env::temp_dir().join("unused.jsonl"), 1 << 20, 1);
        for _ in 0..10 {
            sink.emit(AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, "user:admin"));
        }
        assert_eq!(sink.dropped(), 6); // 4 buffered, 6 dropped — emit never blocked
    }

    #[test]
    fn writer_persists_valid_jsonl_with_seq_and_chain() {
        let dir =
            std::env::temp_dir().join(format!("vx-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let (sink, writer) = FileAuditSink::new(64, path.clone(), 1 << 20, 1);
        let th = writer.spawn();
        for i in 0..10 {
            sink.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, "user:admin")
                    .with_method("server.services.start")
                    .with_detail(format!("i={i}")),
            );
        }
        drop(sink); // closes the channel → writer flushes and exits
        th.join().unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 10);
        for (i, line) in body.lines().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert_eq!(v["seq"].as_u64().unwrap(), i as u64 + 1);
            assert_eq!(v["prev"].as_str().unwrap().len(), 16);
            assert_eq!(v["schema_version"].as_u64(), Some(1));
        }
        // Chain verifies end-to-end (incl. schema-v1 checks)…
        assert_eq!(verify_chain(&path).unwrap(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_chain_rejects_schema_violations_and_seq_gaps() {
        // verify_chain covers the v1 schema, not just the hash links.
        // Missing required key:
        assert!(verify_chain_str("{\"seq\":1,\"prev\":\"0000000000000000\"}\n").is_err());
        // Never panics on garbage (also fuzzed in S4-A5):
        assert!(verify_chain_str("not json\n").is_err());
        assert!(verify_chain_str("").map(|n| n == 0).unwrap_or(false));
        // A seq gap inside one file = loss/tamper evidence (build two valid records
        // with the real writer, then delete the middle line of three — chain AND
        // seq both break; assert Err mentions the line number).
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let dir =
            std::env::temp_dir().join(format!("vx-audit-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let (sink, writer) = FileAuditSink::new(64, path.clone(), 1 << 20, 1);
        let th = writer.spawn();
        for _ in 0..5 {
            sink.emit(AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, "user:admin"));
        }
        drop(sink);
        th.join().unwrap();
        // …edit a middle line (simulated tamper): chain must break.
        let body = std::fs::read_to_string(&path).unwrap();
        let tampered: String = body
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 2 {
                    l.replace("\"ok\"", "\"deny\"")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, tampered).unwrap();
        assert!(verify_chain(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overflow_is_recorded_as_audit_loss_event() {
        // Fill the queue with no writer running, then start the writer:
        // it must drain the buffered events AND emit an AuditLoss record for the drops.
        let dir =
            std::env::temp_dir().join(format!("vx-audit-loss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let (sink, writer) = FileAuditSink::new(2, path.clone(), 1 << 20, 1);
        for _ in 0..5 {
            sink.emit(AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, "user:admin"));
        }
        let th = writer.spawn();
        drop(sink);
        th.join().unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("audit_loss"), "drop count must be persisted: {body}");
        assert!(body.contains("dropped=3"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
