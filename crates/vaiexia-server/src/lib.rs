pub mod api;
pub mod audit;
pub mod auth;
pub mod backend;
pub mod config;
pub mod diag;
pub mod events;
pub mod lifecycle;
pub mod notify;
pub mod transport;

use std::sync::{Arc, Mutex};
use crate::audit::{AuditDecision, AuditEvent, AuditKind, DynAuditSink, FileAuditSink};
use crate::backend::assemble::assemble;
use crate::auth::bootstrap::BootstrapState;
use crate::auth::store::{FileStore, IdentityStore};

pub async fn run(config_path: Option<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cfg = config::load(config_path.as_deref())?;
    let config_warnings = config::validate(&cfg)?;
    for w in &config_warnings {
        tracing::warn!("config: {w}");
    }

    // ── Audit sink ─────────────────────────────────────────────────────────────
    let state_dir = &cfg.state_dir;
    std::fs::create_dir_all(state_dir)?;

    let (audit, writer_handle): (DynAuditSink, Option<std::thread::JoinHandle<()>>) =
        if cfg.audit.enabled {
            let audit_dir = cfg.audit.dir.clone()
                .unwrap_or_else(|| state_dir.join("audit"));
            std::fs::create_dir_all(&audit_dir)?;
            let audit_path = audit_dir.join("audit.jsonl");
            let (sink, writer) = FileAuditSink::new(
                cfg.audit.queue,
                audit_path,
                cfg.audit.max_bytes,
                cfg.audit.generations,
            );
            let handle = writer.spawn();
            (sink as DynAuditSink, Some(handle))
        } else {
            tracing::warn!("audit disabled — every auth/mutation decision will be unrecorded");
            (crate::audit::noop(), None)
        };

    // Config notice.
    audit.emit(
        AuditEvent::new(AuditKind::Config, AuditDecision::Ok, "system")
            .with_detail(format!(
                "config_path={} warnings={}",
                config_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<defaults>".to_string()),
                config_warnings.len(),
            )),
    );

    // Identity store.
    let identity_path = state_dir.join("identity.json");
    let store = Arc::new(FileStore::open(&identity_path)?);

    // Bootstrap code path (adjacent to the store, but not JSON).
    let code_path = state_dir.join("bootstrap.code");
    let bootstrap = Arc::new(Mutex::new(
        BootstrapState::begin(store.is_empty(), code_path),
    ));

    // Assemble backend from config (Auto/Mock/Real mode).
    let backend = Arc::new(assemble(&cfg, Arc::clone(&audit)).await?);

    // Emit Degraded notices for absent optional providers.
    if backend.services.is_none() {
        audit.emit(
            AuditEvent::new(AuditKind::Degraded, AuditDecision::Err, "system")
                .with_detail("provider=services reason=unavailable"),
        );
    }
    if backend.packages.is_none() {
        audit.emit(
            AuditEvent::new(AuditKind::Degraded, AuditDecision::Err, "system")
                .with_detail("provider=packages reason=unavailable"),
        );
    }
    if backend.logs.is_none() {
        audit.emit(
            AuditEvent::new(AuditKind::Degraded, AuditDecision::Err, "system")
                .with_detail("provider=logs reason=unavailable"),
        );
    }

    let (service, pump_handles) =
        lifecycle::build_service(backend, store, bootstrap, Arc::clone(&audit));
    let handles = transport::start_listeners(&cfg, service).await?;

    // Listener notices.
    for h in &handles {
        let addr = h.local_addr();
        tracing::info!("listening on {addr}");
        audit.emit(
            AuditEvent::new(AuditKind::Listener, AuditDecision::Ok, "system")
                .with_detail(format!("addr={addr} event=start")),
        );
    }

    // Daemon started.
    audit.emit(
        AuditEvent::new(AuditKind::Lifecycle, AuditDecision::Ok, "system")
            .with_detail("daemon started"),
    );
    notify::ready();

    lifecycle::shutdown_signal().await;
    notify::stopping();

    // Daemon shutting down.
    audit.emit(
        AuditEvent::new(AuditKind::Lifecycle, AuditDecision::Ok, "system")
            .with_detail("shutting down"),
    );
    for h in &handles {
        let addr = h.local_addr();
        audit.emit(
            AuditEvent::new(AuditKind::Listener, AuditDecision::Ok, "system")
                .with_detail(format!("addr={addr} event=stop")),
        );
    }

    tracing::info!("shutting down");
    for h in pump_handles {
        h.abort();
    }
    for h in handles {
        h.shutdown();
    }

    // Flush audit writer (bounded 3-second join).
    audit.shutdown();
    drop(audit);
    if let Some(jh) = writer_handle {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                let _ = jh.join();
            }),
        )
        .await;
        if result.is_err() {
            tracing::warn!("audit writer did not flush within 3 s — some events may be lost");
        }
    }

    Ok(())
}

/// Validate the effective config and print a summary. Exit-code contract:
/// Ok(()) = valid (warnings allowed), Err = invalid. Used by operators and by
/// the packaged unit's ExecStartPre gate.
pub fn check_config(config_path: Option<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load(config_path.as_deref())?;
    let warnings = config::validate(&cfg)?;
    println!("config OK");
    println!("  state_dir = {}", cfg.state_dir.display());
    println!("  audit     = enabled={} dir={}", cfg.audit.enabled,
        cfg.audit.dir.clone().unwrap_or_else(|| cfg.state_dir.join("audit")).display());
    for (i, l) in cfg.listeners.iter().enumerate() {
        println!("  listener[{i}] = {:?} {}", l.kind, l.bind);
    }
    for w in &warnings {
        println!("  warning: {w}");
    }
    Ok(())
}

/// Reset admin: clear accounts from the identity store and regenerate the
/// bootstrap code so a new admin can be claimed.
pub fn reset_admin(config_path: Option<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load(config_path.as_deref())?;
    let state_dir = &cfg.state_dir;
    let identity_path = state_dir.join("identity.json");

    if identity_path.exists() {
        // Load the store, rebuild it without accounts, then persist.
        // FileStore doesn't expose a remove-account API in Part A, so we
        // manipulate the JSON directly and atomically overwrite.
        let data = std::fs::read(&identity_path)?;
        let mut snap: serde_json::Value = serde_json::from_slice(&data)?;
        if let Some(obj) = snap.as_object_mut() {
            obj.insert("accounts".to_string(), serde_json::json!({}));
        }
        let json = serde_json::to_vec_pretty(&snap)?;
        let tmp = state_dir.join(".identity.reset.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &identity_path)?;
        tracing::info!(path = %identity_path.display(), "accounts cleared");
    }

    // Write a fresh bootstrap code.
    let code_path = state_dir.join("bootstrap.code");
    BootstrapState::begin(true, code_path.clone());
    tracing::info!(path = %code_path.display(), "bootstrap code regenerated for reset-admin");
    println!("reset-admin: bootstrap code written to {}", code_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a minimal TOML config to a temp file and return its path. `tag`
    /// must be unique per test — the tests run concurrently and would otherwise
    /// clobber each other's file.
    fn write_temp_config(tag: &str, toml: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vaiexia-check-cfg-{}-{tag}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();
        path
    }

    #[test]
    fn check_config_valid_http_config_returns_ok() {
        let path = write_temp_config(
            "valid-http",
            r#"
state_dir = "/tmp/vaiexia-test"
[[listeners]]
kind = "http"
bind = "127.0.0.1:7443"
"#,
        );
        let result = check_config(Some(path.clone()));
        let _ = std::fs::remove_file(&path);
        assert!(result.is_ok(), "valid config must return Ok: {result:?}");
    }

    #[test]
    fn check_config_obfs_listener_returns_err() {
        let path = write_temp_config(
            "obfs-listener",
            r#"
state_dir = "/tmp/vaiexia-test"
[[listeners]]
kind = "obfs-tcp"
bind = "127.0.0.1:9000"
"#,
        );
        let result = check_config(Some(path.clone()));
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "obfs listener config must return Err");
    }
}
