pub mod api;
pub mod auth;
pub mod backend;
pub mod config;
pub mod diag;
pub mod events;
pub mod lifecycle;
pub mod transport;

use std::sync::{Arc, Mutex};
use crate::backend::{SystemBackend, mock::MockBackend};
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
    for w in config::validate(&cfg)? {
        tracing::warn!("config: {w}");
    }

    // Identity store.
    let state_dir = &cfg.state_dir;
    std::fs::create_dir_all(state_dir)?;
    let identity_path = state_dir.join("identity.json");
    let store = Arc::new(FileStore::open(&identity_path)?);

    // Bootstrap code path (adjacent to the store, but not JSON).
    let code_path = state_dir.join("bootstrap.code");
    let bootstrap = Arc::new(Mutex::new(
        BootstrapState::begin(store.is_empty(), code_path),
    ));

    // Step 0/1 backend = mock (real sysinfo/systemd = Step 3).
    let mock = Arc::new(MockBackend::new());
    let backend = Arc::new(SystemBackend::from_mock(mock));

    let (service, pump_handles) = lifecycle::build_service(backend, store, bootstrap);
    let handles = transport::start_listeners(&cfg, service).await?;
    for h in &handles {
        tracing::info!("listening on {}", h.local_addr());
    }

    lifecycle::shutdown_signal().await;
    tracing::info!("shutting down");
    for h in pump_handles {
        h.abort();
    }
    for h in handles {
        h.shutdown();
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
