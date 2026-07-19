pub mod api;
pub mod auth;
pub mod backend;
pub mod config;
pub mod diag;
pub mod lifecycle;
pub mod transport;

use std::sync::Arc;
use crate::backend::{SystemBackend, mock::MockBackend};

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

    // Step 0/1 backend = mock (real sysinfo/systemd = Step 3).
    let mock = Arc::new(MockBackend::new());
    let backend = Arc::new(SystemBackend::from_mock(mock));

    let service = lifecycle::build_service(backend);
    let handles = transport::start_listeners(&cfg, service).await?;
    for h in &handles {
        tracing::info!("listening on {}", h.local_addr());
    }

    lifecycle::shutdown_signal().await;
    tracing::info!("shutting down");
    for h in handles {
        h.shutdown();
    }
    Ok(())
}
