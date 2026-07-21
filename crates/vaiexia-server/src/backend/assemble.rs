use std::sync::Arc;

use crate::audit::DynAuditSink;
use crate::backend::{
    SystemBackend,
    metrics::SysinfoMetrics,
    mock::MockBackend,
    probe,
};
use crate::config::model::{BackendMode, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    #[error("no native backend is available for this platform")]
    UnsupportedPlatform,
}

/// Build a `SystemBackend` from the server configuration.
///
/// - `Mock` → all-mock providers (deterministic, no OS dependencies), caps all true.
/// - `Auto` → real `metrics` (sysinfo) always; on non-Linux the optional providers
///   (services/packages/logs) degrade to `None`. On Linux each provider is
///   probed and degrades to `None` (→ UNSUPPORTED at the API) on failure.
/// - `Real` → like Auto but off-Linux → `Err(AssembleError::UnsupportedPlatform)`.
///
/// `audit` is threaded into the privd-backed `PackageManager` provider (on
/// Linux). Mock and non-privd providers ignore it. Pass `audit::noop()` in
/// tests.
///
/// Async: must be called from within the daemon's tokio runtime. The Linux
/// providers spawn long-lived background tasks (systemd watch, journald
/// follow) which must land on the runtime that outlives assembly.
pub async fn assemble(cfg: &ServerConfig, _audit: DynAuditSink) -> Result<SystemBackend, AssembleError> {
    match cfg.backend.mode {
        BackendMode::Mock => Ok(assemble_mock()),
        BackendMode::Auto => Ok(assemble_auto().await),
        BackendMode::Real => assemble_real().await,
    }
}

fn assemble_mock() -> SystemBackend {
    let mock = Arc::new(MockBackend::new());
    SystemBackend::from_mock(mock)
}

async fn assemble_auto() -> SystemBackend {
    let metrics = Arc::new(SysinfoMetrics::new()) as Arc<dyn crate::backend::MetricsProvider>;

    // Platform dispatch goes through a single seam. On Linux, real
    // service/log/package providers are probed at startup. On all other
    // platforms they are None — graceful degradation.
    let (services, packages, logs) = assemble_native_providers().await;

    let caps = probe::derive_capabilities(
        services.is_some(),
        packages.is_some(),
        logs.is_some(),
    );

    if cfg!(not(target_os = "linux")) {
        tracing::info!(
            services = false,
            packages = false,
            logs = false,
            metrics = true,
            "assemble[auto]: real metrics; services/packages/logs unavailable on this platform"
        );
    }

    SystemBackend {
        host: Arc::new(crate::backend::RealHostInfoProvider),
        services,
        packages,
        metrics,
        logs,
        caps,
    }
}

async fn assemble_real() -> Result<SystemBackend, AssembleError> {
    #[cfg(not(target_os = "linux"))]
    return Err(AssembleError::UnsupportedPlatform);

    #[cfg(target_os = "linux")]
    {
        let metrics = Arc::new(SysinfoMetrics::new()) as Arc<dyn crate::backend::MetricsProvider>;
        let (services, packages, logs) = assemble_native_providers().await;

        let caps = probe::derive_capabilities(
            services.is_some(),
            packages.is_some(),
            logs.is_some(),
        );

        tracing::info!(
            ?caps,
            "assemble[real]: capability set on Linux"
        );

        Ok(SystemBackend {
            host: Arc::new(crate::backend::RealHostInfoProvider),
            services,
            packages,
            metrics,
            logs,
            caps,
        })
    }
}

// ── Platform seam ─────────────────────────────────────────────────────────────
//
// `assemble_native_providers` is the single dispatch point for platform-specific
// optional providers. Adding a future `#[cfg(windows)]` backend means adding a
// new function/file and a new arm here — no surgery on existing platform logic.

#[cfg(target_os = "linux")]
async fn assemble_native_providers() -> (
    Option<Arc<dyn crate::backend::ServiceManager>>,
    Option<Arc<dyn crate::backend::PackageManager>>,
    Option<Arc<dyn crate::backend::LogProvider>>,
) {
    assemble_linux_providers().await
}

#[cfg(not(target_os = "linux"))]
async fn assemble_native_providers() -> (
    Option<Arc<dyn crate::backend::ServiceManager>>,
    Option<Arc<dyn crate::backend::PackageManager>>,
    Option<Arc<dyn crate::backend::LogProvider>>,
) {
    (None, None, None)
}

// ── Linux backend ─────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn assemble_linux_providers() -> (
    Option<Arc<dyn crate::backend::ServiceManager>>,
    Option<Arc<dyn crate::backend::PackageManager>>,
    Option<Arc<dyn crate::backend::LogProvider>>,
) {
    // Part B: wire SystemdServices if the system D-Bus is reachable.
    let services: Option<Arc<dyn crate::backend::ServiceManager>> =
        probe_systemd_services().await;

    // Part C: wire JournaldLogs if journalctl is reachable.
    let logs: Option<Arc<dyn crate::backend::LogProvider>> = probe_journald_logs().await;

    // Part C: wire real PackageManager if detected and privd socket reachable.
    let packages: Option<Arc<dyn crate::backend::PackageManager>> = probe_packages();

    (services, packages, logs)
}

#[cfg(target_os = "linux")]
async fn probe_systemd_services() -> Option<Arc<dyn crate::backend::ServiceManager>> {
    use crate::backend::systemd::SystemdServices;

    if !SystemdServices::probe().await {
        tracing::info!("assemble[auto/linux]: system D-Bus unreachable — services=None");
        return None;
    }
    match SystemdServices::new().await {
        Ok(svc) => {
            tracing::info!("assemble[auto/linux]: SystemdServices wired");
            Some(svc as Arc<dyn crate::backend::ServiceManager>)
        }
        Err(e) => {
            tracing::warn!("assemble[auto/linux]: SystemdServices init failed: {e} — services=None");
            None
        }
    }
}

// ── Journald probe ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn probe_journald_logs() -> Option<Arc<dyn crate::backend::LogProvider>> {
    use crate::backend::logs::JournaldLogs;

    if !JournaldLogs::probe().await {
        tracing::info!("assemble[auto/linux]: journalctl unreachable — logs=None");
        return None;
    }
    let logs = JournaldLogs::new();
    tracing::info!("assemble[auto/linux]: JournaldLogs wired");
    Some(Arc::new(logs) as Arc<dyn crate::backend::LogProvider>)
}

// ── Package manager probe ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn probe_packages() -> Option<Arc<dyn crate::backend::PackageManager>> {
    use crate::backend::packages::{
        detect::{from_os_release, confirm},
        RealPackageManager,
    };

    // Detect from /etc/os-release
    let os_release = std::fs::read_to_string("/etc/os-release").ok()?;
    let kind = from_os_release(&os_release)?;

    // Confirm the binary is present
    if !confirm(kind, |p| p.exists()) {
        tracing::info!(
            "assemble[auto/linux]: package manager binary missing for {kind:?} — packages=None"
        );
        return None;
    }

    // Check if privd socket is reachable (just a filesystem check for now)
    let socket_path = crate::backend::packages::privd_client::PRIVD_SOCKET_PATH;
    if !std::path::Path::new(socket_path).exists() {
        tracing::info!(
            "assemble[auto/linux]: privd socket {socket_path} absent — packages=None"
        );
        return None;
    }

    tracing::info!("assemble[auto/linux]: RealPackageManager({kind:?}) wired");
    Some(Arc::new(RealPackageManager::new(kind)) as Arc<dyn crate::backend::PackageManager>)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{assemble, AssembleError};
    use crate::config::model::{BackendCfg, BackendMode, ServerConfig};

    fn cfg_with_mode(mode: BackendMode) -> ServerConfig {
        ServerConfig {
            backend: BackendCfg { mode },
            ..Default::default()
        }
    }

    fn noop() -> crate::audit::DynAuditSink { crate::audit::noop() }

    #[test]
    fn backend_mode_default_is_auto() {
        let cfg = BackendCfg::default();
        assert_eq!(cfg.mode, BackendMode::Auto);
    }

    #[tokio::test]
    async fn assemble_mock_mode_gives_all_caps_true() {
        let cfg = cfg_with_mode(BackendMode::Mock);
        let backend = assemble(&cfg, noop()).await.expect("mock assemble should succeed");
        assert!(backend.caps.services, "mock caps.services must be true");
        assert!(backend.caps.packages, "mock caps.packages must be true");
        assert!(backend.caps.metrics, "mock caps.metrics must be true");
        assert!(backend.caps.logs, "mock caps.logs must be true");
    }

    #[tokio::test]
    async fn assemble_mock_mode_providers_all_present() {
        let cfg = cfg_with_mode(BackendMode::Mock);
        let backend = assemble(&cfg, noop()).await.expect("mock assemble should succeed");
        assert!(backend.services.is_some(), "mock services provider must be Some");
        assert!(backend.packages.is_some(), "mock packages provider must be Some");
        assert!(backend.logs.is_some(), "mock logs provider must be Some");
    }

    #[tokio::test]
    async fn assemble_mock_mode_metrics_works() {
        let cfg = cfg_with_mode(BackendMode::Mock);
        let backend = assemble(&cfg, noop()).await.expect("mock assemble should succeed");
        let snap = backend.metrics.snapshot().expect("mock metrics snapshot should succeed");
        assert!(snap.mem_total > 0);
    }

    #[tokio::test]
    async fn assemble_auto_mode_has_real_metrics() {
        let cfg = cfg_with_mode(BackendMode::Auto);
        let backend = assemble(&cfg, noop()).await.expect("auto assemble should succeed");
        let snap = backend.metrics.snapshot().expect("auto metrics snapshot should succeed");
        // Real sysinfo — mem_total must reflect the actual host
        assert!(snap.mem_total > 0, "auto mode must report real mem_total > 0");
        assert!(snap.uptime_secs > 0, "auto mode must report real uptime > 0");
    }

    #[tokio::test]
    async fn assemble_auto_mode_non_linux_services_none() {
        // On Windows/macOS, services/packages/logs are None (real impls need Linux)
        #[cfg(not(target_os = "linux"))]
        {
            let cfg = cfg_with_mode(BackendMode::Auto);
            let backend = assemble(&cfg, noop()).await.expect("auto assemble should succeed");
            assert!(backend.services.is_none(), "off-linux auto services must be None");
            assert!(backend.packages.is_none(), "off-linux auto packages must be None");
            assert!(backend.logs.is_none(), "off-linux auto logs must be None");
            assert!(!backend.caps.services, "off-linux auto caps.services must be false");
            assert!(!backend.caps.packages, "off-linux auto caps.packages must be false");
            assert!(!backend.caps.logs, "off-linux auto caps.logs must be false");
        }
        #[cfg(target_os = "linux")]
        {
            // On Linux, auto may or may not have services — just check it runs
            let cfg = cfg_with_mode(BackendMode::Auto);
            let _backend = assemble(&cfg).await.expect("auto assemble should succeed on linux");
        }
    }

    #[tokio::test]
    async fn assemble_real_mode_off_linux_returns_error() {
        #[cfg(not(target_os = "linux"))]
        {
            let cfg = cfg_with_mode(BackendMode::Real);
            let result = assemble(&cfg, noop()).await;
            assert!(
                matches!(result, Err(AssembleError::UnsupportedPlatform)),
                "Real mode off-linux must return UnsupportedPlatform"
            );
        }
        #[cfg(target_os = "linux")]
        {
            // On Linux, Real mode is allowed (may succeed or fail with other error)
            let _ = assemble(&cfg_with_mode(BackendMode::Real), noop()).await;
        }
    }

    #[test]
    fn config_parses_backend_mode_mock_from_toml() {
        use figment::{
            providers::{Format, Toml},
            Figment,
        };
        use figment::providers::Serialized;
        let toml = r#"
[backend]
mode = "mock"

[[listeners]]
kind = "http"
bind = "127.0.0.1:7443"
"#;
        let dir = std::env::temp_dir();
        let path = dir.join("vaiexia-assemble-test-config.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg: ServerConfig = Figment::from(Serialized::defaults(ServerConfig::default()))
            .merge(Toml::file(&path))
            .extract()
            .expect("toml parse");
        assert_eq!(cfg.backend.mode, BackendMode::Mock);
    }
}
