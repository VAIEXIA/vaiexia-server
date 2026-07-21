use std::sync::Arc;

use crate::backend::{
    SystemBackend,
    metrics::SysinfoMetrics,
    mock::MockBackend,
    probe,
};
use crate::config::model::{BackendMode, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    #[error("real backends require Linux; this platform is not supported")]
    UnsupportedPlatform,
}

/// Build a `SystemBackend` from the server configuration.
///
/// - `Mock` → all-mock providers (deterministic, no OS dependencies), caps all true.
/// - `Auto` → real `metrics` (sysinfo) always; on non-Linux the optional providers
///   (services/packages/logs) degrade to `None`. On Linux, real impls land
///   in Parts B/C — TODO placeholders return `None` until those parts ship.
/// - `Real` → like Auto but off-Linux → `Err(AssembleError::UnsupportedPlatform)`.
pub fn assemble(cfg: &ServerConfig) -> Result<SystemBackend, AssembleError> {
    match cfg.backend.mode {
        BackendMode::Mock => Ok(assemble_mock()),
        BackendMode::Auto => Ok(assemble_auto()),
        BackendMode::Real => assemble_real(),
    }
}

fn assemble_mock() -> SystemBackend {
    let mock = Arc::new(MockBackend::new());
    SystemBackend::from_mock(mock)
}

fn assemble_auto() -> SystemBackend {
    let metrics = Arc::new(SysinfoMetrics::new()) as Arc<dyn crate::backend::MetricsProvider>;

    // On Linux, real service/log/package providers will be wired in Parts B/C.
    // Off-Linux (Windows, macOS) they are None — graceful degradation.
    #[cfg(target_os = "linux")]
    let (services, packages, logs) = assemble_linux_providers_auto();

    #[cfg(not(target_os = "linux"))]
    let (services, packages, logs) = (None, None, None);

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

fn assemble_real() -> Result<SystemBackend, AssembleError> {
    #[cfg(not(target_os = "linux"))]
    return Err(AssembleError::UnsupportedPlatform);

    #[cfg(target_os = "linux")]
    {
        // On Linux, Real mode would attempt all providers and fail if any are unavailable.
        // Until Parts B/C land, the real providers are TODO placeholders returning None.
        // When real probes are wired (B2/C4), a failed probe here becomes an error.
        let metrics = Arc::new(SysinfoMetrics::new()) as Arc<dyn crate::backend::MetricsProvider>;
        let (services, packages, logs) = assemble_linux_providers_auto();

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

#[cfg(target_os = "linux")]
fn assemble_linux_providers_auto() -> (
    Option<Arc<dyn crate::backend::ServiceManager>>,
    Option<Arc<dyn crate::backend::PackageManager>>,
    Option<Arc<dyn crate::backend::LogProvider>>,
) {
    // Part B: wire SystemdServices if the system D-Bus is reachable.
    let services: Option<Arc<dyn crate::backend::ServiceManager>> =
        probe_systemd_services_blocking();

    // Part C: wire JournaldLogs if journalctl is reachable.
    let logs: Option<Arc<dyn crate::backend::LogProvider>> = probe_journald_logs_blocking();

    // Part C: wire real PackageManager if detected and privd socket reachable.
    let packages: Option<Arc<dyn crate::backend::PackageManager>> =
        probe_packages_blocking();

    (services, packages, logs)
}

#[cfg(target_os = "linux")]
fn probe_systemd_services_blocking() -> Option<Arc<dyn crate::backend::ServiceManager>> {
    use crate::backend::systemd::SystemdServices;
    // We need a short-lived tokio runtime to run the async probe + constructor.
    // assemble() is called from a sync context (before the main runtime starts).
    // If we are already inside an async context this would panic — guard against it.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    rt.block_on(async {
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
    })
}

// ── Journald probe ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn probe_journald_logs_blocking() -> Option<Arc<dyn crate::backend::LogProvider>> {
    use crate::backend::logs::JournaldLogs;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    rt.block_on(async {
        if !JournaldLogs::probe().await {
            tracing::info!("assemble[auto/linux]: journalctl unreachable — logs=None");
            return None;
        }
        let logs = JournaldLogs::new();
        tracing::info!("assemble[auto/linux]: JournaldLogs wired");
        Some(Arc::new(logs) as Arc<dyn crate::backend::LogProvider>)
    })
}

// ── Package manager probe ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn probe_packages_blocking() -> Option<Arc<dyn crate::backend::PackageManager>> {
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

    #[test]
    fn backend_mode_default_is_auto() {
        let cfg = BackendCfg::default();
        assert_eq!(cfg.mode, BackendMode::Auto);
    }

    #[test]
    fn assemble_mock_mode_gives_all_caps_true() {
        let cfg = cfg_with_mode(BackendMode::Mock);
        let backend = assemble(&cfg).expect("mock assemble should succeed");
        assert!(backend.caps.services, "mock caps.services must be true");
        assert!(backend.caps.packages, "mock caps.packages must be true");
        assert!(backend.caps.metrics, "mock caps.metrics must be true");
        assert!(backend.caps.logs, "mock caps.logs must be true");
    }

    #[test]
    fn assemble_mock_mode_providers_all_present() {
        let cfg = cfg_with_mode(BackendMode::Mock);
        let backend = assemble(&cfg).expect("mock assemble should succeed");
        assert!(backend.services.is_some(), "mock services provider must be Some");
        assert!(backend.packages.is_some(), "mock packages provider must be Some");
        assert!(backend.logs.is_some(), "mock logs provider must be Some");
    }

    #[test]
    fn assemble_mock_mode_metrics_works() {
        let cfg = cfg_with_mode(BackendMode::Mock);
        let backend = assemble(&cfg).expect("mock assemble should succeed");
        let snap = backend.metrics.snapshot().expect("mock metrics snapshot should succeed");
        assert!(snap.mem_total > 0);
    }

    #[test]
    fn assemble_auto_mode_has_real_metrics() {
        let cfg = cfg_with_mode(BackendMode::Auto);
        let backend = assemble(&cfg).expect("auto assemble should succeed");
        let snap = backend.metrics.snapshot().expect("auto metrics snapshot should succeed");
        // Real sysinfo — mem_total must reflect the actual host
        assert!(snap.mem_total > 0, "auto mode must report real mem_total > 0");
        assert!(snap.uptime_secs > 0, "auto mode must report real uptime > 0");
    }

    #[test]
    fn assemble_auto_mode_non_linux_services_none() {
        // On Windows/macOS, services/packages/logs are None (real impls need Linux)
        #[cfg(not(target_os = "linux"))]
        {
            let cfg = cfg_with_mode(BackendMode::Auto);
            let backend = assemble(&cfg).expect("auto assemble should succeed");
            assert!(backend.services.is_none(), "off-linux auto services must be None");
            assert!(backend.packages.is_none(), "off-linux auto packages must be None");
            assert!(backend.logs.is_none(), "off-linux auto logs must be None");
            assert!(!backend.caps.services, "off-linux auto caps.services must be false");
            assert!(!backend.caps.packages, "off-linux auto caps.packages must be false");
            assert!(!backend.caps.logs, "off-linux auto caps.logs must be false");
        }
        #[cfg(target_os = "linux")]
        {
            // On Linux, auto may or may not have services — just check it compiles
            let cfg = cfg_with_mode(BackendMode::Auto);
            let _backend = assemble(&cfg).expect("auto assemble should succeed on linux");
        }
    }

    #[test]
    fn assemble_real_mode_off_linux_returns_error() {
        #[cfg(not(target_os = "linux"))]
        {
            let cfg = cfg_with_mode(BackendMode::Real);
            let result = assemble(&cfg);
            assert!(
                matches!(result, Err(AssembleError::UnsupportedPlatform)),
                "Real mode off-linux must return UnsupportedPlatform"
            );
        }
        #[cfg(target_os = "linux")]
        {
            // On Linux, Real mode is allowed (may succeed or fail with other error)
            let _ = assemble(&cfg_with_mode(BackendMode::Real));
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
