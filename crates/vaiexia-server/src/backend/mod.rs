pub mod assemble;
pub mod error;
pub mod metrics;
pub mod mock;
pub mod probe;
pub mod systemd;
pub mod types;
pub mod unit_name;

pub use error::BackendError;
pub use types::{
    BackendCapabilities, HostInfo, LogEntry, LogQuery, MetricsSnapshot, PackageInfo, Page,
    ServiceState, UnitDetail, UnitStatus,
};
pub use unit_name::UnitName;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::broadcast;
use sysinfo::System as SysinfoSystem;

// ── HostInfoProvider (Step 0, unchanged) ────────────────────────────────────

pub trait HostInfoProvider: Send + Sync {
    fn host_info(&self) -> Result<HostInfo, BackendError>;
    fn capabilities(&self) -> BackendCapabilities;
}

// ── ServiceManager ───────────────────────────────────────────────────────────

#[async_trait]
pub trait ServiceManager: Send + Sync {
    async fn list(
        &self,
        state_filter: Option<ServiceState>,
        name_glob: Option<String>,
        page: Option<String>,
    ) -> Result<Page<UnitStatus>, BackendError>;
    async fn status(&self, name: &str) -> Result<UnitDetail, BackendError>;
    async fn start(&self, name: &str) -> Result<ServiceState, BackendError>;
    async fn stop(&self, name: &str) -> Result<ServiceState, BackendError>;
    async fn restart(&self, name: &str) -> Result<ServiceState, BackendError>;
    /// A stream of unit-state changes for the `server.services.status` pump.
    fn watch(&self) -> broadcast::Receiver<UnitStatus>;
}

// ── PackageManager ───────────────────────────────────────────────────────────

#[async_trait]
pub trait PackageManager: Send + Sync {
    /// Package manager kind: "apt" | "dnf" | ... | "mock"
    fn kind(&self) -> &'static str;
    async fn list(
        &self,
        query: Option<String>,
        installed_only: bool,
        page: Option<String>,
    ) -> Result<Page<PackageInfo>, BackendError>;
    /// Invoked by the job runner.
    async fn install(&self, name: &str) -> Result<(), BackendError>;
    async fn remove(&self, name: &str) -> Result<(), BackendError>;
}

// ── MetricsProvider ──────────────────────────────────────────────────────────

/// Synchronous: sysinfo is sync.
pub trait MetricsProvider: Send + Sync {
    fn snapshot(&self) -> Result<MetricsSnapshot, BackendError>;
}

// ── LogProvider ──────────────────────────────────────────────────────────────

#[async_trait]
pub trait LogProvider: Send + Sync {
    async fn query(&self, q: &LogQuery) -> Result<Page<LogEntry>, BackendError>;
    /// A follow stream feeding the `server.logs` pump (each entry carries its cursor).
    fn follow(&self) -> broadcast::Receiver<LogEntry>;
}

// ── RealHostInfoProvider ─────────────────────────────────────────────────────

/// A host info provider backed by real OS calls.
pub struct RealHostInfoProvider;

impl HostInfoProvider for RealHostInfoProvider {
    fn host_info(&self) -> Result<HostInfo, BackendError> {
        Ok(HostInfo {
            hostname: SysinfoSystem::host_name().unwrap_or_else(|| "unknown".to_string()),
            os: SysinfoSystem::long_os_version()
                .unwrap_or_else(|| SysinfoSystem::name().unwrap_or_else(|| "unknown".to_string())),
            kernel: SysinfoSystem::kernel_version().unwrap_or_else(|| "unknown".to_string()),
            arch: std::env::consts::ARCH.to_string(),
        })
    }

    fn capabilities(&self) -> BackendCapabilities {
        // Capabilities are tracked externally in SystemBackend.caps — this is a stub.
        BackendCapabilities {
            services: false,
            packages: false,
            metrics: true,
            logs: false,
        }
    }
}

// ── SystemBackend aggregate ──────────────────────────────────────────────────

pub struct SystemBackend {
    pub host: Arc<dyn HostInfoProvider>,
    pub services: Option<Arc<dyn ServiceManager>>,
    pub packages: Option<Arc<dyn PackageManager>>,
    pub metrics: Arc<dyn MetricsProvider>,
    pub logs: Option<Arc<dyn LogProvider>>,
    pub caps: BackendCapabilities,
}

impl SystemBackend {
    /// Build a full backend from a `MockBackend` with all providers enabled.
    pub fn from_mock(mock: Arc<mock::MockBackend>) -> Self {
        let caps = probe::derive_capabilities(true, true, true);
        SystemBackend {
            host: Arc::clone(&mock) as Arc<dyn HostInfoProvider>,
            services: Some(Arc::clone(&mock) as Arc<dyn ServiceManager>),
            packages: Some(Arc::clone(&mock) as Arc<dyn PackageManager>),
            metrics: Arc::clone(&mock) as Arc<dyn MetricsProvider>,
            logs: Some(Arc::clone(&mock) as Arc<dyn LogProvider>),
            caps,
        }
    }
}
