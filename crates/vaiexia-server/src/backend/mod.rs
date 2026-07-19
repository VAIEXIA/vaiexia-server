pub mod error;
pub mod mock;
pub mod types;
pub mod unit_name;

pub use error::BackendError;
pub use types::{BackendCapabilities, HostInfo};
pub use unit_name::UnitName;

pub trait HostInfoProvider: Send + Sync {
    fn host_info(&self) -> Result<HostInfo, BackendError>;
    fn capabilities(&self) -> BackendCapabilities;
}

/// Step 0 aggregate: host + caps only. Step 1 adds services/packages/metrics/logs Option fields.
pub struct SystemBackend {
    pub host: std::sync::Arc<dyn HostInfoProvider>,
    pub caps: BackendCapabilities,
}
