pub mod dto;
pub mod jobs;
pub mod server_host;
pub mod server_jobs;
pub mod server_logs;
pub mod server_module;
pub mod server_packages;
pub mod server_services;

use std::sync::Arc;
use vaiexia_core::server::ServiceBuilder;

use crate::backend::SystemBackend;

/// The seam for Step 1+ modules to register themselves with the service builder.
pub trait ApiModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, backend: Arc<SystemBackend>) -> ServiceBuilder;
}
