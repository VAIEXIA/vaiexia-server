pub mod dto;
pub mod server_host;
pub mod server_logs;
pub mod server_packages;
pub mod server_services;

use vaiexia_core::server::ServiceBuilder;

/// The seam for Step 1+ modules to register themselves with the service builder.
pub trait ApiModule {
    fn register(self: Box<Self>, builder: ServiceBuilder) -> ServiceBuilder;
}
