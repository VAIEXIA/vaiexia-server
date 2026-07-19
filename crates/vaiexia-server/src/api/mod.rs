pub mod dto;
pub mod server_host;

use vaiexia_core::server::ServiceBuilder;

/// The seam for Step 1+ modules to register themselves with the service builder.
pub trait ApiModule {
    fn register(self: Box<Self>, builder: ServiceBuilder) -> ServiceBuilder;
}
