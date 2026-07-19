use std::sync::Arc;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiModule, server_host, server_logs, server_packages, server_services};
use crate::backend::SystemBackend;

/// Bundles all `server.*` methods (read + status surface for Step 1 Part A).
pub struct ServerModule;

impl ApiModule for ServerModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, backend: Arc<SystemBackend>) -> ServiceBuilder {
        let builder = server_host::register(builder, Arc::clone(&backend));
        let builder = server_services::register(builder, Arc::clone(&backend));
        let builder = server_packages::register(builder, Arc::clone(&backend));
        server_logs::register(builder, backend)
    }
}
