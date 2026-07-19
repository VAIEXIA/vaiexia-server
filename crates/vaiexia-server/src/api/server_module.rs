use std::sync::Arc;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiModule, jobs::JobRegistry, server_host, server_jobs, server_logs, server_packages, server_services};
use crate::backend::SystemBackend;

/// Bundles all `server.*` methods (read + status surface for Step 1).
pub struct ServerModule {
    pub registry: Arc<JobRegistry>,
}

impl ApiModule for ServerModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, backend: Arc<SystemBackend>) -> ServiceBuilder {
        let builder = server_host::register(builder, Arc::clone(&backend));
        let builder = server_services::register(builder, Arc::clone(&backend));
        let builder = server_packages::register(builder, Arc::clone(&backend), Arc::clone(&self.registry));
        let builder = server_logs::register(builder, Arc::clone(&backend));
        server_jobs::register(builder, Arc::clone(&self.registry))
    }
}
