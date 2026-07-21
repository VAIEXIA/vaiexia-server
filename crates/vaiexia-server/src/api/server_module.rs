use std::sync::Arc;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiDeps, ApiModule, jobs::JobRegistry, server_host, server_jobs, server_logs, server_packages, server_services};

/// Bundles all `server.*` methods (read + status surface for Step 1).
pub struct ServerModule {
    pub registry: Arc<JobRegistry>,
}

impl ApiModule for ServerModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, deps: &ApiDeps) -> ServiceBuilder {
        let builder = server_host::register(builder, deps);
        let builder = server_services::register(builder, deps);
        let builder = server_packages::register(builder, deps, Arc::clone(&self.registry));
        let builder = server_logs::register(builder, deps);
        server_jobs::register(builder, deps, Arc::clone(&self.registry))
    }
}
