use std::sync::Arc;
use vaiexia_core::server::{Service, ServiceBuilder};

use crate::api::{ApiModule, server_module::ServerModule};
use crate::auth::SkeletonVerifier;
use crate::backend::SystemBackend;

pub fn build_service(backend: Arc<SystemBackend>) -> Arc<Service> {
    let builder = ServiceBuilder::new().verifier(SkeletonVerifier);
    let modules: Vec<Box<dyn ApiModule>> = vec![Box::new(ServerModule)];
    let builder = modules
        .into_iter()
        .fold(builder, |b, m| m.register(b, Arc::clone(&backend)));
    Arc::new(builder.build())
}

/// Resolves when a shutdown signal (SIGTERM or Ctrl-C) arrives.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::backend::{mock::MockBackend, SystemBackend};

    #[test]
    fn build_service_assembles_without_panic() {
        let mock = Arc::new(MockBackend::new());
        let backend = Arc::new(SystemBackend::from_mock(mock));
        // Should not panic
        let _service = build_service(backend);
    }
}
