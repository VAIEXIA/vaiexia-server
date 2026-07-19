use std::sync::Arc;
use std::time::Duration;

use vaiexia_core::server::{Service, ServiceBuilder};

use crate::api::{ApiModule, jobs::JobRegistry, server_module::ServerModule};
use crate::auth::SkeletonVerifier;
use crate::backend::SystemBackend;
use crate::events::{
    PumpHandle, SeqCounter, spawn_supervised,
    jobs_pump, logs_pump, metrics_pump, status_pump, topics,
};

const METRICS_INTERVAL_SECS: u64 = 2;

pub fn build_service(backend: Arc<SystemBackend>) -> (Arc<Service>, Vec<PumpHandle>) {
    let registry = Arc::new(JobRegistry::new());

    // Get event source senders BEFORE folding modules (event_source_sender takes &mut self)
    let mut builder = ServiceBuilder::new().verifier(SkeletonVerifier);

    let metrics_sender = builder.event_source_sender(topics::metrics());
    let status_sender = builder.event_source_sender(topics::services_status());
    let jobs_sender = builder.event_source_sender(topics::jobs());
    let logs_sender = builder.event_source_sender(topics::logs());

    // Register API methods via modules
    let modules: Vec<Box<dyn ApiModule>> = vec![Box::new(ServerModule {
        registry: Arc::clone(&registry),
    })];
    let builder = modules
        .into_iter()
        .fold(builder, |b, m| m.register(b, Arc::clone(&backend)));

    let service = Arc::new(builder.build());

    // Spawn supervised pumps
    let seq = SeqCounter::new();
    let mut handles: Vec<PumpHandle> = Vec::new();

    // Metrics pump — uses production interval
    {
        let sender = metrics_sender.clone();
        let provider = Arc::clone(&backend.metrics);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("metrics", move || {
            let sender = sender.clone();
            let provider = Arc::clone(&provider);
            let seq = seq2.clone_arc();
            Box::pin(metrics_pump::run(
                sender,
                provider,
                seq,
                Duration::from_secs(METRICS_INTERVAL_SECS),
            ))
        }));
    }

    // Status pump — only if services available
    if let Some(mgr) = &backend.services {
        let sender = status_sender.clone();
        let mgr = Arc::clone(mgr);
        handles.push(spawn_supervised("status", move || {
            let sender = sender.clone();
            let mgr = Arc::clone(&mgr);
            Box::pin(status_pump::run(sender, mgr))
        }));
    }

    // Jobs pump
    {
        let sender = jobs_sender.clone();
        let registry2 = Arc::clone(&registry);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("jobs", move || {
            let sender = sender.clone();
            let registry = Arc::clone(&registry2);
            let seq = seq2.clone_arc();
            Box::pin(jobs_pump::run(sender, registry, seq))
        }));
    }

    // Logs pump — only if logs available
    if let Some(logs) = &backend.logs {
        let sender = logs_sender.clone();
        let provider = Arc::clone(logs);
        let seq2 = seq.clone_arc();
        handles.push(spawn_supervised("logs", move || {
            let sender = sender.clone();
            let provider = Arc::clone(&provider);
            let seq = seq2.clone_arc();
            Box::pin(logs_pump::run(sender, provider, seq))
        }));
    }

    (service, handles)
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

    #[tokio::test]
    async fn build_service_assembles_without_panic() {
        let mock = Arc::new(MockBackend::new());
        let backend = Arc::new(SystemBackend::from_mock(mock));
        // Should not panic; returns service + pump handles
        let (service, handles) = build_service(backend);
        // Abort pumps to avoid leak in test
        for h in handles {
            h.abort();
        }
        drop(service);
    }

    /// B5: build_service registers event sources — the service
    /// should be constructable with event_source_sender wired in.
    #[tokio::test]
    async fn build_service_registers_event_sources_without_panic() {
        let mock = Arc::new(MockBackend::new());
        let backend = Arc::new(SystemBackend::from_mock(mock));
        let (service, handles) = build_service(backend);
        // 4 pumps registered (metrics + status + jobs + logs)
        assert_eq!(handles.len(), 4, "expected 4 pump handles");
        for h in handles {
            h.abort();
        }
        drop(service);
    }
}
