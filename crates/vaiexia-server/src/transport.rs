use std::net::SocketAddr;
use std::sync::Arc;
use vaiexia_core::server::{serve, ServeHandle, Service};

use crate::config::{ListenerKind, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("no listeners configured")]
    NoListeners,
    #[error("https listener lands in Step 4")]
    HttpsNotYetImplemented,
    #[error("obfs listeners are deferred (see spec §5.4)")]
    ObfsDeferred,
    #[error("core serve error: {0}")]
    Core(String),
}

pub enum ListenerHandle {
    Http(ServeHandle),
}

impl std::fmt::Debug for ListenerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenerHandle::Http(h) => write!(f, "ListenerHandle::Http(addr={})", h.addr()),
        }
    }
}

impl ListenerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            ListenerHandle::Http(h) => h.addr(),
        }
    }

    pub fn shutdown(self) {
        match self {
            ListenerHandle::Http(h) => h.shutdown(),
        }
    }
}

pub async fn start_listeners(
    cfg: &ServerConfig,
    service: Arc<Service>,
) -> Result<Vec<ListenerHandle>, TransportError> {
    if cfg.listeners.is_empty() {
        return Err(TransportError::NoListeners);
    }
    let mut handles = Vec::new();
    for l in &cfg.listeners {
        match l.kind {
            ListenerKind::Http => {
                let h = serve(Arc::clone(&service), &l.bind)
                    .await
                    .map_err(|e| TransportError::Core(e.to_string()))?;
                handles.push(ListenerHandle::Http(h));
            }
            ListenerKind::Https => return Err(TransportError::HttpsNotYetImplemented),
            ListenerKind::ObfsTcp | ListenerKind::ObfsUdp => {
                return Err(TransportError::ObfsDeferred)
            }
        }
    }
    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::backend::{SystemBackend, mock::MockBackend};
    use crate::config::{Listener, ListenerKind, ServerConfig};
    use crate::lifecycle::build_service_permissive as build_service;
    use std::path::PathBuf;

    fn make_service() -> Arc<Service> {
        let mock = Arc::new(MockBackend::new());
        let backend = Arc::new(SystemBackend::from_mock(mock));
        let (service, handles) = build_service(backend);
        // Abort pump handles — transport test doesn't need them
        for h in handles { h.abort(); }
        service
    }

    fn http_config(bind: &str) -> ServerConfig {
        ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Http,
                bind: bind.into(),
                cert: None,
                key: None,
            }],
        }
    }

    #[tokio::test]
    async fn http_listener_starts_on_loopback() {
        let svc = make_service();
        let cfg = http_config("127.0.0.1:0");
        let handles = start_listeners(&cfg, svc).await.unwrap();
        assert_eq!(handles.len(), 1);
        let addr = handles[0].local_addr();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
        handles.into_iter().for_each(|h| h.shutdown());
    }

    #[tokio::test]
    async fn https_listener_returns_not_yet_implemented() {
        let svc = make_service();
        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Https,
                bind: "127.0.0.1:443".into(),
                cert: Some(PathBuf::from("/tmp/cert.pem")),
                key: Some(PathBuf::from("/tmp/key.pem")),
            }],
        };
        let err = start_listeners(&cfg, svc).await.unwrap_err();
        assert!(matches!(err, TransportError::HttpsNotYetImplemented));
    }

    #[tokio::test]
    async fn obfs_tcp_listener_returns_deferred() {
        let svc = make_service();
        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::ObfsTcp,
                bind: "127.0.0.1:9000".into(),
                cert: None,
                key: None,
            }],
        };
        let err = start_listeners(&cfg, svc).await.unwrap_err();
        assert!(matches!(err, TransportError::ObfsDeferred));
    }
}
