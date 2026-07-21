use std::net::SocketAddr;
use std::sync::Arc;
use vaiexia_core::server::{serve, ServeHandle, Service};
#[cfg(feature = "tls")]
use vaiexia_core::server::{serve_tls, TlsServeHandle, TlsServerConfig};

use crate::config::{ListenerKind, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("no listeners configured")]
    NoListeners,
    #[error("tls listener: {0}")]
    Tls(String),
    #[error("obfs listeners are deferred (see spec §5.4)")]
    ObfsDeferred,
    #[error("core serve error: {0}")]
    Core(String),
}

pub enum ListenerHandle {
    Http(ServeHandle),
    #[cfg(feature = "tls")]
    Tls(TlsServeHandle),
}

impl std::fmt::Debug for ListenerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenerHandle::Http(h) => write!(f, "ListenerHandle::Http(addr={})", h.addr()),
            #[cfg(feature = "tls")]
            ListenerHandle::Tls(h) => write!(f, "ListenerHandle::Tls(addr={})", h.addr()),
        }
    }
}

impl ListenerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            ListenerHandle::Http(h) => h.addr(),
            #[cfg(feature = "tls")]
            ListenerHandle::Tls(h) => h.addr(),
        }
    }

    pub fn shutdown(self) {
        match self {
            ListenerHandle::Http(h) => h.shutdown(),
            #[cfg(feature = "tls")]
            ListenerHandle::Tls(h) => h.shutdown(),
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
            ListenerKind::Https => {
                #[cfg(feature = "tls")]
                {
                    let cert_path = l.cert.as_ref()
                        .ok_or_else(|| TransportError::Tls("https listener missing cert path".into()))?;
                    let key_path = l.key.as_ref()
                        .ok_or_else(|| TransportError::Tls("https listener missing key path".into()))?;
                    // Fail closed: unreadable/unparsable material aborts startup.
                    let cert_pem = std::fs::read(cert_path)
                        .map_err(|e| TransportError::Tls(format!("read cert {}: {e}", cert_path.display())))?;
                    let key_pem = std::fs::read(key_path)
                        .map_err(|e| TransportError::Tls(format!("read key {}: {e}", key_path.display())))?;
                    let tls = TlsServerConfig { cert_pem, key_pem, client_ca_pem: None };
                    let h = serve_tls(Arc::clone(&service), &l.bind, tls)
                        .await
                        .map_err(|e| TransportError::Tls(e.to_string()))?;
                    tracing::info!(bind = %l.bind, "tls listener started");
                    handles.push(ListenerHandle::Tls(h));
                }
                #[cfg(not(feature = "tls"))]
                {
                    // Fail closed: an https listener was requested but this binary
                    // was built without the `tls` feature (spec §5.3 opt-in).
                    return Err(TransportError::Tls(
                        "https listener requires building with the `tls` feature".into(),
                    ));
                }
            }
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
            ..Default::default()
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

    #[cfg(feature = "tls")]
    #[tokio::test(flavor = "multi_thread")]
    async fn https_listener_serves_hello_with_tls_feature() {
        use std::io::Write;
        let svc = make_service();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let dir = std::env::temp_dir().join(format!("vx-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::File::create(&cert_path).unwrap().write_all(cert.pem().as_bytes()).unwrap();
        std::fs::File::create(&key_path).unwrap().write_all(signing_key.serialize_pem().as_bytes()).unwrap();

        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Https,
                bind: "127.0.0.1:0".into(),
                cert: Some(cert_path.clone()),
                key: Some(key_path.clone()),
            }],
            ..Default::default()
        };
        let handles = start_listeners(&cfg, svc).await.unwrap();
        let addr = handles[0].local_addr();

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
            .build()
            .unwrap();
        let hello: serde_json::Value = client
            .get(format!("https://localhost:{}/hello", addr.port()))
            .send().await.unwrap()
            .json().await.unwrap();
        assert!(
            hello["features"].as_array().unwrap().iter().any(|f| f == "tls"),
            "/hello must advertise the tls feature: {hello}"
        );

        handles.into_iter().for_each(|h| h.shutdown());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn https_listener_fails_closed_on_unreadable_cert() {
        // Fail closed (spec §5.1): unreadable material aborts startup — never a
        // silent plaintext fallback.
        let svc = make_service();
        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Https,
                bind: "127.0.0.1:0".into(),
                cert: Some(PathBuf::from("/definitely/missing/cert.pem")),
                key: Some(PathBuf::from("/definitely/missing/key.pem")),
            }],
            ..Default::default()
        };
        let err = start_listeners(&cfg, svc).await.unwrap_err();
        assert!(matches!(err, TransportError::Tls(_)), "got: {err:?}");
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
            ..Default::default()
        };
        let err = start_listeners(&cfg, svc).await.unwrap_err();
        assert!(matches!(err, TransportError::ObfsDeferred));
    }
}
