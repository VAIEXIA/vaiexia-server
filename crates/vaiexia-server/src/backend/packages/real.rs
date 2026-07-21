//! Real PackageManager backed by OS package tools and vaiexia-privd.
//! Unix-only — process execution and unix socket.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::backend::capped::run_capped;
use crate::backend::{BackendError, PackageInfo, PackageManager, Page};
use super::detect::PackageKind;
use super::query::{build_list_argv, parse_list};
use super::privd_client::{response_to_result, UnixPrivTransport, PRIVD_SOCKET_PATH};
use super::priv_transport::PrivTransport;
use vaiexia_priv_proto::{PackageName, PrivRequest};

/// Maximum bytes to read from package manager stdout. The child is killed
/// past this cap and the captured output is parsed up to the last complete line.
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Hard deadline for a read-side package listing subprocess.
const LIST_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard deadline for the `--version` probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct RealPackageManager {
    kind: PackageKind,
    transport: Arc<dyn PrivTransport>,
}

impl RealPackageManager {
    pub fn new(kind: PackageKind) -> Self {
        let transport = UnixPrivTransport::new(PRIVD_SOCKET_PATH);
        Self {
            kind,
            transport: Arc::new(transport),
        }
    }

    /// Create with a custom `PrivTransport` (e.g. a test double).
    pub fn with_transport(kind: PackageKind, transport: Arc<dyn PrivTransport>) -> Self {
        Self { kind, transport }
    }

    /// Probe: can we execute the package manager binary? Bounded in both
    /// time and captured output.
    pub async fn probe(kind: PackageKind) -> bool {
        use super::detect::binary_path;
        let args = vec!["--version".to_string()];
        match run_capped(binary_path(kind), &args, 64 * 1024, PROBE_TIMEOUT).await {
            Ok(out) => out.success,
            Err(_) => false,
        }
    }
}

#[async_trait]
impl PackageManager for RealPackageManager {
    fn kind(&self) -> &'static str {
        self.kind.as_str()
    }

    async fn list(
        &self,
        query: Option<String>,
        installed_only: bool,
        _page: Option<String>,
    ) -> Result<Page<PackageInfo>, BackendError> {
        let argv = build_list_argv(self.kind, query.as_deref(), installed_only);
        let program = argv[0].clone();
        let args = &argv[1..];

        let out = run_capped(&program, args, MAX_OUTPUT_BYTES, LIST_TIMEOUT)
            .await
            .map_err(|e| {
                tracing::warn!(kind = self.kind.as_str(), "package list: spawn/io failed: {e}");
                BackendError::Unavailable
            })?;

        if out.timed_out {
            tracing::warn!(kind = self.kind.as_str(), "package list: killed after {LIST_TIMEOUT:?}");
            return Err(BackendError::Timeout);
        }

        let mut stdout_bytes = out.stdout;
        if out.truncated {
            tracing::warn!(
                kind = self.kind.as_str(),
                "package list: stdout exceeded {MAX_OUTPUT_BYTES} bytes; child killed, output truncated"
            );
            // Drop the trailing partial line so we never emit a garbage entry.
            let cut = stdout_bytes
                .iter()
                .rposition(|&b| b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            stdout_bytes.truncate(cut);
        }

        let stdout = String::from_utf8_lossy(&stdout_bytes);
        let items = parse_list(self.kind, &stdout);

        Ok(Page { items, next: None })
    }

    async fn install(&self, name: &str) -> Result<(), BackendError> {
        let pkg_name = PackageName::parse(name)
            .map_err(|_| BackendError::InvalidInput(format!("invalid package name: {name}")))?;

        let req = PrivRequest::PkgInstall { name: pkg_name };
        let transport = Arc::clone(&self.transport);

        // Run blocking channel I/O on a thread pool thread
        let resp = tokio::task::spawn_blocking(move || transport.request(&req))
            .await
            .map_err(|_| BackendError::Unavailable)??;

        response_to_result(resp)
    }

    async fn remove(&self, name: &str) -> Result<(), BackendError> {
        let pkg_name = PackageName::parse(name)
            .map_err(|_| BackendError::InvalidInput(format!("invalid package name: {name}")))?;

        let req = PrivRequest::PkgRemove { name: pkg_name };
        let transport = Arc::clone(&self.transport);

        let resp = tokio::task::spawn_blocking(move || transport.request(&req))
            .await
            .map_err(|_| BackendError::Unavailable)??;

        response_to_result(resp)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use vaiexia_priv_proto::{PackageName, PrivRequest, PrivResponse};

    use super::super::detect::PackageKind;

    /// A fake in-memory `PrivTransport` that records all requests sent to it
    /// and returns a configurable `PrivResponse`.
    struct FakePrivTransport {
        response: PrivResponse,
        calls: Mutex<Vec<PrivRequest>>,
    }

    impl FakePrivTransport {
        fn new(response: PrivResponse) -> Self {
            Self { response, calls: Mutex::new(Vec::new()) }
        }

        fn recorded(&self) -> Vec<PrivRequest> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl PrivTransport for FakePrivTransport {
        fn request(&self, req: &PrivRequest) -> Result<PrivResponse, BackendError> {
            self.calls.lock().unwrap().push(req.clone());
            Ok(self.response.clone())
        }
    }

    fn make_pm(response: PrivResponse) -> (RealPackageManager, Arc<FakePrivTransport>) {
        let transport = Arc::new(FakePrivTransport::new(response));
        let pm = RealPackageManager::with_transport(
            PackageKind::Apt,
            Arc::clone(&transport) as Arc<dyn PrivTransport>,
        );
        (pm, transport)
    }

    #[tokio::test]
    async fn install_routes_through_trait() {
        let (pm, transport) = make_pm(PrivResponse::Ok);
        pm.install("nginx").await.expect("install should succeed");

        let calls = transport.recorded();
        assert_eq!(calls.len(), 1, "expected exactly one transport call");
        assert!(
            matches!(&calls[0], PrivRequest::PkgInstall { name } if name == &PackageName::parse("nginx").unwrap()),
            "unexpected request variant: {:?}",
            calls[0]
        );
    }

    #[tokio::test]
    async fn remove_routes_through_trait() {
        let (pm, transport) = make_pm(PrivResponse::Ok);
        pm.remove("nginx").await.expect("remove should succeed");

        let calls = transport.recorded();
        assert_eq!(calls.len(), 1, "expected exactly one transport call");
        assert!(
            matches!(&calls[0], PrivRequest::PkgRemove { name } if name == &PackageName::parse("nginx").unwrap()),
            "unexpected request variant: {:?}",
            calls[0]
        );
    }

    #[tokio::test]
    async fn install_propagates_transport_error() {
        let (pm, _transport) = make_pm(PrivResponse::Error { message: "boom".into() });
        let err = pm.install("nginx").await.expect_err("expected an error");
        assert!(matches!(err, BackendError::Internal(_)));
    }
}
