//! Real PackageManager backed by OS package tools and vaiexia-privd.
//! Unix-only — process execution and unix socket.

#![cfg(unix)]

use async_trait::async_trait;

use crate::backend::{BackendError, PackageInfo, PackageManager, Page};
use super::detect::PackageKind;
use super::query::{build_list_argv, parse_list};
use super::privd_client::{send_request, response_to_result, PRIVD_SOCKET_PATH};
use vaiexia_priv_proto::{PackageName, PrivRequest};

/// Maximum bytes to read from package manager stdout.
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

pub struct RealPackageManager {
    kind: PackageKind,
    socket_path: String,
}

impl RealPackageManager {
    pub fn new(kind: PackageKind) -> Self {
        Self {
            kind,
            socket_path: PRIVD_SOCKET_PATH.to_string(),
        }
    }

    /// Probe: can we execute the package manager binary?
    pub async fn probe(kind: PackageKind) -> bool {
        use super::detect::binary_path;
        tokio::process::Command::new(binary_path(kind))
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
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

        let output = tokio::process::Command::new(&program)
            .args(args)
            .env_clear()
            .output()
            .await
            .map_err(|_| BackendError::Unavailable)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let items = parse_list(self.kind, &stdout);

        Ok(Page { items, next: None })
    }

    async fn install(&self, name: &str) -> Result<(), BackendError> {
        let pkg_name = PackageName::parse(name)
            .map_err(|_| BackendError::InvalidInput(format!("invalid package name: {name}")))?;

        let req = PrivRequest::PkgInstall { name: pkg_name };
        let socket_path = self.socket_path.clone();

        // Run blocking unix socket I/O on a thread pool thread
        let resp = tokio::task::spawn_blocking(move || send_request(&socket_path, &req))
            .await
            .map_err(|_| BackendError::Unavailable)??;

        response_to_result(resp)
    }

    async fn remove(&self, name: &str) -> Result<(), BackendError> {
        let pkg_name = PackageName::parse(name)
            .map_err(|_| BackendError::InvalidInput(format!("invalid package name: {name}")))?;

        let req = PrivRequest::PkgRemove { name: pkg_name };
        let socket_path = self.socket_path.clone();

        let resp = tokio::task::spawn_blocking(move || send_request(&socket_path, &req))
            .await
            .map_err(|_| BackendError::Unavailable)??;

        response_to_result(resp)
    }
}
