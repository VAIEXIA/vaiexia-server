use std::sync::Arc;
use serde::Deserialize;
use vaiexia_core::diagnostic::Diagnostic;
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::dto::{PackageDto, PageDto};
use crate::backend::SystemBackend;
use crate::diag::{backend_error_to_diagnostic, domain_codes};

// ── Params ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PackagesListParams {
    pub query: Option<String>,
    #[serde(default)]
    pub installed_only: bool,
    pub page: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

pub async fn packages_list_result(
    be: &SystemBackend,
    params: PackagesListParams,
) -> Result<PageDto<PackageDto>, Diagnostic> {
    let mgr = be
        .packages
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "packages not supported on this host"))?;
    let page = mgr
        .list(params.query, params.installed_only, params.page)
        .await
        .map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(PageDto::map_from(page, PackageDto::from))
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, be: Arc<SystemBackend>) -> ServiceBuilder {
    let list_method = Method::new("server.packages.list").expect("valid method");
    builder.method_typed(list_method, move |p: PackagesListParams, _subject| {
        let be = Arc::clone(&be);
        async move { packages_list_result(&be, p).await }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::backend::{mock::MockBackend, SystemBackend};

    fn full_backend() -> Arc<SystemBackend> {
        Arc::new(SystemBackend::from_mock(Arc::new(MockBackend::new())))
    }

    fn no_packages_backend() -> Arc<SystemBackend> {
        let mock = Arc::new(MockBackend::new());
        let mut be = SystemBackend::from_mock(mock);
        be.packages = None;
        Arc::new(be)
    }

    #[tokio::test]
    async fn packages_list_returns_all() {
        let be = full_backend();
        let params = PackagesListParams { query: None, installed_only: false, page: None };
        let page = packages_list_result(&be, params).await.unwrap();
        assert!(!page.items.is_empty());
    }

    #[tokio::test]
    async fn packages_list_filters_installed() {
        let be = full_backend();
        let params = PackagesListParams { query: None, installed_only: true, page: None };
        let page = packages_list_result(&be, params).await.unwrap();
        assert!(page.items.iter().all(|p| p.installed));
    }

    #[tokio::test]
    async fn packages_list_unsupported_when_no_provider() {
        let be = no_packages_backend();
        let params = PackagesListParams { query: None, installed_only: false, page: None };
        let err = packages_list_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "UNSUPPORTED");
    }
}
