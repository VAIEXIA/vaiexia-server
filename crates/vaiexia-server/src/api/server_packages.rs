use std::sync::Arc;
use serde::{Deserialize, Serialize};
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;
use vaiexia_priv_proto::PackageName;

use crate::api::dto::{PackageDto, PageDto};
use crate::api::jobs::JobRegistry;
use crate::api::register_scoped;
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

#[derive(Debug, Deserialize)]
pub struct PackageMutateParams {
    pub name: String,
}

// ── Response DTO ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct JobStartDto {
    pub job_id: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_package_name(name: &str) -> Result<String, Diagnostic> {
    PackageName::parse(name)
        .map(|n| n.as_str().to_owned())
        .map_err(|_| Diagnostic::error(codes::INVALID_PARAMS, "invalid package name"))
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

pub async fn packages_install_result(
    be: &SystemBackend,
    registry: &Arc<JobRegistry>,
    params: PackageMutateParams,
) -> Result<JobStartDto, Diagnostic> {
    let name = parse_package_name(&params.name)?;
    let pkgs = be
        .packages
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "packages not supported"))?;
    let pkgs = Arc::clone(pkgs);
    let job_id = registry
        .try_start("install", async move {
            pkgs.install(&name).await.map_err(|e| backend_error_to_diagnostic(&e))
        })
        .map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(JobStartDto { job_id })
}

pub async fn packages_remove_result(
    be: &SystemBackend,
    registry: &Arc<JobRegistry>,
    params: PackageMutateParams,
) -> Result<JobStartDto, Diagnostic> {
    let name = parse_package_name(&params.name)?;
    let pkgs = be
        .packages
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "packages not supported"))?;
    let pkgs = Arc::clone(pkgs);
    let job_id = registry
        .try_start("remove", async move {
            pkgs.remove(&name).await.map_err(|e| backend_error_to_diagnostic(&e))
        })
        .map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(JobStartDto { job_id })
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, be: Arc<SystemBackend>, registry: Arc<JobRegistry>) -> ServiceBuilder {
    let be1 = Arc::clone(&be);
    let list_method = Method::new("server.packages.list").expect("valid method");
    let builder = register_scoped(builder, list_method, move |p: PackagesListParams, _subject: Subject| {
        let be = Arc::clone(&be1);
        async move { packages_list_result(&be, p).await }
    });

    let be2 = Arc::clone(&be);
    let reg2 = Arc::clone(&registry);
    let install_method = Method::new("server.packages.install").expect("valid method");
    let builder = register_scoped(builder, install_method, move |p: PackageMutateParams, _subject: Subject| {
        let be = Arc::clone(&be2);
        let reg = Arc::clone(&reg2);
        async move { packages_install_result(&be, &reg, p).await }
    });

    let be3 = Arc::clone(&be);
    let reg3 = Arc::clone(&registry);
    let remove_method = Method::new("server.packages.remove").expect("valid method");
    register_scoped(builder, remove_method, move |p: PackageMutateParams, _subject: Subject| {
        let be = Arc::clone(&be3);
        let reg = Arc::clone(&reg3);
        async move { packages_remove_result(&be, &reg, p).await }
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

    // ── B2 mutation tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn packages_install_returns_job_id() {
        let be = full_backend();
        let registry = std::sync::Arc::new(crate::api::jobs::JobRegistry::new());
        let params = PackageMutateParams { name: "nginx".into() };
        let dto = packages_install_result(&be, &registry, params).await.unwrap();
        assert!(!dto.job_id.is_empty());
        // Poll until job succeeds
        for _ in 0..50 {
            if let Some(status) = registry.status(&dto.job_id)
                && matches!(status.state, crate::api::jobs::JobState::Succeeded)
            {
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
        panic!("install job never succeeded");
    }

    #[tokio::test]
    async fn packages_install_invalid_name_returns_invalid_params() {
        let be = full_backend();
        let registry = std::sync::Arc::new(crate::api::jobs::JobRegistry::new());
        let params = PackageMutateParams { name: "Bad Name!".into() };
        let err = packages_install_result(&be, &registry, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn packages_install_busy_when_slot_occupied() {
        let be = full_backend();
        let registry = std::sync::Arc::new(crate::api::jobs::JobRegistry::new());
        // Occupy the slot with a blocking job
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        registry.try_start("install", async move { let _ = rx.await; Ok(()) }).unwrap();
        // Second install → busy
        let params = PackageMutateParams { name: "nginx".into() };
        let err = packages_install_result(&be, &registry, params).await.unwrap_err();
        assert_eq!(err.code, crate::diag::domain_codes::BUSY);
        let _ = tx.send(());
    }

    #[tokio::test]
    async fn packages_remove_returns_job_id() {
        let be = full_backend();
        let registry = std::sync::Arc::new(crate::api::jobs::JobRegistry::new());
        let params = PackageMutateParams { name: "nginx".into() };
        let dto = packages_remove_result(&be, &registry, params).await.unwrap();
        assert!(!dto.job_id.is_empty());
    }
}
