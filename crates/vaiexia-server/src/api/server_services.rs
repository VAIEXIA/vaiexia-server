use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::dto::{PageDto, UnitDetailDto, UnitDto};
use crate::backend::{ServiceManager, ServiceState, SystemBackend, UnitName};
use crate::diag::{backend_error_to_diagnostic, domain_codes};

const MUTATION_TIMEOUT_SECS: u64 = 30;

// ── Params ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ServicesListParams {
    pub state_filter: Option<ServiceState>,
    pub name_glob: Option<String>,
    pub page: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceStatusParams {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ServiceMutateParams {
    pub name: String,
}

// ── Response DTO ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ServiceOutcomeDto {
    pub outcome: &'static str,
    pub state: ServiceState,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

pub async fn services_list_result(
    be: &SystemBackend,
    params: ServicesListParams,
) -> Result<PageDto<UnitDto>, Diagnostic> {
    let mgr = be
        .services
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "services not supported on this host"))?;
    let page = mgr
        .list(params.state_filter, params.name_glob, params.page)
        .await
        .map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(PageDto::map_from(page, UnitDto::from))
}

pub async fn service_status_result(
    be: &SystemBackend,
    params: ServiceStatusParams,
) -> Result<UnitDetailDto, Diagnostic> {
    // Validate the name
    UnitName::parse(&params.name)
        .map_err(|_| Diagnostic::error(vaiexia_core::diagnostic::codes::INVALID_PARAMS, "invalid unit name"))?;

    let mgr = be
        .services
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "services not supported on this host"))?;
    let detail = mgr
        .status(&params.name)
        .await
        .map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(UnitDetailDto::from(detail))
}

// ── Mutation handlers ─────────────────────────────────────────────────────────

fn validate_and_get_manager(
    be: &SystemBackend,
    name: &str,
) -> Result<(Arc<dyn crate::backend::ServiceManager>, String), Diagnostic> {
    UnitName::parse(name)
        .map_err(|_| Diagnostic::error(codes::INVALID_PARAMS, "invalid unit name"))?;
    let mgr = be
        .services
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "services not supported on this host"))?;
    Ok((Arc::clone(mgr), name.to_string()))
}

pub async fn services_start_result(
    be: &SystemBackend,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let (mgr, name) = validate_and_get_manager(be, &params.name)?;
    match tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), mgr.start(&name)).await {
        Err(_elapsed) => Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown }),
        Ok(Err(e)) => Err(backend_error_to_diagnostic(&e)),
        Ok(Ok(state)) => Ok(ServiceOutcomeDto { outcome: "ok", state }),
    }
}

pub async fn services_stop_result(
    be: &SystemBackend,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let (mgr, name) = validate_and_get_manager(be, &params.name)?;
    match tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), mgr.stop(&name)).await {
        Err(_elapsed) => Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown }),
        Ok(Err(e)) => Err(backend_error_to_diagnostic(&e)),
        Ok(Ok(state)) => Ok(ServiceOutcomeDto { outcome: "ok", state }),
    }
}

pub async fn services_restart_result(
    be: &SystemBackend,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let (mgr, name) = validate_and_get_manager(be, &params.name)?;
    match tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), mgr.restart(&name)).await {
        Err(_elapsed) => Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown }),
        Ok(Err(e)) => Err(backend_error_to_diagnostic(&e)),
        Ok(Ok(state)) => Ok(ServiceOutcomeDto { outcome: "ok", state }),
    }
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, be: Arc<SystemBackend>) -> ServiceBuilder {
    let be1 = Arc::clone(&be);
    let list_method = Method::new("server.services.list").expect("valid method");
    let builder = builder.method_typed(list_method, move |p: ServicesListParams, _subject| {
        let be = Arc::clone(&be1);
        async move { services_list_result(&be, p).await }
    });

    let be2 = Arc::clone(&be);
    let status_method = Method::new("server.services.status").expect("valid method");
    let builder = builder.method_typed(status_method, move |p: ServiceStatusParams, _subject| {
        let be = Arc::clone(&be2);
        async move { service_status_result(&be, p).await }
    });

    let be3 = Arc::clone(&be);
    let start_method = Method::new("server.services.start").expect("valid method");
    let builder = builder.method_typed(start_method, move |p: ServiceMutateParams, _subject| {
        let be = Arc::clone(&be3);
        async move { services_start_result(&be, p).await }
    });

    let be4 = Arc::clone(&be);
    let stop_method = Method::new("server.services.stop").expect("valid method");
    let builder = builder.method_typed(stop_method, move |p: ServiceMutateParams, _subject| {
        let be = Arc::clone(&be4);
        async move { services_stop_result(&be, p).await }
    });

    let be5 = Arc::clone(&be);
    let restart_method = Method::new("server.services.restart").expect("valid method");
    builder.method_typed(restart_method, move |p: ServiceMutateParams, _subject| {
        let be = Arc::clone(&be5);
        async move { services_restart_result(&be, p).await }
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

    fn no_services_backend() -> Arc<SystemBackend> {
        let mock = Arc::new(MockBackend::new());
        let mut be = SystemBackend::from_mock(mock);
        be.services = None;
        Arc::new(be)
    }

    #[tokio::test]
    async fn services_list_returns_page_dto() {
        let be = full_backend();
        let params = ServicesListParams { state_filter: None, name_glob: None, page: None };
        let page = services_list_result(&be, params).await.unwrap();
        assert!(!page.items.is_empty());
        assert!(page.items.iter().any(|u| u.name == "nginx.service"));
    }

    #[tokio::test]
    async fn services_status_ok_for_known_unit() {
        let be = full_backend();
        let params = ServiceStatusParams { name: "nginx.service".into() };
        let detail = service_status_result(&be, params).await.unwrap();
        assert_eq!(detail.name, "nginx.service");
    }

    #[tokio::test]
    async fn services_status_not_found_for_unknown_unit() {
        let be = full_backend();
        let params = ServiceStatusParams { name: "ghost.service".into() };
        let err = service_status_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "NOT_FOUND");
    }

    #[tokio::test]
    async fn services_status_invalid_params_for_bad_name() {
        let be = full_backend();
        let params = ServiceStatusParams { name: "a b.service".into() };
        let err = service_status_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn services_list_unsupported_when_no_provider() {
        let be = no_services_backend();
        let params = ServicesListParams { state_filter: None, name_glob: None, page: None };
        let err = services_list_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "UNSUPPORTED");
    }

    // ── B2 mutation tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn services_start_returns_ok_and_active_state() {
        let be = full_backend();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_start_result(&be, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Active);
    }

    #[tokio::test]
    async fn services_start_invalid_name_returns_invalid_params() {
        let be = full_backend();
        let params = ServiceMutateParams { name: "a b.service".into() };
        let err = services_start_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn services_stop_returns_ok_and_inactive_state() {
        let be = full_backend();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_stop_result(&be, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Inactive);
    }

    #[tokio::test]
    async fn services_restart_returns_ok_and_active_state() {
        let be = full_backend();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_restart_result(&be, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Active);
    }
}
