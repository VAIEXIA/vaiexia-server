use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiDeps, ScopeAudit, dto::{PageDto, UnitDetailDto, UnitDto}};
use crate::api::register_scoped;
use crate::audit::{AuditDecision, AuditEvent, AuditKind, DynAuditSink};
use crate::backend::{ServiceState, SystemBackend, UnitName};
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

/// Upper bound on the `name_glob` filter. Unit names are ≤ 256 bytes; the
/// glob matcher is O(pattern × text), so an unbounded pattern is a cheap
/// CPU-burn vector across a large unit list.
const MAX_GLOB_LEN: usize = 256;

pub async fn services_list_result(
    be: &SystemBackend,
    params: ServicesListParams,
) -> Result<PageDto<UnitDto>, Diagnostic> {
    if params
        .name_glob
        .as_deref()
        .is_some_and(|g| g.len() > MAX_GLOB_LEN)
    {
        return Err(Diagnostic::error(codes::INVALID_PARAMS, "name_glob too long"));
    }
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
    audit: &DynAuditSink,
    subject: &Subject,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let t0 = Instant::now();
    let (mgr, name) = validate_and_get_manager(be, &params.name)?;
    let result = tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), mgr.start(&name)).await;
    let latency = t0.elapsed().as_micros() as u64;
    match result {
        Err(_elapsed) => {
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, subject.id.as_str())
                    .with_method("server.services.start")
                    .with_detail(format!("unit={name} outcome=timeout"))
                    .with_latency_us(latency),
            );
            Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown })
        }
        Ok(Err(e)) => {
            let diag = backend_error_to_diagnostic(&e);
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, subject.id.as_str())
                    .with_method("server.services.start")
                    .with_detail(format!("unit={name} outcome=err"))
                    .with_latency_us(latency),
            );
            Err(diag)
        }
        Ok(Ok(state)) => {
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, subject.id.as_str())
                    .with_method("server.services.start")
                    .with_detail(format!("unit={name} outcome=ok"))
                    .with_latency_us(latency),
            );
            Ok(ServiceOutcomeDto { outcome: "ok", state })
        }
    }
}

pub async fn services_stop_result(
    be: &SystemBackend,
    audit: &DynAuditSink,
    subject: &Subject,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let t0 = Instant::now();
    let (mgr, name) = validate_and_get_manager(be, &params.name)?;
    let result = tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), mgr.stop(&name)).await;
    let latency = t0.elapsed().as_micros() as u64;
    match result {
        Err(_elapsed) => {
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, subject.id.as_str())
                    .with_method("server.services.stop")
                    .with_detail(format!("unit={name} outcome=timeout"))
                    .with_latency_us(latency),
            );
            Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown })
        }
        Ok(Err(e)) => {
            let diag = backend_error_to_diagnostic(&e);
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, subject.id.as_str())
                    .with_method("server.services.stop")
                    .with_detail(format!("unit={name} outcome=err"))
                    .with_latency_us(latency),
            );
            Err(diag)
        }
        Ok(Ok(state)) => {
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, subject.id.as_str())
                    .with_method("server.services.stop")
                    .with_detail(format!("unit={name} outcome=ok"))
                    .with_latency_us(latency),
            );
            Ok(ServiceOutcomeDto { outcome: "ok", state })
        }
    }
}

pub async fn services_restart_result(
    be: &SystemBackend,
    audit: &DynAuditSink,
    subject: &Subject,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let t0 = Instant::now();
    let (mgr, name) = validate_and_get_manager(be, &params.name)?;
    let result = tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), mgr.restart(&name)).await;
    let latency = t0.elapsed().as_micros() as u64;
    match result {
        Err(_elapsed) => {
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, subject.id.as_str())
                    .with_method("server.services.restart")
                    .with_detail(format!("unit={name} outcome=timeout"))
                    .with_latency_us(latency),
            );
            Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown })
        }
        Ok(Err(e)) => {
            let diag = backend_error_to_diagnostic(&e);
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Err, subject.id.as_str())
                    .with_method("server.services.restart")
                    .with_detail(format!("unit={name} outcome=err"))
                    .with_latency_us(latency),
            );
            Err(diag)
        }
        Ok(Ok(state)) => {
            audit.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, subject.id.as_str())
                    .with_method("server.services.restart")
                    .with_detail(format!("unit={name} outcome=ok"))
                    .with_latency_us(latency),
            );
            Ok(ServiceOutcomeDto { outcome: "ok", state })
        }
    }
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, deps: &ApiDeps) -> ServiceBuilder {
    let be = Arc::clone(&deps.backend);
    let audit = deps.audit.clone();

    let be1 = Arc::clone(&be);
    let audit1 = audit.clone();
    let list_method = Method::new("server.services.list").expect("valid method");
    let builder = register_scoped(
        builder,
        list_method,
        audit1,
        ScopeAudit::DenyOnly,
        move |p: ServicesListParams, _subject: Subject| {
            let be = Arc::clone(&be1);
            async move { services_list_result(&be, p).await }
        },
    );

    let be2 = Arc::clone(&be);
    let audit2 = audit.clone();
    let status_method = Method::new("server.services.status").expect("valid method");
    let builder = register_scoped(
        builder,
        status_method,
        audit2,
        ScopeAudit::DenyOnly,
        move |p: ServiceStatusParams, _subject: Subject| {
            let be = Arc::clone(&be2);
            async move { service_status_result(&be, p).await }
        },
    );

    let be3 = Arc::clone(&be);
    let audit3 = audit.clone();
    let start_method = Method::new("server.services.start").expect("valid method");
    let builder = register_scoped(
        builder,
        start_method,
        audit3.clone(),
        ScopeAudit::DenyOnly,
        move |p: ServiceMutateParams, subject: Subject| {
            let be = Arc::clone(&be3);
            let audit = audit3.clone();
            async move { services_start_result(&be, &audit, &subject, p).await }
        },
    );

    let be4 = Arc::clone(&be);
    let audit4 = audit.clone();
    let stop_method = Method::new("server.services.stop").expect("valid method");
    let builder = register_scoped(
        builder,
        stop_method,
        audit4.clone(),
        ScopeAudit::DenyOnly,
        move |p: ServiceMutateParams, subject: Subject| {
            let be = Arc::clone(&be4);
            let audit = audit4.clone();
            async move { services_stop_result(&be, &audit, &subject, p).await }
        },
    );

    let be5 = Arc::clone(&be);
    let audit5 = audit.clone();
    let restart_method = Method::new("server.services.restart").expect("valid method");
    register_scoped(
        builder,
        restart_method,
        audit5.clone(),
        ScopeAudit::DenyOnly,
        move |p: ServiceMutateParams, subject: Subject| {
            let be = Arc::clone(&be5);
            let audit = audit5.clone();
            async move { services_restart_result(&be, &audit, &subject, p).await }
        },
    )
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

    fn noop_subject() -> Subject {
        Subject {
            id: vaiexia_core::auth::SubjectId::new("user:test"),
            scopes: vaiexia_core::auth::ScopeSet::from_iter::<[&str; 0]>([]),
        }
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

    #[tokio::test]
    async fn services_list_rejects_oversized_glob() {
        let be = full_backend();
        let params = ServicesListParams {
            state_filter: None,
            name_glob: Some("*".repeat(MAX_GLOB_LEN + 1)),
            page: None,
        };
        let err = services_list_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn services_list_accepts_glob_at_limit() {
        let be = full_backend();
        let params = ServicesListParams {
            state_filter: None,
            name_glob: Some("*".repeat(MAX_GLOB_LEN)),
            page: None,
        };
        assert!(services_list_result(&be, params).await.is_ok());
    }

    // ── B2 mutation tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn services_start_returns_ok_and_active_state() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_start_result(&be, &crate::audit::noop(), &subj, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Active);
    }

    #[tokio::test]
    async fn services_start_invalid_name_returns_invalid_params() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "a b.service".into() };
        let err = services_start_result(&be, &crate::audit::noop(), &subj, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn services_stop_returns_ok_and_inactive_state() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_stop_result(&be, &crate::audit::noop(), &subj, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Inactive);
    }

    #[tokio::test]
    async fn services_restart_returns_ok_and_active_state() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_restart_result(&be, &crate::audit::noop(), &subj, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Active);
    }
}
