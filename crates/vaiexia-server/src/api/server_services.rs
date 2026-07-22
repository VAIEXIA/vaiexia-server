use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiDeps, ScopeAudit, dto::{PageDto, UnitDetailDto, UnitDto}};
use crate::api::register_scoped;
use crate::audit::{AuditDecision, AuditKind};
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

/// Shared body for start/stop/restart: validate, run under the mutation
/// timeout, audit the outcome. `verb` selects the backend call and names the
/// method in the audit record — the three public wrappers differ only in that.
async fn run_service_mutation(
    deps: &ApiDeps,
    subject: &Subject,
    verb: ServiceVerb,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    let t0 = Instant::now();
    let (mgr, name) = validate_and_get_manager(&deps.backend, &params.name)?;
    let call = async {
        match verb {
            ServiceVerb::Start => mgr.start(&name).await,
            ServiceVerb::Stop => mgr.stop(&name).await,
            ServiceVerb::Restart => mgr.restart(&name).await,
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(MUTATION_TIMEOUT_SECS), call).await;
    let latency = t0.elapsed().as_micros() as u64;
    let method = verb.method();
    let emit = |decision, outcome: &str| {
        deps.audit.emit(
            crate::api::subject_event(deps, subject, AuditKind::Mutation, decision)
                .with_method(method)
                .with_detail(format!("unit={name} outcome={outcome}"))
                .with_latency_us(latency),
        );
    };
    match result {
        Err(_elapsed) => {
            emit(AuditDecision::Err, "timeout");
            Ok(ServiceOutcomeDto { outcome: "timeout", state: ServiceState::Unknown })
        }
        Ok(Err(e)) => {
            let diag = backend_error_to_diagnostic(&e);
            emit(AuditDecision::Err, "err");
            Err(diag)
        }
        Ok(Ok(state)) => {
            emit(AuditDecision::Ok, "ok");
            Ok(ServiceOutcomeDto { outcome: "ok", state })
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ServiceVerb {
    Start,
    Stop,
    Restart,
}

impl ServiceVerb {
    fn method(self) -> &'static str {
        match self {
            Self::Start => "server.services.start",
            Self::Stop => "server.services.stop",
            Self::Restart => "server.services.restart",
        }
    }
}

pub async fn services_start_result(
    deps: &ApiDeps,
    subject: &Subject,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    run_service_mutation(deps, subject, ServiceVerb::Start, params).await
}

pub async fn services_stop_result(
    deps: &ApiDeps,
    subject: &Subject,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    run_service_mutation(deps, subject, ServiceVerb::Stop, params).await
}

pub async fn services_restart_result(
    deps: &ApiDeps,
    subject: &Subject,
    params: ServiceMutateParams,
) -> Result<ServiceOutcomeDto, Diagnostic> {
    run_service_mutation(deps, subject, ServiceVerb::Restart, params).await
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, deps: &ApiDeps) -> ServiceBuilder {
    let be = Arc::clone(&deps.backend);

    let be1 = Arc::clone(&be);
    let list_method = Method::new("server.services.list").expect("valid method");
    let builder = register_scoped(
        builder,
        list_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: ServicesListParams, _subject: Subject| {
            let be = Arc::clone(&be1);
            async move { services_list_result(&be, p).await }
        },
    );

    let be2 = Arc::clone(&be);
    let status_method = Method::new("server.services.status").expect("valid method");
    let builder = register_scoped(
        builder,
        status_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: ServiceStatusParams, _subject: Subject| {
            let be = Arc::clone(&be2);
            async move { service_status_result(&be, p).await }
        },
    );

    let deps3 = deps.clone();
    let start_method = Method::new("server.services.start").expect("valid method");
    let builder = register_scoped(
        builder,
        start_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: ServiceMutateParams, subject: Subject| {
            let deps = deps3.clone();
            async move { services_start_result(&deps, &subject, p).await }
        },
    );

    let deps4 = deps.clone();
    let stop_method = Method::new("server.services.stop").expect("valid method");
    let builder = register_scoped(
        builder,
        stop_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: ServiceMutateParams, subject: Subject| {
            let deps = deps4.clone();
            async move { services_stop_result(&deps, &subject, p).await }
        },
    );

    let deps5 = deps.clone();
    let restart_method = Method::new("server.services.restart").expect("valid method");
    register_scoped(
        builder,
        restart_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: ServiceMutateParams, subject: Subject| {
            let deps = deps5.clone();
            async move { services_restart_result(&deps, &subject, p).await }
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

    /// Handler deps with a discarding sink and no identity store — the audit
    /// `subject` then falls back to the raw subject id (see `ApiDeps`).
    fn test_deps(backend: Arc<SystemBackend>) -> ApiDeps {
        ApiDeps { backend, audit: crate::audit::noop(), subjects: None }
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

    // "a b.service" has a space (0x20) which passes the generic platform-neutral
    // hygiene check (no NUL / control chars / path separators). The API layer
    // accepts it; the mock backend returns NOT_FOUND because no unit matches.
    // Systemd-charset rejection ("a b" contains a space) is now enforced inside
    // the systemd backend, not in the generic API layer.
    #[tokio::test]
    async fn services_status_space_name_passes_generic_hygiene_not_found() {
        let be = full_backend();
        let params = ServiceStatusParams { name: "a b.service".into() };
        let err = service_status_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "NOT_FOUND");
    }

    // A name with a `$` sign (e.g. Windows SCM `MSSQL$SQLEXPRESS`) must now pass
    // the generic API hygiene check. The mock backend will return NOT_FOUND
    // (no such unit exists) — but no INVALID_PARAMS at the API boundary.
    #[tokio::test]
    async fn services_status_dollar_name_passes_generic_hygiene() {
        let be = full_backend();
        let params = ServiceStatusParams { name: "MSSQL$SQLEXPRESS".into() };
        let err = service_status_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "NOT_FOUND");
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
        let dto = services_start_result(&test_deps(be), &subj, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Active);
    }

    // "a b.service" passes generic API hygiene (space is not a control char /
    // path separator / NUL). The systemd-specific charset check is now at the
    // backend boundary. The mock returns NOT_FOUND.
    #[tokio::test]
    async fn services_start_space_name_passes_generic_hygiene_not_found() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "a b.service".into() };
        let err = services_start_result(&test_deps(be), &subj, params).await.unwrap_err();
        assert_eq!(err.code, "NOT_FOUND");
    }

    // Control characters must still be rejected at the generic API layer.
    #[tokio::test]
    async fn services_start_control_char_returns_invalid_params() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "foo\x01bar".into() };
        let err = services_start_result(&test_deps(be), &subj, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    // Path separators must still be rejected at the generic API layer.
    #[tokio::test]
    async fn services_start_path_sep_returns_invalid_params() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "../etc/shadow".into() };
        let err = services_start_result(&test_deps(be), &subj, params).await.unwrap_err();
        assert_eq!(err.code, vaiexia_core::diagnostic::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn services_stop_returns_ok_and_inactive_state() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_stop_result(&test_deps(be), &subj, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Inactive);
    }

    #[tokio::test]
    async fn services_restart_returns_ok_and_active_state() {
        let be = full_backend();
        let subj = noop_subject();
        let params = ServiceMutateParams { name: "nginx.service".into() };
        let dto = services_restart_result(&test_deps(be), &subj, params).await.unwrap();
        assert_eq!(dto.outcome, "ok");
        assert_eq!(dto.state, crate::backend::ServiceState::Active);
    }
}
