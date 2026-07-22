use std::sync::Arc;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;
use vaiexia_priv_proto::PackageName;

use crate::api::{ApiDeps, ScopeAudit, subject_event, dto::{PackageDto, PageDto}};
use crate::api::jobs::JobRegistry;
use crate::api::register_scoped;
use crate::audit::{AuditDecision, AuditEvent, AuditKind};
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

/// Which package verb a mutation runs. Selects the backend call and names the
/// method in the audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageVerb {
    Install,
    Remove,
}

impl PackageVerb {
    fn method(self) -> &'static str {
        match self {
            Self::Install => "server.packages.install",
            Self::Remove => "server.packages.remove",
        }
    }
    fn job_kind(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Remove => "remove",
        }
    }
}

/// Shared body for install/remove.
///
/// Package mutations are the daemon's highest-privilege operation: they end up
/// in root-owned `privd` running a package manager. Every one of them —
/// accepted, rejected, and its eventual outcome — is audited here. The work
/// itself is asynchronous (a job), so the record is in two parts: a `mutation`
/// event for the request decision, and a `job` event for the outcome, joined
/// by the job id in `detail`.
async fn run_package_mutation(
    deps: &ApiDeps,
    registry: &Arc<JobRegistry>,
    subject: &Subject,
    verb: PackageVerb,
    params: PackageMutateParams,
) -> Result<JobStartDto, Diagnostic> {
    let t0 = Instant::now();
    let method = verb.method();
    // Reject paths are audited too: a stream of rejected installs is exactly
    // the signal that something is probing what this token can reach.
    let reject = |deps: &ApiDeps, detail: String, diag: Diagnostic| {
        deps.audit.emit(
            subject_event(deps, subject, AuditKind::Mutation, AuditDecision::Err)
                .with_method(method)
                .with_detail(detail)
                .with_latency_us(t0.elapsed().as_micros() as u64),
        );
        diag
    };

    let name = match parse_package_name(&params.name) {
        Ok(n) => n,
        // The raw parameter is NOT echoed into the record — `sanitize` caps and
        // strips it, but there is no reason to store attacker-chosen bytes when
        // "the name was invalid" is the whole finding.
        Err(d) => return Err(reject(deps, "outcome=rejected reason=invalid_name".into(), d)),
    };
    let pkgs = match deps.backend.packages.as_ref() {
        Some(p) => Arc::clone(p),
        None => {
            return Err(reject(
                deps,
                format!("pkg={name} outcome=rejected reason=unsupported"),
                Diagnostic::error(domain_codes::UNSUPPORTED, "packages not supported"),
            ));
        }
    };

    // The job future outlives this handler, so it owns everything it audits.
    let job_audit = deps.audit.clone();
    let job_subject = deps.subject_label(subject);
    let job_cap = crate::api::cap_key_id(subject).map(str::to_string);
    let job_name = name.clone();

    let started = registry.try_start(verb.job_kind(), async move {
        let t_job = std::time::Instant::now();
        let result = match verb {
            PackageVerb::Install => pkgs.install(&job_name).await,
            PackageVerb::Remove => pkgs.remove(&job_name).await,
        };
        let (decision, outcome) = match &result {
            Ok(()) => (AuditDecision::Ok, "ok"),
            Err(e) => (AuditDecision::Err, backend_outcome(e)),
        };
        let mut ev = AuditEvent::new(AuditKind::Job, decision, &job_subject)
            .with_method(method)
            .with_detail(format!("pkg={job_name} outcome={outcome}"))
            .with_latency_us(t_job.elapsed().as_micros() as u64);
        if let Some(k) = &job_cap {
            ev = ev.with_cap_key_id(k);
        }
        job_audit.emit(ev);
        result.map_err(|e| backend_error_to_diagnostic(&e))
    });

    let job_id = match started {
        Ok(id) => id,
        Err(e) => {
            let diag = backend_error_to_diagnostic(&e);
            return Err(reject(
                deps,
                format!("pkg={name} outcome=rejected reason=busy"),
                diag,
            ));
        }
    };

    deps.audit.emit(
        subject_event(deps, subject, AuditKind::Mutation, AuditDecision::Ok)
            .with_method(method)
            .with_detail(format!("pkg={name} outcome=accepted job={job_id}"))
            .with_latency_us(t0.elapsed().as_micros() as u64),
    );
    Ok(JobStartDto { job_id })
}

/// Stable, low-cardinality outcome word for a failed package job. The backend
/// error's own message may carry package-manager stderr, which does not belong
/// in a structured audit field.
fn backend_outcome(e: &crate::backend::BackendError) -> &'static str {
    use crate::backend::BackendError as E;
    match e {
        E::Timeout => "timeout",
        E::Unavailable => "unavailable",
        E::Denied => "denied",
        E::NotFound => "not_found",
        E::InvalidName | E::InvalidInput(_) => "invalid_name",
        _ => "err",
    }
}

pub async fn packages_install_result(
    deps: &ApiDeps,
    registry: &Arc<JobRegistry>,
    subject: &Subject,
    params: PackageMutateParams,
) -> Result<JobStartDto, Diagnostic> {
    run_package_mutation(deps, registry, subject, PackageVerb::Install, params).await
}

pub async fn packages_remove_result(
    deps: &ApiDeps,
    registry: &Arc<JobRegistry>,
    subject: &Subject,
    params: PackageMutateParams,
) -> Result<JobStartDto, Diagnostic> {
    run_package_mutation(deps, registry, subject, PackageVerb::Remove, params).await
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, deps: &ApiDeps, registry: Arc<JobRegistry>) -> ServiceBuilder {
    let be = Arc::clone(&deps.backend);

    let be1 = Arc::clone(&be);
    let list_method = Method::new("server.packages.list").expect("valid method");
    let builder = register_scoped(
        builder,
        list_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: PackagesListParams, _subject: Subject| {
            let be = Arc::clone(&be1);
            async move { packages_list_result(&be, p).await }
        },
    );

    let deps2 = deps.clone();
    let reg2 = Arc::clone(&registry);
    let install_method = Method::new("server.packages.install").expect("valid method");
    let builder = register_scoped(
        builder,
        install_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: PackageMutateParams, subject: Subject| {
            let deps = deps2.clone();
            let reg = Arc::clone(&reg2);
            async move { packages_install_result(&deps, &reg, &subject, p).await }
        },
    );

    let deps3 = deps.clone();
    let reg3 = Arc::clone(&registry);
    let remove_method = Method::new("server.packages.remove").expect("valid method");
    register_scoped(
        builder,
        remove_method,
        deps,
        ScopeAudit::DenyOnly,
        move |p: PackageMutateParams, subject: Subject| {
            let deps = deps3.clone();
            let reg = Arc::clone(&reg3);
            async move { packages_remove_result(&deps, &reg, &subject, p).await }
        },
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::audit::AuditSink as _;
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

    /// Deps with a discarding sink (no identity store — `subject` falls back
    /// to the raw id, which is what the mutation tests assert on).
    fn test_deps(backend: Arc<SystemBackend>) -> ApiDeps {
        ApiDeps { backend, audit: crate::audit::noop(), subjects: None }
    }

    fn test_subject() -> Subject {
        Subject {
            id: vaiexia_core::auth::SubjectId::new("user:admin"),
            scopes: vaiexia_core::auth::ScopeSet::from_iter(["server.packages.write"]),
        }
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
        let dto = packages_install_result(&test_deps(be), &registry, &test_subject(), params).await.unwrap();
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
        let err = packages_install_result(&test_deps(be), &registry, &test_subject(), params).await.unwrap_err();
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
        let err = packages_install_result(&test_deps(be), &registry, &test_subject(), params).await.unwrap_err();
        assert_eq!(err.code, crate::diag::domain_codes::BUSY);
        let _ = tx.send(());
    }

    /// The privileged path must leave evidence: an accepted install writes a
    /// `mutation` record naming the package and the job, and the job's outcome
    /// writes a `job` record. Before this was wired, a root-level package
    /// install produced NO audit record at all.
    #[tokio::test]
    async fn package_install_writes_mutation_and_job_records() {
        let dir = std::env::temp_dir()
            .join(format!("vx-audit-pkg-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let (sink, writer) = crate::audit::FileAuditSink::new(64, path.clone(), 1 << 20, 1);
        let th = writer.spawn();

        let deps = ApiDeps {
            backend: full_backend(),
            audit: sink.clone() as crate::audit::DynAuditSink,
            subjects: None,
        };
        let registry = Arc::new(crate::api::jobs::JobRegistry::new());
        let dto = packages_install_result(
            &deps,
            &registry,
            &test_subject(),
            PackageMutateParams { name: "nginx".into() },
        )
        .await
        .unwrap();

        // Wait for the job to reach a terminal state so its record is emitted.
        for _ in 0..50 {
            if registry
                .status(&dto.job_id)
                .is_some_and(|s| !matches!(s.state, crate::api::jobs::JobState::Running))
            {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
        drop(deps);
        sink.shutdown();
        drop(sink);
        th.join().unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("\"kind\":\"mutation\"") && body.contains("server.packages.install"),
            "install request must be audited:\n{body}"
        );
        assert!(
            body.contains(&format!("job={}", dto.job_id)),
            "the mutation record must name the job it started:\n{body}"
        );
        assert!(
            body.contains("\"kind\":\"job\"") && body.contains("pkg=nginx outcome=ok"),
            "the job outcome must be audited:\n{body}"
        );
        assert!(
            crate::audit::verify_chain(&path).is_ok(),
            "records must satisfy schema v1"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rejected install is evidence too — probing for reachable packages must
    /// not be invisible.
    #[tokio::test]
    async fn rejected_package_install_is_audited() {
        let dir = std::env::temp_dir()
            .join(format!("vx-audit-pkg-rej-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let (sink, writer) = crate::audit::FileAuditSink::new(64, path.clone(), 1 << 20, 1);
        let th = writer.spawn();

        let deps = ApiDeps {
            backend: full_backend(),
            audit: sink.clone() as crate::audit::DynAuditSink,
            subjects: None,
        };
        let registry = Arc::new(crate::api::jobs::JobRegistry::new());
        let err = packages_install_result(
            &deps,
            &registry,
            &test_subject(),
            PackageMutateParams { name: "Bad Name!".into() },
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);

        drop(deps);
        sink.shutdown();
        drop(sink);
        th.join().unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("reason=invalid_name") && body.contains("\"decision\":\"err\""),
            "rejected install must be audited:\n{body}"
        );
        // The hostile parameter itself is deliberately not echoed.
        assert!(!body.contains("Bad Name!"), "raw param must not be stored:\n{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn packages_remove_returns_job_id() {
        let be = full_backend();
        let registry = std::sync::Arc::new(crate::api::jobs::JobRegistry::new());
        let params = PackageMutateParams { name: "nginx".into() };
        let dto = packages_remove_result(&test_deps(be), &registry, &test_subject(), params).await.unwrap();
        assert!(!dto.job_id.is_empty());
    }
}
