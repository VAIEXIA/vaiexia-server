pub mod dto;
pub mod jobs;
pub mod server_host;
pub mod server_jobs;
pub mod server_logs;
pub mod server_module;
pub mod server_packages;
pub mod server_services;
pub mod auth_methods;

use std::sync::Arc;
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::audit::{AuditDecision, AuditEvent, AuditKind, DynAuditSink, reason};
use crate::auth::policy::{method_requirement, Requirement};
use crate::backend::SystemBackend;

/// Shared dependencies handed to every ApiModule (spec §9 shape — future
/// modules extend this struct instead of the trait signature).
#[derive(Clone)]
pub struct ApiDeps {
    pub backend: Arc<SystemBackend>,
    pub audit: DynAuditSink,
}

/// The seam for Step 1+ modules to register themselves with the service builder.
pub trait ApiModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, deps: &ApiDeps) -> ServiceBuilder;
}

/// Whether a scope-ALLOW is itself audit-worthy. Deny is always audited.
/// v1 sensitive-read list: exactly `server.logs.query` (logs can leak secrets,
/// spec §4). Subscribe-side log access is covered by verify_topic's
/// TopicDecision-allow. Extend ONLY with a spec citation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScopeAudit {
    DenyOnly,
    /// Also emit ScopeDecision-Allow (reason `sensitive_read`, severity notice).
    AuditAllow,
}

/// Register a typed method handler with automatic scope enforcement.
///
/// Looks up the policy `Requirement` for `method` (panics if none — every
/// registered method MUST have a policy entry).  When the requirement is
/// `Scope(s)`, inserts a guard at the top of the handler that returns
/// `FORBIDDEN` if the authenticated `Subject` lacks that scope.  The guard
/// runs *inside* the handler so the diagnostic passes through dispatch
/// verbatim (not overwritten by UNAUTHENTICATED).
///
/// `scope_audit`: `DenyOnly` → only scope denials are audited (the common
/// case). `AuditAllow` → also emit ScopeDecision-Allow (sensitive-read
/// amendment; v1: server.logs.query only).
pub fn register_scoped<P, R, F, Fut>(
    builder: ServiceBuilder,
    method: Method,
    audit: DynAuditSink,
    scope_audit: ScopeAudit,
    handler: F,
) -> ServiceBuilder
where
    P: serde::de::DeserializeOwned + Send + 'static,
    R: serde::Serialize + 'static,
    F: Fn(P, Subject) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<R, Diagnostic>> + Send + 'static,
{
    let requirement = method_requirement(&method).unwrap_or_else(|| {
        panic!(
            "no policy Requirement for method '{}' — every method MUST have one",
            method.as_str()
        )
    });
    let scope = match requirement {
        Requirement::Scope(s) => Some(s),
        _ => None,
    };
    let method_name = method.as_str().to_string();
    let handler = Arc::new(handler);
    builder.method_typed(method, move |params: P, subject: Subject| {
        let handler = Arc::clone(&handler);
        let scope = scope.clone();
        let audit = audit.clone();
        let method_name = method_name.clone();
        let scope_audit = scope_audit;
        async move {
            if scope.as_ref().is_some_and(|s| !subject.scopes.contains(s)) {
                let s = scope.as_ref().unwrap();
                audit.emit(
                    AuditEvent::new(
                        AuditKind::ScopeDecision,
                        AuditDecision::Deny,
                        subject.id.as_str(),
                    )
                    .with_method(&method_name)
                    .with_reason(reason::MISSING_SCOPE)
                    .with_detail(format!("missing scope {}", s.as_str())),
                );
                return Err(Diagnostic::error(
                    codes::FORBIDDEN,
                    format!("missing scope {}", s.as_str()),
                ));
            }
            // Scope passed — emit Allow if this is a sensitive-read method.
            if scope_audit == ScopeAudit::AuditAllow {
                audit.emit(
                    AuditEvent::new(
                        AuditKind::ScopeDecision,
                        AuditDecision::Allow,
                        subject.id.as_str(),
                    )
                    .with_method(&method_name)
                    .with_reason(reason::SENSITIVE_READ),
                );
            }
            handler(params, subject).await
        }
    })
}
