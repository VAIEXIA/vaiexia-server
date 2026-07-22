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
use crate::auth::store::IdentityStore;
use crate::backend::SystemBackend;

/// Shared dependencies handed to every ApiModule (spec §9 shape — future
/// modules extend this struct instead of the trait signature).
#[derive(Clone)]
pub struct ApiDeps {
    pub backend: Arc<SystemBackend>,
    pub audit: DynAuditSink,
    /// Identity snapshot source, used ONLY to resolve the `cap:<key_id>`
    /// handle a capability-authenticated `Subject` carries back to the
    /// account it belongs to, so audit records name a human. `None` in the
    /// permissive test service; records then fall back to the raw subject id.
    pub subjects: Option<Arc<dyn IdentityStore>>,
}

impl ApiDeps {
    /// The audit `subject` label for `subject`: the account id (`user:admin`),
    /// never the internal `cap:<key_id>` credential handle (schema v1 states
    /// the handle lives in `cap_key_id`). Falls back to the raw id when the
    /// handle cannot be resolved (unknown/pruned capability, or no store).
    pub fn subject_label(&self, subject: &Subject) -> String {
        if let Some(key_id) = cap_key_id(subject)
            && let Some(store) = &self.subjects
            && let Some(rec) = store.snapshot().lookup_capability(key_id)
        {
            return rec.subject_id.clone();
        }
        subject.id.as_str().to_string()
    }
}

/// The loggable capability handle of a capability-authenticated subject.
/// Returns `None` for anonymous/system subjects. NEVER exposes the secret —
/// the handle is all a `Subject` ever carries.
pub fn cap_key_id(subject: &Subject) -> Option<&str> {
    subject.id.as_str().strip_prefix("cap:")
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
    deps: &ApiDeps,
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
    let deps = deps.clone();
    builder.method_typed(method, move |params: P, subject: Subject| {
        let handler = Arc::clone(&handler);
        let scope = scope.clone();
        let deps = deps.clone();
        let method_name = method_name.clone();
        let scope_audit = scope_audit;
        async move {
            if scope.as_ref().is_some_and(|s| !subject.scopes.contains(s)) {
                let s = scope.as_ref().unwrap();
                deps.audit.emit(
                    scoped_event(&deps, &subject, AuditDecision::Deny)
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
                deps.audit.emit(
                    scoped_event(&deps, &subject, AuditDecision::Allow)
                        .with_method(&method_name)
                        .with_reason(reason::SENSITIVE_READ),
                );
            }
            handler(params, subject).await
        }
    })
}

/// An audit event attributed to `subject` the way schema v1 specifies: the
/// resolved account in `subject`, the credential handle in `cap_key_id`.
/// Every handler-side emit MUST go through this so no record ever carries the
/// internal `cap:<key_id>` handle in the human field.
pub fn subject_event(
    deps: &ApiDeps,
    subject: &Subject,
    kind: AuditKind,
    decision: AuditDecision,
) -> AuditEvent {
    let mut ev = AuditEvent::new(kind, decision, deps.subject_label(subject));
    if let Some(k) = cap_key_id(subject) {
        ev = ev.with_cap_key_id(k);
    }
    ev
}

/// [`subject_event`] specialised to `ScopeDecision`.
fn scoped_event(deps: &ApiDeps, subject: &Subject, decision: AuditDecision) -> AuditEvent {
    subject_event(deps, subject, AuditKind::ScopeDecision, decision)
}
