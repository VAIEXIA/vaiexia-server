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

use crate::auth::policy::{method_requirement, Requirement};
use crate::backend::SystemBackend;

/// The seam for Step 1+ modules to register themselves with the service builder.
pub trait ApiModule {
    fn register(self: Box<Self>, builder: ServiceBuilder, backend: Arc<SystemBackend>) -> ServiceBuilder;
}

/// Register a typed method handler with automatic scope enforcement.
///
/// Looks up the policy `Requirement` for `method` (panics if none — every
/// registered method MUST have a policy entry).  When the requirement is
/// `Scope(s)`, inserts a guard at the top of the handler that returns
/// `FORBIDDEN` if the authenticated `Subject` lacks that scope.  The guard
/// runs *inside* the handler so the diagnostic passes through dispatch
/// verbatim (not overwritten by UNAUTHENTICATED).
pub fn register_scoped<P, R, F, Fut>(
    builder: ServiceBuilder,
    method: Method,
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
    let handler = Arc::new(handler);
    builder.method_typed(method, move |params: P, subject: Subject| {
        let handler = Arc::clone(&handler);
        let scope = scope.clone();
        async move {
            if scope.as_ref().is_some_and(|s| !subject.scopes.contains(s)) {
                let s = scope.as_ref().unwrap();
                return Err(Diagnostic::error(
                    codes::FORBIDDEN,
                    format!("missing scope {}", s.as_str()),
                ));
            }
            handler(params, subject).await
        }
    })
}
