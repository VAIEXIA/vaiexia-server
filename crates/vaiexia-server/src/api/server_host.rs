use std::sync::Arc;
use serde::Deserialize;
use vaiexia_core::diagnostic::Diagnostic;
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::dto::HostInfoDto;
use crate::backend::SystemBackend;
use crate::diag::backend_error_to_diagnostic;

pub fn host_info_result(be: &SystemBackend) -> Result<HostInfoDto, Diagnostic> {
    let host = be.host.host_info().map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(HostInfoDto::from_parts(host, be.caps))
}

#[derive(Debug, Deserialize)]
pub struct HostInfoParams {} // {} — no params

pub fn register(builder: ServiceBuilder, be: Arc<SystemBackend>) -> ServiceBuilder {
    let method = Method::new("server.host.info").expect("valid method");
    builder.method_typed(method, move |_p: HostInfoParams, _subject| {
        let be = Arc::clone(&be);
        async move { host_info_result(&be) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::backend::{BackendError, HostInfoProvider, mock::MockBackend, SystemBackend};

    fn make_backend() -> Arc<SystemBackend> {
        let mock = Arc::new(MockBackend::new());
        let caps = mock.capabilities();
        Arc::new(SystemBackend { host: mock, caps })
    }

    #[test]
    fn host_info_result_returns_correct_hostname() {
        let be = make_backend();
        let dto = host_info_result(&be).unwrap();
        assert_eq!(dto.hostname, "mock-host");
        assert!(dto.capabilities.metrics);
    }

    #[test]
    fn host_info_result_with_unavailable_returns_backend_unavailable() {
        let mock = Arc::new(MockBackend::new());
        mock.set_fail_next(BackendError::Unavailable);
        let caps = mock.capabilities();
        let be = Arc::new(SystemBackend { host: mock, caps });
        let err = host_info_result(&be).unwrap_err();
        assert_eq!(err.code, "BACKEND_UNAVAILABLE");
    }
}
