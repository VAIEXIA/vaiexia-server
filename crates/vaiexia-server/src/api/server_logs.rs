use std::sync::Arc;
use serde::Deserialize;
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::dto::{LogEntryDto, PageDto};
use crate::api::register_scoped;
use crate::backend::{LogQuery, SystemBackend};
use crate::diag::{backend_error_to_diagnostic, domain_codes};

const MAX_LIMIT: u32 = 1000;

// ── Params ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogsQueryParams {
    pub unit: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: u32,
    pub cursor: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

pub async fn logs_query_result(
    be: &SystemBackend,
    params: LogsQueryParams,
) -> Result<PageDto<LogEntryDto>, Diagnostic> {
    // Validate + clamp limit
    if params.limit > MAX_LIMIT {
        return Err(Diagnostic::error(codes::INVALID_PARAMS, "limit exceeds maximum of 1000"));
    }
    if params.limit == 0 {
        return Err(Diagnostic::error(codes::INVALID_PARAMS, "limit must be > 0"));
    }

    let provider = be
        .logs
        .as_ref()
        .ok_or_else(|| Diagnostic::error(domain_codes::UNSUPPORTED, "logs not supported on this host"))?;

    let q = LogQuery {
        unit: params.unit,
        since_us: params.since,
        until_us: params.until,
        limit: params.limit,
        cursor: params.cursor,
    };

    let page = provider
        .query(&q)
        .await
        .map_err(|e| backend_error_to_diagnostic(&e))?;
    Ok(PageDto::map_from(page, LogEntryDto::from))
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, be: Arc<SystemBackend>) -> ServiceBuilder {
    let query_method = Method::new("server.logs.query").expect("valid method");
    register_scoped(builder, query_method, move |p: LogsQueryParams, _subject: Subject| {
        let be = Arc::clone(&be);
        async move { logs_query_result(&be, p).await }
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

    fn no_logs_backend() -> Arc<SystemBackend> {
        let mock = Arc::new(MockBackend::new());
        let mut be = SystemBackend::from_mock(mock);
        be.logs = None;
        Arc::new(be)
    }

    #[tokio::test]
    async fn logs_query_respects_limit() {
        let be = full_backend();
        let params = LogsQueryParams { unit: None, since: None, until: None, limit: 5, cursor: None };
        let page = logs_query_result(&be, params).await.unwrap();
        assert!(page.items.len() <= 5);
    }

    #[tokio::test]
    async fn logs_query_entries_have_cursors() {
        let be = full_backend();
        let params = LogsQueryParams { unit: None, since: None, until: None, limit: 10, cursor: None };
        let page = logs_query_result(&be, params).await.unwrap();
        for entry in &page.items {
            assert!(!entry.cursor.is_empty());
        }
    }

    #[tokio::test]
    async fn logs_query_over_limit_returns_invalid_params() {
        let be = full_backend();
        let params = LogsQueryParams { unit: None, since: None, until: None, limit: 1001, cursor: None };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn logs_query_unsupported_when_no_provider() {
        let be = no_logs_backend();
        let params = LogsQueryParams { unit: None, since: None, until: None, limit: 10, cursor: None };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "UNSUPPORTED");
    }
}
