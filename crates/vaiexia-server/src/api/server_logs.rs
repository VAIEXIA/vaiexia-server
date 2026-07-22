use std::sync::Arc;
use serde::Deserialize;
use vaiexia_core::auth::Subject;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::{ApiDeps, ScopeAudit, dto::{LogEntryDto, PageDto}};
use crate::api::register_scoped;
use crate::backend::{LogQuery, SystemBackend, UnitName};
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

    // Validate the unit filter through the UnitName newtype (platform-neutral
    // hygiene: non-empty, ≤ 256 bytes, no NUL / control chars / path
    // separators). Systemd-specific rules (charset, known suffixes) are
    // enforced inside the systemd backend before the name reaches journalctl.
    if params
        .unit
        .as_deref()
        .is_some_and(|u| UnitName::parse(u).is_err())
    {
        return Err(Diagnostic::error(codes::INVALID_PARAMS, "invalid unit name"));
    }

    // Validate the (opaque) resume cursor: non-empty, bounded, no control
    // chars. It is passed to `journalctl --after-cursor` as an argv operand.
    if params
        .cursor
        .as_deref()
        .is_some_and(|c| !crate::backend::logs::cursor::is_valid(c))
    {
        return Err(Diagnostic::error(codes::INVALID_PARAMS, "invalid cursor"));
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

pub fn register(builder: ServiceBuilder, deps: &ApiDeps) -> ServiceBuilder {
    let be = Arc::clone(&deps.backend);
    let query_method = Method::new("server.logs.query").expect("valid method");
    // server.logs.query is on the sensitive-read list (logs can leak secrets, spec §4):
    // emit ScopeDecision-Allow in addition to the usual deny audit.
    register_scoped(
        builder,
        query_method,
        deps,
        ScopeAudit::AuditAllow,
        move |p: LogsQueryParams, _subject: Subject| {
            let be = Arc::clone(&be);
            async move { logs_query_result(&be, p).await }
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

    // `*` is a single printable ASCII character — it passes the generic
    // platform-neutral hygiene check (no control chars, no path separators).
    // The journalctl glob-expansion concern is now addressed at the systemd
    // backend boundary (via SystemdUnitName charset validation), not here.
    // The mock backend simply returns an empty page for an unknown unit name.
    #[tokio::test]
    async fn logs_query_glob_unit_passes_generic_hygiene() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: Some("*".into()),
            since: None,
            until: None,
            limit: 10,
            cursor: None,
        };
        // Generic API layer now accepts `*`; mock returns an empty result set.
        let page = logs_query_result(&be, params).await.unwrap();
        assert!(page.items.is_empty());
    }

    // Control characters must still be rejected at the generic API layer.
    #[tokio::test]
    async fn logs_query_rejects_control_char_unit() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: Some("foo\x01bar".into()),
            since: None,
            until: None,
            limit: 10,
            cursor: None,
        };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
    }

    // A `$`-containing name (Windows SCM style) must pass the generic API layer.
    #[tokio::test]
    async fn logs_query_dollar_unit_passes_generic_hygiene() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: Some("MSSQL$SQLEXPRESS".into()),
            since: None,
            until: None,
            limit: 10,
            cursor: None,
        };
        // No INVALID_PARAMS at the API layer; mock returns empty (no such unit).
        let page = logs_query_result(&be, params).await.unwrap();
        assert!(page.items.is_empty());
    }

    #[tokio::test]
    async fn logs_query_rejects_junk_unit() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: Some("../etc/shadow".into()),
            since: None,
            until: None,
            limit: 10,
            cursor: None,
        };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn logs_query_accepts_valid_unit() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: Some("nginx.service".into()),
            since: None,
            until: None,
            limit: 10,
            cursor: None,
        };
        assert!(logs_query_result(&be, params).await.is_ok());
    }

    #[tokio::test]
    async fn logs_query_rejects_empty_cursor() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: None,
            since: None,
            until: None,
            limit: 10,
            cursor: Some(String::new()),
        };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn logs_query_rejects_oversized_cursor() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: None,
            since: None,
            until: None,
            limit: 10,
            cursor: Some("s=".to_string() + &"a".repeat(4096)),
        };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn logs_query_accepts_realistic_cursor() {
        let be = full_backend();
        let params = LogsQueryParams {
            unit: None,
            since: None,
            until: None,
            limit: 10,
            cursor: Some("s=abc123;i=1;b=def456".into()),
        };
        assert!(logs_query_result(&be, params).await.is_ok());
    }

    #[tokio::test]
    async fn logs_query_unsupported_when_no_provider() {
        let be = no_logs_backend();
        let params = LogsQueryParams { unit: None, since: None, until: None, limit: 10, cursor: None };
        let err = logs_query_result(&be, params).await.unwrap_err();
        assert_eq!(err.code, "UNSUPPORTED");
    }
}
