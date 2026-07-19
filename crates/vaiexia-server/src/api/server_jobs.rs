use std::sync::Arc;
use serde::Deserialize;
use vaiexia_core::diagnostic::Diagnostic;
use vaiexia_core::protocol::Method;
use vaiexia_core::server::ServiceBuilder;

use crate::api::jobs::{JobRegistry, JobStatus};
use crate::diag::domain_codes;

// ── Params ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JobsStatusParams {
    pub job_id: String,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

pub fn jobs_status_result(
    registry: &JobRegistry,
    params: JobsStatusParams,
) -> Result<JobStatus, Diagnostic> {
    registry
        .status(&params.job_id)
        .ok_or_else(|| Diagnostic::error(domain_codes::NOT_FOUND, "job not found"))
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(builder: ServiceBuilder, registry: Arc<JobRegistry>) -> ServiceBuilder {
    let status_method = Method::new("server.jobs.status").expect("valid method");
    builder.method_typed(status_method, move |p: JobsStatusParams, _subject| {
        let registry = Arc::clone(&registry);
        async move { jobs_status_result(&registry, p) }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn jobs_status_not_found_for_unknown_id() {
        let registry = Arc::new(JobRegistry::new());
        let params = JobsStatusParams { job_id: "nonexistent".into() };
        let err = jobs_status_result(&registry, params).unwrap_err();
        assert_eq!(err.code, crate::diag::domain_codes::NOT_FOUND);
    }

    #[tokio::test]
    async fn jobs_status_found_for_completed_job() {
        let registry = Arc::new(JobRegistry::new());
        let id = registry.try_start("install", async { Ok(()) }).unwrap();
        // Wait for completion
        for _ in 0..50 {
            if let Some(status) = registry.status(&id)
                && matches!(status.state, crate::api::jobs::JobState::Succeeded)
            {
                let params = JobsStatusParams { job_id: id.clone() };
                let result = jobs_status_result(&registry, params).unwrap();
                assert_eq!(result.id, id);
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
        panic!("job never completed");
    }
}
