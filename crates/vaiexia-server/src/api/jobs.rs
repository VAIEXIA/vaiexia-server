use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;
use vaiexia_core::diagnostic::Diagnostic;

use crate::backend::BackendError;

// ── Types ─────────────────────────────────────────────────────────────────────

const RECENT_JOBS_CAPACITY: usize = 64;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JobState {
    Running,
    Succeeded,
    Failed { diagnostic: Diagnostic },
}

#[derive(Debug, Clone, Serialize)]
pub struct JobStatus {
    pub id: String,
    #[serde(flatten)]
    pub state: JobState,
    pub progress: Option<f32>,
    pub log_tail: Vec<String>,
}

// ── Registry ──────────────────────────────────────────────────────────────────

struct RegistryInner {
    /// The currently running job id, if any.
    running: Option<String>,
    /// Completed jobs (capped at RECENT_JOBS_CAPACITY).
    recent: HashMap<String, JobStatus>,
    /// Ordered list of recent job ids (for eviction).
    recent_order: Vec<String>,
}

impl RegistryInner {
    fn new() -> Self {
        Self {
            running: None,
            recent: HashMap::new(),
            recent_order: Vec::new(),
        }
    }

    fn store_terminal(&mut self, status: JobStatus) {
        // Evict oldest if at capacity
        if self.recent_order.len() >= RECENT_JOBS_CAPACITY {
            if let Some(evicted) = self.recent_order.first().cloned() {
                self.recent.remove(&evicted);
                self.recent_order.remove(0);
            }
        }
        self.recent_order.push(status.id.clone());
        self.recent.insert(status.id.clone(), status);
        self.running = None;
    }
}

pub struct JobRegistry {
    inner: Arc<Mutex<RegistryInner>>,
    tx: broadcast::Sender<JobStatus>,
}

impl JobRegistry {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(Mutex::new(RegistryInner::new())),
            tx,
        }
    }

    /// Try to start a new job. Returns the job id or `Err(BackendError::Busy)` if
    /// the single slot is occupied.
    pub fn try_start<F>(&self, _kind: &str, fut: F) -> Result<String, BackendError>
    where
        F: Future<Output = Result<(), Diagnostic>> + Send + 'static,
    {
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.running.is_some() {
                return Err(BackendError::Busy);
            }
            inner.running = Some(id.clone());
        }

        // Broadcast initial Running status
        let initial = JobStatus {
            id: id.clone(),
            state: JobState::Running,
            progress: None,
            log_tail: Vec::new(),
        };
        let _ = self.tx.send(initial);

        // Spawn job task — clones of inner/tx survive 'static
        let inner = Arc::clone(&self.inner);
        let tx = self.tx.clone();
        let job_id = id.clone();

        tokio::spawn(async move {
            let result = fut.await;
            let terminal = match result {
                Ok(()) => JobStatus {
                    id: job_id.clone(),
                    state: JobState::Succeeded,
                    progress: None,
                    log_tail: Vec::new(),
                },
                Err(diag) => JobStatus {
                    id: job_id.clone(),
                    state: JobState::Failed { diagnostic: diag },
                    progress: None,
                    log_tail: Vec::new(),
                },
            };
            let _ = tx.send(terminal.clone());
            inner.lock().unwrap().store_terminal(terminal);
        });

        Ok(id)
    }

    /// Get the status of a job by id. Returns `None` if unknown.
    pub fn status(&self, id: &str) -> Option<JobStatus> {
        let inner = self.inner.lock().unwrap();
        // Check recent (terminal) jobs
        if let Some(s) = inner.recent.get(id) {
            return Some(s.clone());
        }
        // Check if it's the currently running job
        if inner.running.as_deref() == Some(id) {
            return Some(JobStatus {
                id: id.to_string(),
                state: JobState::Running,
                progress: None,
                log_tail: Vec::new(),
            });
        }
        None
    }

    /// Subscribe to job status broadcasts.
    pub fn subscribe(&self) -> broadcast::Receiver<JobStatus> {
        self.tx.subscribe()
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::Duration;

    #[tokio::test]
    async fn try_start_returns_job_id_and_eventually_succeeds() {
        let registry = Arc::new(JobRegistry::new());
        let id = registry.try_start("install", async { Ok(()) }).unwrap();
        // Poll until done
        for _ in 0..50 {
            if let Some(status) = registry.status(&id) {
                if matches!(status.state, JobState::Succeeded) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("job never succeeded");
    }

    #[tokio::test]
    async fn second_try_start_while_first_running_returns_busy() {
        let registry = Arc::new(JobRegistry::new());
        let (_id, barrier_tx) = {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let id = registry.try_start("install", async move {
                let _ = rx.await;
                Ok(())
            }).unwrap();
            (id, tx)
        };
        // First job is still running (barrier not released)
        let result = registry.try_start("install", async { Ok(()) });
        assert!(matches!(result, Err(crate::backend::BackendError::Busy)));
        // Release barrier to let first job finish
        let _ = barrier_tx.send(());
    }

    #[tokio::test]
    async fn status_unknown_id_returns_none() {
        let registry = Arc::new(JobRegistry::new());
        assert!(registry.status("no-such-id").is_none());
    }

    #[tokio::test]
    async fn failed_future_produces_failed_state() {
        let registry = Arc::new(JobRegistry::new());
        let id = registry.try_start("install", async {
            Err(vaiexia_core::diagnostic::Diagnostic::error("TEST_ERR", "boom"))
        }).unwrap();
        for _ in 0..50 {
            if let Some(status) = registry.status(&id) {
                if matches!(&status.state, JobState::Failed { .. }) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("job never failed");
    }

    #[tokio::test]
    async fn completed_job_still_accessible() {
        let registry = Arc::new(JobRegistry::new());
        let id = registry.try_start("install", async { Ok(()) }).unwrap();
        // Wait for completion
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Should still be accessible even after slot cleared
        let status = registry.status(&id);
        assert!(status.is_some(), "completed job should still be accessible");
    }
}
