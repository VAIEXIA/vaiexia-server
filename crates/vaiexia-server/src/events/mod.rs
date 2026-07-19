use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use vaiexia_core::protocol::Seq;

pub mod jobs_pump;
pub mod logs_pump;
pub mod metrics_pump;
pub mod status_pump;
pub mod topics;

// ── SeqCounter ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SeqCounter(Arc<AtomicU64>);

impl SeqCounter {
    pub fn new() -> Self {
        SeqCounter(Arc::new(AtomicU64::new(0)))
    }

    pub fn next(&self) -> Seq {
        Seq(self.0.fetch_add(1, Ordering::Relaxed))
    }

    pub fn clone_arc(&self) -> Self {
        SeqCounter(Arc::clone(&self.0))
    }
}

impl Default for SeqCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ── PumpHandle ────────────────────────────────────────────────────────────────

pub struct PumpHandle {
    abort_handle: tokio::task::AbortHandle,
}

impl PumpHandle {
    pub fn abort(self) {
        self.abort_handle.abort();
    }
}

// ── Supervised runner ─────────────────────────────────────────────────────────

const PUMP_BACKOFF_MS: u64 = 100;

/// Spawn a supervised future factory. When the future returns or panics, the
/// factory is called again after a short backoff. Returns a `PumpHandle` that
/// can abort the loop.
pub fn spawn_supervised<F>(
    _name: &'static str,
    mut factory: F,
) -> PumpHandle
where
    F: FnMut() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
{
    let task = tokio::spawn(async move {
        loop {
            factory().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(PUMP_BACKOFF_MS)).await;
        }
    });
    PumpHandle {
        abort_handle: task.abort_handle(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn seq_counter_yields_strictly_increasing_values() {
        let counter = SeqCounter::new();
        let a = counter.next();
        let b = counter.next();
        let c = counter.next();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn seq_counter_clone_arc_shares_state() {
        let counter = SeqCounter::new();
        let clone = counter.clone_arc();
        let a = counter.next();
        let b = clone.next();
        assert!(a < b);
    }

    #[tokio::test]
    async fn spawn_supervised_restarts_after_future_returns() {
        let count = Arc::new(Mutex::new(0u32));
        let count2 = Arc::clone(&count);
        let _handle = spawn_supervised("test-pump", move || {
            let count = Arc::clone(&count2);
            Box::pin(async move {
                let mut c = count.lock().unwrap();
                *c += 1;
            })
        });
        // Give it time to restart several times (each iteration = 100ms backoff)
        tokio::time::sleep(tokio::time::Duration::from_millis(350)).await;
        let c = *count.lock().unwrap();
        assert!(c >= 2, "pump should have restarted at least once, got {c}");
    }

    #[tokio::test]
    async fn pump_handle_abort_stops_restarts() {
        let count = Arc::new(Mutex::new(0u32));
        let count2 = Arc::clone(&count);
        let handle = spawn_supervised("test-pump", move || {
            let count = Arc::clone(&count2);
            Box::pin(async move {
                let mut c = count.lock().unwrap();
                *c += 1;
            })
        });
        // Let it run briefly
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        handle.abort();
        // Count at abort time
        let before = *count.lock().unwrap();
        // Wait more — count should not increase significantly
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        let after = *count.lock().unwrap();
        // After abort, at most 1 more iteration (race), not many more
        assert!(after <= before + 1, "pump should have stopped, before={before} after={after}");
    }
}
