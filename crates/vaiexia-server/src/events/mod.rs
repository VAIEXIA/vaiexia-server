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

/// Spawn a supervised future factory. When the future returns OR panics, the
/// factory is called again after a short backoff. Returns a `PumpHandle` that
/// can abort the loop.
///
/// The panic case is why the poll goes through `catch_unwind`: a panic inside
/// the pump future (a poisoned mutex in the job registry, a provider that
/// unwraps) would otherwise unwind the supervisor task itself, silently
/// killing that event source for the lifetime of the daemon. Catching keeps
/// the restart contract the name promises, and logs the panic — a pump that
/// dies quietly is exactly the kind of degradation an operator never notices.
///
/// The panicked future is dropped before the next attempt; the factory always
/// builds a fresh one, so no state is carried across a panic.
pub fn spawn_supervised<F>(
    name: &'static str,
    mut factory: F,
) -> PumpHandle
where
    F: FnMut() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
{
    let task = tokio::spawn(async move {
        loop {
            let mut fut = factory();
            let outcome = std::future::poll_fn(|cx| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    fut.as_mut().poll(cx)
                })) {
                    Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                    Ok(std::task::Poll::Ready(())) => std::task::Poll::Ready(Ok(())),
                    Err(payload) => std::task::Poll::Ready(Err(payload)),
                }
            })
            .await;
            drop(fut);
            if outcome.is_err() {
                tracing::error!(pump = name, "pump panicked — restarting after backoff");
            }
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

    /// A panicking pump must NOT kill the supervisor: the factory has to be
    /// called again. Without `catch_unwind` in `spawn_supervised` the panic
    /// unwinds the supervisor task and the count stays at 1 forever.
    #[tokio::test]
    async fn spawn_supervised_restarts_after_future_panics() {
        let count = Arc::new(Mutex::new(0u32));
        let count2 = Arc::clone(&count);
        // NOTE: the default panic hook is deliberately left in place — the
        // deliberate panic messages on stderr are noise, but swapping a
        // process-global hook would race every other test thread.
        let handle = spawn_supervised("panicking-pump", move || {
            let count = Arc::clone(&count2);
            Box::pin(async move {
                // Increment BEFORE panicking so the counter records attempts.
                {
                    let mut c = count.lock().unwrap();
                    *c += 1;
                }
                panic!("pump blew up");
            })
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(350)).await;
        handle.abort();
        let c = *count.lock().unwrap();
        assert!(c >= 2, "panicking pump must be restarted, got {c} attempt(s)");
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
