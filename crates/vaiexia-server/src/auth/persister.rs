//! Supervised identity-store maintenance task: flushes buffered last_used
//! timestamps every minute and compacts (prunes) hourly. Keeps ALL disk I/O
//! off the request hot path (Step-4 finding: touch-per-request store rewrite).
use std::sync::Arc;
use std::time::Duration;

use crate::auth::store::{now_secs, IdentityStore};
use crate::events::{spawn_supervised, PumpHandle};

/// Grace after expiry before a capability is pruned (24 h — an expired-but-
/// recent key still yields a clean UNAUTHENTICATED instead of vanishing).
pub const PRUNE_GRACE_SECS: u64 = 86_400;
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);
const PRUNE_EVERY_TICKS: u64 = 60; // hourly

pub async fn run(store: Arc<dyn IdentityStore>) {
    let mut tick = tokio::time::interval(FLUSH_INTERVAL);
    tick.tick().await; // consume the immediate first tick
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        n += 1;
        match store.flush_last_used() {
            Ok(u) if u > 0 => tracing::debug!(updated = u, "flushed last_used"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "last_used flush failed"),
        }
        if n.is_multiple_of(PRUNE_EVERY_TICKS) {
            match store.prune_capabilities(now_secs(), PRUNE_GRACE_SECS) {
                Ok(p) if p > 0 => tracing::info!(pruned = p, "identity store compaction"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "identity store compaction failed"),
            }
        }
    }
}

/// Spawn under the same supervision as the event pumps.
pub fn spawn_persister(store: Arc<dyn IdentityStore>) -> PumpHandle {
    spawn_supervised("persister", move || {
        let store = Arc::clone(&store);
        Box::pin(run(store))
    })
}
