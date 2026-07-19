use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RateLimited {
    /// Approximate seconds until the window resets.
    pub retry_after_secs: u64,
}

struct Bucket {
    attempts: u32,
    window_start: Instant,
}

/// Soft cap on tracked keys. Buckets are keyed by attacker-controlled input
/// (e.g. login account name); without a cap a flood of distinct keys would grow
/// the map without bound. When exceeded, stale (fully-elapsed) buckets are
/// pruned before inserting a new key.
const DEFAULT_MAX_TRACKED: usize = 8192;

pub struct RateLimiter<C = fn() -> Instant> {
    max_attempts: u32,
    window: Duration,
    max_tracked: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
    clock: C,
}

impl RateLimiter {
    /// Create a rate limiter with real wall-clock time.
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self::with_clock(max_attempts, window, Instant::now)
    }
}

impl<C: Fn() -> Instant + Send + Sync> RateLimiter<C> {
    /// Create a rate limiter with an injectable clock (for testing).
    pub fn with_clock(max_attempts: u32, window: Duration, clock: C) -> Self {
        Self::with_clock_and_cap(max_attempts, window, DEFAULT_MAX_TRACKED, clock)
    }

    /// Create a rate limiter with an injectable clock and tracked-key cap.
    pub fn with_clock_and_cap(
        max_attempts: u32,
        window: Duration,
        max_tracked: usize,
        clock: C,
    ) -> Self {
        Self {
            max_attempts,
            window,
            max_tracked: max_tracked.max(1),
            buckets: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Check whether `key` is allowed to make another attempt.
    ///
    /// Returns `Ok(())` if under the limit, `Err(RateLimited)` if exceeded.
    pub fn check(&self, key: &str) -> Result<(), RateLimited> {
        let now = (self.clock)();
        let mut buckets = self.buckets.lock().expect("ratelimit mutex poisoned");

        // Bound memory: before tracking a brand-new key past the soft cap, drop
        // buckets whose window has fully elapsed (they'd reset on next use
        // anyway, so eviction changes no live limiting decision).
        if buckets.len() >= self.max_tracked && !buckets.contains_key(key) {
            let window = self.window;
            buckets.retain(|_, b| now.duration_since(b.window_start) < window);
        }

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            attempts: 0,
            window_start: now,
        });

        // Reset if window has elapsed.
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.attempts = 0;
            bucket.window_start = now;
        }

        if bucket.attempts >= self.max_attempts {
            let elapsed = now.duration_since(bucket.window_start);
            let remaining = self.window.saturating_sub(elapsed);
            return Err(RateLimited {
                retry_after_secs: remaining.as_secs().max(1),
            });
        }

        bucket.attempts += 1;
        Ok(())
    }

    /// Reset the counter for a key (e.g., after successful auth).
    pub fn reset(&self, key: &str) {
        let mut buckets = self.buckets.lock().expect("ratelimit mutex poisoned");
        buckets.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// A simple mutable fake clock for tests.
    ///
    /// We use `Arc<Mutex<Instant>>` so the closure is `Send + Sync` (required by
    /// `RateLimiter<C>`'s trait bounds) while still being sharable with the test body.
    fn make_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync) {
        let t = Arc::new(Mutex::new(Instant::now()));
        let t2 = Arc::clone(&t);
        let clock = move || *t2.lock().unwrap();
        (t, clock)
    }

    #[test]
    fn allows_up_to_max_attempts() {
        let rl: RateLimiter = RateLimiter::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(rl.check("user").is_ok());
        }
    }

    #[test]
    fn blocks_on_max_plus_one() {
        let rl: RateLimiter = RateLimiter::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            rl.check("user").unwrap();
        }
        assert!(rl.check("user").is_err());
    }

    #[test]
    fn different_keys_have_independent_budgets() {
        let rl: RateLimiter = RateLimiter::new(2, Duration::from_secs(60));
        rl.check("alice").unwrap();
        rl.check("alice").unwrap();
        // alice is now exhausted
        assert!(rl.check("alice").is_err());
        // bob still has budget
        assert!(rl.check("bob").is_ok());
    }

    #[test]
    fn budget_refills_after_window_with_injectable_clock() {
        let (clock_cell, clock) = make_clock();
        let window = Duration::from_secs(30);
        let rl = RateLimiter::with_clock(3, window, clock);

        // Exhaust budget
        for _ in 0..3 {
            rl.check("user").unwrap();
        }
        assert!(rl.check("user").is_err());

        // Advance time past the window
        let advanced = *clock_cell.lock().unwrap() + window + Duration::from_millis(1);
        *clock_cell.lock().unwrap() = advanced;

        // Budget should have refilled
        assert!(rl.check("user").is_ok(), "budget must refill after window");
    }

    #[test]
    fn stale_buckets_are_pruned_at_cap() {
        let (clock_cell, clock) = make_clock();
        let window = Duration::from_secs(30);
        // Cap at 4 tracked keys.
        let rl = RateLimiter::with_clock_and_cap(5, window, 4, clock);

        // Fill 4 distinct keys within the window.
        for i in 0..4 {
            rl.check(&format!("k{i}")).unwrap();
        }
        assert_eq!(rl.buckets.lock().unwrap().len(), 4);

        // Advance past the window so all existing buckets are stale.
        let advanced = *clock_cell.lock().unwrap() + window + Duration::from_millis(1);
        *clock_cell.lock().unwrap() = advanced;

        // A new distinct key trips pruning of the 4 stale buckets first.
        rl.check("fresh").unwrap();
        let len = rl.buckets.lock().unwrap().len();
        assert!(len <= 2, "stale buckets must be pruned, got {len}");
    }

    #[test]
    fn reset_clears_budget() {
        let rl: RateLimiter = RateLimiter::new(2, Duration::from_secs(60));
        rl.check("user").unwrap();
        rl.check("user").unwrap();
        assert!(rl.check("user").is_err());
        rl.reset("user");
        assert!(rl.check("user").is_ok());
    }

    #[test]
    fn rate_limited_carries_retry_after() {
        let rl: RateLimiter = RateLimiter::new(1, Duration::from_secs(60));
        rl.check("user").unwrap();
        let err = rl.check("user").unwrap_err();
        assert!(err.retry_after_secs >= 1);
    }
}
