use std::sync::Mutex;
use std::time::{Duration, Instant};

use sysinfo::System;

use crate::backend::{BackendError, MetricsProvider, MetricsSnapshot};

/// Minimum gap between CPU refreshes so the OS can compute a meaningful delta.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(200);

pub struct SysinfoMetrics {
    sys: Mutex<System>,
    last_refresh: Mutex<Option<Instant>>,
}

impl SysinfoMetrics {
    pub fn new() -> Self {
        let mut sys = System::new();
        // Perform an initial refresh so that the first snapshot has a baseline.
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        Self {
            sys: Mutex::new(sys),
            last_refresh: Mutex::new(Some(Instant::now())),
        }
    }
}

impl Default for SysinfoMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsProvider for SysinfoMetrics {
    fn snapshot(&self) -> Result<MetricsSnapshot, BackendError> {
        let mut sys = self.sys.lock().map_err(|_| BackendError::Unavailable)?;
        let mut last = self.last_refresh.lock().map_err(|_| BackendError::Unavailable)?;

        let should_refresh = last
            .map(|t| t.elapsed() >= MIN_REFRESH_INTERVAL)
            .unwrap_or(true);

        if should_refresh {
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            *last = Some(Instant::now());
        }

        let cpu_pct = sys.global_cpu_usage();
        let mem_total = sys.total_memory();
        let mem_used = sys.used_memory();
        let uptime_secs = System::uptime();

        #[cfg(unix)]
        let load_avg = System::load_average();
        #[cfg(not(unix))]
        let load_avg = sysinfo::LoadAvg { one: 0.0, five: 0.0, fifteen: 0.0 };

        Ok(MetricsSnapshot {
            cpu_pct,
            mem_used,
            mem_total,
            load1: load_avg.one as f32,
            load5: load_avg.five as f32,
            load15: load_avg.fifteen as f32,
            uptime_secs,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::SysinfoMetrics;
    use crate::backend::MetricsProvider;
    use std::time::Duration;

    #[test]
    fn snapshot_mem_total_positive() {
        let m = SysinfoMetrics::new();
        let snap = m.snapshot().expect("snapshot should succeed");
        assert!(snap.mem_total > 0, "mem_total must be > 0");
    }

    #[test]
    fn snapshot_mem_used_le_total() {
        let m = SysinfoMetrics::new();
        let snap = m.snapshot().expect("snapshot should succeed");
        assert!(
            snap.mem_used <= snap.mem_total,
            "mem_used ({}) must be <= mem_total ({})",
            snap.mem_used,
            snap.mem_total
        );
    }

    #[test]
    fn snapshot_cpu_pct_in_range() {
        let m = SysinfoMetrics::new();
        let snap = m.snapshot().expect("snapshot should succeed");
        assert!(
            (0.0..=100.0).contains(&snap.cpu_pct),
            "cpu_pct ({}) must be in 0.0..=100.0",
            snap.cpu_pct
        );
    }

    #[test]
    fn snapshot_uptime_positive() {
        let m = SysinfoMetrics::new();
        let snap = m.snapshot().expect("snapshot should succeed");
        assert!(snap.uptime_secs > 0, "uptime_secs must be > 0");
    }

    #[test]
    fn two_snapshots_beyond_min_interval_both_succeed() {
        let m = SysinfoMetrics::new();
        let snap1 = m.snapshot().expect("first snapshot should succeed");
        // Sleep beyond the min_interval so CPU delta can be measured.
        std::thread::sleep(Duration::from_millis(250));
        let snap2 = m.snapshot().expect("second snapshot should succeed");
        // Both must satisfy the invariants.
        assert!(snap1.mem_total > 0);
        assert!(snap2.mem_total > 0);
        assert!((0.0..=100.0).contains(&snap1.cpu_pct));
        assert!((0.0..=100.0).contains(&snap2.cpu_pct));
    }

    #[test]
    fn load_averages_non_negative() {
        let m = SysinfoMetrics::new();
        let snap = m.snapshot().expect("snapshot should succeed");
        // On non-unix hosts (Windows), load averages are 0.0. On unix they are >= 0.
        assert!(snap.load1 >= 0.0, "load1 must be >= 0.0");
        assert!(snap.load5 >= 0.0, "load5 must be >= 0.0");
        assert!(snap.load15 >= 0.0, "load15 must be >= 0.0");
    }
}
