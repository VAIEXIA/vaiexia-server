use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use base64::Engine;
use tokio::sync::broadcast;

use crate::backend::{
    BackendCapabilities, BackendError, HostInfo, HostInfoProvider,
    LogEntry, LogQuery, MetricsSnapshot, PackageInfo, Page,
    PackageManager, LogProvider, MetricsProvider, ServiceManager,
    ServiceState, UnitDetail, UnitStatus,
};

// ── MockState ────────────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 10;

#[derive(Clone)]
struct MockUnit {
    status: UnitStatus,
    since_ms: Option<u64>,
    main_pid: Option<u32>,
}

struct MockState {
    units: Vec<MockUnit>,
    packages: Vec<PackageInfo>,
    logs: Vec<LogEntry>,
    metrics: MetricsSnapshot,
    fail_next: Option<BackendError>,
}

impl Default for MockState {
    fn default() -> Self {
        Self {
            units: vec![
                MockUnit {
                    status: UnitStatus {
                        name: "nginx.service".into(),
                        description: "The NGINX HTTP Server".into(),
                        load_state: "loaded".into(),
                        active_state: ServiceState::Active,
                        sub_state: "running".into(),
                    },
                    since_ms: Some(1_700_000_000_000),
                    main_pid: Some(1234),
                },
                MockUnit {
                    status: UnitStatus {
                        name: "sshd.service".into(),
                        description: "OpenSSH Server".into(),
                        load_state: "loaded".into(),
                        active_state: ServiceState::Active,
                        sub_state: "running".into(),
                    },
                    since_ms: Some(1_700_000_001_000),
                    main_pid: Some(5678),
                },
                MockUnit {
                    status: UnitStatus {
                        name: "mysql.service".into(),
                        description: "MySQL Database".into(),
                        load_state: "loaded".into(),
                        active_state: ServiceState::Inactive,
                        sub_state: "dead".into(),
                    },
                    since_ms: None,
                    main_pid: None,
                },
            ],
            packages: vec![
                PackageInfo {
                    name: "nginx".into(),
                    version: "1.24.0".into(),
                    installed: true,
                    summary: Some("HTTP server".into()),
                },
                PackageInfo {
                    name: "curl".into(),
                    version: "8.1.0".into(),
                    installed: true,
                    summary: Some("URL transfer tool".into()),
                },
                PackageInfo {
                    name: "vim".into(),
                    version: "9.0".into(),
                    installed: false,
                    summary: Some("Text editor".into()),
                },
            ],
            logs: (0..25)
                .map(|i| LogEntry {
                    cursor: cursor_for(i),
                    ts_us: 1_700_000_000_000_000 + i as u64 * 1_000_000,
                    unit: Some("nginx.service".into()),
                    priority: 6,
                    message: format!("log message {}", i),
                })
                .collect(),
            metrics: MetricsSnapshot {
                cpu_pct: 12.5,
                mem_used: 1_073_741_824,
                mem_total: 8_589_934_592,
                load1: 0.5,
                load5: 0.3,
                load15: 0.2,
                uptime_secs: 86400,
            },
            fail_next: None,
        }
    }
}

fn cursor_for(idx: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(idx.to_string())
}

fn cursor_to_idx(cursor: &str) -> Option<usize> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(cursor).ok()?;
    let s = std::str::from_utf8(&bytes).ok()?;
    s.parse().ok()
}

// ── MockBackend ──────────────────────────────────────────────────────────────

pub struct MockBackend {
    state: Arc<Mutex<MockState>>,
    unit_tx: broadcast::Sender<UnitStatus>,
    log_tx: broadcast::Sender<LogEntry>,
}

impl MockBackend {
    pub fn new() -> Self {
        let (unit_tx, _) = broadcast::channel(64);
        let (log_tx, _) = broadcast::channel(64);
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            unit_tx,
            log_tx,
        }
    }

    /// Builder-style: prime mock to return error on the next call (consumes self).
    pub fn fail_next(self, err: BackendError) -> Self {
        self.state.lock().unwrap().fail_next = Some(err);
        self
    }

    /// Prime a failure from a shared reference.
    pub fn set_fail_next(&self, err: BackendError) {
        self.state.lock().unwrap().fail_next = Some(err);
    }

    /// Push a log entry to the follow stream.
    pub fn push_log(&self, entry: LogEntry) {
        let _ = self.log_tx.send(entry);
    }

    /// Override the scripted metrics snapshot.
    pub fn set_metrics(&self, m: MetricsSnapshot) {
        self.state.lock().unwrap().metrics = m;
    }

    /// Replace units (for test setup).
    pub fn with_units(self, units: Vec<(UnitStatus, Option<u64>, Option<u32>)>) -> Self {
        self.state.lock().unwrap().units = units
            .into_iter()
            .map(|(status, since_ms, main_pid)| MockUnit { status, since_ms, main_pid })
            .collect();
        self
    }

    pub fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            services: true,
            packages: true,
            metrics: true,
            logs: true,
        }
    }

    /// Take the queued failure, if any.
    fn take_failure(&self) -> Option<BackendError> {
        self.state.lock().unwrap().fail_next.take()
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ── HostInfoProvider ─────────────────────────────────────────────────────────

impl HostInfoProvider for MockBackend {
    fn host_info(&self) -> Result<HostInfo, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        Ok(HostInfo {
            hostname: "mock-host".into(),
            os: "mock-os".into(),
            kernel: "mock-kernel".into(),
            arch: "mock-arch".into(),
        })
    }

    fn capabilities(&self) -> BackendCapabilities {
        MockBackend::capabilities(self)
    }
}

// ── ServiceManager ───────────────────────────────────────────────────────────

#[async_trait]
impl ServiceManager for MockBackend {
    async fn list(
        &self,
        state_filter: Option<ServiceState>,
        _name_glob: Option<String>,
        page: Option<String>,
    ) -> Result<Page<UnitStatus>, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let state = self.state.lock().unwrap();
        let units: Vec<UnitStatus> = state
            .units
            .iter()
            .filter(|u| {
                state_filter
                    .map(|f| u.status.active_state == f)
                    .unwrap_or(true)
            })
            .map(|u| u.status.clone())
            .collect();

        let start = if let Some(ref cursor) = page {
            cursor_to_idx(cursor).unwrap_or(0)
        } else {
            0
        };

        let items: Vec<UnitStatus> = units.iter().skip(start).take(PAGE_SIZE).cloned().collect();
        let next = if start + PAGE_SIZE < units.len() {
            Some(cursor_for(start + PAGE_SIZE))
        } else {
            None
        };
        Ok(Page { items, next })
    }

    async fn status(&self, name: &str) -> Result<UnitDetail, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let state = self.state.lock().unwrap();
        let unit = state
            .units
            .iter()
            .find(|u| u.status.name == name)
            .ok_or(BackendError::NotFound)?;
        Ok(UnitDetail {
            status: unit.status.clone(),
            since_ms: unit.since_ms,
            main_pid: unit.main_pid,
        })
    }

    async fn start(&self, name: &str) -> Result<ServiceState, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let mut state = self.state.lock().unwrap();
        let unit = state
            .units
            .iter_mut()
            .find(|u| u.status.name == name)
            .ok_or(BackendError::NotFound)?;
        unit.status.active_state = ServiceState::Active;
        unit.status.sub_state = "running".into();
        let updated = unit.status.clone();
        drop(state);
        let _ = self.unit_tx.send(updated);
        Ok(ServiceState::Active)
    }

    async fn stop(&self, name: &str) -> Result<ServiceState, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let mut state = self.state.lock().unwrap();
        let unit = state
            .units
            .iter_mut()
            .find(|u| u.status.name == name)
            .ok_or(BackendError::NotFound)?;
        unit.status.active_state = ServiceState::Inactive;
        unit.status.sub_state = "dead".into();
        let updated = unit.status.clone();
        drop(state);
        let _ = self.unit_tx.send(updated);
        Ok(ServiceState::Inactive)
    }

    async fn restart(&self, name: &str) -> Result<ServiceState, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let mut state = self.state.lock().unwrap();
        let unit = state
            .units
            .iter_mut()
            .find(|u| u.status.name == name)
            .ok_or(BackendError::NotFound)?;
        unit.status.active_state = ServiceState::Active;
        unit.status.sub_state = "running".into();
        let updated = unit.status.clone();
        drop(state);
        let _ = self.unit_tx.send(updated);
        Ok(ServiceState::Active)
    }

    fn watch(&self) -> broadcast::Receiver<UnitStatus> {
        self.unit_tx.subscribe()
    }
}

// ── PackageManager ───────────────────────────────────────────────────────────

#[async_trait]
impl PackageManager for MockBackend {
    fn kind(&self) -> &'static str {
        "mock"
    }

    async fn list(
        &self,
        query: Option<String>,
        installed_only: bool,
        page: Option<String>,
    ) -> Result<Page<PackageInfo>, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let state = self.state.lock().unwrap();
        let pkgs: Vec<PackageInfo> = state
            .packages
            .iter()
            .filter(|p| !installed_only || p.installed)
            .filter(|p| {
                query
                    .as_ref()
                    .map(|q| p.name.contains(q.as_str()))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        let start = if let Some(ref cursor) = page {
            cursor_to_idx(cursor).unwrap_or(0)
        } else {
            0
        };
        let items: Vec<PackageInfo> = pkgs.iter().skip(start).take(PAGE_SIZE).cloned().collect();
        let next = if start + PAGE_SIZE < pkgs.len() {
            Some(cursor_for(start + PAGE_SIZE))
        } else {
            None
        };
        Ok(Page { items, next })
    }

    async fn install(&self, _name: &str) -> Result<(), BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        Ok(())
    }

    async fn remove(&self, _name: &str) -> Result<(), BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        Ok(())
    }
}

// ── MetricsProvider ──────────────────────────────────────────────────────────

impl MetricsProvider for MockBackend {
    fn snapshot(&self) -> Result<MetricsSnapshot, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        Ok(self.state.lock().unwrap().metrics)
    }
}

// ── LogProvider ──────────────────────────────────────────────────────────────

#[async_trait]
impl LogProvider for MockBackend {
    async fn query(&self, q: &LogQuery) -> Result<Page<LogEntry>, BackendError> {
        if let Some(err) = self.take_failure() {
            return Err(err);
        }
        let state = self.state.lock().unwrap();

        let start = if let Some(ref cursor) = q.cursor {
            cursor_to_idx(cursor).unwrap_or(0)
        } else {
            0
        };

        let limit = if q.limit == 0 { PAGE_SIZE } else { q.limit as usize };
        let filtered: Vec<LogEntry> = state
            .logs
            .iter()
            .filter(|e| q.unit.as_ref().map(|u| e.unit.as_deref() == Some(u)).unwrap_or(true))
            .filter(|e| q.since_us.map(|s| e.ts_us >= s).unwrap_or(true))
            .filter(|e| q.until_us.map(|u| e.ts_us <= u).unwrap_or(true))
            .cloned()
            .collect();

        let items: Vec<LogEntry> = filtered.iter().skip(start).take(limit).cloned().collect();
        let next_start = start + items.len();
        let next = if next_start < filtered.len() {
            Some(cursor_for(next_start))
        } else {
            None
        };
        Ok(Page { items, next })
    }

    fn follow(&self) -> broadcast::Receiver<LogEntry> {
        self.log_tx.subscribe()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{LogProvider, MetricsProvider, PackageManager, ServiceManager};

    #[test]
    fn new_returns_host_info() {
        let backend = MockBackend::new();
        let info = backend.host_info().unwrap();
        assert_eq!(info.hostname, "mock-host");
        assert_eq!(info.os, "mock-os");
        assert_eq!(info.kernel, "mock-kernel");
    }

    #[test]
    fn capabilities_all_true() {
        let backend = MockBackend::new();
        let caps = backend.capabilities();
        assert!(caps.services);
        assert!(caps.packages);
        assert!(caps.metrics);
        assert!(caps.logs);
    }

    #[test]
    fn fail_next_returns_error_once_then_succeeds() {
        let backend = MockBackend::new().fail_next(BackendError::Unavailable);
        assert_eq!(backend.host_info(), Err(BackendError::Unavailable));
        assert!(backend.host_info().is_ok());
    }

    #[tokio::test]
    async fn services_list_returns_scripted_units() {
        let mock = MockBackend::new();
        let page = ServiceManager::list(&mock, None, None, None).await.unwrap();
        assert!(!page.items.is_empty());
        assert!(page.items.iter().any(|u| u.name == "nginx.service"));
    }

    #[tokio::test]
    async fn services_status_ok() {
        let mock = MockBackend::new();
        let detail = ServiceManager::status(&mock, "nginx.service").await.unwrap();
        assert_eq!(detail.status.name, "nginx.service");
        assert!(detail.main_pid.is_some());
    }

    #[tokio::test]
    async fn services_status_not_found() {
        let mock = MockBackend::new();
        assert_eq!(
            ServiceManager::status(&mock, "ghost").await,
            Err(BackendError::NotFound)
        );
    }

    #[tokio::test]
    async fn start_emits_on_watch() {
        let mock = MockBackend::new();
        let mut rx = ServiceManager::watch(&mock);
        let state = ServiceManager::start(&mock, "nginx.service").await.unwrap();
        assert_eq!(state, ServiceState::Active);
        let update = rx.recv().await.unwrap();
        assert_eq!(update.name, "nginx.service");
        assert_eq!(update.active_state, ServiceState::Active);
    }

    #[tokio::test]
    async fn packages_list_installed_only() {
        let mock = MockBackend::new();
        let page = PackageManager::list(&mock, None, true, None).await.unwrap();
        assert!(page.items.iter().all(|p| p.installed));
    }

    #[tokio::test]
    async fn packages_install_ok() {
        let mock = MockBackend::new();
        assert!(PackageManager::install(&mock, "nginx").await.is_ok());
    }

    #[test]
    fn metrics_snapshot_has_positive_mem_total() {
        let mock = MockBackend::new();
        let snap = MetricsProvider::snapshot(&mock).unwrap();
        assert!(snap.mem_total > 0);
    }

    #[tokio::test]
    async fn logs_query_respects_limit() {
        let mock = MockBackend::new();
        let q = LogQuery { limit: 5, ..Default::default() };
        let page = LogProvider::query(&mock, &q).await.unwrap();
        assert!(page.items.len() <= 5);
    }

    #[tokio::test]
    async fn logs_query_entries_have_non_empty_cursor() {
        let mock = MockBackend::new();
        let q = LogQuery { limit: 10, ..Default::default() };
        let page = LogProvider::query(&mock, &q).await.unwrap();
        for entry in &page.items {
            assert!(!entry.cursor.is_empty());
        }
    }

    #[tokio::test]
    async fn logs_follow_receives_pushed_entry() {
        let mock = MockBackend::new();
        let mut rx = LogProvider::follow(&mock);
        let entry = LogEntry {
            cursor: "test-cursor".into(),
            ts_us: 12345,
            unit: Some("test.service".into()),
            priority: 3,
            message: "test message".into(),
        };
        mock.push_log(entry.clone());
        let received = rx.recv().await.unwrap();
        assert_eq!(received.cursor, "test-cursor");
        assert_eq!(received.message, "test message");
    }

    #[tokio::test]
    async fn fail_next_makes_services_list_fail() {
        let mock = MockBackend::new();
        mock.set_fail_next(BackendError::Busy);
        let result = ServiceManager::list(&mock, None, None, None).await;
        assert_eq!(result, Err(BackendError::Busy));
        // Second call succeeds
        assert!(ServiceManager::list(&mock, None, None, None).await.is_ok());
    }

    #[tokio::test]
    async fn pagination_returns_next_cursor_and_second_page() {
        let mock = MockBackend::new();
        // Default mock has 25 log entries
        let q = LogQuery { limit: 10, ..Default::default() };
        let page1 = LogProvider::query(&mock, &q).await.unwrap();
        assert_eq!(page1.items.len(), 10);
        assert!(page1.next.is_some());

        let q2 = LogQuery { limit: 10, cursor: page1.next.clone(), ..Default::default() };
        let page2 = LogProvider::query(&mock, &q2).await.unwrap();
        assert!(!page2.items.is_empty());
        // Pages should not overlap
        let ids1: Vec<&str> = page1.items.iter().map(|e| e.cursor.as_str()).collect();
        let ids2: Vec<&str> = page2.items.iter().map(|e| e.cursor.as_str()).collect();
        assert!(ids1.iter().all(|id| !ids2.contains(id)));
    }
}
