use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub services: bool,
    pub packages: bool,
    pub metrics: bool,
    pub logs: bool,
}

// ── Service types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitStatus {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: ServiceState,
    pub sub_state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitDetail {
    pub status: UnitStatus,
    pub since_ms: Option<u64>,
    pub main_pid: Option<u32>,
}

// ── Package types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub installed: bool,
    pub summary: Option<String>,
}

// ── Log types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    pub cursor: String,
    pub ts_us: u64,
    pub unit: Option<String>,
    pub priority: u8,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LogQuery {
    pub unit: Option<String>,
    pub since_us: Option<u64>,
    pub until_us: Option<u64>,
    pub limit: u32,
    pub cursor: Option<String>,
}

// ── Metrics types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub cpu_pct: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub load1: f32,
    pub load5: f32,
    pub load15: f32,
    pub uptime_secs: u64,
}

// ── Pagination ───────────────────────────────────────────────────────────────

/// A page of results + an opaque continuation cursor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}

