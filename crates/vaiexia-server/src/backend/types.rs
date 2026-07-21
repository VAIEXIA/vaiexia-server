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

/// Normalized service state — the platform-neutral projection every backend
/// maps onto. This is an OPEN set for wire-contract purposes: clients MUST
/// treat any unrecognized value as [`ServiceState::Unknown`] and never assume
/// the variant list is exhaustive. A non-systemd backend (e.g. a future Windows
/// SCM backend) maps its own states here — SCM `PAUSED` has no dedicated variant
/// and lands on `Unknown` with the native detail carried in `sub_state`; SCM has
/// no first-class `Failed` (approximated by stopped + nonzero exit).
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
    /// Platform-native, free-form state detail — NOT a stable enum. On systemd
    /// this is the unit load state (`loaded`/`not-found`/…); another backend
    /// fills its own native vocabulary. Clients display it but must not branch on it.
    pub load_state: String,
    pub active_state: ServiceState,
    /// Platform-native, free-form sub-state detail (systemd `running`/`dead`/…;
    /// a Windows SCM backend would put `paused`/`start-pending`/… here). Display-only.
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
    /// syslog severity scale 0–7 (0=emerg … 7=debug). Non-syslog sources map
    /// onto it — e.g. a Windows Event Log backend maps Critical..Verbose here.
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
    /// Unix load average (1/5/15 min). Reported as `0.0` on platforms without a
    /// load-average concept (e.g. Windows) — treat `0.0` as "unavailable", not idle.
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

