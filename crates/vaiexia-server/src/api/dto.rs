use serde::{Deserialize, Serialize};
use crate::backend::{
    BackendCapabilities, HostInfo, LogEntry, MetricsSnapshot, PackageInfo, Page,
    ServiceState, UnitDetail, UnitStatus,
};

// ── Step 0 DTOs (unchanged) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilitiesDto {
    pub services: bool,
    pub packages: bool,
    pub metrics: bool,
    pub logs: bool,
}

impl From<BackendCapabilities> for BackendCapabilitiesDto {
    fn from(c: BackendCapabilities) -> Self {
        Self {
            services: c.services,
            packages: c.packages,
            metrics: c.metrics,
            logs: c.logs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfoDto {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub capabilities: BackendCapabilitiesDto,
}

impl HostInfoDto {
    pub fn from_parts(h: HostInfo, caps: BackendCapabilities) -> Self {
        Self {
            hostname: h.hostname,
            os: h.os,
            kernel: h.kernel,
            arch: h.arch,
            capabilities: caps.into(),
        }
    }
}

// ── Step 1 DTOs — frozen wire contract ──────────────────────────────────────

/// Pagination wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageDto<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}

impl<T> PageDto<T> {
    pub fn map_from<B, F>(page: Page<B>, f: F) -> Self
    where
        F: Fn(B) -> T,
    {
        PageDto {
            items: page.items.into_iter().map(f).collect(),
            next: page.next,
        }
    }
}

/// Compact unit listing entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitDto {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: ServiceState,
    pub sub_state: String,
}

impl From<UnitStatus> for UnitDto {
    fn from(s: UnitStatus) -> Self {
        Self {
            name: s.name,
            description: s.description,
            load_state: s.load_state,
            active_state: s.active_state,
            sub_state: s.sub_state,
        }
    }
}

/// Detailed unit status (for `server.services.status`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitDetailDto {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: ServiceState,
    pub sub_state: String,
    pub since_ms: Option<u64>,
    pub main_pid: Option<u32>,
}

impl From<UnitDetail> for UnitDetailDto {
    fn from(d: UnitDetail) -> Self {
        Self {
            name: d.status.name,
            description: d.status.description,
            load_state: d.status.load_state,
            active_state: d.status.active_state,
            sub_state: d.status.sub_state,
            since_ms: d.since_ms,
            main_pid: d.main_pid,
        }
    }
}

/// Package listing entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDto {
    pub name: String,
    pub version: String,
    pub installed: bool,
    pub summary: Option<String>,
}

impl From<PackageInfo> for PackageDto {
    fn from(p: PackageInfo) -> Self {
        Self {
            name: p.name,
            version: p.version,
            installed: p.installed,
            summary: p.summary,
        }
    }
}

/// System metrics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsDto {
    pub cpu_pct: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub load1: f32,
    pub load5: f32,
    pub load15: f32,
    pub uptime_secs: u64,
}

impl From<MetricsSnapshot> for MetricsDto {
    fn from(s: MetricsSnapshot) -> Self {
        Self {
            cpu_pct: s.cpu_pct,
            mem_used: s.mem_used,
            mem_total: s.mem_total,
            load1: s.load1,
            load5: s.load5,
            load15: s.load15,
            uptime_secs: s.uptime_secs,
        }
    }
}

/// Single journal/log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntryDto {
    pub cursor: String,
    pub ts_us: u64,
    pub unit: Option<String>,
    pub priority: u8,
    pub message: String,
}

impl From<LogEntry> for LogEntryDto {
    fn from(e: LogEntry) -> Self {
        Self {
            cursor: e.cursor,
            ts_us: e.ts_us,
            unit: e.unit,
            priority: e.priority,
            message: e.message,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::types::ServiceState;

    fn make_unit_status() -> UnitStatus {
        UnitStatus {
            name: "nginx.service".into(),
            description: "NGINX".into(),
            load_state: "loaded".into(),
            active_state: ServiceState::Active,
            sub_state: "running".into(),
        }
    }

    #[test]
    fn unit_dto_from_unit_status() {
        let status = make_unit_status();
        let dto = UnitDto::from(status);
        assert_eq!(dto.name, "nginx.service");
        assert_eq!(dto.active_state, ServiceState::Active);
    }

    #[test]
    fn unit_dto_serde_roundtrip() {
        let status = make_unit_status();
        let dto = UnitDto::from(status);
        let json = serde_json::to_string(&dto).unwrap();
        let back: UnitDto = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, dto.name);
        assert_eq!(back.active_state, dto.active_state);
    }

    #[test]
    fn unit_detail_dto_from_unit_detail() {
        let detail = UnitDetail {
            status: make_unit_status(),
            since_ms: Some(12345),
            main_pid: Some(999),
        };
        let dto = UnitDetailDto::from(detail);
        assert_eq!(dto.name, "nginx.service");
        assert_eq!(dto.since_ms, Some(12345));
        assert_eq!(dto.main_pid, Some(999));
    }

    #[test]
    fn package_dto_from_package_info() {
        let pkg = PackageInfo {
            name: "nginx".into(),
            version: "1.24".into(),
            installed: true,
            summary: Some("HTTP server".into()),
        };
        let dto = PackageDto::from(pkg);
        assert_eq!(dto.name, "nginx");
        assert!(dto.installed);
    }

    #[test]
    fn metrics_dto_from_metrics_snapshot() {
        let snap = MetricsSnapshot {
            cpu_pct: 25.0,
            mem_used: 1024,
            mem_total: 4096,
            load1: 0.5,
            load5: 0.3,
            load15: 0.2,
            uptime_secs: 3600,
        };
        let dto = MetricsDto::from(snap);
        assert_eq!(dto.mem_total, 4096);
        assert_eq!(dto.cpu_pct, 25.0);
    }

    #[test]
    fn log_entry_dto_from_log_entry() {
        let entry = LogEntry {
            cursor: "abc".into(),
            ts_us: 999,
            unit: Some("sshd.service".into()),
            priority: 3,
            message: "hello".into(),
        };
        let dto = LogEntryDto::from(entry);
        assert_eq!(dto.cursor, "abc");
        assert_eq!(dto.message, "hello");
    }

    #[test]
    fn page_dto_shape_with_next_null() {
        let page = Page::<UnitStatus> { items: vec![make_unit_status()], next: None };
        let dto = PageDto::map_from(page, UnitDto::from);
        let json = serde_json::to_value(&dto).unwrap();
        assert!(json["items"].is_array());
        assert!(json["next"].is_null());
    }

    #[test]
    fn page_dto_shape_with_next_some() {
        let page = Page::<UnitStatus> {
            items: vec![make_unit_status()],
            next: Some("cursor123".into()),
        };
        let dto = PageDto::map_from(page, UnitDto::from);
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["next"], "cursor123");
    }
}
