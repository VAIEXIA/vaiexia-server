use serde::{Deserialize, Serialize};
use crate::backend::{BackendCapabilities, HostInfo};

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
