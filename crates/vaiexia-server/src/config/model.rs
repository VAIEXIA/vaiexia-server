use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerKind {
    Http,
    Https,
    ObfsTcp,
    ObfsUdp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    pub kind: ListenerKind,
    pub bind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    // obfs-* fields (server_key/profile/allowed_client_keys) reserved; parsed in a later step.
}

/// How the daemon selects backend providers at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackendMode {
    /// Use real providers where the platform supports them; degrade to None otherwise.
    #[default]
    Auto,
    /// Always use the in-process mock (deterministic, no OS dependencies).
    Mock,
    /// Require all real providers; return an error if the platform does not support them.
    Real,
}

/// Backend selection configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendCfg {
    pub mode: BackendMode,
}

impl Default for BackendCfg {
    fn default() -> Self {
        Self { mode: BackendMode::Auto }
    }
}

/// Audit trail configuration.
///
/// The audit file is a BLAKE3-chained JSONL file (schema v1). Disable ONLY
/// for throwaway dev instances — the daemon logs a loud warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditCfg {
    /// Set `false` ONLY for throwaway dev instances; the daemon logs a loud warning.
    pub enabled: bool,
    /// Audit directory. Defaults to `<state_dir>/audit`.
    pub dir: Option<PathBuf>,
    /// Rotation threshold per file (bytes). Default: 8 MiB.
    pub max_bytes: u64,
    /// Rotated generations kept (`audit.jsonl.1` … `.N`). Minimum 1.
    pub generations: u8,
    /// Bounded queue between request tasks and the writer thread. Minimum 64.
    pub queue: usize,
}

impl Default for AuditCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            max_bytes: 8 * 1024 * 1024,
            generations: 3,
            queue: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub state_dir: PathBuf,
    pub listeners: Vec<Listener>,
    pub backend: BackendCfg,
    pub audit: AuditCfg,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Http,
                bind: "127.0.0.1:7443".into(),
                cert: None,
                key: None,
            }],
            backend: BackendCfg::default(),
            audit: AuditCfg::default(),
        }
    }
}
