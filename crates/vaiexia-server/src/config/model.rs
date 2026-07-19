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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub state_dir: PathBuf,
    pub listeners: Vec<Listener>,
    pub backend: BackendCfg,
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
        }
    }
}
