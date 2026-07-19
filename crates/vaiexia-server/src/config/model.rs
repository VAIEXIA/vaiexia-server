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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub state_dir: PathBuf,
    pub listeners: Vec<Listener>,
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
        }
    }
}
