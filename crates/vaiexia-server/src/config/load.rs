use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use std::net::SocketAddr;
use std::path::Path;

use crate::config::model::{ListenerKind, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no listeners configured")]
    Empty,
    #[error("obfs listeners are deferred (see spec §5.4)")]
    ObfsDeferred,
    #[error("TLS material (cert/key) missing for https listener")]
    TlsMaterialMissing,
    #[error("config error: {0}")]
    Figment(String),
}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        ConfigError::Figment(e.to_string())
    }
}

pub fn load(path: Option<&Path>) -> Result<ServerConfig, ConfigError> {
    let mut fig = Figment::from(Serialized::defaults(ServerConfig::default()));
    if let Some(p) = path {
        fig = fig.merge(Toml::file(p));
    }
    fig = fig.merge(Env::prefixed("VAIEXIA_SERVER__").split("__"));
    Ok(fig.extract()?)
}

pub fn validate(cfg: &ServerConfig) -> Result<Vec<String>, ConfigError> {
    if cfg.listeners.is_empty() {
        return Err(ConfigError::Empty);
    }
    let mut warnings = Vec::new();
    for l in &cfg.listeners {
        match l.kind {
            ListenerKind::ObfsTcp | ListenerKind::ObfsUdp => {
                return Err(ConfigError::ObfsDeferred);
            }
            ListenerKind::Https => {
                if l.cert.is_none() || l.key.is_none() {
                    return Err(ConfigError::TlsMaterialMissing);
                }
            }
            ListenerKind::Http => {
                // Warn if the HTTP listener is not on loopback.
                if let Ok(addr) = l.bind.parse::<SocketAddr>()
                    && !addr.ip().is_loopback()
                {
                    warnings.push(format!(
                        "http listener on non-loopback address {} — consider using https",
                        l.bind
                    ));
                }
            }
        }
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{Listener, ListenerKind};
    use std::path::PathBuf;

    #[test]
    fn parse_toml_with_http_listener() {
        let toml = r#"
[[listeners]]
kind = "http"
bind = "127.0.0.1:7443"
"#;
        // Write a temp file
        let dir = std::env::temp_dir();
        let path = dir.join("vaiexia-test-config.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].kind, ListenerKind::Http);
        assert_eq!(cfg.listeners[0].bind, "127.0.0.1:7443");
    }

    #[test]
    fn env_override_state_dir() {
        // Set an env var, load with no file, check override
        // SAFETY: single-threaded test, no concurrent env reads.
        unsafe { std::env::set_var("VAIEXIA_SERVER__STATE_DIR", "/tmp/x") };
        let cfg = load(None).unwrap();
        unsafe { std::env::remove_var("VAIEXIA_SERVER__STATE_DIR") };
        assert_eq!(cfg.state_dir, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn default_config_has_loopback_http_listener() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].kind, ListenerKind::Http);
        assert_eq!(cfg.listeners[0].bind, "127.0.0.1:7443");
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/vaiexia"));
    }

    #[test]
    fn validate_empty_listeners_returns_err() {
        let cfg = ServerConfig { state_dir: PathBuf::from("/var/lib/vaiexia"), listeners: vec![] };
        assert!(matches!(validate(&cfg), Err(ConfigError::Empty)));
    }

    #[test]
    fn validate_obfs_tcp_listener_returns_err() {
        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::ObfsTcp,
                bind: "127.0.0.1:9000".into(),
                cert: None,
                key: None,
            }],
        };
        assert!(matches!(validate(&cfg), Err(ConfigError::ObfsDeferred)));
    }

    #[test]
    fn validate_https_without_cert_returns_err() {
        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Https,
                bind: "127.0.0.1:443".into(),
                cert: None,
                key: None,
            }],
        };
        assert!(matches!(validate(&cfg), Err(ConfigError::TlsMaterialMissing)));
    }

    #[test]
    fn validate_non_loopback_http_returns_warning() {
        let cfg = ServerConfig {
            state_dir: PathBuf::from("/var/lib/vaiexia"),
            listeners: vec![Listener {
                kind: ListenerKind::Http,
                bind: "0.0.0.0:7443".into(),
                cert: None,
                key: None,
            }],
        };
        let warnings = validate(&cfg).unwrap();
        assert!(!warnings.is_empty());
    }
}
