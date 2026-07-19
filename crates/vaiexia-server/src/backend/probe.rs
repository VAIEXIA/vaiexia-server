use crate::backend::types::BackendCapabilities;

/// Derive capabilities from which providers are present.
/// `metrics` is always `true` — it is always available.
pub fn derive_capabilities(services: bool, packages: bool, logs: bool) -> BackendCapabilities {
    BackendCapabilities {
        services,
        packages,
        metrics: true,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_false_still_has_metrics() {
        let caps = derive_capabilities(false, false, false);
        assert!(!caps.services);
        assert!(!caps.packages);
        assert!(caps.metrics);
        assert!(!caps.logs);
    }

    #[test]
    fn all_true() {
        let caps = derive_capabilities(true, true, true);
        assert!(caps.services);
        assert!(caps.packages);
        assert!(caps.metrics);
        assert!(caps.logs);
    }
}
