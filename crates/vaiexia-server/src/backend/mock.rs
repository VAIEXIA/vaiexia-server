use std::sync::Mutex;
use crate::backend::{BackendCapabilities, BackendError, HostInfo, HostInfoProvider};

pub struct MockBackend {
    fail_queue: Mutex<Option<BackendError>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self { fail_queue: Mutex::new(None) }
    }

    /// Prime the mock to return this error on the next `host_info()` call.
    pub fn fail_next(self, err: BackendError) -> Self {
        *self.fail_queue.lock().unwrap() = Some(err);
        self
    }

    /// Set a queued failure from a shared reference (for use after construction).
    pub fn set_fail_next(&self, err: BackendError) {
        *self.fail_queue.lock().unwrap() = Some(err);
    }
}

impl Default for MockBackend {
    fn default() -> Self { Self::new() }
}

impl HostInfoProvider for MockBackend {
    fn host_info(&self) -> Result<HostInfo, BackendError> {
        if let Some(err) = self.fail_queue.lock().unwrap().take() {
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
        BackendCapabilities {
            services: false,
            packages: false,
            metrics: true,
            logs: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_host_info() {
        let backend = MockBackend::new();
        let info = backend.host_info().unwrap();
        assert_eq!(info.hostname, "mock-host");
        assert_eq!(info.os, "mock-os");
        assert_eq!(info.kernel, "mock-kernel");
    }

    #[test]
    fn capabilities_metrics_true_others_false() {
        let backend = MockBackend::new();
        let caps = backend.capabilities();
        assert!(!caps.services);
        assert!(!caps.packages);
        assert!(caps.metrics);
        assert!(!caps.logs);
    }

    #[test]
    fn fail_next_returns_error_once_then_succeeds() {
        let backend = MockBackend::new().fail_next(BackendError::Unavailable);
        assert_eq!(backend.host_info(), Err(BackendError::Unavailable));
        // Second call should succeed
        assert!(backend.host_info().is_ok());
    }
}
