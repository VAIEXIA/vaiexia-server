use vaiexia_core::diagnostic::{codes, Diagnostic};
use crate::backend::BackendError;

// Domain-level codes not present in core::diagnostic::codes.
pub mod domain_codes {
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const UNSUPPORTED: &str = "UNSUPPORTED";
    pub const BACKEND_UNAVAILABLE: &str = "BACKEND_UNAVAILABLE";
    pub const BUSY: &str = "BUSY";
    pub const TIMEOUT: &str = "TIMEOUT";
}

/// Maps a backend error to a client-facing Diagnostic. Internal-detail variants
/// (Denied/Protocol/Io) collapse to INTERNAL — the real cause goes to the audit
/// log (Step 2/3), never across the wire.
pub fn backend_error_to_diagnostic(e: &BackendError) -> Diagnostic {
    use BackendError::*;
    match e {
        NotFound => Diagnostic::error(domain_codes::NOT_FOUND, "resource not found"),
        InvalidName => Diagnostic::error(codes::INVALID_PARAMS, "invalid name"),
        Unsupported => Diagnostic::error(domain_codes::UNSUPPORTED, "operation not supported on this host"),
        Unavailable => Diagnostic::error(domain_codes::BACKEND_UNAVAILABLE, "backend unavailable"),
        Busy => Diagnostic::error(domain_codes::BUSY, "resource busy"),
        Timeout => Diagnostic::error(domain_codes::TIMEOUT, "operation timed out"),
        Denied | Protocol | Io => Diagnostic::error(codes::INTERNAL, "internal error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_maps_to_not_found() {
        let d = backend_error_to_diagnostic(&BackendError::NotFound);
        assert_eq!(d.code, "NOT_FOUND");
    }

    #[test]
    fn invalid_name_maps_to_invalid_params() {
        let d = backend_error_to_diagnostic(&BackendError::InvalidName);
        assert_eq!(d.code, codes::INVALID_PARAMS);
    }

    #[test]
    fn unsupported_maps_to_unsupported() {
        let d = backend_error_to_diagnostic(&BackendError::Unsupported);
        assert_eq!(d.code, "UNSUPPORTED");
    }

    #[test]
    fn unavailable_maps_to_backend_unavailable() {
        let d = backend_error_to_diagnostic(&BackendError::Unavailable);
        assert_eq!(d.code, "BACKEND_UNAVAILABLE");
    }

    #[test]
    fn busy_maps_to_busy() {
        let d = backend_error_to_diagnostic(&BackendError::Busy);
        assert_eq!(d.code, "BUSY");
    }

    #[test]
    fn timeout_maps_to_timeout() {
        let d = backend_error_to_diagnostic(&BackendError::Timeout);
        assert_eq!(d.code, "TIMEOUT");
    }

    #[test]
    fn denied_maps_to_internal() {
        let d = backend_error_to_diagnostic(&BackendError::Denied);
        assert_eq!(d.code, codes::INTERNAL);
    }

    #[test]
    fn protocol_maps_to_internal() {
        let d = backend_error_to_diagnostic(&BackendError::Protocol);
        assert_eq!(d.code, codes::INTERNAL);
    }

    #[test]
    fn io_maps_to_internal() {
        let d = backend_error_to_diagnostic(&BackendError::Io);
        assert_eq!(d.code, codes::INTERNAL);
    }
}
