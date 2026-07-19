#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    #[error("not found")]
    NotFound,
    #[error("invalid name")]
    InvalidName,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsupported")]
    Unsupported,
    #[error("backend unavailable")]
    Unavailable,
    #[error("privilege setup broken")]
    Denied,
    #[error("busy")]
    Busy,
    #[error("timed out")]
    Timeout,
    #[error("protocol error")]
    Protocol,
    #[error("io error")]
    Io,
    #[error("internal error: {0}")]
    Internal(String),
}
