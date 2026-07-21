//! `PrivTransport` trait — abstraction over the "privileged helper channel".
//!
//! The trait itself is portable; concrete implementations are gated by
//! platform `#[cfg]` attributes in their own modules.  A future Windows
//! named-pipe transport can implement `PrivTransport` without touching any
//! package logic.

use vaiexia_priv_proto::{PrivRequest, PrivResponse};

use crate::backend::BackendError;

/// A synchronous, blocking channel to the privileged helper daemon.
///
/// Implementations are expected to be cheap to clone or to live behind
/// `Arc`; callers may move them across thread-pool boundaries
/// (`tokio::task::spawn_blocking`).
pub trait PrivTransport: Send + Sync + 'static {
    /// Send `req` to the privileged helper and return its response.
    fn request(&self, req: &PrivRequest) -> Result<PrivResponse, BackendError>;
}
