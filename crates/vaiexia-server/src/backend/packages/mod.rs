// Portable helpers — compiled on ALL platforms, unit-tested cross-platform.
pub mod detect;
pub mod query;

// Portable privileged-channel trait (no platform dependencies).
pub mod priv_transport;

// Unix-only process execution and privd client
#[cfg(unix)]
pub mod privd_client;

// Unix-only real implementation
#[cfg(unix)]
mod real;

#[cfg(unix)]
pub use real::RealPackageManager;
