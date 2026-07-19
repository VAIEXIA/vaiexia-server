// Portable helpers — compiled on ALL platforms, unit-tested cross-platform.
pub mod detect;
pub mod query;

// Unix-only process execution and privd client
#[cfg(unix)]
pub mod privd_client;

// Unix-only real implementation
#[cfg(unix)]
mod real;

#[cfg(unix)]
pub use real::RealPackageManager;
