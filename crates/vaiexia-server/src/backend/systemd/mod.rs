// Portable helpers — compiled on ALL platforms, unit-tested cross-platform.
pub mod unit;
pub mod manager;

// D-Bus I/O — Linux runtime only.
#[cfg(target_os = "linux")]
pub mod watch;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::SystemdServices;
