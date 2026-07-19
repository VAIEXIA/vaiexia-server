// Portable helpers — compiled on ALL platforms, unit-tested cross-platform.
pub mod journald;
pub mod cursor;

// Linux-only real implementation
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::JournaldLogs;
