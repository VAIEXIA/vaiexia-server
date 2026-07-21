//! Linux-only D-Bus implementation of `ServiceManager` via zbus.
//! Only compiled on Linux (`#[cfg(target_os = "linux")]` in mod.rs).

use std::sync::Arc;
use async_trait::async_trait;
use futures_util::StreamExt as _;
use tokio::sync::broadcast;
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

use crate::backend::{
    BackendError, Page, ServiceManager, ServiceState, UnitDetail, UnitStatus,
};
use super::unit::{active_state_from_dbus, validate};
use super::manager::{list_filter, paginate};

// ── D-Bus proxy ──────────────────────────────────────────────────────────────

/// org.freedesktop.systemd1.Manager proxy.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub(crate) trait Manager {
    /// List all units.
    #[allow(clippy::type_complexity)]
    fn list_units(
        &self,
    ) -> zbus::Result<
        Vec<(
            String, String, String, String, String,
            String, OwnedObjectPath, u32, String, OwnedObjectPath,
        )>,
    >;

    /// Get the object path of the named unit.
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    /// Start a unit with the given mode (use "replace").
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// Stop a unit.
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// Restart a unit.
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// Subscribe to D-Bus signals.
    fn subscribe(&self) -> zbus::Result<()>;

    /// JobRemoved signal: (id, job_path, unit, result)
    #[zbus(signal)]
    fn job_removed(
        &self,
        id: u32,
        job: zbus::zvariant::ObjectPath<'_>,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;
}

/// org.freedesktop.systemd1.Unit proxy — per-unit properties.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
pub(crate) trait Unit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn sub_state(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn description(&self) -> zbus::Result<String>;

    /// Microseconds since epoch when the unit entered the active state.
    #[zbus(property)]
    fn active_enter_timestamp(&self) -> zbus::Result<u64>;

    /// Main PID (0 if not a service or not running).
    #[zbus(property)]
    fn main_pid(&self) -> zbus::Result<u32>;
}

// ── SystemdServices ──────────────────────────────────────────────────────────

/// Real `ServiceManager` backed by the systemd D-Bus API.
pub struct SystemdServices {
    conn: Connection,
    unit_tx: broadcast::Sender<UnitStatus>,
}

impl SystemdServices {
    /// Connect to the system bus. Returns an error if the bus is unreachable.
    pub async fn new() -> Result<Arc<Self>, BackendError> {
        let conn = Connection::system()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        let (unit_tx, _) = broadcast::channel(256);
        let svc = Arc::new(Self { conn, unit_tx });
        // Spawn the watch task.
        let conn2 = svc.conn.clone();
        let tx2 = svc.unit_tx.clone();
        tokio::spawn(async move {
            super::watch::spawn_watch_task(conn2, tx2).await;
        });
        Ok(svc)
    }

    /// Probe whether the system D-Bus is reachable.
    pub async fn probe() -> bool {
        Connection::system().await.is_ok()
    }

    /// Issue a start/stop/restart verb, await the matching JobRemoved signal,
    /// then return the resulting ServiceState.
    async fn run_job(&self, name: &str, verb: &str) -> Result<ServiceState, BackendError> {
        let manager = ManagerProxy::new(&self.conn)
            .await
            .map_err(map_dbus_error)?;

        // Subscribe before submitting the job to avoid missing the signal.
        manager.subscribe().await.map_err(map_dbus_error)?;

        // Set up signal stream before triggering the job so we don't race.
        let mut signal_stream = manager.receive_job_removed().await.map_err(map_dbus_error)?;

        // Submit the job.
        let job_path: OwnedObjectPath = match verb {
            "start" => manager.start_unit(name, "replace").await,
            "stop" => manager.stop_unit(name, "replace").await,
            "restart" => manager.restart_unit(name, "replace").await,
            _ => unreachable!("unknown verb"),
        }
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("NoSuchUnit") {
                BackendError::NotFound
            } else if s.contains("AccessDenied") || s.contains("Authorization") {
                BackendError::Denied
            } else {
                map_dbus_error(e)
            }
        })?;

        // Wait for the JobRemoved signal matching our job path or unit name.
        let job_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            async {
                while let Some(signal) = signal_stream.next().await {
                    let args = match signal.args() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    // Match by job object path (as str) or unit name.
                    if args.job.as_str() == job_path.as_str() || args.unit == name {
                        return Ok(args.result.to_string());
                    }
                }
                Err(BackendError::Unavailable)
            },
        )
        .await
        .map_err(|_| BackendError::Timeout)??;

        // Map the result string to a final state.
        match job_result.as_str() {
            "done" | "skipped" => {
                // Query the actual resulting state.
                match self.status(name).await {
                    Ok(detail) => Ok(detail.status.active_state),
                    Err(_) => Ok(ServiceState::Unknown),
                }
            }
            "failed" => Ok(ServiceState::Failed),
            "canceled" | "dependency" => Err(BackendError::Unavailable),
            _ => Ok(ServiceState::Unknown),
        }
    }
}

// ── error mapping ────────────────────────────────────────────────────────────

fn map_dbus_error(e: zbus::Error) -> BackendError {
    let msg = e.to_string();
    if msg.contains("AccessDenied")
        || msg.contains("PolicyKit")
        || msg.contains("Authorization")
    {
        BackendError::Denied
    } else if msg.contains("NoSuchUnit") || msg.contains("not found") {
        BackendError::NotFound
    } else if msg.contains("Timeout") || msg.contains("timeout") {
        BackendError::Timeout
    } else {
        BackendError::Unavailable
    }
}

// ── pagination helpers ────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 25;

fn cursor_to_idx(cursor: &str) -> Option<usize> {
    cursor.parse().ok()
}

// ── ServiceManager impl ──────────────────────────────────────────────────────

#[async_trait]
impl ServiceManager for SystemdServices {
    async fn list(
        &self,
        state_filter: Option<ServiceState>,
        name_glob: Option<String>,
        page: Option<String>,
    ) -> Result<Page<UnitStatus>, BackendError> {
        let proxy = ManagerProxy::new(&self.conn)
            .await
            .map_err(map_dbus_error)?;

        let raw = proxy.list_units().await.map_err(map_dbus_error)?;

        let all: Vec<UnitStatus> = raw
            .into_iter()
            .map(|(name, desc, load, active, sub, _, _, _, _, _)| UnitStatus {
                name,
                description: desc,
                load_state: load,
                active_state: active_state_from_dbus(&active),
                sub_state: sub,
            })
            .collect();

        let filtered = list_filter(all, state_filter, name_glob.as_deref());

        let start = page
            .as_deref()
            .and_then(cursor_to_idx)
            .unwrap_or(0);

        // Overflow-safe pagination (`start` is a caller-supplied cursor).
        let (items, next) = paginate(&filtered, start, PAGE_SIZE);

        Ok(Page { items, next })
    }

    async fn status(&self, name: &str) -> Result<UnitDetail, BackendError> {
        validate(name).map_err(|_| BackendError::InvalidName)?;

        let manager = ManagerProxy::new(&self.conn)
            .await
            .map_err(map_dbus_error)?;

        let path = manager.get_unit(name).await.map_err(|e| {
            if e.to_string().contains("NoSuchUnit") {
                BackendError::NotFound
            } else {
                map_dbus_error(e)
            }
        })?;

        let unit = UnitProxy::builder(&self.conn)
            .path(path)
            .map_err(|_| BackendError::Unavailable)?
            .build()
            .await
            .map_err(map_dbus_error)?;

        let active_state_str = unit.active_state().await.map_err(map_dbus_error)?;
        let sub_state = unit.sub_state().await.map_err(map_dbus_error)?;
        let load_state = unit.load_state().await.map_err(map_dbus_error)?;
        let description = unit.description().await.map_err(map_dbus_error)?;
        let since_us = unit.active_enter_timestamp().await.ok();
        let main_pid = unit.main_pid().await.ok().filter(|&p| p != 0);

        Ok(UnitDetail {
            status: UnitStatus {
                name: name.to_string(),
                description,
                load_state,
                active_state: active_state_from_dbus(&active_state_str),
                sub_state,
            },
            // Convert microseconds since epoch to milliseconds.
            since_ms: since_us.filter(|&t| t > 0).map(|t| t / 1000),
            main_pid,
        })
    }

    async fn start(&self, name: &str) -> Result<ServiceState, BackendError> {
        validate(name).map_err(|_| BackendError::InvalidName)?;
        self.run_job(name, "start").await
    }

    async fn stop(&self, name: &str) -> Result<ServiceState, BackendError> {
        validate(name).map_err(|_| BackendError::InvalidName)?;
        self.run_job(name, "stop").await
    }

    async fn restart(&self, name: &str) -> Result<ServiceState, BackendError> {
        validate(name).map_err(|_| BackendError::InvalidName)?;
        self.run_job(name, "restart").await
    }

    fn watch(&self) -> broadcast::Receiver<UnitStatus> {
        self.unit_tx.subscribe()
    }
}
