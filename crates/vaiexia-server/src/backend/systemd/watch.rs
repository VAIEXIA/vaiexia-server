//! Linux-only watch task.
//! Subscribes to systemd D-Bus signals and forwards `UnitStatus` onto a broadcast channel.
//! Only compiled on Linux (`#[cfg(target_os = "linux")]` in mod.rs).

use futures_util::StreamExt as _;
use tokio::sync::broadcast;
use zbus::Connection;

use crate::backend::UnitStatus;
use super::linux::{ManagerProxy, UnitProxy};
use super::unit::active_state_from_dbus;

/// Spawn a background task that watches for systemd state changes.
/// The task ends when the connection drops or the channel closes.
pub(super) async fn spawn_watch_task(conn: Connection, tx: broadcast::Sender<UnitStatus>) {
    tokio::spawn(watch_loop(conn, tx));
}

async fn watch_loop(conn: Connection, tx: broadcast::Sender<UnitStatus>) {
    let proxy = match ManagerProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("systemd watch: ManagerProxy failed: {e}");
            return;
        }
    };

    if let Err(e) = proxy.subscribe().await {
        tracing::error!("systemd watch: Subscribe() failed: {e}");
        return;
    }

    let mut job_stream = match proxy.receive_job_removed().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("systemd watch: receive_job_removed failed: {e}");
            return;
        }
    };

    while let Some(signal) = job_stream.next().await {
        let args = match signal.args() {
            Ok(a) => a,
            Err(_) => continue,
        };

        let unit_name = args.unit.to_string();
        let state = fetch_unit_state(&conn, &unit_name).await;

        let status = UnitStatus {
            name: unit_name,
            description: String::new(),
            load_state: String::new(),
            active_state: state,
            sub_state: String::new(),
        };

        // Ignore send errors — no active receivers is fine.
        let _ = tx.send(status);
    }
}

async fn fetch_unit_state(conn: &Connection, unit_name: &str) -> crate::backend::ServiceState {
    async fn inner(conn: &Connection, unit_name: &str) -> Result<crate::backend::ServiceState, zbus::Error> {
        let manager = ManagerProxy::new(conn).await?;
        let path = manager.get_unit(unit_name).await?;
        let unit = UnitProxy::builder(conn)
            .path(path)?
            .build()
            .await?;
        let state_str = unit.active_state().await?;
        Ok(active_state_from_dbus(&state_str))
    }

    inner(conn, unit_name)
        .await
        .unwrap_or(crate::backend::ServiceState::Unknown)
}
