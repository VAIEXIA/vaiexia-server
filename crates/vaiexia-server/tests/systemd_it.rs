// Live systemd integration tests.
// Only compiled on Linux with --features system-it.
// All tests are marked #[ignore] — run explicitly on Linux CI with:
//   cargo test --features system-it -- --ignored
#![cfg(all(target_os = "linux", feature = "system-it"))]

use vaiexia_server::backend::{ServiceManager, ServiceState};
use vaiexia_server::backend::systemd::SystemdServices;

#[tokio::test]
#[ignore = "requires Linux system D-Bus; run on CI with --features system-it --ignored"]
async fn systemd_list_returns_units() {
    let svc = SystemdServices::new()
        .await
        .expect("system bus must be reachable");

    let page = svc
        .list(None, None, None)
        .await
        .expect("list() must succeed on a systemd host");

    assert!(!page.items.is_empty(), "systemd must have at least one unit");
}

#[tokio::test]
#[ignore = "requires Linux system D-Bus; run on CI with --features system-it --ignored"]
async fn systemd_status_dbus_service() {
    let svc = SystemdServices::new()
        .await
        .expect("system bus must be reachable");

    let detail = svc
        .status("dbus.service")
        .await
        .expect("dbus.service must exist on a systemd host");

    assert_eq!(detail.status.name, "dbus.service");
    assert_eq!(detail.status.active_state, ServiceState::Active,
        "dbus.service must be active");
}

#[tokio::test]
#[ignore = "requires Linux system D-Bus + polkit; run on CI with appropriate privileges"]
async fn systemd_list_active_glob_filter() {
    let svc = SystemdServices::new()
        .await
        .expect("system bus must be reachable");

    let page = svc
        .list(Some(ServiceState::Active), Some("dbus*".to_string()), None)
        .await
        .expect("filtered list() must succeed");

    // dbus.service should appear in the filtered results.
    assert!(
        page.items.iter().any(|u| u.name.starts_with("dbus")),
        "dbus.service must appear in filtered list"
    );
    assert!(
        page.items.iter().all(|u| u.active_state == ServiceState::Active),
        "all returned units must be active"
    );
}

// NOTE: start/stop round-trip tests are intentionally omitted here.
// They require a safe throwaway unit, root/polkit permissions, and
// careful teardown. Add them to a dedicated CI job with a test unit file.
