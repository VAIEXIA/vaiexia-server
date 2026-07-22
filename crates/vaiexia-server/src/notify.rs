//! Minimal sd_notify(3) client — std-only, no dependencies.
//! Linux: send state datagrams to $NOTIFY_SOCKET (filesystem or abstract).
//! Everywhere else: no-op. Failures are silent by design (notify is advisory;
//! a missing/broken socket must never affect the daemon).

/// Send `state` to the notify socket named by `$NOTIFY_SOCKET`, if any.
pub fn notify(state: &str) {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    notify_to(&path, state);
}

/// Send `state` to an explicit notify socket address (`@name` = abstract
/// namespace, anything else = filesystem path). Split out from [`notify`] so
/// it is testable without mutating process-global environment.
#[cfg(target_os = "linux")]
pub fn notify_to(path: &str, state: &str) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Ok(sock) = UnixDatagram::unbound() else { return };
    let addr = if let Some(name) = path.strip_prefix('@') {
        SocketAddr::from_abstract_name(name.as_bytes())
    } else {
        SocketAddr::from_pathname(path)
    };
    let Ok(addr) = addr else { return };
    let _ = sock.send_to_addr(state.as_bytes(), &addr);
}

#[cfg(not(target_os = "linux"))]
pub fn notify_to(_path: &str, _state: &str) {}

/// Startup complete — listeners bound, service ready.
pub fn ready() { notify("READY=1"); }
/// Orderly shutdown began.
pub fn stopping() { notify("STOPPING=1"); }

#[cfg(test)]
mod tests {
    use super::*;

    /// On all platforms: the env-driven entry points must not panic, whether or
    /// not `NOTIFY_SOCKET` happens to be set in this environment. The env var is
    /// deliberately NOT mutated here — `set_var`/`remove_var` race with every
    /// other test thread reading the environment (figment's env provider does).
    #[test]
    fn notify_entry_points_do_not_panic() {
        notify("READY=1");
        ready();
        stopping();
    }

    /// An abstract-namespace address (leading `@`) must not panic even if no
    /// socket is listening — the impl silently discards send errors. Exercises
    /// the `strip_prefix('@')` branch on Linux and the no-op elsewhere.
    #[test]
    fn notify_to_abstract_socket_does_not_panic() {
        notify_to("@/run/systemd/notify-test", "READY=1");
    }

    /// A pathname address (no `@`) must not panic even if the socket is absent.
    #[test]
    fn notify_to_pathname_socket_does_not_panic() {
        notify_to("/run/vaiexia/notify.sock", "STOPPING=1");
    }
}
