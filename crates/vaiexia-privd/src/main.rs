mod exec;
mod handler;

#[cfg(unix)]
mod socket;

fn main() {
    #[cfg(unix)]
    run_unix();

    #[cfg(not(unix))]
    {
        eprintln!("vaiexia-privd: not supported on this platform");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run_unix() {
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    use exec::PackageKind;
    use socket::{handle_connection, SOCKET_PATH};

    // Detect package manager from /etc/os-release
    let kind = detect_package_kind();

    // Determine the allowed daemon uid (from env or default to our own uid)
    let daemon_uid = std::env::var("VAIEXIA_DAEMON_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() });

    let job_lock = Arc::new(Mutex::new(()));

    // Socket activation: check LISTEN_FDS (systemd)
    let listener = create_listener();

    eprintln!(
        "vaiexia-privd: listening on socket, kind={:?}, daemon_uid={daemon_uid}",
        kind
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let job_lock = Arc::clone(&job_lock);
                #[cfg(target_os = "linux")]
                handle_connection(stream, daemon_uid, kind, &job_lock);
                #[cfg(not(target_os = "linux"))]
                {
                    // On non-linux unix (macOS) no SO_PEERCRED — refuse all
                    eprintln!("privd: only supported on Linux (SO_PEERCRED required)");
                    drop(stream);
                }
            }
            Err(e) => {
                eprintln!("privd: accept error: {e}");
            }
        }
    }
}

#[cfg(unix)]
fn create_listener() -> std::os::unix::net::UnixListener {
    use std::os::unix::net::UnixListener;

    // Check for systemd socket activation: LISTEN_FDS env var
    if let Ok(fds_str) = std::env::var("LISTEN_FDS") {
        if let Ok(n) = fds_str.parse::<i32>() {
            if n >= 1 {
                use std::os::unix::io::FromRawFd;
                // First listen fd is SD_LISTEN_FDS_START = 3
                let listener = unsafe { UnixListener::from_raw_fd(3) };
                eprintln!("privd: using socket-activated fd 3");
                return listener;
            }
        }
    }

    // Bind a new socket
    let path = socket::SOCKET_PATH;

    // Remove stale socket file
    let _ = std::fs::remove_file(path);

    // Create parent directory if needed
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(path).unwrap_or_else(|e| {
        eprintln!("privd: failed to bind {path}: {e}");
        std::process::exit(1);
    });

    // Set permissions to 0600
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("privd: failed to set socket permissions: {e}");
    }

    eprintln!("privd: bound to {path}");
    listener
}

#[cfg(unix)]
fn detect_package_kind() -> exec::PackageKind {
    let content = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    match detect_from_os_release_text(&content) {
        Some(k) => k,
        None => {
            eprintln!("privd: could not detect package manager — defaulting to Apt");
            exec::PackageKind::Apt
        }
    }
}

#[allow(dead_code)]
fn detect_from_os_release_text(content: &str) -> Option<exec::PackageKind> {
    let mut id: Option<&str> = None;
    let mut id_like: Option<&str> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("ID=") {
            id = Some(val.trim_matches('"'));
        } else if let Some(val) = line.strip_prefix("ID_LIKE=") {
            id_like = Some(val.trim_matches('"'));
        }
    }

    if let Some(k) = id.and_then(kind_from_id_str) {
        return Some(k);
    }
    if let Some(like) = id_like {
        for token in like.split_whitespace() {
            if let Some(k) = kind_from_id_str(token) {
                return Some(k);
            }
        }
    }
    None
}

#[allow(dead_code)]
fn kind_from_id_str(id: &str) -> Option<exec::PackageKind> {
    match id {
        "debian" | "ubuntu" | "raspbian" | "linuxmint" | "pop" => Some(exec::PackageKind::Apt),
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => Some(exec::PackageKind::Dnf),
        "arch" | "manjaro" | "endeavouros" | "artix" => Some(exec::PackageKind::Pacman),
        "alpine" => Some(exec::PackageKind::Apk),
        _ => None,
    }
}
