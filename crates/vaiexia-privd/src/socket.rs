//! Unix socket server for vaiexia-privd.
//!
//! Security model:
//! - Binds `/run/vaiexia/privd.sock` (0600) or uses socket-activated fd
//! - Checks SO_PEERCRED: only accepts connections from the daemon uid
//! - Reads length-prefixed PrivRequest frames
//! - Dispatches via handler::handle() extended with exec::verb_to_argv
//! - Writes length-prefixed PrivResponse frames
//! - One job at a time (mutex), hard timeout, cleared env, absolute paths
//! - Writes audit line to stderr on every exec operation
//!
//! Unix-only — compiled only on unix targets.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

use vaiexia_priv_proto::{PrivRequest, PrivResponse};

use crate::allowlist::Allowlist;
use crate::exec::{verb_to_argv, PackageKind};
use crate::handler::handle;

/// Default socket path.
pub const SOCKET_PATH: &str = "/run/vaiexia/privd.sock";

/// Max frame size for incoming requests (1 MiB).
const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Max frame size for outgoing responses (1 MiB).
const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Hard timeout for a single package operation.
const EXEC_TIMEOUT: Duration = Duration::from_secs(300);

/// Read a length-prefixed frame from the stream.
/// Frame: 4-byte BE length + payload bytes.
pub fn read_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_REQUEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a length-prefixed frame to the stream.
pub fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    Ok(())
}

/// Check SO_PEERCRED on the unix stream and return the peer uid.
#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;

    #[repr(C)]
    struct UCred {
        pid: libc::pid_t,
        uid: libc::uid_t,
        gid: libc::gid_t,
    }

    let fd = stream.as_raw_fd();
    let mut cred = UCred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<UCred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut UCred as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 { Some(cred.uid) } else { None }
}

/// Max bytes of child stderr surfaced back to the caller (defense against a
/// chatty manager both wedging the drain thread and bloating the response).
const MAX_STDERR_CAPTURE: usize = 64 * 1024;

/// Truncate a string to at most `max` bytes on a char boundary, appending an
/// ellipsis marker when clipped. Keeps error messages bounded.
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... (truncated)", &s[..end])
}

/// Run a package operation subprocess.
///
/// - Uses absolute path from argv[0] (built by `verb_to_argv`, never PATH)
/// - Clears env (no `LD_PRELOAD`/`APT::`/`DEB_*` influence)
/// - Discards stdin/stdout; drains stderr on a helper thread so a full pipe
///   cannot deadlock the wait loop
/// - Enforces a HARD timeout: a hung manager is killed at `EXEC_TIMEOUT`
/// - Returns Ok/Error PrivResponse
fn run_exec(argv: &[String]) -> PrivResponse {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    if argv.is_empty() {
        return PrivResponse::Error { message: "empty argv".into() };
    }

    let program = &argv[0];
    let args = &argv[1..];

    // Audit log to stderr (journald/supervisor will capture this)
    eprintln!("privd exec: {argv:?}");

    let mut child = match Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("privd exec io error: {e}");
            return PrivResponse::Error { message: format!("io: {e}") };
        }
    };

    // Drain stderr fully on a helper thread (so a full pipe can never deadlock
    // the wait loop) while KEEPING only a bounded prefix (so a chatty child
    // can't exhaust memory or bloat the response).
    let stderr_pipe = child.stderr.take();
    let stderr_reader = std::thread::spawn(move || {
        let cap = MAX_STDERR_CAPTURE;
        let mut kept: Vec<u8> = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if kept.len() < cap {
                            let room = cap - kept.len();
                            kept.extend_from_slice(&chunk[..n.min(room)]);
                        }
                        // Bytes beyond the cap are read and discarded to keep
                        // the pipe drained.
                    }
                    Err(_) => break,
                }
            }
        }
        kept
    });

    // Poll for completion until the hard deadline; kill on timeout.
    let deadline = Instant::now() + EXEC_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    eprintln!("privd exec timeout after {EXEC_TIMEOUT:?}: killing child");
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("privd exec wait error: {e}");
                let _ = child.kill();
                let _ = child.wait();
                let _ = stderr_reader.join();
                return PrivResponse::Error { message: format!("wait: {e}") };
            }
        }
    };

    let stderr_bytes = stderr_reader.join().unwrap_or_default();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    match status {
        Some(status) if status.success() => {
            eprintln!("privd exec ok: exit={status}");
            PrivResponse::Ok
        }
        Some(status) => {
            eprintln!("privd exec failed: exit={status}");
            PrivResponse::Error {
                message: format!("exit {}: {}", status, clip(stderr.trim(), 512)),
            }
        }
        None => PrivResponse::Error { message: "operation timed out".into() },
    }
}

/// Dispatch a request: either handle it in-process or exec a package command.
pub fn dispatch(
    req: &PrivRequest,
    kind: PackageKind,
    job_lock: &Mutex<()>,
    allowlist: &Allowlist,
) -> PrivResponse {
    // Ping/ProtoVersion: handled in-process, no exec
    if matches!(req, PrivRequest::Ping | PrivRequest::ProtoVersion) {
        return handle(req);
    }

    // Package operations: one at a time
    let _guard = match job_lock.try_lock() {
        Ok(g) => g,
        Err(_) => {
            return PrivResponse::Error { message: "busy: another operation in progress".into() }
        }
    };

    // Allowlist enforcement for install/remove (BEFORE verb_to_argv — defense in depth:
    // re-validates PackageName AND checks the operator-configured allowlist).
    match req {
        PrivRequest::PkgInstall { name } | PrivRequest::PkgRemove { name } => {
            if !allowlist.permits(name.as_str()) {
                eprintln!("privd: refused package '{}' (not in allowlist)", name.as_str());
                return PrivResponse::Error {
                    message: "rejected: package not in allowlist".into(),
                };
            }
        }
        _ => {}
    }

    match verb_to_argv(req, kind) {
        Some(argv) => run_exec(&argv),
        None => PrivResponse::Error { message: "rejected: invalid request or name".into() },
    }
}

/// Handle a single connection: read request, dispatch, write response.
#[cfg(target_os = "linux")]
pub fn handle_connection(
    mut stream: UnixStream,
    daemon_uid: u32,
    kind: PackageKind,
    job_lock: &Mutex<()>,
    allowlist: &Allowlist,
) {
    // SO_PEERCRED uid check
    match peer_uid(&stream) {
        Some(uid) if uid == daemon_uid || uid == 0 => {
            // uid 0 (root) is also allowed for testing/setup
        }
        Some(uid) => {
            eprintln!("privd: refused connection from uid {uid} (expected {daemon_uid})");
            return;
        }
        None => {
            eprintln!("privd: SO_PEERCRED failed — refusing connection");
            return;
        }
    }

    // Read request frame
    let frame = match read_frame(&mut stream) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("privd: read_frame error: {e}");
            return;
        }
    };

    // Deserialize request
    let req: PrivRequest = match serde_json::from_slice(&frame) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("privd: deserialize error: {e}");
            let resp = PrivResponse::Error { message: "protocol error".into() };
            let _ = write_response(&mut stream, &resp);
            return;
        }
    };

    // Dispatch
    let resp = dispatch(&req, kind, job_lock, allowlist);

    // Write response
    let _ = write_response(&mut stream, &resp);
}

fn write_response(stream: &mut UnixStream, resp: &PrivResponse) {
    match serde_json::to_vec(resp) {
        Ok(payload) => {
            if let Err(e) = write_frame(stream, &payload) {
                eprintln!("privd: write_frame error: {e}");
            }
        }
        Err(e) => eprintln!("privd: serialize response error: {e}"),
    }
}
