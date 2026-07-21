//! Bounded subprocess-output capture.
//!
//! `tokio::process::Command::output()` buffers child stdout without any
//! limit, so a hostile or runaway `journalctl` / package manager could OOM
//! the daemon. These helpers stream stdout with a hard byte cap and a hard
//! deadline, killing the child when either is exceeded (spec §4/§C1/§C2).
//!
//! The reader helpers are pure over `AsyncRead`/`AsyncBufRead` and are
//! unit-tested cross-platform; `run_capped` performs the actual spawn.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt};

// ── Capped bulk read ─────────────────────────────────────────────────────────

/// Result of reading a stream up to a byte cap.
pub struct CappedRead {
    /// Bytes read, at most `cap`.
    pub bytes: Vec<u8>,
    /// True if the stream had more data than `cap` (reading stopped early).
    pub truncated: bool,
}

/// Read from `r` until EOF or until `cap` bytes have been collected.
///
/// Never buffers more than `cap` bytes (+ one internal chunk). On cap hit,
/// returns `truncated: true` without draining the remainder — the caller is
/// expected to kill the producing child process.
pub async fn read_capped<R: AsyncRead + Unpin>(
    mut r: R,
    cap: usize,
) -> std::io::Result<CappedRead> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Ok(CappedRead { bytes, truncated: false });
        }
        let room = cap - bytes.len();
        if n > room {
            bytes.extend_from_slice(&chunk[..room]);
            return Ok(CappedRead { bytes, truncated: true });
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
}

// ── Capped line read ─────────────────────────────────────────────────────────

/// Read one `\n`-terminated line into `buf` (cleared first), capping the
/// stored line at `max` bytes. Overlong tails are consumed and discarded so
/// the stream stays line-aligned, but they never accumulate in memory.
///
/// Returns:
/// - `Ok(None)` on clean EOF with no pending data,
/// - `Ok(Some(true))` for a line stored in full (≤ max bytes),
/// - `Ok(Some(false))` for a line that was longer than `max` (truncated).
pub async fn read_line_capped<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Option<bool>> {
    buf.clear();
    let mut truncated = false;
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            // EOF: emit any pending partial line.
            if buf.is_empty() && !truncated {
                return Ok(None);
            }
            return Ok(Some(!truncated));
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let upto = newline.unwrap_or(available.len());
        if !truncated {
            let room = max.saturating_sub(buf.len());
            let take = room.min(upto);
            buf.extend_from_slice(&available[..take]);
            if take < upto {
                truncated = true;
            }
        }
        match newline {
            Some(pos) => {
                r.consume(pos + 1);
                return Ok(Some(!truncated));
            }
            None => {
                let len = available.len();
                r.consume(len);
            }
        }
    }
}

// ── Capped subprocess run ────────────────────────────────────────────────────

/// Outcome of a capped, deadline-bounded subprocess run.
pub struct RunOutcome {
    /// Captured stdout, at most `cap` bytes. May end mid-line if `truncated`.
    pub stdout: Vec<u8>,
    /// The child produced more than `cap` bytes and was killed.
    pub truncated: bool,
    /// The deadline elapsed and the child was killed.
    pub timed_out: bool,
    /// The child exited on its own with a success status.
    pub success: bool,
}

/// Spawn `program` with `args` (no shell, env cleared, stdin/stderr null,
/// stdout piped) and capture stdout up to `cap` bytes within `deadline`.
///
/// The child is killed if it exceeds the cap or the deadline; `kill_on_drop`
/// also covers cancellation of the calling future.
pub async fn run_capped(
    program: &str,
    args: &[String],
    cap: usize,
    deadline: Duration,
) -> std::io::Result<RunOutcome> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = child.stdout.take().ok_or_else(|| {
        std::io::Error::other("child stdout not piped")
    })?;

    let until = tokio::time::Instant::now() + deadline;

    let read = match tokio::time::timeout_at(until, read_capped(stdout, cap)).await {
        Err(_elapsed) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Ok(RunOutcome {
                stdout: Vec::new(),
                truncated: false,
                timed_out: true,
                success: false,
            });
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(e);
        }
        Ok(Ok(read)) => read,
    };

    if read.truncated {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Ok(RunOutcome {
            stdout: read.bytes,
            truncated: true,
            timed_out: false,
            success: false,
        });
    }

    // Stdout hit EOF; the child should exit promptly — bound the wait too.
    match tokio::time::timeout_at(until, child.wait()).await {
        Err(_elapsed) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Ok(RunOutcome {
                stdout: read.bytes,
                truncated: false,
                timed_out: true,
                success: false,
            })
        }
        Ok(Err(e)) => Err(e),
        Ok(Ok(status)) => Ok(RunOutcome {
            stdout: read.bytes,
            truncated: false,
            timed_out: false,
            success: status.success(),
        }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    // ── read_capped ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_capped_under_cap_reads_all() {
        let data = b"hello world".as_slice();
        let out = read_capped(data, 1024).await.unwrap();
        assert_eq!(out.bytes, b"hello world");
        assert!(!out.truncated);
    }

    #[tokio::test]
    async fn read_capped_exactly_at_cap_not_truncated() {
        // 11 bytes with cap 11: exact fit followed by EOF is NOT truncation.
        let data = b"hello world".as_slice();
        let out = read_capped(data, 11).await.unwrap();
        assert_eq!(out.bytes, b"hello world");
        assert!(!out.truncated);
    }

    #[tokio::test]
    async fn read_capped_one_past_cap_truncates() {
        let data = b"hello world!".as_slice(); // 12 bytes
        let out = read_capped(data, 11).await.unwrap();
        assert_eq!(out.bytes, b"hello world");
        assert!(out.truncated);
    }

    #[tokio::test]
    async fn read_capped_over_cap_truncates() {
        let data = vec![b'x'; 100_000];
        let out = read_capped(data.as_slice(), 4096).await.unwrap();
        assert_eq!(out.bytes.len(), 4096);
        assert!(out.truncated);
    }

    #[tokio::test]
    async fn read_capped_zero_cap_returns_empty_truncated() {
        let data = b"abc".as_slice();
        let out = read_capped(data, 0).await.unwrap();
        assert!(out.bytes.is_empty());
        assert!(out.truncated);
    }

    #[tokio::test]
    async fn read_capped_empty_stream() {
        let data = b"".as_slice();
        let out = read_capped(data, 1024).await.unwrap();
        assert!(out.bytes.is_empty());
        assert!(!out.truncated);
    }

    // ── read_line_capped ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_line_capped_normal_lines() {
        let mut r = BufReader::new(b"one\ntwo\nthree\n".as_slice());
        let mut buf = Vec::new();

        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), Some(true));
        assert_eq!(buf, b"one");
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), Some(true));
        assert_eq!(buf, b"two");
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), Some(true));
        assert_eq!(buf, b"three");
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_line_capped_overlong_line_truncated_and_stream_stays_aligned() {
        let mut data = vec![b'a'; 10_000];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let mut r = BufReader::new(data.as_slice());
        let mut buf = Vec::new();

        // Overlong line: truncated flag, only `max` bytes retained.
        assert_eq!(read_line_capped(&mut r, &mut buf, 100).await.unwrap(), Some(false));
        assert_eq!(buf.len(), 100);
        assert!(buf.iter().all(|&b| b == b'a'));

        // The following line is intact — the overlong tail was discarded.
        assert_eq!(read_line_capped(&mut r, &mut buf, 100).await.unwrap(), Some(true));
        assert_eq!(buf, b"next");
    }

    #[tokio::test]
    async fn read_line_capped_partial_last_line_without_newline() {
        let mut r = BufReader::new(b"tail-no-newline".as_slice());
        let mut buf = Vec::new();
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), Some(true));
        assert_eq!(buf, b"tail-no-newline");
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_line_capped_empty_lines() {
        let mut r = BufReader::new(b"\n\n".as_slice());
        let mut buf = Vec::new();
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), Some(true));
        assert!(buf.is_empty());
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), Some(true));
        assert!(buf.is_empty());
        assert_eq!(read_line_capped(&mut r, &mut buf, 64).await.unwrap(), None);
    }

    // ── run_capped (smoke, per-platform command) ─────────────────────────────

    #[cfg(windows)]
    #[tokio::test]
    async fn run_capped_smoke_echo() {
        let args: Vec<String> = ["/C", "echo hi"].iter().map(|s| s.to_string()).collect();
        let out = run_capped("cmd", &args, 1024, Duration::from_secs(10))
            .await
            .expect("cmd /C echo should spawn");
        assert!(out.success);
        assert!(!out.truncated);
        assert!(!out.timed_out);
        assert!(String::from_utf8_lossy(&out.stdout).contains("hi"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_capped_smoke_echo() {
        let args: Vec<String> = ["-c", "echo hi"].iter().map(|s| s.to_string()).collect();
        let out = run_capped("/bin/sh", &args, 1024, Duration::from_secs(10))
            .await
            .expect("/bin/sh -c echo should spawn");
        assert!(out.success);
        assert!(String::from_utf8_lossy(&out.stdout).contains("hi"));
    }

    #[tokio::test]
    async fn run_capped_missing_binary_is_io_error() {
        let out = run_capped(
            "/definitely/not/a/real/binary",
            &[],
            1024,
            Duration::from_secs(1),
        )
        .await;
        assert!(out.is_err());
    }
}
