//! Linux-only journald log provider backed by `journalctl` subprocess.

use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::backend::capped::{read_line_capped, run_capped};
use crate::backend::{BackendError, LogEntry, LogProvider, LogQuery, Page};
use super::journald::{build_argv, parse_journal_line};

/// Maximum bytes to read from journalctl stdout (per query). The child is
/// killed past this cap; complete lines captured so far are still parsed
/// (a trailing partial JSON line simply fails to parse and is dropped).
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// Output size limit per single query (soft guard).
const MAX_LINES: usize = 10_000;

/// Hard deadline for a single `journalctl` query subprocess.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard deadline for the `journalctl --version` probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum bytes retained for a single line on the follow stream. Overlong
/// lines are truncated (tail discarded) but the stream stays line-aligned.
const MAX_FOLLOW_LINE_BYTES: usize = 1024 * 1024; // 1 MiB

pub struct JournaldLogs {
    _follow_tx: broadcast::Sender<LogEntry>,
    follow_handle: Arc<tokio::task::JoinHandle<()>>,
}

impl JournaldLogs {
    /// Probe: can we reach the systemd journal?
    /// Returns true if `/usr/bin/journalctl --version` exits 0 (bounded).
    pub async fn probe() -> bool {
        let args = vec!["--version".to_string()];
        match run_capped("/usr/bin/journalctl", &args, 64 * 1024, PROBE_TIMEOUT).await {
            Ok(out) => out.success,
            Err(_) => false,
        }
    }

    /// Construct and start a background follow task.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        let tx_clone = tx.clone();

        let handle = tokio::spawn(async move {
            follow_journal(tx_clone).await;
        });

        Self {
            _follow_tx: tx,
            follow_handle: Arc::new(handle),
        }
    }
}

impl Drop for JournaldLogs {
    fn drop(&mut self) {
        // Stop the follow task; kill_on_drop reaps the journalctl child.
        self.follow_handle.abort();
    }
}

/// Background task: run `journalctl -o json --follow` and feed entries to tx.
async fn follow_journal(tx: broadcast::Sender<LogEntry>) {
    use tokio::io::BufReader;
    use tokio::process::Command;

    let mut child = match Command::new("/usr/bin/journalctl")
        .args(["-o", "json", "--follow", "--no-pager"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("journald follow: failed to spawn journalctl: {e}");
            return;
        }
    };

    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut line: Vec<u8> = Vec::new();
        loop {
            match read_line_capped(&mut reader, &mut line, MAX_FOLLOW_LINE_BYTES).await {
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("journald follow: read error: {e}");
                    break;
                }
                Ok(Some(complete)) => {
                    if !complete {
                        // Truncated overlong line — not valid JSON; skip it.
                        continue;
                    }
                    if let Some(entry) = parse_journal_line(&line) {
                        let _ = tx.send(entry);
                    }
                }
            }
        }
    }
    tracing::warn!("journald follow: stream ended");
}

#[async_trait]
impl LogProvider for JournaldLogs {
    async fn query(&self, q: &LogQuery) -> Result<Page<LogEntry>, BackendError> {
        let argv = build_argv(q);
        let program = argv[0].clone();
        let args = &argv[1..];

        let out = run_capped(&program, args, MAX_OUTPUT_BYTES, QUERY_TIMEOUT)
            .await
            .map_err(|e| {
                tracing::warn!("journalctl query: spawn/io failed: {e}");
                BackendError::Unavailable
            })?;

        if out.timed_out {
            tracing::warn!("journalctl query: killed after {QUERY_TIMEOUT:?}");
            return Err(BackendError::Timeout);
        }
        if out.truncated {
            tracing::warn!(
                "journalctl query: stdout exceeded {MAX_OUTPUT_BYTES} bytes; child killed, output truncated"
            );
        }
        if !out.truncated && !out.success && out.stdout.is_empty() {
            return Err(BackendError::Unavailable);
        }

        let mut entries = Vec::new();
        let stdout = &out.stdout;
        let mut last_cursor: Option<String> = None;

        for line in stdout.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if entries.len() >= MAX_LINES {
                break;
            }
            // A trailing partial line (truncated output) fails to parse → skipped.
            if let Some(entry) = parse_journal_line(line) {
                if !entry.cursor.is_empty() {
                    last_cursor = Some(entry.cursor.clone());
                }
                entries.push(entry);
            }
        }

        let next = last_cursor;
        Ok(Page { items: entries, next })
    }

    fn follow(&self) -> broadcast::Receiver<LogEntry> {
        self._follow_tx.subscribe()
    }
}
