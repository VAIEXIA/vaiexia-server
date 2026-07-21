//! Linux-only journald log provider backed by `journalctl` subprocess.

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::backend::{BackendError, LogEntry, LogProvider, LogQuery, Page};
use super::journald::{build_argv, parse_journal_line};

/// Maximum bytes to read from journalctl stdout (per query).
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// Output size limit per single query (soft guard).
const MAX_LINES: usize = 10_000;

pub struct JournaldLogs {
    _follow_tx: broadcast::Sender<LogEntry>,
    _follow_handle: Arc<tokio::task::JoinHandle<()>>,
}

impl JournaldLogs {
    /// Probe: can we reach the systemd journal?
    /// Returns true if `/usr/bin/journalctl --version` exits 0.
    pub async fn probe() -> bool {
        tokio::process::Command::new("/usr/bin/journalctl")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
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
            _follow_handle: Arc::new(handle),
        }
    }
}

/// Background task: run `journalctl -o json --follow` and feed entries to tx.
async fn follow_journal(tx: broadcast::Sender<LogEntry>) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let mut child = match Command::new("/usr/bin/journalctl")
        .args(["-o", "json", "--follow", "--no-pager"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if let Some(entry) = parse_journal_line(line.as_bytes()) {
                        let _ = tx.send(entry);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl LogProvider for JournaldLogs {
    async fn query(&self, q: &LogQuery) -> Result<Page<LogEntry>, BackendError> {
        use tokio::process::Command;

        let argv = build_argv(q);
        let program = argv[0].clone();
        let args = &argv[1..];

        let output = Command::new(&program)
            .args(args)
            .env_clear()
            .output()
            .await
            .map_err(|_| BackendError::Unavailable)?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(BackendError::Unavailable);
        }

        let mut entries = Vec::new();
        let stdout = &output.stdout;
        let mut last_cursor: Option<String> = None;

        for line in stdout.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if entries.len() >= MAX_LINES {
                break;
            }
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
