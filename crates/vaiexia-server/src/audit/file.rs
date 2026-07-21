//! `FileAuditSink` (v1 `AuditSink` impl) + background JSONL writer: dedicated
//! OS thread (blocking recv + batch drain), one open BufWriter (0600), BLAKE3
//! chain, N-generation size rotation.
//! No async runtime involvement: the tokio side only does sync `try_send`.
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{AuditDecision, AuditEvent, AuditKind, AuditSink, line_hash};

/// Max events written per batch before a flush.
const BATCH: usize = 64;
/// Genesis `prev` for a chain with no predecessor.
const GENESIS: &str = "0000000000000000";

// `Event` dominates the size, but boxing it would add a heap allocation on
// every audit emit (the hot path); the enum only ever lives briefly in a
// bounded channel, so keeping it unboxed is the deliberate perf choice.
#[allow(clippy::large_enum_variant)]
pub(super) enum Msg {
    Event(AuditEvent),
    Shutdown,
}

#[derive(serde::Serialize)]
struct Record<'a> {
    seq: u64,
    prev: &'a str,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

/// The v1 sink: bounded queue into a dedicated writer thread. Cheap to share
/// as `Arc<FileAuditSink>` / `DynAuditSink`.
pub struct FileAuditSink {
    tx: mpsc::Sender<Msg>,
    dropped: Arc<AtomicU64>,
}

impl FileAuditSink {
    /// `capacity` bounds the queue; `max_bytes`/`generations` configure the
    /// writer's rotation. Returns the shared sink and its (not-yet-started)
    /// writer.
    pub fn new(
        capacity: usize,
        path: PathBuf,
        max_bytes: u64,
        generations: u8,
    ) -> (Arc<Self>, FileAuditWriter) {
        let (tx, rx) = mpsc::channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer =
            FileAuditWriter::new(rx, Arc::clone(&dropped), path, max_bytes, generations);
        (Arc::new(Self { tx, dropped }), writer)
    }

    /// Total events dropped so far (tests / diagnostics).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl AuditSink for FileAuditSink {
    /// Non-blocking. Drops (and counts) under overflow — audit must never
    /// gate the hot path.
    fn emit(&self, event: AuditEvent) {
        if self.tx.try_send(Msg::Event(event)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Ask the writer to drain and exit (non-blocking; the bounded thread-join
    /// in `run()` is the actual wait). Emits after shutdown just count as drops.
    fn shutdown(&self) {
        let _ = self.tx.try_send(Msg::Shutdown);
    }
}

pub struct FileAuditWriter {
    rx: mpsc::Receiver<Msg>,
    dropped: Arc<AtomicU64>,
    path: PathBuf,
    max_bytes: u64,
    generations: u8,
}

impl FileAuditWriter {
    pub(super) fn new(
        rx: mpsc::Receiver<Msg>,
        dropped: Arc<AtomicU64>,
        path: PathBuf,
        max_bytes: u64,
        generations: u8,
    ) -> Self {
        Self { rx, dropped, path, max_bytes, generations: generations.max(1) }
    }

    /// Start the writer on its own OS thread. Returns the JoinHandle; the
    /// thread exits (after a final flush) when every `AuditSink` clone drops.
    pub fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("vaiexia-audit".into())
            .spawn(move || self.run())
            .expect("spawn audit writer thread")
    }

    fn run(mut self) {
        let mut state = match WriterState::open(&self.path) {
            Ok(s) => s,
            Err(e) => {
                // Fail loud but never crash the daemon over its audit file.
                tracing::error!(error = %e, path = %self.path.display(), "audit writer disabled: cannot open file");
                // Drain and drop so senders never observe a closed channel error path.
                while self.rx.blocking_recv().is_some() {}
                return;
            }
        };
        let mut batch: Vec<AuditEvent> = Vec::with_capacity(BATCH);
        let mut stopping = false;
        'outer: loop {
            // Surface any drops since the last batch as a first-class record.
            let lost = self.dropped.swap(0, Ordering::Relaxed);
            if lost > 0 {
                batch.push(
                    AuditEvent::new(AuditKind::AuditLoss, AuditDecision::Err, "audit")
                        .with_detail(format!("dropped={lost}")),
                );
            }
            if batch.is_empty() {
                match self.rx.blocking_recv() {
                    Some(Msg::Event(ev)) => batch.push(ev),
                    Some(Msg::Shutdown) => break 'outer, // orderly stop requested
                    None => break 'outer,                // all sinks dropped → done
                }
            }
            while batch.len() < BATCH {
                match self.rx.try_recv() {
                    Ok(Msg::Event(ev)) => batch.push(ev),
                    Ok(Msg::Shutdown) => {
                        stopping = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if let Err(e) = self.write_batch(&mut state, &mut batch) {
                tracing::warn!(error = %e, "audit write failed");
            }
            batch.clear();
            if stopping {
                break;
            }
        }
        // Drain whatever is still queued, then a final loss record + flush.
        while let Ok(Msg::Event(ev)) = self.rx.try_recv() {
            batch.push(ev);
        }
        let lost = self.dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            batch.push(
                AuditEvent::new(AuditKind::AuditLoss, AuditDecision::Err, "audit")
                    .with_detail(format!("dropped={lost}")),
            );
        }
        if !batch.is_empty() {
            let _ = self.write_batch(&mut state, &mut batch);
        }
        let _ = state.out.flush();
    }

    fn write_batch(
        &self,
        state: &mut WriterState,
        batch: &mut Vec<AuditEvent>,
    ) -> std::io::Result<()> {
        for ev in batch.drain(..) {
            if state.bytes >= self.max_bytes {
                self.rotate(state)?;
            }
            state.seq += 1;
            let rec = Record { seq: state.seq, prev: &state.prev, event: &ev };
            let line = serde_json::to_string(&rec).unwrap_or_else(|_| {
                format!("{{\"seq\":{},\"prev\":\"{}\"}}", state.seq, state.prev)
            });
            state.prev = line_hash(&line);
            state.out.write_all(line.as_bytes())?;
            state.out.write_all(b"\n")?;
            state.bytes += line.len() as u64 + 1;
        }
        state.out.flush()
    }

    /// audit.jsonl → audit.jsonl.1 → … → audit.jsonl.N (oldest deleted).
    /// Runs between records — a rotation never splits or loses a line. The new
    /// file's first record chains to the rotated file's last line (`state.prev`
    /// is carried over), so `verify_chain` accepts each file standalone and the
    /// cross-file link is recorded.
    fn rotate(&self, state: &mut WriterState) -> std::io::Result<()> {
        state.out.flush()?;
        let gen_path = |n: u8| self.path.with_extension(format!("jsonl.{n}"));
        let _ = std::fs::remove_file(gen_path(self.generations));
        for n in (1..self.generations).rev() {
            let _ = std::fs::rename(gen_path(n), gen_path(n + 1));
        }
        std::fs::rename(&self.path, gen_path(1))?;
        let file = open_0600(&self.path)?;
        state.out = BufWriter::new(file);
        state.bytes = 0;
        // state.prev intentionally NOT reset — links the chain across files.
        Ok(())
    }
}

struct WriterState {
    out: BufWriter<File>,
    bytes: u64,
    seq: u64,
    prev: String,
}

impl WriterState {
    fn open(path: &std::path::Path) -> std::io::Result<Self> {
        // Resume the chain AND the seq counter from an existing file's last
        // line (tail read, bounded). Resuming seq matters: verify_chain now
        // flags seq gaps, so a daemon restart must continue, not reset.
        let (bytes, prev, seq) = match std::fs::metadata(path) {
            Ok(m) if m.len() > 0 => {
                let (hash, last_seq) =
                    last_line_meta(path)?.unwrap_or_else(|| (GENESIS.into(), 0));
                (m.len(), hash, last_seq)
            }
            _ => (0, GENESIS.to_string(), 0),
        };
        let file = open_0600(path)?;
        Ok(Self { out: BufWriter::new(file), bytes, seq, prev })
    }
}

fn open_0600(path: &std::path::Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// (hash, seq) of the last non-empty line, reading at most the final 64 KiB.
/// A last line that is not valid JSON (torn write) yields seq 0 — the next
/// record then restarts the count and verify_chain reports the tear honestly.
fn last_line_meta(path: &std::path::Path) -> std::io::Result<Option<(String, u64)>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let take = len.min(64 * 1024);
    f.seek(SeekFrom::End(-(take as i64)))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf.lines().filter(|l| !l.is_empty()).next_back().map(|l| {
        let seq = serde_json::from_str::<serde_json::Value>(l)
            .ok()
            .and_then(|v| v["seq"].as_u64())
            .unwrap_or(0);
        (line_hash(l), seq)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{AuditDecision, AuditEvent, AuditKind, verify_chain};

    #[test]
    fn rotation_keeps_generations_and_links_chain() {
        let dir =
            std::env::temp_dir().join(format!("vx-audit-rot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        // tiny max_bytes forces rotation; 2 generations kept
        let (sink, writer) = FileAuditSink::new(256, path.clone(), 400, 2);
        let th = writer.spawn();
        for i in 0..50 {
            sink.emit(
                AuditEvent::new(AuditKind::Mutation, AuditDecision::Ok, "user:admin")
                    .with_detail(format!("padding-padding-padding-{i}")),
            );
        }
        drop(sink);
        th.join().unwrap();
        assert!(path.exists());
        assert!(path.with_extension("jsonl.1").exists());
        assert!(!path.with_extension("jsonl.3").exists(), "only N generations kept");
        // active file's first record links to the rotated file's last line hash
        assert!(verify_chain(&path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
