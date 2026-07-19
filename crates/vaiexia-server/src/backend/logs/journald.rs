//! Portable helpers for journald JSON parsing and argv construction.
//! Compiled on ALL platforms; unit-tested cross-platform.

use crate::backend::{LogEntry, LogQuery};

// ── parse_journal_line ────────────────────────────────────────────────────────

/// Parse a single `journalctl -o json` output line into a `LogEntry`.
///
/// Journal fields used:
/// - `__CURSOR`              → `cursor` (default: "")
/// - `__REALTIME_TIMESTAMP`  → `ts_us` as u64 (default: 0)
/// - `_SYSTEMD_UNIT`         → `unit` (optional)
/// - `PRIORITY`              → `priority` as u8 (default: 6 = info)
/// - `MESSAGE`               → `message`; may be a JSON string OR an array of
///   integers (byte-array representation) — both handled.
///
/// Returns `None` on totally unparseable input; panics never.
pub fn parse_journal_line(bytes: &[u8]) -> Option<LogEntry> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = v.as_object()?;

    let cursor = obj
        .get("__CURSOR")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let ts_us: u64 = obj
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let unit: Option<String> = obj
        .get("_SYSTEMD_UNIT")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let priority: u8 = obj
        .get("PRIORITY")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    // MESSAGE may be a string or an array of integers (byte values)
    let message: String = match obj.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => {
            // byte array: collect to Vec<u8>, convert to lossy UTF-8
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| {
                    v.as_i64()
                        .and_then(|n| u8::try_from(n).ok())
                        .or_else(|| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                })
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    };

    Some(LogEntry {
        cursor,
        ts_us,
        unit,
        priority,
        message,
    })
}

// ── build_argv ────────────────────────────────────────────────────────────────

/// Build the argv for `journalctl -o json --no-pager` from a `LogQuery`.
///
/// - unit: passed as `-u <unit>` (validated via `UnitName` at the API handler
///   before it reaches here; also an option-argument, so never re-parsed as a
///   flag by journalctl)
/// - since_us: `--since` (converted from microseconds to ISO-like seconds)
/// - until_us: `--until`
/// - limit (> 0): `-n <n>`
/// - cursor: `--after-cursor <c>`
///
/// The first element is always the absolute path `/usr/bin/journalctl`.
pub fn build_argv(q: &LogQuery) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "/usr/bin/journalctl".to_string(),
        "-o".to_string(),
        "json".to_string(),
        "--no-pager".to_string(),
    ];

    if let Some(ref unit) = q.unit {
        args.push("-u".to_string());
        args.push(unit.clone());
    }

    if let Some(since_us) = q.since_us {
        // journalctl accepts "@<unix_seconds.micros>" format
        let secs = since_us / 1_000_000;
        let micros = since_us % 1_000_000;
        args.push("--since".to_string());
        args.push(format!("@{secs}.{micros:06}"));
    }

    if let Some(until_us) = q.until_us {
        let secs = until_us / 1_000_000;
        let micros = until_us % 1_000_000;
        args.push("--until".to_string());
        args.push(format!("@{secs}.{micros:06}"));
    }

    if q.limit > 0 {
        args.push("-n".to_string());
        args.push(q.limit.to_string());
    }

    if let Some(ref cursor) = q.cursor {
        args.push("--after-cursor".to_string());
        args.push(cursor.clone());
    }

    args
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_journal_line ────────────────────────────────────────────────────

    /// A realistic `journalctl -o json` line fixture with MESSAGE as a string.
    const FIXTURE_STRING_MSG: &[u8] = br#"{
        "__CURSOR": "s=abc123;i=1;b=def456",
        "__REALTIME_TIMESTAMP": "1700000000000000",
        "_SYSTEMD_UNIT": "nginx.service",
        "PRIORITY": "6",
        "MESSAGE": "started nginx"
    }"#;

    /// A realistic fixture with MESSAGE as a byte-array (array of ints).
    const FIXTURE_ARRAY_MSG: &[u8] = br#"{
        "__CURSOR": "s=abc123;i=2;b=def456",
        "__REALTIME_TIMESTAMP": "1700000001000000",
        "_SYSTEMD_UNIT": "sshd.service",
        "PRIORITY": "3",
        "MESSAGE": [104, 101, 108, 108, 111]
    }"#;

    /// A fixture with no optional fields (cursor empty, no unit).
    const FIXTURE_MINIMAL: &[u8] = br#"{
        "MESSAGE": "bare message"
    }"#;

    /// Junk input.
    const FIXTURE_JUNK: &[u8] = b"not json at all!!!";

    #[test]
    fn parse_string_message_extracts_all_fields() {
        let entry = parse_journal_line(FIXTURE_STRING_MSG).expect("should parse");
        assert_eq!(entry.cursor, "s=abc123;i=1;b=def456");
        assert_eq!(entry.ts_us, 1_700_000_000_000_000);
        assert_eq!(entry.unit, Some("nginx.service".to_string()));
        assert_eq!(entry.priority, 6);
        assert_eq!(entry.message, "started nginx");
    }

    #[test]
    fn parse_array_message_decodes_bytes_to_string() {
        let entry = parse_journal_line(FIXTURE_ARRAY_MSG).expect("should parse");
        assert_eq!(entry.cursor, "s=abc123;i=2;b=def456");
        assert_eq!(entry.ts_us, 1_700_000_001_000_000);
        assert_eq!(entry.unit, Some("sshd.service".to_string()));
        assert_eq!(entry.priority, 3);
        assert_eq!(entry.message, "hello"); // [104,101,108,108,111] = "hello"
    }

    #[test]
    fn parse_minimal_uses_sensible_defaults() {
        let entry = parse_journal_line(FIXTURE_MINIMAL).expect("should parse minimal");
        assert_eq!(entry.cursor, "");
        assert_eq!(entry.ts_us, 0);
        assert_eq!(entry.unit, None);
        assert_eq!(entry.priority, 6); // default info
        assert_eq!(entry.message, "bare message");
    }

    #[test]
    fn parse_junk_returns_none_no_panic() {
        assert_eq!(parse_journal_line(FIXTURE_JUNK), None);
    }

    #[test]
    fn parse_empty_bytes_returns_none() {
        assert_eq!(parse_journal_line(b""), None);
    }

    #[test]
    fn parse_array_json_root_returns_none() {
        // Top-level array is not a valid journal line
        assert_eq!(parse_journal_line(b"[1,2,3]"), None);
    }

    #[test]
    fn parse_message_null_gives_empty_string() {
        let bytes = br#"{"MESSAGE": null}"#;
        let entry = parse_journal_line(bytes).expect("null message still parseable");
        assert_eq!(entry.message, "");
    }

    // ── build_argv ────────────────────────────────────────────────────────────

    #[test]
    fn build_argv_base_always_present() {
        let q = LogQuery::default();
        let args = build_argv(&q);
        assert_eq!(args[0], "/usr/bin/journalctl");
        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"json".to_string()));
        assert!(args.contains(&"--no-pager".to_string()));
    }

    #[test]
    fn build_argv_with_unit() {
        let q = LogQuery {
            unit: Some("nginx.service".to_string()),
            ..Default::default()
        };
        let args = build_argv(&q);
        let u_pos = args.iter().position(|a| a == "-u").expect("-u flag");
        assert_eq!(args[u_pos + 1], "nginx.service");
    }

    #[test]
    fn build_argv_with_limit() {
        let q = LogQuery {
            limit: 100,
            ..Default::default()
        };
        let args = build_argv(&q);
        let n_pos = args.iter().position(|a| a == "-n").expect("-n flag");
        assert_eq!(args[n_pos + 1], "100");
    }

    #[test]
    fn build_argv_zero_limit_omits_n_flag() {
        let q = LogQuery {
            limit: 0,
            ..Default::default()
        };
        let args = build_argv(&q);
        assert!(!args.contains(&"-n".to_string()));
    }

    #[test]
    fn build_argv_with_cursor() {
        let q = LogQuery {
            cursor: Some("s=abc;i=1".to_string()),
            ..Default::default()
        };
        let args = build_argv(&q);
        let c_pos = args
            .iter()
            .position(|a| a == "--after-cursor")
            .expect("--after-cursor flag");
        assert_eq!(args[c_pos + 1], "s=abc;i=1");
    }

    #[test]
    fn build_argv_with_since_and_until() {
        let q = LogQuery {
            since_us: Some(1_700_000_000_500_000),
            until_us: Some(1_700_000_010_000_000),
            ..Default::default()
        };
        let args = build_argv(&q);
        let since_pos = args.iter().position(|a| a == "--since").expect("--since");
        let until_pos = args.iter().position(|a| a == "--until").expect("--until");
        // @1700000000.500000
        assert_eq!(args[since_pos + 1], "@1700000000.500000");
        // @1700000010.000000
        assert_eq!(args[until_pos + 1], "@1700000010.000000");
    }

    #[test]
    fn build_argv_no_shell_metachars_in_unit() {
        // Even if the unit string contained odd chars, the argv is a Vec<String>
        // with no shell expansion — each element is passed directly to execvp.
        // Here we just verify no shell is involved: the returned argv is a plain
        // list, NOT a shell string. If there were shell injection, the command
        // would need to be joined — we confirm it is not.
        let q = LogQuery {
            unit: Some("nginx.service".to_string()),
            ..Default::default()
        };
        let args = build_argv(&q);
        // No shell wrapper elements like "/bin/sh", "-c" etc.
        assert!(!args.iter().any(|a| a == "/bin/sh" || a == "-c"));
    }
}
