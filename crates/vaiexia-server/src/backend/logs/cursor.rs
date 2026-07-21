//! Cursor helpers for the journald log provider.
//! A cursor is an opaque string from `__CURSOR` in the journal JSON.
//! These helpers are portable and unit-tested cross-platform.

/// Upper bound on an accepted cursor. Real journald cursors are ~150-250
/// bytes; anything much larger is junk and only inflates the argv we pass
/// to `journalctl --after-cursor`.
pub const MAX_CURSOR_LEN: usize = 1024;

/// Returns true if the cursor string is plausible: non-empty, within
/// `MAX_CURSOR_LEN`, and free of control characters (a journald cursor is
/// printable `key=value;...` text; NUL/newlines would be junk in an argv).
///
/// We do NOT validate the full structure — journald cursors are opaque.
pub fn is_valid(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_CURSOR_LEN
        && !cursor.bytes().any(|b| b.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cursor_is_invalid() {
        assert!(!is_valid(""));
    }

    #[test]
    fn non_empty_cursor_is_valid() {
        assert!(is_valid("s=abc123;i=1;b=def456"));
    }

    #[test]
    fn oversized_cursor_is_invalid() {
        let big = "s=".to_string() + &"a".repeat(MAX_CURSOR_LEN);
        assert!(!is_valid(&big));
    }

    #[test]
    fn cursor_at_limit_is_valid() {
        let exact = "a".repeat(MAX_CURSOR_LEN);
        assert!(is_valid(&exact));
    }

    #[test]
    fn control_chars_are_invalid() {
        assert!(!is_valid("s=abc\ndef"));
        assert!(!is_valid("s=abc\0def"));
        assert!(!is_valid("\t"));
    }
}
