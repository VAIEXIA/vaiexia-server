//! Cursor helpers for the journald log provider.
//! A cursor is an opaque string from `__CURSOR` in the journal JSON.
//! These helpers are portable and unit-tested cross-platform.

/// Returns true if the cursor string is non-empty and looks like a valid
/// journald cursor (starts with "s=" field or is otherwise non-empty).
///
/// We do NOT validate the full structure — journald cursors are opaque.
/// This is a simple non-empty guard.
pub fn is_valid(cursor: &str) -> bool {
    !cursor.is_empty()
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
}
