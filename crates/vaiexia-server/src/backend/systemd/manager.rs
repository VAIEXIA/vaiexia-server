//! Portable list-filter helper for systemd unit listings.
//! Compiled on ALL platforms; unit-tested cross-platform.

use crate::backend::{ServiceState, UnitStatus};

// ── Glob matching ────────────────────────────────────────────────────────────

/// Minimal glob matcher supporting `*` (any sequence) and `?` (any single char).
/// Case-sensitive. No escaping needed for unit names.
///
/// Iterative single-backtrack-point algorithm: O(len(pattern) * len(text))
/// worst case, no recursion. The pattern is caller-supplied (API filter), so
/// the exponential blowup of a naive recursive matcher would be a DoS vector.
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();

    let mut p = 0; // position in pattern
    let mut t = 0; // position in text
    let mut star: Option<usize> = None; // pattern index just after the last '*'
    let mut mark = 0; // text index where the last '*' started matching

    while t < txt.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == txt[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == '*' {
            star = Some(p + 1);
            mark = t;
            p += 1;
        } else if let Some(after_star) = star {
            // Backtrack: let the last '*' consume one more text char.
            p = after_star;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    // Remaining pattern must be all '*'.
    pat[p..].iter().all(|&c| c == '*')
}

// ── list_filter ──────────────────────────────────────────────────────────────

/// Filter a list of `UnitStatus` by optional state and optional name glob.
///
/// - `state_filter`: if `Some(s)`, keep only units where `active_state == s`.
/// - `name_glob`: if `Some(g)`, keep only units whose `name` matches the glob.
pub fn list_filter(
    units: Vec<UnitStatus>,
    state_filter: Option<ServiceState>,
    name_glob: Option<&str>,
) -> Vec<UnitStatus> {
    units
        .into_iter()
        .filter(|u| {
            state_filter
                .map(|s| u.active_state == s)
                .unwrap_or(true)
        })
        .filter(|u| {
            name_glob
                .map(|g| glob_matches(g, &u.name))
                .unwrap_or(true)
        })
        .collect()
}

// ── Pagination ───────────────────────────────────────────────────────────────

/// Slice `items` into a page of at most `size` starting at `start`, with
/// overflow-safe index math (`start` comes from a caller-supplied cursor).
///
/// Returns the page and the next-page cursor (the next start index) if more
/// items remain.
pub fn paginate<T: Clone>(items: &[T], start: usize, size: usize) -> (Vec<T>, Option<String>) {
    let begin = start.min(items.len());
    let end = begin.saturating_add(size).min(items.len());
    let page = items[begin..end].to_vec();
    let next = if end < items.len() {
        Some(end.to_string())
    } else {
        None
    };
    (page, next)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ServiceState, UnitStatus};

    fn make_unit(name: &str, state: ServiceState) -> UnitStatus {
        UnitStatus {
            name: name.to_string(),
            description: String::new(),
            load_state: "loaded".to_string(),
            active_state: state,
            sub_state: String::new(),
        }
    }

    fn fixture() -> Vec<UnitStatus> {
        vec![
            make_unit("nginx.service", ServiceState::Active),
            make_unit("sshd.service", ServiceState::Active),
            make_unit("mysql.service", ServiceState::Inactive),
            make_unit("ssh-agent.service", ServiceState::Failed),
            make_unit("cron.timer", ServiceState::Active),
        ]
    }

    // ── state filter ─────────────────────────────────────────────────────────

    #[test]
    fn filter_active_state_keeps_only_active() {
        let result = list_filter(fixture(), Some(ServiceState::Active), None);
        assert_eq!(result.len(), 3);
        assert!(result.iter().all(|u| u.active_state == ServiceState::Active));
    }

    #[test]
    fn filter_inactive_state() {
        let result = list_filter(fixture(), Some(ServiceState::Inactive), None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "mysql.service");
    }

    #[test]
    fn filter_failed_state() {
        let result = list_filter(fixture(), Some(ServiceState::Failed), None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "ssh-agent.service");
    }

    #[test]
    fn filter_no_state_returns_all() {
        let result = list_filter(fixture(), None, None);
        assert_eq!(result.len(), 5);
    }

    // ── glob filter ──────────────────────────────────────────────────────────

    #[test]
    fn filter_glob_ssh_star_matches_two() {
        let result = list_filter(fixture(), None, Some("ssh*"));
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|u| u.name == "sshd.service"));
        assert!(result.iter().any(|u| u.name == "ssh-agent.service"));
    }

    #[test]
    fn filter_glob_star_service_matches_four_services() {
        let result = list_filter(fixture(), None, Some("*.service"));
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn filter_glob_question_mark() {
        // "?yssql.service" → should NOT match "mysql.service" (m != ?)
        // "?ysql.service" → should match "mysql.service"
        let result = list_filter(fixture(), None, Some("?ysql.service"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "mysql.service");
    }

    #[test]
    fn filter_glob_no_match_returns_empty() {
        let result = list_filter(fixture(), None, Some("postgres*"));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_glob_exact_match() {
        let result = list_filter(fixture(), None, Some("nginx.service"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "nginx.service");
    }

    // ── combined filter ──────────────────────────────────────────────────────

    #[test]
    fn filter_active_and_ssh_glob() {
        let result = list_filter(fixture(), Some(ServiceState::Active), Some("ssh*"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "sshd.service");
    }

    // ── glob_matches unit tests ───────────────────────────────────────────────

    #[test]
    fn glob_star_matches_empty() {
        assert!(glob_matches("*", ""));
    }

    #[test]
    fn glob_star_matches_anything() {
        assert!(glob_matches("*", "nginx.service"));
    }

    #[test]
    fn glob_star_suffix() {
        assert!(glob_matches("ssh*", "sshd.service"));
        assert!(glob_matches("ssh*", "ssh-agent.service"));
        assert!(!glob_matches("ssh*", "nginx.service"));
    }

    #[test]
    fn glob_question_mark_single_char() {
        assert!(glob_matches("?ginx.service", "nginx.service"));
        assert!(!glob_matches("?ginx.service", "ginx.service")); // too short
    }

    #[test]
    fn glob_no_wildcards_exact() {
        assert!(glob_matches("nginx.service", "nginx.service"));
        assert!(!glob_matches("nginx.service", "nginx.timer"));
    }

    #[test]
    fn glob_star_in_middle() {
        assert!(glob_matches("ssh*.service", "ssh-agent.service"));
        assert!(glob_matches("*ssh*", "openssh-server"));
        assert!(!glob_matches("ssh*.timer", "sshd.service"));
    }

    #[test]
    fn glob_trailing_stars_match() {
        assert!(glob_matches("nginx**", "nginx"));
        assert!(glob_matches("**", ""));
    }

    #[test]
    fn glob_pathological_pattern_completes_quickly() {
        // A naive recursive matcher is exponential on this shape; the
        // iterative matcher must answer (false) in well under a second.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text: String = std::iter::repeat_n('a', 500).collect();
        let started = std::time::Instant::now();
        assert!(!glob_matches(pattern, &text));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "glob match took too long: {:?}",
            started.elapsed()
        );
    }

    // ── paginate ─────────────────────────────────────────────────────────────

    #[test]
    fn paginate_first_page_with_next() {
        let items: Vec<u32> = (0..60).collect();
        let (page, next) = paginate(&items, 0, 25);
        assert_eq!(page.len(), 25);
        assert_eq!(page[0], 0);
        assert_eq!(next, Some("25".to_string()));
    }

    #[test]
    fn paginate_last_partial_page_no_next() {
        let items: Vec<u32> = (0..60).collect();
        let (page, next) = paginate(&items, 50, 25);
        assert_eq!(page.len(), 10);
        assert_eq!(page[0], 50);
        assert_eq!(next, None);
    }

    #[test]
    fn paginate_exact_boundary_no_next() {
        let items: Vec<u32> = (0..50).collect();
        let (page, next) = paginate(&items, 25, 25);
        assert_eq!(page.len(), 25);
        assert_eq!(next, None);
    }

    #[test]
    fn paginate_start_beyond_len_empty() {
        let items: Vec<u32> = (0..10).collect();
        let (page, next) = paginate(&items, 100, 25);
        assert!(page.is_empty());
        assert_eq!(next, None);
    }

    #[test]
    fn paginate_hostile_usize_max_cursor_no_panic() {
        // A cursor of usize::MAX must not overflow (previously
        // `start + PAGE_SIZE` could panic in debug builds).
        let items: Vec<u32> = (0..10).collect();
        let (page, next) = paginate(&items, usize::MAX, 25);
        assert!(page.is_empty());
        assert_eq!(next, None);
        // And size = usize::MAX must saturate, not overflow.
        let (page, next) = paginate(&items, 5, usize::MAX);
        assert_eq!(page.len(), 5);
        assert_eq!(next, None);
    }

    #[test]
    fn paginate_empty_items() {
        let items: Vec<u32> = Vec::new();
        let (page, next) = paginate(&items, 0, 25);
        assert!(page.is_empty());
        assert_eq!(next, None);
    }
}
