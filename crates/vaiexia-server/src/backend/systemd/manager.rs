//! Portable list-filter helper for systemd unit listings.
//! Compiled on ALL platforms; unit-tested cross-platform.

use crate::backend::{ServiceState, UnitStatus};

// ── Glob matching ────────────────────────────────────────────────────────────

/// Minimal glob matcher supporting `*` (any sequence) and `?` (any single char).
/// Case-sensitive. No escaping needed for unit names.
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    match (pat.first(), txt.first()) {
        (None, None) => true,
        (Some(&'*'), _) => {
            // Try matching zero characters, then one, etc.
            glob_match_inner(&pat[1..], txt)
                || (!txt.is_empty() && glob_match_inner(pat, &txt[1..]))
        }
        (Some(&'?'), Some(_)) => glob_match_inner(&pat[1..], &txt[1..]),
        (Some(p), Some(t)) if p == t => glob_match_inner(&pat[1..], &txt[1..]),
        _ => false,
    }
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
}
