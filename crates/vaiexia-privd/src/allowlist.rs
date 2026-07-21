//! Operator-configured package allowlist (spec §4 privilege containment).
//! Absent file = permissive (any valid PackageName — the pre-Step-4 posture).
//! Present file = only listed packages may be installed/removed: a compromised
//! daemon cannot direct root-privd at an arbitrary attacker package.
//! Std-only; read once at startup; restart to change.
//!
//! This module is portable (not cfg-gated): the pure logic is unit-tested on
//! Windows; the dispatch wiring lives in socket.rs which is #[cfg(unix)].
// The items here are consumed by run_unix() / socket.rs (both cfg(unix)), so
// the dead_code lint fires on the Windows/non-unix dev host — silence it.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::BTreeSet;
use std::path::Path;

pub const DEFAULT_PATH: &str = "/etc/vaiexia/pkg-allowlist";
pub const PATH_ENV: &str = "VAIEXIA_PKG_ALLOWLIST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowlist {
    Permissive,
    Restricted(BTreeSet<String>),
}

impl Allowlist {
    /// True iff `name` is a valid PackageName AND (permissive OR listed).
    /// Validity re-checked here — defense in depth, independent of dispatch.
    pub fn permits(&self, name: &str) -> bool {
        if vaiexia_priv_proto::PackageName::parse(name).is_err() {
            return false;
        }
        match self {
            Allowlist::Permissive => true,
            Allowlist::Restricted(set) => set.contains(name),
        }
    }
}

/// Pure parser (unit-tested on every platform). Returns warnings for skipped
/// invalid lines — skipping NARROWS the list (fail-closed direction).
pub fn parse_allowlist(body: &str) -> (Allowlist, Vec<String>) {
    let mut set = BTreeSet::new();
    let mut warnings = Vec::new();
    for (i, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match vaiexia_priv_proto::PackageName::parse(line) {
            Ok(_) => {
                set.insert(line.to_string());
            }
            Err(_) => warnings.push(format!(
                "pkg-allowlist line {}: invalid package name, skipped",
                i + 1
            )),
        }
    }
    (Allowlist::Restricted(set), warnings)
}

/// File loader: ENOENT → Permissive; any OTHER error → Err (caller must
/// refuse to start — the operator's restriction intent must not silently
/// degrade to permissive). Warnings are printed by the caller.
pub fn load_allowlist(path: &Path) -> std::io::Result<Allowlist> {
    match std::fs::read_to_string(path) {
        Ok(body) => {
            let (al, warnings) = parse_allowlist(&body);
            for w in &warnings {
                eprintln!("privd: {w}");
            }
            if matches!(&al, Allowlist::Restricted(s) if s.is_empty()) {
                eprintln!(
                    "privd: pkg-allowlist present but empty — ALL package installs/removes will be refused"
                );
            }
            Ok(al)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Allowlist::Permissive),
        Err(e) => Err(e),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_default_is_permissive_and_permits_any_valid_name() {
        let al = Allowlist::Permissive;
        assert!(al.permits("nginx"));
        assert!(al.permits("libfoo2-dev"));
    }

    #[test]
    fn parse_builds_restricted_set_skipping_comments_blanks_and_invalid() {
        let (al, warnings) = parse_allowlist("# web stack\nnginx\n\n  curl  \n-rf\nvim\n");
        // "-rf" is not a valid PackageName → warned + skipped (narrowing = fail-closed)
        assert_eq!(warnings.len(), 1);
        match &al {
            Allowlist::Restricted(set) => {
                assert_eq!(set.len(), 3);
                assert!(al.permits("nginx") && al.permits("curl") && al.permits("vim"));
                assert!(!al.permits("netcat"), "valid name NOT on the list → denied");
                assert!(!al.permits("-rf"), "invalid names denied regardless");
            }
            Allowlist::Permissive => panic!("non-empty file must restrict"),
        }
    }

    #[test]
    fn empty_file_denies_everything() {
        let (al, _) = parse_allowlist("# locked\n");
        assert!(matches!(&al, Allowlist::Restricted(s) if s.is_empty()));
        assert!(!al.permits("nginx"));
    }

    #[test]
    fn load_from_missing_path_is_permissive() {
        let missing = std::env::temp_dir().join("vx-allowlist-definitely-missing");
        let _ = std::fs::remove_file(&missing);
        assert!(matches!(load_allowlist(&missing).unwrap(), Allowlist::Permissive));
    }
}
