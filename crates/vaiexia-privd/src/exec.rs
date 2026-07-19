//! Package operation argv builder for vaiexia-privd.
//!
//! This module builds the exact subprocess argv for each supported package
//! operation. Security requirements:
//! - Absolute paths only (no PATH lookups)
//! - Fixed flags (no user-controlled flags)
//! - `--` separator before the package name (prevents flag injection)
//! - PackageName re-validated inside privd (defense-in-depth)
//! - Ping/ProtoVersion have no subprocess — return None
//!
//! Portable — compiled on ALL platforms, unit-tested cross-platform.

use vaiexia_priv_proto::{PackageName, PrivRequest};

/// The package manager kind, mirrored here to avoid a dependency on
/// the server crate's backend module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PackageKind {
    Apt,
    Dnf,
    Pacman,
    Apk,
}

/// Build the subprocess argv for a package operation.
///
/// Returns `None` for non-exec verbs (Ping, ProtoVersion).
/// The name is re-validated — an invalid name returns `None`
/// (the caller should respond with an Error).
#[allow(dead_code)]
pub fn verb_to_argv(req: &PrivRequest, kind: PackageKind) -> Option<Vec<String>> {
    match req {
        PrivRequest::Ping | PrivRequest::ProtoVersion => None,

        PrivRequest::PkgInstall { name } => {
            // Re-validate: defense-in-depth
            let name_str = name.as_str();
            if PackageName::parse(name_str).is_err() {
                return None;
            }
            Some(install_argv(kind, name_str))
        }

        PrivRequest::PkgRemove { name } => {
            let name_str = name.as_str();
            if PackageName::parse(name_str).is_err() {
                return None;
            }
            Some(remove_argv(kind, name_str))
        }

        PrivRequest::PkgRefreshIndex => Some(refresh_argv(kind)),
    }
}

fn install_argv(kind: PackageKind, name: &str) -> Vec<String> {
    match kind {
        PackageKind::Apt => vec![
            "/usr/bin/apt-get".into(),
            "install".into(),
            "-y".into(),
            "--no-install-recommends".into(),
            "--".into(),
            name.to_string(),
        ],
        PackageKind::Dnf => vec![
            "/usr/bin/dnf".into(),
            "install".into(),
            "-y".into(),
            "--".into(),
            name.to_string(),
        ],
        PackageKind::Pacman => vec![
            "/usr/bin/pacman".into(),
            "-S".into(),
            "--noconfirm".into(),
            "--".into(),
            name.to_string(),
        ],
        PackageKind::Apk => vec![
            "/sbin/apk".into(),
            "add".into(),
            "--".into(),
            name.to_string(),
        ],
    }
}

fn remove_argv(kind: PackageKind, name: &str) -> Vec<String> {
    match kind {
        PackageKind::Apt => vec![
            "/usr/bin/apt-get".into(),
            "remove".into(),
            "-y".into(),
            "--".into(),
            name.to_string(),
        ],
        PackageKind::Dnf => vec![
            "/usr/bin/dnf".into(),
            "remove".into(),
            "-y".into(),
            "--".into(),
            name.to_string(),
        ],
        PackageKind::Pacman => vec![
            "/usr/bin/pacman".into(),
            "-R".into(),
            "--noconfirm".into(),
            "--".into(),
            name.to_string(),
        ],
        PackageKind::Apk => vec![
            "/sbin/apk".into(),
            "del".into(),
            "--".into(),
            name.to_string(),
        ],
    }
}

fn refresh_argv(kind: PackageKind) -> Vec<String> {
    match kind {
        PackageKind::Apt => vec![
            "/usr/bin/apt-get".into(),
            "update".into(),
            "-y".into(),
        ],
        PackageKind::Dnf => vec![
            "/usr/bin/dnf".into(),
            "check-update".into(),
        ],
        PackageKind::Pacman => vec![
            "/usr/bin/pacman".into(),
            "-Sy".into(),
        ],
        PackageKind::Apk => vec![
            "/sbin/apk".into(),
            "update".into(),
        ],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vaiexia_priv_proto::{PackageName, PrivRequest};

    fn pkg_install(name: &str) -> PrivRequest {
        PrivRequest::PkgInstall {
            name: PackageName::parse(name).expect("valid test name"),
        }
    }

    fn pkg_remove(name: &str) -> PrivRequest {
        PrivRequest::PkgRemove {
            name: PackageName::parse(name).expect("valid test name"),
        }
    }

    // ── Ping / ProtoVersion → None ────────────────────────────────────────────

    #[test]
    fn ping_returns_none() {
        assert_eq!(verb_to_argv(&PrivRequest::Ping, PackageKind::Apt), None);
    }

    #[test]
    fn proto_version_returns_none() {
        assert_eq!(verb_to_argv(&PrivRequest::ProtoVersion, PackageKind::Apt), None);
    }

    // ── Apt install ────────────────────────────────────────────────��──────────

    #[test]
    fn apt_install_nginx() {
        let argv = verb_to_argv(&pkg_install("nginx"), PackageKind::Apt).unwrap();
        assert_eq!(argv[0], "/usr/bin/apt-get");
        assert_eq!(argv[1], "install");
        assert!(argv.contains(&"-y".to_string()));
        assert!(argv.contains(&"--no-install-recommends".to_string()));
        // -- guard before name
        let dash_dash_pos = argv.iter().position(|a| a == "--").expect("-- guard");
        assert_eq!(argv[dash_dash_pos + 1], "nginx");
    }

    #[test]
    fn apt_install_has_absolute_path() {
        let argv = verb_to_argv(&pkg_install("curl"), PackageKind::Apt).unwrap();
        assert!(argv[0].starts_with('/'), "must be absolute path");
    }

    #[test]
    fn apt_install_no_shell_wrapper() {
        let argv = verb_to_argv(&pkg_install("curl"), PackageKind::Apt).unwrap();
        assert!(!argv.iter().any(|a| a == "/bin/sh" || a == "-c"));
    }

    // ── Dnf install ───────────────────────────────────────────────────────────

    #[test]
    fn dnf_install_has_dash_dash_guard() {
        let argv = verb_to_argv(&pkg_install("nginx"), PackageKind::Dnf).unwrap();
        assert_eq!(argv[0], "/usr/bin/dnf");
        let dd = argv.iter().position(|a| a == "--").expect("-- guard");
        assert_eq!(argv[dd + 1], "nginx");
    }

    // ── Pacman install ────────────────────────────────────────────────────────

    #[test]
    fn pacman_install_has_dash_dash_guard() {
        let argv = verb_to_argv(&pkg_install("nginx"), PackageKind::Pacman).unwrap();
        assert_eq!(argv[0], "/usr/bin/pacman");
        assert!(argv.contains(&"--noconfirm".to_string()));
        let dd = argv.iter().position(|a| a == "--").expect("-- guard");
        assert_eq!(argv[dd + 1], "nginx");
    }

    // ── Apk install ───────────────────────────────────────────────────────────

    #[test]
    fn apk_install_has_dash_dash_guard() {
        let argv = verb_to_argv(&pkg_install("nginx"), PackageKind::Apk).unwrap();
        assert_eq!(argv[0], "/sbin/apk");
        let dd = argv.iter().position(|a| a == "--").expect("-- guard");
        assert_eq!(argv[dd + 1], "nginx");
    }

    // ── Remove verbs ──────────────────────────────────────────────────────────

    #[test]
    fn apt_remove_has_remove_verb() {
        let argv = verb_to_argv(&pkg_remove("curl"), PackageKind::Apt).unwrap();
        assert_eq!(argv[1], "remove");
        let dd = argv.iter().position(|a| a == "--").expect("-- guard");
        assert_eq!(argv[dd + 1], "curl");
    }

    #[test]
    fn dnf_remove_has_remove_verb() {
        let argv = verb_to_argv(&pkg_remove("curl"), PackageKind::Dnf).unwrap();
        assert_eq!(argv[1], "remove");
    }

    #[test]
    fn pacman_remove_uses_minus_r() {
        let argv = verb_to_argv(&pkg_remove("curl"), PackageKind::Pacman).unwrap();
        assert!(argv.contains(&"-R".to_string()));
    }

    #[test]
    fn apk_remove_uses_del() {
        let argv = verb_to_argv(&pkg_remove("curl"), PackageKind::Apk).unwrap();
        assert_eq!(argv[1], "del");
    }

    // ── RefreshIndex ──────────────────────────────────────────────────────────

    #[test]
    fn apt_refresh_uses_apt_get_update() {
        let argv = verb_to_argv(&PrivRequest::PkgRefreshIndex, PackageKind::Apt).unwrap();
        assert_eq!(argv[0], "/usr/bin/apt-get");
        assert_eq!(argv[1], "update");
    }

    #[test]
    fn dnf_refresh_uses_check_update() {
        let argv = verb_to_argv(&PrivRequest::PkgRefreshIndex, PackageKind::Dnf).unwrap();
        assert_eq!(argv[1], "check-update");
    }

    #[test]
    fn pacman_refresh_uses_sy() {
        let argv = verb_to_argv(&PrivRequest::PkgRefreshIndex, PackageKind::Pacman).unwrap();
        assert!(argv.contains(&"-Sy".to_string()));
    }

    #[test]
    fn apk_refresh_uses_update() {
        let argv = verb_to_argv(&PrivRequest::PkgRefreshIndex, PackageKind::Apk).unwrap();
        assert_eq!(argv[1], "update");
    }

    // ── All install verbs have absolute paths ─────────────────────────────────

    #[test]
    fn all_managers_install_use_absolute_paths() {
        for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
            let argv = verb_to_argv(&pkg_install("nginx"), kind).unwrap();
            assert!(
                argv[0].starts_with('/'),
                "{kind:?} install argv[0] must be absolute, got: {}",
                argv[0]
            );
        }
    }

    // ── All install verbs have -- guard ───────────────────────────────────────

    #[test]
    fn all_managers_install_have_dash_dash_guard() {
        for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
            let argv = verb_to_argv(&pkg_install("nginx"), kind).unwrap();
            assert!(
                argv.iter().any(|a| a == "--"),
                "{kind:?} install must contain -- guard: {argv:?}"
            );
        }
    }

    // ── All remove verbs have -- guard ────────────────────────────────────────

    #[test]
    fn all_managers_remove_have_dash_dash_guard() {
        for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
            let argv = verb_to_argv(&pkg_remove("nginx"), kind).unwrap();
            assert!(
                argv.iter().any(|a| a == "--"),
                "{kind:?} remove must contain -- guard: {argv:?}"
            );
        }
    }
}
