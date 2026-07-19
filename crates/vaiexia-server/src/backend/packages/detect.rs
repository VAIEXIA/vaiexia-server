//! Package manager detection from `/etc/os-release`.
//! Portable — compiled on ALL platforms, unit-tested cross-platform.

use std::path::Path;

/// The detected package manager kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageKind {
    Apt,
    Dnf,
    Pacman,
    Apk,
}

impl PackageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PackageKind::Apt => "apt",
            PackageKind::Dnf => "dnf",
            PackageKind::Pacman => "pacman",
            PackageKind::Apk => "apk",
        }
    }
}

/// Parse `/etc/os-release` text to detect the package manager.
///
/// Checks `ID=` and `ID_LIKE=` fields (space-separated list in ID_LIKE).
/// Returns `None` for unknown distros.
pub fn from_os_release(content: &str) -> Option<PackageKind> {
    let mut id: Option<&str> = None;
    let mut id_like: Option<&str> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("ID=") {
            id = Some(val.trim_matches('"'));
        } else if let Some(val) = line.strip_prefix("ID_LIKE=") {
            id_like = Some(val.trim_matches('"'));
        }
    }

    // Check primary ID first, then fallback to ID_LIKE
    if let Some(kind) = id.and_then(kind_from_id) {
        return Some(kind);
    }
    // ID_LIKE may be space-separated list of distros
    if let Some(like) = id_like {
        for token in like.split_whitespace() {
            if let Some(kind) = kind_from_id(token) {
                return Some(kind);
            }
        }
    }
    None
}

fn kind_from_id(id: &str) -> Option<PackageKind> {
    match id {
        "debian" | "ubuntu" | "raspbian" | "linuxmint" | "pop" => Some(PackageKind::Apt),
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => Some(PackageKind::Dnf),
        "arch" | "manjaro" | "endeavouros" | "artix" => Some(PackageKind::Pacman),
        "alpine" => Some(PackageKind::Apk),
        _ => None,
    }
}

/// Absolute allowlisted paths for each package manager binary.
pub fn binary_path(kind: PackageKind) -> &'static str {
    match kind {
        PackageKind::Apt => "/usr/bin/apt-get",
        PackageKind::Dnf => "/usr/bin/dnf",
        PackageKind::Pacman => "/usr/bin/pacman",
        PackageKind::Apk => "/sbin/apk",
    }
}

/// Confirm the package manager is usable by checking if its binary exists.
///
/// `path_exists` is injected for testability; in production pass
/// `|p| p.exists()`.
pub fn confirm(kind: PackageKind, mut path_exists: impl FnMut(&Path) -> bool) -> bool {
    let path = Path::new(binary_path(kind));
    path_exists(path)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── from_os_release ───────────────────────────────────────────────────────

    #[test]
    fn debian_id_gives_apt() {
        let content = "ID=debian\nVERSION=12\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Apt));
    }

    #[test]
    fn ubuntu_id_gives_apt() {
        let content = "ID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Apt));
    }

    #[test]
    fn fedora_id_gives_dnf() {
        let content = "ID=fedora\nVERSION=39\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Dnf));
    }

    #[test]
    fn centos_id_like_fedora_gives_dnf() {
        // CentOS has ID=centos, which maps directly
        let content = "ID=centos\nID_LIKE=\"rhel fedora\"\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Dnf));
    }

    #[test]
    fn arch_id_gives_pacman() {
        let content = "ID=arch\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Pacman));
    }

    #[test]
    fn alpine_id_gives_apk() {
        let content = "ID=alpine\nVERSION_ID=3.18.0\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Apk));
    }

    #[test]
    fn unknown_id_returns_none() {
        let content = "ID=gentoo\nID_LIKE=unknown\n";
        assert_eq!(from_os_release(content), None);
    }

    #[test]
    fn empty_content_returns_none() {
        assert_eq!(from_os_release(""), None);
    }

    #[test]
    fn id_like_fallback_debian_gives_apt() {
        // When primary ID is unknown but ID_LIKE contains debian
        let content = "ID=linuxmint\nID_LIKE=ubuntu debian\n";
        // linuxmint directly maps to Apt
        assert_eq!(from_os_release(content), Some(PackageKind::Apt));
    }

    #[test]
    fn id_like_with_unknown_id_falls_back() {
        // ID is some unknown distro, ID_LIKE has arch
        let content = "ID=steamos\nID_LIKE=arch\n";
        // steamos is not known, but arch in ID_LIKE should work
        assert_eq!(from_os_release(content), Some(PackageKind::Pacman));
    }

    #[test]
    fn quoted_id_value_stripped() {
        let content = "ID=\"debian\"\n";
        assert_eq!(from_os_release(content), Some(PackageKind::Apt));
    }

    // ── confirm ───────────────────────────────────────────────────────────────

    #[test]
    fn confirm_apt_when_binary_exists() {
        assert!(confirm(PackageKind::Apt, |_| true));
    }

    #[test]
    fn confirm_apt_fails_when_binary_missing() {
        assert!(!confirm(PackageKind::Apt, |_| false));
    }

    #[test]
    fn confirm_checks_correct_path_for_dnf() {
        let mut checked_path: Option<String> = None;
        confirm(PackageKind::Dnf, |p| {
            checked_path = Some(p.to_string_lossy().to_string());
            true
        });
        let path = checked_path.unwrap();
        assert!(path.contains("dnf"), "expected dnf path, got: {path}");
    }

    #[test]
    fn confirm_checks_correct_path_for_pacman() {
        let mut checked_path: Option<String> = None;
        confirm(PackageKind::Pacman, |p| {
            checked_path = Some(p.to_string_lossy().to_string());
            true
        });
        let path = checked_path.unwrap();
        assert!(path.contains("pacman"), "expected pacman path, got: {path}");
    }

    #[test]
    fn confirm_checks_correct_path_for_apk() {
        let mut checked_path: Option<String> = None;
        confirm(PackageKind::Apk, |p| {
            checked_path = Some(p.to_string_lossy().to_string());
            true
        });
        let path = checked_path.unwrap();
        assert!(path.contains("apk"), "expected apk path, got: {path}");
    }
}
