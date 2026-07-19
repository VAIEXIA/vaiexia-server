//! Package manager list/query argv building and output parsing.
//! Portable — compiled on ALL platforms, unit-tested cross-platform.

use crate::backend::PackageInfo;
use super::detect::PackageKind;

// ── build_list_argv ───────────────────────────────────────────────────────────

/// Build machine-readable argv for listing packages.
///
/// Uses the most reliable read-only tool per manager:
/// - Apt: `dpkg-query -W -f=${Package}\t${Version}\t${Status}\t${binary:Summary}\n`
/// - Dnf: `dnf list --quiet` (installed or all)
/// - Pacman: `pacman -Q` (installed) or `pacman -Ss` (search) — we use `-Q` for
///   installed, and `pacman -Ss <query>` for search
/// - Apk: `apk list --installed` or `apk list`
///
/// `query`: optional search string (passed as a search term, manager-specific).
/// `installed_only`: restrict to installed packages.
///
/// No shell metachars — argv is a Vec<String> passed directly to exec.
pub fn build_list_argv(
    kind: PackageKind,
    query: Option<&str>,
    installed_only: bool,
) -> Vec<String> {
    match kind {
        PackageKind::Apt => build_apt_list_argv(query, installed_only),
        PackageKind::Dnf => build_dnf_list_argv(query, installed_only),
        PackageKind::Pacman => build_pacman_list_argv(query, installed_only),
        PackageKind::Apk => build_apk_list_argv(query, installed_only),
    }
}

fn build_apt_list_argv(query: Option<&str>, installed_only: bool) -> Vec<String> {
    if installed_only || query.is_none() {
        // Use dpkg-query for installed packages — reliable, machine-readable
        let mut args = vec![
            "/usr/bin/dpkg-query".to_string(),
            "-W".to_string(),
            "-f=${Package}\\t${Version}\\t${Status}\\t${binary:Summary}\\n".to_string(),
        ];
        if let Some(q) = query {
            args.push(format!("*{}*", q));
        }
        args
    } else {
        // apt-cache search for all packages
        let mut args = vec![
            "/usr/bin/apt-cache".to_string(),
            "search".to_string(),
            "--names-only".to_string(),
        ];
        if let Some(q) = query {
            args.push(q.to_string());
        } else {
            args.push(".*".to_string());
        }
        args
    }
}

fn build_dnf_list_argv(query: Option<&str>, installed_only: bool) -> Vec<String> {
    let mut args = vec![
        "/usr/bin/dnf".to_string(),
        "list".to_string(),
        "--quiet".to_string(),
    ];
    if installed_only {
        args.push("--installed".to_string());
    }
    if let Some(q) = query {
        args.push(q.to_string());
    }
    args
}

fn build_pacman_list_argv(query: Option<&str>, installed_only: bool) -> Vec<String> {
    if installed_only {
        // pacman -Q [filter] — lists installed packages
        let mut args = vec![
            "/usr/bin/pacman".to_string(),
            "-Q".to_string(),
        ];
        if let Some(q) = query {
            args.push(q.to_string());
        }
        args
    } else {
        // pacman -Ss <query> — search all repos
        let mut args = vec![
            "/usr/bin/pacman".to_string(),
            "-Ss".to_string(),
        ];
        if let Some(q) = query {
            args.push(q.to_string());
        }
        args
    }
}

fn build_apk_list_argv(query: Option<&str>, installed_only: bool) -> Vec<String> {
    let mut args = vec![
        "/sbin/apk".to_string(),
        "list".to_string(),
    ];
    if installed_only {
        args.push("--installed".to_string());
    }
    if let Some(q) = query {
        args.push(q.to_string());
    }
    args
}

// ── parse_list ────────────────────────────────────────────────────────────────

/// Parse the stdout of a package list command into `Vec<PackageInfo>`.
pub fn parse_list(kind: PackageKind, stdout: &str) -> Vec<PackageInfo> {
    match kind {
        PackageKind::Apt => parse_dpkg_query(stdout),
        PackageKind::Dnf => parse_dnf_list(stdout),
        PackageKind::Pacman => parse_pacman_query(stdout),
        PackageKind::Apk => parse_apk_list(stdout),
    }
}

/// Parse `dpkg-query -W -f=...` output.
///
/// Each line: `name\tversion\tstatus\tsummary`
/// Status contains "install ok installed" for installed packages.
fn parse_dpkg_query(stdout: &str) -> Vec<PackageInfo> {
    let mut result = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0].trim().to_string();
        let version = parts[1].trim().to_string();
        let status = if parts.len() >= 3 { parts[2].trim() } else { "" };
        let summary = if parts.len() >= 4 {
            let s = parts[3].trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        } else {
            None
        };
        let installed = status.contains("install ok installed");
        if name.is_empty() {
            continue;
        }
        result.push(PackageInfo { name, version, installed, summary });
    }
    result
}

/// Parse `dnf list --quiet` output.
///
/// Lines look like: `nginx.x86_64   1:1.24.0-1.fc39   @fedora`
/// The third column starts with `@` for installed packages.
fn parse_dnf_list(stdout: &str) -> Vec<PackageInfo> {
    let mut result = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        // Skip header lines
        if line.starts_with("Installed") || line.starts_with("Available") || line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        // name may have arch suffix like "nginx.x86_64" — strip it
        let name_arch = parts[0];
        let name = name_arch.split('.').next().unwrap_or(name_arch).to_string();
        let version = parts[1].to_string();
        let installed = parts.get(2).map(|r| r.starts_with('@')).unwrap_or(false);
        result.push(PackageInfo { name, version, installed, summary: None });
    }
    result
}

/// Parse `pacman -Q` output.
///
/// Each line: `package version`
/// All output from -Q is installed.
fn parse_pacman_query(stdout: &str) -> Vec<PackageInfo> {
    let mut result = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0].to_string();
        let version = parts[1].trim().to_string();
        result.push(PackageInfo { name, version, installed: true, summary: None });
    }
    result
}

/// Parse `apk list` output.
///
/// Lines look like: `nginx-1.24.0-r0 x86_64 {nginx} (BSD-2-Clause) [installed]`
fn parse_apk_list(stdout: &str) -> Vec<PackageInfo> {
    let mut result = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let installed = line.contains("[installed]");
        // Name-version is the first token, e.g. "nginx-1.24.0-r0"
        let first = line.split_whitespace().next().unwrap_or("");
        // Split at last '-' that's followed by digit to separate name from version
        let (name, version) = split_apk_name_version(first);
        if name.is_empty() {
            continue;
        }
        result.push(PackageInfo { name, version, installed, summary: None });
    }
    result
}

/// Split an apk package string like "nginx-1.24.0-r0" into ("nginx", "1.24.0-r0").
fn split_apk_name_version(s: &str) -> (String, String) {
    // Find the last '-' preceded by a non-version char or the first '-' followed by a digit
    // Strategy: find the first '-' followed by a digit
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'-' && bytes[i + 1].is_ascii_digit() {
            return (s[..i].to_string(), s[i + 1..].to_string());
        }
    }
    (s.to_string(), String::new())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_list_argv ───────────────────────────────────────────────────────

    #[test]
    fn apt_installed_only_uses_dpkg_query() {
        let args = build_list_argv(PackageKind::Apt, None, true);
        assert!(args[0].contains("dpkg-query"), "expected dpkg-query, got: {:?}", args);
        assert!(args.contains(&"-W".to_string()));
    }

    #[test]
    fn apt_search_uses_apt_cache() {
        let args = build_list_argv(PackageKind::Apt, Some("nginx"), false);
        assert!(args[0].contains("apt-cache"), "expected apt-cache, got: {:?}", args);
        assert!(args.contains(&"nginx".to_string()));
    }

    #[test]
    fn dnf_installed_only_has_installed_flag() {
        let args = build_list_argv(PackageKind::Dnf, None, true);
        assert_eq!(args[0], "/usr/bin/dnf");
        assert!(args.contains(&"--installed".to_string()));
    }

    #[test]
    fn dnf_all_packages() {
        let args = build_list_argv(PackageKind::Dnf, None, false);
        assert!(!args.contains(&"--installed".to_string()));
    }

    #[test]
    fn pacman_installed_uses_minus_q() {
        let args = build_list_argv(PackageKind::Pacman, None, true);
        assert_eq!(args[0], "/usr/bin/pacman");
        assert!(args.contains(&"-Q".to_string()));
        assert!(!args.contains(&"-Ss".to_string()));
    }

    #[test]
    fn pacman_search_uses_minus_ss() {
        let args = build_list_argv(PackageKind::Pacman, Some("nginx"), false);
        assert!(args.contains(&"-Ss".to_string()));
        assert!(args.contains(&"nginx".to_string()));
    }

    #[test]
    fn apk_installed_only_has_flag() {
        let args = build_list_argv(PackageKind::Apk, None, true);
        assert_eq!(args[0], "/sbin/apk");
        assert!(args.contains(&"--installed".to_string()));
    }

    #[test]
    fn no_argv_contains_shell_wrapper() {
        // Verify no shell wrappers in any manager's argv
        for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
            let args = build_list_argv(kind, Some("test"), true);
            assert!(
                !args.iter().any(|a| a == "/bin/sh" || a == "-c"),
                "found shell wrapper in {kind:?} argv: {args:?}"
            );
        }
    }

    // ── parse_list ────────────────────────────────────────────────────────────

    const DPKG_FIXTURE: &str = "\
nginx\t1.24.0-1\tinstall ok installed\tHTTP server\n\
curl\t8.1.0\tinstall ok installed\tURL transfer tool\n\
vim\t9.0\tinstall ok not-installed\tText editor\n";

    #[test]
    fn parse_dpkg_extracts_installed_packages() {
        let pkgs = parse_list(PackageKind::Apt, DPKG_FIXTURE);
        assert_eq!(pkgs.len(), 3);
        let nginx = pkgs.iter().find(|p| p.name == "nginx").unwrap();
        assert_eq!(nginx.version, "1.24.0-1");
        assert!(nginx.installed);
        assert_eq!(nginx.summary, Some("HTTP server".to_string()));
    }

    #[test]
    fn parse_dpkg_marks_not_installed_correctly() {
        let pkgs = parse_list(PackageKind::Apt, DPKG_FIXTURE);
        let vim = pkgs.iter().find(|p| p.name == "vim").unwrap();
        assert!(!vim.installed);
    }

    const DNF_FIXTURE: &str = "\
Installed Packages\n\
nginx.x86_64            1:1.24.0-1.fc39         @fedora\n\
curl.x86_64             7.85.0-1.fc39           @anaconda\n\
Available Packages\n\
vim-enhanced.x86_64     9.0.1-1.fc39            fedora\n";

    #[test]
    fn parse_dnf_installed_packages() {
        let pkgs = parse_list(PackageKind::Dnf, DNF_FIXTURE);
        let nginx = pkgs.iter().find(|p| p.name == "nginx").unwrap();
        assert!(nginx.installed);
    }

    #[test]
    fn parse_dnf_available_packages() {
        let pkgs = parse_list(PackageKind::Dnf, DNF_FIXTURE);
        let vim = pkgs.iter().find(|p| p.name == "vim-enhanced").unwrap();
        assert!(!vim.installed);
    }

    const PACMAN_FIXTURE: &str = "\
nginx 1.24.0-1\n\
curl 8.1.0-2\n\
vim 9.0.1-1\n";

    #[test]
    fn parse_pacman_all_installed() {
        let pkgs = parse_list(PackageKind::Pacman, PACMAN_FIXTURE);
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs.iter().all(|p| p.installed));
        let nginx = pkgs.iter().find(|p| p.name == "nginx").unwrap();
        assert_eq!(nginx.version, "1.24.0-1");
    }

    const APK_FIXTURE: &str = "\
nginx-1.24.0-r0 x86_64 {nginx} (BSD-2-Clause) [installed]\n\
curl-8.1.0-r0 x86_64 {curl} (MIT) [installed]\n\
vim-9.0-r0 x86_64 {vim} (Vim) \n";

    #[test]
    fn parse_apk_installed_flag() {
        let pkgs = parse_list(PackageKind::Apk, APK_FIXTURE);
        assert_eq!(pkgs.len(), 3);
        let nginx = pkgs.iter().find(|p| p.name == "nginx").unwrap();
        assert!(nginx.installed);
        assert_eq!(nginx.version, "1.24.0-r0");
    }

    #[test]
    fn parse_apk_not_installed() {
        let pkgs = parse_list(PackageKind::Apk, APK_FIXTURE);
        let vim = pkgs.iter().find(|p| p.name == "vim").unwrap();
        assert!(!vim.installed);
    }

    #[test]
    fn parse_empty_output_returns_empty_vec() {
        for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
            let result = parse_list(kind, "");
            assert!(result.is_empty(), "{kind:?} parse of empty should be empty");
        }
    }
}
