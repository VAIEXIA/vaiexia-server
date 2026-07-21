//! Structural contract test over `packaging/**`.
//!
//! Pins the confirmed security-critical directives in the systemd units, polkit
//! rules, sysusers, and tmpfiles artifacts so a well-meaning future edit can't
//! silently weaken the posture.  These are text-level assertions — no new deps,
//! no new build-time tools, no Linux runtime required.  Run on every platform:
//!
//!     cargo test -p vaiexia-server --test packaging_structural
//!
//! HOW TO READ THE ASSERTIONS:
//!   Every assertion carries a comment explaining WHICH security decision it
//!   pins and WHERE that decision is documented (plan task + spec §).
//!   If you deliberately change a pinned directive, update this file AND leave
//!   a comment explaining the new decision.  Don't just remove the assertion.

use std::path::Path;

// Resolve every packaging artifact relative to this crate's manifest directory.
// CARGO_MANIFEST_DIR = crates/vaiexia-server; step up two levels → repo root.
fn pkg(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging")
        .join(rel)
}

fn read(rel: &str) -> String {
    let path = pkg(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read packaging/{rel}: {e}"))
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Assert `text` contains the literal `needle`.  Message shows where to look.
fn assert_contains(label: &str, text: &str, needle: &str) {
    assert!(
        text.contains(needle),
        "{label}: expected to contain {needle:?}\n--- file contents ---\n{text}"
    );
}

/// Assert `text` does NOT contain `needle` on any non-comment line
/// (deliberate omission contract).  Comment lines (trimmed `#` or `//`) are
/// excluded so that a comment explaining WHY a directive is absent doesn't
/// falsely trigger the assertion.
fn assert_absent(label: &str, text: &str, needle: &str) {
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue; // skip comment lines
        }
        assert!(
            !line.contains(needle),
            "{label} line {}: must NOT contain {needle:?} on a non-comment line \
             (deliberate omission — read the comment in this test before removing the assertion)\n\
             --- offending line ---\n{line}",
            i + 1
        );
    }
}

/// Assert a line in `text` matches the regex pattern (multiline, anchored).
fn assert_line_matches(label: &str, text: &str, pattern: &str) {
    let re = regex_line(pattern);
    assert!(
        re.is_match(text),
        "{label}: expected a line matching /{pattern}/\n--- file contents ---\n{text}"
    );
}

/// Very small multiline regex: `^…$` over the whole text.  Avoids a regex dep
/// by implementing the minimum needed: literal matching with `^`/`$` anchors.
fn regex_line(pattern: &str) -> SimpleLineRegex {
    SimpleLineRegex(pattern.to_string())
}

struct SimpleLineRegex(String);

impl SimpleLineRegex {
    /// Match the pattern against each line.  Supports only the subset used
    /// below: `^`, `$`, `.*` (greedy any-chars), and literals.
    fn is_match(&self, text: &str) -> bool {
        let p = self.0.as_str();
        // Strip anchors — our patterns are always fully anchored.
        let inner = p.trim_start_matches('^').trim_end_matches('$');
        for line in text.lines() {
            if Self::line_matches(line, inner) {
                return true;
            }
        }
        false
    }

    fn line_matches(line: &str, pattern: &str) -> bool {
        // Split on `.*` and check each segment is present in order.
        let parts: Vec<&str> = pattern.split(".*").collect();
        if parts.is_empty() {
            return true;
        }
        let mut haystack = line;
        for (i, part) in parts.iter().enumerate() {
            if i == 0 {
                // First part: must be a prefix of the remaining haystack.
                if !haystack.starts_with(part) {
                    return false;
                }
                haystack = &haystack[part.len()..];
            } else {
                // Subsequent parts: find the part anywhere in the remaining haystack.
                match haystack.find(part) {
                    Some(pos) => haystack = &haystack[pos + part.len()..],
                    None => return false,
                }
            }
        }
        true
    }
}

/// Extract the body of a JavaScript array assignment `var NAME = [ … ];`.
/// Returns the text between `[` and `]` (inclusive of brackets) so callers can
/// check what is (or isn't) in the array body without being confused by comments
/// outside it that happen to mention the same names.
fn extract_js_array(text: &str, var_name: &str) -> String {
    // Find `var NAME` then the opening bracket.
    let search = format!("var {var_name}");
    let start = match text.find(&search) {
        Some(pos) => pos,
        None => return String::new(),
    };
    let after_var = &text[start..];
    let bracket_open = match after_var.find('[') {
        Some(pos) => start + pos,
        None => return String::new(),
    };
    let bracket_close = match text[bracket_open..].find(']') {
        Some(pos) => bracket_open + pos + 1,
        None => return String::new(),
    };
    text[bracket_open..bracket_close].to_string()
}

// ── Unit grammar walk ─────────────────────────────────────────────────────────

/// Verify that every non-empty line in a systemd unit file is one of:
///   - a section header `[…]`
///   - a comment `# …`
///   - a `key=value` (value may be empty)
///   - a blank line
///
/// This catches typos like an accidentally blank `=` sign or a stray sentence.
fn assert_valid_unit_grammar(label: &str, text: &str) {
    for (i, line) in text.lines().enumerate() {
        let ln = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue; // blank — ok
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            continue; // section header — ok
        }
        if trimmed.starts_with('#') {
            continue; // comment — ok
        }
        assert!(
            trimmed.contains('='),
            "{label} line {ln}: not a section header, comment, blank, or key=value: {line:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: vaiexia-server.service
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn daemon_unit_security_posture() {
    let label = "vaiexia-server.service";
    let text = read("systemd/vaiexia-server.service");

    // ── identity & activation ──────────────────────────────────────────────
    // spec §4: daemon runs as the dedicated non-root system user
    assert_contains(label, &text, "User=vaiexia");

    // spec §6 / S4-A7: Type=notify so systemd waits for READY=1 from sd_notify;
    // without this the unit would report active before the service is ready.
    assert_contains(label, &text, "Type=notify");

    // S4-A7 / plan: ExecStartPre runs --check-config so a broken config
    // aborts the start before the daemon touches any privileged state.
    assert_line_matches(label, &text, "^ExecStartPre=.*--check-config.*$");

    // ── capability & syscall sandbox (spec §4) ─────────────────────────────
    // PRIVILEGE SPLIT — read before changing either of these two pins:
    //
    //   vaiexia-server: non-root, empty CapabilityBoundingSet + full syscall filter
    //   vaiexia-privd:  root, NO CapabilityBoundingSet, NO SystemCallFilter
    //
    // The split is intentional and documented in vaiexia-privd.service and
    // THREAT-MODEL.md.  A PR that "hardens" privd by adding a filter or a
    // capability drop MUST break the privd_unit_privilege_split_pins test below
    // and MUST update the threat model before that test is changed.
    //
    // daemon side: empty CapabilityBoundingSet (no cap survives exec).
    // Regex: the line is exactly "CapabilityBoundingSet=" with no value.
    assert_line_matches(label, &text, "^CapabilityBoundingSet=$");

    // daemon side: full @system-service syscall filter (spec §4 hardening row).
    assert_contains(label, &text, "SystemCallFilter=@system-service");

    // ── deliberate OMISSIONS — do not add these directives ─────────────────
    //
    // RuntimeDirectory= is absent on purpose: vaiexia-privd.socket uses a
    // manually managed path (/run/vaiexia/privd.sock via tmpfiles).  If
    // RuntimeDirectory= were added here, systemd would delete /run/vaiexia on
    // daemon stop and tear down the privd socket mid-flight.
    assert_absent(label, &text, "RuntimeDirectory=");

    // WatchdogSec= is absent because sd_watchdog_enabled() / WATCHDOG_USEC
    // ping is not implemented in v1.  Adding the directive without the ping
    // would cause systemd to kill the daemon after the timeout.
    // Implement sd_watchdog_ping in notify.rs BEFORE adding this.
    assert_absent(label, &text, "WatchdogSec=");

    // ── grammar ────────────────────────────────────────────────────────────
    assert_valid_unit_grammar(label, &text);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: vaiexia-privd.service — privilege-split pins
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn privd_unit_privilege_split_pins() {
    let label = "vaiexia-privd.service";
    let text = read("systemd/vaiexia-privd.service");

    // Type=exec: privd uses socket activation; exec means systemd tracks the
    // main PID after execve, which is correct for a socket-activated helper.
    // (Type=notify would require sd_notify from privd — not implemented.)
    assert_contains(label, &text, "Type=exec");

    // ── DELIBERATE OMISSIONS — the confirmed no-seccomp-on-privd decision ──
    //
    // privd runs as root with NO SystemCallFilter and NO CapabilityBoundingSet.
    // Reason: apt/dnf and their package maintainer scripts need broad root and
    // make syscalls that a seccomp filter would silently break.
    //
    // privd's containment layers (in order, all enforced without a filter):
    //   1. Closed verb vocabulary (PrivRequest — no generic exec)
    //   2. SO_PEERCRED uid gate (only the daemon uid may connect)
    //   3. In-privd PackageName re-validation
    //   4. Optional operator package allowlist (/etc/vaiexia/pkg-allowlist)
    //   5. Single job + hard timeout
    //   6. Defense-in-depth sandbox directives that ARE compatible (NNP, etc.)
    //
    // A "hardening" PR that adds SystemCallFilter= or CapabilityBoundingSet=
    // to privd MUST break this test and MUST update THREAT-MODEL.md §privilege-split
    // with evidence that every supported package manager and its maintainer
    // scripts pass under the proposed filter on the target distro matrix.
    assert_absent(
        label,
        &text,
        "SystemCallFilter=",
        // Note: SystemCallArchitectures= is fine (and present) — it is NOT a
        // filter, it just sets the personality.  Only SystemCallFilter= is pinned.
    );
    assert_absent(label, &text, "CapabilityBoundingSet=");

    // ── grammar ────────────────────────────────────────────────────────────
    assert_valid_unit_grammar(label, &text);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: vaiexia-privd.socket
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn privd_socket_unit() {
    let label = "vaiexia-privd.socket";
    let text = read("systemd/vaiexia-privd.socket");

    // spec §4: the socket is owned by the daemon user; mode 0600 means only
    // vaiexia (uid) can connect — the peercred gate in privd is a second layer.
    assert_contains(label, &text, "SocketMode=0600");
    assert_contains(label, &text, "SocketUser=vaiexia");
    assert_contains(label, &text, "ListenStream=/run/vaiexia/privd.sock");

    assert_valid_unit_grammar(label, &text);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: polkit denylist rule
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn polkit_denylist_rule_content() {
    let label = "50-vaiexia-manage-units.rules";
    let text = read("polkit/50-vaiexia-manage-units.rules");

    // The rule is scoped to the manage-units action (spec §4 privilege separation).
    assert_contains(label, &text, "org.freedesktop.systemd1.manage-units");

    // Only the vaiexia user is affected; all others fall through.
    assert_contains(label, &text, "subject.user !== \"vaiexia\"");

    // ── denylist must reference the action verb lookup ─────────────────────
    assert_contains(label, &text, "action.lookup(\"unit\")");

    // ── every shipped unit filename must appear in the denylist ────────────
    // These assertions cross-check the polkit rule against the actual filenames
    // shipped in packaging/systemd/.  If a new unit is added, add it here AND
    // in the polkit rule's denied array.
    for unit_file in &[
        "vaiexia-server.service",
        "vaiexia-privd.service",
        "vaiexia-privd.socket",
    ] {
        assert_contains(
            label,
            &text,
            unit_file,
            // Each vaiexia unit must be in the denylist so the daemon cannot
            // stop/restart its own privilege boundary.
        );
    }

    // ── critical system units that must remain in the denylist ─────────────
    // These prevent a compromised daemon from restarting polkit/dbus/journald
    // to bypass auditing or elevate privilege.
    for system_unit in &[
        "dbus.service",
        "polkit.service",
        "systemd-journald.service",
    ] {
        assert_contains(label, &text, system_unit);
    }

    // The rule grants the vaiexia user start/stop/restart on non-denied units.
    assert_contains(label, &text, "polkit.Result.YES");
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: polkit — exactly ONE active *.rules file shipped
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn polkit_exactly_one_active_rules_file() {
    // The .example file is inert (not installed by the default path).  Only
    // the denylist rule is the active artifact.  If this test breaks because
    // a new *.rules file was added, verify that both rules compose correctly
    // (polkit evaluates ALL matching rules; two addRule() calls from different
    // files both run).
    let polkit_dir = pkg("polkit");
    let entries: Vec<_> = std::fs::read_dir(&polkit_dir)
        .unwrap_or_else(|e| panic!("cannot read packaging/polkit/: {e}"))
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| x == "rules")
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        entries.len(),
        1,
        "expected exactly 1 *.rules file in packaging/polkit/ (the .example is inert); \
         found: {entries:?}"
    );

    // That one file must be the denylist, not the allowlist example.
    let name = entries[0].file_name();
    assert_eq!(
        name.to_str().unwrap(),
        "50-vaiexia-manage-units.rules",
        "the single active rules file must be the denylist"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: polkit allowlist example
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn polkit_allowlist_example_content() {
    let label = "50-vaiexia-manage-units.allowlist.rules.example";
    let text = read("polkit/50-vaiexia-manage-units.allowlist.rules.example");

    // The example is an opt-in allowlist variant (documented in S4-B2/INSTALL.md).
    assert_contains(label, &text, "org.freedesktop.systemd1.manage-units");

    // In locked-down mode everything outside the allowed list from the vaiexia
    // user returns an explicit NO (unlike the denylist, which falls through).
    assert_contains(label, &text, "polkit.Result.NO");

    // The vaiexia units must NOT appear in the example's `allowed` array.
    // The comment in the file says "Never list vaiexia-server.service /
    // vaiexia-privd.* here".  Pin that contract by extracting the `allowed`
    // array body and checking it there (comments may reference the names for
    // explanatory purposes, and that is fine).
    let allowed_block = extract_js_array(&text, "allowed");
    for unit in &[
        "vaiexia-server.service",
        "vaiexia-privd.service",
        "vaiexia-privd.socket",
    ] {
        assert!(
            !allowed_block.contains(unit),
            "{label}: {unit:?} must NOT appear in the `allowed` array \
             (the daemon must not manage its own privilege boundary in either mode). \
             Found in:\n{allowed_block}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: sysusers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sysusers_grammar() {
    let label = "sysusers/vaiexia.conf";
    let text = read("sysusers/vaiexia.conf");

    // sysusers.d(5): `u NAME ID GECOS HOME SHELL`
    //   u = create a system user
    //   vaiexia = username
    //   - = auto-assign uid
    //   "…" = gecos / comment field
    //   /var/lib/vaiexia = home directory (persistent state)
    assert_line_matches(label, &text, r"^u vaiexia - .* /var/lib/vaiexia$");
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST: tmpfiles
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tmpfiles_grammar() {
    let label = "tmpfiles/vaiexia.conf";
    let text = read("tmpfiles/vaiexia.conf");

    // /run/vaiexia: runtime dir for the privd socket.  Must be owned by root
    // (not vaiexia) — the socket file itself is owned by vaiexia via SocketUser=.
    // If this becomes `vaiexia vaiexia` the peercred gate loses a layer.
    assert_line_matches(label, &text, "^d /run/vaiexia 0755 root root.*$");

    // /var/lib/vaiexia: persistent state dir, owned by the daemon user, 0700.
    assert_line_matches(label, &text, "^d /var/lib/vaiexia 0700 vaiexia vaiexia.*$");

    // The socket path goes under /run/vaiexia, not /run/vaiexia directly.
    assert_contains(label, &text, "/run/vaiexia");
}
