//! Deterministic adversarial corpus over every attacker-facing parser.
//! Complements (does not replace) the cargo-fuzz targets: this runs on every
//! `cargo test` on every platform; libFuzzer explores further on nightly CI.
//!
//! CI fuzz commands (nightly toolchain required):
//!   cargo install cargo-fuzz
//!   cargo +nightly fuzz run package_name  -- -runs=200000
//!   cargo +nightly fuzz run unit_name     -- -runs=200000
//!   cargo +nightly fuzz run journal_line  -- -runs=200000
//!   cargo +nightly fuzz run priv_request  -- -runs=200000
//!   cargo +nightly fuzz run token_parse   -- -runs=200000
//!   cargo +nightly fuzz run pkg_list      -- -runs=200000
//!   cargo +nightly fuzz run audit_chain   -- -runs=200000
use vaiexia_core::auth::Capability;
use vaiexia_server::backend::packages::detect::PackageKind;

fn corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\0".to_vec(),
        b"\xff\xfe\xfd".to_vec(),                        // invalid UTF-8
        b"-rf".to_vec(),
        b"--config=/etc/shadow".to_vec(),
        b"a; rm -rf /".to_vec(),
        b"..\\..\\windows".to_vec(),
        b"../../../etc/passwd".to_vec(),
        "vxs1..".as_bytes().to_vec(),
        "vxs1.k.".as_bytes().to_vec(),
        "vxs1.\u{202e}gnp.exe.AAAA".as_bytes().to_vec(), // RTL override
        vec![b'A'; 1 << 20],                              // 1 MiB blob
        format!("vxs1.{}.{}", "k".repeat(100_000), "s".repeat(100_000)).into_bytes(),
        b"{\"verb\":\"pkg_install\",\"name\":\"-rf\"}".to_vec(),
        b"{\"verb\":\"pkg_install\",\"name\":123}".to_vec(),
        [b"[".repeat(10_000), b"]".repeat(10_000)].concat(), // deep nesting → serde_json recursion limit, not stack overflow
        b"{\"__CURSOR\":123,\"MESSAGE\":[[[[]]]]}".to_vec(),
        b"{\"MESSAGE\":[256,-1,99999999999999999999]}".to_vec(),
        // audit-chain near-misses: valid-ish JSONL with broken seq/prev/schema
        b"{\"schema_version\":1,\"seq\":1,\"prev\":\"0000000000000000\",\"kind\":\"mutation\",\"severity\":\"notice\",\"decision\":\"ok\",\"subject\":\"x\"}\n{\"schema_version\":1,\"seq\":9,\"prev\":\"ffff\"}".to_vec(),
        b"{\"schema_version\":99,\"seq\":1,\"prev\":\"0000000000000000\"}".to_vec(),
        // u64::MAX seq — the checked_add in verify_chain_str must not overflow-panic
        b"{\"seq\":18446744073709551615,\"prev\":\"0000000000000000\",\"schema_version\":1,\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}".to_vec(),
    ];
    // A few structured near-misses.
    c.push(serde_json::json!({"MESSAGE": "x".repeat(100_000)}).to_string().into_bytes());
    c
}

#[test]
fn no_parser_panics_on_adversarial_corpus() {
    for input in corpus() {
        let _ = serde_json::from_slice::<vaiexia_priv_proto::PrivRequest>(&input);
        let _ = vaiexia_server::backend::logs::journald::parse_journal_line(&input);
        if let Ok(s) = std::str::from_utf8(&input) {
            let _ = vaiexia_priv_proto::PackageName::parse(s);
            let _ = vaiexia_server::backend::UnitName::parse(s);
            let _ = vaiexia_server::auth::token::parse(&Capability::new(s.to_owned()));
            let _ = vaiexia_server::backend::logs::cursor::is_valid(s);
            let _ = vaiexia_server::audit::verify_chain_str(s); // Err, never panic
            // pkg_list: query is pub; PackageKind is accessible via detect module.
            for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
                let _ = vaiexia_server::backend::packages::query::parse_list(kind, s);
            }
        }
    }
}

#[test]
fn priv_request_never_yields_invalid_package_name() {
    // The security property the custom Deserialize exists for.
    for input in corpus() {
        if let Ok(vaiexia_priv_proto::PrivRequest::PkgInstall { name })
        | Ok(vaiexia_priv_proto::PrivRequest::PkgRemove { name }) =
            serde_json::from_slice::<vaiexia_priv_proto::PrivRequest>(&input)
        {
            assert!(vaiexia_priv_proto::PackageName::parse(name.as_str()).is_ok());
        }
    }
}

#[test]
fn verify_chain_str_never_panics_on_mangled_input() {
    // Specific audit-chain adversarial inputs beyond the general corpus.
    let cases: &[&[u8]] = &[
        b"",
        b"not json\n",
        // Missing schema_version
        b"{\"seq\":1,\"prev\":\"0000000000000000\"}\n",
        // schema_version wrong type
        b"{\"schema_version\":\"1\",\"seq\":1,\"prev\":\"0000000000000000\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n",
        // seq = u64::MAX: checked_add must yield Err(SeqGap or BadSchema), not panic
        b"{\"schema_version\":1,\"seq\":18446744073709551615,\"prev\":\"0000000000000000\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n\
{\"schema_version\":1,\"seq\":0,\"prev\":\"aaaa\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n",
        // broken prev chain
        b"{\"schema_version\":1,\"seq\":1,\"prev\":\"0000000000000000\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n\
{\"schema_version\":1,\"seq\":2,\"prev\":\"BADBADBADBAD0000\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n",
        // seq gap
        b"{\"schema_version\":1,\"seq\":1,\"prev\":\"0000000000000000\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n\
{\"schema_version\":1,\"seq\":9,\"prev\":\"aaaa\",\"kind\":\"x\",\"severity\":\"x\",\"decision\":\"x\",\"subject\":\"x\"}\n",
        // control chars and injection attempt
        b"FAKE_LINE\nINJECTED=1\n",
        // deeply nested JSON
        b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
    ];
    for case in cases {
        if let Ok(s) = std::str::from_utf8(case) {
            // Must return Result, never panic.
            let _ = vaiexia_server::audit::verify_chain_str(s);
        }
    }
}
