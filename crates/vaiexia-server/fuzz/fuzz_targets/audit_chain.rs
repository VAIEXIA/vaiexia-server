#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // verify_chain_str walks a JSONL body an attacker with file access may have
    // mangled — it must return Err, never panic. UTF-8 gate the bytes first
    // (the function takes &str; non-UTF-8 is a separate, structurally different
    // surface that the individual parser targets cover).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = vaiexia_server::audit::verify_chain_str(s);
    }
});
