#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vaiexia_server::backend::logs::journald::parse_journal_line(data);
});
