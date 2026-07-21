#![no_main]
use libfuzzer_sys::fuzz_target;
use vaiexia_server::backend::packages::detect::PackageKind;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Exercise parse_list across all package manager kinds.
        for kind in [PackageKind::Apt, PackageKind::Dnf, PackageKind::Pacman, PackageKind::Apk] {
            let _ = vaiexia_server::backend::packages::query::parse_list(kind, s);
        }
    }
});
