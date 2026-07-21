#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The privd frame payload boundary: must never panic; a PkgInstall that
    // deserializes implies a PackageName that satisfies parse() invariants.
    if let Ok(req) = serde_json::from_slice::<vaiexia_priv_proto::PrivRequest>(data) {
        if let vaiexia_priv_proto::PrivRequest::PkgInstall { name }
        | vaiexia_priv_proto::PrivRequest::PkgRemove { name } = req
        {
            assert!(vaiexia_priv_proto::PackageName::parse(name.as_str()).is_ok());
        }
    }
});
