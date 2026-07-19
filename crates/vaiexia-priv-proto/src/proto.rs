use serde::{Deserialize, Serialize};
use crate::package_name::PackageName;

pub const PROTO_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum PrivRequest {
    Ping,
    ProtoVersion,
    PkgInstall { name: PackageName },
    PkgRemove { name: PackageName },
    PkgRefreshIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PrivResponse {
    Pong,
    ProtoVersion { version: u32 },
    Ok,
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let req = PrivRequest::Ping;
        let s = serde_json::to_string(&req).unwrap();
        let back: PrivRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn pong_roundtrip() {
        let resp = PrivResponse::Pong;
        let s = serde_json::to_string(&resp).unwrap();
        let back: PrivResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn proto_version_roundtrip() {
        let req = PrivRequest::ProtoVersion;
        let s = serde_json::to_string(&req).unwrap();
        let back: PrivRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn proto_version_resp_roundtrip() {
        let resp = PrivResponse::ProtoVersion { version: PROTO_VERSION };
        let s = serde_json::to_string(&resp).unwrap();
        let back: PrivResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn pkg_install_roundtrip() {
        let req = PrivRequest::PkgInstall { name: PackageName::parse("nginx").unwrap() };
        let s = serde_json::to_string(&req).unwrap();
        let back: PrivRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn pkg_remove_roundtrip() {
        let req = PrivRequest::PkgRemove { name: PackageName::parse("openssl").unwrap() };
        let s = serde_json::to_string(&req).unwrap();
        let back: PrivRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn pkg_refresh_index_roundtrip() {
        let req = PrivRequest::PkgRefreshIndex;
        let s = serde_json::to_string(&req).unwrap();
        let back: PrivRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn ok_resp_roundtrip() {
        let resp = PrivResponse::Ok;
        let s = serde_json::to_string(&resp).unwrap();
        let back: PrivResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn error_resp_roundtrip() {
        let resp = PrivResponse::Error { message: "something failed".into() };
        let s = serde_json::to_string(&resp).unwrap();
        let back: PrivResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }
}
