use vaiexia_priv_proto::{PrivRequest, PrivResponse, PROTO_VERSION};

pub fn handle(req: &PrivRequest) -> PrivResponse {
    match req {
        PrivRequest::Ping => PrivResponse::Pong,
        PrivRequest::ProtoVersion => PrivResponse::ProtoVersion { version: PROTO_VERSION },
        PrivRequest::PkgInstall { .. }
        | PrivRequest::PkgRemove { .. }
        | PrivRequest::PkgRefreshIndex => {
            PrivResponse::Error {
                message: "package operations not implemented in this build".into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_returns_pong() {
        assert_eq!(handle(&PrivRequest::Ping), PrivResponse::Pong);
    }

    #[test]
    fn proto_version_returns_current() {
        assert_eq!(
            handle(&PrivRequest::ProtoVersion),
            PrivResponse::ProtoVersion { version: PROTO_VERSION }
        );
    }

    #[test]
    fn pkg_refresh_index_returns_error() {
        assert!(matches!(
            handle(&PrivRequest::PkgRefreshIndex),
            PrivResponse::Error { .. }
        ));
    }
}
