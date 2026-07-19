use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::protocol::Method;

/// TEMPORARY Step-0 verifier: authenticates everyone as an anonymous subject with
/// read scope so the skeleton can serve `server.host.info`. Replaced by DaemonVerifier
/// (capability tokens + scopes + verify_topic override) in Step 2. DO NOT SHIP.
pub struct SkeletonVerifier;

impl Verifier for SkeletonVerifier {
    fn verify(
        &self,
        _cap: Option<&Capability>,
        _method: &Method,
    ) -> vaiexia_core::error::Result<Subject> {
        // Grant all known scopes so register_scoped's scope guard never blocks
        // during permissive (test-only) use.
        Ok(Subject {
            id: SubjectId::new("anonymous"),
            scopes: ScopeSet::from_iter([
                "server.read",
                "server.logs.read",
                "server.services.write",
                "server.packages.write",
                "auth.admin",
            ]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaiexia_core::auth::Scope;

    #[test]
    fn skeleton_verifier_returns_subject_with_server_read() {
        let v = SkeletonVerifier;
        let method = Method::new("server.host.info").unwrap();
        let subject = v.verify(None, &method).unwrap();
        assert!(subject.scopes.contains(&Scope::new("server.read")));
    }
}
