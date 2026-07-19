pub use vaiexia_core::auth::Scope;
use vaiexia_core::protocol::{Method, Topic};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    Anonymous,
    Authenticated,
    Scope(Scope),
}

pub fn method_requirement(m: &Method) -> Option<Requirement> {
    let s = |name: &str| Requirement::Scope(Scope::new(name));
    Some(match m.as_str() {
        "server.host.info"
        | "server.services.list"
        | "server.services.status"
        | "server.packages.list"
        | "server.jobs.status" => s("server.read"),
        "server.services.start" | "server.services.stop" | "server.services.restart" => {
            s("server.services.write")
        }
        "server.packages.install" | "server.packages.remove" => s("server.packages.write"),
        "server.logs.query" => s("server.logs.read"),
        "auth.login" | "auth.bootstrap.claim" => Requirement::Anonymous,
        "auth.whoami" => Requirement::Authenticated,
        "auth.token.create" | "auth.token.list" | "auth.token.revoke" => s("auth.admin"),
        _ => return None,
    })
}

pub fn topic_scope(t: &Topic) -> Option<Scope> {
    Some(match t.as_str() {
        "server.metrics" | "server.services.status" | "server.jobs" => Scope::new("server.read"),
        "server.logs" => Scope::new("server.logs.read"),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_host_info_requires_server_read() {
        let m = Method::new("server.host.info").unwrap();
        assert_eq!(
            method_requirement(&m),
            Some(Requirement::Scope(Scope::new("server.read")))
        );
    }

    #[test]
    fn server_services_start_requires_services_write() {
        let m = Method::new("server.services.start").unwrap();
        assert_eq!(
            method_requirement(&m),
            Some(Requirement::Scope(Scope::new("server.services.write")))
        );
    }

    #[test]
    fn server_logs_query_requires_logs_read() {
        let m = Method::new("server.logs.query").unwrap();
        assert_eq!(
            method_requirement(&m),
            Some(Requirement::Scope(Scope::new("server.logs.read")))
        );
    }

    #[test]
    fn auth_login_is_anonymous() {
        let m = Method::new("auth.login").unwrap();
        assert_eq!(method_requirement(&m), Some(Requirement::Anonymous));
    }

    #[test]
    fn auth_bootstrap_claim_is_anonymous() {
        let m = Method::new("auth.bootstrap.claim").unwrap();
        assert_eq!(method_requirement(&m), Some(Requirement::Anonymous));
    }

    #[test]
    fn auth_whoami_is_authenticated() {
        let m = Method::new("auth.whoami").unwrap();
        assert_eq!(method_requirement(&m), Some(Requirement::Authenticated));
    }

    #[test]
    fn auth_token_create_requires_auth_admin() {
        let m = Method::new("auth.token.create").unwrap();
        assert_eq!(
            method_requirement(&m),
            Some(Requirement::Scope(Scope::new("auth.admin")))
        );
    }

    #[test]
    fn unknown_method_returns_none() {
        let m = Method::new("vpn.peers.list").unwrap();
        assert_eq!(method_requirement(&m), None);
    }

    #[test]
    fn all_method_variants_covered() {
        let methods = [
            "server.host.info",
            "server.services.list",
            "server.services.status",
            "server.packages.list",
            "server.jobs.status",
            "server.services.start",
            "server.services.stop",
            "server.services.restart",
            "server.packages.install",
            "server.packages.remove",
            "server.logs.query",
            "auth.login",
            "auth.bootstrap.claim",
            "auth.whoami",
            "auth.token.create",
            "auth.token.list",
            "auth.token.revoke",
        ];
        for name in &methods {
            let m = Method::new(*name).unwrap();
            assert!(
                method_requirement(&m).is_some(),
                "method {name} must have a requirement"
            );
        }
    }

    #[test]
    fn server_logs_topic_requires_logs_read() {
        let t = Topic::new("server.logs");
        assert_eq!(topic_scope(&t), Some(Scope::new("server.logs.read")));
    }

    #[test]
    fn server_metrics_topic_requires_server_read() {
        let t = Topic::new("server.metrics");
        assert_eq!(topic_scope(&t), Some(Scope::new("server.read")));
    }

    #[test]
    fn server_services_status_topic_requires_server_read() {
        let t = Topic::new("server.services.status");
        assert_eq!(topic_scope(&t), Some(Scope::new("server.read")));
    }

    #[test]
    fn server_jobs_topic_requires_server_read() {
        let t = Topic::new("server.jobs");
        assert_eq!(topic_scope(&t), Some(Scope::new("server.read")));
    }

    #[test]
    fn unknown_topic_returns_none() {
        let t = Topic::new("vpn.peers");
        assert_eq!(topic_scope(&t), None);
    }
}
