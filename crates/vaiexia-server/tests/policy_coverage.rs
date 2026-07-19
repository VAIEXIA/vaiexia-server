/// Policy coverage test: verifies that every registered method and topic
/// has a corresponding policy entry in auth::policy.
///
/// This test is a static compile-time + runtime guard that prevents shipping
/// a method without a Requirement or a topic without a Scope.
use vaiexia_server::auth::policy::{method_requirement, topic_scope};
use vaiexia_core::protocol::{Method, Topic};

/// All RPC methods that MUST have a policy Requirement.
const ALL_METHODS: &[&str] = &[
    // server read surface
    "server.host.info",
    "server.services.list",
    "server.services.status",
    "server.packages.list",
    "server.jobs.status",
    // server mutations
    "server.services.start",
    "server.services.stop",
    "server.services.restart",
    "server.packages.install",
    "server.packages.remove",
    // logs
    "server.logs.query",
    // auth — anonymous
    "auth.login",
    "auth.bootstrap.claim",
    // auth — authenticated
    "auth.whoami",
    // auth — admin-scoped
    "auth.token.create",
    "auth.token.list",
    "auth.token.revoke",
];

/// All subscribe topics that MUST have a scope entry.
const ALL_TOPICS: &[&str] = &[
    "server.metrics",
    "server.services.status",
    "server.jobs",
    "server.logs",
];

#[test]
fn every_method_has_a_requirement() {
    for name in ALL_METHODS {
        let m = Method::new(*name).unwrap_or_else(|_| panic!("invalid method name: {name}"));
        let req = method_requirement(&m);
        assert!(
            req.is_some(),
            "method '{name}' has no policy Requirement — add it to policy.rs"
        );
    }
}

#[test]
fn every_topic_has_a_scope() {
    for name in ALL_TOPICS {
        let t = Topic::new(*name);
        let scope = topic_scope(&t);
        assert!(
            scope.is_some(),
            "topic '{name}' has no scope entry — add it to policy.rs"
        );
    }
}

#[test]
fn no_duplicate_methods_in_list() {
    let mut seen = std::collections::HashSet::new();
    for name in ALL_METHODS {
        assert!(
            seen.insert(*name),
            "method '{name}' appears twice in ALL_METHODS"
        );
    }
}

#[test]
fn no_duplicate_topics_in_list() {
    let mut seen = std::collections::HashSet::new();
    for name in ALL_TOPICS {
        assert!(
            seen.insert(*name),
            "topic '{name}' appears twice in ALL_TOPICS"
        );
    }
}
