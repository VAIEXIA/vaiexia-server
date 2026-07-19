use vaiexia_core::protocol::Topic;

pub fn metrics() -> Topic {
    Topic::new("server.metrics")
}

pub fn services_status() -> Topic {
    Topic::new("server.services.status")
}

pub fn jobs() -> Topic {
    Topic::new("server.jobs")
}

pub fn logs() -> Topic {
    Topic::new("server.logs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_topic_serializes_correctly() {
        let t = metrics();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#""server.metrics""#);
    }

    #[test]
    fn services_status_topic_serializes_correctly() {
        let t = services_status();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#""server.services.status""#);
    }

    #[test]
    fn jobs_topic_serializes_correctly() {
        let t = jobs();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#""server.jobs""#);
    }

    #[test]
    fn logs_topic_serializes_correctly() {
        let t = logs();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#""server.logs""#);
    }
}
