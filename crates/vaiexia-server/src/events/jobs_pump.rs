use std::sync::Arc;

use tokio::sync::broadcast;
use vaiexia_core::protocol::Event;

use crate::api::jobs::{JobRegistry, JobStatus};
use crate::events::{SeqCounter, topics};

pub async fn run(
    sender: broadcast::Sender<Event>,
    registry: Arc<JobRegistry>,
    seq: SeqCounter,
) {
    let mut rx = registry.subscribe();
    loop {
        match rx.recv().await {
            Ok(status) => {
                let payload = serde_json::to_value(&status).unwrap();
                let ev = Event {
                    topic: topics::jobs(),
                    seq: seq.next(),
                    payload,
                };
                let _ = sender.send(ev);
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::broadcast;
    use tokio::time::Duration;
    use vaiexia_core::protocol::Event;

    use crate::api::jobs::JobRegistry;
    use crate::events::{SeqCounter, topics};

    #[tokio::test]
    async fn jobs_pump_emits_event_when_job_starts() {
        let registry = Arc::new(JobRegistry::new());
        let (tx, mut rx) = broadcast::channel::<Event>(16);
        let seq = SeqCounter::new();

        tokio::spawn(run(tx, Arc::clone(&registry), seq));

        // Start a job
        registry.try_start("install", async { Ok(()) }).unwrap();

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within 2s")
            .expect("no lagged");

        assert_eq!(ev.topic, topics::jobs());
        assert!(ev.payload["id"].is_string());
    }
}
