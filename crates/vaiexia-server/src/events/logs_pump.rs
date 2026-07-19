use std::sync::Arc;

use tokio::sync::broadcast;
use vaiexia_core::protocol::Event;

use crate::api::dto::LogEntryDto;
use crate::backend::LogProvider;
use crate::events::{SeqCounter, topics};

pub async fn run(
    sender: broadcast::Sender<Event>,
    provider: Arc<dyn LogProvider>,
    seq: SeqCounter,
) {
    let mut rx = provider.follow();
    loop {
        match rx.recv().await {
            Ok(entry) => {
                let dto = LogEntryDto::from(entry);
                let payload = serde_json::to_value(&dto).unwrap();
                let ev = Event {
                    topic: topics::logs(),
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

    use crate::backend::{mock::MockBackend, LogEntry, SystemBackend};
    use crate::events::{SeqCounter, topics};

    #[tokio::test]
    async fn logs_pump_emits_event_when_log_pushed() {
        let mock = Arc::new(MockBackend::new());
        let be = Arc::new(SystemBackend::from_mock(Arc::clone(&mock)));
        let (tx, mut rx) = broadcast::channel::<Event>(16);
        let seq = SeqCounter::new();

        let log_provider = be.logs.as_ref().unwrap().clone();
        tokio::spawn(run(tx, log_provider, seq));

        // Wait for the pump task to subscribe
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Push a log entry
        mock.push_log(LogEntry {
            cursor: "test-cursor".into(),
            ts_us: 1,
            unit: None,
            priority: 6,
            message: "hello pump".into(),
        });

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within 2s")
            .expect("no lagged");

        assert_eq!(ev.topic, topics::logs());
        assert_eq!(ev.payload["message"], "hello pump");
    }
}
