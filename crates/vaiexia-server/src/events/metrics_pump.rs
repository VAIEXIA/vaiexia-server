use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use vaiexia_core::protocol::Event;

use crate::api::dto::MetricsDto;
use crate::backend::MetricsProvider;
use crate::events::{SeqCounter, topics};

pub async fn run(
    sender: broadcast::Sender<Event>,
    provider: Arc<dyn MetricsProvider>,
    seq: SeqCounter,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let Ok(snap) = provider.snapshot() else { continue };
        let dto = MetricsDto::from(snap);
        let payload = serde_json::to_value(&dto).unwrap();
        let ev = Event {
            topic: topics::metrics(),
            seq: seq.next(),
            payload,
        };
        // Ignore send errors (no subscribers)
        let _ = sender.send(ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::Duration;
    use vaiexia_core::protocol::Event;

    use crate::backend::{mock::MockBackend, SystemBackend};
    use crate::events::{SeqCounter, topics};

    #[tokio::test]
    async fn metrics_pump_emits_event_with_correct_topic() {
        let mock = Arc::new(MockBackend::new());
        let be = Arc::new(SystemBackend::from_mock(mock));
        let (tx, mut rx) = broadcast::channel::<Event>(16);
        let seq = SeqCounter::new();

        tokio::spawn(run(tx, Arc::clone(&be.metrics), seq, Duration::from_millis(10)));

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within 2s")
            .expect("no lagged");

        assert_eq!(ev.topic, topics::metrics());

        let dto: crate::api::dto::MetricsDto = serde_json::from_value(ev.payload)
            .expect("payload should deserialize to MetricsDto");
        assert!(dto.mem_total > 0);
    }
}
