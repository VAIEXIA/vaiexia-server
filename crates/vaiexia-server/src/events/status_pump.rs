use std::sync::Arc;

use tokio::sync::broadcast;
use vaiexia_core::protocol::Event;

use crate::api::dto::UnitDto;
use crate::backend::ServiceManager;
use crate::events::{SeqCounter, topics};

pub async fn run(
    sender: broadcast::Sender<Event>,
    mgr: Arc<dyn ServiceManager>,
) {
    let seq = SeqCounter::new();
    let mut rx = mgr.watch();
    loop {
        match rx.recv().await {
            Ok(unit_status) => {
                let dto = UnitDto::from(unit_status);
                let payload = serde_json::to_value(&dto).unwrap();
                let ev = Event {
                    topic: topics::services_status(),
                    seq: seq.next(),
                    payload,
                };
                let _ = sender.send(ev);
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                // Skip lagged events — resume
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Channel closed — pump exits (supervised will restart)
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

    use crate::backend::{mock::MockBackend, SystemBackend, ServiceManager};
    use crate::events::topics;

    #[tokio::test]
    async fn status_pump_emits_event_when_service_changes() {
        let mock = Arc::new(MockBackend::new());
        let be = Arc::new(SystemBackend::from_mock(Arc::clone(&mock)));
        let (tx, mut rx) = broadcast::channel::<Event>(16);

        // Subscribe BEFORE spawning to avoid race — use mock's watch directly
        let mut unit_rx = mock.watch();
        let mgr = be.services.as_ref().unwrap().clone();
        tokio::spawn(run(tx, mgr));

        // Let the pump task start and subscribe internally
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Trigger a state change
        mock.start("nginx.service").await.unwrap();

        // Verify the raw watch receives the event
        let _ = tokio::time::timeout(Duration::from_secs(2), unit_rx.recv())
            .await
            .expect("unit_rx should receive")
            .expect("no lagged");

        // Now check the event channel
        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within 2s")
            .expect("no lagged");

        assert_eq!(ev.topic, topics::services_status());
        // Payload should have name field
        assert!(ev.payload["name"].is_string());
    }
}
