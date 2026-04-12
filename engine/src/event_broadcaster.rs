use common::{AuditDecision, AuditEvent, AuditMetrics};
use tokio::sync::broadcast;

#[derive(Debug)]
pub struct EventBroadcaster {
    event_sender: broadcast::Sender<BroadcastEvent>,
}

#[derive(Debug, Clone)]
pub enum BroadcastEvent {
    Event(AuditEvent),
    Decision(AuditDecision),
    Metrics(AuditMetrics),
}

impl EventBroadcaster {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        EventBroadcaster {
            event_sender: sender,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BroadcastEvent> {
        self.event_sender.subscribe()
    }

    pub fn broadcast_event(&self, event: AuditEvent) {
        let _ = self.event_sender.send(BroadcastEvent::Event(event));
    }

    pub fn broadcast_decision(&self, decision: AuditDecision) {
        let _ = self.event_sender.send(BroadcastEvent::Decision(decision));
    }

    pub fn broadcast_metrics(&self, metrics: AuditMetrics) {
        let _ = self.event_sender.send(BroadcastEvent::Metrics(metrics));
    }
}

impl Default for EventBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}
