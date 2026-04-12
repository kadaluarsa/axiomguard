use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassAlert {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub reason: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

const MAX_ALERTS: usize = 1000;

#[derive(Debug)]
pub struct BypassDetector {
    alerts: RwLock<VecDeque<BypassAlert>>,
}

impl BypassDetector {
    pub fn new() -> Self {
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(MAX_ALERTS)),
        }
    }

    pub fn record(&self, alert: BypassAlert) {
        tracing::warn!(
            tenant_id = %alert.tenant_id,
            agent_id = %alert.agent_id,
            tool = %alert.tool_name,
            reason = %alert.reason,
            "Bypass attempt detected"
        );
        let mut alerts = self.alerts.write().unwrap();
        if alerts.len() >= MAX_ALERTS {
            alerts.pop_front();
        }
        alerts.push_back(alert);
    }

    pub fn list_alerts(&self) -> Vec<BypassAlert> {
        self.alerts.read().unwrap().iter().cloned().collect()
    }

    pub fn list_alerts_by_tenant(&self, tenant_id: &str) -> Vec<BypassAlert> {
        self.alerts
            .read()
            .unwrap()
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.read().unwrap().len()
    }
}
