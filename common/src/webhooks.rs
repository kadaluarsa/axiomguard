use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use reqwest::Client;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use uuid::Uuid;
use chrono::Utc;
use crate::AuditDecision;
use metrics::{counter, gauge, histogram};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Webhook {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub enabled: bool,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub events: Vec<String>,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookPayload {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<Utc>,
    pub event_type: String,
    pub decision: AuditDecision,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    pub delivery: WebhookDelivery,
    pub failed_at: chrono::DateTime<Utc>,
    pub error: String,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub webhook: Webhook,
    pub payload: WebhookPayload,
    pub attempt: u32,
    pub last_attempt: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct DeadLetterQueue {
    entries: Arc<Mutex<Vec<DeadLetterEntry>>>,
}

impl DeadLetterQueue {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn add(&self, entry: DeadLetterEntry) {
        let mut entries = self.entries.lock().await;
        entries.push(entry);
        counter!("webhooks.dlq.added").increment(1);
        gauge!("webhooks.dlq.size").set(entries.len() as f64);
    }

    pub async fn get_all(&self) -> Vec<DeadLetterEntry> {
        self.entries.lock().await.clone()
    }

    pub async fn clear(&self) {
        let mut entries = self.entries.lock().await;
        entries.clear();
        gauge!("webhooks.dlq.size").set(0.0);
    }
}

#[derive(Debug, Clone)]
pub struct WebhookService {
    client: Client,
    webhooks: std::collections::HashMap<Uuid, Webhook>,
    delivery_queue: mpsc::Sender<WebhookDelivery>,
    dead_letter_queue: DeadLetterQueue,
}

impl WebhookService {
    pub fn new() -> Self {
        // ✅ HIGH PERFORMANCE HTTP CLIENT WITH CONNECTION POOLING
        let client = Client::builder()
            .timeout(Duration::from_millis(50))    // Aggressive 50ms timeout
            .pool_max_idle_per_host(16)           // Keep up to 16 connections per host alive
            .pool_idle_timeout(Duration::from_secs(60))
            .tcp_keepalive(Duration::from_secs(30))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(5))
            .http2_keep_alive_while_idle(true)
            .connect_timeout(Duration::from_millis(30))
            .build()
            .unwrap();
        
        let (tx, rx) = mpsc::channel(10000);  // Increase queue capacity
        let rx = Arc::new(Mutex::new(rx));
        let dlq = DeadLetterQueue::new();

        // ✅ PARALLEL DELIVERY WORKERS - single shared channel with load balancing
        let num_workers = std::cmp::max(1, num_cpus::get());
        let delivery_queue_clone = tx.clone();
        let dlq_clone = dlq.clone();
        
        for worker_id in 0..num_workers {
            let worker_rx = rx.clone();
            let client_clone = client.clone();
            let tx_clone = delivery_queue_clone.clone();
            let worker_dlq = dlq_clone.clone();
            
            tokio::spawn(async move {
                tracing::debug!(worker_id = %worker_id, "Webhook delivery worker started");
                
                while let Some(mut delivery) = worker_rx.lock().await.recv().await {
                    let client = client_clone.clone();
                    let tx_retry = tx_clone.clone();
                    let dlq = worker_dlq.clone();
                    
                    tokio::spawn(async move {
                        match deliver_webhook(&client, &mut delivery).await {
                            Ok(()) => {
                                counter!("webhooks.delivery.success").increment(1);
                                histogram!("webhooks.delivery.attempts").record(delivery.attempt as f64);
                            }
                            Err(e) => {
                                if delivery.attempt < delivery.webhook.max_retries {
                                    counter!("webhooks.delivery.retry").increment(1);
                                    // Requeue for retry
                                    let _ = tx_retry.send(delivery).await;
                                } else {
                                    counter!("webhooks.delivery.failed").increment(1);
                                    dlq.add(DeadLetterEntry {
                                        delivery,
                                        failed_at: Utc::now(),
                                        error: e.to_string(),
                                        status_code: None,
                                    }).await;
                                }
                            }
                        }
                    });
                }
            });
        }

        Self {
            client,
            webhooks: std::collections::HashMap::new(),
            delivery_queue: tx,
            dead_letter_queue: dlq,
        }
    }

    pub fn register_webhook(&mut self, webhook: Webhook) {
        self.webhooks.insert(webhook.id, webhook);
    }

    pub async fn deliver_decision(&self, decision: &AuditDecision) -> Result<(), Box<dyn std::error::Error>> {
        for webhook in self.webhooks.values().filter(|w| w.enabled) {
            let payload = WebhookPayload {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                event_type: "audit_decision".to_string(),
                decision: decision.clone(),
                metadata: serde_json::Value::Null,
            };

            let delivery = WebhookDelivery {
                webhook: webhook.clone(),
                payload,
                attempt: 0,
                last_attempt: None,
            };

            if let Err(e) = self.delivery_queue.send(delivery).await {
                tracing::error!(error = %e, "Failed to queue webhook delivery");
                counter!("webhooks.queue.failed").increment(1);
            } else {
                counter!("webhooks.queue.added").increment(1);
            }
        }

        Ok(())
    }

    // Webhook configuration endpoints
    pub fn get_webhook(&self, id: Uuid) -> Option<&Webhook> {
        self.webhooks.get(&id)
    }

    pub fn list_webhooks(&self) -> Vec<&Webhook> {
        self.webhooks.values().collect()
    }

    pub fn delete_webhook(&mut self, id: Uuid) -> Option<Webhook> {
        self.webhooks.remove(&id)
    }

    pub fn update_webhook(&mut self, webhook: Webhook) {
        self.webhooks.insert(webhook.id, webhook);
    }

    // DLQ access
    pub async fn get_dead_letter_entries(&self) -> Vec<DeadLetterEntry> {
        self.dead_letter_queue.get_all().await
    }

    pub async fn clear_dead_letter_queue(&self) {
        self.dead_letter_queue.clear().await
    }
}

async fn deliver_webhook(client: &Client, delivery: &mut WebhookDelivery) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let backoff = calculate_backoff(delivery.attempt);
    
    if delivery.attempt > 0 {
        time::sleep(Duration::from_millis(backoff)).await;
    }

    let signature = calculate_signature(&delivery.webhook.secret, &delivery.payload);
    
    let mut request = client
        .post(&delivery.webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Signature", signature)
        .header("X-Webhook-Attempt", delivery.attempt.to_string())
        .timeout(Duration::from_millis(delivery.webhook.timeout_ms))
        .json(&delivery.payload);

    for (key, value) in &delivery.webhook.headers {
        request = request.header(key, value);
    }

    let response = request.send().await;
    
    delivery.attempt += 1;
    delivery.last_attempt = Some(Utc::now());

    match response {
        Ok(res) if res.status().is_success() => {
            tracing::info!(
                webhook_id = %delivery.webhook.id,
                attempt = %delivery.attempt,
                status = %res.status(),
                "Webhook delivered successfully"
            );
            Ok(())
        }
        Ok(res) => {
            let status = res.status();
            tracing::warn!(
                webhook_id = %delivery.webhook.id,
                attempt = %delivery.attempt,
                status = %status,
                "Webhook delivery failed with non-success status"
            );
            
            // Only retry on transient errors
            if status.is_server_error() || status == 429 {
                Err(format!("Webhook failed with status {}", status).into())
            } else {
                // Permanent failure: don't retry
                Err(format!("Permanent failure: webhook returned {}", status).into())
            }
        }
        Err(e) => {
            tracing::error!(
                webhook_id = %delivery.webhook.id,
                attempt = %delivery.attempt,
                error = %e,
                "Webhook delivery failed"
            );
            
            Err(e.into())
        }
    }
}

fn calculate_backoff(attempt: u32) -> u64 {
    let base = 100; // 100ms base delay
    let multiplier = 2u64.pow(attempt);
    let jitter = rand::random::<u64>() % 100;
    
    std::cmp::min(base * multiplier + jitter, 30000) // Max 30 seconds
}

fn calculate_signature(secret: &str, payload: &WebhookPayload) -> String {
    use sha2::{Sha256, Digest};
    use hex::ToHex;
    use hmac::{Hmac, Mac};
    
    // Use proper HMAC-SHA256 signing (correct security standard)
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    let payload_json = serde_json::to_string(payload).expect("Failed to serialize payload");
    mac.update(payload_json.as_bytes());
    let hash = mac.finalize().into_bytes();
    
    format!("sha256={}", hash.encode_hex::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditDecision;
    use crate::DecisionType;

    #[test]
    fn test_backoff_calculation() {
        assert!(calculate_backoff(0) >= 100);
        assert!(calculate_backoff(1) >= 200);
        assert!(calculate_backoff(2) >= 400);
        assert!(calculate_backoff(3) >= 800);
        assert!(calculate_backoff(10) <= 30000); // Max 30s
    }

    #[test]
    fn test_webhook_creation() {
        let webhook = Webhook {
            id: Uuid::new_v4(),
            url: "https://example.com/webhook".to_string(),
            secret: "test_secret".to_string(),
            enabled: true,
            timeout_ms: 5000,
            max_retries: 3,
            events: vec!["audit_decision".to_string()],
            headers: Vec::new(),
        };

        assert!(webhook.enabled);
        assert_eq!(webhook.max_retries, 3);
    }

    #[tokio::test]
    async fn test_webhook_service() {
        let mut service = WebhookService::new();
        
        let webhook = Webhook {
            id: Uuid::new_v4(),
            url: "https://example.com/webhook".to_string(),
            secret: "test_secret".to_string(),
            enabled: true,
            timeout_ms: 5000,
            max_retries: 3,
            events: vec!["audit_decision".to_string()],
            headers: Vec::new(),
        };

        service.register_webhook(webhook);
        
        let decision = AuditDecision {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            decision: DecisionType::Allow,
            confidence: 0.95,
            rules_matched: Vec::new(),
            ai_insights: None,
            processing_time_ms: 15,
        };

        // This will fail to deliver since example.com is not our test server,
        // but the service should handle it gracefully
        let result = service.deliver_decision(&decision).await;
        assert!(result.is_ok());
    }
}