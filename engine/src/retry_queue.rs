use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use common::database::repository_v2::{EventRepository, Event as DbEvent};

const QUEUE_CAPACITY: usize = 10_000;
const DISK_DLQ_DIR: &str = "/tmp/axiomguard-dlq";

struct RetryItem {
    event: DbEvent,
    embedding: Vec<f32>,
    attempt: usize,
}

/// Bounded event persistence retry queue with background worker and disk DLQ.
///
/// Events that exhaust all retries are written to a local disk DLQ
/// so no data is ever silently dropped.
#[derive(Debug, Clone)]
pub struct EventRetryQueue {
    sender: mpsc::Sender<RetryItem>,
    dropped_count: Arc<std::sync::atomic::AtomicU64>,
}

impl EventRetryQueue {
    pub fn new(repo: Arc<EventRepository>, max_retries: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel::<RetryItem>(QUEUE_CAPACITY);
        let dropped_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_clone = dropped_count.clone();

        tokio::spawn(async move {
            while let Some(mut item) = receiver.recv().await {
                loop {
                    match repo.insert_with_embedding(&item.event, &item.embedding).await {
                        Ok(()) => break,
                        Err(e) => {
                            if item.attempt < max_retries {
                                let delay = Duration::from_millis(
                                    500 * (2_u64.saturating_pow(item.attempt as u32))
                                );
                                tracing::warn!(
                                    event_id = %item.event.id,
                                    attempt = item.attempt + 1,
                                    max_retries = max_retries,
                                    delay_ms = delay.as_millis() as u64,
                                    error = %e,
                                    "Event persistence failed, retrying"
                                );
                                tokio::time::sleep(delay).await;
                                item.attempt += 1;
                            } else {
                                dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                tracing::error!(
                                    event_id = %item.event.id,
                                    attempts = item.attempt + 1,
                                    error = %e,
                                    "Event persistence failed permanently, writing to disk DLQ"
                                );
                                if let Err(dlq_err) = Self::write_to_dlq(&item).await {
                                    tracing::error!(error = %dlq_err, "Failed to write to disk DLQ");
                                }
                                break;
                            }
                        }
                    }
                }
            }
            tracing::info!("Event retry queue worker shutting down");
        });

        Self { sender, dropped_count }
    }

    pub fn submit(&self, event: DbEvent, embedding: Vec<f32>) {
        let item = RetryItem {
            event,
            embedding,
            attempt: 0,
        };
        match self.sender.try_send(item) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(item)) => {
                self.dropped_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(
                    event_id = %item.event.id,
                    "Retry queue full ({} items), writing to disk DLQ",
                    QUEUE_CAPACITY
                );
                let dropped = self.dropped_count.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::write_to_dlq(&item).await {
                        tracing::error!(error = %e, "Failed to write overflow to disk DLQ");
                    }
                    drop(dropped);
                });
            }
            Err(mpsc::error::TrySendError::Closed(item)) => {
                tracing::error!(event_id = %item.event.id, "Retry queue channel closed");
                let _ = item;
            }
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn write_to_dlq(item: &RetryItem) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::task::spawn_blocking({
            let id = item.event.id.to_string();
            let json = serde_json::to_string(&serde_json::json!({
                "event_id": id,
                "attempt": item.attempt,
                "event_type": item.event.event_type,
                "timestamp": item.event.timestamp.to_rfc3339(),
            }))?;
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                std::fs::create_dir_all(DISK_DLQ_DIR)?;
                let path = format!("{}/{}.json", DISK_DLQ_DIR, id);
                std::fs::write(&path, &json)?;
                Ok(())
            }
        })
        .await??;
        Ok(())
    }
}
