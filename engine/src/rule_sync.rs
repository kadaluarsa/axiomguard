//! PostgreSQL LISTEN/NOTIFY integration for real-time rule synchronization
//!
//! This module enables hot reloading of security rules without restarting
//! the Shield service.

use common::database::Database;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use serde_json::Value;

/// Rule sync notification from PostgreSQL
#[derive(Debug, Clone)]
pub struct RuleSyncNotification {
    pub sync_type: SyncType,
    pub rule_ids: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub enum SyncType {
    FullSync,
    RuleAdded,
    RuleUpdated,
    RuleDeleted,
}

impl From<&str> for SyncType {
    fn from(op: &str) -> Self {
        match op {
            "INSERT" => SyncType::RuleAdded,
            "UPDATE" => SyncType::RuleUpdated,
            "DELETE" => SyncType::RuleDeleted,
            _ => SyncType::FullSync,
        }
    }
}

/// Rule synchronizer that listens for database changes
pub struct RuleSynchronizer {
    db: Database,
    tx: mpsc::Sender<RuleSyncNotification>,
}

impl RuleSynchronizer {
    /// Create a new rule synchronizer
    pub fn new(db: Database) -> (Self, mpsc::Receiver<RuleSyncNotification>) {
        let (tx, rx) = mpsc::channel(100);
        
        (Self { db, tx }, rx)
    }

    /// Start listening for rule changes using PostgreSQL LISTEN/NOTIFY
    pub async fn start_listening(self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting rule synchronization (LISTEN/NOTIFY mode)");
        
        tokio::spawn(async move {
            if let Err(e) = self.run_pg_listener().await {
                error!("PgListener error: {}", e);
            }
        });
        
        Ok(())
    }

    /// Run the PostgreSQL LISTEN/NOTIFY listener
    async fn run_pg_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
        let pool = self.db.pool();
        let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
        listener.listen("rules_updated").await?;
        info!("Connected to PostgreSQL LISTEN/NOTIFY channel: rules_updated");
        
        loop {
            match listener.recv().await {
                Ok(notification) => {
                    let payload = notification.payload();
                    info!(payload = %payload, "Received rule change notification");
                    
                    if let Err(e) = self.handle_notification(payload).await {
                        warn!("Failed to handle notification: {}", e);
                    }
                }
                Err(e) => {
                    error!("PgListener recv error: {}", e);
                    // Reconnect on error
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    listener = sqlx::postgres::PgListener::connect_with(pool).await?;
                    listener.listen("rules_updated").await?;
                }
            }
        }
    }

    /// Handle a notification payload
    async fn handle_notification(&self, payload: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Parse the JSON payload
        let data: Value = serde_json::from_str(payload)?;
        
        let op = data["type"].as_str().unwrap_or("");
        let sync_type = SyncType::from(op);
        
        let rule_id = data["id"].as_str()
            .or_else(|| data["rule_id"].as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();
        
        let notification = RuleSyncNotification {
            sync_type,
            rule_ids: rule_id,
            timestamp: chrono::Utc::now(),
        };
        
        info!(
            sync_type = ?notification.sync_type,
            rule_ids = ?notification.rule_ids,
            "Received rule change notification"
        );
        
        // Send notification to the channel
        if let Err(e) = self.tx.send(notification).await {
            error!(error = %e, "Failed to send rule sync notification");
        }
        
        Ok(())
    }
}

/// Integration with ShieldEngine for hot rule reloading
pub async fn setup_rule_sync(
    db: Database,
    engine: std::sync::Arc<crate::ShieldEngine>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sync, mut rx) = RuleSynchronizer::new(db.clone());
    
    // Start listening for notifications
    sync.start_listening().await?;
    
    // Spawn task to handle sync notifications
    tokio::spawn(async move {
        // Initial load
        if let Err(e) = engine.reload_rules_from_db(&db).await {
            error!("Failed to load initial rules: {}", e);
        }
        
        while let Some(notification) = rx.recv().await {
            info!(
                sync_type = ?notification.sync_type,
                "Processing rule sync notification - reloading rules"
            );
            
            match notification.sync_type {
                SyncType::RuleAdded => info!("Rule added"),
                SyncType::RuleUpdated => info!("Rule updated"),
                SyncType::RuleDeleted => info!("Rule deleted"),
                SyncType::FullSync => info!("Full sync requested"),
            }
            
            // Reload all rules from database
            if let Err(e) = engine.reload_rules_from_db(&db).await {
                error!("Failed to reload rules: {}", e);
            }
        }
    });
    
    Ok(())
}
