use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Error;
use std::time::Duration;
use tracing::{info, error};
use super::DatabaseConfig;

#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
    pub config: DatabaseConfig,
}

impl Database {
    pub async fn new(config: DatabaseConfig) -> Result<Self, Error> {
        info!("Initializing PostgreSQL connection pool");
        
        // Mask password in logs
        let masked_url = mask_password(&config.url);
        info!("Connecting to: {}", masked_url);
        
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_millis(config.acquire_timeout_ms))
            .idle_timeout(Duration::from_millis(config.idle_timeout_ms))
            .max_lifetime(Duration::from_millis(config.max_lifetime_ms))
            .test_before_acquire(true)
            .connect(&config.url)
            .await?;

        info!("PostgreSQL connection pool initialized successfully");
        
        let db = Self { pool, config };
        
        // Initialize extensions
        db.init_extensions().await?;
        
        Ok(db)
    }
    
    async fn init_extensions(&self) -> Result<(), Error> {
        // Enable required extensions
        sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
            .execute(&self.pool)
            .await?;
            
        if self.config.enable_vector {
            sqlx::query("CREATE EXTENSION IF NOT EXISTS vector")
                .execute(&self.pool)
                .await?;
            info!("pgvector extension enabled");
        }
        
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn close(&self) {
        info!("Closing PostgreSQL connection pool");
        self.pool.close().await;
        info!("PostgreSQL connection pool closed");
    }

    pub async fn ping(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    
    /// Listen for notifications on a channel
    pub async fn listen(&self, channel: &str) -> Result<sqlx::postgres::PgListener, Error> {
        let mut listener = sqlx::postgres::PgListener::connect_with(&self.pool).await?;
        listener.listen(channel).await?;
        Ok(listener)
    }
}

/// Mask password in connection string for logging
fn mask_password(url: &str) -> String {
    use regex::Regex;
    let re = Regex::new(r"(postgres://[^:]+:)([^@]+)(@.+)").unwrap();
    re.replace(url, "${1}***${3}").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_password() {
        let url = "postgres://user:secret@localhost:5432/db";
        let masked = mask_password(url);
        assert!(masked.contains("***"));
        assert!(!masked.contains("secret"));
    }
}
