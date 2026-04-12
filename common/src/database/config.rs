use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL for metadata (tenants, rules)
    /// Format: postgres://user:password@host:port/database
    pub url: String,
    
    /// PostgreSQL connection URL for events/decisions
    /// Defaults to `url` if not set
    pub events_url: String,
    
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    
    /// Minimum number of connections in the pool
    pub min_connections: u32,
    
    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,
    
    /// Acquire timeout in milliseconds
    pub acquire_timeout_ms: u64,
    
    /// Idle timeout in milliseconds
    pub idle_timeout_ms: u64,
    
    /// Max lifetime of a connection in milliseconds
    pub max_lifetime_ms: u64,
    
    /// Enable pgvector extension
    pub enable_vector: bool,
    
    /// Vector dimension size (default: 768 for Gemma embeddings)
    pub vector_dimension: i32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        let url = "postgres://localhost:5432/axiomguard".to_string();
        Self {
            url: url.clone(),
            events_url: url,
            max_connections: 20,
            min_connections: 5,
            connect_timeout_ms: 5000,
            acquire_timeout_ms: 5000,
            idle_timeout_ms: 300000,
            max_lifetime_ms: 1800000, // 30 minutes
            enable_vector: true,
            vector_dimension: 768,
        }
    }
}

impl DatabaseConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        use std::env;
        
        let url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost:5432/axiomguard".to_string());
        let events_url = env::var("EVENTS_DATABASE_URL")
            .unwrap_or_else(|_| url.clone());
        
        Self {
            url,
            events_url,
            max_connections: env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20),
            min_connections: env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            connect_timeout_ms: env::var("DB_CONNECT_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5000),
            acquire_timeout_ms: env::var("DB_ACQUIRE_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5000),
            idle_timeout_ms: env::var("DB_IDLE_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300000),
            max_lifetime_ms: env::var("DB_MAX_LIFETIME_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800000),
            enable_vector: env::var("DB_ENABLE_VECTOR")
                .ok()
                .map(|s| s == "true" || s == "1")
                .unwrap_or(true),
            vector_dimension: env::var("DB_VECTOR_DIMENSION")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(768),
        }
    }
}
