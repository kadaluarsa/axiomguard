use config::Config;
use serde::Deserialize;
use std::{fs, net::SocketAddr, path::Path};
use tracing::Level;

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AiConfig {
    pub enabled: bool,
    pub api_key: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl: u64,
    pub max_size: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct QueueConfig {
    pub max_events: u64,
    pub worker_threads: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub require_authentication: bool,
    pub valid_api_keys: Vec<String>,
    pub valid_bearer_tokens: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub metrics_address: String,
    pub log_level: String,
    pub database: DatabaseConfig,
    pub ai: AiConfig,
    pub cache: CacheConfig,
    pub queue: QueueConfig,
    pub auth: AuthConfig,
}

impl ServerConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config_content = fs::read_to_string(path)?;
        let config = Config::builder()
            .add_source(config::File::from_str(
                &config_content,
                config::FileFormat::Toml,
            ))
            .build()?;

        let instance: Self = config.try_deserialize()?;
        instance.validate()?;

        Ok(instance)
    }

    pub fn from_default() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_file("config.toml")
    }

    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Validate server addresses
        if let Err(e) = self.address.parse::<SocketAddr>() {
            return Err(format!("invalid server address '{}': {}", self.address, e).into());
        }

        if let Err(e) = self.metrics_address.parse::<SocketAddr>() {
            return Err(
                format!("invalid metrics address '{}': {}", self.metrics_address, e).into(),
            );
        }

        // Validate log level
        if let Err(e) = self.log_level.parse::<Level>() {
            return Err(format!(
                "invalid log level '{}': {}. Valid levels: error, warn, info, debug, trace",
                self.log_level, e
            )
            .into());
        }

        // Validate database configuration
        self.database.validate()?;

        // Validate AI configuration
        self.ai.validate()?;

        // Validate cache configuration
        self.cache.validate()?;

        // Validate queue configuration
        self.queue.validate()?;

        // Validate auth configuration
        self.auth.validate()?;

        Ok(())
    }
}

impl DatabaseConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.url.is_empty() {
            return Err("database url cannot be empty".into());
        }

        if self.max_connections == 0 {
            return Err("database max_connections must be greater than 0".into());
        }

        Ok(())
    }
}

impl AiConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.enabled {
            if self.api_key.is_empty() || self.api_key == "YOUR_API_KEY" {
                return Err("ai.api_key must be configured when AI is enabled".into());
            }

            if self.model.is_empty() {
                return Err("ai.model cannot be empty when AI is enabled".into());
            }

            if !(0.0..=2.0).contains(&self.temperature) {
                return Err(format!(
                    "ai.temperature must be between 0.0 and 2.0, got {}",
                    self.temperature
                )
                .into());
            }

            if self.max_tokens == 0 {
                return Err("ai.max_tokens must be greater than 0".into());
            }
        }

        Ok(())
    }
}

impl CacheConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.enabled {
            if self.ttl == 0 {
                return Err("cache.ttl must be greater than 0 when cache is enabled".into());
            }

            if self.max_size == 0 {
                return Err("cache.max_size must be greater than 0 when cache is enabled".into());
            }
        }

        Ok(())
    }
}

impl QueueConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.max_events == 0 {
            return Err("queue.max_events must be greater than 0".into());
        }

        if self.worker_threads == 0 {
            return Err("queue.worker_threads must be greater than 0".into());
        }

        if self.worker_threads > 128 {
            return Err(format!(
                "queue.worker_threads cannot exceed 128, got {}",
                self.worker_threads
            )
            .into());
        }

        Ok(())
    }
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.require_authentication
            && self.valid_api_keys.is_empty()
            && self.valid_bearer_tokens.is_empty()
        {
            return Err(
                "authentication is required but no valid api keys or bearer tokens are configured"
                    .into(),
            );
        }

        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:50051".to_string(),
            metrics_address: "0.0.0.0:9090".to_string(),
            log_level: "info".to_string(),
            database: DatabaseConfig {
                url: "sqlite:///var/lib/axiomguard/audit.db".to_string(),
                max_connections: 10,
            },
            ai: AiConfig {
                enabled: true,
                api_key: "YOUR_API_KEY".to_string(),
                model: "gemma-7b-it".to_string(),
                temperature: 0.1,
                max_tokens: 512,
            },
            cache: CacheConfig {
                enabled: true,
                ttl: 300,
                max_size: 10000,
            },
            queue: QueueConfig {
                max_events: 10000,
                worker_threads: 8,
            },
            auth: AuthConfig {
                require_authentication: true,
                valid_api_keys: Vec::new(),
                valid_bearer_tokens: Vec::new(),
            },
        }
    }
}
