use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Shield service gRPC endpoint
    pub shield_endpoint: String,

    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,

    /// API key -> tenant_id mappings
    #[serde(default)]
    pub api_keys: HashMap<String, String>,

    /// Default API key to use when none is provided (stdio mode)
    #[serde(default)]
    pub default_api_key: Option<String>,

    /// Transport type: stdio or sse
    #[serde(default)]
    pub transport: TransportType,

    /// Bind address for SSE transport
    pub bind_address: String,

    /// Cache size for classification results
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, clap::ValueEnum)]
pub enum TransportType {
    #[default]
    Stdio,
    Sse,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Stdio => write!(f, "stdio"),
            TransportType::Sse => write!(f, "sse"),
        }
    }
}

fn default_cache_size() -> usize {
    10000
}

fn default_cache_ttl_secs() -> u64 {
    60
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            shield_endpoint: "http://localhost:50051".to_string(),
            request_timeout_ms: 100,
            api_keys: HashMap::new(),
            default_api_key: None,
            transport: TransportType::Stdio,
            bind_address: "0.0.0.0:8081".to_string(),
            cache_size: default_cache_size(),
            cache_ttl_secs: default_cache_ttl_secs(),
        }
    }
}

fn parse_api_keys(s: String) -> HashMap<String, String> {
    s.split(',')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, ':');
            let key = parts.next()?.trim().to_string();
            let tenant = parts.next()?.trim().to_string();
            if key.is_empty() || tenant.is_empty() {
                None
            } else {
                Some((key, tenant))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = McpConfig::default();
        assert_eq!(config.shield_endpoint, "http://localhost:50051");
        assert_eq!(config.bind_address, "0.0.0.0:8081");
        assert_eq!(config.cache_size, 10000);
        assert_eq!(config.cache_ttl_secs, 60);
        assert!(config.api_keys.is_empty());
    }

    #[test]
    fn test_parse_api_keys() {
        let keys = parse_api_keys("key1:tenant1,key2:tenant2".to_string());
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.get("key1"), Some(&"tenant1".to_string()));
        assert_eq!(keys.get("key2"), Some(&"tenant2".to_string()));
    }

    #[test]
    fn test_parse_api_keys_ignores_empty() {
        let keys = parse_api_keys("key1:tenant1,,,:,:tenant3".to_string());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.get("key1"), Some(&"tenant1".to_string()));
    }
}

impl McpConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        use std::env;

        Self {
            shield_endpoint: env::var("SHIELD_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:50051".to_string()),
            request_timeout_ms: env::var("REQUEST_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            api_keys: env::var("MCP_API_KEYS")
                .ok()
                .map(parse_api_keys)
                .unwrap_or_default(),
            default_api_key: env::var("MCP_API_KEY").ok(),
            transport: env::var("MCP_TRANSPORT")
                .ok()
                .and_then(|s| match s.as_str() {
                    "sse" => Some(TransportType::Sse),
                    _ => Some(TransportType::Stdio),
                })
                .unwrap_or_default(),
            bind_address: env::var("MCP_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
            cache_size: env::var("MCP_CACHE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_cache_size),
            cache_ttl_secs: env::var("MCP_CACHE_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_cache_ttl_secs),
        }
    }

    /// Load from TOML file
    pub fn from_file(path: &str) -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("MCP"))
            .build()?;

        settings.try_deserialize()
    }
}
