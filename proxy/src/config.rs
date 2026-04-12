use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address to bind the proxy server
    pub bind_address: String,
    
    /// Shield service gRPC endpoint
    pub shield_endpoint: String,
    
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
    
    /// Maximum request size in bytes
    pub max_request_size: usize,
    
    /// Rate limiting: requests per second per IP
    pub rate_limit_rps: u32,
    
    /// Enable CORS
    pub enable_cors: bool,
    
    /// Allowed CORS origins (empty = allow all)
    pub cors_origins: Vec<String>,
    
    /// API key -> tenant_id mappings (format: key1:tenant1,key2:tenant2)
    #[serde(default)]
    pub api_keys: HashMap<String, String>,
    
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".to_string(),
            shield_endpoint: "http://localhost:50051".to_string(),
            request_timeout_ms: 100, // 100ms decisive timer
            max_request_size: 1024 * 1024, // 1MB
            rate_limit_rps: 100,
            enable_cors: true,
            cors_origins: vec![],
            api_keys: HashMap::new(),
            tls: None,
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

impl ProxyConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        use std::env;
        
        Self {
            bind_address: env::var("PROXY_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            shield_endpoint: env::var("SHIELD_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:50051".to_string()),
            request_timeout_ms: env::var("REQUEST_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            max_request_size: env::var("MAX_REQUEST_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024 * 1024),
            rate_limit_rps: env::var("RATE_LIMIT_RPS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            enable_cors: env::var("ENABLE_CORS")
                .ok()
                .map(|s| s == "true" || s == "1")
                .unwrap_or(true),
            cors_origins: env::var("CORS_ORIGINS")
                .ok()
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default(),
            api_keys: env::var("PROXY_API_KEYS")
                .ok()
                .map(parse_api_keys)
                .unwrap_or_default(),
            tls: None, // TLS config from file
        }
    }
    
    /// Load from TOML file
    pub fn from_file(path: &str) -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("PROXY"))
            .build()?;
            
        settings.try_deserialize()
    }
}
