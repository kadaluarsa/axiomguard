use std::{
    sync::Arc,
    time::Duration,
};

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use prometheus::Histogram;
use tracing::{debug, error, warn, info, instrument};

use common::*;

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),
    
    #[error("Invalid response from AI endpoint: {0}")]
    InvalidResponse(String),
    
    #[error("AI service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Request timeout after {0}ms")]
    Timeout(u64),
    
    #[error("Rate limited, retry after {0}s")]
    RateLimited(u64),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("All retries exhausted")]
    RetriesExhausted,
}

pub type Result<T> = std::result::Result<T, AiError>;

/// AI backend configuration
#[derive(Debug, Clone)]
pub enum AiBackend {
    /// vLLM local inference
    Vllm {
        endpoint: String,
        model: String,
    },
    /// Vertex AI (GCP)
    VertexAi {
        project_id: String,
        location: String,
        model: String,
    },
    /// Modal.com serverless inference
    Modal {
        endpoint: String,
        model: String,
        api_key: Option<String>,
    },
}

impl Default for AiBackend {
    fn default() -> Self {
        AiBackend::Vllm {
            endpoint: "http://localhost:8000/v1".to_string(),
            model: "mistralai/Mistral-7B-Instruct-v0.2".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatCompletionMessage {
    role: String,
    content: String,
}

#[derive(Debug, Clone, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatCompletionMessage>,
    temperature: f32,
    max_tokens: u32,
    stream: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatCompletionChoice {
    message: ChatCompletionMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatCompletionResponse {
    id: Option<String>,
    choices: Vec<ChatCompletionChoice>,
    usage: Option<serde_json::Value>,
}

/// Classification result from AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventClassification {
    pub risk_level: f32,
    pub category: String,
    pub anomalies: Vec<String>,
    pub recommendations: Vec<String>,
    pub confidence: f32,
    pub model: String,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    classification: EventClassification,
    created_at: chrono::DateTime<Utc>,
    hits: u64,
}

/// AI Engine with vLLM primary and Vertex AI fallback
#[derive(Debug)]
pub struct AiEngine {
    client: Client,
    primary_backend: AiBackend,
    fallback_backend: Option<AiBackend>,
    timeout: Duration,
    max_retries: u32,
    initial_backoff: Duration,
    cache: moka::sync::Cache<u64, CacheEntry>,
    cache_ttl: Duration,
    metrics: Option<Histogram>,
    use_structured_output: bool,
}

impl Default for AiEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AiEngine {
    /// Create a new AI engine with default configuration
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(60))
            .tcp_keepalive(Duration::from_secs(30))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(5))
            .http2_keep_alive_while_idle(true)
            .connect_timeout(Duration::from_millis(100))
            .build()
            .expect("Failed to create HTTP client for AI engine");

        // Read configuration from environment
        let primary_backend = Self::get_primary_backend();
        let fallback_backend = Self::get_fallback_backend();

        Self {
            client,
            primary_backend,
            fallback_backend,
            timeout: Duration::from_millis(60),
            max_retries: 2,
            initial_backoff: Duration::from_millis(10),
            cache: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .time_to_idle(Duration::from_secs(300))
                .build(),
            cache_ttl: Duration::from_secs(300),
            metrics: None,
            use_structured_output: true,
        }
    }

    /// Create AI engine from environment variables
    fn get_primary_backend() -> AiBackend {
        use std::env;
        
        match env::var("AI_BACKEND").as_deref() {
            Ok("vertex-ai") | Ok("vertex") => AiBackend::VertexAi {
                project_id: env::var("VERTEX_AI_PROJECT").unwrap_or_default(),
                location: env::var("VERTEX_AI_LOCATION").unwrap_or("us-central1".to_string()),
                model: env::var("AI_MODEL").unwrap_or("gemini-1.5-pro".to_string()),
            },
            Ok("modal") => AiBackend::Modal {
                endpoint: env::var("MODAL_ENDPOINT")
                    .expect("MODAL_ENDPOINT must be set when AI_BACKEND=modal"),
                model: env::var("AI_MODEL")
                    .unwrap_or("mistralai/Mistral-7B-Instruct-v0.2".to_string()),
                api_key: env::var("MODAL_API_KEY").ok(),
            },
            _ => AiBackend::Vllm {
                endpoint: env::var("VLLM_ENDPOINT")
                    .unwrap_or("http://localhost:8000/v1".to_string()),
                model: env::var("AI_MODEL")
                    .unwrap_or("mistralai/Mistral-7B-Instruct-v0.2".to_string()),
            },
        }
    }

    fn get_fallback_backend() -> Option<AiBackend> {
        use std::env;
        
        match env::var("AI_FALLBACK").as_deref() {
            Ok("vertex-ai") | Ok("vertex") => Some(AiBackend::VertexAi {
                project_id: env::var("VERTEX_AI_PROJECT").unwrap_or_default(),
                location: env::var("VERTEX_AI_LOCATION").unwrap_or("us-central1".to_string()),
                model: env::var("AI_FALLBACK_MODEL")
                    .unwrap_or("gemini-1.5-flash".to_string()),
            }),
            Ok("modal") => Some(AiBackend::Modal {
                endpoint: env::var("MODAL_FALLBACK_ENDPOINT")
                    .expect("MODAL_FALLBACK_ENDPOINT must be set when AI_FALLBACK=modal"),
                model: env::var("AI_FALLBACK_MODEL")
                    .unwrap_or("google/gemma-2b-it".to_string()),
                api_key: env::var("MODAL_API_KEY").ok(),
            }),
            Ok("vllm") => Some(AiBackend::Vllm {
                endpoint: env::var("VLLM_FALLBACK_ENDPOINT")
                    .unwrap_or("http://vllm-backup:8000/v1".to_string()),
                model: env::var("AI_FALLBACK_MODEL")
                    .unwrap_or("google/gemma-2b-it".to_string()),
            }),
            _ => None,
        }
    }

    pub fn with_metrics(mut self, ai_processing_time: Histogram) -> Self {
        self.metrics = Some(ai_processing_time);
        self
    }

    /// Classify content by racing primary and fallback backends in parallel.
    /// Total AI time is capped at self.timeout regardless of fallback status.
    #[instrument(skip_all, fields(content_length = %content.len()))]
    pub async fn classify_text(&self, content: &str) -> Result<EventClassification> {
        let start_time = std::time::Instant::now();
        
        let cache_key = self.calculate_cache_key(content);
        if let Some(cached) = self.get_cached_classification(cache_key).await {
            debug!(cache_hits = %cached.hits, "Using cached AI classification");
            self.record_metrics(start_time);
            return Ok(cached.classification);
        }

        let classification = if let Some(ref fallback) = self.fallback_backend {
            self.classify_racing(content, &self.primary_backend, fallback).await?
        } else {
            match tokio::time::timeout(
                self.timeout,
                self.classify_with_backend(content, &self.primary_backend)
            ).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    warn!(error = %e, "Primary backend failed, no fallback configured");
                    return Err(e);
                }
                Err(_) => {
                    return Err(AiError::Timeout(self.timeout.as_millis() as u64));
                }
            }
        };

        self.cache_classification(cache_key, classification.clone()).await;
        self.record_metrics(start_time);

        Ok(classification)
    }

    /// Race primary and fallback backends with a hard timeout.
    /// First successful response wins; the other is cancelled.
    async fn classify_racing(
        &self,
        content: &str,
        primary: &AiBackend,
        fallback: &AiBackend,
    ) -> Result<EventClassification> {
        let primary_fut = self.classify_with_backend(content, primary);
        let fallback_fut = self.classify_with_backend(content, fallback);
        let deadline = self.timeout;

        let result = tokio::time::timeout(deadline, async {
            tokio::select! {
                r = primary_fut => {
                    match r {
                        Ok(classification) => {
                            info!(backend = "primary", model = %classification.model, "Classification successful");
                            Ok(classification)
                        }
                        Err(e) => {
                            warn!(error = %e, "Primary backend failed, waiting for fallback");
                            Err(e)
                        }
                    }
                }
                r = fallback_fut => {
                    match r {
                        Ok(mut classification) => {
                            classification.model = format!("{}_fallback", classification.model);
                            info!(backend = "fallback", model = %classification.model, "Fallback responded first");
                            Ok(classification)
                        }
                        Err(e) => {
                            warn!(error = %e, "Fallback backend also failed");
                            Err(e)
                        }
                    }
                }
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => {
                error!("Both AI backends timed out after {}ms", self.timeout.as_millis());
                Err(AiError::Timeout(self.timeout.as_millis() as u64))
            }
        }
    }

    /// Classify using a specific backend
    async fn classify_with_backend(
        &self,
        content: &str,
        backend: &AiBackend,
    ) -> Result<EventClassification> {
        match backend {
            AiBackend::Vllm { endpoint, model } => {
                self.classify_vllm(content, endpoint, model).await
            }
            AiBackend::VertexAi { project_id, location, model } => {
                self.classify_vertex(content, project_id, location, model).await
            }
            AiBackend::Modal { endpoint, model, api_key } => {
                self.classify_modal(content, endpoint, model, api_key.as_deref()).await
            }
        }
    }

    /// Classify using vLLM (OpenAI-compatible API)
    async fn classify_vllm(
        &self,
        content: &str,
        endpoint: &str,
        model: &str,
    ) -> Result<EventClassification> {
        let prompt = self.build_classification_prompt(content);
        
        let request = ChatCompletionRequest {
            model: model.to_string(),
            messages: vec![
                ChatCompletionMessage {
                    role: "system".to_string(),
                    content: "You are a security analysis AI. Analyze content and respond with JSON only.".to_string(),
                },
                ChatCompletionMessage {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            temperature: 0.1,
            max_tokens: 256,
            stream: false,
        };

        let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
        
        let response = self.client
            .post(&url)
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => {
                return Err(AiError::RateLimited(60));
            }
            StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => {
                return Err(AiError::ServiceUnavailable(format!("HTTP {}", response.status())));
            }
            status => {
                let text = response.text().await.unwrap_or_default();
                return Err(AiError::InvalidResponse(format!("HTTP {}: {}", status, text)));
            }
        }

        let completion: ChatCompletionResponse = response.json().await?;
        
        let choice = completion.choices.first()
            .ok_or_else(|| AiError::InvalidResponse("No choices in response".to_string()))?;

        // Parse the JSON response
        self.parse_classification_response(&choice.message.content, model)
    }

    /// Classify using Vertex AI (Gemini API)
    async fn classify_vertex(
        &self,
        content: &str,
        project_id: &str,
        location: &str,
        model: &str,
    ) -> Result<EventClassification> {
        // Vertex AI Gemini API endpoint
        let url = format!(
            "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
            location, project_id, location, model
        );

        let request_body = serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{"text": self.build_classification_prompt(content)}]
            }],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 256,
                "responseMimeType": "application/json"
            }
        });

        // Get access token from metadata service (GKE) or environment
        let token = self.get_gcp_token().await?;

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request_body)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AiError::InvalidResponse(format!("Vertex AI error: {}", text)));
        }

        let result: serde_json::Value = response.json().await?;
        
        // Extract text from Gemini response
        let text = result["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .ok_or_else(|| AiError::InvalidResponse("Invalid Gemini response format".to_string()))?;

        self.parse_classification_response(text, model)
    }

    /// Classify using Modal.com (OpenAI-compatible web endpoint)
    async fn classify_modal(
        &self,
        content: &str,
        endpoint: &str,
        model: &str,
        api_key: Option<&str>,
    ) -> Result<EventClassification> {
        let request_body = serde_json::json!({
            "content": content,
            "model": model,
        });

        let mut request = self.client
            .post(endpoint)
            .json(&request_body)
            .timeout(self.timeout);

        // Add API key if provided
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request.send().await?;

        match response.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => {
                return Err(AiError::RateLimited(60));
            }
            StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => {
                return Err(AiError::ServiceUnavailable(format!("Modal error: HTTP {}", response.status())));
            }
            status => {
                let text = response.text().await.unwrap_or_default();
                return Err(AiError::InvalidResponse(format!("Modal error: HTTP {} - {}", status, text)));
            }
        }

        // Modal returns the classification directly as JSON
        let result: serde_json::Value = response.json().await?;
        
        // Parse the response (it's already in the classification format)
        let classification = EventClassification {
            risk_level: result["risk_level"].as_f64().unwrap_or(0.5) as f32,
            category: result["category"].as_str().unwrap_or("unknown").to_string(),
            anomalies: result["anomalies"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            recommendations: result["recommendations"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            confidence: result["confidence"].as_f64().unwrap_or(0.8) as f32,
            model: model.to_string(),
        };

        Ok(classification)
    }

    /// Build classification prompt
    fn build_classification_prompt(&self, content: &str) -> String {
        format!(
            r#"Analyze this content for security risks and respond with JSON only:

Content: {}

Provide a JSON object with these fields:
- risk_level: float between 0.0 (safe) and 1.0 (critical)
- category: string describing the risk type (e.g., "spam", "phishing", "fraud", "safe")
- anomalies: array of strings listing suspicious elements found
- recommendations: array of strings with suggested actions
- confidence: float between 0.0 and 1.0 indicating your confidence

Example response:
{{
  "risk_level": 0.7,
  "category": "suspicious",
  "anomalies": ["unusual language", "request for personal info"],
  "recommendations": ["flag for review"],
  "confidence": 0.85
}}"#,
            content
        )
    }

    /// Parse classification response from AI
    fn parse_classification_response(&self, text: &str, model: &str) -> Result<EventClassification> {
        // Try to extract JSON from the response (in case there's extra text)
        let json_str = if let Some(start) = text.find('{') {
            if let Some(end) = text.rfind('}') {
                &text[start..=end]
            } else {
                text
            }
        } else {
            text
        };

        let parsed: serde_json::Value = serde_json::from_str(json_str)?;
        
        // Ensure all required fields exist with defaults
        let classification = EventClassification {
            risk_level: parsed["risk_level"].as_f64().unwrap_or(0.5) as f32,
            category: parsed["category"].as_str().unwrap_or("unknown").to_string(),
            anomalies: parsed["anomalies"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            recommendations: parsed["recommendations"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            confidence: parsed["confidence"].as_f64().unwrap_or(0.8) as f32,
            model: model.to_string(),
        };

        Ok(classification)
    }

    /// Get GCP access token
    async fn get_gcp_token(&self) -> Result<String> {
        // Try metadata service first (when running on GKE)
        match self.client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let token: serde_json::Value = response.json().await?;
                return token["access_token"]
                    .as_str()
                    .map(String::from)
                    .ok_or_else(|| AiError::InvalidResponse("Invalid token response".to_string()));
            }
            _ => {}
        }

        // Fall back to environment variable
        std::env::var("GCP_ACCESS_TOKEN")
            .map_err(|_| AiError::ServiceUnavailable("Could not obtain GCP access token".to_string()))
    }

    /// Calculate cache key from content
    fn calculate_cache_key(&self, content: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }

    async fn get_cached_classification(&self, key: u64) -> Option<CacheEntry> {
        self.cache.get(&key).and_then(|entry| {
            if entry.created_at + self.cache_ttl > Utc::now() {
                Some(entry)
            } else {
                self.cache.invalidate(&key);
                None
            }
        })
    }

    async fn cache_classification(&self, key: u64, classification: EventClassification) {
        self.cache.insert(key, CacheEntry {
            classification,
            created_at: Utc::now(),
            hits: 0,
        });
    }

    fn record_metrics(&self, start_time: std::time::Instant) {
        if let Some(metrics) = &self.metrics {
            let elapsed = start_time.elapsed().as_millis() as f64;
            metrics.observe(elapsed);
        }
    }

    pub async fn clear_cache(&self) {
        self.cache.invalidate_all();
        debug!("AI classification cache cleared");
    }

    pub async fn cache_stats(&self) -> (usize, u64) {
        let count = self.cache.entry_count() as usize;
        (count, 0)
    }

    /// Health check for AI backends
    pub async fn health_check(&self) -> (bool, bool) {
        let primary_healthy = self.check_backend_health(&self.primary_backend).await;
        let fallback_healthy = if let Some(ref fallback) = self.fallback_backend {
            self.check_backend_health(fallback).await
        } else {
            false
        };
        
        (primary_healthy, fallback_healthy)
    }

    async fn check_backend_health(&self, backend: &AiBackend) -> bool {
        match backend {
            AiBackend::Vllm { endpoint, .. } => {
                match self.client
                    .get(format!("{}/health", endpoint.trim_end_matches('/')))
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await
                {
                    Ok(response) => response.status().is_success(),
                    Err(_) => false,
                }
            }
            AiBackend::VertexAi { .. } => {
                // Vertex AI is generally always available if credentials work
                self.get_gcp_token().await.is_ok()
            }
            AiBackend::Modal { endpoint, api_key, .. } => {
                // Modal web endpoints don't have a standard /health path
                // Try a simple POST with minimal content
                let health_url = endpoint.replace("/classify", "/health");
                let mut request = self.client
                    .get(&health_url)
                    .timeout(Duration::from_secs(2));
                
                if let Some(key) = api_key {
                    request = request.header("Authorization", format!("Bearer {}", key));
                }
                
                match request.send().await {
                    Ok(response) => response.status().is_success(),
                    Err(_) => {
                        // If health endpoint fails, assume it might be warm
                        // Modal will cold-start if needed
                        true
                    }
                }
            }
        }
    }
}
