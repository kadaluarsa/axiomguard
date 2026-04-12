use axum::{
    extract::{ws::WebSocket, Query, State, WebSocketUpgrade},
    response::{sse::Event, Sse, IntoResponse},
    routing::{get, post},
    Router,
    http::StatusCode,
};
use futures::stream::Stream;
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

pub mod config;
pub mod shield_client;
pub mod sse;
pub mod websocket;

use config::ProxyConfig;
use shield_client::ShieldClient;

/// Cache entry with TTL
#[derive(Clone)]
pub struct CacheEntry {
    value: serde_json::Value,
    inserted_at: std::time::Instant,
}

impl CacheEntry {
    fn is_valid(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() < ttl
    }
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub shield_client: ShieldClient,
    pub config: Arc<ProxyConfig>,
    pub decision_cache: moka::sync::Cache<String, CacheEntry>,
    pub metrics: Arc<ProxyMetrics>,
}

/// Prometheus metrics for the proxy
#[derive(Clone)]
pub struct ProxyMetrics {
    pub total_requests: prometheus::IntCounter,
    pub cache_hits: prometheus::IntCounter,
    pub auth_failures: prometheus::IntCounter,
    pub classification_errors: prometheus::IntCounter,
    pub shield_latency: prometheus::Histogram,
}

impl ProxyMetrics {
    pub fn new() -> Self {
        let registry = common::metrics::REGISTRY.clone();
        
        let total_requests = prometheus::IntCounter::with_opts(
            prometheus::opts!("axiomguard_proxy_total_requests", "Total HTTP requests received")
        ).unwrap();
        
        let cache_hits = prometheus::IntCounter::with_opts(
            prometheus::opts!("axiomguard_proxy_cache_hits", "Proxy cache hits")
        ).unwrap();
        
        let auth_failures = prometheus::IntCounter::with_opts(
            prometheus::opts!("axiomguard_proxy_auth_failures", "API key authentication failures")
        ).unwrap();
        
        let classification_errors = prometheus::IntCounter::with_opts(
            prometheus::opts!("axiomguard_proxy_classification_errors", "Classification request errors")
        ).unwrap();
        
        let shield_latency = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::from(
                prometheus::opts!("axiomguard_proxy_shield_latency_ms", "gRPC call latency to shield service")
            )
        ).unwrap();
        
        registry.register(Box::new(total_requests.clone())).ok();
        registry.register(Box::new(cache_hits.clone())).ok();
        registry.register(Box::new(auth_failures.clone())).ok();
        registry.register(Box::new(classification_errors.clone())).ok();
        registry.register(Box::new(shield_latency.clone())).ok();
        
        Self {
            total_requests,
            cache_hits,
            auth_failures,
            classification_errors,
            shield_latency,
        }
    }
}

/// Validate an API key against the configured key map.
/// Returns the tenant_id if valid. In development mode (no keys configured), allows all.
fn validate_api_key(api_keys: &HashMap<String, String>, key: &str) -> Option<String> {
    if api_keys.is_empty() {
        return Some("default".to_string());
    }
    let provided = key.as_bytes();
    for (configured_key, tenant_id) in api_keys {
        if provided.ct_eq(configured_key.as_bytes()).into() {
            return Some(tenant_id.clone());
        }
    }
    None
}

/// Run the proxy server
pub async fn run_server(config: ProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize distributed tracer
    common::telemetry::init_tracer("axiomguard-proxy");
    
    let bind_address = config.bind_address.clone();
    let shield_client = ShieldClient::connect(&config.shield_endpoint).await?;
    
    let cache = moka::sync::Cache::builder()
        .max_capacity(10_000)
        .time_to_idle(Duration::from_secs(300))
        .build();
    
    let state = AppState {
        shield_client,
        config: Arc::new(config),
        decision_cache: cache,
        metrics: Arc::new(ProxyMetrics::new()),
    };

    let app = Router::new()
        // SSE endpoint for streaming classifications
        .route("/v1/stream", get(sse_handler))
        // WebSocket endpoint for bidirectional streaming
        .route("/v1/ws", get(websocket_handler))
        // Health check
        .route("/health", get(health_check))
        // Single classification request
        .route("/v1/classify", post(classify_handler))
        // Metrics
        .route("/metrics", get(metrics_handler))
        .with_state(state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let addr: SocketAddr = bind_address.parse()?;
    info!("Starting AxiomGuard Proxy on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(serde::Deserialize)]
struct SseClassifyParams {
    session_id: String,
    content: String,
    #[serde(default)]
    metadata: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
}

/// SSE handler for server-sent events
async fn sse_handler(
    State(state): State<AppState>,
    Query(params): Query<SseClassifyParams>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    state.metrics.total_requests.inc();
    let api_key = params.api_key.clone();
    let tenant_id = api_key.as_ref()
        .and_then(|k| validate_api_key(&state.config.api_keys, k));
    if api_key.is_some() && tenant_id.is_none() {
        state.metrics.auth_failures.inc();
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (tx, rx) = mpsc::channel(100);
    let client = state.shield_client.clone();
    let cache = state.decision_cache.clone();
    let metrics = state.metrics.clone();
    
    // Build classification request
    let mut request = serde_json::json!({
        "session_id": params.session_id,
        "content": params.content,
    });
    
    if let Some(ref metadata_str) = params.metadata {
        if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(metadata_str) {
            request["metadata"] = metadata;
        }
    }
    
    // Inject authenticated tenant_id into request metadata
    if let Some(tenant) = tenant_id.as_ref() {
        if let Some(metadata) = request.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            metadata.insert("tenant_id".to_string(), serde_json::json!(tenant));
        } else {
            request["metadata"] = serde_json::json!({"tenant_id": tenant});
        }
    }
    
    let cache_key = build_cache_key(&request, tenant_id.as_deref());
    
    tokio::spawn(async move {
        // Check proxy cache first
        if let Some(key) = &cache_key {
            if let Some(entry) = cache.get(key) {
                if entry.is_valid(Duration::from_secs(60)) {
                    metrics.cache_hits.inc();
                    info!("SSE proxy cache hit");
                    let data = serde_json::to_string(&entry.value).unwrap_or_default();
                    let _ = tx.send(Ok(Event::default().event("classification").data(data))).await;
                    let mut interval = tokio::time::interval(Duration::from_secs(15));
                    loop {
                        interval.tick().await;
                        let event = Event::default()
                            .event("heartbeat")
                            .data(r#"{"status":"alive"}"#);
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    return;
                }
            }
        }
        
        // Send started event
        let _ = tx.send(Ok(Event::default().event("started").data(r#"{"status":"processing"}"#))).await;
        
        // Perform classification
        let start = std::time::Instant::now();
        match client.classify_stream(request, api_key.as_deref()).await {
            Ok(response) => {
                metrics.shield_latency.observe(start.elapsed().as_millis() as f64);
                // Store in cache
                if let Some(key) = cache_key {
                    cache.insert(key, CacheEntry {
                        value: response.clone(),
                        inserted_at: std::time::Instant::now(),
                    });
                }
                let data = serde_json::to_string(&response).unwrap_or_default();
                let _ = tx.send(Ok(Event::default().event("classification").data(data))).await;
            }
            Err(e) => {
                metrics.classification_errors.inc();
                metrics.shield_latency.observe(start.elapsed().as_millis() as f64);
                error!("SSE classification error: {}", e);
                let data = format!(r#"{{"error":"{}"}}"#, e);
                let _ = tx.send(Ok(Event::default().event("error").data(data))).await;
            }
        }
        
        // Send periodic heartbeats to keep connection alive
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            
            let event = Event::default()
                .event("heartbeat")
                .data(r#"{"status":"alive"}"#);
                
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });

    Ok(Sse::new(ReceiverStream::new(rx))
        .keep_alive(axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive-text")))
}

/// WebSocket handler
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // WebSocket auth is validated on the first message inside handle_websocket
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

/// Handle WebSocket connection
async fn handle_websocket(socket: WebSocket, state: AppState) {
    use axum::extract::ws::Message;
    use futures::{sink::SinkExt, stream::StreamExt};
    
    let (mut sender, mut receiver) = socket.split();
    let client = state.shield_client.clone();
    let cache = state.decision_cache.clone();
    let metrics = state.metrics.clone();
    let config = state.config.clone();
    
    // Spawn task to handle incoming WebSocket messages
    let handle = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Parse the message as a classification request
                    match serde_json::from_str::<serde_json::Value>(&text) {
                        Ok(mut request) => {
                            metrics.total_requests.inc();
                            
                            // Extract and validate API key from message metadata
                            let api_key = request.get("metadata")
                                .and_then(|m| m.get("x-api-key"))
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let tenant_id = api_key.as_ref()
                                .and_then(|k| validate_api_key(&config.api_keys, k));
                            if api_key.is_some() && tenant_id.is_none() {
                                metrics.auth_failures.inc();
                                let _ = sender.send(Message::Text(r#"{"error":"Unauthorized"}"#.to_string())).await;
                                break;
                            }
                            
                            // Inject authenticated tenant_id into request metadata
                            if let Some(tenant) = tenant_id.as_ref() {
                                if let Some(metadata) = request.get_mut("metadata").and_then(|m| m.as_object_mut()) {
                                    metadata.insert("tenant_id".to_string(), serde_json::json!(tenant));
                                } else {
                                    request["metadata"] = serde_json::json!({"tenant_id": tenant});
                                }
                            }
                            
                            let cache_key = build_cache_key(&request, tenant_id.as_deref());
                            
                            if let Some(key) = &cache_key {
                                if let Some(entry) = cache.get(key) {
                                    if entry.is_valid(Duration::from_secs(60)) {
                                        metrics.cache_hits.inc();
                                        info!("WebSocket cache hit");
                                        if sender.send(Message::Text(entry.value.to_string())).await.is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                }
                            }

                            // Convert to gRPC request and send to Shield
                            let start = std::time::Instant::now();
                            match client.classify_stream(request.clone(), api_key.as_deref()).await {
                                Ok(response) => {
                                    metrics.shield_latency.observe(start.elapsed().as_millis() as f64);
                                    let response_json = serde_json::to_string(&response).unwrap_or_default();
                                    
                                    // Store in cache
                                    if let Some(key) = cache_key {
                                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&response_json) {
                                            cache.insert(key, CacheEntry {
                                                value,
                                                inserted_at: std::time::Instant::now(),
                                            });
                                        }
                                    }
                                    
                                    if sender.send(Message::Text(response_json)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    metrics.classification_errors.inc();
                                    metrics.shield_latency.observe(start.elapsed().as_millis() as f64);
                                    let error_str = e.to_string();
                                    error!("Classification error: {}", error_str);
                                    let error_msg = format!(r#"{{"error":"{}"}}"#, error_str);
                                    if sender.send(Message::Text(error_msg)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Invalid JSON received: {}", e);
                            let error_msg = format!(r#"{{"error":"Invalid JSON: {}"}}"#, e);
                            let _ = sender.send(Message::Text(error_msg)).await;
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("WebSocket connection closed by client");
                    break;
                }
                Ok(Message::Ping(data)) => {
                    if sender.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });
    
    if let Err(e) = handle.await {
        error!("WebSocket handler error: {}", e);
    }
}

/// Health check endpoint
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match state.shield_client.health_check().await {
        Ok(true) => axum::Json(serde_json::json!({
            "status": "healthy",
            "service": "axiomguard-proxy",
            "shield": "healthy",
            "version": env!("CARGO_PKG_VERSION"),
        })).into_response(),
        Ok(false) => {
            (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({
                "status": "degraded",
                "service": "axiomguard-proxy",
                "shield": "unhealthy",
                "version": env!("CARGO_PKG_VERSION"),
            }))).into_response()
        }
        Err(e) => {
            (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({
                "status": "degraded",
                "service": "axiomguard-proxy",
                "shield": "unreachable",
                "error": e.to_string(),
                "version": env!("CARGO_PKG_VERSION"),
            }))).into_response()
        }
    }
}

/// Single classification request handler
async fn classify_handler(
    State(state): State<AppState>,
    axum::Json(mut request): axum::Json<serde_json::Value>,
) -> Result<axum::response::Response, StatusCode> {
    state.metrics.total_requests.inc();
    
    let api_key = request.get("metadata")
        .and_then(|m| m.get("x-api-key"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let tenant_id = api_key.as_ref()
        .and_then(|k| validate_api_key(&state.config.api_keys, k));
    if api_key.is_some() && tenant_id.is_none() {
        state.metrics.auth_failures.inc();
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // Inject authenticated tenant_id into request metadata
    if let Some(tenant) = tenant_id.as_ref() {
        if let Some(metadata) = request.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            metadata.insert("tenant_id".to_string(), serde_json::json!(tenant));
        } else {
            request["metadata"] = serde_json::json!({"tenant_id": tenant});
        }
    }
    
    let cache_key = build_cache_key(&request, tenant_id.as_deref());
    
    // Check proxy cache
    if let Some(key) = &cache_key {
        if let Some(entry) = state.decision_cache.get(key) {
            if entry.is_valid(Duration::from_secs(60)) {
                state.metrics.cache_hits.inc();
                info!("Proxy cache hit for classify");
                return Ok(axum::Json(entry.value).into_response());
            }
        }
    }
    
    let start = std::time::Instant::now();
    Ok(match state.shield_client.classify_stream(request, api_key.as_deref()).await {
        Ok(response) => {
            state.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);
            // Store in cache
            if let Some(key) = cache_key {
                state.decision_cache.insert(key, CacheEntry {
                    value: response.clone(),
                    inserted_at: std::time::Instant::now(),
                });
            }
            axum::Json(response).into_response()
        }
        Err(e) => {
            state.metrics.classification_errors.inc();
            state.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);
            error!("Classification error: {}", e);
            let error_response = serde_json::json!({
                "error": e.to_string(),
                "decision": "HANDOVER",
                "reason": "Classification service unavailable"
            });
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, axum::Json(error_response)).into_response()
        }
    })
}

/// Metrics endpoint (Prometheus format)
async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = common::metrics::REGISTRY.gather();
    let mut buf = String::new();
    if let Err(e) = encoder.encode_utf8(&metric_families, &mut buf) {
        error!("Failed to encode metrics: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain")],
            format!("Failed to encode metrics: {}", e),
        );
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        buf,
    )
}

/// Build a cache key from a classification request
fn build_cache_key(request: &serde_json::Value, authenticated_tenant: Option<&str>) -> Option<String> {
    let tenant_id = authenticated_tenant
        .or_else(|| request.get("tenant_id").and_then(|v| v.as_str()))
        .or_else(|| request.get("metadata").and_then(|m| m.get("tenant_id")).and_then(|v| v.as_str()))
        .unwrap_or("default");
    let session_id = request.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
    let content = request.get("content")
        .and_then(|v| v.as_str())
        .or_else(|| request.get("content_chunk").and_then(|v| v.as_str()))
        .unwrap_or("");
    
    if content.is_empty() {
        return None;
    }
    
    Some(format!("{}:{}:{}", tenant_id, session_id, content))
}
