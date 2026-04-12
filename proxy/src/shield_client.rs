use proto::shield::shield_service_client::ShieldServiceClient;
use proto::shield::ShieldRequest;
use serde_json::Value;
use std::time::Duration;
use tonic::transport::Channel;
use tracing::{error, info};

/// Error type for Shield client operations
#[derive(Debug, Clone)]
pub enum ShieldClientError {
    ConnectionError(String),
    RequestError(String),
    Timeout,
}

impl std::fmt::Display for ShieldClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldClientError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            ShieldClientError::RequestError(msg) => write!(f, "Request error: {}", msg),
            ShieldClientError::Timeout => write!(f, "Request timeout"),
        }
    }
}

impl std::error::Error for ShieldClientError {}

/// gRPC client for the Shield service
#[derive(Clone)]
pub struct ShieldClient {
    inner: ShieldServiceClient<Channel>,
    timeout: Duration,
}

impl ShieldClient {
    /// Connect to the Shield service
    pub async fn connect(endpoint: &str) -> Result<Self, ShieldClientError> {
        info!("Connecting to Shield service at {}", endpoint);
        
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| ShieldClientError::ConnectionError(format!("Invalid endpoint: {}", e)))?
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
            .map_err(|e| ShieldClientError::ConnectionError(e.to_string()))?;
            
        let client = ShieldServiceClient::new(channel);
        
        info!("Connected to Shield service");
        
        Ok(Self {
            inner: client,
            timeout: Duration::from_millis(100),
        })
    }
    
    /// Classify a single request
    pub async fn classify_stream(&self, request: Value, api_key: Option<&str>) -> Result<Value, ShieldClientError> {
        use proto::shield::{ShieldRequest};
        use chrono::Utc;
        use uuid::Uuid;
        
        let session_id = request.get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
            
        let content_chunk = request.get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
            
        let mut metadata = request.get("metadata")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<std::collections::HashMap<String, String>>()
            })
            .unwrap_or_default();
        
        // Inject tenant_id from request metadata for multi-tenant isolation
        let tenant_id = request.get("tenant_id")
            .and_then(|v| v.as_str())
            .or_else(|| request.get("metadata").and_then(|m| m.get("tenant_id")).and_then(|v| v.as_str()))
            .unwrap_or("default");
        metadata.insert("x-tenant-id".to_string(), tenant_id.to_string());
        
        let grpc_request = ShieldRequest {
            session_id,
            content_chunk,
            metadata,
            timestamp: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: Utc::now().timestamp_subsec_nanos() as i32,
            }),
            request_id: Uuid::new_v4().to_string(),
            embedding: vec![], // Would be populated if pre-computed
        };
        
        // Create a new client for this request (since we need mutable access)
        let mut client = self.inner.clone();
        
        // Build tonic request and inject API key into gRPC metadata for service-layer auth
        let mut tonic_request = tonic::Request::new(grpc_request);
        if let Some(key) = api_key {
            if let Ok(val) = tonic::metadata::AsciiMetadataValue::try_from(key) {
                tonic_request.metadata_mut().insert("x-api-key", val);
            }
        }
        
        // Inject distributed tracing context
        let tracer = common::telemetry::tracer();
        let trace_context = common::telemetry::TraceContext::new()
            .with_baggage("tenant_id", tenant_id);
        let headers = tracer.inject_into_headers(&trace_context);
        if let Some(traceparent) = headers.get("traceparent") {
            if let Ok(val) = tonic::metadata::AsciiMetadataValue::try_from(traceparent.clone()) {
                tonic_request.metadata_mut().insert("traceparent", val);
            }
        }
        
        match client.classify_stream(tonic_request).await {
            Ok(response) => {
                let response = response.into_inner();
                Ok(shield_response_to_json(response))
            }
            Err(e) => {
                error!("gRPC error: {}", e);
                Err(ShieldClientError::RequestError(e.to_string()))
            }
        }
    }
    
    /// Explain a classification decision
    pub async fn explain_decision(
        &self,
        tenant_id: &str,
        content: &str,
        decision: &str,
        matched_rules: Vec<String>,
        ai_insights: Option<serde_json::Value>,
        tool_calls: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, ShieldClientError> {
        use proto::shield::{ExplainRequest, AiInsights, ToolCall};
        
        let decision_enum = match decision {
            "BLOCK" => 1,
            "HANDOVER" => 2,
            "FLAG" => 3,
            _ => 0,
        };
        
        let ai_insights_proto = ai_insights.and_then(|v| {
            Some(AiInsights {
                risk_level: v.get("risk_level")?.as_f64()? as f32,
                category: v.get("category")?.as_str()?.to_string(),
                anomalies: v.get("anomalies")?.as_array()?.iter()
                    .filter_map(|a| a.as_str().map(String::from))
                    .collect(),
                recommendations: v.get("recommendations")?.as_array()?.iter()
                    .filter_map(|a| a.as_str().map(String::from))
                    .collect(),
                model: v.get("model")?.as_str()?.to_string(),
                fallback_used: v.get("fallback_used")?.as_bool().unwrap_or(false),
            })
        });
        
        let tool_calls_proto: Vec<ToolCall> = tool_calls.into_iter().filter_map(|tc| {
            Some(ToolCall {
                tool_name: tc.get("tool_name")?.as_str()?.to_string(),
                arguments_json: tc.get("arguments_json")?.as_str()?.to_string(),
                target: tc.get("target")?.as_str().unwrap_or("").to_string(),
                risk_score: tc.get("risk_score")?.as_f64()? as f32,
            })
        }).collect();
        
        let mut client = self.inner.clone();
        let request = tonic::Request::new(ExplainRequest {
            tenant_id: tenant_id.to_string(),
            content: content.to_string(),
            decision: decision_enum,
            matched_rules,
            ai_insights: ai_insights_proto,
            tool_calls: tool_calls_proto,
        });
        
        match client.explain_decision(request).await {
            Ok(response) => {
                let response = response.into_inner();
                Ok(serde_json::json!({
                    "explanation": response.explanation,
                    "key_factors": response.key_factors,
                    "remediation": response.remediation,
                }))
            }
            Err(e) => {
                error!("Explain decision gRPC error: {}", e);
                Err(ShieldClientError::RequestError(e.to_string()))
            }
        }
    }
    
    /// Analyze root cause using RAG
    pub async fn analyze_root_cause(
        &self,
        tenant_id: &str,
        content: &str,
        session_id: &str,
        lookback_hours: i32,
    ) -> Result<serde_json::Value, ShieldClientError> {
        use proto::shield::RcaRequest;
        
        let mut client = self.inner.clone();
        let request = tonic::Request::new(RcaRequest {
            tenant_id: tenant_id.to_string(),
            content: content.to_string(),
            session_id: session_id.to_string(),
            lookback_hours,
        });
        
        match client.analyze_root_cause(request).await {
            Ok(response) => {
                let response = response.into_inner();
                Ok(serde_json::json!({
                    "root_cause": response.root_cause,
                    "confidence": response.confidence,
                    "related_events": response.related_events.iter().map(|e| serde_json::json!({
                        "event_id": e.event_id,
                        "decision_type": e.decision_type,
                        "similarity": e.similarity,
                        "summary": e.summary,
                    })).collect::<Vec<_>>(),
                    "recommendations": response.recommendations,
                }))
            }
            Err(e) => {
                error!("Analyze root cause gRPC error: {}", e);
                Err(ShieldClientError::RequestError(e.to_string()))
            }
        }
    }
    
    /// Check health of the Shield service
    pub async fn health_check(&self) -> Result<bool, ShieldClientError> {
        use proto::shield::HealthCheckRequest;
        
        let mut client = self.inner.clone();
        let request = tonic::Request::new(HealthCheckRequest {
            component: "".to_string(),
        });
        
        match client.health_check(request).await {
            Ok(response) => {
                let response = response.into_inner();
                Ok(response.status == 0) // HEALTHY = 0
            }
            Err(e) => {
                error!("Health check failed: {}", e);
                Ok(false)
            }
        }
    }
}

/// Convert ShieldResponse to JSON Value
fn shield_response_to_json(response: proto::shield::ShieldResponse) -> Value {
    let decision = match response.decision {
        0 => "ALLOW",
        1 => "BLOCK",
        2 => "HANDOVER",
        3 => "FLAG",
        _ => "UNKNOWN",
    };
    
    let ai_insights = response.ai_insights.map(|insights| {
        serde_json::json!({
            "risk_level": insights.risk_level,
            "category": insights.category,
            "anomalies": insights.anomalies,
            "recommendations": insights.recommendations,
            "model": insights.model,
            "fallback_used": insights.fallback_used,
        })
    });
    
    let tool_calls: Vec<Value> = response.tool_calls.iter().map(|tc| {
        serde_json::json!({
            "tool_name": tc.tool_name,
            "arguments_json": tc.arguments_json,
            "target": tc.target,
            "risk_score": tc.risk_score,
        })
    }).collect();
    
    serde_json::json!({
        "decision": decision,
        "confidence": response.confidence,
        "reason": response.reason,
        "matched_rules": response.matched_rules,
        "ai_insights": ai_insights,
        "processing_time_ms": response.processing_time_ms,
        "cached": response.cached,
        "tool_calls": tool_calls,
        "explanation": response.explanation,
    })
}
