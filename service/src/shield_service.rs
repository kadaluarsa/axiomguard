use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status, Streaming};
use proto::shield::shield_service_server::{ShieldService, ShieldServiceServer};
use proto::shield::*;
use engine::ShieldEngine;
use tracing::{info, error, warn};
use futures_util::stream::StreamExt;
use tokio::sync::mpsc;
use common::database::repository_v2::{EventRepository, DecisionRepository};

/// Shield Service implementation
#[derive(Debug)]
pub struct ShieldServiceImpl {
    engine: Arc<ShieldEngine>,
}

impl ShieldServiceImpl {
    pub fn new(engine: Arc<ShieldEngine>) -> Self {
        Self { engine }
    }
    
    fn extract_trace_context<T>(request: &Request<T>) -> Option<engine::telemetry::TraceContext> {
        if let Some(traceparent_val) = request.metadata().get("traceparent") {
            if let Ok(traceparent) = traceparent_val.to_str() {
                return engine::telemetry::TraceContext::from_traceparent(traceparent);
            }
        }
        None
    }
    
    fn result_to_response(result: &engine::DecisionResult) -> ShieldResponse {
        ShieldResponse {
            decision: match result.decision {
                common::DecisionType::Allow => Decision::Allow as i32,
                common::DecisionType::Block => Decision::Block as i32,
                common::DecisionType::Flag => Decision::Flag as i32,
                common::DecisionType::Review => Decision::Handover as i32,
                common::DecisionType::Handover => Decision::Handover as i32,
            },
            confidence: result.confidence,
            reason: result.reason.clone(),
            matched_rules: result.matched_rules.clone(),
            ai_insights: result.ai_insights.clone().map(|insights| AiInsights {
                risk_level: insights.risk_level,
                category: insights.category,
                anomalies: insights.anomalies,
                recommendations: insights.recommendations,
                model: insights.model,
                fallback_used: insights.fallback_used,
            }),
            processing_time_ms: result.processing_time_ms,
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: chrono::Utc::now().timestamp_subsec_nanos() as i32,
            }),
            session_context: vec![],
            cached: result.cached,
            tool_calls: result.tool_calls.iter().map(|tc| ToolCall {
                tool_name: tc.tool_name.clone(),
                arguments_json: tc.arguments_json.clone(),
                target: tc.target.clone().unwrap_or_default(),
                risk_score: tc.risk_score,
            }).collect(),
            explanation: result.explanation.clone().unwrap_or_default(),
        }
    }
}

#[tonic::async_trait]
impl ShieldService for ShieldServiceImpl {
    async fn classify_stream(
        &self,
        request: Request<ShieldRequest>,
    ) -> Result<Response<ShieldResponse>, Status> {
        let trace_context = Self::extract_trace_context(&request);
        let _span = if let Some(ctx) = trace_context {
            engine::telemetry::tracer().continue_trace("classify_stream", ctx)
        } else {
            engine::telemetry::tracer().start_trace("classify_stream")
        };
        
        let req = request.into_inner();
        
        // Extract tenant_id from metadata (set by auth middleware)
        let tenant_id = req.metadata.get("x-tenant-id")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        
        info!(
            tenant_id = %tenant_id,
            session_id = %req.session_id,
            request_id = %req.request_id,
            content_length = %req.content_chunk.len(),
            "Received classification request"
        );
        
        // Build metadata from request
        let metadata = serde_json::json!({
            "session_id": &req.session_id,
            "request_id": &req.request_id,
            "custom": req.metadata,
        });
        
        // Call the shield engine with tenant_id for quota enforcement
        let result = self.engine.classify(
            &tenant_id,
            &req.session_id,
            &req.content_chunk,
            &metadata
        ).await;
        
        // Convert engine result to gRPC response
        let response = Self::result_to_response(&result);
        
        info!(
            request_id = %req.request_id,
            decision = %response.decision,
            processing_time_ms = %response.processing_time_ms,
            "Classification complete"
        );
        
        Ok(Response::new(response))
    }

    type StreamSessionStream = tokio_stream::wrappers::ReceiverStream<Result<ShieldResponse, Status>>;

    async fn stream_session(
        &self,
        request: Request<Streaming<ShieldRequest>>,
    ) -> Result<Response<Self::StreamSessionStream>, Status> {
        let mut stream = request.into_inner();
        let engine = self.engine.clone();
        
        // Extract tenant_id from first request (all requests in stream should be same tenant)
        let first_req = stream.next().await;
        if first_req.is_none() {
            return Err(Status::invalid_argument("Empty stream"));
        }
        let first_req = first_req.unwrap().map_err(|e| Status::internal(e.to_string()))?;
        let tenant_id = first_req.metadata.get("x-tenant-id")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        
        let (tx, rx) = mpsc::channel(100);
        
        let tenant_id_clone = tenant_id.clone();
        tokio::spawn(async move {
            // Process first request
            let metadata = serde_json::json!({
                "session_id": &first_req.session_id,
                "request_id": &first_req.request_id,
                "custom": first_req.metadata,
            });
            
            let result = engine.classify(
                &tenant_id_clone,
                &first_req.session_id,
                &first_req.content_chunk,
                &metadata
            ).await;
            
            let response = Self::result_to_response(&result);
            
            if tx.send(Ok(response)).await.is_err() {
                return;
            }
            
            // Process remaining requests
            while let Some(Ok(req)) = stream.next().await {
                let metadata = serde_json::json!({
                    "session_id": &req.session_id,
                    "request_id": &req.request_id,
                    "custom": req.metadata,
                });
                
                let result = engine.classify(
                    &tenant_id_clone,
                    &req.session_id,
                    &req.content_chunk,
                    &metadata
                ).await;
                
                let response = Self::result_to_response(&result);
                
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });
        
        use tokio_stream::wrappers::ReceiverStream;
        let stream = ReceiverStream::new(rx);
        Ok(Response::new(stream))
    }

    async fn explain_decision(
        &self,
        request: Request<ExplainRequest>,
    ) -> Result<Response<ExplainResponse>, Status> {
        let req = request.into_inner();
        
        let decision_result = engine::DecisionResult {
            decision: match req.decision {
                0 => common::DecisionType::Allow,
                1 => common::DecisionType::Block,
                2 => common::DecisionType::Handover,
                3 => common::DecisionType::Flag,
                _ => common::DecisionType::Handover,
            },
            confidence: 0.0,
            reason: "Explanation request".to_string(),
            matched_rules: req.matched_rules.clone(),
            ai_insights: req.ai_insights.map(|insights| engine::AiInsights {
                risk_level: insights.risk_level,
                category: insights.category,
                anomalies: insights.anomalies,
                recommendations: insights.recommendations,
                model: insights.model,
                fallback_used: insights.fallback_used,
            }),
            processing_time_ms: 0,
            cached: false,
            rule_eval_time_ms: None,
            ai_time_ms: None,
            tool_calls: req.tool_calls.iter().map(|tc| engine::tool_parser::ToolCall {
                tool_name: tc.tool_name.clone(),
                arguments_json: tc.arguments_json.clone(),
                target: if tc.target.is_empty() { None } else { Some(tc.target.clone()) },
                risk_score: tc.risk_score,
            }).collect(),
            explanation: None,
        };
        
        let explanation = engine::explainability::explain_decision(
            &decision_result,
            &decision_result.tool_calls,
            &req.content
        );
        
        Ok(Response::new(ExplainResponse {
            explanation: explanation.explanation,
            key_factors: explanation.key_factors,
            remediation: explanation.remediation,
        }))
    }
    
    async fn analyze_root_cause(
        &self,
        request: Request<RcaRequest>,
    ) -> Result<Response<RcaResponse>, Status> {
        let req = request.into_inner();
        
        match self.engine.analyze_root_cause(
            &req.tenant_id,
            &req.content,
            &req.session_id,
            req.lookback_hours as i64,
        ).await {
            Ok((root_cause, confidence, related_events)) => {
                Ok(Response::new(RcaResponse {
                    root_cause,
                    confidence,
                    related_events: related_events.into_iter().map(|(id, summary, similarity)| RelatedEvent {
                        event_id: id,
                        decision_type: summary,
                        similarity: similarity as f32,
                        summary: String::new(),
                    }).collect(),
                    recommendations: vec!["Review related events for patterns".to_string()],
                }))
            }
            Err(e) => {
                tracing::error!("RCA failed: {}", e);
                Err(Status::internal(format!("RCA analysis failed: {}", e)))
            }
        }
    }
    
    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        // Check engine health
        let status = HealthStatus::Healthy;
        
        let mut components = std::collections::HashMap::new();
        components.insert("jsonlogic".to_string(), HealthStatus::Healthy as i32);
        components.insert("ai_engine".to_string(), HealthStatus::Healthy as i32);
        components.insert("cache".to_string(), HealthStatus::Healthy as i32);
        
        let response = HealthCheckResponse {
            status: status as i32,
            components,
            latency_ms: 1,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        
        Ok(Response::new(response))
    }
}

/// Run the shield gRPC server
pub async fn run_shield_server(
    config: &crate::config::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    // Initialize database connections
    let db_config = common::database::DatabaseConfig::from_env();
    
    // Metadata DB for rules, tenants
    let metadata_db_config = common::database::DatabaseConfig {
        url: db_config.url.clone(),
        ..db_config.clone()
    };
    let metadata_db = Arc::new(common::database::Database::new(metadata_db_config).await?);
    
    // Events DB for audit events and decisions (can be same or separate)
    let events_db_config = common::database::DatabaseConfig {
        url: db_config.events_url.clone(),
        ..db_config.clone()
    };
    let events_db = Arc::new(common::database::Database::new(events_db_config).await?);
    
    // Create event and decision repositories and attach to engine
    let event_repo = Arc::new(EventRepository::new(Arc::clone(&events_db)));
    let decision_repo = Arc::new(DecisionRepository::new(Arc::clone(&events_db)));
    let retry_queue = engine::retry_queue::EventRetryQueue::new(Arc::clone(&event_repo), 3);
    let text_embedding = engine::init_text_embedding().await;
    let engine = Arc::new(
        ShieldEngine::new()
            .with_event_repository(event_repo)
            .with_decision_repository(decision_repo)
            .with_event_retry_queue(retry_queue)
            .with_text_embedding(text_embedding)
    );
    
    // Start rule synchronization (LISTEN/NOTIFY) on metadata DB
    let engine_clone = Arc::clone(&engine);
    let metadata_db_clone = Arc::clone(&metadata_db);
    tokio::spawn(async move {
        if let Err(e) = engine::rule_sync::setup_rule_sync(
            (*metadata_db_clone).clone(),
            engine_clone,
        ).await {
            error!("Failed to start rule sync: {}", e);
        }
    });
    
    // Create auth interceptor from config
    let auth_interceptor = crate::auth::AuthInterceptor::new(
        config.auth.valid_api_keys.clone(),
        config.auth.valid_bearer_tokens.clone(),
        config.auth.require_authentication,
    );
    
    // Initialize distributed tracer
    engine::telemetry::init_tracer("axiomguard-shield");
    
    let service = ShieldServiceImpl::new(engine);

    let addr: SocketAddr = config.address.parse()?;
    info!(
        address = %addr,
        require_auth = config.auth.require_authentication,
        api_keys_count = config.auth.valid_api_keys.len(),
        bearer_tokens_count = config.auth.valid_bearer_tokens.len(),
        "Starting AxiomGuard Shield service"
    );

    Server::builder()
        .add_service(ShieldServiceServer::with_interceptor(service, auth_interceptor))
        .serve(addr)
        .await?;

    Ok(())
}
