use std::sync::Arc;
use tokio::sync::RwLock;
use common::*;
use common::database::repository_v2::{EventRepository, Event as DbEvent, DecisionRepository, Decision as DbDecision};
use sqlx::Row;
use chrono::Utc;
use prometheus::{IntCounter, Histogram, opts};
use std::time::{Duration, Instant};
use serde_json::Value;
pub mod ai;
pub mod circuit_breaker;
pub mod event_broadcaster;
pub mod jsonlogic;
pub mod pii;
pub mod quota;
pub mod retention;
pub mod retry_queue;
pub mod rule_sync;
pub mod routing;
pub mod shutdown;
pub mod tool_parser;
pub mod explainability;
pub mod ml_layer;
pub mod z3_engine;

// Re-export telemetry from common for backward compatibility
pub use common::telemetry as telemetry;

#[cfg(test)]
mod concurrency_tests;

use jsonlogic::JsonLogicEngine;
use quota::{QuotaManager, ClassificationType, QuotaError};
use routing::{ClassificationRouter, RoutingMode};

/// The Shield Engine - Core classification engine with JSONLogic support
pub struct ShieldEngine {
    /// JSONLogic engine for deterministic rule evaluation
    jsonlogic: JsonLogicEngine,
    /// Active security rules
    rules: Arc<RwLock<Vec<SecurityRule>>>,
    /// Processing metrics
    metrics: EngineMetrics,
    /// AI engine for ML-based classification
    ai_engine: ai::AiEngine,
    /// Event broadcaster for real-time updates
    event_broadcaster: event_broadcaster::EventBroadcaster,
    /// Decision cache for fast lookups
    decision_cache: moka::sync::Cache<String, DecisionResult>,
    /// Event retry queue for resilient persistence
    event_retry_queue: Option<retry_queue::EventRetryQueue>,
    /// Deterministic compliance mode (disables AI, external calls)
    compliance_mode: bool,
    /// Decisive timer timeout
    timeout_ms: u64,
    /// Smart router for deterministic vs AI classification
    router: ClassificationRouter,
    /// Quota manager for tenant resource control
    quota_manager: Arc<QuotaManager>,
    /// Event repository for database persistence
    event_repository: Option<Arc<EventRepository>>,
    /// Decision repository for decision snapshotting
    decision_repository: Option<Arc<DecisionRepository>>,
    /// Optional semantic text embedding model
    text_embedding: Option<Arc<fastembed::TextEmbedding>>,
    /// Z3 formal verification engine
    z3_engine: Option<crate::z3_engine::Z3Engine>,
    /// ML layer for PII, injection detection, and risk scoring
    ml_layer: ml_layer::MlLayer,
    /// Stop evaluating rules after first BLOCK match (for performance)
    early_exit_on_block: bool,
}

impl std::fmt::Debug for ShieldEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShieldEngine")
            .field("jsonlogic", &self.jsonlogic)
            .field("rules", &self.rules)
            .field("metrics", &self.metrics)
            .field("ai_engine", &self.ai_engine)
            .field("event_broadcaster", &self.event_broadcaster)
            .field("decision_cache", &self.decision_cache)
            .field("timeout_ms", &self.timeout_ms)
            .field("router", &self.router)
            .field("quota_manager", &self.quota_manager)
            .field("event_repository", &self.event_repository)
            .field("decision_repository", &self.decision_repository)
            .field("text_embedding", &self.text_embedding.is_some())
            .field("ml_layer", &self.ml_layer)
            .field("early_exit_on_block", &self.early_exit_on_block)
            .finish()
    }
}

/// Security rule with JSONLogic
#[derive(Debug, Clone)]
pub struct SecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    /// JSONLogic rule as JSON value (for API/persistence)
    pub logic: serde_json::Value,
    /// Pre-compiled rule (populated at load time)
    pub compiled_rule: Option<jsonlogic::Rule>,
    pub decision: DecisionType,
    pub priority: i32,
    pub is_active: bool,
    pub version: i32,
}

impl SecurityRule {
    pub fn compile(&mut self) {
        if self.compiled_rule.is_none() {
            self.compiled_rule = serde_json::from_value(self.logic.clone()).ok();
        }
    }
}

/// Classification decision result
#[derive(Debug, Clone)]
pub struct DecisionResult {
    pub decision: DecisionType,
    pub confidence: f32,
    pub reason: String,
    pub matched_rules: Vec<String>,
    pub ai_insights: Option<AiInsights>,
    pub verification_result: Option<String>,
    pub z3_verified: bool,
    pub processing_time_ms: u64,
    pub cached: bool,
    pub rule_eval_time_ms: Option<u64>,
    pub ai_time_ms: Option<u64>,
    pub tool_calls: Vec<tool_parser::ToolCall>,
    pub explanation: Option<String>,
    /// ML layer results
    pub pii_detected: bool,
    pub injection_detected: bool,
    pub injection_confidence: f32,
    pub ml_risk_score: f32,
}

/// AI insights
#[derive(Debug, Clone, serde::Serialize)]
pub struct AiInsights {
    pub risk_level: f32,
    pub category: String,
    pub anomalies: Vec<String>,
    pub recommendations: Vec<String>,
    pub model: String,
    pub fallback_used: bool,
}

/// Internal result from rule evaluation
#[derive(Debug, Clone)]
struct RuleEvaluationResult {
    pub decision: Option<DecisionType>,
    pub reason: Option<String>,
    pub matched_rules: Vec<String>,
    pub priority: Option<i32>,
}

impl RuleEvaluationResult {
    fn new() -> Self {
        Self {
            decision: None,
            reason: None,
            matched_rules: Vec::new(),
            priority: None,
        }
    }
}

#[derive(Debug, Clone)]
struct EngineMetrics {
    total_events: IntCounter,
    processed_events: IntCounter,
    blocked_events: IntCounter,
    handed_over_events: IntCounter,
    flagged_events: IntCounter,
    cache_hits: IntCounter,
    timeouts: IntCounter,
    rule_evaluation_time: Histogram,
    ai_processing_time: Histogram,
    total_processing_time: Histogram,
}

impl EngineMetrics {
    fn new() -> Self {
        let registry = common::metrics::REGISTRY.clone();
        
        let total_events = IntCounter::with_opts(opts!(
            "axiomguard_shield_total_events",
            "Total number of events received by Shield"
        )).unwrap();
        
        let processed_events = IntCounter::with_opts(opts!(
            "axiomguard_shield_processed_events",
            "Number of events processed"
        )).unwrap();
        
        let blocked_events = IntCounter::with_opts(opts!(
            "axiomguard_shield_blocked_events",
            "Number of events blocked"
        )).unwrap();
        
        let handed_over_events = IntCounter::with_opts(opts!(
            "axiomguard_shield_handed_over_events",
            "Number of events handed to human operators"
        )).unwrap();
        
        let flagged_events = IntCounter::with_opts(opts!(
            "axiomguard_shield_flagged_events",
            "Number of events flagged"
        )).unwrap();
        
        let cache_hits = IntCounter::with_opts(opts!(
            "axiomguard_shield_cache_hits",
            "Number of cache hits"
        )).unwrap();
        
        let timeouts = IntCounter::with_opts(opts!(
            "axiomguard_shield_timeouts",
            "Number of requests that timed out"
        )).unwrap();
        
        let rule_evaluation_time = Histogram::with_opts(prometheus::HistogramOpts::from(opts!(
            "axiomguard_shield_rule_evaluation_time_ms",
            "Rule evaluation time in milliseconds"
        ))).unwrap();
        
        let ai_processing_time = Histogram::with_opts(prometheus::HistogramOpts::from(opts!(
            "axiomguard_shield_ai_processing_time_ms",
            "AI processing time in milliseconds"
        ))).unwrap();
        
        let total_processing_time = Histogram::with_opts(prometheus::HistogramOpts::from(opts!(
            "axiomguard_shield_total_processing_time_ms",
            "Total event processing time in milliseconds"
        ))).unwrap();
        
        // Ignore registration errors (for tests)
        let _ = registry.register(Box::new(total_events.clone()));
        let _ = registry.register(Box::new(processed_events.clone()));
        let _ = registry.register(Box::new(blocked_events.clone()));
        let _ = registry.register(Box::new(handed_over_events.clone()));
        let _ = registry.register(Box::new(flagged_events.clone()));
        let _ = registry.register(Box::new(cache_hits.clone()));
        let _ = registry.register(Box::new(timeouts.clone()));
        let _ = registry.register(Box::new(rule_evaluation_time.clone()));
        let _ = registry.register(Box::new(ai_processing_time.clone()));
        let _ = registry.register(Box::new(total_processing_time.clone()));
        
        Self {
            total_events,
            processed_events,
            blocked_events,
            handed_over_events,
            flagged_events,
            cache_hits,
            timeouts,
            rule_evaluation_time,
            ai_processing_time,
            total_processing_time,
        }
    }
}

impl Default for ShieldEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldEngine {
    pub fn new() -> Self {
        Self::with_routing_mode(RoutingMode::Sequential)
    }
    
    /// Create with specific routing mode
    pub fn with_routing_mode(mode: RoutingMode) -> Self {
        let metrics = EngineMetrics::new();
        let cache = moka::sync::Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(300))
            .build();
        
        Self {
            jsonlogic: JsonLogicEngine::new(),
            rules: Arc::new(RwLock::new(Vec::new())),
            metrics,
            ai_engine: ai::AiEngine::new(),
            event_broadcaster: event_broadcaster::EventBroadcaster::new(),
            decision_cache: cache,
            event_retry_queue: None,
            compliance_mode: false,
            timeout_ms: 100, // 100ms decisive timer
            router: ClassificationRouter::new(mode),
            quota_manager: Arc::new(QuotaManager::new()),
            event_repository: None,
            decision_repository: None,
            text_embedding: None,
            ml_layer: ml_layer::MlLayer::new(),
            early_exit_on_block: false,
            z3_engine: None,
        }
    }
    
    /// Create with custom quota manager
    pub fn with_quota_manager(mut self, quota_manager: Arc<QuotaManager>) -> Self {
        self.quota_manager = quota_manager;
        self
    }
    
    /// Attach an event repository for database persistence
    pub fn with_event_repository(mut self, repo: Arc<EventRepository>) -> Self {
        self.event_repository = Some(repo);
        self
    }
    
    /// Attach a decision repository for decision snapshotting
    pub fn with_decision_repository(mut self, repo: Arc<DecisionRepository>) -> Self {
        self.decision_repository = Some(repo);
        self
    }

    /// Enable early exit: stop rule evaluation after first BLOCK match.
    /// Improves performance but collects fewer matched rules for audit.
    pub fn with_early_exit_on_block(mut self, enabled: bool) -> Self {
        self.early_exit_on_block = enabled;
        self
    }
    
    /// Attach an event retry queue for resilient persistence
    pub fn with_event_retry_queue(mut self, queue: retry_queue::EventRetryQueue) -> Self {
        self.event_retry_queue = Some(queue);
        self
    }
    
    /// Enable deterministic compliance mode (rules-only, no AI, no external calls)
    pub fn with_compliance_mode(mut self, enabled: bool) -> Self {
        self.compliance_mode = enabled;
        if enabled {
            self.router = ClassificationRouter::new(RoutingMode::RulesOnly);
            tracing::info!("Compliance mode enabled: AI disabled, rules-only routing enforced");
        }
        self
    }
    
    /// Attach a semantic text embedding model
    pub fn with_text_embedding(mut self, embedder: Option<Arc<fastembed::TextEmbedding>>) -> Self {
        self.text_embedding = embedder;
        self
    }

    /// Attach a Z3 formal verification engine
    pub fn with_z3_engine(mut self, engine: Option<crate::z3_engine::Z3Engine>) -> Self {
        self.z3_engine = engine;
        self
    }
    
    /// Process an event with decisive timer enforcement
    /// 
    /// # Arguments
    /// * `tenant_id` - Tenant identifier for quota enforcement
    /// * `session_id` - Session identifier for caching
    /// * `content` - Content to classify
    /// * `metadata` - Additional metadata for rule evaluation
    pub async fn classify(&self, tenant_id: &str, session_id: &str, content: &str, metadata: &serde_json::Value) -> DecisionResult {
        let start = Instant::now();
        self.metrics.total_events.inc();
        
        // Check content size limit (10KB for realtime)
        if content.len() > 10_000 {
            return DecisionResult {
                decision: DecisionType::Handover,
                confidence: 0.0,
                reason: "Content too large: max 10KB for realtime classification".to_string(),
                matched_rules: vec![],
                ai_insights: None,
                verification_result: None,
                z3_verified: false,
                processing_time_ms: start.elapsed().as_millis() as u64,
                cached: false,
                rule_eval_time_ms: None,
                ai_time_ms: None,
                tool_calls: vec![],
                explanation: None,
                pii_detected: false,
                injection_detected: false,
                injection_confidence: 0.0,
                ml_risk_score: 0.0,
            };
        }
        
        let cache_key = format!("{}:{}:{}", tenant_id, session_id, hash_content(content));
        if let Some(cached) = self.decision_cache.get(&cache_key) {
            self.metrics.cache_hits.inc();
            let mut result = cached.clone();
            result.cached = true;
            result.processing_time_ms = start.elapsed().as_millis() as u64;
            return result;
        }
        
        // Check quota for realtime classification
        match self.quota_manager.check_classification_quota(
            tenant_id,
            ClassificationType::Realtime,
            content,
        ).await {
            Ok(_) => {},  // Quota available
            Err(QuotaError::DailyRealtimeLimitExceeded { used, limit, resets_in }) => {
                return DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!(
                        "Quota exceeded: {}/{} realtime classifications today. Resets in {:?}. Upgrade at https://axiomguard.com/upgrade",
                        used, limit, resets_in
                    ),
                    matched_rules: vec![],
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: None,
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                };
            }
            Err(QuotaError::RateLimitExceeded { retry_after, .. }) => {
                return DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!(
                        "Rate limit exceeded. Retry after {:?}",
                        retry_after
                    ),
                    matched_rules: vec![],
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: None,
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                };
            }
            Err(QuotaError::ContentTooLarge { size, max }) => {
                return DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!(
                        "Content too large: {} bytes (max: {} bytes). Upgrade for larger content.",
                        size, max
                    ),
                    matched_rules: vec![],
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: None,
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                };
            }
            Err(_) => {
                // Other quota errors - still process but log
                tracing::warn!("Quota check failed, proceeding with classification");
            }
        }
        
        // Create timeout future
        let timeout = tokio::time::timeout(
            Duration::from_millis(self.timeout_ms),
            self.do_classify(tenant_id, session_id, content, metadata)
        );
        
        let result = match timeout.await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                tracing::error!("Classification error: {}", e);
                self.create_fallback_result("Classification error", start.elapsed())
            }
            Err(_) => {
                // Timeout - handover to human
                self.metrics.timeouts.inc();
                self.create_fallback_result("Processing timeout - handover required", start.elapsed())
            }
        };
        
        let processing_time = start.elapsed();
        let mut final_result = result;
        final_result.processing_time_ms = processing_time.as_millis() as u64;
        
        // Parse tool calls from content
        final_result.tool_calls = tool_parser::parse_tool_calls(content);
        
        // Generate explanation
        let explanation = explainability::explain_decision(&final_result, &final_result.tool_calls, content);
        final_result.explanation = Some(explanation.explanation);
        
        // Update metrics
        self.update_metrics(&final_result);
        
        // Cache the result
        self.decision_cache.insert(cache_key, final_result.clone());
        
        // Broadcast event
        let broadcast_event = common::AuditEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            source: session_id.to_string(),
            event_type: "classification".to_string(),
            data: serde_json::json!({
                "content": content,
                "metadata": metadata,
                "decision": format!("{:?}", final_result.decision),
            }),
        };
        self.event_broadcaster.broadcast_event(broadcast_event.clone());
        
        // Build rule version snapshot from active rules
        let rule_versions = {
            let rules = self.rules.read().await;
            let versions: serde_json::Map<String, serde_json::Value> = rules
                .iter()
                .filter(|r| r.is_active)
                .map(|r| (r.id.clone(), serde_json::json!({"version": r.version, "name": r.name})))
                .collect();
            serde_json::Value::Object(versions)
        };
        
        // Persist event and decision to database
        if let Some(repo) = &self.event_repository {
            let repo = Arc::clone(repo);
            let decision_repo = self.decision_repository.as_ref().map(Arc::clone);
            let retry_queue = self.event_retry_queue.clone();
            let tenant_id_str = tenant_id.to_string();
            let session_id_str = session_id.to_string();
            let decision = final_result.decision.clone();
            let confidence = final_result.confidence;
            let processing_time_ms = final_result.processing_time_ms;
            let rule_eval_time_ms = final_result.rule_eval_time_ms;
            let ai_time_ms = final_result.ai_time_ms;
            let cached = final_result.cached;
            let reason_clone = final_result.reason.clone();
            let content_clone = content.to_string();
            let metadata_clone = metadata.clone();
            let ai_insights = final_result.ai_insights.clone();
            let matched_rules = final_result.matched_rules.clone();
            let text_embedding = self.text_embedding.clone();
            let event_id = broadcast_event.id;
            let event_timestamp = broadcast_event.timestamp;
            let rule_versions_clone = rule_versions.clone();
            
            tokio::spawn(async move {
                let embedding = match text_embedding {
                    Some(embedder) => {
                        let content_for_embed = content_clone.clone();
                        match tokio::task::spawn_blocking(move || {
                            embedder.embed(vec![content_for_embed], None)
                        }).await {
                            Ok(Ok(vectors)) => vectors.into_iter().next().unwrap_or_else(|| generate_embedding(&content_clone)),
                            Ok(Err(e)) => {
                                tracing::warn!("Embedding model failed: {}, falling back to hash embedding", e);
                                generate_embedding(&content_clone)
                            }
                            Err(e) => {
                                tracing::warn!("Embedding task panicked: {}, falling back to hash embedding", e);
                                generate_embedding(&content_clone)
                            }
                        }
                    }
                    None => generate_embedding(&content_clone),
                };
                let event = DbEvent {
                    id: event_id,
                    tenant_id: match uuid::Uuid::parse_str(&tenant_id_str) {
                        Ok(id) => id,
                        Err(_) => uuid::Uuid::nil(),
                    },
                    event_type: "classification".to_string(),
                    source: session_id_str.clone(),
                    data: serde_json::json!({
                        "content": content_clone,
                        "metadata": metadata_clone,
                        "decision": format!("{:?}", decision),
                        "matched_rules": matched_rules,
                        "ai_insights": ai_insights,
                        "action": match decision {
                            DecisionType::Block => "blocked",
                            DecisionType::Flag => "flagged",
                            DecisionType::Allow => "allowed",
                            _ => "flagged",
                        },
                        "severity": match decision {
                            DecisionType::Block => "critical",
                            DecisionType::Flag => "high",
                            DecisionType::Allow => "low",
                            _ => "medium",
                        },
                        "agentId": metadata_clone.get("agent_id").and_then(|v| v.as_str()).unwrap_or("shield-engine"),
                        "ruleId": matched_rules.first().cloned().unwrap_or_default(),
                        "ruleName": matched_rules.first().cloned().unwrap_or_default(),
                        "path": metadata_clone.get("path").and_then(|v| v.as_str()).unwrap_or("/api/v1/classify"),
                        "method": "POST",
                        "clientIp": metadata_clone.get("ip").or_else(|| metadata_clone.get("client_ip")).and_then(|v| v.as_str()).unwrap_or("127.0.0.1"),
                        "traceId": format!("trace_{}", event_id),
                    }),
                    session_id: Some(session_id_str),
                    user_id: None,
                    decision_type: Some(format!("{:?}", decision)),
                    confidence: Some(confidence),
                    processing_time_ms: Some(processing_time_ms as i32),
                    timestamp: event_timestamp,
                    created_at: Utc::now(),
                };
                
                // Use retry queue if available, otherwise direct insert
                if let Some(queue) = retry_queue {
                    queue.submit(event, embedding);
                } else if let Err(e) = repo.insert_with_embedding(&event, &embedding).await {
                    tracing::error!("Failed to persist event: {}", e);
                }
                
                // Persist decision snapshot
                if let Some(drepo) = decision_repo {
                    let db_decision = DbDecision {
                        id: uuid::Uuid::new_v4(),
                        tenant_id: match uuid::Uuid::parse_str(&tenant_id_str) {
                            Ok(id) => id,
                            Err(_) => uuid::Uuid::nil(),
                        },
                        event_id,
                        decision_type: format!("{:?}", decision).to_uppercase(),
                        confidence: confidence as f64,
                        reasoning: Some(reason_clone),
                        rules_applied: Some(serde_json::json!(matched_rules)),
                        rule_versions: Some(rule_versions_clone),
                        ai_insights: ai_insights.as_ref().map(|i| serde_json::to_value(i).unwrap_or_default()),
                        processing_time_ms: Some(processing_time_ms as i32),
                        rule_eval_time_ms: rule_eval_time_ms.map(|v| v as i32),
                        ai_time_ms: ai_time_ms.map(|v| v as i32),
                        cache_hit: Some(cached),
                        ai_model: ai_insights.as_ref().map(|i| i.model.clone()),
                        ai_fallback_used: ai_insights.as_ref().map(|i| i.fallback_used),
                        timestamp: event_timestamp,
                        created_at: Utc::now(),
                    };
                    if let Err(e) = drepo.insert(&db_decision).await {
                        tracing::error!("Failed to persist decision: {}", e);
                    }
                }
            });
        }
        
        final_result
    }
    
    /// Perform root cause analysis using RAG over historical events
    pub async fn analyze_root_cause(
        &self,
        tenant_id: &str,
        content: &str,
        session_id: &str,
        lookback_hours: i64,
    ) -> Result<(String, f32, Vec<(String, String, f64)>), Box<dyn std::error::Error>> {
        if self.compliance_mode {
            return Ok((
                "RCA unavailable in compliance mode: AI analysis is disabled".to_string(),
                0.0,
                vec![],
            ));
        }
        
        let tenant_uuid = match uuid::Uuid::parse_str(tenant_id) {
            Ok(id) => id,
            Err(_) => uuid::Uuid::nil(),
        };
        
        // Generate embedding for the content
        let embedding = match self.text_embedding.clone() {
            Some(embedder) => {
                let content_for_embed = content.to_string();
                match tokio::task::spawn_blocking(move || {
                    embedder.embed(vec![content_for_embed], None)
                }).await {
                    Ok(Ok(vectors)) => vectors.into_iter().next().unwrap_or_else(|| generate_embedding(content)),
                    Ok(Err(e)) => {
                        tracing::warn!("Embedding model failed for RCA: {}, falling back", e);
                        generate_embedding(content)
                    }
                    Err(e) => {
                        tracing::warn!("Embedding task panicked for RCA: {}, falling back", e);
                        generate_embedding(content)
                    }
                }
            }
            None => generate_embedding(content),
        };
        
        // Search for similar events
        let mut related_events = Vec::new();
        if let Some(ref repo) = self.event_repository {
            match repo.find_similar(tenant_uuid, &embedding, 0.7, 5).await {
                Ok(similar) => {
                    for (event, similarity) in similar {
                        let summary = format!(
                            "{} | decision: {} | source: {}",
                            event.event_type,
                            event.decision_type.as_deref().unwrap_or("unknown"),
                            event.source
                        );
                        related_events.push((event.id.to_string(), summary, similarity));
                    }
                }
                Err(e) => {
                    tracing::warn!("Vector search failed for RCA: {}", e);
                }
            }
        }
        
        // Build RCA prompt with related events context
        let mut rca_prompt = format!(
            "Analyze the following security event and identify the root cause.\n\nEvent content: {}\nSession ID: {}\nLookback: {} hours\n\n",
            content, session_id, lookback_hours
        );
        
        if !related_events.is_empty() {
            rca_prompt.push_str("Related historical events:\n");
            for (id, summary, similarity) in &related_events {
                rca_prompt.push_str(&format!("- [{}] {} (similarity: {:.2})\n", id, summary, similarity));
            }
        }
        
        rca_prompt.push_str("\nProvide a concise root cause analysis in 1-2 sentences.");
        
        // Use AI engine for RCA (reuse classify_text with the prompt as content)
        let root_cause = match self.ai_engine.classify_text(&rca_prompt).await {
            Ok(classification) => {
                let cause = if classification.recommendations.is_empty() {
                    classification.category
                } else {
                    classification.recommendations.join(". ")
                };
                (cause, classification.confidence)
            }
            Err(e) => {
                tracing::warn!("AI RCA failed: {}, using heuristic fallback", e);
                (format!("Unable to determine root cause automatically. Error: {}", e), 0.0)
            }
        };
        
        Ok((root_cause.0, root_cause.1, related_events))
    }
    
    async fn do_classify(&self, tenant_id: &str, session_id: &str, content: &str, metadata: &serde_json::Value) -> Result<DecisionResult, Box<dyn std::error::Error>> {
        let start = Instant::now();

        // ML pre-processing: PII sanitization + injection detection (<2ms)
        let (_sanitized, pii_detected) = self.ml_layer.sanitize_pii(content);
        let (injection_detected, injection_confidence) = self.ml_layer.detect_injection(content);

        // Short-circuit: block high-confidence injection without expensive AI call
        if injection_detected && injection_confidence > 0.8 {
            self.metrics.blocked_events.inc();
            return Ok(DecisionResult {
                decision: DecisionType::Block,
                confidence: injection_confidence,
                reason: "Prompt injection detected by ML layer".to_string(),
                matched_rules: vec![],
                ai_insights: None,
                verification_result: None,
                z3_verified: false,
                processing_time_ms: start.elapsed().as_millis() as u64,
                cached: false,
                rule_eval_time_ms: None,
                ai_time_ms: None,
                tool_calls: vec![],
                explanation: None,
                pii_detected,
                injection_detected,
                injection_confidence,
                ml_risk_score: 0.0,
            });
        }

        // Use sanitized content for downstream processing (prevents PII leaking to AI backends)
        let content = if pii_detected { &_sanitized } else { content };

        // Compliance mode: force rules-only
        if self.compliance_mode {
            let context = serde_json::json!({
                "session_id": session_id,
                "content": content,
                "metadata": metadata,
                "content_length": content.len(),
            });
            return self.classify_rules_only(&context).await;
        }

        // Build evaluation context
        let context = serde_json::json!({
            "session_id": session_id,
            "content": content,
            "metadata": metadata,
            "content_length": content.len(),
        });

        // Check routing mode
        match self.router.mode() {
            RoutingMode::RulesOnly => {
                return self.classify_rules_only(&context).await;
            }
            RoutingMode::AiOnly => {
                return self.classify_ai_only(tenant_id, content).await;
            }
            RoutingMode::Sequential => {
                return self.classify_sequential(tenant_id, &context, content, session_id).await;
            }
            RoutingMode::Speculative => {
                return self.classify_speculative(tenant_id, &context, content, session_id).await;
            }
            RoutingMode::Smart => {
                return self.classify_smart(tenant_id, &context, content, session_id).await;
            }
            RoutingMode::Formal => {
                // Formal mode: Combine rules and AI for audit trails (reuse parallel execution)
                return self.classify_speculative(tenant_id, &context, content, session_id).await;
                return self.classify_sequential(tenant_id, &context, content, session_id).await;
            }
        }
    }
    
    /// Rules-only classification mode
    async fn classify_rules_only(&self, context: &serde_json::Value) -> Result<DecisionResult, Box<dyn std::error::Error>> {
        let start = Instant::now();
        let rule_start = Instant::now();
        let rule_result = self.evaluate_rules(context).await;
        let rule_time = rule_start.elapsed();
        
        let decision = rule_result.decision.unwrap_or(DecisionType::Allow);
        let reason = rule_result.reason.unwrap_or_else(|| "No rules matched".to_string());
        
        Ok(DecisionResult {
            decision,
            confidence: 0.95,
            reason,
            matched_rules: rule_result.matched_rules,
            ai_insights: None,
            verification_result: None,
            z3_verified: false,
            processing_time_ms: start.elapsed().as_millis() as u64,
            cached: false,
            rule_eval_time_ms: Some(rule_time.as_millis() as u64),
            ai_time_ms: None,
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        })
    }
    
    /// AI-only classification mode
    async fn classify_ai_only(&self, tenant_id: &str, content: &str) -> Result<DecisionResult, Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        // Check deep analysis quota BEFORE calling AI
        match self.quota_manager.check_classification_quota(
            tenant_id,
            ClassificationType::DeepAnalysis { estimated_tokens: content.len() / 4 },
            content,
        ).await {
            Ok(_) => {},
            Err(QuotaError::MonthlyDeepAnalysisLimitExceeded { used, limit }) => {
                return Ok(DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!(
                        "Deep analysis quota exceeded: {}/{} per month. Upgrade at https://axiomguard.com/upgrade",
                        used, limit
                    ),
                    matched_rules: vec![],
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: None,
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
            Err(_) => {
                // Other errors - proceed but warn
                tracing::warn!("Deep analysis quota check failed, proceeding");
            }
        }
        
        let ai_start = Instant::now();
        let ai_result = self.ai_engine.classify_text(content).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let ai_time = ai_start.elapsed();
        
        let decision = self.risk_to_decision(ai_result.risk_level);
        
        Ok(DecisionResult {
            decision,
            confidence: ai_result.confidence,
            reason: "AI classification only".to_string(),
            matched_rules: vec![],
            ai_insights: Some(AiInsights {
                risk_level: ai_result.risk_level,
                category: ai_result.category,
                anomalies: ai_result.anomalies,
                recommendations: ai_result.recommendations,
                model: ai_result.model,
                fallback_used: false,
            }),
            verification_result: None,
            z3_verified: false,
            processing_time_ms: start.elapsed().as_millis() as u64,
            cached: false,
            rule_eval_time_ms: None,
            ai_time_ms: Some(ai_time.as_millis() as u64),
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        })
    }
    
    /// Sequential classification: Rules first, AI if needed
    async fn classify_sequential(&self, tenant_id: &str, context: &serde_json::Value, content: &str, session_id: &str) -> Result<DecisionResult, Box<dyn std::error::Error>> {
        let start = Instant::now();
        let rule_start = Instant::now();
        
        // Evaluate rules
        let rule_result = self.evaluate_rules(context).await;
        let rule_time = rule_start.elapsed();
        self.metrics.rule_evaluation_time.observe(rule_time.as_millis() as f64);
        
        // Check if we should skip AI based on routing decision
        let rule_matched = rule_result.decision.is_some();
        if !self.router.should_use_ai(content, rule_matched) {
            // Return rule-based result
            if let Some(decision) = rule_result.decision {
                return Ok(DecisionResult {
                    decision,
                    confidence: 0.95,
                    reason: rule_result.reason.unwrap_or_else(|| "Rule match".to_string()),
                    matched_rules: rule_result.matched_rules,
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
        }
        
        // Check deep analysis quota BEFORE calling AI
        match self.quota_manager.check_classification_quota(
            tenant_id,
            ClassificationType::DeepAnalysis { estimated_tokens: content.len() / 4 },
            content,
        ).await {
            Ok(_) => {},
            Err(QuotaError::MonthlyDeepAnalysisLimitExceeded { used, limit }) => {
                return Ok(DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!(
                        "Deep analysis quota exceeded: {}/{} per month. Upgrade at https://axiomguard.com/upgrade",
                        used, limit
                    ),
                    matched_rules: rule_result.matched_rules,
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
            Err(_) => {}
        }
        
        // Run AI classification
        let ai_start = Instant::now();
        let ai_result = self.ai_engine.classify_text(content).await.ok();
        let ai_time = ai_start.elapsed();
        self.metrics.ai_processing_time.observe(ai_time.as_millis() as f64);
        
        // Combine rule and AI results
        let (decision, confidence, reason_text, ai_insights) = if let Some(ai) = ai_result {
            let decision = self.risk_to_decision(ai.risk_level);
            
            let insights = AiInsights {
                risk_level: ai.risk_level,
                category: ai.category,
                anomalies: ai.anomalies,
                recommendations: ai.recommendations,
                model: ai.model,
                fallback_used: false,
            };
            
            (decision, ai.confidence, "AI classification".to_string(), Some(insights))
        } else {
            // AI failed - use rule result or handover
            if let Some(decision) = rule_result.decision {
                let reason = format!("Rule match (AI unavailable): {}", rule_result.reason.unwrap_or_default());
                (decision, 0.8, reason, None)
            } else {
                (DecisionType::Handover, 0.5, "No rule match, AI unavailable".to_string(), None)
            }
        };
        
        Ok(DecisionResult {
            decision,
            confidence,
            reason: reason_text,
            matched_rules: rule_result.matched_rules,
            ai_insights,
            verification_result: None,
            z3_verified: false,
            processing_time_ms: start.elapsed().as_millis() as u64,
            cached: false,
            rule_eval_time_ms: Some(rule_time.as_millis() as u64),
            ai_time_ms: Some(ai_time.as_millis() as u64),
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        })
    }
    
    /// Speculative classification: Run rules and AI in parallel
    async fn classify_speculative(&self, tenant_id: &str, context: &serde_json::Value, content: &str, _session_id: &str) -> Result<DecisionResult, Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        // Check deep analysis quota BEFORE running AI (speculative still consumes quota)
        match self.quota_manager.check_classification_quota(
            tenant_id,
            ClassificationType::DeepAnalysis { estimated_tokens: content.len() / 4 },
            content,
        ).await {
            Ok(_) => {},
            Err(QuotaError::MonthlyDeepAnalysisLimitExceeded { used, limit }) => {
                // Fall back to rules-only
                let rule_start = Instant::now();
                let rule_result = self.evaluate_rules(context).await;
                let rule_time = rule_start.elapsed();
                if let Some(decision) = rule_result.decision {
                    return Ok(DecisionResult {
                        decision,
                        confidence: 0.85,
                        reason: format!("Rule match (AI quota exceeded: {}/{})", used, limit),
                        matched_rules: rule_result.matched_rules,
                        ai_insights: None,
                        verification_result: None,
                        z3_verified: false,
                        processing_time_ms: start.elapsed().as_millis() as u64,
                        cached: false,
                        rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                        ai_time_ms: None,
                        tool_calls: vec![],
                        explanation: None,
                        pii_detected: false,
                        injection_detected: false,
                        injection_confidence: 0.0,
                        ml_risk_score: 0.0,
                    });
                }
                return Ok(DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!("AI quota exceeded: {}/{} per month. Upgrade at https://axiomguard.com/upgrade", used, limit),
                    matched_rules: vec![],
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
            Err(_) => {}
        }
        
        // Run both in parallel
        let rule_start = Instant::now();
        let rule_future = self.evaluate_rules(context);
        let ai_future = self.ai_engine.classify_text(content);
        
        let (rule_result, ai_result) = tokio::join!(rule_future, ai_future);
        let rule_time = rule_start.elapsed();
        
        // Use rule result if available and AI didn't respond
        if let Err(ref e) = ai_result {
            tracing::warn!("AI classification failed: {}", e);
            if let Some(decision) = rule_result.decision {
                return Ok(DecisionResult {
                    decision,
                    confidence: 0.85,
                    reason: format!("Rule match (AI failed): {}", rule_result.reason.unwrap_or_default()),
                    matched_rules: rule_result.matched_rules,
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
        }
        
        let ai = ai_result?;
        let ai_decision = self.risk_to_decision(ai.risk_level);
        
        // Combine results: rule wins if both available
        let (final_decision, confidence, reason) = if let Some(rule_decision) = rule_result.decision {
            // Rule matched - use it but incorporate AI confidence
            let final_confidence = if rule_decision == ai_decision {
                0.98 // High confidence when both agree
            } else {
                0.90 // Lower confidence when they disagree
            };
            (rule_decision, final_confidence, format!("Rule+AI hybrid: {:?}", ai.category))
        } else {
            // No rule match - use AI
            (ai_decision, ai.confidence, "AI classification (no rule match)".to_string())
        };
        
        Ok(DecisionResult {
            decision: final_decision,
            confidence,
            reason,
            matched_rules: rule_result.matched_rules,
            ai_insights: Some(AiInsights {
                risk_level: ai.risk_level,
                category: ai.category,
                anomalies: ai.anomalies,
                recommendations: ai.recommendations,
                model: ai.model,
                fallback_used: false,
            }),
            verification_result: None,
            z3_verified: false,
            processing_time_ms: start.elapsed().as_millis() as u64,
            cached: false,
            rule_eval_time_ms: Some(rule_time.as_millis() as u64),
            ai_time_ms: None,
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        })
    }
    
    /// Smart classification: Dynamically choose based on content
    async fn classify_smart(&self, tenant_id: &str, context: &serde_json::Value, content: &str, _session_id: &str) -> Result<DecisionResult, Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        // First, quickly evaluate rules
        let rule_start = Instant::now();
        let rule_result = self.evaluate_rules(context).await;
        let rule_time = rule_start.elapsed();
        let rule_matched = rule_result.decision.is_some();
        
        // Check if we should use AI
        if !self.router.should_use_ai(content, rule_matched) {
            // Simple case - return rule result
            if let Some(decision) = rule_result.decision {
                return Ok(DecisionResult {
                    decision,
                    confidence: 0.95,
                    reason: rule_result.reason.unwrap_or_else(|| "Deterministic match".to_string()),
                    matched_rules: rule_result.matched_rules,
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
            // No rule match but content is simple - allow
            return Ok(DecisionResult {
                decision: DecisionType::Allow,
                confidence: 0.7,
                reason: "Simple content, no rules matched".to_string(),
                matched_rules: vec![],
                ai_insights: None,
                verification_result: None,
                z3_verified: false,
                processing_time_ms: start.elapsed().as_millis() as u64,
                cached: false,
                rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                ai_time_ms: None,
                tool_calls: vec![],
                explanation: None,
                pii_detected: false,
                injection_detected: false,
                injection_confidence: 0.0,
                ml_risk_score: 0.0,
            });
        }
        
        // Complex content - need AI
        // Check deep analysis quota first
        match self.quota_manager.check_classification_quota(
            tenant_id,
            ClassificationType::DeepAnalysis { estimated_tokens: content.len() / 4 },
            content,
        ).await {
            Ok(_) => {},
            Err(QuotaError::MonthlyDeepAnalysisLimitExceeded { used, limit }) => {
                return Ok(DecisionResult {
                    decision: DecisionType::Handover,
                    confidence: 0.0,
                    reason: format!(
                        "Complex content detected but AI quota exceeded: {}/{} per month. Upgrade at https://axiomguard.com/upgrade",
                        used, limit
                    ),
                    matched_rules: rule_result.matched_rules,
                    ai_insights: None,
                    verification_result: None,
                    z3_verified: false,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    cached: false,
                    rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                    ai_time_ms: None,
                    tool_calls: vec![],
                    explanation: None,
                    pii_detected: false,
                    injection_detected: false,
                    injection_confidence: 0.0,
                    ml_risk_score: 0.0,
                });
            }
            Err(_) => {}
        }
        
        let ai_start = Instant::now();
        let ai_result = self.ai_engine.classify_text(content).await.ok();
        let ai_time = ai_start.elapsed();
        
        if let Some(ai) = ai_result {
            let decision = self.risk_to_decision(ai.risk_level);
            Ok(DecisionResult {
                decision,
                confidence: ai.confidence,
                reason: format!("AI classification (complex content): {:?}", ai.category),
                matched_rules: rule_result.matched_rules,
                ai_insights: Some(AiInsights {
                    risk_level: ai.risk_level,
                    category: ai.category,
                    anomalies: ai.anomalies,
                    recommendations: ai.recommendations,
                    model: ai.model,
                    fallback_used: false,
                }),
                verification_result: None,
                z3_verified: false,
                processing_time_ms: start.elapsed().as_millis() as u64,
                cached: false,
                rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                ai_time_ms: Some(ai_time.as_millis() as u64),
                tool_calls: vec![],
                explanation: None,
                pii_detected: false,
                injection_detected: false,
                injection_confidence: 0.0,
                ml_risk_score: 0.0,
            })
        } else {
            // AI failed - handover for complex content
            Ok(DecisionResult {
                decision: DecisionType::Handover,
                confidence: 0.5,
                reason: "Complex content, AI unavailable".to_string(),
                matched_rules: rule_result.matched_rules,
                ai_insights: None,
                verification_result: None,
                z3_verified: false,
                processing_time_ms: start.elapsed().as_millis() as u64,
                cached: false,
                rule_eval_time_ms: Some(rule_time.as_millis() as u64),
                ai_time_ms: None,
                tool_calls: vec![],
                explanation: None,
                pii_detected: false,
                injection_detected: false,
                injection_confidence: 0.0,
                ml_risk_score: 0.0,
            })
        }
    }
    
    /// Evaluate all rules and return the best match.
    /// When `early_exit_on_block` is enabled, stops after first BLOCK match
    /// at priority <= 100 (security-critical rules).
    async fn evaluate_rules(&self, context: &serde_json::Value) -> RuleEvaluationResult {
        let rules = self.rules.read().await;
        let mut matched_rules = Vec::new();
        let mut highest_priority: Option<&SecurityRule> = None;

        for rule in rules.iter().filter(|r| r.is_active) {
            let result = if let Some(ref compiled) = rule.compiled_rule {
                self.jsonlogic.evaluate(compiled, context)
            } else {
                self.jsonlogic.evaluate_json(&rule.logic, context)
            };

            match result {
                Ok(Value::Bool(true)) => {
                    matched_rules.push(rule.id.clone());

                    if highest_priority.map_or(true, |hp| rule.priority < hp.priority) {
                        highest_priority = Some(rule);
                    }

                    // Early exit: stop evaluating after first security-critical BLOCK
                    if self.early_exit_on_block
                        && rule.decision == DecisionType::Block
                        && rule.priority <= 100
                    {
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("Rule evaluation error for {}: {}", rule.id, e);
                }
            }
        }

        RuleEvaluationResult {
            decision: highest_priority.map(|r| r.decision.clone()),
            reason: highest_priority.map(|r| r.name.clone()),
            matched_rules,
            priority: highest_priority.map(|r| r.priority),
        }
    }
    
    /// Convert risk level to decision type
    fn risk_to_decision(&self, risk_level: f32) -> DecisionType {
        if risk_level > 0.9 {
            DecisionType::Block
        } else if risk_level > 0.7 {
            DecisionType::Flag
        } else {
            DecisionType::Allow
        }
    }
    
    fn create_fallback_result(&self, reason: &str, elapsed: Duration) -> DecisionResult {
        DecisionResult {
            decision: DecisionType::Handover,
            confidence: 0.0,
            reason: reason.to_string(),
            matched_rules: vec![],
            ai_insights: None,
            verification_result: None,
            z3_verified: false,
            processing_time_ms: elapsed.as_millis() as u64,
            cached: false,
            rule_eval_time_ms: None,
            ai_time_ms: None,
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        }
    }
    
    fn update_metrics(&self, result: &DecisionResult) {
        self.metrics.processed_events.inc();
        self.metrics.total_processing_time.observe(result.processing_time_ms as f64);
        
        match result.decision {
            DecisionType::Block => self.metrics.blocked_events.inc(),
            DecisionType::Handover => self.metrics.handed_over_events.inc(),
            DecisionType::Flag => self.metrics.flagged_events.inc(),
            _ => {}
        }
    }
    
    /// Update active rules (thread-safe)
    pub async fn update_rules(&self, rules: Vec<SecurityRule>) {
        let mut compiled = rules;
        let mut active = 0;
        let mut deactivated = 0;
        for rule in &mut compiled {
            // Validate rule logic — deactivate malformed rules
            if let Err(e) = self.jsonlogic.validate(&rule.logic) {
                tracing::warn!(
                    "Deactivating invalid rule '{}' ({}): {}",
                    rule.name, rule.id, e
                );
                rule.is_active = false;
                deactivated += 1;
                continue;
            }
            rule.compile();
            if rule.is_active {
                active += 1;
            }
        }
        let mut guard = self.rules.write().await;
        *guard = compiled;
        tracing::info!("Updated {} security rules ({} active, {} deactivated)", guard.len(), active, deactivated);
    }
    
    /// Get current active rules
    pub async fn get_rules(&self) -> Vec<SecurityRule> {
        self.rules.read().await.clone()
    }
    
    /// Load rules from database repository
    pub async fn reload_rules_from_db(&self, db: &common::database::Database) -> Result<(), Box<dyn std::error::Error>> {
        let rows = sqlx::query(
            "SELECT id, name, description, logic, decision, priority, status, version FROM security_rules WHERE status = 'active' AND deleted_at IS NULL ORDER BY priority ASC"
        )
        .fetch_all(db.pool())
        .await?;
        
        let mut engine_rules = Vec::new();
        for row in rows {
            let mut rule = SecurityRule {
                id: row.try_get::<uuid::Uuid, _>("id")?.to_string(),
                name: row.try_get("name")?,
                description: row.try_get::<Option<String>, _>("description")?.unwrap_or_default(),
                logic: row.try_get("logic")?,
                compiled_rule: None,
                decision: match row.try_get::<String, _>("decision")?.as_str() {
                    "allow" => DecisionType::Allow,
                    "block" => DecisionType::Block,
                    "flag" => DecisionType::Flag,
                    "review" => DecisionType::Review,
                    "handover" => DecisionType::Handover,
                    _ => DecisionType::Allow,
                },
                priority: row.try_get("priority")?,
                is_active: row.try_get::<String, _>("status")? == "active",
                version: row.try_get::<Option<i32>, _>("version")?.unwrap_or(1),
            };
            rule.compile();
            engine_rules.push(rule);
        }
        
        self.update_rules(engine_rules).await;
        Ok(())
    }
    
    /// Subscribe to events
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<event_broadcaster::BroadcastEvent> {
        self.event_broadcaster.subscribe()
    }
    
    /// Clear decision cache
    pub async fn clear_cache(&self) {
        self.decision_cache.invalidate_all();
    }
    
    /// Get current routing mode
    pub fn routing_mode(&self) -> RoutingMode {
        self.router.mode()
    }
    
    /// Set routing mode (runtime configurable)
    pub fn set_routing_mode(&mut self, mode: RoutingMode) {
        self.router.set_mode(mode);
        tracing::info!("Routing mode changed to: {:?}", mode);
    }
    
    /// Configure smart routing thresholds
    pub fn with_smart_config(
        mut self,
        content_threshold: usize,
        complexity_threshold: f32,
        speculative_timeout_ms: u64,
    ) -> Self {
        self.router = ClassificationRouter::new(self.router.mode())
            .with_config(content_threshold, complexity_threshold, speculative_timeout_ms);
        self
    }
}

/// Canonicalize content and hash for cache key.
/// If content is valid JSON, canonicalize it first so that
/// `{"a":1}` and `{ "a" : 1 }` produce identical cache keys.
fn hash_content(content: &str) -> String {
    use sha2::{Sha256, Digest};
    let canonical = match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| content.to_string()),
        Err(_) => content.to_string(),
    };
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

/// Initialize the semantic text embedding model asynchronously.
/// 
/// Runs model loading (and potential download) in a blocking thread
/// to avoid stalling the async runtime. Falls back to None on failure.
pub async fn init_text_embedding() -> Option<Arc<fastembed::TextEmbedding>> {
    match tokio::task::spawn_blocking(|| {
        let mut options = fastembed::InitOptions::default();
        options.model_name = fastembed::EmbeddingModel::NomicEmbedTextV15;
        options.show_download_progress = true;
        fastembed::TextEmbedding::try_new(options)
    }).await {
        Ok(Ok(model)) => {
            tracing::info!("Semantic embedding model loaded: NomicEmbedTextV15 (768-dim)");
            Some(Arc::new(model))
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to load semantic embedding model: {}. Events will use hash-based embeddings.", e);
            None
        }
        Err(e) => {
            tracing::warn!("Embedding initialization task panicked: {}. Events will use hash-based embeddings.", e);
            None
        }
    }
}

/// Generate a deterministic 768-dim embedding from content
/// 
/// Uses token-hash averaging for fast, dependency-free embeddings.
/// Similar content will produce similar vectors.
pub fn generate_embedding(content: &str) -> Vec<f32> {
    let normalized = content.to_lowercase();
    let words: Vec<&str> = normalized.split_whitespace().collect();
    let dim = 768;
    let mut vec = vec![0.0f32; dim];
    
    for word in words.iter() {
        let hash = {
            use sha2::{Sha256, Digest};
            Sha256::digest(word.as_bytes())
        };
        for i in 0..dim {
            let byte = hash[i % 32];
            vec[i] += (byte as f32) / 128.0 - 1.0; // Center around 0
        }
    }
    
    if !words.is_empty() {
        let len = words.len() as f32;
        for v in &mut vec {
            *v /= len;
        }
    }
    
    // Normalize to unit vector
    let magnitude: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for v in &mut vec {
            *v /= magnitude;
        }
    }
    
    vec
}
