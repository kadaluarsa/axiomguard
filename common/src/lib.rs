use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditDecision {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub decision: DecisionType,
    pub confidence: f32,
    pub rules_matched: Vec<String>,
    pub ai_insights: Option<String>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DecisionType {
    Allow,
    Block,
    Flag,
    Review,
    Handover,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub decision: DecisionType,
    pub priority: u32,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    NotContains,
    RegexMatch,
    In,
    NotIn,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditMetrics {
    pub total_events: u64,
    pub processed_events: u64,
    pub blocked_events: u64,
    pub flagged_events: u64,
    pub avg_processing_time_ms: f64,
    pub errors: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessingStats {
    pub event_id: Uuid,
    pub rule_evaluation_time_ms: u64,
    pub ai_processing_time_ms: Option<u64>,
    pub total_time_ms: u64,
}

pub mod metrics;
pub mod telemetry;
pub mod webhooks;
pub mod database;
