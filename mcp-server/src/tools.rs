use std::borrow::Cow;
use std::time::Instant;

use rmcp::{
    ErrorData,
    handler::server::router::tool::{AsyncTool, ToolBase},
    model::JsonObject,
    schemars,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::server::AxiomGuardMcpServer;

#[derive(Debug)]
pub struct ToolError(pub String);

impl From<ToolError> for ErrorData {
    fn from(err: ToolError) -> Self {
        ErrorData::internal_error(err.0, None)
    }
}

impl From<ErrorData> for ToolError {
    fn from(err: ErrorData) -> Self {
        ToolError(err.to_string())
    }
}

/// Wrapper around `serde_json::Value` that reports its JSON Schema as an object.
/// MCP requires tool `outputSchema` to have root type `object`.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(transparent)]
pub struct JsonObjectValue(pub Value);

impl schemars::JsonSchema for JsonObjectValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "JsonObjectValue".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        serde_json::json!({"type": "object"}).try_into().unwrap()
    }
}

// ============================================================================
// classify_content
// ============================================================================

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct ClassifyContentInput {
    pub content: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub api_key: Option<String>,
}

pub struct ClassifyContentTool;

impl ToolBase for ClassifyContentTool {
    type Parameter = ClassifyContentInput;
    type Output = JsonObjectValue;
    type Error = ToolError;

    fn name() -> Cow<'static, str> {
        "classify_content".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Classify content using the AxiomGuard Shield engine".into())
    }
}

impl AsyncTool<AxiomGuardMcpServer> for ClassifyContentTool {
    async fn invoke(
        server: &AxiomGuardMcpServer,
        param: Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        server.metrics.tool_calls.inc();
        let tenant_id = server.resolve_tenant(param.api_key.as_deref())
            .map_err(|e| ToolError(e.message.to_string()))?;

        let session_id = param.session_id.unwrap_or_else(|| "default".to_string());
        let agent_id = param.agent_id.unwrap_or_else(|| "default".to_string());
        let cache_key = AxiomGuardMcpServer::build_cache_key(&tenant_id, &format!("{}:{}", agent_id, session_id), &param.content);
        let ttl = std::time::Duration::from_secs(server.config.cache_ttl_secs);

        // Check cache
        if let Some(entry) = server.cache.get(&cache_key) {
            if entry.is_valid(ttl) {
                return Ok(JsonObjectValue(entry.value));
            }
        }

        let mut request = serde_json::json!({
            "session_id": session_id,
            "content": param.content,
        });

        if let Some(metadata) = param.metadata {
            let mut metadata_obj = metadata;
            metadata_obj.insert("tenant_id".to_string(), serde_json::json!(tenant_id));
            request["metadata"] = Value::Object(metadata_obj);
        } else {
            request["metadata"] = serde_json::json!({"tenant_id": tenant_id, "agent_id": agent_id});
        }

        let start = Instant::now();
        let response = server.shield_client()?.classify_stream(request, param.api_key.as_deref()).await
            .map_err(|e| ToolError(e.to_string()))?;
        server.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);

        // Store in cache
        server.cache.insert(cache_key, crate::server::CacheEntry {
            value: response.clone(),
            inserted_at: Instant::now(),
        });

        Ok(JsonObjectValue(response))
    }
}

// ============================================================================
// explain_decision
// ============================================================================

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct ExplainDecisionInput {
    pub decision: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub matched_rules: Vec<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub ai_insights: Option<Value>,
    #[serde(default)]
    pub tool_calls: Option<Vec<Value>>,
    #[serde(default)]
    pub api_key: Option<String>,
}

pub struct ExplainDecisionTool;

impl ToolBase for ExplainDecisionTool {
    type Parameter = ExplainDecisionInput;
    type Output = JsonObjectValue;
    type Error = ToolError;

    fn name() -> Cow<'static, str> {
        "explain_decision".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Explain a classification decision with key factors and remediation".into())
    }
}

impl AsyncTool<AxiomGuardMcpServer> for ExplainDecisionTool {
    async fn invoke(
        server: &AxiomGuardMcpServer,
        param: Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        server.metrics.tool_calls.inc();
        let tenant_id = server.resolve_tenant(param.api_key.as_deref())
            .map_err(|e| ToolError(e.message.to_string()))?;

        let start = Instant::now();
        let response = server.shield_client()?.explain_decision(
            &tenant_id,
            param.content.as_deref().unwrap_or(""),
            &param.decision,
            param.matched_rules,
            param.ai_insights,
            param.tool_calls.unwrap_or_default(),
        ).await.map_err(|e| ToolError(e.to_string()))?;
        server.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);

        Ok(JsonObjectValue(response))
    }
}

// ============================================================================
// analyze_root_cause
// ============================================================================

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct AnalyzeRootCauseInput {
    pub content: String,
    pub session_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default = "default_lookback")]
    pub lookback_hours: i32,
    #[serde(default)]
    pub api_key: Option<String>,
}

fn default_lookback() -> i32 {
    24
}

pub struct AnalyzeRootCauseTool;

impl ToolBase for AnalyzeRootCauseTool {
    type Parameter = AnalyzeRootCauseInput;
    type Output = JsonObjectValue;
    type Error = ToolError;

    fn name() -> Cow<'static, str> {
        "analyze_root_cause".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Analyze root cause using RAG over historical events".into())
    }
}

impl AsyncTool<AxiomGuardMcpServer> for AnalyzeRootCauseTool {
    async fn invoke(
        server: &AxiomGuardMcpServer,
        param: Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        server.metrics.tool_calls.inc();
        let tenant_id = server.resolve_tenant(param.api_key.as_deref())
            .map_err(|e| ToolError(e.message.to_string()))?;

        let start = Instant::now();
        let response = server.shield_client()?.analyze_root_cause(
            &tenant_id,
            &param.content,
            &param.session_id,
            param.lookback_hours,
        ).await.map_err(|e| ToolError(e.to_string()))?;
        server.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);

        Ok(JsonObjectValue(response))
    }
}

// ============================================================================
// get_health_status
// ============================================================================

#[derive(Deserialize, schemars::JsonSchema, Default)]
pub struct GetHealthStatusInput {
    #[serde(default)]
    pub api_key: Option<String>,
}

pub struct GetHealthStatusTool;

impl ToolBase for GetHealthStatusTool {
    type Parameter = GetHealthStatusInput;
    type Output = JsonObjectValue;
    type Error = ToolError;

    fn name() -> Cow<'static, str> {
        "get_health_status".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Check the health status of the AxiomGuard Shield service".into())
    }
}

impl AsyncTool<AxiomGuardMcpServer> for GetHealthStatusTool {
    async fn invoke(
        server: &AxiomGuardMcpServer,
        _param: Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        server.metrics.tool_calls.inc();

        let start = Instant::now();
        let healthy = server.shield_client()?.health_check().await
            .map_err(|e| ToolError(e.to_string()))?;
        server.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);

        Ok(JsonObjectValue(serde_json::json!({
            "status": if healthy { "healthy" } else { "unhealthy" },
            "service": "axiomguard-shield",
        })))
    }
}
