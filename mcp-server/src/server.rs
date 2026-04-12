use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::{
    ServerHandler,
    handler::server::{
        router::{
            Router,
            prompt::PromptRoute,
        },
        tool::ToolRouter,
    },
    model::{
        GetPromptResult, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
        Prompt, PromptMessage, PromptMessageRole, ReadResourceResult, Resource, ResourceContents,
        ServerCapabilities, ServerInfo,
    },
    schemars,
};
use serde_json::Value;
use tracing::{info, warn};

use crate::{
    config::McpConfig,
    metrics::McpMetrics,
    prompts,
    tools::{self, ToolError},
};

/// Cache entry with TTL
#[derive(Clone)]
pub struct CacheEntry {
    pub value: Value,
    pub inserted_at: Instant,
}

impl CacheEntry {
    pub fn is_valid(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() < ttl
    }
}

/// AxiomGuard MCP Server
#[derive(Clone)]
pub struct AxiomGuardMcpServer {
    pub shield_client: Option<proxy::shield_client::ShieldClient>,
    pub config: McpConfig,
    pub metrics: McpMetrics,
    pub cache: moka::sync::Cache<String, CacheEntry>,
    pub default_tenant_id: Option<String>,
}

impl AxiomGuardMcpServer {
    pub async fn new(config: McpConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let shield_client = match proxy::shield_client::ShieldClient::connect(&config.shield_endpoint).await {
            Ok(client) => Some(client),
            Err(e) => {
                warn!(error = %e, "Failed to connect to Shield; MCP tools requiring Shield will fail until it becomes available");
                None
            }
        };

        let cache = moka::sync::Cache::builder()
            .max_capacity(config.cache_size as u64)
            .time_to_idle(Duration::from_secs(config.cache_ttl_secs as u64))
            .build();

        // In stdio mode, resolve default API key to tenant_id once at startup
        let default_tenant_id = config.default_api_key.as_ref().and_then(|key| {
            Self::validate_api_key(&config.api_keys, key)
        });

        if config.default_api_key.is_some() && default_tenant_id.is_none() {
            warn!("Configured default API key is invalid");
        }

        Ok(Self {
            shield_client,
            config,
            metrics: McpMetrics::new(),
            cache,
            default_tenant_id,
        })
    }

    /// Validate an API key and return the tenant_id.
    /// In dev mode (empty api_keys), allows all keys and returns "default".
    pub fn validate_api_key(api_keys: &std::collections::HashMap<String, String>, key: &str) -> Option<String> {
        use subtle::ConstantTimeEq;
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

    /// Resolve tenant_id from an optional API key, falling back to the default.
    pub fn resolve_tenant(&self, api_key: Option<&str>) -> Result<String, rmcp::ErrorData> {
        if let Some(key) = api_key {
            if let Some(tenant) = Self::validate_api_key(&self.config.api_keys, key) {
                return Ok(tenant);
            }
            self.metrics.auth_failures.inc();
            return Err(rmcp::ErrorData::invalid_params(
                "Invalid API key",
                None,
            ));
        }
        if let Some(ref tenant) = self.default_tenant_id {
            return Ok(tenant.clone());
        }
        if self.config.api_keys.is_empty() {
            return Ok("default".to_string());
        }
        self.metrics.auth_failures.inc();
        Err(rmcp::ErrorData::invalid_params(
            "API key required",
            None,
        ))
    }

    /// Build a cache key for classify requests
    pub fn build_cache_key(tenant_id: &str, session_id: &str, content: &str) -> String {
        format!("{}:{}:{}", tenant_id, session_id, content)
    }

    /// Get the shield client if connected
    pub fn shield_client(&self) -> Result<&proxy::shield_client::ShieldClient, rmcp::ErrorData> {
        self.shield_client.as_ref().ok_or_else(|| {
            rmcp::ErrorData::internal_error(
                "Shield service is not connected. Ensure axiomguard-shield is running.",
                None,
            )
        })
    }

    pub fn router(self) -> Router<AxiomGuardMcpServer> {
        let tool_router = ToolRouter::<AxiomGuardMcpServer>::new()
            .with_async_tool::<tools::ClassifyContentTool>()
            .with_async_tool::<tools::ExplainDecisionTool>()
            .with_async_tool::<tools::AnalyzeRootCauseTool>()
            .with_async_tool::<tools::GetHealthStatusTool>();

        let security_review_prompt = PromptRoute::new_dyn(
            Prompt::new(
                "security_review",
                Some("Structured prompt for reviewing a security decision"),
                Some(vec![
                    rmcp::model::PromptArgument::new("decision")
                        .with_description("The decision type (ALLOW, BLOCK, FLAG, HANDOVER)")
                        .with_required(true),
                    rmcp::model::PromptArgument::new("reason")
                        .with_description("The reason for the decision")
                        .with_required(true),
                ]),
            ),
            |ctx| {
                Box::pin(async move {
                    prompts::security_review_prompt(ctx.arguments)
                })
            },
        );

        let incident_response_prompt = PromptRoute::new_dyn(
            Prompt::new(
                "incident_response",
                Some("Structured prompt for responding to a root cause analysis"),
                Some(vec![
                    rmcp::model::PromptArgument::new("root_cause")
                        .with_description("The identified root cause")
                        .with_required(true),
                    rmcp::model::PromptArgument::new("recommendations")
                        .with_description("Comma-separated recommendations")
                        .with_required(false),
                ]),
            ),
            |ctx| {
                Box::pin(async move {
                    prompts::incident_response_prompt(ctx.arguments)
                })
            },
        );

        Router::new(self)
            .with_tools(tool_router)
            .with_prompt(security_review_prompt)
            .with_prompt(incident_response_prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_api_key_dev_mode() {
        let empty_keys = std::collections::HashMap::new();
        assert_eq!(
            AxiomGuardMcpServer::validate_api_key(&empty_keys, "any-key"),
            Some("default".to_string())
        );
    }

    #[test]
    fn test_validate_api_key_match() {
        let mut keys = std::collections::HashMap::new();
        keys.insert("secret-key".to_string(), "tenant-42".to_string());
        assert_eq!(
            AxiomGuardMcpServer::validate_api_key(&keys, "secret-key"),
            Some("tenant-42".to_string())
        );
    }

    #[test]
    fn test_validate_api_key_no_match() {
        let mut keys = std::collections::HashMap::new();
        keys.insert("secret-key".to_string(), "tenant-42".to_string());
        assert_eq!(
            AxiomGuardMcpServer::validate_api_key(&keys, "wrong-key"),
            None
        );
    }

    #[test]
    fn test_validate_api_key_timing_safe() {
        // Constant-time comparison should reject partial matches
        let mut keys = std::collections::HashMap::new();
        keys.insert("secret-key".to_string(), "tenant-42".to_string());
        assert_eq!(
            AxiomGuardMcpServer::validate_api_key(&keys, "secret-ke"),
            None
        );
    }

    #[test]
    fn test_build_cache_key() {
        let key = AxiomGuardMcpServer::build_cache_key("tenant-1", "session-a", "hello world");
        assert_eq!(key, "tenant-1:session-a:hello world");
    }
}

impl ServerHandler for AxiomGuardMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut caps = ServerCapabilities::default();
        caps.tools = Some(rmcp::model::ToolsCapability {
            list_changed: Some(false),
        });
        caps.resources = Some(rmcp::model::ResourcesCapability {
            list_changed: Some(false),
            subscribe: Some(false),
        });
        caps.prompts = Some(rmcp::model::PromptsCapability {
            list_changed: Some(false),
        });
        ServerInfo::new(caps)
    }

    fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + rmcp::service::MaybeSendFuture + '_ {
        std::future::ready(Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(
                rmcp::model::RawResource {
                    uri: "axiomguard://health".into(),
                    name: "shield-health".into(),
                    title: Some("Shield Health".into()),
                    description: Some("Current Shield service health status".into()),
                    mime_type: Some("application/json".into()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                None,
            ),
        ])))
    }

    fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + rmcp::service::MaybeSendFuture + '_ {
        let uri = request.uri;
        async move {
            match uri.as_str() {
                "axiomguard://health" => {
                    let start = Instant::now();
                    let client = self.shield_client()?;
                    let health = client.health_check().await;
                    self.metrics.shield_latency.observe(start.elapsed().as_millis() as f64);

                    let status = match health {
                        Ok(true) => serde_json::json!({"status": "healthy"}),
                        Ok(false) => serde_json::json!({"status": "unhealthy"}),
                        Err(e) => serde_json::json!({"status": "unreachable", "error": e.to_string()}),
                    };

                    Ok(ReadResourceResult::new(vec![ResourceContents::TextResourceContents {
                        uri: uri.into(),
                        mime_type: Some("application/json".into()),
                        text: status.to_string(),
                        meta: None,
                    }]))
                }
                _ => Err(rmcp::ErrorData::invalid_params(
                    format!("Unknown resource: {}", uri),
                    None,
                )),
            }
        }
    }

    fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + rmcp::service::MaybeSendFuture + '_ {
        std::future::ready(Ok(ListPromptsResult::with_all_items(vec![
            Prompt::new(
                "security_review",
                Some("Structured prompt for reviewing a security decision"),
                None,
            ),
            Prompt::new(
                "incident_response",
                Some("Structured prompt for responding to a root cause analysis"),
                None,
            ),
        ])))
    }

    fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, rmcp::ErrorData>> + rmcp::service::MaybeSendFuture + '_ {
        let name = request.name;
        let args = request.arguments;
        async move {
            match name.as_str() {
                "security_review" => prompts::security_review_prompt(args),
                "incident_response" => prompts::incident_response_prompt(args),
                _ => Err(rmcp::ErrorData::invalid_params(
                    format!("Unknown prompt: {}", name),
                    None,
                )),
            }
        }
    }
}
