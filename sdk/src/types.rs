use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionType {
    Allow,
    Block,
    Flag,
    Handover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalePolicyAction {
    Warn,
    HardFail,
}

impl Default for StalePolicyAction {
    fn default() -> Self {
        StalePolicyAction::Warn
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub arguments_json: String,
    pub target: Option<String>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResult {
    pub decision: DecisionType,
    pub confidence: f32,
    pub reason: String,
    pub matched_rules: Vec<String>,
    pub tool_calls: Vec<ToolCall>,
    pub cached: bool,
    pub risk_score: f32,
    pub processing_time_us: u64,
}

impl GuardResult {
    pub fn blocked(&self) -> bool {
        self.decision == DecisionType::Block
    }

    pub fn allowed(&self) -> bool {
        self.decision == DecisionType::Allow
    }

    pub fn flagged(&self) -> bool {
        self.decision == DecisionType::Flag
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolPermission {
    Allow,
    Deny,
    Restrict { allowed_args: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub decision: DecisionType,
    pub priority: i32,
    pub is_agent_specific: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQuota {
    pub max_calls_per_day: u32,
    pub max_calls_per_minute: u32,
    pub used_today: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub agent_id: String,
    pub tool_allowlist: HashMap<String, ToolPermission>,
    pub rules: Vec<CompiledRule>,
    #[serde(default = "default_risk_threshold")]
    pub risk_threshold: f32,
    pub quota: Option<AgentQuota>,
    #[serde(default = "default_timestamp")]
    pub fetched_at: i64,
    #[serde(default = "default_timestamp")]
    pub expires_at: i64,
}

fn default_timestamp() -> i64 {
    0
}

fn default_risk_threshold() -> f32 {
    0.7
}

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(key: String) -> Self {
        Self(key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub control_plane_url: Option<String>,
    pub tenant_id: String,
    pub agent_id: String,
    pub api_key: Option<ApiKey>,
    pub policy_file: Option<String>,
    pub session_id: Option<String>,
    pub enable_tool_tokens: bool,
    pub timeout_ms: u64,
    pub cache_size: usize,
    pub stale_policy_action: StalePolicyAction,
}

impl GuardConfig {
    pub fn builder() -> GuardConfigBuilder {
        GuardConfigBuilder::default()
    }
}

#[derive(Debug, Clone)]
pub struct GuardConfigBuilder {
    control_plane_url: Option<String>,
    tenant_id: Option<String>,
    agent_id: Option<String>,
    api_key: Option<ApiKey>,
    policy_file: Option<String>,
    session_id: Option<String>,
    enable_tool_tokens: bool,
    timeout_ms: u64,
    cache_size: usize,
    stale_policy_action: StalePolicyAction,
}

impl Default for GuardConfigBuilder {
    fn default() -> Self {
        Self {
            control_plane_url: None,
            tenant_id: None,
            agent_id: None,
            api_key: None,
            policy_file: None,
            session_id: None,
            enable_tool_tokens: false,
            timeout_ms: 0,
            cache_size: 0,
            stale_policy_action: StalePolicyAction::Warn,
        }
    }
}

impl GuardConfigBuilder {
    pub fn control_plane_url(mut self, url: impl Into<String>) -> Self {
        self.control_plane_url = Some(url.into());
        self
    }

    pub fn tenant_id(mut self, id: impl Into<String>) -> Self {
        self.tenant_id = Some(id.into());
        self
    }

    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.agent_id = Some(id.into());
        self
    }

    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(ApiKey::new(key.into()));
        self
    }

    pub fn policy_file(mut self, path: impl Into<String>) -> Self {
        self.policy_file = Some(path.into());
        self
    }

    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn enable_tool_tokens(mut self, enabled: bool) -> Self {
        self.enable_tool_tokens = enabled;
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    pub fn stale_policy_action(mut self, action: StalePolicyAction) -> Self {
        self.stale_policy_action = action;
        self
    }

    pub fn build(self) -> Result<GuardConfig, GuardConfigError> {
        let tenant_id = self
            .tenant_id
            .ok_or(GuardConfigError::MissingField("tenant_id"))?;
        let agent_id = self
            .agent_id
            .ok_or(GuardConfigError::MissingField("agent_id"))?;
        let timeout_ms = if self.timeout_ms == 0 {
            100
        } else {
            self.timeout_ms
        };
        let cache_size = if self.cache_size == 0 {
            10000
        } else {
            self.cache_size
        };

        Ok(GuardConfig {
            control_plane_url: self.control_plane_url,
            tenant_id,
            agent_id,
            api_key: self.api_key,
            policy_file: self.policy_file,
            session_id: self.session_id,
            enable_tool_tokens: self.enable_tool_tokens,
            timeout_ms,
            cache_size,
            stale_policy_action: self.stale_policy_action,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GuardConfigError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("pipeline error: {0}")]
    Pipeline(String),

    #[error("policy not loaded")]
    PolicyNotLoaded,

    #[error("quota exceeded")]
    QuotaExceeded,

    #[error("timeout after {0}ms")]
    Timeout(u64),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("policy stale")]
    PolicyStale,
}
