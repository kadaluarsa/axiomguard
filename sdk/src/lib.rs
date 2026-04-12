pub mod types;
pub mod jsonlogic;
pub mod tool_parser;
pub mod pii;
pub mod pipeline;
pub mod schema;
pub mod session;
pub mod audit_buffer;
pub mod integrity;
pub mod policy_cache;

pub use types::{DecisionType, GuardConfig, GuardConfigBuilder, GuardResult, ToolCall, ToolPermission, AgentPolicy};

use std::sync::RwLock;
use types::GuardError;

pub struct Guard {
    config: GuardConfig,
    pub(crate) pipeline: pipeline::GuardPipeline,
    session_tracker: RwLock<session::SessionTracker>,
    policy: RwLock<Option<AgentPolicy>>,
}

impl Guard {
    pub fn new(config: GuardConfig) -> Self {
        let pipeline = pipeline::GuardPipeline::new(&config);
        let session_tracker = session::SessionTracker::new(
            config.session_id.clone(),
            config.tenant_id.clone(),
            config.agent_id.clone(),
        );

        Self {
            config,
            pipeline,
            session_tracker: RwLock::new(session_tracker),
            policy: RwLock::new(None),
        }
    }

    pub async fn check(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<GuardResult, GuardError> {
        self.pipeline
            .evaluate(tool_name, arguments, &self.policy, &self.session_tracker)
            .await
    }

    pub fn load_policy(&self, mut policy: AgentPolicy) {
        let now = chrono::Utc::now().timestamp();
        policy.fetched_at = now;
        policy.expires_at = now + 3600;
        if let Ok(mut guard) = self.policy.write() {
            *guard = Some(policy);
        }
    }

    pub fn new_with_audit_wal(config: GuardConfig, wal_path: impl AsRef<std::path::Path>) -> Self {
        let mut guard = Guard::new(config);
        guard.pipeline.audit_buffer = crate::audit_buffer::AuditBuffer::new_with_wal(wal_path);
        guard
    }

    pub fn session_id(&self) -> Option<&str> {
        self.config.session_id.as_deref()
    }

    pub fn flush_audit(&self) -> Vec<crate::audit_buffer::AuditEvent> {
        self.pipeline.audit_buffer.flush()
    }

    #[cfg(feature = "hydration")]
    pub async fn hydrate_session(&self) -> Result<(), String> {
        let session_id = match &self.config.session_id {
            Some(id) if !id.is_empty() => id.clone(),
            _ => return Ok(()),
        };
        let cp_url = match &self.config.control_plane_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => return Ok(()),
        };

        let client = reqwest::Client::new();
        let url = format!("{}/v1/session/state", cp_url.trim_end_matches('/'));

        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "session_id": session_id,
                "tenant_id": self.config.tenant_id,
                "agent_id": self.config.agent_id,
            }))
            .send()
            .await
            .map_err(|e| format!("hydration request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("hydration returned status {}", resp.status()));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("hydration parse failed: {}", e))?;

        let hydrated = body.get("hydrated").and_then(|v| v.as_bool()).unwrap_or(false);
        if !hydrated {
            return Ok(());
        }

        let events: Vec<session::AuditEventReplay> = body
            .get("recent_tool_calls")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().enumerate().map(|(i, item)| session::AuditEventReplay {
                    sequence: i as u64 + 1,
                    tool_name: item.get("tool_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    args: serde_json::json!({}),
                    decision: item.get("decision").and_then(|v| v.as_str())
                        .and_then(|d| match d {
                            "Allow" => Some(DecisionType::Allow),
                            "Block" => Some(DecisionType::Block),
                            "Flag" => Some(DecisionType::Flag),
                            "Handover" => Some(DecisionType::Handover),
                            _ => None,
                        })
                        .unwrap_or(DecisionType::Allow),
                    timestamp: 0,
                    processing_time_us: 0,
                    reason: String::new(),
                    matched_rules: Vec::new(),
                }).collect()
            })
            .unwrap_or_default();

        if let Ok(mut tracker) = self.session_tracker.write() {
            tracker.hydrate_from_events(&events);
        }

        Ok(())
    }

    #[cfg(not(feature = "hydration"))]
    pub async fn hydrate_session(&self) -> Result<(), String> {
        Ok(())
    }
}
