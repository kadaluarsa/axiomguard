use crate::types::*;
use crate::jsonlogic;
use crate::schema;
use crate::session::SessionTracker;
use crate::audit_buffer::{AuditBuffer, AuditEvent, AuditEventContext};
use std::sync::RwLock;
use std::time::Instant;

pub struct GuardPipeline {
    jsonlogic: jsonlogic::JsonLogicEngine,
    decision_cache: moka::sync::Cache<String, DecisionType>,
    pub(crate) audit_buffer: AuditBuffer,
    tenant_id: String,
    agent_id: String,
    stale_policy_action: StalePolicyAction,
}

impl GuardPipeline {
    pub fn new(config: &GuardConfig) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(config.cache_size as u64)
            .build();
        Self {
            jsonlogic: jsonlogic::JsonLogicEngine::new(),
            decision_cache: cache,
            audit_buffer: AuditBuffer::new(),
            tenant_id: config.tenant_id.clone(),
            agent_id: config.agent_id.clone(),
            stale_policy_action: config.stale_policy_action,
        }
    }

    fn emit_audit(&self, result: &GuardResult, tool_name: &str, session_id: Option<String>) {
        let ctx = AuditEventContext {
            tenant_id: self.tenant_id.clone(),
            agent_id: self.agent_id.clone(),
            session_id,
            tool_name: tool_name.to_string(),
        };
        let event = AuditEvent::from_guard_result(result, &ctx);
        self.audit_buffer.record(event);
    }


    pub async fn evaluate(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
        policy: &RwLock<Option<AgentPolicy>>,
        session: &RwLock<SessionTracker>,
    ) -> Result<GuardResult, GuardError> {
        let start = Instant::now();

        let cache_key = self.compute_cache_key(tool_name, args);

        if let Some(cached_decision) = self.decision_cache.get(&cache_key) {
            let result = GuardResult {
                decision: cached_decision,
                confidence: 1.0,
                reason: "cached".to_string(),
                matched_rules: vec!["cache".to_string()],
                tool_calls: Vec::new(),
                cached: true,
                risk_score: 0.0,
                processing_time_us: start.elapsed().as_micros() as u64,
            };
            let sid = session.read().ok().and_then(|s| s.session_id.clone());
            self.emit_audit(&result, tool_name, sid);
            return Ok(result);
        }

        let policy_guard = policy.read().map_err(|e| GuardError::Pipeline(e.to_string()))?;

        if let Some(ref pol) = *policy_guard {
            let now = chrono::Utc::now().timestamp();
            if now > pol.expires_at {
                match self.stale_policy_action {
                    StalePolicyAction::HardFail => {
                        return Err(GuardError::PolicyStale);
                    }
                    StalePolicyAction::Warn => {
                        tracing::warn!(
                            "Policy is stale for agent {}, continuing",
                            self.agent_id
                        );
                    }
                }
            }
        }

        if let Some(ref pol) = *policy_guard {
            if let Some(decision) = self.check_tool_allowlist(tool_name, pol) {
                drop(policy_guard);
                self.decision_cache.insert(cache_key, decision);

                {
                    let mut sess = session.write().map_err(|e| GuardError::Pipeline(e.to_string()))?;
                    sess.record_tool_call(tool_name, args, decision);
                }

                let result = GuardResult {
                    decision,
                    confidence: 1.0,
                    reason: format!("tool '{}' denied by allowlist", tool_name),
                    matched_rules: vec!["tool_allowlist".to_string()],
                    tool_calls: Vec::new(),
                    cached: false,
                    risk_score: 1.0,
                    processing_time_us: start.elapsed().as_micros() as u64,
                };
                let sid = session.read().ok().and_then(|s| s.session_id.clone());
                self.emit_audit(&result, tool_name, sid);
                return Ok(result);
            }
        }

        let schema_result = schema::validate_arguments(tool_name, args);
        if !schema_result.is_valid {
            drop(policy_guard);
            self.decision_cache.insert(cache_key, DecisionType::Block);

            {
                let mut sess = session.write().map_err(|e| GuardError::Pipeline(e.to_string()))?;
                sess.record_tool_call(tool_name, args, DecisionType::Block);
            }

            let result = GuardResult {
                decision: DecisionType::Block,
                confidence: 1.0,
                reason: format!(
                    "schema validation failed: {}",
                    schema_result.violations.join("; ")
                ),
                matched_rules: vec!["schema_validation".to_string()],
                tool_calls: Vec::new(),
                cached: false,
                risk_score: 1.0,
                processing_time_us: start.elapsed().as_micros() as u64,
            };
            let sid = session.read().ok().and_then(|s| s.session_id.clone());
            self.emit_audit(&result, tool_name, sid);
            return Ok(result);
        }

        let session_id_str = {
            let sess = session.read().map_err(|e| GuardError::Pipeline(e.to_string()))?;
            sess.session_id.clone()
        };

        let (mut decision, mut reason, mut risk_score, mut matched_rule_ids, had_match) =
            if let Some(ref pol) = *policy_guard {
                let matching_rule = pol
                    .rules
                    .iter()
                    .filter(|r| r.is_active)
                    .min_by_key(|r| r.priority);

                if let Some(rule) = matching_rule {
                    (
                        rule.decision,
                        rule.name.clone(),
                        0.5f32,
                        vec![rule.id.clone()],
                        true,
                    )
                } else {
                    (
                        DecisionType::Allow,
                        "no matching rule (fail-open)".to_string(),
                        0.0f32,
                        Vec::new(),
                        false,
                    )
                }
            } else {
                (
                    DecisionType::Allow,
                    "no matching rule (fail-open)".to_string(),
                    0.0f32,
                    Vec::new(),
                    false,
                )
            };

        drop(policy_guard);

        {
            let mut sess = session.write().map_err(|e| GuardError::Pipeline(e.to_string()))?;
            sess.record_tool_call(tool_name, args, decision);
        }

        let cumulative_risk = {
            let sess = session.read().map_err(|e| GuardError::Pipeline(e.to_string()))?;
            sess.risk_score()
        };
        let risk_threshold = {
            let policy_guard = policy.read().map_err(|e| GuardError::Pipeline(e.to_string()))?;
            policy_guard
                .as_ref()
                .map(|p| p.risk_threshold)
                .unwrap_or(0.7)
        };

        if cumulative_risk > risk_threshold && decision == DecisionType::Allow {
            decision = if cumulative_risk > risk_threshold * 1.5 {
                DecisionType::Handover
            } else {
                DecisionType::Flag
            };
            reason = format!(
                "{} (risk override: cumulative risk {:.2} exceeds threshold {:.2})",
                reason, cumulative_risk, risk_threshold
            );
            risk_score = cumulative_risk;
        }

        self.decision_cache.insert(cache_key, decision);

        let result = GuardResult {
            decision,
            confidence: if had_match { 0.95 } else { 0.5 },
            reason,
            matched_rules: matched_rule_ids,
            tool_calls: Vec::new(),
            cached: false,
            risk_score,
            processing_time_us: start.elapsed().as_micros() as u64,
        };
        self.emit_audit(&result, tool_name, session_id_str);
        return Ok(result);
    }

    fn check_tool_allowlist(&self, tool_name: &str, policy: &AgentPolicy) -> Option<DecisionType> {
        match policy.tool_allowlist.get(tool_name) {
            Some(ToolPermission::Deny) => Some(DecisionType::Block),
            Some(ToolPermission::Restrict { allowed_args: _ }) => None,
            Some(ToolPermission::Allow) => None,
            None => None,
        }
    }

    fn evaluate_rules<'a>(
        &self,
        rules: &'a [CompiledRule],
        _context: &serde_json::Value,
    ) -> Option<&'a CompiledRule> {
        let mut sorted: Vec<&CompiledRule> = rules.iter().filter(|r| r.is_active).collect();
        sorted.sort_by_key(|r| r.priority);
        sorted.into_iter().next()
    }

    fn compute_cache_key(&self, tool_name: &str, args: &serde_json::Value) -> String {
        use sha2::{Digest, Sha256};

        let canonical = serde_json::to_string(args).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let hash = hasher.finalize();

        format!(
            "{}:{}:{}:{:x}",
            self.tenant_id,
            self.agent_id,
            tool_name,
            hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> GuardConfig {
        GuardConfigBuilder::default()
            .tenant_id("tenant-1")
            .agent_id("agent-1")
            .build()
            .unwrap()
    }

    fn test_session() -> RwLock<SessionTracker> {
        RwLock::new(SessionTracker::new(None, "tenant-1".to_string(), "agent-1".to_string()))
    }

    fn deny_policy() -> AgentPolicy {
        let mut tool_allowlist = HashMap::new();
        tool_allowlist.insert("dangerous_tool".to_string(), ToolPermission::Deny);
        let now = chrono::Utc::now().timestamp();

        AgentPolicy {
            agent_id: "agent-1".to_string(),
            tool_allowlist,
            rules: Vec::new(),
            risk_threshold: 0.7,
            quota: None,
            fetched_at: now,
            expires_at: now + 3600,
        }
    }

    fn policy_with_rules() -> AgentPolicy {
        let now = chrono::Utc::now().timestamp();
        AgentPolicy {
            agent_id: "agent-1".to_string(),
            tool_allowlist: HashMap::new(),
            rules: vec![
                CompiledRule {
                    id: "rule-low".to_string(),
                    name: "low priority rule".to_string(),
                    decision: DecisionType::Flag,
                    priority: 100,
                    is_agent_specific: false,
                    is_active: true,
                },
                CompiledRule {
                    id: "rule-high".to_string(),
                    name: "high priority rule".to_string(),
                    decision: DecisionType::Block,
                    priority: 1,
                    is_agent_specific: false,
                    is_active: true,
                },
            ],
            risk_threshold: 0.7,
            quota: None,
            fetched_at: now,
            expires_at: now + 3600,
        }
    }

    fn stale_policy() -> AgentPolicy {
        let mut tool_allowlist = HashMap::new();
        tool_allowlist.insert("dangerous_tool".to_string(), ToolPermission::Deny);
        let now = chrono::Utc::now().timestamp();

        AgentPolicy {
            agent_id: "agent-1".to_string(),
            tool_allowlist,
            rules: Vec::new(),
            risk_threshold: 0.7,
            quota: None,
            fetched_at: now - 7200,
            expires_at: now - 3600,
        }
    }

    #[tokio::test]
    async fn test_tool_denial_returns_block() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = RwLock::new(Some(deny_policy()));

        let result = pipeline
            .evaluate("dangerous_tool", &serde_json::json!({}), &policy, &session)
            .await
            .unwrap();

        assert_eq!(result.decision, DecisionType::Block);
        assert!(!result.cached);
    }

    #[tokio::test]
    async fn test_missing_policy_returns_allow() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy: RwLock<Option<AgentPolicy>> = RwLock::new(None);

        let result = pipeline
            .evaluate("some_tool", &serde_json::json!({"arg": "value"}), &policy, &session)
            .await
            .unwrap();

        assert_eq!(result.decision, DecisionType::Allow);
    }

    #[tokio::test]
    async fn test_rule_evaluation_respects_priority() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = RwLock::new(Some(policy_with_rules()));

        let result = pipeline
            .evaluate("some_tool", &serde_json::json!({}), &policy, &session)
            .await
            .unwrap();

        assert_eq!(result.decision, DecisionType::Block);
        assert!(result.matched_rules.contains(&"rule-high".to_string()));
    }

    #[tokio::test]
    async fn test_cache_hit_returns_cached_result() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = RwLock::new(Some(deny_policy()));

        let result1 = pipeline
            .evaluate("safe_tool", &serde_json::json!({"x": 1}), &policy, &session)
            .await
            .unwrap();

        let result2 = pipeline
            .evaluate("safe_tool", &serde_json::json!({"x": 1}), &policy, &session)
            .await
            .unwrap();

        assert!(!result1.cached);
        assert!(result2.cached);
        assert_eq!(result2.decision, result1.decision);
    }

    #[tokio::test]
    async fn test_schema_validation_blocks_dangerous_args() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy: RwLock<Option<AgentPolicy>> = RwLock::new(None);

        let result = pipeline
            .evaluate(
                "exec",
                &serde_json::json!({"command": "rm -rf /"}),
                &policy,
                &session,
            )
            .await
            .unwrap();

        assert_eq!(result.decision, DecisionType::Block);
        assert!(result.reason.contains("schema"));
    }

    #[tokio::test]
    async fn test_audit_emitted_on_cache_hit() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = std::sync::RwLock::new(Some(deny_policy()));

        let _r1 = pipeline
            .evaluate("safe_tool", &serde_json::json!({"x": 1}), &policy, &session)
            .await
            .unwrap();

        let _r2 = pipeline
            .evaluate("safe_tool", &serde_json::json!({"x": 1}), &policy, &session)
            .await
            .unwrap();

        assert_eq!(pipeline.audit_buffer.len(), 2);
    }

    #[tokio::test]
    async fn test_audit_emitted_on_allowlist_deny() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = std::sync::RwLock::new(Some(deny_policy()));

        let res = pipeline
            .evaluate("dangerous_tool", &serde_json::json!({}), &policy, &session)
            .await
            .unwrap();

        assert_eq!(pipeline.audit_buffer.len(), 1);
        assert_eq!(res.decision, DecisionType::Block);
    }

    #[tokio::test]
    async fn test_audit_emitted_on_schema_block() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy: std::sync::RwLock<Option<AgentPolicy>> = std::sync::RwLock::new(None);

        let res = pipeline
            .evaluate(
                "exec",
                &serde_json::json!({"command": "rm -rf /"}),
                &policy,
                &session,
            )
            .await
            .unwrap();

        assert_eq!(res.decision, DecisionType::Block);
        // schema path should produce an audit as well
        assert!(pipeline.audit_buffer.len() >= 1);
    }

    #[tokio::test]
    async fn test_flush_returns_events_and_clears() {
        let config = test_config();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy: std::sync::RwLock<Option<AgentPolicy>> = std::sync::RwLock::new(None);

        let _ = pipeline
            .evaluate("some_tool", &serde_json::json!({"a": 1}), &policy, &session)
            .await
            .unwrap();
        let _ = pipeline
            .evaluate("exec", &serde_json::json!({"command": "echo hi"}), &policy, &session)
            .await
            .unwrap();
        let _ = pipeline
            .evaluate("dangerous_tool", &serde_json::json!({}), &policy, &session)
            .await
            .unwrap();

        let events = pipeline.audit_buffer.flush();
        assert_eq!(events.len(), 3);
        assert!(pipeline.audit_buffer.is_empty());
    }

    #[tokio::test]
    async fn test_stale_policy_warn_continues() {
        let config = GuardConfigBuilder::default()
            .tenant_id("tenant-1")
            .agent_id("agent-1")
            .stale_policy_action(StalePolicyAction::Warn)
            .build()
            .unwrap();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = std::sync::RwLock::new(Some(stale_policy()));

        let result = pipeline
            .evaluate("dangerous_tool", &serde_json::json!({}), &policy, &session)
            .await
            .unwrap();

        assert_eq!(result.decision, DecisionType::Block);
    }

    #[tokio::test]
    async fn test_stale_policy_hard_fail() {
        let config = GuardConfigBuilder::default()
            .tenant_id("tenant-1")
            .agent_id("agent-1")
            .stale_policy_action(StalePolicyAction::HardFail)
            .build()
            .unwrap();
        let pipeline = GuardPipeline::new(&config);
        let session = test_session();
        let policy = std::sync::RwLock::new(Some(stale_policy()));

        let result = pipeline
            .evaluate("dangerous_tool", &serde_json::json!({}), &policy, &session)
            .await;

        assert!(matches!(result, Err(GuardError::PolicyStale)));
    }
}
