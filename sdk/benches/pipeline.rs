use criterion::{black_box, criterion_group, criterion_main, Criterion};
use axiomguard_sdk::{
    Guard, GuardConfig, AgentPolicy, ToolPermission, CompiledRule, DecisionType,
};

fn setup_guard() -> Guard {
    let config = GuardConfig::builder()
        .tenant_id("bench-tenant")
        .agent_id("bench-agent")
        .build()
        .unwrap();
    Guard::new(config)
}

fn policy_with_deny_exec() -> AgentPolicy {
    AgentPolicy {
        agent_id: "bench-agent".into(),
        tool_allowlist: vec![
            ("exec".into(), ToolPermission::Deny),
            ("read_file".into(), ToolPermission::Allow),
        ].into_iter().collect(),
        rules: vec![],
        risk_threshold: 0.7,
        quota: None,
    }
}

fn policy_with_allow() -> AgentPolicy {
    AgentPolicy {
        agent_id: "bench-agent".into(),
        tool_allowlist: vec![
            ("read_file".into(), ToolPermission::Allow),
        ].into_iter().collect(),
        rules: vec![],
        risk_threshold: 0.7,
        quota: None,
    }
}

fn bench_block_tool_deny(c: &mut Criterion) {
    let guard = setup_guard();
    guard.load_policy(policy_with_deny_exec());
    let args = serde_json::json!({"command": "rm -rf /"});
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("block_tool_deny", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = guard.check(black_box("exec"), black_box(&args)).await;
        })
    });
}

fn bench_allow_tool_check(c: &mut Criterion) {
    let guard = setup_guard();
    guard.load_policy(policy_with_allow());
    let args = serde_json::json!({"path": "/tmp/safe.txt"});
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("allow_tool_check", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = guard.check(black_box("read_file"), black_box(&args)).await;
        })
    });
}

fn bench_cached_tool_check(c: &mut Criterion) {
    let guard = setup_guard();
    guard.load_policy(policy_with_allow());
    let args = serde_json::json!({"path": "/tmp/safe.txt"});
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(guard.check("read_file", &args)).unwrap();

    c.bench_function("cached_tool_check", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = guard.check(black_box("read_file"), black_box(&args)).await;
        })
    });
}

fn bench_100_rules(c: &mut Criterion) {
    let guard = setup_guard();
    let rules: Vec<CompiledRule> = (0..100).map(|i| CompiledRule {
        id: format!("rule-{}", i),
        name: format!("Test Rule {}", i),
        decision: if i == 50 { DecisionType::Block } else { DecisionType::Allow },
        priority: i,
        is_agent_specific: i < 50,
        is_active: true,
    }).collect();

    let policy = AgentPolicy {
        agent_id: "bench-agent".into(),
        tool_allowlist: vec![("exec".into(), ToolPermission::Allow)].into_iter().collect(),
        rules,
        risk_threshold: 0.7,
        quota: None,
    };
    guard.load_policy(policy);
    let args = serde_json::json!({"command": "ls"});
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("100_rules_evaluation", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = guard.check(black_box("exec"), black_box(&args)).await;
        })
    });
}

criterion_group!(
    benches,
    bench_block_tool_deny,
    bench_allow_tool_check,
    bench_cached_tool_check,
    bench_100_rules,
);
criterion_main!(benches);
