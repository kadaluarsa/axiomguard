use criterion::{criterion_group, criterion_main, Criterion};
use common::*;
use engine::AuditEngine;
use rand::Rng;
use chrono::Utc;
use uuid::Uuid;

fn create_test_rules() -> Vec<AuditRule> {
    vec![
        AuditRule {
            id: "rule1".to_string(),
            name: "Block high value transactions".to_string(),
            description: "Blocks transactions over $1000".to_string(),
            conditions: vec![
                RuleCondition {
                    field: "transaction.amount".to_string(),
                    operator: ConditionOperator::GreaterThan,
                    value: serde_json::json!(1000),
                },
            ],
            decision: DecisionType::Block,
            priority: 1,
            enabled: true,
        },
        AuditRule {
            id: "rule2".to_string(),
            name: "Flag unusual activity".to_string(),
            description: "Flags transactions from unusual locations".to_string(),
            conditions: vec![
                RuleCondition {
                    field: "user.region".to_string(),
                    operator: ConditionOperator::In,
                    value: serde_json::json!(["unknown", "suspicious"]),
                },
            ],
            decision: DecisionType::Flag,
            priority: 2,
            enabled: true,
        },
        AuditRule {
            id: "rule3".to_string(),
            name: "Review large transfers".to_string(),
            description: "Requires review for transfers over $5000".to_string(),
            conditions: vec![
                RuleCondition {
                    field: "transaction.amount".to_string(),
                    operator: ConditionOperator::GreaterThan,
                    value: serde_json::json!(5000),
                },
                RuleCondition {
                    field: "transaction.currency".to_string(),
                    operator: ConditionOperator::Equals,
                    value: serde_json::json!("USD"),
                },
            ],
            decision: DecisionType::Review,
            priority: 3,
            enabled: true,
        },
    ]
}

fn generate_random_event() -> AuditEvent {
    let mut rng = rand::thread_rng();
    
    let sources = ["payment_gateway", "api_gateway", "mobile_app", "web_app"];
    let event_types = ["transaction", "login", "api_call", "data_access"];
    let regions = ["us-east-1", "eu-west-1", "ap-southeast-1", "unknown", "suspicious"];
    
    let amount = rng.gen_range(1.0..10000.0);
    let source = sources[rng.gen_range(0..sources.len())];
    let event_type = event_types[rng.gen_range(0..event_types.len())];
    let region = regions[rng.gen_range(0..regions.len())];
    
    let data = serde_json::json!({
        "transaction": {
            "id": format!("txn{}", rng.gen_range(1000..9999)),
            "amount": amount,
            "currency": "USD"
        },
        "user": {
            "id": format!("user{}", rng.gen_range(1..1000)),
            "region": region,
            "email": format!("user{}@example.com", rng.gen_range(1..1000))
        },
        "metadata": {
            "timestamp": Utc::now().to_rfc3339(),
            "ip_address": format!("{}.{}.{}.{}", 
                rng.gen_range(0..255), 
                rng.gen_range(0..255), 
                rng.gen_range(0..255), 
                rng.gen_range(0..255)
            ),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    });
    
    AuditEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        source: source.to_string(),
        event_type: event_type.to_string(),
        data,
    }
}

async fn engine_performance_test(engine: &engine::AuditEngine, events: Vec<AuditEvent>) {
    for event in events {
        let _ = engine.process_event(&event).await;
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let engine = engine::AuditEngine::new();
    let rules = create_test_rules();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        engine.update_rules(rules).await;
    });

    let mut group = c.benchmark_group("Engine Performance");
    group.sample_size(1000);
    group.measurement_time(std::time::Duration::from_secs(30));
    
    // Single event processing
    group.bench_function("single_event", |b| {
        let event = generate_random_event();
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| engine.process_event(&event));
    });
    
    // Batch processing
    let batch_sizes = [10, 100, 1000];
    for &size in &batch_sizes {
        let events: Vec<_> = (0..size).map(|_| generate_random_event()).collect();
        
        group.bench_function(format!("batch_{}", size), |b| {
            let events = events.clone();
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| engine_performance_test(&engine, events.clone()));
        });
    }
    
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);