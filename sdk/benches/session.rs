use axiomguard_sdk::session::SessionTracker;
use axiomguard_sdk::DecisionType;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_session_single_call(c: &mut Criterion) {
    let mut tracker = SessionTracker::new(
        Some("session-1".into()),
        "tenant-1".into(),
        "agent-1".into(),
    );
    let args = serde_json::json!({"path": "/tmp/file.txt"});

    c.bench_function("session_single_call", |b| {
        b.iter(|| {
            tracker.record_tool_call(
                black_box("read_file"),
                black_box(&args),
                black_box(DecisionType::Allow),
            )
        })
    });
}

fn bench_session_10_call_sequence(c: &mut Criterion) {
    c.bench_function("session_10_call_sequence", |b| {
        b.iter(|| {
            let mut tracker = SessionTracker::new(
                Some("session-seq".into()),
                "tenant-1".into(),
                "agent-1".into(),
            );
            let calls = [
                ("read_file", DecisionType::Allow),
                ("exec", DecisionType::Allow),
                ("http_post", DecisionType::Allow),
                ("write_file", DecisionType::Allow),
                ("read_file", DecisionType::Allow),
                ("exec", DecisionType::Allow),
                ("http_post", DecisionType::Allow),
                ("read_file", DecisionType::Allow),
                ("exec", DecisionType::Allow),
                ("http_post", DecisionType::Allow),
            ];
            for (tool, decision) in &calls {
                let args = serde_json::json!({"command": "test"});
                tracker.record_tool_call(tool, &args, *decision);
            }
            tracker.risk_score()
        })
    });
}

fn bench_pattern_detection(c: &mut Criterion) {
    let mut tracker = SessionTracker::new(
        Some("session-attack".into()),
        "tenant-1".into(),
        "agent-1".into(),
    );
    let args = serde_json::json!({"command": "base64 data"});
    tracker.record_tool_call("read_file", &args, DecisionType::Allow);
    tracker.record_tool_call("exec", &args, DecisionType::Allow);

    c.bench_function("pattern_detection_on_3rd_call", |b| {
        b.iter(|| {
            let mut t = tracker.clone();
            t.record_tool_call(
                black_box("http_post"),
                black_box(&args),
                black_box(DecisionType::Allow),
            );
            t.risk_score()
        })
    });
}

criterion_group!(
    benches,
    bench_session_single_call,
    bench_session_10_call_sequence,
    bench_pattern_detection,
);
criterion_main!(benches);
