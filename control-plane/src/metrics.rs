use prometheus::{opts, Histogram, HistogramOpts, IntCounter, Registry};
use std::sync::LazyLock;

pub static CP_REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry::new());

pub static REQUESTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let c =
        IntCounter::with_opts(opts!("axiomguard_cp_requests_total", "Total CP requests")).unwrap();
    CP_REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub static TOKEN_ISSUANCES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::with_opts(opts!("axiomguard_cp_token_issuances", "Tokens issued")).unwrap();
    CP_REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub static BYPASS_ALERTS: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::with_opts(opts!(
        "axiomguard_cp_bypass_alerts",
        "Bypass attempts detected"
    ))
    .unwrap();
    CP_REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub static REQUEST_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    let h = Histogram::with_opts(HistogramOpts::new(
        "axiomguard_cp_request_latency_ms",
        "Request latency",
    ))
    .unwrap();
    CP_REGISTRY.register(Box::new(h.clone())).ok();
    h
});

pub fn metrics_handler() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = CP_REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
