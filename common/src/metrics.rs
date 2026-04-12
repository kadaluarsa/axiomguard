use once_cell::sync::Lazy;
use prometheus::{
    exponential_buckets, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry, HistogramOpts,
    HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
};

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

// Counter metrics
pub static AUDIT_EVENTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        Opts::new(
            "axiomguard_audit_events_total",
            "Total audit events processed"
        ),
        &["decision", "source"],
        REGISTRY.clone()
    )
    .unwrap()
});

pub static AUDIT_ERRORS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter_with_registry!(
        Opts::new(
            "axiomguard_audit_errors_total",
            "Total audit processing errors"
        ),
        REGISTRY.clone()
    )
    .unwrap()
});

pub static WEBHOOK_DELIVERIES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        Opts::new(
            "axiomguard_webhook_deliveries_total",
            "Total webhook deliveries attempted"
        ),
        &["status", "endpoint"],
        REGISTRY.clone()
    )
    .unwrap()
});

pub static DB_OPERATIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        Opts::new(
            "axiomguard_db_operations_total",
            "Total database operations executed"
        ),
        &["operation", "status"],
        REGISTRY.clone()
    )
    .unwrap()
});

// Histogram metrics for latency
pub static AUDIT_PROCESSING_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    let buckets = exponential_buckets(0.001, 2.0, 15).unwrap();
    let opts = HistogramOpts::new(
        "axiomguard_audit_processing_duration_seconds",
        "Audit event total processing time in seconds",
    )
    .buckets(buckets);

    register_histogram_vec_with_registry!(opts, &["stage"], REGISTRY.clone()).unwrap()
});

pub static AI_PROCESSING_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    let buckets = exponential_buckets(0.001, 2.0, 15).unwrap();
    let opts = HistogramOpts::new(
        "axiomguard_ai_processing_duration_seconds",
        "AI model inference processing time in seconds",
    )
    .buckets(buckets);

    register_histogram_vec_with_registry!(opts, &["model"], REGISTRY.clone()).unwrap()
});

pub static DB_OPERATION_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    let buckets = exponential_buckets(0.0001, 2.0, 14).unwrap();
    let opts = HistogramOpts::new(
        "axiomguard_db_operation_duration_seconds",
        "Database operation execution time in seconds",
    )
    .buckets(buckets);

    register_histogram_vec_with_registry!(opts, &["operation"], REGISTRY.clone()).unwrap()
});

pub static WEBHOOK_DELIVERY_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    let buckets = exponential_buckets(0.01, 2.0, 12).unwrap();
    let opts = HistogramOpts::new(
        "axiomguard_webhook_delivery_duration_seconds",
        "Webhook delivery request time in seconds",
    )
    .buckets(buckets);

    register_histogram_vec_with_registry!(opts, &["endpoint"], REGISTRY.clone()).unwrap()
});

// System resource metrics
pub static SYSTEM_MEMORY_USAGE_BYTES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        Opts::new(
            "axiomguard_system_memory_usage_bytes",
            "System memory usage in bytes"
        ),
        &["type"],
        REGISTRY.clone()
    )
    .unwrap()
});

pub static SYSTEM_GPU_UTILIZATION: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "axiomguard_system_gpu_utilization_ratio",
        "GPU utilization ratio 0.0-1.0",
    );
    register_histogram_vec_with_registry!(opts, &["gpu_id"], REGISTRY.clone()).unwrap()
});
