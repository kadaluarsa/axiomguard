use prometheus::{IntCounter, Histogram, HistogramOpts, opts};

#[derive(Clone)]
pub struct McpMetrics {
    pub total_requests: IntCounter,
    pub tool_calls: IntCounter,
    pub auth_failures: IntCounter,
    pub shield_latency: Histogram,
}

impl McpMetrics {
    pub fn new() -> Self {
        let registry = common::metrics::REGISTRY.clone();

        let total_requests = IntCounter::with_opts(
            opts!("axiomguard_mcp_total_requests", "Total MCP requests received")
        ).unwrap();

        let tool_calls = IntCounter::with_opts(
            opts!("axiomguard_mcp_tool_calls", "Total MCP tool calls")
        ).unwrap();

        let auth_failures = IntCounter::with_opts(
            opts!("axiomguard_mcp_auth_failures", "MCP authentication failures")
        ).unwrap();

        let shield_latency = Histogram::with_opts(
            HistogramOpts::from(
                opts!("axiomguard_mcp_shield_latency_ms", "gRPC call latency to shield service")
            )
        ).unwrap();

        registry.register(Box::new(total_requests.clone())).ok();
        registry.register(Box::new(tool_calls.clone())).ok();
        registry.register(Box::new(auth_failures.clone())).ok();
        registry.register(Box::new(shield_latency.clone())).ok();

        Self {
            total_requests,
            tool_calls,
            auth_failures,
            shield_latency,
        }
    }
}

impl Default for McpMetrics {
    fn default() -> Self {
        Self::new()
    }
}
