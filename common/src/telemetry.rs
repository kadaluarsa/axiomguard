//! Distributed tracing for AxiomGuard
//!
//! Provides OpenTelemetry-compatible tracing for request correlation across services.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Unique trace ID for request correlation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(pub String);

impl TraceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
    
    pub fn from_string(id: String) -> Self {
        Self(id)
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

/// Span ID for individual operations within a trace
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpanId(pub String);

impl SpanId {
    pub fn new() -> Self {
        // Use hex encoding without dashes
        Self(Uuid::new_v4().as_simple().to_string()[..16].to_string())
    }
}

impl Default for SpanId {
    fn default() -> Self {
        Self::new()
    }
}

/// Trace context propagated across services
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub sampled: bool,
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            trace_id: TraceId::new(),
            span_id: SpanId::new(),
            parent_span_id: None,
            sampled: true,
            baggage: HashMap::new(),
        }
    }
    
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: SpanId::new(),
            parent_span_id: Some(self.span_id.clone()),
            sampled: self.sampled,
            baggage: self.baggage.clone(),
        }
    }
    
    /// Convert to W3C traceparent header format
    pub fn to_traceparent(&self) -> String {
        // W3C format: 00-<trace-id>-<span-id>-<flags>
        // Flags: 01 = sampled, 00 = not sampled
        let flags = if self.sampled { "01" } else { "00" };
        format!("00-{}-{}-{}", self.trace_id.0.replace("-", ""), self.span_id.0, flags)
    }
    
    /// Parse from W3C traceparent header
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        
        // parts[0] = version (00)
        // parts[1] = trace-id (32 hex chars)
        // parts[2] = span-id (16 hex chars)
        // parts[3] = flags (00 or 01)
        
        let trace_id = format!("{}-{}-{}-{}-{}", 
            &parts[1][0..8],
            &parts[1][8..12],
            &parts[1][12..16],
            &parts[1][16..20],
            &parts[1][20..32]
        );
        
        Some(Self {
            trace_id: TraceId::from_string(trace_id),
            span_id: SpanId(parts[2].to_string()),
            parent_span_id: None,
            sampled: parts[3] == "01",
            baggage: HashMap::new(),
        })
    }
    
    /// Add baggage item
    pub fn with_baggage(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.baggage.insert(key.into(), value.into());
        self
    }
    
    /// Get tenant ID from baggage
    pub fn tenant_id(&self) -> Option<&str> {
        self.baggage.get("tenant_id").map(|s| s.as_str())
    }
    
    /// Get user ID from baggage
    pub fn user_id(&self) -> Option<&str> {
        self.baggage.get("user_id").map(|s| s.as_str())
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A span represents a single operation within a trace
#[derive(Debug, Clone)]
pub struct Span {
    pub context: TraceContext,
    pub name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub attributes: HashMap<String, String>,
    pub status: SpanStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

impl Span {
    pub fn new(name: impl Into<String>, context: TraceContext) -> Self {
        Self {
            context,
            name: name.into(),
            start_time: Utc::now(),
            end_time: None,
            attributes: HashMap::new(),
            status: SpanStatus::Unset,
        }
    }
    
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }
    
    pub fn set_error(&mut self) {
        self.status = SpanStatus::Error;
    }
    
    pub fn set_ok(&mut self) {
        self.status = SpanStatus::Ok;
    }
    
    pub fn finish(mut self) -> FinishedSpan {
        self.end_time = Some(Utc::now());
        FinishedSpan {
            span: self,
        }
    }
    
    pub fn duration_ms(&self) -> i64 {
        let end = self.end_time.unwrap_or_else(Utc::now);
        (end - self.start_time).num_milliseconds()
    }
}

#[derive(Debug, Clone)]
pub struct FinishedSpan {
    pub span: Span,
}

/// Tracer for creating and managing spans
pub struct Tracer {
    service_name: String,
    spans: Arc<RwLock<Vec<FinishedSpan>>>,
}

impl Tracer {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            spans: Arc::new(RwLock::new(vec![])),
        }
    }
    
    /// Start a new trace
    pub fn start_trace(&self, operation_name: impl Into<String>) -> Span {
        Span::new(operation_name, TraceContext::new())
            .with_attribute("service.name", &self.service_name)
    }
    
    /// Continue a trace from incoming context
    pub fn continue_trace(&self, operation_name: impl Into<String>, context: TraceContext) -> Span {
        Span::new(operation_name, context.child())
            .with_attribute("service.name", &self.service_name)
    }
    
    /// Record a finished span
    pub async fn record_span(&self, span: FinishedSpan) {
        let mut spans = self.spans.write().await;
        spans.push(span);
        
        // Keep only last 10000 spans in memory
        if spans.len() > 10000 {
            spans.remove(0);
        }
    }
    
    /// Get all recorded spans
    pub async fn get_spans(&self) -> Vec<FinishedSpan> {
        self.spans.read().await.clone()
    }
    
    /// Export spans (placeholder for OTLP/Jaeger export)
    pub async fn export_spans(&self) -> Result<(), Box<dyn std::error::Error>> {
        let spans = self.get_spans().await;
        
        // In production, this would send to Jaeger/Tempo/OTLP
        for span in spans {
            tracing::info!(
                trace_id = %span.span.context.trace_id.0,
                span_id = %span.span.context.span_id.0,
                operation = %span.span.name,
                duration_ms = span.span.duration_ms(),
                status = ?span.span.status,
                "Span exported"
            );
        }
        
        Ok(())
    }
    
    /// Extract trace context from HTTP headers
    pub fn extract_from_headers(&self, headers: &HashMap<String, String>) -> Option<TraceContext> {
        // Try W3C traceparent
        if let Some(traceparent) = headers.get("traceparent") {
            if let Some(ctx) = TraceContext::from_traceparent(traceparent) {
                return Some(ctx);
            }
        }
        
        // Try X-Request-ID as trace ID
        if let Some(request_id) = headers.get("x-request-id") {
            let mut ctx = TraceContext::new();
            ctx.trace_id = TraceId::from_string(request_id.clone());
            
            // Extract baggage
            if let Some(tenant_id) = headers.get("x-tenant-id") {
                ctx.baggage.insert("tenant_id".to_string(), tenant_id.clone());
            }
            if let Some(user_id) = headers.get("x-user-id") {
                ctx.baggage.insert("user_id".to_string(), user_id.clone());
            }
            
            return Some(ctx);
        }
        
        None
    }
    
    /// Inject trace context into HTTP headers
    pub fn inject_into_headers(&self, context: &TraceContext) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        
        headers.insert("traceparent".to_string(), context.to_traceparent());
        headers.insert("x-request-id".to_string(), context.trace_id.0.clone());
        
        for (key, value) in &context.baggage {
            headers.insert(format!("x-baggage-{}", key), value.clone());
        }
        
        headers
    }
}

/// Extension trait for adding tracing to spans
pub trait SpanExt {
    fn with_attribute(self, key: impl Into<String>, value: impl Into<String>) -> Self;
    fn with_tenant(self, tenant_id: impl Into<String>) -> Self;
    fn with_user(self, user_id: impl Into<String>) -> Self;
}

impl SpanExt for Span {
    fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_attribute(key, value);
        self
    }
    
    fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.context.baggage.insert("tenant_id".to_string(), tenant_id.into());
        self
    }
    
    fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.context.baggage.insert("user_id".to_string(), user_id.into());
        self
    }
}

/// Global tracer instance - thread-safe initialization
use std::sync::OnceLock;
static GLOBAL_TRACER: OnceLock<Tracer> = OnceLock::new();

/// Initialize the global tracer - safe to call multiple times
pub fn init_tracer(service_name: impl Into<String>) -> &'static Tracer {
    GLOBAL_TRACER.get_or_init(|| Tracer::new(service_name))
}

/// Get the global tracer - panics if not initialized
pub fn tracer() -> &'static Tracer {
    GLOBAL_TRACER.get().expect("Tracer not initialized. Call init_tracer() first.")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trace_context_generation() {
        let ctx = TraceContext::new();
        assert!(!ctx.trace_id.0.is_empty());
        assert!(!ctx.span_id.0.is_empty());
        assert!(ctx.sampled);
    }
    
    #[test]
    fn test_trace_context_child() {
        let parent = TraceContext::new();
        let child = parent.child();
        
        assert_eq!(parent.trace_id.0, child.trace_id.0);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }
    
    #[test]
    fn test_traceparent_format() {
        let ctx = TraceContext::new();
        let traceparent = ctx.to_traceparent();
        
        // Format: 00-<32-hex>-<16-hex>-01
        assert!(traceparent.starts_with("00-"));
        assert!(traceparent.ends_with("-01"));
        
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[1].len(), 32);  // trace-id
        assert_eq!(parts[2].len(), 16);  // span-id
    }
    
    #[test]
    fn test_traceparent_roundtrip() {
        let original = TraceContext::new();
        let traceparent = original.to_traceparent();
        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();
        
        assert_eq!(original.trace_id.0.replace("-", ""), parsed.trace_id.0.replace("-", ""));
        assert_eq!(original.span_id.0, parsed.span_id.0);
        assert_eq!(original.sampled, parsed.sampled);
    }
    
    #[test]
    fn test_baggage() {
        let ctx = TraceContext::new()
            .with_baggage("tenant_id", "tenant-123")
            .with_baggage("user_id", "user-456");
        
        assert_eq!(ctx.tenant_id(), Some("tenant-123"));
        assert_eq!(ctx.user_id(), Some("user-456"));
    }
    
    #[tokio::test]
    async fn test_tracer() {
        let tracer = Tracer::new("test-service");
        
        let span = tracer.start_trace("test-operation")
            .with_attribute("key", "value")
            .with_tenant("tenant-123");
        
        assert_eq!(span.name, "test-operation");
        assert_eq!(span.context.baggage.get("tenant_id"), Some(&"tenant-123".to_string()));
        
        let finished = span.finish();
        tracer.record_span(finished).await;
        
        let spans = tracer.get_spans().await;
        assert_eq!(spans.len(), 1);
    }
    
    #[test]
    fn test_header_extraction() {
        let tracer = Tracer::new("test");
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "abc-123".to_string());
        headers.insert("x-tenant-id".to_string(), "tenant-456".to_string());
        
        let ctx = tracer.extract_from_headers(&headers).unwrap();
        assert_eq!(ctx.trace_id.0, "abc-123");
        assert_eq!(ctx.tenant_id(), Some("tenant-456"));
    }
}
