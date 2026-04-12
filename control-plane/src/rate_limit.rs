use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 60,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: u32,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    buckets: DashMap<String, Bucket>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: DashMap::new(),
            config,
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let max = self.config.max_requests;
        let window = std::time::Duration::from_secs(self.config.window_secs);

        let mut entry = self.buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: max,
            last_refill: now,
        });

        let elapsed = now.duration_since(entry.last_refill);
        if elapsed >= window {
            entry.tokens = max;
            entry.last_refill = now;
        }

        if entry.tokens > 0 {
            entry.tokens -= 1;
            true
        } else {
            false
        }
    }

    pub fn cleanup(&self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.config.window_secs * 2);
        self.buckets
            .retain(|_, bucket| bucket.last_refill > cutoff);
    }
}

pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("anonymous")
        .to_string();

    if !limiter.check(&key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}
