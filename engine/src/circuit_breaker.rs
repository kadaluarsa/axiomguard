//! Circuit breaker pattern for AI backend protection
//!
//! Prevents cascading failures and cost explosions during AI service outages

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Failing fast - requests rejected immediately
    Open,
    /// Testing if service recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Successes required to close circuit from half-open
    pub success_threshold: u32,
    /// Duration to wait before trying half-open
    pub timeout_duration: Duration,
    /// Percentage of requests to allow through in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,           // Open after 5 failures
            success_threshold: 3,           // Close after 3 successes
            timeout_duration: Duration::from_secs(30), // Try again after 30s
            half_open_max_requests: 3,      // Allow 3 test requests
        }
    }
}

/// Circuit breaker for AI backend
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    config: CircuitBreakerConfig,
    
    // Failure tracking
    failure_count: AtomicU32,
    success_count: AtomicU32,
    consecutive_successes: AtomicU32,
    
    // Timing
    last_failure_time: RwLock<Option<Instant>>,
    last_state_change: RwLock<Instant>,
    
    // Half-open tracking
    half_open_requests: AtomicU32,
    
    // Metrics
    name: String,
}

/// Error types for circuit breaker
#[derive(Debug, Clone, thiserror::Error)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is OPEN - service unavailable")]
    CircuitOpen,
    
    #[error("Circuit breaker is HALF_OPEN - limited requests allowed")]
    CircuitHalfOpen,
    
    #[error("Too many requests in half-open state")]
    HalfOpenLimitExceeded,
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_config(name, CircuitBreakerConfig::default())
    }
    
    pub fn with_config(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            config,
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
            last_state_change: RwLock::new(Instant::now()),
            half_open_requests: AtomicU32::new(0),
            name: name.into(),
        }
    }
    
    /// Get current state
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }
    
    /// Check if circuit allows request through
    pub async fn allow_request(&self) -> Result<(), CircuitBreakerError> {
        let mut state = self.state.write().await;
        
        match *state {
            CircuitState::Closed => {
                // Normal operation - allow
                Ok(())
            }
            CircuitState::Open => {
                // Check if timeout has elapsed
                let should_try_half_open = {
                    let last_change = *self.last_state_change.read().await;
                    last_change.elapsed() >= self.config.timeout_duration
                };
                
                if should_try_half_open {
                    info!(
                        name = %self.name,
                        "Circuit transitioning to HALF_OPEN"
                    );
                    *state = CircuitState::HalfOpen;
                    *self.last_state_change.write().await = Instant::now();
                    self.half_open_requests.store(0, Ordering::SeqCst);
                    Ok(())
                } else {
                    // Still in timeout
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }
            CircuitState::HalfOpen => {
                // Limited requests allowed
                let current_requests = self.half_open_requests.fetch_add(1, Ordering::SeqCst);
                
                if current_requests >= self.config.half_open_max_requests {
                    // Too many concurrent test requests
                    self.half_open_requests.fetch_sub(1, Ordering::SeqCst);
                    Err(CircuitBreakerError::HalfOpenLimitExceeded)
                } else {
                    Ok(())
                }
            }
        }
    }
    
    /// Record a successful request
    pub async fn record_success(&self) {
        let state = *self.state.read().await;
        
        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
                self.success_count.fetch_add(1, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let successes = self.consecutive_successes.fetch_add(1, Ordering::SeqCst) + 1;
                
                if successes >= self.config.success_threshold {
                    // Close the circuit
                    let mut state = self.state.write().await;
                    if *state == CircuitState::HalfOpen {
                        info!(
                            name = %self.name,
                            successes = successes,
                            "Circuit transitioning to CLOSED"
                        );
                        *state = CircuitState::Closed;
                        *self.last_state_change.write().await = Instant::now();
                        self.failure_count.store(0, Ordering::SeqCst);
                        self.consecutive_successes.store(0, Ordering::SeqCst);
                    }
                }
                
                // Decrement half-open counter
                self.half_open_requests.fetch_sub(1, Ordering::SeqCst);
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }
    
    /// Record a failed request
    pub async fn record_failure(&self) {
        let state = *self.state.read().await;
        
        match state {
            CircuitState::Closed => {
                let failures = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                *self.last_failure_time.write().await = Some(Instant::now());
                
                if failures >= self.config.failure_threshold {
                    // Open the circuit
                    let mut state = self.state.write().await;
                    if *state == CircuitState::Closed {
                        warn!(
                            name = %self.name,
                            failures = failures,
                            "Circuit transitioning to OPEN"
                        );
                        *state = CircuitState::Open;
                        *self.last_state_change.write().await = Instant::now();
                    }
                }
            }
            CircuitState::HalfOpen => {
                // Failure in half-open goes back to open
                let mut state = self.state.write().await;
                if *state == CircuitState::HalfOpen {
                    warn!(
                        name = %self.name,
                        "Circuit returning to OPEN after half-open failure"
                    );
                    *state = CircuitState::Open;
                    *self.last_state_change.write().await = Instant::now();
                    self.consecutive_successes.store(0, Ordering::SeqCst);
                }
                
                // Decrement half-open counter
                self.half_open_requests.fetch_sub(1, Ordering::SeqCst);
            }
            CircuitState::Open => {
                // Already open, just update failure count
                self.failure_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    
    /// Execute a function with circuit breaker protection
    pub async fn call<F, Fut, T>(&self, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
    {
        // Check if allowed
        self.allow_request().await?;
        
        // Execute
        match f().await {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(_e) => {
                self.record_failure().await;
                Err(CircuitBreakerError::CircuitOpen)
            }
        }
    }
    
    /// Force circuit open (for maintenance)
    pub async fn force_open(&self) {
        let mut state = self.state.write().await;
        *state = CircuitState::Open;
        *self.last_state_change.write().await = Instant::now();
        warn!(name = %self.name, "Circuit manually opened");
    }
    
    /// Force circuit closed (after recovery)
    pub async fn force_close(&self) {
        let mut state = self.state.write().await;
        *state = CircuitState::Closed;
        *self.last_state_change.write().await = Instant::now();
        self.failure_count.store(0, Ordering::SeqCst);
        self.consecutive_successes.store(0, Ordering::SeqCst);
        info!(name = %self.name, "Circuit manually closed");
    }
    
    /// Get current metrics
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        CircuitBreakerMetrics {
            failure_count: self.failure_count.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            consecutive_successes: self.consecutive_successes.load(Ordering::Relaxed),
            half_open_requests: self.half_open_requests.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    pub failure_count: u32,
    pub success_count: u32,
    pub consecutive_successes: u32,
    pub half_open_requests: u32,
}

/// Circuit breaker registry for multiple backends
pub struct CircuitBreakerRegistry {
    breakers: RwLock<std::collections::HashMap<String, Arc<CircuitBreaker>>>,
}

impl CircuitBreakerRegistry {
    pub fn new() -> Self {
        Self {
            breakers: RwLock::new(std::collections::HashMap::new()),
        }
    }
    
    /// Get or create circuit breaker
    pub async fn get(&self, name: &str) -> Arc<CircuitBreaker> {
        {
            let breakers = self.breakers.read().await;
            if let Some(cb) = breakers.get(name) {
                return cb.clone();
            }
        }
        
        // Create new
        let mut breakers = self.breakers.write().await;
        let cb = Arc::new(CircuitBreaker::new(name));
        breakers.insert(name.to_string(), cb.clone());
        cb
    }
    
    /// Get metrics for all breakers
    pub async fn all_metrics(&self) -> Vec<(String, CircuitBreakerMetrics)> {
        let breakers = self.breakers.read().await;
        breakers
            .iter()
            .map(|(name, cb)| (name.clone(), cb.metrics()))
            .collect()
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_circuit_opens_after_failures() {
        let cb = CircuitBreaker::with_config(
            "test",
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 2,
                timeout_duration: Duration::from_secs(1),
                half_open_max_requests: 1,
            }
        );
        
        // Initially closed
        assert_eq!(cb.state().await, CircuitState::Closed);
        
        // Record failures
        for _ in 0..3 {
            cb.record_failure().await;
        }
        
        // Should be open now
        assert_eq!(cb.state().await, CircuitState::Open);
    }
    
    #[tokio::test]
    async fn test_circuit_half_open_then_close() {
        let cb = CircuitBreaker::with_config(
            "test",
            CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                timeout_duration: Duration::from_millis(10),
                half_open_max_requests: 10,
            }
        );
        
        // Open the circuit
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
        
        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        // Should be able to request (half-open)
        cb.allow_request().await.unwrap();
        assert_eq!(cb.state().await, CircuitState::HalfOpen);
        
        // Record successes
        cb.record_success().await;
        cb.record_success().await;
        
        // Should be closed
        assert_eq!(cb.state().await, CircuitState::Closed);
    }
}
