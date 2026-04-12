//! Graceful shutdown handling for AxiomGuard
//!
//! Ensures zero-downtime deployments by:
//! - Stopping new connections
//! - Completing in-flight requests
//! - Flushing buffers and caches
//! - Closing resources cleanly

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock, Notify};
use tokio::time::{timeout, Instant};
use tracing::{info, warn, error, instrument};

/// Shutdown signal sent to components
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// Start graceful shutdown
    Shutdown,
    /// Force immediate shutdown (timeout exceeded)
    Force,
}

/// Component that can be gracefully shut down
#[async_trait::async_trait]
pub trait Shutdownable: Send + Sync {
    /// Component name for logging
    fn name(&self) -> &str;
    
    /// Perform graceful shutdown
    async fn shutdown(&self) -> Result<(), ShutdownError>;
    
    /// Optional: Time to wait for shutdown before forcing
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// Error during shutdown
#[derive(Debug, Clone)]
pub enum ShutdownError {
    Timeout { component: String },
    Failed { component: String, reason: String },
    AlreadyShuttingDown,
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownError::Timeout { component } => {
                write!(f, "Shutdown timeout for component: {}", component)
            }
            ShutdownError::Failed { component, reason } => {
                write!(f, "Shutdown failed for component {}: {}", component, reason)
            }
            ShutdownError::AlreadyShuttingDown => {
                write!(f, "System already shutting down")
            }
        }
    }
}

impl std::error::Error for ShutdownError {}

/// Graceful shutdown coordinator
pub struct ShutdownManager {
    /// Broadcast channel for shutdown signals
    shutdown_tx: broadcast::Sender<ShutdownSignal>,
    /// List of registered components
    components: RwLock<Vec<Arc<dyn Shutdownable>>>,
    /// Shutdown state
    state: RwLock<ShutdownState>,
    /// Notify when shutdown complete
    complete: Notify,
    /// Global timeout for entire shutdown
    global_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownState {
    Running,
    ShuttingDown,
    ShutDown,
}

impl ShutdownManager {
    pub fn new() -> Arc<Self> {
        let (shutdown_tx, _) = broadcast::channel(100);
        
        Arc::new(Self {
            shutdown_tx,
            components: RwLock::new(vec![]),
            state: RwLock::new(ShutdownState::Running),
            complete: Notify::new(),
            global_timeout: Duration::from_secs(60),
        })
    }
    
    /// Register a component for graceful shutdown
    /// Returns error if shutdown has already started
    pub async fn register(&self, component: Arc<dyn Shutdownable>) -> Result<(), ShutdownError> {
        // Check state first to prevent registration during shutdown
        let state = self.state.read().await;
        if *state != ShutdownState::Running {
            return Err(ShutdownError::AlreadyShuttingDown);
        }
        drop(state);
        
        let mut components = self.components.write().await;
        
        // Double-check after acquiring write lock
        let state = self.state.read().await;
        if *state != ShutdownState::Running {
            return Err(ShutdownError::AlreadyShuttingDown);
        }
        drop(state);
        
        info!("Registering shutdown handler for {}", component.name());
        components.push(component);
        Ok(())
    }
    
    /// Subscribe to shutdown signals
    pub fn subscribe(&self) -> broadcast::Receiver<ShutdownSignal> {
        self.shutdown_tx.subscribe()
    }
    
    /// Check if shutdown has been initiated
    pub async fn is_shutting_down(&self) -> bool {
        let state = self.state.read().await;
        *state != ShutdownState::Running
    }
    
    /// Initiate graceful shutdown
    pub async fn shutdown(self: Arc<Self>) -> Result<(), ShutdownError> {
        let mut state = self.state.write().await;
        
        if *state != ShutdownState::Running {
            return Err(ShutdownError::AlreadyShuttingDown);
        }
        
        *state = ShutdownState::ShuttingDown;
        drop(state);
        
        info!("Initiating graceful shutdown...");
        
        // Send shutdown signal to all subscribers
        let _ = self.shutdown_tx.send(ShutdownSignal::Shutdown);
        
        // Wait a moment for components to receive signal
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Shutdown all registered components
        let start = Instant::now();
        let components = self.components.read().await.clone();
        
        for component in components {
            let remaining = self.global_timeout.saturating_sub(start.elapsed());
            
            if remaining.is_zero() {
                warn!("Global shutdown timeout exceeded, forcing remaining components");
                let _ = self.shutdown_tx.send(ShutdownSignal::Force);
                break;
            }
            
            let component_timeout = component.shutdown_timeout().min(remaining);
            
            info!("Shutting down {} (timeout: {:?})", component.name(), component_timeout);
            
            match timeout(component_timeout, component.shutdown()).await {
                Ok(Ok(())) => {
                    info!("Successfully shut down {}", component.name());
                }
                Ok(Err(e)) => {
                    error!("Shutdown error for {}: {}", component.name(), e);
                }
                Err(_) => {
                    error!("Shutdown timeout for {}", component.name());
                }
            }
        }
        
        let mut state = self.state.write().await;
        *state = ShutdownState::ShutDown;
        
        info!("Graceful shutdown complete (took {:?})", start.elapsed());
        self.complete.notify_waiters();
        
        Ok(())
    }
    
    /// Wait for shutdown to complete
    pub async fn wait_for_shutdown(&self) {
        let state = self.state.read().await;
        if *state == ShutdownState::ShutDown {
            return;
        }
        drop(state);
        
        self.complete.notified().await;
    }
}

impl Default for ShutdownManager {
    fn default() -> Self {
        let (shutdown_tx, _) = broadcast::channel(100);
        Self {
            shutdown_tx,
            components: RwLock::new(vec![]),
            state: RwLock::new(ShutdownState::Running),
            complete: Notify::new(),
            global_timeout: Duration::from_secs(60),
        }
    }
}

/// HTTP server shutdown handler
pub struct HttpServerShutdown {
    name: String,
    connection_count: Arc<RwLock<usize>>,
    shutdown_complete: Notify,
}

impl HttpServerShutdown {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            connection_count: Arc::new(RwLock::new(0)),
            shutdown_complete: Notify::new(),
        }
    }
    
    /// Track a new connection
    pub async fn connection_started(&self) {
        let mut count = self.connection_count.write().await;
        *count += 1;
    }
    
    /// Mark connection as complete
    pub async fn connection_ended(&self) {
        let mut count = self.connection_count.write().await;
        *count -= 1;
        if *count == 0 {
            self.shutdown_complete.notify_waiters();
        }
    }
    
    /// Get current connection count
    pub async fn connection_count(&self) -> usize {
        *self.connection_count.read().await
    }
}

#[async_trait::async_trait]
impl Shutdownable for HttpServerShutdown {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
    
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        info!("HTTP server stopping new connections...");
        
        // Wait for existing connections to complete
        let timeout = Instant::now() + self.shutdown_timeout();
        
        loop {
            let count = self.connection_count().await;
            if count == 0 {
                info!("All HTTP connections completed");
                return Ok(());
            }
            
            if Instant::now() > timeout {
                return Err(ShutdownError::Timeout {
                    component: self.name.clone(),
                });
            }
            
            info!("Waiting for {} HTTP connections to complete...", count);
            
            // Wait with timeout
            tokio::select! {
                _ = self.shutdown_complete.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }
}

/// Cache flush shutdown handler
pub struct CacheShutdown {
    name: String,
    flush_fn: Box<dyn Fn() -> tokio::task::JoinHandle<Result<(), String>> + Send + Sync>,
}

impl CacheShutdown {
    pub fn new<F, Fut>(name: impl Into<String>, flush_fn: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            name: name.into(),
            flush_fn: Box::new(move || tokio::spawn(flush_fn())),
        }
    }
}

#[async_trait::async_trait]
impl Shutdownable for CacheShutdown {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        info!("Flushing cache {}...", self.name);
        
        let handle = (self.flush_fn)();
        
        match timeout(Duration::from_secs(10), handle).await {
            Ok(Ok(Ok(()))) => {
                info!("Cache {} flushed successfully", self.name);
                Ok(())
            }
            Ok(Ok(Err(e))) => Err(ShutdownError::Failed {
                component: self.name.clone(),
                reason: e,
            }),
            Ok(Err(_)) => Err(ShutdownError::Failed {
                component: self.name.clone(),
                reason: "Task panicked".to_string(),
            }),
            Err(_) => Err(ShutdownError::Timeout {
                component: self.name.clone(),
            }),
        }
    }
}

/// Background task shutdown handler
pub struct TaskShutdown {
    name: String,
    abort_handle: tokio::task::AbortHandle,
}

impl TaskShutdown {
    pub fn new(name: impl Into<String>, abort_handle: tokio::task::AbortHandle) -> Self {
        Self {
            name: name.into(),
            abort_handle,
        }
    }
}

#[async_trait::async_trait]
impl Shutdownable for TaskShutdown {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        info!("Aborting background task {}...", self.name);
        self.abort_handle.abort();
        
        // Give it a moment to clean up
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        info!("Background task {} aborted", self.name);
        Ok(())
    }
}

/// Signal handler for OS signals (SIGTERM, SIGINT)
pub struct SignalHandler;

impl SignalHandler {
    /// Wait for shutdown signal
    pub async fn wait_for_shutdown() {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate()
        ).expect("Failed to create SIGTERM handler");
        
        let mut sigint = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt()
        ).expect("Failed to create SIGINT handler");
        
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, starting graceful shutdown...");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, starting graceful shutdown...");
            }
        }
    }
}

/// Helper for connection tracking in Axum/tower
#[derive(Clone)]
pub struct ConnectionTracker {
    inner: Arc<HttpServerShutdown>,
}

impl ConnectionTracker {
    pub fn new(shutdown: Arc<HttpServerShutdown>) -> Self {
        Self { inner: shutdown }
    }
    
    pub async fn track<F, Fut, R>(&self, f: F) -> R
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        self.inner.connection_started().await;
        let result = f().await;
        self.inner.connection_ended().await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct TestComponent {
        name: String,
        delay_ms: u64,
    }
    
    #[async_trait::async_trait]
    impl Shutdownable for TestComponent {
        fn name(&self) -> &str {
            &self.name
        }
        
        async fn shutdown(&self) -> Result<(), ShutdownError> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            Ok(())
        }
    }
    
    #[tokio::test]
    async fn test_shutdown_manager() {
        let manager = ShutdownManager::new();
        
        let component = Arc::new(TestComponent {
            name: "test".to_string(),
            delay_ms: 10,
        });
        
        let _ = manager.register(component).await;
        
        assert!(!manager.is_shutting_down().await);
        
        let result = Arc::clone(&manager).shutdown().await;
        assert!(result.is_ok());
        
        assert!(manager.is_shutting_down().await);
    }
    
    #[tokio::test]
    async fn test_shutdown_broadcast() {
        let manager = ShutdownManager::new();
        let mut rx1 = manager.subscribe();
        let mut rx2 = manager.subscribe();
        
        tokio::spawn(async move {
            Arc::clone(&manager).shutdown().await.unwrap();
        });
        
        let sig1 = rx1.recv().await.unwrap();
        let sig2 = rx2.recv().await.unwrap();
        
        assert_eq!(sig1, ShutdownSignal::Shutdown);
        assert_eq!(sig2, ShutdownSignal::Shutdown);
    }
    
    #[tokio::test]
    async fn test_http_server_shutdown() {
        let shutdown = Arc::new(HttpServerShutdown::new("test-server"));
        
        // Simulate connections
        shutdown.connection_started().await;
        shutdown.connection_started().await;
        assert_eq!(shutdown.connection_count().await, 2);
        
        // End one connection
        shutdown.connection_ended().await;
        assert_eq!(shutdown.connection_count().await, 1);
        
        // End second connection
        shutdown.connection_ended().await;
        assert_eq!(shutdown.connection_count().await, 0);
        
        // Shutdown should complete immediately
        let result = shutdown.shutdown().await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_cache_shutdown() {
        let flushed = Arc::new(RwLock::new(false));
        let flushed_clone = Arc::clone(&flushed);
        
        let cache = CacheShutdown::new("test-cache", move || {
            let f = Arc::clone(&flushed_clone);
            async move {
                *f.write().await = true;
                Ok(())
            }
        });
        
        cache.shutdown().await.unwrap();
        
        assert!(*flushed.read().await);
    }
    
    #[tokio::test]
    async fn test_double_shutdown_error() {
        let manager = ShutdownManager::new();
        
        // First shutdown
        let result = Arc::clone(&manager).shutdown().await;
        assert!(result.is_ok());
        
        // Second shutdown should fail
        let result = Arc::clone(&manager).shutdown().await;
        assert!(matches!(result, Err(ShutdownError::AlreadyShuttingDown)));
    }
}
