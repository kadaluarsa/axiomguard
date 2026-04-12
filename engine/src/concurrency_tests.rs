//! Concurrency stress tests for race condition verification
//! Run with: cargo test --package engine --lib concurrency_tests -- --nocapture

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::task::JoinSet;
    use std::time::Duration;

    // Test telemetry global tracer is thread-safe
    #[tokio::test]
    async fn test_telemetry_thread_safety() {
        use crate::telemetry::{init_tracer, tracer, TraceContext};
        
        // Initialize once
        init_tracer("test-service");
        
        // Spawn many tasks that access the tracer concurrently
        let mut join_set = JoinSet::new();
        
        for i in 0..100 {
            join_set.spawn(async move {
                // All tasks should be able to access tracer safely
                let _tracer = tracer();
                
                // Create trace contexts concurrently
                let ctx = TraceContext::new()
                    .with_baggage("task_id", i.to_string());
                
                // Create spans concurrently
                let span = tracer().start_trace(format!("operation-{}", i));
                tokio::time::sleep(Duration::from_micros(10)).await;
                let _finished = span.finish();
                
                ctx
            });
        }
        
        let results: Vec<_> = join_set.join_all().await;
        assert_eq!(results.len(), 100);
        
        // Verify all trace IDs are unique
        let unique_ids: std::collections::HashSet<_> = results
            .iter()
            .map(|ctx| ctx.trace_id.0.clone())
            .collect();
        assert_eq!(unique_ids.len(), 100, "All trace IDs should be unique");
    }

    // Test shutdown manager handles concurrent registrations
    #[tokio::test]
    async fn test_shutdown_concurrent_registration() {
        use crate::shutdown::{ShutdownManager, Shutdownable, ShutdownError};
        use async_trait::async_trait;
        
        struct TestComponent {
            id: String,
        }
        
        #[async_trait]
        impl Shutdownable for TestComponent {
            fn name(&self) -> &str {
                &self.id
            }
            
            async fn shutdown(&self) -> Result<(), ShutdownError> {
                Ok(())
            }
        }
        
        let shutdown = ShutdownManager::new();
        let mut join_set = JoinSet::new();
        
        // Register 50 components concurrently
        for i in 0..50 {
            let s = Arc::clone(&shutdown);
            join_set.spawn(async move {
                let component = Arc::new(TestComponent {
                    id: format!("component-{}", i),
                });
                s.register(component).await
            });
        }
        
        let results: Vec<_> = join_set.join_all().await;
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 50, "All registrations should succeed");
    }

    // Test shutdown prevents registration after shutdown starts
    #[tokio::test]
    async fn test_shutdown_prevents_late_registration() {
        use crate::shutdown::{ShutdownManager, Shutdownable, ShutdownError};
        use async_trait::async_trait;
        
        struct TestComponent {
            id: String,
        }
        
        #[async_trait]
        impl Shutdownable for TestComponent {
            fn name(&self) -> &str {
                &self.id
            }
            
            async fn shutdown(&self) -> Result<(), ShutdownError> {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(())
            }
        }
        
        let shutdown = ShutdownManager::new();
        
        // Register a component
        let component = Arc::new(TestComponent {
            id: "early".to_string(),
        });
        assert!(shutdown.register(component).await.is_ok());
        
        // Start shutdown in background
        let s = Arc::clone(&shutdown);
        let shutdown_handle = tokio::spawn(async move {
            Arc::clone(&s).shutdown().await
        });
        
        // Give shutdown time to start
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Try to register during shutdown - should fail
        let late_component = Arc::new(TestComponent {
            id: "late".to_string(),
        });
        let result = shutdown.register(late_component).await;
        assert!(matches!(result, Err(ShutdownError::AlreadyShuttingDown)));
        
        // Wait for shutdown to complete
        shutdown_handle.await.unwrap().unwrap();
    }

    // Test PII sanitizer is Send + Sync for concurrent use
    #[tokio::test]
    async fn test_pii_concurrent_sanitization() {
        use crate::pii::PiiSanitizer;
        
        let sanitizer = Arc::new(PiiSanitizer::default());
        let mut join_set = JoinSet::new();
        
        let test_inputs = vec![
            "Contact me at john@example.com",
            "My SSN is 123-45-6789",
            "Card: 4532015112830366",
            "Password: secret12345",
            "No PII here",
        ];
        
        // Spawn many concurrent sanitization tasks
        for _ in 0..100 {
            let s = Arc::clone(&sanitizer);
            let inputs = test_inputs.clone();
            join_set.spawn(async move {
                let mut results = Vec::new();
                for input in inputs {
                    let redacted = s.redact(input);
                    results.push(redacted);
                }
                results
            });
        }
        
        let all_results: Vec<_> = join_set.join_all().await;
        assert_eq!(all_results.len(), 100);
        
        // Verify all results are consistent
        for results in &all_results {
            assert!(results[0].contains("[REDACTED-EMAIL]"));
            assert!(results[1].contains("[REDACTED-SSN]"));
            assert!(results[2].contains("[REDACTED-CREDIT_CARD]"));
            assert!(results[3].contains("[REDACTED-PASSWORD]"));
            assert_eq!(results[4], "No PII here");
        }
    }

    // Test quota manager concurrent access
    #[tokio::test]
    async fn test_quota_concurrent_access() {
        use crate::quota::{QuotaManager, ClassificationType, TenantQuota, PlanType};
        
        let manager = Arc::new(QuotaManager::new());
        let tenant_id = "concurrent-test";
        
        // Set up Pro tier quota (higher burst limit for testing)
        let mut quota = TenantQuota::pro_tier(tenant_id.to_string());
        quota.quota_realtime_burst = 200; // Allow burst for test
        manager.set_quota(tenant_id, quota).await;
        
        let mut join_set = JoinSet::new();
        
        // Spawn 150 concurrent requests (pro tier allows 10,000/day with burst of 200)
        for i in 0..150 {
            let m = Arc::clone(&manager);
            join_set.spawn(async move {
                let result = m.check_classification_quota(
                    tenant_id,
                    ClassificationType::Realtime,
                    "test",
                ).await;
                (i, result.is_ok())
            });
        }
        
        let results: Vec<_> = join_set.join_all().await;
        let allowed_count = results.iter().filter(|(_, ok)| *ok).count();
        let rejected_count = results.iter().filter(|(_, ok)| !*ok).count();
        
        println!("Allowed: {}, Rejected: {}", allowed_count, rejected_count);
        
        // All 150 should be allowed (under burst limit of 200)
        assert_eq!(allowed_count, 150, "All requests should be allowed under burst limit");
        assert_eq!(rejected_count, 0);
    }
    
    // Test quota enforces daily limit under concurrent load
    #[tokio::test]
    async fn test_quota_daily_limit_concurrent() {
        use crate::quota::{QuotaManager, ClassificationType, TenantQuota};
        
        let manager = Arc::new(QuotaManager::new());
        let tenant_id = "daily-limit-test";
        
        // Set up quota with burst high enough to test daily limit
        let mut quota = TenantQuota::free_tier(tenant_id.to_string());
        quota.quota_realtime_burst = 200; // High burst so rate limiter doesn't interfere
        quota.quota_realtime_per_day = 50; // Set daily limit to 50
        manager.set_quota(tenant_id, quota).await;
        
        // Process requests sequentially first to consume quota
        for _ in 0..50 {
            let _ = manager.check_classification_quota(
                tenant_id,
                ClassificationType::Realtime,
                "test",
            ).await;
        }
        
        // Now spawn concurrent requests - all should be rejected
        let mut join_set = JoinSet::new();
        for i in 0..50 {
            let m = Arc::clone(&manager);
            join_set.spawn(async move {
                let result = m.check_classification_quota(
                    tenant_id,
                    ClassificationType::Realtime,
                    "test",
                ).await;
                (i, result.is_ok())
            });
        }
        
        let results: Vec<_> = join_set.join_all().await;
        let allowed_count = results.iter().filter(|(_, ok)| *ok).count();
        
        // All should be rejected (daily limit already consumed)
        assert_eq!(allowed_count, 0, "All requests should be rejected after daily limit reached");
    }

    // Test cache concurrent access pattern
    #[tokio::test]
    async fn test_cache_concurrent_reads() {
        use crate::ShieldEngine;
        use common::DecisionType;
        
        let engine = Arc::new(ShieldEngine::new());
        let mut join_set = JoinSet::new();
        
        // Pre-populate cache
        let _ = engine.classify("test-tenant", "session-1", "safe content", &serde_json::json!({})).await;
        
        // Spawn 100 concurrent cache reads
        for i in 0..100 {
            let e = Arc::clone(&engine);
            join_set.spawn(async move {
                let result = e.classify(
                    "test-tenant",
                    &format!("session-{}", i % 2), // Half will be cache hits
                    "safe content",
                    &serde_json::json!({}),
                ).await;
                (i, result.cached)
            });
        }
        
        let results: Vec<_> = join_set.join_all().await;
        let cache_hits = results.iter().filter(|(_, cached)| *cached).count();
        
        println!("Cache hits: {}/100", cache_hits);
        // At least some should be cached (session-0 and session-1 patterns)
        assert!(cache_hits > 0, "Should have some cache hits");
    }
}
