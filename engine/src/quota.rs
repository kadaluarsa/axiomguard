//! Quota management for multi-tenant resource control
//!
//! Enforces limits for:
//! - Real-time classifications (rules/cache) - per day
//! - Deep analysis (AI calls) - per month
//! - Content size limits
//! - Rate limiting (requests per second)

use std::sync::Arc;
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc, Datelike};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;

/// Classification type for quota tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationType {
    /// Rules/cache based (fast, cheap)
    Realtime,
    /// AI-based deep analysis (slow, expensive)
    DeepAnalysis { estimated_tokens: usize },
}

/// Quota status returned after check
#[derive(Debug, Clone)]
pub enum QuotaStatus {
    /// Request allowed, with remaining quota info
    Allowed {
        remaining_today: u32,
        remaining_this_month: Option<u32>,
        resets_in: Duration,
    },
    /// Request blocked, with reason
    Blocked {
        reason: String,
        upgrade_url: String,
        current_usage: u32,
        limit: u32,
    },
}

/// Quota error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum QuotaError {
    #[error("Daily realtime limit exceeded: {used}/{limit} (resets in {resets_in:?})")]
    DailyRealtimeLimitExceeded {
        used: u32,
        limit: u32,
        resets_in: Duration,
    },
    
    #[error("Monthly deep analysis limit exceeded: {used}/{limit}")]
    MonthlyDeepAnalysisLimitExceeded {
        used: u32,
        limit: u32,
    },
    
    #[error("Rate limit exceeded: {requests}/{limit} per second")]
    RateLimitExceeded {
        requests: u32,
        limit: u32,
        retry_after: Duration,
    },
    
    #[error("Content too large: {size} bytes (max: {max})")]
    ContentTooLarge {
        size: usize,
        max: usize,
    },
    
    #[error("Rule quota exceeded: {used}/{max} rules")]
    RuleQuotaExceeded {
        used: u32,
        max: u32,
    },
    
    #[error("Tenant not found: {0}")]
    TenantNotFound(String),
}

/// Tenant quota configuration (from database)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuota {
    pub tenant_id: String,
    pub plan_type: PlanType,
    
    // Real-time (rules + cache) limits
    pub quota_realtime_per_day: u32,
    pub quota_realtime_burst: u32,  // per second
    pub max_content_size_realtime: usize,  // bytes
    
    // Deep analysis (AI) limits
    pub quota_deep_analysis_per_month: u32,
    pub max_content_size_deep_analysis: usize,  // bytes
    pub max_tokens_per_analysis: u32,
    
    // Rules limits
    pub quota_rules_max: u32,
    
    // Usage tracking (in-memory, flushed to DB periodically)
    pub used_realtime_today: u32,
    pub used_deep_analysis_this_month: u32,
    pub last_reset_date: DateTime<Utc>,
    
    // Behavior
    pub hard_limit_enabled: bool,
    pub alert_threshold_percent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanType {
    Free,
    Pro,
    Enterprise,
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self::free_tier("default".to_string())
    }
}

impl TenantQuota {
    /// Create free tier quota
    pub fn free_tier(tenant_id: String) -> Self {
        Self {
            tenant_id,
            plan_type: PlanType::Free,
            quota_realtime_per_day: 100,
            quota_realtime_burst: 1,
            max_content_size_realtime: 10 * 1024,  // 10KB
            quota_deep_analysis_per_month: 1,
            max_content_size_deep_analysis: 100 * 1024,  // 100KB
            max_tokens_per_analysis: 10_000,
            quota_rules_max: 5,
            used_realtime_today: 0,
            used_deep_analysis_this_month: 0,
            last_reset_date: Utc::now(),
            hard_limit_enabled: true,
            alert_threshold_percent: 80,
        }
    }
    
    /// Create pro tier quota
    pub fn pro_tier(tenant_id: String) -> Self {
        Self {
            tenant_id: tenant_id.clone(),
            plan_type: PlanType::Pro,
            quota_realtime_per_day: 10_000,
            quota_realtime_burst: 100,  // 100/sec
            max_content_size_realtime: 10 * 1024,  // 10KB
            quota_deep_analysis_per_month: 500,
            max_content_size_deep_analysis: 100 * 1024,  // 100KB
            max_tokens_per_analysis: 100_000,
            quota_rules_max: 50,
            used_realtime_today: 0,
            used_deep_analysis_this_month: 0,
            last_reset_date: Utc::now(),
            hard_limit_enabled: true,
            alert_threshold_percent: 80,
        }
    }
    
    /// Check if we need to reset daily counters
    pub fn maybe_reset_daily(&mut self) -> bool {
        let now = Utc::now();
        if now.date_naive() != self.last_reset_date.date_naive() {
            self.used_realtime_today = 0;
            self.last_reset_date = now;
            true
        } else {
            false
        }
    }
    
    /// Check if we need to reset monthly counters
    pub fn maybe_reset_monthly(&mut self) -> bool {
        let now = Utc::now();
        if now.month() != self.last_reset_date.month() || 
           now.year() != self.last_reset_date.year() {
            self.used_deep_analysis_this_month = 0;
            self.last_reset_date = now;
            true
        } else {
            false
        }
    }
    
    /// Get upgrade URL based on plan
    pub fn upgrade_url(&self) -> String {
        match self.plan_type {
            PlanType::Free => "https://axiomguard.com/upgrade/pro".to_string(),
            PlanType::Pro => "https://axiomguard.com/upgrade/enterprise".to_string(),
            PlanType::Enterprise => "https://axiomguard.com/contact".to_string(),
        }
    }
}

/// In-memory rate limiter per tenant
#[derive(Debug)]
struct RateLimiter {
    windows: DashMap<String, (Instant, u32)>,
    window_size: Duration,
}

impl RateLimiter {
    fn new(window_size: Duration) -> Self {
        Self {
            windows: DashMap::new(),
            window_size,
        }
    }
    
    async fn check_and_increment(&self, tenant_id: &str, limit: u32) -> Result<(), QuotaError> {
        let now = Instant::now();
        
        let mut entry = self.windows.entry(tenant_id.to_string()).or_insert((now, 0));
        
        if now.duration_since(entry.0) > self.window_size {
            *entry = (now, 1);
            return Ok(());
        }
        
        if entry.1 >= limit {
            let retry_after = self.window_size - now.duration_since(entry.0);
            return Err(QuotaError::RateLimitExceeded {
                requests: entry.1,
                limit,
                retry_after,
            });
        }
        
        entry.1 += 1;
        Ok(())
    }
}

/// Quota manager for enforcing tenant limits
#[derive(Debug)]
pub struct QuotaManager {
    quotas: DashMap<String, TenantQuota>,
    rate_limiter: RateLimiter,
}

impl QuotaManager {
    pub fn new() -> Self {
        Self {
            quotas: DashMap::new(),
            rate_limiter: RateLimiter::new(Duration::from_secs(1)),
        }
    }
    
    async fn get_quota(&self, tenant_id: &str) -> Result<TenantQuota, QuotaError> {
        if let Some(entry) = self.quotas.get(tenant_id) {
            return Ok(entry.value().clone());
        }
        
        let quota = TenantQuota::free_tier(tenant_id.to_string());
        self.quotas.insert(tenant_id.to_string(), quota.clone());
        
        Ok(quota)
    }
    
    /// Check content size limits
    fn check_content_size(
        &self,
        content: &str,
        classification_type: ClassificationType,
        quota: &TenantQuota,
    ) -> Result<(), QuotaError> {
        let content_size = content.len();
        
        match classification_type {
            ClassificationType::Realtime => {
                if content_size > quota.max_content_size_realtime {
                    return Err(QuotaError::ContentTooLarge {
                        size: content_size,
                        max: quota.max_content_size_realtime,
                    });
                }
            }
            ClassificationType::DeepAnalysis { .. } => {
                if content_size > quota.max_content_size_deep_analysis {
                    return Err(QuotaError::ContentTooLarge {
                        size: content_size,
                        max: quota.max_content_size_deep_analysis,
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Main quota check - call this before classification
    pub async fn check_classification_quota(
        &self,
        tenant_id: &str,
        classification_type: ClassificationType,
        content: &str,
    ) -> Result<QuotaStatus, QuotaError> {
        // Get quota
        let mut quota = self.get_quota(tenant_id).await?;
        
        // Check content size first (cheapest check)
        self.check_content_size(content, classification_type, &quota)?;
        
        // Reset counters if needed
        quota.maybe_reset_daily();
        quota.maybe_reset_monthly();
        
        match classification_type {
            ClassificationType::Realtime => {
                // Check rate limit
                self.rate_limiter.check_and_increment(
                    tenant_id,
                    quota.quota_realtime_burst
                ).await?;
                
                // Check daily quota
                if quota.used_realtime_today >= quota.quota_realtime_per_day {
                    if quota.hard_limit_enabled {
                        return Err(QuotaError::DailyRealtimeLimitExceeded {
                            used: quota.used_realtime_today,
                            limit: quota.quota_realtime_per_day,
                            resets_in: Self::time_until_midnight(),
                        });
                    }
                }
                
                // Consume quota
                if let Some(mut q) = self.quotas.get_mut(tenant_id) {
                    q.used_realtime_today += 1;
                }
                
                // Check alert threshold
                let usage_percent = (quota.used_realtime_today as f32 / quota.quota_realtime_per_day as f32) * 100.0;
                if usage_percent >= quota.alert_threshold_percent as f32 {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        usage_percent = %usage_percent,
                        "Quota alert: Approaching daily limit"
                    );
                }
                
                Ok(QuotaStatus::Allowed {
                    remaining_today: quota.quota_realtime_per_day - quota.used_realtime_today,
                    remaining_this_month: None,
                    resets_in: Self::time_until_midnight(),
                })
            }
            
            ClassificationType::DeepAnalysis { .. } => {
                // Check monthly quota BEFORE consuming
                if quota.used_deep_analysis_this_month >= quota.quota_deep_analysis_per_month {
                    return Err(QuotaError::MonthlyDeepAnalysisLimitExceeded {
                        used: quota.used_deep_analysis_this_month,
                        limit: quota.quota_deep_analysis_per_month,
                    });
                }
                
                // Consume quota BEFORE calling AI (prevent abuse)
                if let Some(mut q) = self.quotas.get_mut(tenant_id) {
                    q.used_deep_analysis_this_month += 1;
                }
                
                tracing::info!(
                    tenant_id = %tenant_id,
                    used = quota.used_deep_analysis_this_month + 1,
                    limit = quota.quota_deep_analysis_per_month,
                    "Deep analysis quota consumed"
                );
                
                Ok(QuotaStatus::Allowed {
                    remaining_today: quota.quota_realtime_per_day - quota.used_realtime_today,
                    remaining_this_month: Some(quota.quota_deep_analysis_per_month - quota.used_deep_analysis_this_month - 1),
                    resets_in: Self::time_until_end_of_month(),
                })
            }
        }
    }
    
    /// Check if tenant can create more rules
    pub async fn check_rule_quota(
        &self,
        tenant_id: &str,
        current_rule_count: u32,
    ) -> Result<(), QuotaError> {
        let quota = self.get_quota(tenant_id).await?;
        
        if current_rule_count >= quota.quota_rules_max {
            return Err(QuotaError::RuleQuotaExceeded {
                used: current_rule_count,
                max: quota.quota_rules_max,
            });
        }
        
        Ok(())
    }
    
    /// Get current quota status (for dashboard)
    pub async fn get_quota_status(&self, tenant_id: &str) -> Result<TenantQuota, QuotaError> {
        let quota = self.get_quota(tenant_id).await?;
        Ok(quota)
    }
    
    pub async fn set_quota(&self, tenant_id: &str, quota: TenantQuota) {
        self.quotas.insert(tenant_id.to_string(), quota);
    }
    
    fn time_until_midnight() -> Duration {
        let now = Utc::now();
        let tomorrow = now.date_naive().succ_opt().unwrap_or(now.date_naive());
        let midnight = tomorrow.and_hms_opt(0, 0, 0).unwrap();
        let duration = midnight.signed_duration_since(now.naive_local());
        
        Duration::from_secs(duration.num_seconds().max(0) as u64)
    }
    
    fn time_until_end_of_month() -> Duration {
        let now = Utc::now();
        let current_year = now.year();
        let current_month = now.month();
        
        // Calculate first day of next month
        let (next_year, next_month) = if current_month == 12 {
            (current_year + 1, 1)
        } else {
            (current_year, current_month + 1)
        };
        
        let next_month_start = chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        
        let duration = next_month_start.signed_duration_since(now.naive_local());
        Duration::from_secs(duration.num_seconds().max(0) as u64)
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_free_tier_realtime_limit() {
        let manager = QuotaManager::new();
        let tenant_id = "test-free";
        
        // Set free tier quota with high burst for testing daily limit
        let mut quota = TenantQuota::free_tier(tenant_id.to_string());
        quota.quota_realtime_burst = 200; // High burst so rate limiter doesn't interfere
        manager.set_quota(tenant_id, quota).await;
        
        // Should allow first 100 requests
        for i in 0..100 {
            let result = manager.check_classification_quota(
                tenant_id,
                ClassificationType::Realtime,
                "test",
            ).await;
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }
        
        // 101st request should fail
        let result = manager.check_classification_quota(
            tenant_id,
            ClassificationType::Realtime,
            "test",
        ).await;
        assert!(result.is_err(), "Request 101 should be blocked");
    }
    
    #[tokio::test]
    async fn test_content_size_limit() {
        let manager = QuotaManager::new();
        let tenant_id = "test-size";
        
        let quota = TenantQuota::free_tier(tenant_id.to_string());
        manager.set_quota(tenant_id, quota).await;
        
        // Small content should pass
        let result = manager.check_classification_quota(
            tenant_id,
            ClassificationType::Realtime,
            "small",
        ).await;
        assert!(result.is_ok());
        
        // Large content should fail (free tier = 10KB limit)
        let large_content = "x".repeat(20_000);  // 20KB
        let result = manager.check_classification_quota(
            tenant_id,
            ClassificationType::Realtime,
            &large_content,
        ).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_deep_analysis_quota() {
        let manager = QuotaManager::new();
        let tenant_id = "test-deep";
        
        let quota = TenantQuota::free_tier(tenant_id.to_string());
        manager.set_quota(tenant_id, quota).await;
        
        // First deep analysis should succeed
        let result = manager.check_classification_quota(
            tenant_id,
            ClassificationType::DeepAnalysis { estimated_tokens: 100 },
            "test",
        ).await;
        assert!(result.is_ok());
        
        // Second should fail (free tier = 1/month)
        let result = manager.check_classification_quota(
            tenant_id,
            ClassificationType::DeepAnalysis { estimated_tokens: 100 },
            "test",
        ).await;
        assert!(result.is_err());
    }
}
