//! Data retention management for automatic cleanup
//!
//! Enforces tenant-specific data retention policies to control storage costs
//!
//! NOTE: This is a stub implementation. The full implementation should be
//! in the service layer where database access is available, or run via
//! the Kubernetes CronJob which executes SQL directly.

use chrono::{DateTime, Utc, Duration as ChronoDuration};

/// Retention configuration for a tenant
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    pub retention_events_days: i32,
    pub retention_audit_days: i32,
    pub retention_sessions_days: i32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_events_days: 90,
            retention_audit_days: 365,
            retention_sessions_days: 30,
        }
    }
}

/// Stub retention manager
/// 
/// Full implementation requires database access (sqlx) which is in the common crate.
/// The actual cleanup should be run via the Kubernetes CronJob or service layer.
pub struct RetentionManager;

impl RetentionManager {
    pub fn new() -> Self {
        Self
    }
    
    /// Validate retention configuration
    pub fn validate_config(&self, config: &RetentionConfig) -> Result<(), String> {
        if config.retention_events_days < 1 {
            return Err("retention_events_days must be at least 1".to_string());
        }
        if config.retention_audit_days < 1 {
            return Err("retention_audit_days must be at least 1".to_string());
        }
        if config.retention_sessions_days < 1 {
            return Err("retention_sessions_days must be at least 1".to_string());
        }
        Ok(())
    }
    
    /// Calculate cutoff date for given retention period
    pub fn calculate_cutoff(&self, retention_days: i32) -> DateTime<Utc> {
        Utc::now() - ChronoDuration::days(retention_days as i64)
    }
}

impl Default for RetentionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_bytes: i64,
    pub events_bytes: i64,
    pub decisions_bytes: i64,
}

impl StorageStats {
    /// Format bytes to human-readable string
    pub fn format_bytes(bytes: i64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;
        
        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(StorageStats::format_bytes(512), "512.00 B");
        assert_eq!(StorageStats::format_bytes(1024), "1.00 KB");
        assert_eq!(StorageStats::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(StorageStats::format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }
    
    #[test]
    fn test_validate_config() {
        let manager = RetentionManager::new();
        
        // Valid config
        let valid = RetentionConfig::default();
        assert!(manager.validate_config(&valid).is_ok());
        
        // Invalid - zero days
        let invalid = RetentionConfig {
            retention_events_days: 0,
            ..Default::default()
        };
        assert!(manager.validate_config(&invalid).is_err());
    }
}
