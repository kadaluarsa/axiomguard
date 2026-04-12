use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPolicy {
    pub agent_id: String,
    pub tenant_id: String,
    pub agent_rules: Vec<serde_json::Value>,
    pub global_rules: Vec<serde_json::Value>,
    pub tool_allowlist: std::collections::HashMap<String, serde_json::Value>,
    pub risk_threshold: f32,
    pub version: u64,
    pub fetched_at: i64,
    pub expires_at: i64,
}

#[derive(Debug)]
pub struct PolicyCache {
    cache: Cache<String, CachedPolicy>,
    encryption_key: [u8; 32],
    ttl: Duration,
}

impl PolicyCache {
    pub fn new(encryption_key: [u8; 32], max_entries: usize, ttl: Duration) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_entries as u64)
                .time_to_live(ttl)
                .build(),
            encryption_key,
            ttl,
        }
    }

    pub fn get(&self, agent_id: &str) -> Option<CachedPolicy> {
        self.cache.get(agent_id)
    }

    pub fn store(&self, policy: CachedPolicy) {
        let agent_id = policy.agent_id.clone();
        self.cache.insert(agent_id, policy);
    }

    pub fn encrypt_to_bytes(&self, policy: &CachedPolicy) -> Result<Vec<u8>, PolicyCacheError> {
        let json = serde_json::to_vec(policy)
            .map_err(|e| PolicyCacheError::Serialization(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| PolicyCacheError::Encryption("key error".into()))?;

        let nonce_bytes = {
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}", policy.agent_id, policy.version).as_bytes());
            let hash = hasher.finalize();
            let mut arr = [0u8; 12];
            arr.copy_from_slice(&hash[..12]);
            arr
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, json.as_ref())
            .map_err(|e| PolicyCacheError::Encryption(e.to_string()))?;

        Ok(encrypted)
    }

    pub fn decrypt_from_bytes(
        &self,
        encrypted: &[u8],
        agent_id: &str,
        version: u64,
    ) -> Result<CachedPolicy, PolicyCacheError> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| PolicyCacheError::Encryption("key error".into()))?;

        let nonce_bytes = {
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}", agent_id, version).as_bytes());
            let hash = hasher.finalize();
            let mut arr = [0u8; 12];
            arr.copy_from_slice(&hash[..12]);
            arr
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| PolicyCacheError::Encryption(e.to_string()))?;

        serde_json::from_slice(&decrypted)
            .map_err(|e| PolicyCacheError::Serialization(e.to_string()))
    }

    pub fn is_fresh(&self, policy: &CachedPolicy) -> bool {
        let now = chrono::Utc::now().timestamp();
        now < policy.expires_at
    }

    pub fn persist_to_disk(
        &self,
        policy: &CachedPolicy,
        path: &std::path::Path,
    ) -> Result<(), PolicyCacheError> {
        let encrypted = self.encrypt_to_bytes(policy)?;
        std::fs::write(path, encrypted).map_err(|e| PolicyCacheError::Io(e.to_string()))
    }

    pub fn load_from_disk(
        &self,
        path: &std::path::Path,
        agent_id: &str,
        version: u64,
    ) -> Result<CachedPolicy, PolicyCacheError> {
        let encrypted = std::fs::read(path).map_err(|e| PolicyCacheError::Io(e.to_string()))?;
        self.decrypt_from_bytes(&encrypted, agent_id, version)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyCacheError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(agent_id: &str, version: u64) -> CachedPolicy {
        CachedPolicy {
            agent_id: agent_id.to_string(),
            tenant_id: "tenant-1".to_string(),
            agent_rules: vec![],
            global_rules: vec![],
            tool_allowlist: std::collections::HashMap::new(),
            risk_threshold: 0.5,
            version,
            fetched_at: chrono::Utc::now().timestamp(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
        }
    }

    #[test]
    fn test_store_and_get() {
        let cache = PolicyCache::new([3u8; 32], 100, Duration::from_secs(300));
        let policy = make_policy("agent-1", 1);
        cache.store(policy);
        let got = cache.get("agent-1").unwrap();
        assert_eq!(got.agent_id, "agent-1");
        assert_eq!(got.version, 1);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cache = PolicyCache::new([3u8; 32], 100, Duration::from_secs(300));
        let policy = make_policy("agent-1", 5);
        let encrypted = cache.encrypt_to_bytes(&policy).unwrap();
        let restored = cache.decrypt_from_bytes(&encrypted, "agent-1", 5).unwrap();
        assert_eq!(restored.agent_id, "agent-1");
        assert_eq!(restored.version, 5);
    }

    #[test]
    fn test_disk_persist_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.enc");
        let cache = PolicyCache::new([3u8; 32], 100, Duration::from_secs(300));
        let policy = make_policy("agent-disk", 3);
        cache.persist_to_disk(&policy, &path).unwrap();
        let restored = cache.load_from_disk(&path, "agent-disk", 3).unwrap();
        assert_eq!(restored.agent_id, "agent-disk");
    }

    #[test]
    fn test_is_fresh() {
        let cache = PolicyCache::new([3u8; 32], 100, Duration::from_secs(300));
        let fresh = make_policy("agent-1", 1);
        assert!(cache.is_fresh(&fresh));

        let mut stale = make_policy("agent-1", 1);
        stale.expires_at = chrono::Utc::now().timestamp() - 10;
        assert!(!cache.is_fresh(&stale));
    }
}
