use chrono::{DateTime, Utc};
use std::collections::HashMap;

const REVOCATION_TTL_SECS: i64 = 86400;

#[derive(Debug)]
pub struct RevocationList {
    revoked: HashMap<String, DateTime<Utc>>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self {
            revoked: HashMap::new(),
        }
    }

    pub fn revoke(&mut self, jti: String) {
        self.revoked.insert(jti, Utc::now());
        if self.revoked.len() % 100 == 0 {
            self.cleanup();
        }
    }

    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains_key(jti)
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    fn cleanup(&mut self) {
        let now = Utc::now();
        self.revoked.retain(|_, revoked_at| {
            now.signed_duration_since(*revoked_at).num_seconds() < REVOCATION_TTL_SECS
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation() {
        let mut list = RevocationList::new();
        assert!(!list.is_revoked("token-1"));
        list.revoke("token-1".into());
        assert!(list.is_revoked("token-1"));
        assert!(!list.is_revoked("token-2"));
    }

    #[test]
    fn test_len() {
        let mut list = RevocationList::new();
        assert_eq!(list.len(), 0);
        list.revoke("t1".into());
        list.revoke("t2".into());
        assert_eq!(list.len(), 2);
    }
}
