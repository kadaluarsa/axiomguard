use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBlob {
    pub agent_id: String,
    pub tenant_id: String,
    pub agent_rules: Vec<serde_json::Value>,
    pub global_rules: Vec<serde_json::Value>,
    pub tool_allowlist: std::collections::HashMap<String, serde_json::Value>,
    pub risk_threshold: f32,
    pub version: u64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicy {
    pub policy_base64: String,
    pub nonce_base64: String,
    pub signature: String,
    pub version: u64,
}

#[derive(Debug)]
pub struct PolicyEngine {
    signing_key: Mutex<SigningKey>,
    encryption_key: [u8; 32],
    version_counter: std::sync::atomic::AtomicU64,
}

impl PolicyEngine {
    pub fn new(signing_seed: [u8; 32], encryption_key: [u8; 32]) -> Self {
        Self {
            signing_key: Mutex::new(SigningKey::from_bytes(&signing_seed)),
            encryption_key,
            version_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn compile_and_sign(&self, blob: PolicyBlob) -> Result<SignedPolicy, PolicyError> {
        let json =
            serde_json::to_vec(&blob).map_err(|e| PolicyError::Serialization(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| PolicyError::Encryption("key error".into()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, json.as_ref())
            .map_err(|e| PolicyError::Encryption(e.to_string()))?;

        let policy_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        let nonce_base64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);

        let signature = self
            .signing_key
            .lock()
            .map_err(|_| PolicyError::Encryption("lock poisoned".into()))?
            .sign(encrypted.as_slice());
        let sig_hex = hex_encode(&signature.to_bytes());

        let version = self
            .version_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(SignedPolicy {
            policy_base64,
            nonce_base64,
            signature: sig_hex,
            version,
        })
    }

    pub fn verify_and_decrypt(&self, signed: &SignedPolicy) -> Result<PolicyBlob, PolicyError> {
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(&signed.policy_base64)
            .map_err(|e: base64::DecodeError| PolicyError::InvalidFormat(e.to_string()))?;

        let sig_bytes = hex_decode(&signed.signature)
            .ok_or_else(|| PolicyError::InvalidFormat("bad signature hex".into()))?;
        let signature = ed25519_dalek::Signature::try_from(sig_bytes.as_slice()).map_err(
            |e: ed25519_dalek::SignatureError| PolicyError::InvalidSignature(e.to_string()),
        )?;

        let verifying_key = self
            .signing_key
            .lock()
            .map_err(|_| PolicyError::Encryption("lock poisoned".into()))?
            .verifying_key();
        verifying_key.verify(&encrypted, &signature).map_err(
            |e: ed25519_dalek::SignatureError| PolicyError::InvalidSignature(e.to_string()),
        )?;

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| PolicyError::Encryption("key error".into()))?;

        let nonce_bytes: [u8; 12] = base64::engine::general_purpose::STANDARD
            .decode(&signed.nonce_base64)
            .map_err(|e: base64::DecodeError| {
                PolicyError::InvalidFormat(format!("bad nonce: {}", e))
            })?
            .try_into()
            .map_err(|_| PolicyError::InvalidFormat("nonce must be 12 bytes".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|e| PolicyError::Encryption(e.to_string()))?;

        serde_json::from_slice(&decrypted).map_err(|e| PolicyError::Serialization(e.to_string()))
    }

    pub fn next_version(&self) -> u64 {
        self.version_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [1u8; 32];
        let enc = [2u8; 32];
        let engine = PolicyEngine::new(seed, enc);

        let blob = PolicyBlob {
            agent_id: "test-agent".into(),
            tenant_id: "test-tenant".into(),
            agent_rules: vec![],
            global_rules: vec![],
            tool_allowlist: std::collections::HashMap::new(),
            risk_threshold: 0.7,
            version: 1,
            timestamp: chrono::Utc::now().timestamp(),
        };

        let signed = engine.compile_and_sign(blob.clone()).unwrap();
        let restored = engine.verify_and_decrypt(&signed).unwrap();
        assert_eq!(restored.agent_id, "test-agent");
    }
}
