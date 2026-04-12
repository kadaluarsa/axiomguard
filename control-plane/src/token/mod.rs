pub mod keys;
pub mod revocation;

use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, RwLock};
use uuid::Uuid;

pub const TOKEN_TTL_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub tool: String,
    pub args_hash: String,
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub decision: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub risk_score: f32,
}

#[derive(Debug)]
pub struct TokenEngine {
    signing_key: Mutex<SigningKey>,
    revocation: RwLock<revocation::RevocationList>,
}

impl TokenEngine {
    pub fn new(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            signing_key: Mutex::new(signing_key),
            revocation: RwLock::new(revocation::RevocationList::new()),
        }
    }

    pub fn issue_token(
        &self,
        tool: &str,
        args_hash: &str,
        session_id: &str,
        tenant_id: &str,
        agent_id: &str,
        decision: &str,
        risk_score: f32,
    ) -> Result<String, TokenError> {
        let now = Utc::now();
        let claims = TokenClaims {
            tool: tool.to_string(),
            args_hash: args_hash.to_string(),
            session_id: session_id.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.to_string(),
            decision: decision.to_string(),
            iat: now.timestamp(),
            exp: now.timestamp() + TOKEN_TTL_SECS,
            jti: Uuid::new_v4().to_string(),
            risk_score,
        };

        let payload =
            serde_json::to_vec(&claims).map_err(|e| TokenError::Serialization(e.to_string()))?;

        let signature = self
            .signing_key
            .lock()
            .map_err(|_| TokenError::Internal)?
            .sign(&payload);

        let token = SignedToken {
            header: "ag-exec-v1".to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(&payload),
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        crate::metrics::TOKEN_ISSUANCES.inc();

        let encoded =
            serde_json::to_string(&token).map_err(|e| TokenError::Serialization(e.to_string()))?;
        Ok(encoded)
    }

    pub fn verify_token(&self, token_str: &str) -> Result<TokenClaims, TokenError> {
        let token: SignedToken = serde_json::from_str(token_str)
            .map_err(|e| TokenError::InvalidFormat(e.to_string()))?;

        if token.header != "ag-exec-v1" {
            return Err(TokenError::InvalidFormat("unsupported token type".into()));
        }

        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(&token.payload)
            .map_err(|e: base64::DecodeError| TokenError::InvalidFormat(e.to_string()))?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&token.signature)
            .map_err(|e: base64::DecodeError| TokenError::InvalidFormat(e.to_string()))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| TokenError::InvalidFormat("bad signature length".into()))?;
        let signature = Signature::from_bytes(&sig_array);
        let verifying_key = self
            .signing_key
            .lock()
            .map_err(|_| TokenError::Internal)?
            .verifying_key();

        verifying_key
            .verify(&payload_bytes, &signature)
            .map_err(|_| TokenError::InvalidSignature)?;

        let claims: TokenClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        let now = Utc::now().timestamp();
        if now > claims.exp {
            return Err(TokenError::Expired);
        }

        {
            let rev = self.revocation.read().map_err(|_| TokenError::Internal)?;
            if rev.is_revoked(&claims.jti) {
                return Err(TokenError::Revoked);
            }
        }

        Ok(claims)
    }

    pub fn revoke_token(&self, jti: &str) {
        if let Ok(mut rev) = self.revocation.write() {
            rev.revoke(jti.to_string());
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key
            .lock()
            .expect("signing key lock")
            .verifying_key()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedToken {
    header: String,
    payload: String,
    signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid token format: {0}")]
    InvalidFormat(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("token expired")]
    Expired,
    #[error("token revoked")]
    Revoked,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("internal error")]
    Internal,
}
