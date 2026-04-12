use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const TOKEN_HEADER: &str = "ag-exec-v1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignedToken {
    header: String,
    payload: String,
    signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid token format: {0}")]
    InvalidFormat(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("token expired")]
    Expired,
    #[error("tool mismatch: expected {expected}, got {actual}")]
    ToolMismatch { expected: String, actual: String },
    #[error("args hash mismatch — token was issued for different arguments")]
    ArgsHashMismatch,
    #[error("agent id mismatch: expected {expected}, got {actual}")]
    AgentIdMismatch { expected: String, actual: String },
    #[error("decision was not Allow (got {decision}), refusing execution")]
    DecisionNotAllow { decision: String },
    #[error("risk score too high: {score} > {threshold}")]
    RiskTooHigh { score: f32, threshold: f32 },
}

pub fn verify_token(
    token_str: &str,
    verifying_key: &VerifyingKey,
) -> Result<TokenClaims, VerifyError> {
    let token: SignedToken =
        serde_json::from_str(token_str).map_err(|e| VerifyError::InvalidFormat(e.to_string()))?;

    if token.header != TOKEN_HEADER {
        return Err(VerifyError::InvalidFormat(format!(
            "unsupported token header: {}",
            token.header
        )));
    }

    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.payload)
        .map_err(|e: base64::DecodeError| VerifyError::InvalidFormat(e.to_string()))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.signature)
        .map_err(|e: base64::DecodeError| VerifyError::InvalidFormat(e.to_string()))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidFormat("bad signature length".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    let claims: TokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VerifyError::InvalidFormat(e.to_string()))?;

    let now = chrono::Utc::now().timestamp();
    if now > claims.exp {
        return Err(VerifyError::Expired);
    }

    Ok(claims)
}

pub fn compute_args_hash(args: &serde_json::Value) -> String {
    let canonical = canonicalize_json(args);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    hex_encode(&hash)
}

pub fn compute_string_hash(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash = hasher.finalize();
    hex_encode(&hash)
}

pub fn verify_args_hash(claims: &TokenClaims, args: &serde_json::Value) -> Result<(), VerifyError> {
    let actual = compute_args_hash(args);
    if !constant_time_eq(&claims.args_hash, &actual) {
        return Err(VerifyError::ArgsHashMismatch);
    }
    Ok(())
}

pub fn verify_tool(claims: &TokenClaims, expected_tool: &str) -> Result<(), VerifyError> {
    if claims.tool != expected_tool {
        return Err(VerifyError::ToolMismatch {
            expected: expected_tool.to_string(),
            actual: claims.tool.clone(),
        });
    }
    Ok(())
}

pub fn verify_agent_id(claims: &TokenClaims, expected_agent_id: &str) -> Result<(), VerifyError> {
    if claims.agent_id != expected_agent_id {
        return Err(VerifyError::AgentIdMismatch {
            expected: expected_agent_id.to_string(),
            actual: claims.agent_id.clone(),
        });
    }
    Ok(())
}

pub fn verify_decision_allow(claims: &TokenClaims) -> Result<(), VerifyError> {
    if claims.decision != "Allow" {
        return Err(VerifyError::DecisionNotAllow {
            decision: claims.decision.clone(),
        });
    }
    Ok(())
}

pub fn verify_risk_below(claims: &TokenClaims, threshold: f32) -> Result<(), VerifyError> {
    if claims.risk_score > threshold {
        return Err(VerifyError::RiskTooHigh {
            score: claims.risk_score,
            threshold,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BypassReport {
    pub tool: String,
    pub reason: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub timestamp: i64,
    pub details: serde_json::Value,
}

impl BypassReport {
    pub fn new(
        tool: &str,
        reason: &str,
        tenant_id: &str,
        agent_id: &str,
        session_id: &str,
        details: serde_json::Value,
    ) -> Self {
        Self {
            tool: tool.to_string(),
            reason: reason.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            details,
        }
    }

    pub fn for_verification_failure(claims: &TokenClaims, error: &VerifyError) -> Option<Self> {
        match error {
            VerifyError::ArgsHashMismatch => Some(Self::new(
                &claims.tool,
                "args_hash_mismatch",
                &claims.tenant_id,
                &claims.agent_id,
                &claims.session_id,
                serde_json::json!({
                    "expected_hash": claims.args_hash,
                }),
            )),
            VerifyError::AgentIdMismatch { expected, actual } => Some(Self::new(
                &claims.tool,
                "agent_id_mismatch",
                &claims.tenant_id,
                &claims.agent_id,
                &claims.session_id,
                serde_json::json!({
                    "expected_agent_id": expected,
                    "actual_agent_id": actual,
                }),
            )),
            VerifyError::ToolMismatch { expected, actual } => Some(Self::new(
                actual,
                "tool_mismatch",
                &claims.tenant_id,
                &claims.agent_id,
                &claims.session_id,
                serde_json::json!({
                    "expected_tool": expected,
                    "actual_tool": actual,
                }),
            )),
            _ => None,
        }
    }
}

pub fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes = hex_decode(hex_str)
        .ok_or_else(|| VerifyError::InvalidFormat("bad hex in verifying key".into()))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidFormat("verifying key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|e| VerifyError::InvalidFormat(format!("invalid verifying key: {}", e)))
}

fn canonicalize_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}:{}", k, canonicalize_json(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", inner.join(","))
        }
        serde_json::Value::String(s) => format!("\"{}\"", s),
        other => other.to_string(),
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

fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        let mut result: u8 = 0xff;
        let longer = if a.len() > b.len() { a } else { b };
        for byte in longer.as_bytes() {
            result |= byte ^ byte;
        }
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    fn make_token(claims: &TokenClaims, signing_key: &SigningKey) -> String {
        let payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(claims).unwrap());
        let sig = signing_key.sign(&serde_json::to_vec(claims).unwrap());
        let token = SignedToken {
            header: TOKEN_HEADER.to_string(),
            payload,
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        };
        serde_json::to_string(&token).unwrap()
    }

    fn make_claims(tool: &str, args_hash: &str, agent_id: &str) -> TokenClaims {
        TokenClaims {
            tool: tool.to_string(),
            args_hash: args_hash.to_string(),
            session_id: "sess-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            agent_id: agent_id.to_string(),
            decision: "Allow".to_string(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 60,
            jti: "jti-1".to_string(),
            risk_score: 0.1,
        }
    }

    #[test]
    fn test_verify_valid_token() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let claims = make_claims("exec", "abc123", "agent-1");
        let token_str = make_token(&claims, &signing_key);

        let result = verify_token(&token_str, &verifying_key).unwrap();
        assert_eq!(result.tool, "exec");
        assert_eq!(result.agent_id, "agent-1");
    }

    #[test]
    fn test_verify_expired_token() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut claims = make_claims("exec", "abc123", "agent-1");
        claims.exp = chrono::Utc::now().timestamp() - 10;
        let token_str = make_token(&claims, &signing_key);

        let result = verify_token(&token_str, &verifying_key);
        assert!(matches!(result, Err(VerifyError::Expired)));
    }

    #[test]
    fn test_verify_wrong_key() {
        let seed1 = [42u8; 32];
        let seed2 = [99u8; 32];
        let signing_key = SigningKey::from_bytes(&seed1);
        let wrong_vk = SigningKey::from_bytes(&seed2).verifying_key();

        let claims = make_claims("exec", "abc123", "agent-1");
        let token_str = make_token(&claims, &signing_key);

        let result = verify_token(&token_str, &wrong_vk);
        assert!(matches!(result, Err(VerifyError::InvalidSignature)));
    }

    #[test]
    fn test_args_hash_deterministic() {
        let args = serde_json::json!({"command": "ls", "args": ["-la"]});
        let h1 = compute_args_hash(&args);
        let h2 = compute_args_hash(&args);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_args_hash_key_order_independent() {
        let a = serde_json::json!({"b": 2, "a": 1});
        let b = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(compute_args_hash(&a), compute_args_hash(&b));
    }

    #[test]
    fn test_verify_args_hash_match() {
        let args = serde_json::json!({"command": "ls"});
        let hash = compute_args_hash(&args);
        let claims = make_claims("exec", &hash, "agent-1");
        assert!(verify_args_hash(&claims, &args).is_ok());
    }

    #[test]
    fn test_verify_args_hash_mismatch() {
        let args = serde_json::json!({"command": "ls"});
        let claims = make_claims("exec", "wrong_hash", "agent-1");
        assert!(matches!(
            verify_args_hash(&claims, &args),
            Err(VerifyError::ArgsHashMismatch)
        ));
    }

    #[test]
    fn test_verify_tool_match() {
        let claims = make_claims("exec", "hash", "agent-1");
        assert!(verify_tool(&claims, "exec").is_ok());
        assert!(matches!(
            verify_tool(&claims, "file"),
            Err(VerifyError::ToolMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_agent_id_match() {
        let claims = make_claims("exec", "hash", "agent-1");
        assert!(verify_agent_id(&claims, "agent-1").is_ok());
        assert!(matches!(
            verify_agent_id(&claims, "agent-2"),
            Err(VerifyError::AgentIdMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_decision_allow() {
        let claims = make_claims("exec", "hash", "agent-1");
        assert!(verify_decision_allow(&claims).is_ok());

        let mut blocked = claims.clone();
        blocked.decision = "Block".to_string();
        assert!(matches!(
            verify_decision_allow(&blocked),
            Err(VerifyError::DecisionNotAllow { .. })
        ));
    }

    #[test]
    fn test_verify_risk_below() {
        let claims = make_claims("exec", "hash", "agent-1");
        assert!(verify_risk_below(&claims, 1.0).is_ok());
        assert!(matches!(
            verify_risk_below(&claims, 0.05),
            Err(VerifyError::RiskTooHigh { .. })
        ));
    }

    #[test]
    fn test_parse_verifying_key_roundtrip() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key();
        let hex = hex_encode(vk.as_bytes());

        let parsed = parse_verifying_key(&hex).unwrap();
        assert_eq!(vk.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn test_bypass_report_for_args_mismatch() {
        let claims = make_claims("exec", "wrong", "agent-1");
        let err = VerifyError::ArgsHashMismatch;
        let report = BypassReport::for_verification_failure(&claims, &err).unwrap();
        assert_eq!(report.reason, "args_hash_mismatch");
        assert_eq!(report.tool, "exec");
        assert_eq!(report.agent_id, "agent-1");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }
}
