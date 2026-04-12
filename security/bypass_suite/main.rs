use ag_tool_common::{
    compute_args_hash, parse_verifying_key, verify_agent_id, verify_args_hash,
    verify_decision_allow, verify_risk_below, verify_token, verify_tool, BypassReport, TokenClaims,
    TOKEN_HEADER,
};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

fn make_token(claims: &TokenClaims, signing_key: &SigningKey) -> String {
    let payload =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(claims).unwrap());
    let sig = signing_key.sign(&serde_json::to_vec(claims).unwrap());

    #[derive(serde::Serialize, serde::Deserialize)]
    struct SignedToken {
        header: String,
        payload: String,
        signature: String,
    }

    serde_json::to_string(&SignedToken {
        header: TOKEN_HEADER.to_string(),
        payload,
        signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
    })
    .unwrap()
}

fn make_claims(tool: &str, args_hash: &str, agent_id: &str) -> TokenClaims {
    TokenClaims {
        tool: tool.to_string(),
        args_hash: args_hash.to_string(),
        session_id: "sess-bypass".to_string(),
        tenant_id: "tenant-bypass".to_string(),
        agent_id: agent_id.to_string(),
        decision: "Allow".to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp: chrono::Utc::now().timestamp() + 60,
        jti: "jti-bypass".to_string(),
        risk_score: 0.1,
    }
}

#[test]
fn bypass_forged_token_wrong_key() {
    let real_key = SigningKey::from_bytes(&[1u8; 32]);
    let forged_key = SigningKey::from_bytes(&[2u8; 32]);
    let real_vk = real_key.verifying_key();

    let claims = make_claims("exec", "abc", "agent-1");
    let token = make_token(&claims, &forged_key);

    let result = verify_token(&token, &real_vk);
    assert!(result.is_err(), "Forged token should be rejected");
    assert!(
        matches!(result, Err(ag_tool_common::VerifyError::InvalidSignature)),
        "Should fail with InvalidSignature"
    );
}

#[test]
fn bypass_expired_token() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();

    let mut claims = make_claims("exec", "abc", "agent-1");
    claims.exp = chrono::Utc::now().timestamp() - 10;
    let token = make_token(&claims, &signing_key);

    let result = verify_token(&token, &vk);
    assert!(result.is_err(), "Expired token should be rejected");
}

#[test]
fn bypass_args_tampering() {
    let original_args = serde_json::json!({"command": "ls", "args": ["-la"]});
    let tampered_args = serde_json::json!({"command": "rm", "args": ["-rf", "/"]});

    let original_hash = compute_args_hash(&original_args);
    let tampered_hash = compute_args_hash(&tampered_args);

    assert_ne!(
        original_hash, tampered_hash,
        "Different args must produce different hashes"
    );

    let claims = make_claims("exec", &original_hash, "agent-1");
    let result = verify_args_hash(&claims, &tampered_args);
    assert!(result.is_err(), "Tampered args should fail hash check");
}

#[test]
fn bypass_cross_agent_token_reuse() {
    let claims = make_claims("exec", "abc", "agent-1");
    let result = verify_agent_id(&claims, "agent-2");
    assert!(
        result.is_err(),
        "Token issued for agent-1 should not work for agent-2"
    );
}

#[test]
fn bypass_tool_mismatch() {
    let claims = make_claims("exec", "abc", "agent-1");
    let result = verify_tool(&claims, "file");
    assert!(
        result.is_err(),
        "Token for 'exec' should not work for 'file'"
    );
}

#[test]
fn bypass_decision_not_allow() {
    let mut claims = make_claims("exec", "abc", "agent-1");
    claims.decision = "Block".to_string();
    let result = verify_decision_allow(&claims);
    assert!(result.is_err(), "Blocked decision should not be executable");
}

#[test]
fn bypass_risk_threshold_exceeded() {
    let mut claims = make_claims("exec", "abc", "agent-1");
    claims.risk_score = 0.95;
    let result = verify_risk_below(&claims, 0.5);
    assert!(result.is_err(), "High risk score should be rejected");
}

#[test]
fn bypass_manually_constructed_token() {
    let vk = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

    let fake_token = r#"{"header":"ag-exec-v1","payload":"imanattackerya","signature":"AAAAAA=="}"#;
    let result = verify_token(fake_token, &vk);
    assert!(
        result.is_err(),
        "Manually constructed token should be rejected"
    );
}

#[test]
fn bypass_empty_signature() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    let claims = make_claims("exec", "abc", "agent-1");

    let payload =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&claims).unwrap());

    let fake_token = serde_json::json!({
        "header": TOKEN_HEADER,
        "payload": payload,
        "signature": ""
    })
    .to_string();

    let result = verify_token(&fake_token, &vk);
    assert!(result.is_err(), "Empty signature should be rejected");
}

#[test]
fn bypass_wrong_header() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    let claims = make_claims("exec", "abc", "agent-1");
    let token = make_token(&claims, &signing_key);

    let mut parsed: serde_json::Value = serde_json::from_str(&token).unwrap();
    parsed["header"] = serde_json::json!("evil-header");
    let modified = serde_json::to_string(&parsed).unwrap();

    let result = verify_token(&modified, &vk);
    assert!(result.is_err(), "Wrong header should be rejected");
}

#[test]
fn bypass_payload_modification() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    let claims = make_claims("exec", "abc", "agent-1");
    let token = make_token(&claims, &signing_key);

    let mut parsed: serde_json::Value = serde_json::from_str(&token).unwrap();
    parsed["payload"] = serde_json::json!(base64::engine::general_purpose::STANDARD
        .encode(serde_json::json!({"tool": "file", "agent_id": "agent-evil"}).to_string()));
    let modified = serde_json::to_string(&parsed).unwrap();

    let result = verify_token(&modified, &vk);
    assert!(
        result.is_err(),
        "Modified payload should fail signature check"
    );
}

#[test]
fn bypass_report_generation() {
    let claims = make_claims("exec", "abc", "agent-1");
    let err = ag_tool_common::VerifyError::ArgsHashMismatch;
    let report = BypassReport::for_verification_failure(&claims, &err).unwrap();
    assert_eq!(report.tool, "exec");
    assert_eq!(report.reason, "args_hash_mismatch");
    assert_eq!(report.agent_id, "agent-1");
    assert_eq!(report.tenant_id, "tenant-bypass");
}

#[test]
fn bypass_key_order_independent_hash() {
    let args1 = serde_json::json!({"z": 1, "a": 2});
    let args2 = serde_json::json!({"a": 2, "z": 1});
    assert_eq!(
        compute_args_hash(&args1),
        compute_args_hash(&args2),
        "Key reordering should not change hash"
    );
}
