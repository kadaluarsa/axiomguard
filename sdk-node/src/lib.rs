use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub fn compute_hash(json_str: String) -> Result<String> {
    let val: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| Error::from_reason(format!("invalid JSON: {}", e)))?;
    Ok(ag_tool_common::compute_args_hash(&val))
}

#[napi(object)]
pub struct Claims {
    pub tool: String,
    pub args_hash: String,
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub decision: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub risk_score: f64,
}

#[napi(object)]
pub struct VerifyResult {
    pub valid: bool,
    pub claims: Option<Claims>,
    pub error: Option<String>,
}

#[napi]
pub fn verify_token(token_str: String, verifying_key_hex: String) -> Result<VerifyResult> {
    let vk = ag_tool_common::parse_verifying_key(&verifying_key_hex)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    match ag_tool_common::verify_token(&token_str, &vk) {
        Ok(claims) => Ok(VerifyResult {
            valid: true,
            claims: Some(Claims {
                tool: claims.tool,
                args_hash: claims.args_hash,
                session_id: claims.session_id,
                tenant_id: claims.tenant_id,
                agent_id: claims.agent_id,
                decision: claims.decision,
                iat: claims.iat,
                exp: claims.exp,
                jti: claims.jti,
                risk_score: claims.risk_score as f64,
            }),
            error: None,
        }),
        Err(e) => Ok(VerifyResult {
            valid: false,
            claims: None,
            error: Some(e.to_string()),
        }),
    }
}

#[napi]
pub fn verify_token_with_checks(
    token_str: String,
    verifying_key_hex: String,
    expected_tool: Option<String>,
    expected_agent_id: Option<String>,
    expected_args_json: Option<String>,
    max_risk: Option<f64>,
) -> Result<VerifyResult> {
    let vk = ag_tool_common::parse_verifying_key(&verifying_key_hex)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    let claims = match ag_tool_common::verify_token(&token_str, &vk) {
        Ok(c) => c,
        Err(e) => {
            return Ok(VerifyResult {
                valid: false,
                claims: None,
                error: Some(e.to_string()),
            })
        }
    };

    if let Some(ref tool) = expected_tool {
        if let Err(e) = ag_tool_common::verify_tool(&claims, tool) {
            return Ok(VerifyResult {
                valid: false,
                claims: Some(into_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Some(ref aid) = expected_agent_id {
        if let Err(e) = ag_tool_common::verify_agent_id(&claims, aid) {
            return Ok(VerifyResult {
                valid: false,
                claims: Some(into_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Some(ref args_json) = expected_args_json {
        let val: serde_json::Value = serde_json::from_str(args_json)
            .map_err(|e| Error::from_reason(format!("invalid args JSON: {}", e)))?;
        if let Err(e) = ag_tool_common::verify_args_hash(&claims, &val) {
            return Ok(VerifyResult {
                valid: false,
                claims: Some(into_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Some(max) = max_risk {
        if let Err(e) = ag_tool_common::verify_risk_below(&claims, max as f32) {
            return Ok(VerifyResult {
                valid: false,
                claims: Some(into_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Err(e) = ag_tool_common::verify_decision_allow(&claims) {
        return Ok(VerifyResult {
            valid: false,
            claims: Some(into_claims(&claims)),
            error: Some(e.to_string()),
        });
    }

    Ok(VerifyResult {
        valid: true,
        claims: Some(into_claims(&claims)),
        error: None,
    })
}

fn into_claims(c: &ag_tool_common::TokenClaims) -> Claims {
    Claims {
        tool: c.tool.clone(),
        args_hash: c.args_hash.clone(),
        session_id: c.session_id.clone(),
        tenant_id: c.tenant_id.clone(),
        agent_id: c.agent_id.clone(),
        decision: c.decision.clone(),
        iat: c.iat,
        exp: c.exp,
        jti: c.jti.clone(),
        risk_score: c.risk_score as f64,
    }
}
