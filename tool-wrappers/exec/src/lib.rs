use ag_tool_common::{
    verify_agent_id, verify_args_hash, verify_decision_allow, verify_risk_below,
    verify_token, verify_tool, BypassReport, TokenClaims, VerifyError,
};
use ed25519_dalek::VerifyingKey;
use std::time::Instant;

pub const TOOL_NAME: &str = "exec";

pub struct ExecConfig {
    pub verifying_key: VerifyingKey,
    pub max_risk_score: f32,
    pub timeout_secs: u64,
    pub bypass_reporter: Option<Box<dyn Fn(BypassReport) + Send + Sync>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("verification failed: {0}")]
    Verification(#[from] VerifyError),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("execution timed out after {0}s")]
    Timeout(u64),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecArgs {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub elapsed_ms: u64,
}

pub async fn execute_with_token(
    token_str: &str,
    agent_id: &str,
    args: &ExecArgs,
    config: &ExecConfig,
) -> Result<ExecResult, ExecError> {
    let claims = verify_token(token_str, &config.verifying_key)?;

    let args_json = serde_json::to_value(args).expect("ExecArgs serialization is infallible");
    if let Err(e) = run_checks(&claims, agent_id, &args_json, config.max_risk_score) {
        report_bypass(&config, &claims, &e);
        return Err(ExecError::Verification(e));
    }

    let start = Instant::now();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(config.timeout_secs),
        tokio::process::Command::new(&args.command)
            .args(&args.args)
            .output(),
    )
    .await
    .map_err(|_| ExecError::Timeout(config.timeout_secs))?
    .map_err(|e| ExecError::Execution(e.to_string()))?;

    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

fn run_checks(
    claims: &TokenClaims,
    expected_agent_id: &str,
    args_json: &serde_json::Value,
    max_risk: f32,
) -> Result<(), VerifyError> {
    verify_tool(claims, TOOL_NAME)?;
    verify_agent_id(claims, expected_agent_id)?;
    verify_decision_allow(claims)?;
    verify_risk_below(claims, max_risk)?;
    verify_args_hash(claims, args_json)?;
    Ok(())
}

fn report_bypass(config: &ExecConfig, claims: &TokenClaims, error: &VerifyError) {
    if let Some(ref reporter) = config.bypass_reporter {
        if let Some(report) = BypassReport::for_verification_failure(claims, error) {
            reporter(report);
        } else {
            let report = BypassReport::new(
                TOOL_NAME,
                &format!("{}", error),
                &claims.tenant_id,
                &claims.agent_id,
                &claims.session_id,
                serde_json::json!({}),
            );
            reporter(report);
        }
    }
    tracing::warn!(
        tool = TOOL_NAME,
        agent_id = %claims.agent_id,
        error = %error,
        "exec verification failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_tool_common::{compute_args_hash, TOKEN_HEADER};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_token(claims: &TokenClaims) -> (String, VerifyingKey) {
        let seed = [77u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key();

        let payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(claims).unwrap());
        let sig = signing_key.sign(&serde_json::to_vec(claims).unwrap());

        #[derive(serde::Serialize, serde::Deserialize)]
        struct SignedToken {
            header: String,
            payload: String,
            signature: String,
        }

        let token = SignedToken {
            header: TOKEN_HEADER.to_string(),
            payload,
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        };
        (serde_json::to_string(&token).unwrap(), vk)
    }

    fn make_claims(tool: &str, args: &ExecArgs, agent_id: &str) -> TokenClaims {
        TokenClaims {
            tool: tool.to_string(),
            args_hash: compute_args_hash(&serde_json::to_value(args).unwrap()),
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

    #[tokio::test]
    async fn test_exec_echo_with_valid_token() {
        let args = ExecArgs {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = ExecConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            timeout_secs: 5,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-1", &args, &config)
            .await
            .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello"));
    }

    #[tokio::test]
    async fn test_exec_wrong_tool_rejected() {
        let args = ExecArgs {
            command: "echo".to_string(),
            args: vec![],
        };
        let claims = make_claims("file", &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = ExecConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            timeout_secs: 5,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-1", &args, &config).await;
        assert!(matches!(
            result,
            Err(ExecError::Verification(VerifyError::ToolMismatch { .. }))
        ));
    }

    #[tokio::test]
    async fn test_exec_wrong_agent_rejected() {
        let args = ExecArgs {
            command: "echo".to_string(),
            args: vec![],
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = ExecConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            timeout_secs: 5,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-2", &args, &config).await;
        assert!(matches!(
            result,
            Err(ExecError::Verification(VerifyError::AgentIdMismatch { .. }))
        ));
    }

    #[tokio::test]
    async fn test_exec_args_mismatch_rejected() {
        let args = ExecArgs {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let wrong_args = ExecArgs {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/".to_string()],
        };

        let config = ExecConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            timeout_secs: 5,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-1", &wrong_args, &config).await;
        assert!(matches!(
            result,
            Err(ExecError::Verification(VerifyError::ArgsHashMismatch))
        ));
    }

    #[tokio::test]
    async fn test_exec_bypass_reporter_called() {
        let args = ExecArgs {
            command: "echo".to_string(),
            args: vec![],
        };
        let claims = make_claims("wrong_tool", &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let reported = std::sync::Arc::new(std::sync::Mutex::new(None));
        let reported_clone = reported.clone();

        let config = ExecConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            timeout_secs: 5,
            bypass_reporter: Some(Box::new(move |report: BypassReport| {
                *reported_clone.lock().unwrap() = Some(report);
            })),
        };

        let _ = execute_with_token(&token_str, "agent-1", &args, &config).await;
        let report = reported.lock().unwrap().take().unwrap();
        assert_eq!(report.reason, "tool_mismatch");
    }
}
