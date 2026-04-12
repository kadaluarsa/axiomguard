use ag_tool_common::{
    verify_agent_id, verify_args_hash, verify_decision_allow, verify_risk_below,
    verify_token, verify_tool, BypassReport, TokenClaims, VerifyError,
};
use ed25519_dalek::VerifyingKey;

pub const TOOL_NAME: &str = "file";

pub struct FileConfig {
    pub verifying_key: VerifyingKey,
    pub max_risk_score: f32,
    pub bypass_reporter: Option<Box<dyn Fn(BypassReport) + Send + Sync>>,
}

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("verification failed: {0}")]
    Verification(#[from] VerifyError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("path traversal detected: {0}")]
    PathTraversal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileArgs {
    pub path: String,
    pub mode: FileMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileMode {
    Read,
    Write,
    Append,
}

#[derive(Debug)]
pub struct FileResult {
    pub content: Option<String>,
    pub bytes_written: Option<u64>,
    pub path: String,
}

pub async fn execute_with_token(
    token_str: &str,
    agent_id: &str,
    args: &FileArgs,
    config: &FileConfig,
) -> Result<FileResult, FileError> {
    validate_path(&args.path)?;

    let claims = verify_token(token_str, &config.verifying_key)?;

    let args_json = serde_json::to_value(args).expect("FileArgs serialization is infallible");
    if let Err(e) = run_checks(&claims, agent_id, &args_json, config.max_risk_score) {
        report_bypass(&config, &claims, &e);
        return Err(FileError::Verification(e));
    }

    match &args.mode {
        FileMode::Read => {
            let content = tokio::fs::read_to_string(&args.path).await?;
            Ok(FileResult {
                content: Some(content),
                bytes_written: None,
                path: args.path.clone(),
            })
        }
        FileMode::Write => {
            let data = args.content.as_deref().unwrap_or("");
            tokio::fs::write(&args.path, data).await?;
            Ok(FileResult {
                content: None,
                bytes_written: Some(data.len() as u64),
                path: args.path.clone(),
            })
        }
        FileMode::Append => {
            let data = args.content.as_deref().unwrap_or("");
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&args.path)
                .await?;
            file.write_all(data.as_bytes()).await?;
            Ok(FileResult {
                content: None,
                bytes_written: Some(data.len() as u64),
                path: args.path.clone(),
            })
        }
    }
}

fn validate_path(path: &str) -> Result<(), FileError> {
    if path.contains("..") {
        return Err(FileError::PathTraversal(path.to_string()));
    }
    if path.starts_with('/') && !path.starts_with("/tmp/") && !path.starts_with("/home/") {
        tracing::warn!(path = %path, "write to sensitive absolute path");
    }
    Ok(())
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

fn report_bypass(config: &FileConfig, claims: &TokenClaims, error: &VerifyError) {
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
        "file verification failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_tool_common::{compute_args_hash, TOKEN_HEADER};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_token(claims: &TokenClaims) -> (String, VerifyingKey) {
        let seed = [88u8; 32];
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

    fn make_claims(tool: &str, args: &FileArgs, agent_id: &str) -> TokenClaims {
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

    #[test]
    fn test_path_traversal_blocked() {
        assert!(validate_path("../../../etc/passwd").is_err());
        assert!(validate_path("data/../../../etc/shadow").is_err());
    }

    #[test]
    fn test_normal_path_allowed() {
        assert!(validate_path("data/output.txt").is_ok());
        assert!(validate_path("/tmp/workdir/file.txt").is_ok());
    }

    #[tokio::test]
    async fn test_file_read_with_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        tokio::fs::write(&file_path, "hello world").await.unwrap();

        let path_str = file_path.to_str().unwrap().to_string();
        let args = FileArgs {
            path: path_str.clone(),
            mode: FileMode::Read,
            content: None,
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = FileConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-1", &args, &config)
            .await
            .unwrap();
        assert_eq!(result.content.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn test_file_write_with_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("output.txt");
        let path_str = file_path.to_str().unwrap().to_string();

        let args = FileArgs {
            path: path_str.clone(),
            mode: FileMode::Write,
            content: Some("test content".to_string()),
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = FileConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-1", &args, &config)
            .await
            .unwrap();
        assert_eq!(result.bytes_written.unwrap(), 12);

        let written = tokio::fs::read_to_string(&file_path).await.unwrap();
        assert_eq!(written, "test content");
    }

    #[tokio::test]
    async fn test_file_wrong_agent_rejected() {
        let args = FileArgs {
            path: "/tmp/test.txt".to_string(),
            mode: FileMode::Read,
            content: None,
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = FileConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            bypass_reporter: None,
        };

        let result = execute_with_token(&token_str, "agent-2", &args, &config).await;
        assert!(matches!(
            result,
            Err(FileError::Verification(VerifyError::AgentIdMismatch { .. }))
        ));
    }

    #[tokio::test]
    async fn test_file_path_traversal_rejected_before_verify() {
        let args = FileArgs {
            path: "../../../etc/passwd".to_string(),
            mode: FileMode::Read,
            content: None,
        };

        let seed = [88u8; 32];
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let config = FileConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            bypass_reporter: None,
        };

        let result = execute_with_token("dummy", "agent-1", &args, &config).await;
        assert!(matches!(result, Err(FileError::PathTraversal(_))));
    }
}
