use ag_tool_common::{
    verify_agent_id, verify_args_hash, verify_decision_allow, verify_risk_below,
    verify_token, verify_tool, BypassReport, TokenClaims, VerifyError,
};
use ed25519_dalek::VerifyingKey;

pub const TOOL_NAME: &str = "http";

pub struct HttpConfig {
    pub verifying_key: VerifyingKey,
    pub max_risk_score: f32,
    pub bypass_reporter: Option<Box<dyn Fn(BypassReport) + Send + Sync>>,
    pub http_client: Option<reqwest::Client>,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("verification failed: {0}")]
    Verification(#[from] VerifyError),
    #[error("internal IP blocked: {0}")]
    InternalIpBlocked(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpArgs {
    pub url: String,
    pub method: HttpMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

#[derive(Debug)]
pub struct HttpResult {
    pub status: u16,
    pub body: String,
    pub url: String,
}

pub async fn execute_with_token(
    token_str: &str,
    agent_id: &str,
    args: &HttpArgs,
    config: &HttpConfig,
) -> Result<HttpResult, HttpError> {
    validate_url(&args.url)?;

    let claims = verify_token(token_str, &config.verifying_key)?;

    let args_json = serde_json::to_value(args).expect("HttpArgs serialization is infallible");
    if let Err(e) = run_checks(&claims, agent_id, &args_json, config.max_risk_score) {
        report_bypass(&config, &claims, &e);
        return Err(HttpError::Verification(e));
    }

    let client = config
        .http_client
        .as_ref()
        .unwrap_or_else(|| {
            static DEFAULT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
            DEFAULT.get_or_init(|| reqwest::Client::new())
        });

    let mut request = match &args.method {
        HttpMethod::Get => client.get(&args.url),
        HttpMethod::Post => client.post(&args.url),
        HttpMethod::Put => client.put(&args.url),
        HttpMethod::Delete => client.delete(&args.url),
        HttpMethod::Patch => client.patch(&args.url),
    };

    if let Some(headers) = &args.headers {
        for (k, v) in headers {
            request = request.header(k.as_str(), v.as_str());
        }
    }

    if let Some(body) = &args.body {
        request = request.json(body);
    }

    let response = request.send().await?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    Ok(HttpResult {
        status,
        body,
        url: args.url.clone(),
    })
}

fn validate_url(url: &str) -> Result<(), HttpError> {
    if url.contains("127.0.0.1")
        || url.contains("localhost")
        || url.contains("0.0.0.0")
        || url.contains("169.254.169.254")
    {
        return Err(HttpError::InternalIpBlocked(url.to_string()));
    }

    if let Ok(host) = extract_host(url) {
        if host.starts_with("192.168.")
            || host.starts_with("10.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.2")
            || host.starts_with("172.3")
        {
            return Err(HttpError::InternalIpBlocked(url.to_string()));
        }
    }

    Ok(())
}

fn extract_host(url: &str) -> Result<String, ()> {
    let stripped = url.strip_prefix("https://").or(url.strip_prefix("http://")).ok_or(())?;
    let host = stripped.split(':').next().unwrap_or(stripped);
    let host = host.split('/').next().unwrap_or(host);
    Ok(host.to_string())
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

fn report_bypass(config: &HttpConfig, claims: &TokenClaims, error: &VerifyError) {
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
        "http verification failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_tool_common::{compute_args_hash, TOKEN_HEADER};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_token(claims: &TokenClaims) -> (String, VerifyingKey) {
        let seed = [55u8; 32];
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

    fn make_claims(tool: &str, args: &HttpArgs, agent_id: &str) -> TokenClaims {
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
    fn test_internal_ip_localhost_blocked() {
        assert!(validate_url("http://localhost/admin").is_err());
        assert!(validate_url("http://127.0.0.1/secret").is_err());
    }

    #[test]
    fn test_internal_ip_169_blocked() {
        assert!(validate_url("http://169.254.169.254/metadata").is_err());
    }

    #[test]
    fn test_internal_ip_private_blocked() {
        assert!(validate_url("http://192.168.1.1/admin").is_err());
        assert!(validate_url("http://10.0.0.1/secret").is_err());
    }

    #[test]
    fn test_external_url_allowed() {
        assert!(validate_url("https://api.example.com/data").is_ok());
        assert!(validate_url("https://github.com/repos").is_ok());
    }

    #[test]
    fn test_wrong_tool_rejected() {
        let args = HttpArgs {
            url: "https://api.example.com".to_string(),
            method: HttpMethod::Get,
            headers: None,
            body: None,
        };
        let claims = make_claims("exec", &args, "agent-1");
        let (token_str, vk) = make_signed_token(&claims);

        let config = HttpConfig {
            verifying_key: vk,
            max_risk_score: 1.0,
            bypass_reporter: None,
            http_client: None,
        };

        let args_json = serde_json::to_value(&args).unwrap();
        let result = run_checks(&claims, "agent-1", &args_json, 1.0);
        assert!(matches!(result, Err(VerifyError::ToolMismatch { .. })));
    }

    #[test]
    fn test_agent_id_mismatch_rejected() {
        let args = HttpArgs {
            url: "https://api.example.com".to_string(),
            method: HttpMethod::Get,
            headers: None,
            body: None,
        };
        let claims = make_claims(TOOL_NAME, &args, "agent-1");
        let args_json = serde_json::to_value(&args).unwrap();
        let result = run_checks(&claims, "agent-2", &args_json, 1.0);
        assert!(matches!(result, Err(VerifyError::AgentIdMismatch { .. })));
    }

    #[test]
    fn test_url_validation_before_token_check() {
        let args = HttpArgs {
            url: "http://169.254.169.254/metadata".to_string(),
            method: HttpMethod::Get,
            headers: None,
            body: None,
        };

        assert!(validate_url(&args.url).is_err());
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("https://api.example.com/path").unwrap(), "api.example.com");
        assert_eq!(extract_host("http://localhost:8080/test").unwrap(), "localhost");
    }
}
