use tonic::{Request, Status};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthScheme {
    ApiKey,
    BearerToken,
}

impl fmt::Display for AuthScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthScheme::ApiKey => write!(f, "API Key"),
            AuthScheme::BearerToken => write!(f, "Bearer Token"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub authenticated: bool,
    pub scheme: Option<AuthScheme>,
    pub principal: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthInterceptor {
    valid_api_keys: Arc<RwLock<HashSet<String>>>,
    valid_bearer_tokens: Arc<RwLock<HashSet<String>>>,
    require_auth: bool,
}

impl AuthInterceptor {
    pub fn new(valid_api_keys: Vec<String>, valid_bearer_tokens: Vec<String>, require_auth: bool) -> Self {
        Self {
            valid_api_keys: Arc::new(RwLock::new(valid_api_keys.into_iter().collect())),
            valid_bearer_tokens: Arc::new(RwLock::new(valid_bearer_tokens.into_iter().collect())),
            require_auth,
        }
    }

    pub fn add_api_key(&self, api_key: String) {
        let mut keys = self.valid_api_keys.write().unwrap();
        keys.insert(api_key);
        info!(action = "add_api_key", "Added new valid API key");
    }

    pub fn remove_api_key(&self, api_key: &str) {
        let mut keys = self.valid_api_keys.write().unwrap();
        keys.remove(api_key);
        info!(action = "remove_api_key", "Removed API key");
    }

    pub fn add_bearer_token(&self, token: String) {
        let mut tokens = self.valid_bearer_tokens.write().unwrap();
        tokens.insert(token);
        info!(action = "add_bearer_token", "Added new valid bearer token");
    }

    pub fn remove_bearer_token(&self, token: &str) {
        let mut tokens = self.valid_bearer_tokens.write().unwrap();
        tokens.remove(token);
        info!(action = "remove_bearer_token", "Removed bearer token");
    }

    /// Constant time validation of credentials to prevent timing attacks
    fn validate_credential(&self, credential: &str, scheme: AuthScheme) -> bool {
        let credentials = match scheme {
            AuthScheme::ApiKey => self.valid_api_keys.read().unwrap(),
            AuthScheme::BearerToken => self.valid_bearer_tokens.read().unwrap(),
        };

        for valid_cred in credentials.iter() {
            if valid_cred.as_bytes().ct_eq(credential.as_bytes()).into() {
                return true;
            }
        }

        false
    }

    fn validate_request_inner<T>(&self, mut request: Request<T>) -> Result<Request<T>, Status> {
        let peer_addr = request.remote_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());

        // Check for API key first
        if let Some(api_key_val) = request.metadata().get("x-api-key") {
            let api_key = api_key_val.to_str().map_err(|_| {
                warn!(peer = %peer_addr, scheme = %AuthScheme::ApiKey, "Invalid API key encoding");
                Status::unauthenticated("Invalid API key format")
            })?;

            if self.validate_credential(api_key, AuthScheme::ApiKey) {
                info!(peer = %peer_addr, scheme = %AuthScheme::ApiKey, "Authentication successful");
                request.extensions_mut().insert(AuthContext {
                    authenticated: true,
                    scheme: Some(AuthScheme::ApiKey),
                    principal: None,
                });
                return Ok(request);
            }

            warn!(peer = %peer_addr, scheme = %AuthScheme::ApiKey, "Invalid API key provided");
            return Err(Status::permission_denied("Invalid API key"));
        }

        // Check for Bearer token
        if let Some(auth_header) = request.metadata().get("authorization") {
            let auth_str = auth_header.to_str().map_err(|_| {
                warn!(peer = %peer_addr, "Invalid Authorization header encoding");
                Status::unauthenticated("Invalid Authorization header format")
            })?;

            if !auth_str.starts_with("Bearer ") {
                warn!(peer = %peer_addr, "Authorization header missing Bearer scheme");
                return Err(Status::unauthenticated("Invalid Authorization scheme"));
            }

            let token = &auth_str[7..];
            if self.validate_credential(token, AuthScheme::BearerToken) {
                info!(peer = %peer_addr, scheme = %AuthScheme::BearerToken, "Authentication successful");
                request.extensions_mut().insert(AuthContext {
                    authenticated: true,
                    scheme: Some(AuthScheme::BearerToken),
                    principal: None,
                });
                return Ok(request);
            }

            warn!(peer = %peer_addr, scheme = %AuthScheme::BearerToken, "Invalid bearer token provided");
            return Err(Status::permission_denied("Invalid bearer token"));
        }

        // No credentials provided
        if self.require_auth {
            warn!(peer = %peer_addr, "Authentication required but no credentials provided");
            return Err(Status::unauthenticated("Missing authentication credentials"));
        }

        // Auth is optional, allow request
        info!(peer = %peer_addr, "Anonymous access allowed (auth not required)");
        request.extensions_mut().insert(AuthContext {
            authenticated: false,
            scheme: None,
            principal: None,
        });

        Ok(request)
    }

    /// Validate incoming gRPC request (async wrapper for backwards compatibility)
    pub async fn validate_request<T>(&self, request: Request<T>) -> Result<Request<T>, Status> {
        Ok(self.validate_request_inner(request)?)
    }
}

/// Tonic interceptor implementation
impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        self.validate_request_inner(request)
    }
}
