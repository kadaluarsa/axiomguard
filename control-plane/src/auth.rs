use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AuthState {
    pub valid_api_keys: HashSet<String>,
    pub admin_keys: HashSet<String>,
    pub require_auth: bool,
}

impl AuthState {
    pub fn new(valid_api_keys: HashSet<String>, admin_keys: HashSet<String>, require_auth: bool) -> Self {
        Self { valid_api_keys, admin_keys, require_auth }
    }
}

fn extract_api_key(request: &Request) -> Option<&str> {
    request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
}

fn insert_tenant_id(request: &mut Request) {
    let tenant_id = request
        .headers()
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default")
        .to_string();
    request.extensions_mut().insert(TenantId(tenant_id));
}

pub async fn auth_middleware(
    State(state): State<Arc<AuthState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !state.require_auth {
        return Ok(next.run(request).await);
    }

    let api_key = match extract_api_key(&request) {
        Some(k) => k,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let is_valid = state.valid_api_keys.iter().any(|key| {
        key.as_bytes().ct_eq(api_key.as_bytes()).into()
    });

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    insert_tenant_id(&mut request);
    Ok(next.run(request).await)
}

pub async fn admin_auth_middleware(
    State(state): State<Arc<AuthState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !state.require_auth {
        return Ok(next.run(request).await);
    }

    let api_key = match extract_api_key(&request) {
        Some(k) => k,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let is_valid = state.admin_keys.iter().any(|key| {
        key.as_bytes().ct_eq(api_key.as_bytes()).into()
    });

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    insert_tenant_id(&mut request);
    Ok(next.run(request).await)
}

#[derive(Debug, Clone)]
pub struct TenantId(pub String);
