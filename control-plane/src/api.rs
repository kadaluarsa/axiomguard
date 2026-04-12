use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::agent::{Agent, RuleEntry};
use crate::auth::TenantId;
use crate::db::{AuditEventRow, SessionRow};
use crate::policy::PolicyBlob;
use crate::state::AppState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct TokenIssueRequest {
    pub tool: String,
    pub args_hash: String,
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub decision: String,
    pub risk_score: f32,
}

#[derive(Debug, Serialize)]
pub struct TokenIssueResponse {
    pub token: String,
    pub expires_in_secs: i64,
}

#[derive(Debug, Deserialize)]
pub struct PolicyPullRequest {
    pub tenant_id: String,
    pub agent_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AssignRuleRequest {
    pub rule_id: String,
    pub priority_override: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub database: bool,
}

fn server_error(status: StatusCode, msg: String) -> Response {
    (status, msg).into_response()
}

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let db_healthy = if let Some(repo) = &state.db_repo {
        repo.health_check().await.unwrap_or(false)
    } else {
        false
    };
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "healthy",
            version: env!("CARGO_PKG_VERSION"),
            database: db_healthy,
        }),
    )
}

pub async fn token_issue(
    State(state): State<AppState>,
    Json(req): Json<TokenIssueRequest>,
) -> Response {
    match state.token_engine.issue_token(
        &req.tool,
        &req.args_hash,
        &req.session_id,
        &req.tenant_id,
        &req.agent_id,
        &req.decision,
        req.risk_score,
    ) {
        Ok(token) => (
            StatusCode::OK,
            Json(TokenIssueResponse {
                token,
                expires_in_secs: 60,
            }),
        )
            .into_response(),
        Err(e) => server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn token_verify(State(state): State<AppState>, body: String) -> Response {
    match state.token_engine.verify_token(&body) {
        Ok(claims) => (StatusCode::OK, Json(claims)).into_response(),
        Err(e) => server_error(StatusCode::UNAUTHORIZED, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRevokeRequest {
    pub jti: String,
}

pub async fn token_revoke(
    State(state): State<AppState>,
    Json(req): Json<TokenRevokeRequest>,
) -> Response {
    state.token_engine.revoke_token(&req.jti);

    if let Some(repo) = &state.db_repo {
        if let Err(e) = repo.persist_revocation(&req.jti).await {
            tracing::error!(error = %e, jti = %req.jti, "Failed to persist revocation");
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"revoked": req.jti})),
    )
        .into_response()
}

pub async fn policy_pull(
    State(state): State<AppState>,
    Json(req): Json<PolicyPullRequest>,
) -> Response {
    let agent = match state.agent_manager.get_agent(&req.agent_id) {
        Ok(a) => a,
        Err(_) => {
            return server_error(
                StatusCode::NOT_FOUND,
                format!("agent not found: {}", req.agent_id),
            )
        }
    };

    let agent_rules = state
        .agent_manager
        .get_rules_for_agent(&req.agent_id)
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();

    let global_rules = state
        .agent_manager
        .get_tenant_global_rules(&req.tenant_id)
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();

    let tool_allowlist: std::collections::HashMap<String, serde_json::Value> = agent
        .tool_allowlist
        .into_iter()
        .map(|(k, v)| (k, serde_json::to_value(v).unwrap_or_default()))
        .collect();

    let blob = PolicyBlob {
        agent_id: req.agent_id.clone(),
        tenant_id: req.tenant_id,
        agent_rules,
        global_rules,
        tool_allowlist,
        risk_threshold: agent.risk_threshold,
        version: 0,
        timestamp: chrono::Utc::now().timestamp(),
    };

    match state.policy_engine.compile_and_sign(blob) {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn audit_batch(State(state): State<AppState>, body: String) -> Response {
    crate::metrics::REQUESTS_TOTAL.inc();
    tracing::info!(len = body.len(), "Audit batch received");

    if let Some(pool) = &state.db_pool {
        match sqlx::query(
            "INSERT INTO events (id, event_type, source, data, session_id, timestamp) \
             VALUES ($1, $2, $3, $4, $5, NOW())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("audit_batch")
        .bind("sdk")
        .bind(&body)
        .bind("batch")
        .execute(pool.as_ref())
        .await
        {
            Ok(_) => tracing::debug!("Audit batch persisted to legacy events"),
            Err(e) => tracing::error!(error = %e, "Failed to persist audit batch to legacy events"),
        }
    }

    if let Some(repo) = &state.db_repo {
        if let Ok(events) = serde_json::from_str::<Vec<crate::db::CpAuditEventInsert>>(&body) {
            if let Err(e) = repo.insert_audit_event_batch(&events).await {
                tracing::error!(error = %e, "Failed to persist structured audit events");
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

pub async fn bypass_report(
    State(state): State<AppState>,
    Json(alert): Json<crate::analyst::BypassAlert>,
) -> Response {
    crate::metrics::BYPASS_ALERTS.inc();
    tracing::warn!(
        tenant_id = %alert.tenant_id,
        agent_id = %alert.agent_id,
        tool = %alert.tool_name,
        reason = %alert.reason,
        "Bypass report received"
    );

    if let Some(repo) = &state.db_repo {
        if let Err(e) = repo.persist_bypass_alert(&alert).await {
            tracing::error!(error = %e, "Failed to persist bypass alert");
        }
    }

    state.bypass_detector.record(alert);
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

pub async fn sdk_heartbeat(body: String) -> Response {
    tracing::debug!(len = body.len(), "SDK heartbeat received");
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SessionStateRequest {
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
}

#[derive(Debug, Serialize)]
pub struct ToolCallSummary {
    pub tool_name: String,
    pub decision: String,
    pub risk_score: f32,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct SessionStateResponse {
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub cumulative_risk: f32,
    pub total_calls: u64,
    pub block_count: u64,
    pub recent_tool_calls: Vec<ToolCallSummary>,
    pub hydrated: bool,
}

pub async fn session_state(
    State(state): State<AppState>,
    Json(req): Json<SessionStateRequest>,
) -> Response {
    tracing::info!(
        session_id = %req.session_id,
        tenant_id = %req.tenant_id,
        agent_id = %req.agent_id,
        "Session state request"
    );

    let events = if let Some(repo) = &state.db_repo {
        match repo.query_session_events(&req.session_id, &req.tenant_id, &req.agent_id, 100).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "Failed to query session events");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    if events.is_empty() {
        return (StatusCode::OK, Json(SessionStateResponse {
            session_id: req.session_id,
            tenant_id: req.tenant_id,
            agent_id: req.agent_id,
            cumulative_risk: 0.0,
            total_calls: 0,
            block_count: 0,
            recent_tool_calls: Vec::new(),
            hydrated: false,
        })).into_response();
    }

    let total_calls = events.len() as u64;
    let block_count = events.iter().filter(|e| e.decision == "Block").count() as u64;
    let recent: Vec<ToolCallSummary> = events.iter().rev().take(10).map(|e| ToolCallSummary {
        tool_name: e.tool_name.clone(),
        decision: e.decision.clone(),
        risk_score: e.risk_score,
        timestamp: e.timestamp.to_rfc3339(),
    }).collect();

    let cumulative_risk = {
        let mut risk: f32 = 0.0;
        for e in &events {
            risk += e.risk_score;
            if risk > 1.0 { risk = 1.0; }
        }
        risk
    };

    (StatusCode::OK, Json(SessionStateResponse {
        session_id: req.session_id,
        tenant_id: req.tenant_id,
        agent_id: req.agent_id,
        cumulative_risk,
        total_calls,
        block_count,
        recent_tool_calls: recent,
        hydrated: true,
    })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct EscalationRequest {
    pub session_id: Option<String>,
    pub tenant_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub decision: String,
    pub risk_score: f32,
    pub reason: String,
    pub cumulative_risk: f32,
}

#[derive(Debug, Serialize)]
pub struct EscalationResponse {
    pub escalation_id: String,
    pub status: String,
    pub ai_insights: Option<String>,
}

pub async fn escalate(
    State(state): State<AppState>,
    Json(req): Json<EscalationRequest>,
) -> Response {
    tracing::warn!(
        tenant_id = %req.tenant_id,
        agent_id = %req.agent_id,
        decision = %req.decision,
        risk_score = req.risk_score,
        cumulative_risk = req.cumulative_risk,
        "Escalation received"
    );

    let escalation_id = uuid::Uuid::new_v4().to_string();

    let insert = crate::db::EscalationInsert {
        tenant_id: req.tenant_id.clone(),
        agent_id: req.agent_id.clone(),
        session_id: req.session_id.clone(),
        tool_name: req.tool_name.clone(),
        decision: req.decision.clone(),
        risk_score: req.risk_score,
        cumulative_risk: req.cumulative_risk,
        reason: req.reason.clone(),
        ai_insights: None,
        status: "escalated_no_ai".to_string(),
    };

    if let Some(repo) = &state.db_repo {
        match repo.insert_escalation(&insert).await {
            Ok(_) => tracing::info!(escalation_id = %escalation_id, "Escalation persisted"),
            Err(e) => tracing::error!(error = %e, "Failed to persist escalation"),
        }
    }

    (StatusCode::OK, Json(EscalationResponse {
        escalation_id,
        status: "escalated_no_ai".to_string(),
        ai_insights: None,
    })).into_response()
}

pub async fn list_rules(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let rules = state.agent_manager.list_rules_by_tenant(&tenant_id);
    (StatusCode::OK, Json(rules)).into_response()
}

pub async fn create_rule(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(rule): Json<RuleEntry>,
) -> Response {
    match state.agent_manager.create_rule(rule.clone(), &tenant_id).await {
        Ok(()) => (StatusCode::OK, Json(rule)).into_response(),
        Err(e) => server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn update_rule(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
    Json(rule): Json<RuleEntry>,
) -> Response {
    match state.agent_manager.update_rule(&id, &tenant_id, rule).await {
        Ok(updated) => (StatusCode::OK, Json(updated)).into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    match state.agent_manager.delete_rule(&id, &tenant_id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response(),
        Ok(false) => server_error(StatusCode::NOT_FOUND, format!("rule not found: {}", id)),
        Err(e) => server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn list_agents(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let agents = state.agent_manager.list_agents_by_tenant(&tenant_id);
    (StatusCode::OK, Json(agents)).into_response()
}

pub async fn create_agent(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(agent): Json<Agent>,
) -> Response {
    match state.agent_manager.create_agent(agent.clone(), &tenant_id).await {
        Ok(()) => (StatusCode::OK, Json(agent)).into_response(),
        Err(e) => server_error(StatusCode::CONFLICT, e.to_string()),
    }
}

pub async fn get_agent(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    match state.agent_manager.get_agent_for_tenant(&id, &tenant_id) {
        Ok(agent) => (StatusCode::OK, Json(agent)).into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn update_agent(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
    Json(agent): Json<Agent>,
) -> Response {
    match state.agent_manager.update_agent(&id, &tenant_id, agent).await {
        Ok(updated) => (StatusCode::OK, Json(updated)).into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn delete_agent(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    match state.agent_manager.delete_agent(&id, &tenant_id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn list_agent_rules(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    match state.agent_manager.list_agent_rules(&id, &tenant_id) {
        Ok(rules) => (StatusCode::OK, Json(rules)).into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn assign_agent_rule(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
    Json(req): Json<AssignRuleRequest>,
) -> Response {
    match state
        .agent_manager
        .assign_rule(&id, &req.rule_id, &tenant_id, req.priority_override)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"assigned": req.rule_id})),
        )
            .into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn unassign_agent_rule(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path((id, rule_id)): Path<(String, String)>,
) -> Response {
    match state.agent_manager.unassign_rule(&id, &rule_id, &tenant_id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"unassigned": rule_id})),
        )
            .into_response(),
        Err(e) => server_error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn list_bypass_alerts(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let alerts = state.bypass_detector.list_alerts_by_tenant(&tenant_id);
    (StatusCode::OK, Json(alerts)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub agent_id: Option<String>,
    pub permissions: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct KeyItem {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub status: String,
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub rotated_from_id: Option<String>,
    pub rotated_to_id: Option<String>,
    pub grace_period_ends_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub grace_period_hours: Option<i64>,
    pub revoke_old_immediately: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub aggregate: AnalyticsAggregate,
    pub per_agent: Vec<AgentAnalytics>,
    pub cache_hit_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsAggregate {
    pub total_calls: i64,
    pub allow_count: i64,
    pub block_count: i64,
    pub flag_count: i64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct AgentAnalytics {
    pub agent_id: String,
    pub name: String,
    pub total_calls: i64,
    pub allow_count: i64,
    pub block_count: i64,
    pub flag_count: i64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub agent_id: Option<String>,
    pub action: Option<String>,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditListResponse {
    pub events: Vec<AuditEventRow>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionRow>,
}

#[derive(Debug, Serialize)]
pub struct TenantSettingsResponse {
    pub tenant_id: String,
    pub webhook_url: Option<String>,
    pub webhook_enabled: bool,
    pub webhook_secret: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub webhook_url: Option<String>,
    pub webhook_enabled: Option<bool>,
    pub webhook_secret: Option<String>,
}

pub async fn list_keys(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    match repo.list_api_keys(&tenant_id).await {
        Ok(rows) => {
            let keys: Vec<KeyItem> = rows
                .into_iter()
                .map(|r| KeyItem {
                    id: r.id,
                    name: r.name,
                    key_prefix: r.key_prefix,
                    permissions: r.permissions,
                    status: r.status,
                    agent_id: r.agent_id,
                    agent_name: r.agent_name,
                    rotated_from_id: r.rotated_from_id,
                    rotated_to_id: r.rotated_to_id,
                    grace_period_ends_at: r.grace_period_ends_at,
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                    last_used_at: r.last_used_at,
                    revoked_at: r.revoked_at,
                })
                .collect();
            (StatusCode::OK, Json(keys)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list API keys");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

pub async fn create_key(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(req): Json<CreateKeyRequest>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    let (full_key, key_hash, key_prefix) = crate::utils::generate_api_key();
    match repo
        .create_api_key(
            &tenant_id,
            req.agent_id.as_deref(),
            &req.name,
            &key_hash,
            &key_prefix,
            &req.permissions,
            req.expires_at,
        )
        .await
    {
        Ok(row) => {
            let resp = CreateKeyResponse {
                id: row.id,
                name: row.name,
                key: full_key,
                key_prefix: row.key_prefix,
                permissions: row.permissions,
                created_at: row.created_at,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to create API key");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

pub async fn rotate_key(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
    Json(req): Json<RotateKeyRequest>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };

    let old_key = match repo.get_api_key(&id).await {
        Ok(Some(k)) if k.tenant_id == tenant_id => k,
        Ok(_) => return server_error(StatusCode::NOT_FOUND, "API key not found".into()),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get API key");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    let (full_key, key_hash, key_prefix) = crate::utils::generate_api_key();
    let new_row = match repo
        .create_api_key(
            &tenant_id,
            old_key.agent_id.as_deref(),
            &old_key.name,
            &key_hash,
            &key_prefix,
            &old_key.permissions,
            old_key.expires_at,
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create rotated API key");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    if let Err(e) = repo.link_rotated_key(&id, &new_row.id).await {
        tracing::error!(error = %e, "Failed to link rotated key");
        return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    let now = chrono::Utc::now();
    let revoke_old = req.revoke_old_immediately.unwrap_or(false);
    let grace = if revoke_old {
        (None, Some(now))
    } else {
        let hours = req.grace_period_hours.unwrap_or(24);
        (Some(now + chrono::Duration::hours(hours)), None)
    };

    let status = if revoke_old { "revoked" } else { "rotated" };
    if let Err(e) = repo
        .update_api_key_status(&id, status, Some(&new_row.id), grace.0, grace.1)
        .await
    {
        tracing::error!(error = %e, "Failed to update old key status");
        return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    let resp = serde_json::json!({
        "id": new_row.id,
        "key": full_key,
        "rotated_from": id,
    });
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn revoke_key(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    match repo.get_api_key(&id).await {
        Ok(Some(k)) if k.tenant_id == tenant_id => {}
        Ok(_) => return server_error(StatusCode::NOT_FOUND, "API key not found".into()),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get API key");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };
    let now = chrono::Utc::now();
    if let Err(e) = repo.update_api_key_status(&id, "revoked", None, None, Some(now)).await {
        tracing::error!(error = %e, "Failed to revoke API key");
        return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"revoked": id})),
    )
        .into_response()
}

pub async fn delete_key(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    match repo.get_api_key(&id).await {
        Ok(Some(k)) if k.tenant_id == tenant_id => {}
        Ok(_) => return server_error(StatusCode::NOT_FOUND, "API key not found".into()),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get API key");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };
    if let Err(e) = repo.delete_api_key(&id).await {
        tracing::error!(error = %e, "Failed to delete API key");
        return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"deleted": id})),
    )
        .into_response()
}

pub async fn analytics(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    let agg = match repo.get_analytics_aggregate(&tenant_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "Failed to get analytics aggregate");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };
    let per_agent = match repo.get_analytics_per_agent(&tenant_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "Failed to get per-agent analytics");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    let cache_hit_rate = 0.95; // Mock

    let resp = AnalyticsResponse {
        aggregate: AnalyticsAggregate {
            total_calls: agg.total_calls.unwrap_or(0),
            allow_count: agg.allow_count.unwrap_or(0),
            block_count: agg.block_count.unwrap_or(0),
            flag_count: agg.flag_count.unwrap_or(0),
            avg_latency_ms: agg.avg_latency_ms.unwrap_or(0.0),
        },
        per_agent: per_agent
            .into_iter()
            .map(|a| AgentAnalytics {
                agent_id: a.agent_id,
                name: a.name.unwrap_or_default(),
                total_calls: a.total_calls.unwrap_or(0),
                allow_count: a.allow_count.unwrap_or(0),
                block_count: a.block_count.unwrap_or(0),
                flag_count: a.flag_count.unwrap_or(0),
                avg_latency_ms: a.avg_latency_ms.unwrap_or(0.0),
            })
            .collect(),
        cache_hit_rate,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn list_audit(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).max(1).min(100);
    let offset = (page - 1) * page_size;

    let (events, total) = match tokio::try_join!(
        repo.list_audit_events(
            &tenant_id,
            q.agent_id.as_deref(),
            q.action.as_deref(),
            q.from,
            q.to,
            q.search.as_deref(),
            page_size,
            offset
        ),
        repo.count_audit_events(
            &tenant_id,
            q.agent_id.as_deref(),
            q.action.as_deref(),
            q.from,
            q.to,
            q.search.as_deref()
        )
    ) {
        Ok((e, t)) => (e, t),
        Err(e) => {
            tracing::error!(error = %e, "Failed to list audit events");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    let resp = AuditListResponse {
        events,
        total,
        page,
        page_size,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn export_audit(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };

    let events = match repo
        .list_audit_events(
            &tenant_id,
            q.agent_id.as_deref(),
            q.action.as_deref(),
            q.from,
            q.to,
            q.search.as_deref(),
            10000,
            0,
        )
        .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "Failed to export audit events");
            return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    let mut csv = String::from(
        "id,tenant_id,event_type,source,session_id,decision_type,confidence,processing_time_ms,timestamp\n",
    );
    for e in events {
        let line = format!(
            "{},{},{},{},{},{},{},{},{}\n",
            e.id,
            e.tenant_id,
            e.event_type,
            e.source,
            e.session_id.as_deref().unwrap_or(""),
            e.decision_type.as_deref().unwrap_or(""),
            e.confidence.map(|v| v.to_string()).unwrap_or_default(),
            e.processing_time_ms.map(|v| v.to_string()).unwrap_or_default(),
            e.timestamp.to_rfc3339()
        );
        csv.push_str(&line);
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/csv")],
        csv,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct HistogramQuery {
    pub range: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HistogramResponse {
    pub buckets: Vec<crate::db::EventHistogramRow>,
    pub total_events: i64,
    pub time_range: serde_json::Value,
    pub bucket_size: String,
}

pub async fn list_audit_histogram(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Query(q): Query<HistogramQuery>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    let now = chrono::Utc::now();
    let (from, bucket_minutes) = match q.range.as_deref() {
        Some("15m") => (now - chrono::Duration::minutes(15), 1),
        Some("30m") => (now - chrono::Duration::minutes(30), 1),
        Some("6h") => (now - chrono::Duration::hours(6), 5),
        Some("24h") => (now - chrono::Duration::hours(24), 15),
        Some("7d") => (now - chrono::Duration::days(7), 60),
        _ => (now - chrono::Duration::hours(1), 1),
    };
    match repo.get_event_histogram(&tenant_id, from, now, bucket_minutes).await {
        Ok(buckets) => {
            let total_events = buckets.iter().map(|b| b.total.unwrap_or(0)).sum();
            let resp = HistogramResponse {
                buckets,
                total_events,
                time_range: serde_json::json!({"from": from.to_rfc3339(), "to": now.to_rfc3339()}),
                bucket_size: format!("{}m", bucket_minutes),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get event histogram");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

pub async fn list_sessions(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    match repo.list_sessions(&tenant_id).await {
        Ok(rows) => (
            StatusCode::OK,
            Json(SessionListResponse { sessions: rows }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to list sessions");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

pub async fn session_timeline(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Path(id): Path<String>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    match repo.get_session_timeline(&tenant_id, &id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, session_id = %id, "Failed to get session timeline");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

pub async fn get_settings(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    match repo.get_tenant_settings(&tenant_id).await {
        Ok(Some(row)) => {
            let resp = TenantSettingsResponse {
                tenant_id: row.tenant_id,
                webhook_url: row.webhook_url,
                webhook_enabled: row.webhook_enabled,
                webhook_secret: row.webhook_secret,
                updated_at: row.updated_at,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Ok(None) => {
            let resp = TenantSettingsResponse {
                tenant_id: tenant_id.clone(),
                webhook_url: None,
                webhook_enabled: false,
                webhook_secret: None,
                updated_at: chrono::Utc::now(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get tenant settings");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

pub async fn update_settings(
    State(state): State<AppState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Response {
    let Some(repo) = &state.db_repo else {
        return server_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable".into());
    };
    let webhook_enabled = req.webhook_enabled.unwrap_or(false);
    if let Err(e) = repo
        .upsert_tenant_settings(
            &tenant_id,
            req.webhook_url.as_deref(),
            webhook_enabled,
            req.webhook_secret.as_deref(),
        )
        .await
    {
        tracing::error!(error = %e, "Failed to upsert tenant settings");
        return server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    match repo.get_tenant_settings(&tenant_id).await {
        Ok(Some(row)) => {
            let resp = TenantSettingsResponse {
                tenant_id: row.tenant_id,
                webhook_url: row.webhook_url,
                webhook_enabled: row.webhook_enabled,
                webhook_secret: row.webhook_secret,
                updated_at: row.updated_at,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Ok(None) => server_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Settings not found after update".into(),
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get tenant settings after update");
            server_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}
