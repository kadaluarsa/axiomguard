mod agent;
mod analyst;
mod api;
mod auth;
mod config;
mod db;
mod metrics;
mod policy;
mod rate_limit;
mod state;
mod token;
mod utils;

use axum::{
    Router,
    routing::{delete, get, post, put},
    middleware,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("axiomguard_cp=info".parse()?))
        .init();

    let config = config::CpConfig::from_env();
    tracing::info!(
        address = %config.bind_address,
        require_auth = config.require_auth,
        "Starting AxiomGuard Control Plane"
    );

    let auth_state = Arc::new(auth::AuthState::new(
        config.api_keys.clone(),
        config.admin_keys.clone(),
        config.require_auth,
    ));

    let token_engine = Arc::new(token::TokenEngine::new(config.signing_key_seed));
    let policy_engine = Arc::new(policy::PolicyEngine::new(config.signing_key_seed, config.encryption_key));
    let bypass_detector = Arc::new(analyst::BypassDetector::new());

    let (db_pool, db_repo, agent_manager) = match init_db(&config.database_url).await {
        Ok(pool) => {
            let pool_arc = Arc::new(pool);
            let repo = Arc::new(db::CpRepository::new(pool_arc.clone()));
            let mgr = Arc::new(agent::AgentManager::with_pool(pool_arc.clone()));
            tracing::info!("Database connected, loading data");
            if let Err(e) = mgr.load_from_db().await {
                tracing::error!(error = %e, "Failed to load from database, continuing with empty state");
            }
            (Some(pool_arc), Some(repo), mgr)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Database unavailable, running in memory-only mode"
            );
            (None, None, Arc::new(agent::AgentManager::new()))
        }
    };

    let app_state = state::AppState {
        auth: auth_state.clone(),
        token_engine,
        policy_engine,
        agent_manager,
        bypass_detector,
        encryption_key: config.encryption_key,
        db_pool,
        db_repo,
    };

    let rate_limiter = Arc::new(rate_limit::RateLimiter::new(
        rate_limit::RateLimitConfig {
            max_requests: 1000,
            window_secs: 60,
        },
    ));

    let admin_rate_limiter = Arc::new(rate_limit::RateLimiter::new(
        rate_limit::RateLimitConfig {
            max_requests: 100,
            window_secs: 60,
        },
    ));

    let sdk_routes = Router::new()
        .route("/v1/token/issue", post(api::token_issue))
        .route("/v1/token/verify", post(api::token_verify))
        .route("/v1/token/revoke", post(api::token_revoke))
        .route("/v1/policy/pull", post(api::policy_pull))
        .route("/v1/audit/batch", post(api::audit_batch))
        .route("/v1/session/state", post(api::session_state))
        .route("/v1/escalate", post(api::escalate))
        .route("/v1/bypass/report", post(api::bypass_report))
        .route("/v1/sdk/heartbeat", post(api::sdk_heartbeat))
        .route("/v1/health", get(api::health))
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            rate_limit::rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(auth_state.clone(), auth::auth_middleware));

    let admin_routes = Router::new()
        .route("/admin/rules", get(api::list_rules).post(api::create_rule))
        .route("/admin/rules/{id}", put(api::update_rule).delete(api::delete_rule))
        .route("/admin/agents", get(api::list_agents).post(api::create_agent))
        .route("/admin/agents/{id}", get(api::get_agent).put(api::update_agent).delete(api::delete_agent))
        .route("/admin/agents/{id}/rules", get(api::list_agent_rules).post(api::assign_agent_rule))
        .route("/admin/agents/{id}/rules/{rule_id}", delete(api::unassign_agent_rule))
        .route("/admin/bypass-alerts", get(api::list_bypass_alerts))
        .route("/admin/keys", get(api::list_keys).post(api::create_key))
        .route("/admin/keys/{id}/rotate", post(api::rotate_key))
        .route("/admin/keys/{id}/revoke", post(api::revoke_key))
        .route("/admin/keys/{id}", delete(api::delete_key))
        .route("/admin/analytics", get(api::analytics))
        .route("/admin/audit", get(api::list_audit))
        .route("/admin/audit/export", get(api::export_audit))
        .route("/admin/audit/histogram", get(api::list_audit_histogram))
        .route("/admin/sessions", get(api::list_sessions))
        .route("/admin/sessions/{id}/timeline", get(api::session_timeline))
        .route("/admin/settings", get(api::get_settings).put(api::update_settings))
        .layer(middleware::from_fn_with_state(
            admin_rate_limiter,
            rate_limit::rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(auth_state.clone(), auth::admin_auth_middleware));

    let app = Router::new()
        .merge(sdk_routes)
        .merge(admin_routes)
        .route("/metrics", get(|| async { metrics::metrics_handler() }))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    tracing::info!("Control Plane listening on {}", config.bind_address);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn init_db(database_url: &str) -> Result<sqlx::postgres::PgPool, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;

    db::run_cp_migrations(&pool).await?;
    tracing::info!("CP database migrations applied");

    Ok(pool)
}
