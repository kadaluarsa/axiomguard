use crate::agent::AgentManager;
use crate::analyst::BypassDetector;
use crate::auth::AuthState;
use crate::db::CpRepository;
use crate::policy::PolicyEngine;
use crate::token::TokenEngine;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AppState {
    pub auth: Arc<AuthState>,
    pub token_engine: Arc<TokenEngine>,
    pub policy_engine: Arc<PolicyEngine>,
    pub agent_manager: Arc<AgentManager>,
    pub bypass_detector: Arc<BypassDetector>,
    pub encryption_key: [u8; 32],
    pub db_pool: Option<Arc<sqlx::postgres::PgPool>>,
    pub db_repo: Option<Arc<CpRepository>>,
}
