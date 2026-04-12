use sqlx::SqlitePool;
use uuid::Uuid;
use chrono::Utc;
use crate::database::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub email: String,
    pub api_key: String,
    pub status: String,
    pub quota_events: i64,
    pub quota_agents: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: i32,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRule {
    pub id: String,
    pub agent_id: String,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub priority: i32,
    pub action: String,
    pub configuration: serde_json::Value,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub id: String,
    pub agent_id: String,
    pub session_context: Option<serde_json::Value>,
    pub expires_at: Option<i64>,
    pub last_activity_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct TenantRepository {
    pool: SqlitePool,
}

impl TenantRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Tenants
    pub async fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        sqlx::query!(
            "INSERT INTO tenants (id, name, display_name, email, api_key, status, quota_events, quota_agents, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            tenant.id, tenant.name, tenant.display_name, tenant.email, tenant.api_key, tenant.status, 
            tenant.quota_events, tenant.quota_agents, tenant.created_at, tenant.updated_at
        ).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_tenant_by_api_key(&self, api_key: &str) -> Result<Option<Tenant>> {
        let tenant = sqlx::query_as!(
            Tenant,
            "SELECT * FROM tenants WHERE api_key = ? AND status = 'active'",
            api_key
        ).fetch_optional(&self.pool).await?;
        Ok(tenant)
    }

    // Agents
    pub async fn create_agent(&self, agent: &Agent) -> Result<()> {
        sqlx::query!(
            "INSERT INTO agents (id, tenant_id, name, description, model, temperature, max_tokens, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            agent.id, agent.tenant_id, agent.name, agent.description, agent.model,
            agent.temperature, agent.max_tokens, agent.status, agent.created_at, agent.updated_at
        ).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_agents_by_tenant(&self, tenant_id: &str) -> Result<Vec<Agent>> {
        let agents = sqlx::query_as!(
            Agent,
            "SELECT * FROM agents WHERE tenant_id = ? AND status = 'active'",
            tenant_id
        ).fetch_all(&self.pool).await?;
        Ok(agents)
    }

    // Rules
    pub async fn create_rule(&self, rule: &AgentRule) -> Result<()> {
        sqlx::query!(
            "INSERT INTO agent_rules (id, agent_id, name, description, rule_type, priority, action, configuration, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rule.id, rule.agent_id, rule.name, rule.description, rule.rule_type,
            rule.priority, rule.action, rule.configuration, rule.enabled, rule.created_at, rule.updated_at
        ).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_rules_by_agent(&self, agent_id: &str) -> Result<Vec<AgentRule>> {
        let rules = sqlx::query_as!(
            AgentRule,
            "SELECT * FROM agent_rules WHERE agent_id = ? AND enabled = 1 ORDER BY priority ASC",
            agent_id
        ).fetch_all(&self.pool).await?;
        Ok(rules)
    }

    // Sessions
    pub async fn create_session(&self, session: &AgentSession) -> Result<()> {
        sqlx::query!(
            "INSERT INTO agent_sessions (id, agent_id, session_context, expires_at, last_activity_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            session.id, session.agent_id, session.session_context,
            session.expires_at, session.last_activity_at, session.created_at, session.updated_at
        ).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_session_activity(&self, session_id: &str) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query!(
            "UPDATE agent_sessions SET last_activity_at = ?, updated_at = ? WHERE id = ?",
            now, now, session_id
        ).execute(&self.pool).await?;
        Ok(())
    }
}
