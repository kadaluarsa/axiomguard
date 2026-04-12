use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub tool_allowlist: HashMap<String, ToolPermission>,
    pub risk_threshold: f32,
    pub quota_max_daily: u32,
    pub quota_max_burst: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolPermission {
    Allow,
    Deny,
    Restrict { allowed_args: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuleBinding {
    pub agent_id: String,
    pub rule_id: String,
    pub priority_override: Option<i32>,
}

#[derive(Debug)]
pub struct AgentManager {
    agents: DashMap<String, Agent>,
    rule_bindings: DashMap<String, Vec<AgentRuleBinding>>,
    bound_rule_ids: RwLock<HashSet<String>>,
    rules: DashMap<String, RuleEntry>,
    pool: Option<Arc<PgPool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub logic: serde_json::Value,
    pub decision: String,
    pub priority: i32,
    pub is_active: bool,
    pub version: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent not found: {0}")]
    NotFound(String),
    #[error("agent already exists: {0}")]
    AlreadyExists(String),
    #[error("rule not found: {0}")]
    RuleNotFound(String),
    #[error("database error: {0}")]
    Database(String),
}

impl AgentManager {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            rule_bindings: DashMap::new(),
            bound_rule_ids: RwLock::new(HashSet::new()),
            rules: DashMap::new(),
            pool: None,
        }
    }

    pub fn with_pool(pool: Arc<PgPool>) -> Self {
        Self {
            agents: DashMap::new(),
            rule_bindings: DashMap::new(),
            bound_rule_ids: RwLock::new(HashSet::new()),
            rules: DashMap::new(),
            pool: Some(pool),
        }
    }

    pub async fn load_from_db(&self) -> Result<(), AgentError> {
        let pool = match &self.pool {
            Some(p) => p,
            None => return Ok(()),
        };

        let agent_rows = sqlx::query_as::<_, AgentRow>(
            "SELECT id, tenant_id, name, tool_allowlist, risk_threshold, \
             quota_max_daily, quota_max_burst, created_at, updated_at \
             FROM cp_agents WHERE deleted_at IS NULL",
        )
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| AgentError::Database(e.to_string()))?;

        for row in agent_rows {
            let allowlist: HashMap<String, ToolPermission> =
                serde_json::from_value(row.tool_allowlist).unwrap_or_default();
            let agent = Agent {
                id: row.id,
                tenant_id: row.tenant_id,
                name: row.name,
                tool_allowlist: allowlist,
                risk_threshold: row.risk_threshold,
                quota_max_daily: row.quota_max_daily as u32,
                quota_max_burst: row.quota_max_burst as u32,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };
            self.agents.insert(agent.id.clone(), agent);
        }

        let rule_rows = sqlx::query_as::<_, RuleRow>(
            "SELECT id, tenant_id, name, description, logic, decision, \
             priority, is_active, version FROM cp_rules WHERE deleted_at IS NULL",
        )
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| AgentError::Database(e.to_string()))?;

        for row in rule_rows {
            let rule = RuleEntry {
                id: row.id,
                tenant_id: row.tenant_id,
                name: row.name,
                description: row.description,
                logic: row.logic,
                decision: row.decision,
                priority: row.priority,
                is_active: row.is_active,
                version: row.version,
            };
            self.rules.insert(rule.id.clone(), rule);
        }

        let binding_rows = sqlx::query_as::<_, BindingRow>(
            "SELECT agent_id, rule_id, priority_override FROM cp_agent_rule_bindings",
        )
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| AgentError::Database(e.to_string()))?;

        let mut bound_ids = self.bound_rule_ids.write().unwrap();
        for row in binding_rows {
            bound_ids.insert(row.rule_id.clone());
            self.rule_bindings
                .entry(row.agent_id.clone())
                .or_insert_with(Vec::new)
                .push(AgentRuleBinding {
                    agent_id: row.agent_id,
                    rule_id: row.rule_id,
                    priority_override: row.priority_override,
                });
        }

        Ok(())
    }

    pub async fn create_agent(&self, mut agent: Agent, tenant_id: &str) -> Result<(), AgentError> {
        agent.tenant_id = tenant_id.to_string();
        use dashmap::mapref::entry::Entry;

        match self.agents.entry(agent.id.clone()) {
            Entry::Occupied(_) => return Err(AgentError::AlreadyExists(agent.id.clone())),
            Entry::Vacant(vacant) => {
                if let Some(pool) = &self.pool {
                    let allowlist_json = serde_json::to_value(&agent.tool_allowlist)
                        .unwrap_or(serde_json::json!({}));
                    sqlx::query(
                        "INSERT INTO cp_agents (id, tenant_id, name, tool_allowlist, risk_threshold, \
                         quota_max_daily, quota_max_burst, created_at, updated_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    )
                    .bind(&agent.id)
                    .bind(&agent.tenant_id)
                    .bind(&agent.name)
                    .bind(allowlist_json)
                    .bind(agent.risk_threshold)
                    .bind(agent.quota_max_daily as i32)
                    .bind(agent.quota_max_burst as i32)
                    .bind(agent.created_at)
                    .bind(agent.updated_at)
                    .execute(pool.as_ref())
                    .await
                    .map_err(|e| AgentError::Database(e.to_string()))?;
                }
                vacant.insert(agent);
                Ok(())
            }
        }
    }

    pub fn get_agent(&self, id: &str) -> Result<Agent, AgentError> {
        self.agents
            .get(id)
            .map(|v| v.value().clone())
            .ok_or_else(|| AgentError::NotFound(id.to_string()))
    }

    pub fn get_agent_for_tenant(&self, id: &str, tenant_id: &str) -> Result<Agent, AgentError> {
        self.verify_agent_tenant(id, tenant_id)
    }

    pub fn list_agents(&self) -> Vec<Agent> {
        self.agents.iter().map(|r| r.value().clone()).collect()
    }

    pub fn list_agents_by_tenant(&self, tenant_id: &str) -> Vec<Agent> {
        self.agents
            .iter()
            .filter(|a| a.value().tenant_id == tenant_id)
            .map(|a| a.value().clone())
            .collect()
    }

    fn verify_agent_tenant(&self, id: &str, tenant_id: &str) -> Result<Agent, AgentError> {
        let agent = self.get_agent(id)?;
        if agent.tenant_id != tenant_id {
            return Err(AgentError::NotFound(id.to_string()));
        }
        Ok(agent)
    }

    fn verify_rule_tenant(&self, id: &str, tenant_id: &str) -> Result<RuleEntry, AgentError> {
        let rule = self.get_rule(id).ok_or_else(|| AgentError::RuleNotFound(id.to_string()))?;
        if rule.tenant_id != tenant_id {
            return Err(AgentError::RuleNotFound(id.to_string()));
        }
        Ok(rule)
    }

    pub async fn update_agent(&self, id: &str, tenant_id: &str, mut update: Agent) -> Result<Agent, AgentError> {
        self.verify_agent_tenant(id, tenant_id)?;
        update.tenant_id = tenant_id.to_string();
        let updated = Agent {
            updated_at: chrono::Utc::now(),
            ..update
        };

        if let Some(pool) = &self.pool {
            let allowlist_json = serde_json::to_value(&updated.tool_allowlist)
                .unwrap_or(serde_json::json!({}));
            let result = sqlx::query(
                "UPDATE cp_agents SET name=$2, tool_allowlist=$3, risk_threshold=$4, \
                 quota_max_daily=$5, quota_max_burst=$6, updated_at=$7 \
                 WHERE id=$1 AND deleted_at IS NULL",
            )
            .bind(id)
            .bind(&updated.name)
            .bind(allowlist_json)
            .bind(updated.risk_threshold)
            .bind(updated.quota_max_daily as i32)
            .bind(updated.quota_max_burst as i32)
            .bind(updated.updated_at)
            .execute(pool.as_ref())
            .await
            .map_err(|e| AgentError::Database(e.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(AgentError::NotFound(id.to_string()));
            }
        }

        let mut entry = self
            .agents
            .get_mut(id)
            .ok_or_else(|| AgentError::NotFound(id.to_string()))?;
        *entry.value_mut() = updated.clone();
        Ok(updated)
    }

    pub async fn delete_agent(&self, id: &str, tenant_id: &str) -> Result<(), AgentError> {
        self.verify_agent_tenant(id, tenant_id)?;

        if let Some(pool) = &self.pool {
            sqlx::query("UPDATE cp_agents SET deleted_at=NOW() WHERE id=$1")
                .bind(id)
                .execute(pool.as_ref())
                .await
                .map_err(|e| AgentError::Database(e.to_string()))?;
            sqlx::query("DELETE FROM cp_agent_rule_bindings WHERE agent_id=$1")
                .bind(id)
                .execute(pool.as_ref())
                .await
                .map_err(|e| AgentError::Database(e.to_string()))?;
        }

        if let Some((_, bindings)) = self.rule_bindings.remove(id) {
            let mut bound_ids = self.bound_rule_ids.write().unwrap();
            for b in &bindings {
                let still_bound = self.rule_bindings.iter().any(|entry| {
                    entry.value().iter().any(|binding| binding.rule_id == b.rule_id)
                });
                if !still_bound {
                    bound_ids.remove(&b.rule_id);
                }
            }
        }

        self.agents.remove(id);
        Ok(())
    }

    pub async fn assign_rule(
        &self,
        agent_id: &str,
        rule_id: &str,
        tenant_id: &str,
        priority_override: Option<i32>,
    ) -> Result<(), AgentError> {
        self.verify_agent_tenant(agent_id, tenant_id)?;
        self.verify_rule_tenant(rule_id, tenant_id)?;

        if let Some(pool) = &self.pool {
            sqlx::query(
                "INSERT INTO cp_agent_rule_bindings (agent_id, rule_id, priority_override) \
                 VALUES ($1, $2, $3) ON CONFLICT (agent_id, rule_id) DO UPDATE SET priority_override = $3",
            )
            .bind(agent_id)
            .bind(rule_id)
            .bind(priority_override)
            .execute(pool.as_ref())
            .await
            .map_err(|e| AgentError::Database(e.to_string()))?;
        }

        self.rule_bindings
            .entry(agent_id.to_string())
            .or_insert_with(Vec::new)
            .retain(|b| b.rule_id != rule_id);

        self.rule_bindings
            .entry(agent_id.to_string())
            .or_insert_with(Vec::new)
            .push(AgentRuleBinding {
                agent_id: agent_id.to_string(),
                rule_id: rule_id.to_string(),
                priority_override,
            });

        self.bound_rule_ids.write().unwrap().insert(rule_id.to_string());
        Ok(())
    }

    pub async fn unassign_rule(&self, agent_id: &str, rule_id: &str, tenant_id: &str) -> Result<(), AgentError> {
        self.verify_agent_tenant(agent_id, tenant_id)?;
        if let Some(pool) = &self.pool {
            sqlx::query(
                "DELETE FROM cp_agent_rule_bindings WHERE agent_id=$1 AND rule_id=$2",
            )
            .bind(agent_id)
            .bind(rule_id)
            .execute(pool.as_ref())
            .await
            .map_err(|e| AgentError::Database(e.to_string()))?;
        }

        let mut removed = false;
        if let Some(mut bindings) = self.rule_bindings.get_mut(agent_id) {
            let before = bindings.len();
            bindings.retain(|b| b.rule_id != rule_id);
            removed = bindings.len() != before;
        }

        if removed {
            let still_bound = self.rule_bindings.iter().any(|b| {
                b.value().iter().any(|binding| binding.rule_id == rule_id)
            });
            if !still_bound {
                self.bound_rule_ids.write().unwrap().remove(rule_id);
            }
            Ok(())
        } else {
            Err(AgentError::RuleNotFound(rule_id.to_string()))
        }
    }

    pub fn list_agent_rules(&self, agent_id: &str, tenant_id: &str) -> Result<Vec<AgentRuleBinding>, AgentError> {
        self.verify_agent_tenant(agent_id, tenant_id)?;
        Ok(self.rule_bindings
            .get(agent_id)
            .map(|b| b.value().clone())
            .unwrap_or_default())
    }

    pub async fn create_rule(&self, mut rule: RuleEntry, tenant_id: &str) -> Result<(), AgentError> {
        rule.tenant_id = tenant_id.to_string();
        if let Some(pool) = &self.pool {
            sqlx::query(
                "INSERT INTO cp_rules (id, tenant_id, name, description, logic, decision, \
                 priority, is_active, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&rule.id)
            .bind(&rule.tenant_id)
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(&rule.logic)
            .bind(&rule.decision)
            .bind(rule.priority)
            .bind(rule.is_active)
            .bind(rule.version)
            .execute(pool.as_ref())
            .await
            .map_err(|e| AgentError::Database(e.to_string()))?;
        }

        self.rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    pub fn list_rules(&self) -> Vec<RuleEntry> {
        self.rules.iter().map(|r| r.value().clone()).collect()
    }

    pub fn list_rules_by_tenant(&self, tenant_id: &str) -> Vec<RuleEntry> {
        self.rules
            .iter()
            .filter(|r| r.value().tenant_id == tenant_id)
            .map(|r| r.value().clone())
            .collect()
    }

    pub fn get_rule(&self, id: &str) -> Option<RuleEntry> {
        self.rules.get(id).map(|r| r.value().clone())
    }

    pub fn get_rule_for_tenant(&self, id: &str, tenant_id: &str) -> Result<RuleEntry, AgentError> {
        self.verify_rule_tenant(id, tenant_id)
    }

    pub async fn update_rule(&self, id: &str, tenant_id: &str, mut update: RuleEntry) -> Result<RuleEntry, AgentError> {
        self.verify_rule_tenant(id, tenant_id)?;
        update.tenant_id = tenant_id.to_string();
        if let Some(pool) = &self.pool {
            let result = sqlx::query(
                "UPDATE cp_rules SET name=$2, description=$3, logic=$4, decision=$5, \
                 priority=$6, is_active=$7, version=$8, updated_at=NOW() \
                 WHERE id=$1 AND deleted_at IS NULL",
            )
            .bind(id)
            .bind(&update.name)
            .bind(&update.description)
            .bind(&update.logic)
            .bind(&update.decision)
            .bind(update.priority)
            .bind(update.is_active)
            .bind(update.version)
            .execute(pool.as_ref())
            .await
            .map_err(|e| AgentError::Database(e.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(AgentError::RuleNotFound(id.to_string()));
            }
        }

        let mut entry = self
            .rules
            .get_mut(id)
            .ok_or_else(|| AgentError::RuleNotFound(id.to_string()))?;
        *entry.value_mut() = update.clone();
        Ok(update)
    }

    pub async fn delete_rule(&self, id: &str, tenant_id: &str) -> Result<bool, AgentError> {
        self.verify_rule_tenant(id, tenant_id)?;
        if let Some(pool) = &self.pool {
            sqlx::query("UPDATE cp_rules SET deleted_at=NOW() WHERE id=$1")
                .bind(id)
                .execute(pool.as_ref())
                .await
                .map_err(|e| AgentError::Database(e.to_string()))?;
            sqlx::query("DELETE FROM cp_agent_rule_bindings WHERE rule_id=$1")
                .bind(id)
                .execute(pool.as_ref())
                .await
                .map_err(|e| AgentError::Database(e.to_string()))?;
        }

        for mut entry in self.rule_bindings.iter_mut() {
            entry.value_mut().retain(|b| b.rule_id != id);
        }

        self.rule_bindings.retain(|_, bindings| !bindings.is_empty());
        self.bound_rule_ids.write().unwrap().remove(id);

        Ok(self.rules.remove(id).is_some())
    }

    pub fn get_rules_for_agent(&self, agent_id: &str) -> Vec<RuleEntry> {
        let bindings = match self.rule_bindings.get(agent_id) {
            Some(b) => b,
            None => return Vec::new(),
        };

        bindings
            .value()
            .iter()
            .filter_map(|b| self.rules.get(&b.rule_id).map(|r| r.value().clone()))
            .collect()
    }

    pub fn get_tenant_global_rules(&self, tenant_id: &str) -> Vec<RuleEntry> {
        let bound_ids = self.bound_rule_ids.read().unwrap();

        self.rules
            .iter()
            .filter(|r| {
                r.value().tenant_id == tenant_id && !bound_ids.contains(&r.value().id)
            })
            .map(|r| r.value().clone())
            .collect()
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AgentRow {
    id: String,
    tenant_id: String,
    name: String,
    tool_allowlist: serde_json::Value,
    risk_threshold: f32,
    quota_max_daily: i32,
    quota_max_burst: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct RuleRow {
    id: String,
    tenant_id: String,
    name: String,
    description: String,
    logic: serde_json::Value,
    decision: String,
    priority: i32,
    is_active: bool,
    version: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct BindingRow {
    agent_id: String,
    rule_id: String,
    priority_override: Option<i32>,
}
