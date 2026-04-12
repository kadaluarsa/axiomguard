use crate::analyst::BypassAlert;
use sqlx::postgres::PgPool;
use std::sync::Arc;

pub async fn run_cp_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(cp_schema())
        .execute(pool)
        .await?;
    Ok(())
}

fn cp_schema() -> &'static str {
    r#"
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS cp_agents (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        tool_allowlist JSONB NOT NULL DEFAULT '{}',
        risk_threshold REAL NOT NULL DEFAULT 0.5,
        quota_max_daily INTEGER NOT NULL DEFAULT 10000,
        quota_max_burst INTEGER NOT NULL DEFAULT 100,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_cp_agents_tenant ON cp_agents(tenant_id) WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS cp_rules (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        logic JSONB NOT NULL,
        decision TEXT NOT NULL DEFAULT 'Block',
        priority INTEGER NOT NULL DEFAULT 100,
        is_active BOOLEAN NOT NULL DEFAULT true,
        version INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_cp_rules_tenant ON cp_rules(tenant_id) WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS cp_agent_rule_bindings (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        agent_id TEXT NOT NULL REFERENCES cp_agents(id),
        rule_id TEXT NOT NULL REFERENCES cp_rules(id),
        priority_override INTEGER,
        UNIQUE(agent_id, rule_id)
    );
    CREATE INDEX IF NOT EXISTS idx_cp_bindings_agent ON cp_agent_rule_bindings(agent_id);

    CREATE TABLE IF NOT EXISTS cp_revoked_tokens (
        jti TEXT PRIMARY KEY,
        revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cp_bypass_alerts (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        reason TEXT NOT NULL,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cp_bypass_alerts_tenant ON cp_bypass_alerts(tenant_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_cp_bypass_alerts_agent ON cp_bypass_alerts(agent_id, timestamp DESC);

    CREATE TABLE IF NOT EXISTS cp_api_keys (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        tenant_id TEXT NOT NULL,
        agent_id TEXT REFERENCES cp_agents(id),
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        permissions TEXT[] NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'active',
        rotated_from_id UUID REFERENCES cp_api_keys(id),
        rotated_to_id UUID REFERENCES cp_api_keys(id),
        grace_period_ends_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_cp_api_keys_tenant ON cp_api_keys(tenant_id) WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_cp_api_keys_agent ON cp_api_keys(agent_id) WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS cp_tenant_settings (
        tenant_id TEXT PRIMARY KEY,
        webhook_url TEXT,
        webhook_enabled BOOLEAN NOT NULL DEFAULT false,
        webhook_secret TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cp_audit_events (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        event_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        session_id TEXT,
        tool_name TEXT NOT NULL,
        decision TEXT NOT NULL,
        risk_score REAL NOT NULL DEFAULT 0.0,
        processing_time_us BIGINT NOT NULL DEFAULT 0,
        reason TEXT NOT NULL DEFAULT '',
        matched_rules JSONB NOT NULL DEFAULT '[]',
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cp_audit_session ON cp_audit_events(session_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_cp_audit_tenant_agent ON cp_audit_events(tenant_id, agent_id, timestamp DESC);

    CREATE TABLE IF NOT EXISTS cp_escalations (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        session_id TEXT,
        tool_name TEXT NOT NULL,
        decision TEXT NOT NULL,
        risk_score REAL NOT NULL,
        cumulative_risk REAL NOT NULL,
        reason TEXT NOT NULL,
        ai_insights TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cp_escalations_tenant ON cp_escalations(tenant_id, created_at DESC);
    "#
}

#[derive(Debug, Clone)]
pub struct CpRepository {
    pool: Arc<PgPool>,
}

impl CpRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn health_check(&self) -> Result<bool, sqlx::Error> {
        let row: (i64,) = sqlx::query_as("SELECT 1")
            .fetch_one(&*self.pool)
            .await?;
        Ok(row.0 == 1)
    }

    pub async fn persist_bypass_alert(&self, alert: &BypassAlert) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO cp_bypass_alerts (id, tenant_id, agent_id, tool_name, reason, timestamp) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&alert.id)
        .bind(&alert.tenant_id)
        .bind(&alert.agent_id)
        .bind(&alert.tool_name)
        .bind(&alert.reason)
        .bind(alert.timestamp)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    pub async fn persist_revocation(&self, jti: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO cp_revoked_tokens (jti) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(jti)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    pub async fn is_revoked(&self, jti: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT jti FROM cp_revoked_tokens WHERE jti = $1")
                .bind(jti)
                .fetch_optional(&*self.pool)
                .await?;
        Ok(row.is_some())
    }

    pub async fn cleanup_expired_revocations(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM cp_revoked_tokens WHERE revoked_at < NOW() - INTERVAL '24 hours'",
        )
        .execute(&*self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ============== API Keys ==============

    pub async fn list_api_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyRow>, sqlx::Error> {
        sqlx::query_as::<_, ApiKeyRow>(
            "SELECT k.id, k.tenant_id, k.agent_id, k.name, k.key_prefix, k.permissions, \
             k.status, k.rotated_from_id, k.rotated_to_id, k.grace_period_ends_at, \
             k.created_at, k.expires_at, k.last_used_at, k.revoked_at, a.name as agent_name \
             FROM cp_api_keys k LEFT JOIN cp_agents a ON k.agent_id = a.id \
             WHERE k.tenant_id = $1 AND k.deleted_at IS NULL \
             ORDER BY k.created_at DESC"
        )
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await
    }

    pub async fn get_api_key(&self, id: &str) -> Result<Option<ApiKeyRow>, sqlx::Error> {
        sqlx::query_as::<_, ApiKeyRow>(
            "SELECT k.id, k.tenant_id, k.agent_id, k.name, k.key_prefix, k.permissions, \
             k.status, k.rotated_from_id, k.rotated_to_id, k.grace_period_ends_at, \
             k.created_at, k.expires_at, k.last_used_at, k.revoked_at, a.name as agent_name \
             FROM cp_api_keys k LEFT JOIN cp_agents a ON k.agent_id = a.id \
             WHERE k.id = $1 AND k.deleted_at IS NULL"
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
    }

    pub async fn create_api_key(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        name: &str,
        key_hash: &str,
        key_prefix: &str,
        permissions: &[String],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ApiKeyRow, sqlx::Error> {
        let row = sqlx::query_as::<_, ApiKeyRow>(
            "INSERT INTO cp_api_keys (tenant_id, agent_id, name, key_hash, key_prefix, permissions, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, tenant_id, agent_id, name, key_prefix, permissions, status, \
             rotated_from_id, rotated_to_id, grace_period_ends_at, created_at, expires_at, last_used_at, revoked_at, \
             (SELECT name FROM cp_agents WHERE id = $2) as agent_name"
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(name)
        .bind(key_hash)
        .bind(key_prefix)
        .bind(permissions)
        .bind(expires_at)
        .fetch_one(&*self.pool)
        .await?;
        Ok(row)
    }

    pub async fn update_api_key_status(
        &self,
        id: &str,
        status: &str,
        rotated_to_id: Option<&str>,
        grace_period_ends_at: Option<chrono::DateTime<chrono::Utc>>,
        revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE cp_api_keys SET status = $2, rotated_to_id = $3, \
             grace_period_ends_at = $4, revoked_at = $5 WHERE id = $1"
        )
        .bind(id)
        .bind(status)
        .bind(rotated_to_id)
        .bind(grace_period_ends_at)
        .bind(revoked_at)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    pub async fn link_rotated_key(
        &self,
        old_id: &str,
        new_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE cp_api_keys SET rotated_to_id = $2 WHERE id = $1"
        )
        .bind(old_id)
        .bind(new_id)
        .execute(&*self.pool)
        .await?;
        sqlx::query(
            "UPDATE cp_api_keys SET rotated_from_id = $2 WHERE id = $1"
        )
        .bind(new_id)
        .bind(old_id)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_api_key(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE cp_api_keys SET deleted_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // ============== Analytics ==============

    pub async fn get_analytics_aggregate(
        &self,
        tenant_id: &str,
    ) -> Result<AnalyticsAggregateRow, sqlx::Error> {
        let from = chrono::Utc::now() - chrono::Duration::hours(24);
        let row = sqlx::query_as::<_, AnalyticsAggregateRow>(
            "SELECT \
             COUNT(*) as total_calls, \
             COUNT(*) FILTER (WHERE data->>'action' = 'allowed') as allow_count, \
             COUNT(*) FILTER (WHERE data->>'action' = 'blocked') as block_count, \
             COUNT(*) FILTER (WHERE data->>'action' = 'flagged') as flag_count, \
             AVG(processing_time_ms) as avg_latency_ms \
             FROM events WHERE tenant_id = $1 AND timestamp >= $2"
        )
        .bind(tenant_id)
        .bind(from)
        .fetch_one(&*self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_analytics_per_agent(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AgentAnalyticsRow>, sqlx::Error> {
        let from = chrono::Utc::now() - chrono::Duration::hours(24);
        sqlx::query_as::<_, AgentAnalyticsRow>(
            "SELECT \
             COALESCE(data->>'agentId', 'unknown') as agent_id, \
             COALESCE(data->>'agentName', 'Unknown Agent') as name, \
             COUNT(*) as total_calls, \
             COUNT(*) FILTER (WHERE data->>'action' = 'allowed') as allow_count, \
             COUNT(*) FILTER (WHERE data->>'action' = 'blocked') as block_count, \
             COUNT(*) FILTER (WHERE data->>'action' = 'flagged') as flag_count, \
             AVG(processing_time_ms) as avg_latency_ms \
             FROM events WHERE tenant_id = $1 AND timestamp >= $2 \
             GROUP BY data->>'agentId', data->>'agentName' \
             ORDER BY total_calls DESC"
        )
        .bind(tenant_id)
        .bind(from)
        .fetch_all(&*self.pool)
        .await
    }

    // ============== Audit / Events ==============

    pub async fn list_audit_events(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        action: Option<&str>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEventRow>, sqlx::Error> {
        // Using query builder with manual interpolation for simplicity
        let mut sql = format!(
            "SELECT id, tenant_id, event_type, source, session_id, decision_type, confidence, \
             processing_time_ms, data, timestamp, created_at \
             FROM events WHERE tenant_id = '{}' ",
            tenant_id
        );
        sql.push_str(" AND timestamp >= '");
        sql.push_str(&from.unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339());
        sql.push('\'');
        if let Some(aid) = agent_id {
            sql.push_str(" AND data->>'agentId' = '");
            sql.push_str(aid);
            sql.push('\'');
        }
        if let Some(act) = action {
            sql.push_str(" AND data->>'action' = '");
            sql.push_str(act);
            sql.push('\'');
        }
        if let Some(t) = to {
            sql.push_str(" AND timestamp <= '");
            sql.push_str(&t.to_rfc3339());
            sql.push('\'');
        }
        if let Some(s) = search {
            sql.push_str(" AND (data->>'path' ILIKE '%");
            sql.push_str(&s.replace('\\', "\\\\").replace('\'', "''"));
            sql.push_str("%' OR data->>'ruleName' ILIKE '%");
            sql.push_str(&s.replace('\\', "\\\\").replace('\'', "''"));
            sql.push_str("%')");
        }
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT {} OFFSET {}", limit, offset));
        // Safety: tenant_id and agent_id are trusted (auth middleware), search is escaped
        sqlx::query_as::<_, AuditEventRow>(&sql)
            .fetch_all(&*self.pool)
            .await
    }

    pub async fn count_audit_events(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        action: Option<&str>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        search: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let mut sql = format!(
            "SELECT COUNT(*) as cnt FROM events WHERE tenant_id = '{}' ",
            tenant_id
        );
        sql.push_str(" AND timestamp >= '");
        sql.push_str(&from.unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339());
        sql.push('\'');
        if let Some(aid) = agent_id {
            sql.push_str(" AND data->>'agentId' = '");
            sql.push_str(aid);
            sql.push('\'');
        }
        if let Some(act) = action {
            sql.push_str(" AND data->>'action' = '");
            sql.push_str(act);
            sql.push('\'');
        }
        if let Some(t) = to {
            sql.push_str(" AND timestamp <= '");
            sql.push_str(&t.to_rfc3339());
            sql.push('\'');
        }
        if let Some(s) = search {
            sql.push_str(" AND (data->>'path' ILIKE '%");
            sql.push_str(&s.replace('\\', "\\\\").replace('\'', "''"));
            sql.push_str("%' OR data->>'ruleName' ILIKE '%");
            sql.push_str(&s.replace('\\', "\\\\").replace('\'', "''"));
            sql.push_str("%')");
        }
        let row: (i64,) = sqlx::query_as(&sql).fetch_one(&*self.pool).await?;
        Ok(row.0)
    }

    pub async fn get_event_histogram(
        &self,
        tenant_id: &str,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
        bucket_minutes: i32,
    ) -> Result<Vec<EventHistogramRow>, sqlx::Error> {
        let sql = format!(
            "SELECT \
             time_bucket('{} minutes', timestamp) as bucket, \
             COUNT(*) as total, \
             COUNT(*) FILTER (WHERE data->>'action' = 'blocked') as blocked, \
             COUNT(*) FILTER (WHERE data->>'action' = 'allowed') as allowed, \
             COUNT(*) FILTER (WHERE data->>'action' = 'flagged') as flagged \
             FROM events WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3 \
             GROUP BY bucket ORDER BY bucket",
            bucket_minutes
        );
        sqlx::query_as::<_, EventHistogramRow>(&sql)
            .bind(tenant_id)
            .bind(from)
            .bind(to)
            .fetch_all(&*self.pool)
            .await
    }

    // ============== Sessions ==============

    pub async fn list_sessions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<SessionRow>, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
        sqlx::query_as::<_, SessionRow>(
            "SELECT \
             COALESCE(session_id, 'unknown') as session_id, \
             COALESCE(data->>'agentId', 'unknown') as agent_id, \
             COUNT(*) as tool_call_count, \
             MAX(CASE WHEN data->>'riskScore' IS NOT NULL THEN (data->>'riskScore')::float ELSE 0 END) as risk_score, \
             MIN(timestamp) as created_at, \
             MAX(timestamp) as last_active \
             FROM events WHERE tenant_id = $1 AND timestamp >= $2 \
             GROUP BY session_id, data->>'agentId' \
             ORDER BY last_active DESC"
        )
        .bind(tenant_id)
        .bind(cutoff)
        .fetch_all(&*self.pool)
        .await
    }

    pub async fn get_session_timeline(
        &self,
        _tenant_id: &str,
        session_id: &str,
    ) -> Result<Vec<SessionTimelineRow>, sqlx::Error> {
        sqlx::query_as::<_, SessionTimelineRow>(
            "SELECT timestamp, data->>'tool' as tool, COALESCE(data->>'action', 'allowed') as decision, \
             COALESCE(data->>'reason', '') as reason \
             FROM events WHERE session_id = $1 ORDER BY timestamp"
        )
        .bind(session_id)
        .fetch_all(&*self.pool)
        .await
    }

    // ============== Tenant Settings ==============

    pub async fn get_tenant_settings(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantSettingsRow>, sqlx::Error> {
        sqlx::query_as::<_, TenantSettingsRow>(
            "SELECT tenant_id, webhook_url, webhook_enabled, webhook_secret, updated_at \
             FROM cp_tenant_settings WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&*self.pool)
        .await
    }

    pub async fn upsert_tenant_settings(
        &self,
        tenant_id: &str,
        webhook_url: Option<&str>,
        webhook_enabled: bool,
        webhook_secret: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO cp_tenant_settings (tenant_id, webhook_url, webhook_enabled, webhook_secret, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
             webhook_url = EXCLUDED.webhook_url, \
             webhook_enabled = EXCLUDED.webhook_enabled, \
             webhook_secret = EXCLUDED.webhook_secret, \
             updated_at = NOW()"
        )
        .bind(tenant_id)
        .bind(webhook_url)
        .bind(webhook_enabled)
        .bind(webhook_secret)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    // ============== Structured Audit Events (cp_audit_events) ==============

    pub async fn insert_audit_event_batch(
        &self,
        events: &[CpAuditEventInsert],
    ) -> Result<(), sqlx::Error> {
        for ev in events {
            sqlx::query(
                "INSERT INTO cp_audit_events (event_id, tenant_id, agent_id, session_id, tool_name, decision, \
                 risk_score, processing_time_us, reason, matched_rules, timestamp) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())"
            )
            .bind(&ev.event_id)
            .bind(&ev.tenant_id)
            .bind(&ev.agent_id)
            .bind(&ev.session_id)
            .bind(&ev.tool_name)
            .bind(&ev.decision)
            .bind(ev.risk_score)
            .bind(ev.processing_time_us as i64)
            .bind(&ev.reason)
            .bind(&ev.matched_rules)
            .execute(&*self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn query_session_events(
        &self,
        session_id: &str,
        tenant_id: &str,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<CpAuditEventRow>, sqlx::Error> {
        sqlx::query_as::<_, CpAuditEventRow>(
            "SELECT id, event_id, tenant_id, agent_id, session_id, tool_name, decision, \
             risk_score, processing_time_us, reason, matched_rules, timestamp \
             FROM cp_audit_events \
             WHERE session_id = $1 AND tenant_id = $2 AND agent_id = $3 \
             ORDER BY timestamp ASC LIMIT $4"
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(agent_id)
        .bind(limit)
        .fetch_all(&*self.pool)
        .await
    }

    // ============== Escalations (cp_escalations) ==============

    pub async fn insert_escalation(
        &self,
        esc: &EscalationInsert,
    ) -> Result<uuid::Uuid, sqlx::Error> {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO cp_escalations (id, tenant_id, agent_id, session_id, tool_name, decision, \
             risk_score, cumulative_risk, reason, ai_insights, status, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())"
        )
        .bind(id)
        .bind(&esc.tenant_id)
        .bind(&esc.agent_id)
        .bind(&esc.session_id)
        .bind(&esc.tool_name)
        .bind(&esc.decision)
        .bind(esc.risk_score)
        .bind(esc.cumulative_risk)
        .bind(&esc.reason)
        .bind(&esc.ai_insights)
        .bind(&esc.status)
        .execute(&*self.pool)
        .await?;
        Ok(id)
    }
}

// ============== Row Types ==============

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: Option<String>,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub status: String,
    pub rotated_from_id: Option<String>,
    pub rotated_to_id: Option<String>,
    pub grace_period_ends_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AnalyticsAggregateRow {
    pub total_calls: Option<i64>,
    pub allow_count: Option<i64>,
    pub block_count: Option<i64>,
    pub flag_count: Option<i64>,
    pub avg_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AgentAnalyticsRow {
    pub agent_id: String,
    pub name: Option<String>,
    pub total_calls: Option<i64>,
    pub allow_count: Option<i64>,
    pub block_count: Option<i64>,
    pub flag_count: Option<i64>,
    pub avg_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AuditEventRow {
    pub id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub source: String,
    pub session_id: Option<String>,
    pub decision_type: Option<String>,
    pub confidence: Option<f64>,
    pub processing_time_ms: Option<f64>,
    pub data: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct EventHistogramRow {
    pub bucket: chrono::DateTime<chrono::Utc>,
    pub total: Option<i64>,
    pub blocked: Option<i64>,
    pub allowed: Option<i64>,
    pub flagged: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct SessionRow {
    pub session_id: String,
    pub agent_id: String,
    pub tool_call_count: Option<i64>,
    pub risk_score: Option<f64>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_active: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct SessionTimelineRow {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tool: Option<String>,
    pub decision: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct TenantSettingsRow {
    pub tenant_id: String,
    pub webhook_url: Option<String>,
    pub webhook_enabled: bool,
    pub webhook_secret: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct CpAuditEventRow {
    pub id: uuid::Uuid,
    pub event_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub decision: String,
    pub risk_score: f32,
    pub processing_time_us: i64,
    pub reason: String,
    pub matched_rules: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CpAuditEventInsert {
    pub event_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub decision: String,
    pub risk_score: f32,
    pub processing_time_us: u64,
    pub reason: String,
    pub matched_rules: serde_json::Value,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct EscalationInsert {
    pub tenant_id: String,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub decision: String,
    pub risk_score: f32,
    pub cumulative_risk: f32,
    pub reason: String,
    pub ai_insights: Option<String>,
    pub status: String,
}
