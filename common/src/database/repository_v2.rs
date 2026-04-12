//! Production-grade repository implementations with multi-tenancy

use sqlx::{Error, query_as, query, Row, Postgres};
use uuid::Uuid;
use chrono::{DateTime, Utc, NaiveDateTime};
use serde_json::Value;
use super::Database;
use std::sync::Arc;

// ============================================================================
// TENANT REPOSITORY
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub status: String,
    pub config: Value,
    pub features: Value,
    pub quota_events_per_day: i32,
    pub quota_rules_max: i32,
    pub plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TenantRepository {
    db: Arc<Database>,
}

impl TenantRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, Error> {
        let tenant = query_as::<_, Tenant>(
            "SELECT * FROM tenants WHERE slug = $1 AND deleted_at IS NULL"
        )
        .bind(slug)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(tenant)
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Tenant>, Error> {
        let tenant = query_as::<_, Tenant>(
            "SELECT * FROM tenants WHERE id = $1 AND deleted_at IS NULL"
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(tenant)
    }

    pub async fn create(&self, tenant: &Tenant) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO tenants (id, name, slug, status, config, features, 
                quota_events_per_day, quota_rules_max, plan, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#
        )
        .bind(&tenant.id)
        .bind(&tenant.name)
        .bind(&tenant.slug)
        .bind(&tenant.status)
        .bind(&tenant.config)
        .bind(&tenant.features)
        .bind(tenant.quota_events_per_day)
        .bind(tenant.quota_rules_max)
        .bind(&tenant.plan)
        .bind(&tenant.created_at)
        .bind(&tenant.updated_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn update_quota_usage(&self, tenant_id: Uuid, events_today: i64) -> Result<(), Error> {
        query(
            "UPDATE tenants SET config = jsonb_set(config, '{events_today}', $1::jsonb) WHERE id = $2"
        )
        .bind(serde_json::json!(events_today))
        .bind(tenant_id)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }
}

// ============================================================================
// SECURITY RULE REPOSITORY (Multi-tenant)
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityRule {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub rule_key: String,
    pub version: i32,
    pub name: String,
    pub description: Option<String>,
    pub logic: Value,
    pub decision: String,
    pub priority: i32,
    pub tags: Vec<String>,
    pub category: String,
    pub status: String,
    pub match_count: i64,
    pub last_matched_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SecurityRuleRepository {
    db: Arc<Database>,
}

impl SecurityRuleRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Set tenant context for RLS
    pub async fn set_tenant_context(&self, tenant_id: Uuid) -> Result<(), Error> {
        sqlx::query("SET LOCAL app.current_tenant = $1")
            .bind(tenant_id.to_string())
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    pub async fn list_active_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<SecurityRule>, Error> {
        let rules = query_as::<_, SecurityRule>(
            r#"
            SELECT * FROM security_rules 
            WHERE tenant_id = $1 
            AND status = 'active' 
            AND deleted_at IS NULL
            ORDER BY priority ASC
            "#
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rules)
    }

    pub async fn get_by_key(&self, tenant_id: Uuid, rule_key: &str) -> Result<Option<SecurityRule>, Error> {
        let rule = query_as::<_, SecurityRule>(
            r#"
            SELECT * FROM security_rules 
            WHERE tenant_id = $1 
            AND rule_key = $2 
            AND deleted_at IS NULL
            "#
        )
        .bind(tenant_id)
        .bind(rule_key)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(rule)
    }

    pub async fn insert(&self, rule: &SecurityRule) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO security_rules 
            (id, tenant_id, rule_key, version, name, description, logic, decision, 
             priority, tags, category, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#
        )
        .bind(&rule.id)
        .bind(&rule.tenant_id)
        .bind(&rule.rule_key)
        .bind(rule.version)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.logic)
        .bind(&rule.decision)
        .bind(rule.priority)
        .bind(&rule.tags)
        .bind(&rule.category)
        .bind(&rule.status)
        .bind(&rule.created_at)
        .bind(&rule.updated_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn increment_match_count(&self, rule_id: Uuid) -> Result<(), Error> {
        query(
            "UPDATE security_rules SET match_count = match_count + 1, last_matched_at = NOW() WHERE id = $1"
        )
        .bind(rule_id)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn count_active_for_tenant(&self, tenant_id: Uuid) -> Result<i64, Error> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_rules WHERE tenant_id = $1 AND status = 'active' AND deleted_at IS NULL"
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;
        Ok(count)
    }

    pub async fn soft_delete(&self, tenant_id: Uuid, rule_key: &str) -> Result<(), Error> {
        query(
            "UPDATE security_rules SET deleted_at = NOW() WHERE tenant_id = $1 AND rule_key = $2 AND deleted_at IS NULL"
        )
        .bind(tenant_id)
        .bind(rule_key)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }
}

// ============================================================================
// EVENT REPOSITORY (Partitioned)
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub source: String,
    pub data: Value,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub decision_type: Option<String>,
    pub confidence: Option<f32>,
    pub processing_time_ms: Option<i32>,
    pub timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EventRepository {
    db: Arc<Database>,
}

impl EventRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn insert(&self, event: &Event) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO events 
            (id, tenant_id, event_type, source, data, session_id, user_id, 
             decision_type, confidence, processing_time_ms, timestamp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#
        )
        .bind(&event.id)
        .bind(&event.tenant_id)
        .bind(&event.event_type)
        .bind(&event.source)
        .bind(&event.data)
        .bind(&event.session_id)
        .bind(&event.user_id)
        .bind(&event.decision_type)
        .bind(event.confidence)
        .bind(event.processing_time_ms)
        .bind(&event.timestamp)
        .bind(&event.created_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn insert_with_embedding(&self, event: &Event, embedding: &[f32]) -> Result<(), Error> {
        let embedding_str = format!("[{}]", embedding.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(","));
        query(
            r#"
            INSERT INTO events 
            (id, tenant_id, event_type, source, data, session_id, user_id, 
             decision_type, confidence, processing_time_ms, timestamp, created_at, embedding)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::vector)
            "#
        )
        .bind(&event.id)
        .bind(&event.tenant_id)
        .bind(&event.event_type)
        .bind(&event.source)
        .bind(&event.data)
        .bind(&event.session_id)
        .bind(&event.user_id)
        .bind(&event.decision_type)
        .bind(event.confidence)
        .bind(event.processing_time_ms)
        .bind(&event.timestamp)
        .bind(&event.created_at)
        .bind(&embedding_str)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Event>, Error> {
        let events = query_as::<_, Event>(
            r#"
            SELECT * FROM events 
            WHERE tenant_id = $1 
            AND timestamp >= $2 
            AND timestamp <= $3 
            ORDER BY timestamp DESC 
            LIMIT $4 OFFSET $5
            "#
        )
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.db.pool())
        .await?;
        Ok(events)
    }

    pub async fn count_for_tenant_today(&self, tenant_id: Uuid) -> Result<i64, Error> {
        let start_of_day = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let start: DateTime<Utc> = DateTime::from_naive_utc_and_offset(start_of_day, Utc);
        
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND timestamp >= $2"
        )
        .bind(tenant_id)
        .bind(start)
        .fetch_one(self.db.pool())
        .await?;
        Ok(count)
    }

    /// Find similar events using vector similarity
    pub async fn find_similar(
        &self,
        tenant_id: Uuid,
        embedding: &[f32],
        threshold: f64,
        limit: i64,
    ) -> Result<Vec<(Event, f64)>, Error> {
        let embedding_str = format!("[{}]", embedding.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(","));
        
        let rows = query(
            r#"
            SELECT *, 1 - (embedding <=> $1::vector) as similarity
            FROM events
            WHERE tenant_id = $2
            AND embedding IS NOT NULL 
            AND 1 - (embedding <=> $1::vector) > $3
            ORDER BY embedding <=> $1::vector
            LIMIT $4
            "#
        )
        .bind(&embedding_str)
        .bind(tenant_id)
        .bind(threshold)
        .bind(limit)
        .fetch_all(self.db.pool())
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let event = Event {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                event_type: row.get("event_type"),
                source: row.get("source"),
                data: row.get("data"),
                session_id: row.get("session_id"),
                user_id: row.get("user_id"),
                decision_type: row.get("decision_type"),
                confidence: row.get("confidence"),
                processing_time_ms: row.get("processing_time_ms"),
                timestamp: row.get("timestamp"),
                created_at: row.get("created_at"),
            };
            let similarity: f64 = row.get("similarity");
            results.push((event, similarity));
        }

        Ok(results)
    }
}

// ============================================================================
// DECISION REPOSITORY (Partitioned)
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Decision {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_id: Uuid,
    pub decision_type: String,
    pub confidence: f64,
    pub reasoning: Option<String>,
    pub rules_applied: Option<Value>,
    pub rule_versions: Option<Value>,
    pub ai_insights: Option<Value>,
    pub processing_time_ms: Option<i32>,
    pub rule_eval_time_ms: Option<i32>,
    pub ai_time_ms: Option<i32>,
    pub cache_hit: Option<bool>,
    pub ai_model: Option<String>,
    pub ai_fallback_used: Option<bool>,
    pub timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DecisionRepository {
    db: Arc<Database>,
}

impl DecisionRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn insert(&self, decision: &Decision) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO decisions 
            (id, tenant_id, event_id, decision_type, confidence, reasoning, 
             rules_applied, rule_versions, ai_insights, processing_time_ms, 
             rule_eval_time_ms, ai_time_ms, cache_hit, ai_model, 
             ai_fallback_used, timestamp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            "#
        )
        .bind(&decision.id)
        .bind(&decision.tenant_id)
        .bind(&decision.event_id)
        .bind(&decision.decision_type)
        .bind(decision.confidence)
        .bind(&decision.reasoning)
        .bind(&decision.rules_applied)
        .bind(&decision.rule_versions)
        .bind(&decision.ai_insights)
        .bind(decision.processing_time_ms)
        .bind(decision.rule_eval_time_ms)
        .bind(decision.ai_time_ms)
        .bind(decision.cache_hit)
        .bind(&decision.ai_model)
        .bind(decision.ai_fallback_used)
        .bind(&decision.timestamp)
        .bind(&decision.created_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn get_stats_for_tenant(
        &self,
        tenant_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<DecisionStats, Error> {
        let row = query(
            r#"
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE decision_type = 'ALLOW') as allowed,
                COUNT(*) FILTER (WHERE decision_type = 'BLOCK') as blocked,
                COUNT(*) FILTER (WHERE decision_type = 'HANDOVER') as handed_over,
                COUNT(*) FILTER (WHERE decision_type = 'FLAG') as flagged,
                AVG(confidence) as avg_confidence,
                AVG(processing_time_ms) as avg_processing_time
            FROM decisions
            WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
            "#
        )
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .fetch_one(self.db.pool())
        .await?;

        Ok(DecisionStats {
            total: row.get::<i64, _>("total"),
            allowed: row.get::<i64, _>("allowed"),
            blocked: row.get::<i64, _>("blocked"),
            handed_over: row.get::<i64, _>("handed_over"),
            flagged: row.get::<i64, _>("flagged"),
            avg_confidence: row.get::<Option<f64>, _>("avg_confidence").unwrap_or(0.0),
            avg_processing_time_ms: row.get::<Option<f64>, _>("avg_processing_time").unwrap_or(0.0),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DecisionStats {
    pub total: i64,
    pub allowed: i64,
    pub blocked: i64,
    pub handed_over: i64,
    pub flagged: i64,
    pub avg_confidence: f64,
    pub avg_processing_time_ms: f64,
}

// ============================================================================
// SESSION CONTEXT REPOSITORY
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionContext {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: String,
    pub risk_score: f64,
    pub event_count: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct SessionContextRepository {
    db: Arc<Database>,
}

impl SessionContextRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn upsert(&self, context: &SessionContext) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO session_contexts 
            (id, tenant_id, session_id, risk_score, event_count, 
             first_seen, last_seen, expires_at, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (tenant_id, session_id) DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                event_count = session_contexts.event_count + 1,
                last_seen = EXCLUDED.last_seen,
                expires_at = EXCLUDED.expires_at,
                metadata = EXCLUDED.metadata
            "#
        )
        .bind(&context.id)
        .bind(&context.tenant_id)
        .bind(&context.session_id)
        .bind(context.risk_score)
        .bind(context.event_count)
        .bind(&context.first_seen)
        .bind(&context.last_seen)
        .bind(&context.expires_at)
        .bind(&context.metadata)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn get_by_session(
        &self, 
        tenant_id: Uuid, 
        session_id: &str
    ) -> Result<Option<SessionContext>, Error> {
        let context = query_as::<_, SessionContext>(
            "SELECT * FROM session_contexts WHERE tenant_id = $1 AND session_id = $2"
        )
        .bind(tenant_id)
        .bind(session_id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(context)
    }
}

// ============================================================================
// AGGREGATED REPOSITORY
// ============================================================================

pub struct RepositoryV2 {
    pub tenants: TenantRepository,
    pub rules: SecurityRuleRepository,
    pub events: EventRepository,
    pub decisions: DecisionRepository,
    pub sessions: SessionContextRepository,
}

impl RepositoryV2 {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            tenants: TenantRepository::new(db.clone()),
            rules: SecurityRuleRepository::new(db.clone()),
            events: EventRepository::new(db.clone()),
            decisions: DecisionRepository::new(db.clone()),
            sessions: SessionContextRepository::new(db),
        }
    }
}
