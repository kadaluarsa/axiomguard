use sqlx::{Error, query_as, query, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::Value;
use super::Database;

// ============================================================================
// Security Rule Repository
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub logic: Value,
    pub decision: String,
    pub priority: i32,
    pub is_active: bool,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SecurityRuleRepository {
    db: Database,
}

impl SecurityRuleRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn insert(&self, rule: &SecurityRule) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO security_rules 
            (id, name, description, logic, decision, priority, is_active, tags, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.logic)
        .bind(&rule.decision)
        .bind(rule.priority)
        .bind(rule.is_active)
        .bind(&rule.tags)
        .bind(&rule.created_at)
        .bind(&rule.updated_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<SecurityRule>, Error> {
        let rule = query_as::<_, SecurityRule>(
            "SELECT * FROM security_rules WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(rule)
    }

    pub async fn list_active(&self) -> Result<Vec<SecurityRule>, Error> {
        let rules = query_as::<_, SecurityRule>(
            "SELECT * FROM security_rules WHERE is_active = true ORDER BY priority ASC"
        )
        .fetch_all(self.db.pool())
        .await?;
        Ok(rules)
    }

    pub async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<SecurityRule>, Error> {
        let rules = query_as::<_, SecurityRule>(
            "SELECT * FROM security_rules ORDER BY priority ASC LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rules)
    }

    pub async fn update(&self, rule: &SecurityRule) -> Result<(), Error> {
        query(
            r#"
            UPDATE security_rules 
            SET name = $1, description = $2, logic = $3, decision = $4, 
                priority = $5, is_active = $6, tags = $7, updated_at = NOW()
            WHERE id = $8
            "#
        )
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.logic)
        .bind(&rule.decision)
        .bind(rule.priority)
        .bind(rule.is_active)
        .bind(&rule.tags)
        .bind(&rule.id)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), Error> {
        query("DELETE FROM security_rules WHERE id = $1")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }
}

// ============================================================================
// Event Repository
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub event_type: String,
    pub source: String,
    pub data: Value,
    pub session_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EventRepository {
    db: Database,
}

impl EventRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn insert(&self, event: &Event) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO events (id, event_type, source, data, session_id, timestamp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(&event.id)
        .bind(&event.event_type)
        .bind(&event.source)
        .bind(&event.data)
        .bind(&event.session_id)
        .bind(&event.timestamp)
        .bind(&event.created_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Event>, Error> {
        let event = query_as::<_, Event>(
            "SELECT * FROM events WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(event)
    }

    pub async fn list_by_time_range(
        &self, 
        start: DateTime<Utc>, 
        end: DateTime<Utc>, 
        limit: i64, 
        offset: i64
    ) -> Result<Vec<Event>, Error> {
        let events = query_as::<_, Event>(
            "SELECT * FROM events WHERE timestamp >= $1 AND timestamp <= $2 ORDER BY timestamp DESC LIMIT $3 OFFSET $4"
        )
        .bind(start)
        .bind(end)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.db.pool())
        .await?;
        Ok(events)
    }

    /// Find similar events using vector similarity search (requires pgvector)
    pub async fn find_similar(
        &self,
        embedding: &[f32],
        threshold: f64,
        limit: i64,
    ) -> Result<Vec<(Event, f64)>, Error> {
        // Use raw SQL with pgvector operator
        let embedding_str = format!("[{}]", embedding.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(","));
        
        let rows = query(
            r#"
            SELECT id, event_type, source, data, session_id, timestamp, created_at,
                   1 - (embedding <=> $1::vector) as similarity
            FROM events
            WHERE embedding IS NOT NULL AND 1 - (embedding <=> $1::vector) > $2
            ORDER BY embedding <=> $1::vector
            LIMIT $3
            "#
        )
        .bind(&embedding_str)
        .bind(threshold)
        .bind(limit)
        .fetch_all(self.db.pool())
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let event = Event {
                id: row.get("id"),
                event_type: row.get("event_type"),
                source: row.get("source"),
                data: row.get("data"),
                session_id: row.get("session_id"),
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
// Decision Repository
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Decision {
    pub id: Uuid,
    pub event_id: Uuid,
    pub decision_type: String,
    pub confidence: f64,
    pub reasoning: Option<String>,
    pub rules_applied: Option<Value>,
    pub ai_insights: Option<Value>,
    pub processing_time_ms: Option<i32>,
    pub timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DecisionRepository {
    db: Database,
}

impl DecisionRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn insert(&self, decision: &Decision) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO decisions 
            (id, event_id, decision_type, confidence, reasoning, rules_applied, ai_insights, processing_time_ms, timestamp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#
        )
        .bind(&decision.id)
        .bind(&decision.event_id)
        .bind(&decision.decision_type)
        .bind(decision.confidence)
        .bind(&decision.reasoning)
        .bind(&decision.rules_applied)
        .bind(&decision.ai_insights)
        .bind(decision.processing_time_ms)
        .bind(&decision.timestamp)
        .bind(&decision.created_at)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn get_by_event_id(&self, event_id: Uuid) -> Result<Vec<Decision>, Error> {
        let decisions = query_as::<_, Decision>(
            "SELECT * FROM decisions WHERE event_id = $1 ORDER BY timestamp DESC"
        )
        .bind(event_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(decisions)
    }

    pub async fn get_stats_by_time_range(
        &self,
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
                AVG(processing_time_ms) as avg_processing_time
            FROM decisions
            WHERE timestamp >= $1 AND timestamp <= $2
            "#
        )
        .bind(start)
        .bind(end)
        .fetch_one(self.db.pool())
        .await?;

        Ok(DecisionStats {
            total: row.get::<i64, _>("total") as u64,
            allowed: row.get::<i64, _>("allowed") as u64,
            blocked: row.get::<i64, _>("blocked") as u64,
            handed_over: row.get::<i64, _>("handed_over") as u64,
            flagged: row.get::<i64, _>("flagged") as u64,
            avg_processing_time_ms: row.get::<Option<f64>, _>("avg_processing_time").unwrap_or(0.0),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DecisionStats {
    pub total: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub handed_over: u64,
    pub flagged: u64,
    pub avg_processing_time_ms: f64,
}

// ============================================================================
// Session Context Repository
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionContext {
    pub id: Uuid,
    pub session_id: String,
    pub risk_score: f64,
    pub event_count: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct SessionContextRepository {
    db: Database,
}

impl SessionContextRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn upsert(&self, context: &SessionContext) -> Result<(), Error> {
        query(
            r#"
            INSERT INTO session_contexts 
            (id, session_id, risk_score, event_count, first_seen, last_seen, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (session_id) DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                event_count = session_contexts.event_count + 1,
                last_seen = EXCLUDED.last_seen,
                metadata = EXCLUDED.metadata
            "#
        )
        .bind(&context.id)
        .bind(&context.session_id)
        .bind(context.risk_score)
        .bind(context.event_count)
        .bind(&context.first_seen)
        .bind(&context.last_seen)
        .bind(&context.metadata)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    pub async fn get_by_session_id(&self, session_id: &str) -> Result<Option<SessionContext>, Error> {
        let context = query_as::<_, SessionContext>(
            "SELECT * FROM session_contexts WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(context)
    }
}

// ============================================================================
// Combined Database Repository
// ============================================================================

#[derive(Debug, Clone)]
pub struct Repository {
    pub rules: SecurityRuleRepository,
    pub events: EventRepository,
    pub decisions: DecisionRepository,
    pub sessions: SessionContextRepository,
}

impl Repository {
    pub fn new(db: Database) -> Self {
        Self {
            rules: SecurityRuleRepository::new(db.clone()),
            events: EventRepository::new(db.clone()),
            decisions: DecisionRepository::new(db.clone()),
            sessions: SessionContextRepository::new(db),
        }
    }
}
