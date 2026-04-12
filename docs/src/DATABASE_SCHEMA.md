# AxiomGuard Database Schema (v3 + v4 CP)

## Overview

This is a production-grade, multi-tenant TimescaleDB schema with:
- **Multi-tenancy** with row-level security (RLS)
- **Hypertables** for automatic time-series chunking (events, decisions)
- **Automatic compression** after 7 days for cost-efficient storage
- **Continuous aggregates** for sub-second analytics
- **Vector similarity** search with pgvector
- **Data retention** policies
- **Optimized indexes** for query performance

---

## Entity Relationship Diagram

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│    tenants      │     │  tenant_settings │     │    api_keys     │
├─────────────────┤     ├──────────────────┤     ├─────────────────┤
│ id (PK)         │◄────┤ tenant_id (FK)   │     │ tenant_id (FK)  │
│ name            │     │ ai_enabled       │     │ key_hash        │
│ slug (unique)   │     │ ai_model_primary │     │ scopes          │
│ plan            │     │ webhook_url      │     │ rate_limit      │
│ quota_*         │     │ alert_email      │     │ expires_at      │
│ retention_*     │     └──────────────────┘     └─────────────────┘
└────────┬────────┘
         │
         │ 1:N
         │
         ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ security_rules  │     │  session_contexts│     │  audit_logs     │
├─────────────────┤     ├──────────────────┤     ├─────────────────┤
│ id (PK)         │     │ id (PK)          │     │ id (PK)         │
│ tenant_id (FK)  │     │ tenant_id (FK)   │     │ tenant_id (FK)  │
│ rule_key        │     │ session_id       │     │ action          │
│ version         │     │ risk_score       │     │ resource_type   │
│ logic (JSONB)   │     │ context_vector   │     │ actor_id        │
│ decision        │     │ event_count      │     │ changes (JSONB) │
│ status          │     │ expires_at       │     │ severity        │
└────────┬────────┘     └──────────────────┘     └─────────────────┘
         │
         │ (generates)
         ▼
┌─────────────────┐     ┌──────────────────┐
│     events      │────►│    decisions     │
├─────────────────┤     ├──────────────────┤
│ id (PK)         │     │ id (PK)          │
│ tenant_id (FK)  │     │ tenant_id (FK)   │
│ event_type      │     │ event_id (FK)    │
│ data (JSONB)    │     │ decision_type    │
│ embedding       │     │ confidence       │
│ decision_type   │     │ rules_applied    │
│ timestamp       │     │ ai_insights      │
│ (hypertable)    │     │ timestamp        │
└─────────────────┘     │ (hypertable)     │
                        └──────────────────┘

┌─────────────────┐
│ metrics_hourly  │
├─────────────────┤
│ id (PK)         │
│ tenant_id (FK)  │
│ hour            │
│ total_requests  │
│ latency_p95     │
│ decisions_count │
└─────────────────┘
```

---

## Table Details

### 1. `tenants` - Multi-tenancy Foundation

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,  -- URL-friendly identifier
    status TEXT CHECK (status IN ('active', 'suspended', 'deleted')),
    config JSONB DEFAULT '{}',  -- Feature flags and settings
    quota_events_per_day INTEGER DEFAULT 100000,
    quota_rules_max INTEGER DEFAULT 100,
    retention_events_days INTEGER DEFAULT 90,
    plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ  -- Soft delete
);
```

**Purpose**: Root entity for multi-tenancy. Every other table references this.

**Key Features**:
- Slug-based lookup for API routing (`/api/v1/{tenant}/...`)
- Quota enforcement per tenant
- Configurable data retention
- Soft delete for compliance

---

### 2. `security_rules` - Classification Rules

```sql
CREATE TABLE security_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_key TEXT NOT NULL,  -- Unique within tenant (e.g., "block-high-risk")
    version INTEGER NOT NULL DEFAULT 1,  -- Versioning for audit
    parent_rule_id UUID REFERENCES security_rules(id),  -- For rule evolution
    name TEXT NOT NULL,
    logic JSONB NOT NULL,  -- JSONLogic expression
    decision TEXT CHECK (decision IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    priority INTEGER NOT NULL DEFAULT 100,
    tags TEXT[] DEFAULT '{}',
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'draft')),
    match_count BIGINT DEFAULT 0,  -- Usage statistics
    last_matched_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,  -- Soft delete
    UNIQUE(tenant_id, rule_key, deleted_at)
);
```

**Purpose**: Stores JSONLogic classification rules per tenant.

**Key Features**:
- **Versioning**: Track rule changes over time
- **Soft deletes**: Never lose audit history
- **Statistics**: Track rule effectiveness (match_count)
- **LISTEN/NOTIFY**: Real-time updates when rules change

**Indexes**:
- `(tenant_id, status, priority)` - Fast active rule lookup
- `USING GIN(logic)` - Fast JSONLogic queries
- `USING GIN(tags)` - Tag-based filtering

---

### 3. `events` - Classification Events (Hypertable)

```sql
CREATE TABLE events (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    data JSONB NOT NULL,
    session_id TEXT,
    user_id TEXT,
    embedding VECTOR(768),  -- For semantic similarity
    decision_type TEXT CHECK (decision_type IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    confidence REAL,
    processing_time_ms INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);
```

**Purpose**: Stores every classification request and result.

**Key Features**:
- **Partitioned by month**: `events_2024_01`, `events_2024_02`, etc.
- **Vector embeddings**: Semantic similarity search with pgvector
- **Automatic cleanup**: Old chunks dropped via `drop_chunks()` per retention policy
- **Denormalized**: decision_type stored for fast queries

**Partitions**:
```sql
-- Automatically created for current month ± 3 months
-- Each chunk has its own indexes for query performance
-- Old chunks are dropped based on tenant.retention_events_days
```

---

### 4. `decisions` - Classification Decisions (Hypertable)

```sql
CREATE TABLE decisions (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    event_id UUID NOT NULL,
    decision_type TEXT NOT NULL CHECK (decision_type IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    reasoning TEXT,
    rules_applied JSONB,  -- Array of rule IDs that matched
    rule_versions JSONB,  -- Version numbers at decision time
    ai_insights JSONB,
    processing_time_ms INTEGER,
    rule_eval_time_ms INTEGER,
    ai_time_ms INTEGER,
    cache_hit BOOLEAN DEFAULT false,
    ai_model TEXT,
    ai_fallback_used BOOLEAN DEFAULT false,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);
```

**Purpose**: Detailed audit trail of every classification decision.

**Key Features**:
- **Performance breakdown**: rule_eval_time, ai_time, processing_time
- **Rule versioning**: Know exactly which rule versions were used
- **AI tracking**: Which model, was fallback used
- **Cache metrics**: Hit/miss tracking

---

### 5. `session_contexts` - Real-time Session Tracking

```sql
CREATE TABLE session_contexts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    session_id TEXT NOT NULL,
    context_vector VECTOR(768),
    risk_score REAL DEFAULT 0.0,
    risk_score_history REAL[] DEFAULT '{}',
    event_count INTEGER DEFAULT 0,
    decision_counts JSONB DEFAULT '{"ALLOW": 0, "BLOCK": 0, "HANDOVER": 0, "FLAG": 0}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    metadata JSONB DEFAULT '{}',
    user_agent TEXT,
    ip_address INET,
    UNIQUE(tenant_id, session_id)
);
```

**Purpose**: Track ongoing sessions for stateful classification.

**Key Features**:
- **Vector context**: Session behavior embeddings
- **Risk history**: Track risk score changes over time
- **Auto-expiry**: Sessions automatically cleaned up after 24h
- **Aggregated counts**: Fast decision statistics per session

---

### 6. `metrics_hourly` - Time-Series Aggregations

```sql
CREATE TABLE metrics_hourly (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    hour TIMESTAMPTZ NOT NULL,  -- Truncated to hour
    total_requests BIGINT DEFAULT 0,
    allowed_count BIGINT DEFAULT 0,
    blocked_count BIGINT DEFAULT 0,
    handed_over_count BIGINT DEFAULT 0,
    flagged_count BIGINT DEFAULT 0,
    latency_p50 REAL,
    latency_p95 REAL,
    latency_p99 REAL,
    ai_requests BIGINT DEFAULT 0,
    ai_fallback_count BIGINT DEFAULT 0,
    cache_hits BIGINT DEFAULT 0,
    cache_misses BIGINT DEFAULT 0,
    errors_total BIGINT DEFAULT 0,
    timeouts BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, hour)
);
```

**Purpose**: Pre-aggregated metrics for fast dashboard queries.

**Benefits**:
- Fast analytics queries (no need to scan millions of events)
- Cheap to query for dashboards
- Automatic rollup from events table

---

## Row Level Security (RLS)

All tenant-scoped tables have RLS enabled:

```sql
-- Enable RLS
ALTER TABLE security_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
-- etc.

-- Create policy
CREATE POLICY tenant_isolation_security_rules ON security_rules
    USING (tenant_id = current_setting('app.current_tenant')::UUID);
```

**Usage**:
```rust
// Set tenant context before queries
sqlx::query("SET LOCAL app.current_tenant = $1")
    .bind(tenant_id.to_string())
    .execute(&pool)
    .await?;

// Now all queries are automatically filtered by tenant
let rules = sqlx::query_as::<_, SecurityRule>("SELECT * FROM security_rules")
    .fetch_all(&pool)
    .await?;  // Only returns this tenant's rules
```

---

## Data Retention

### Automatic Cleanup

```sql
-- Function to clean up old events
CREATE FUNCTION cleanup_old_events() RETURNS void AS $$
DECLARE
    tenant_record RECORD;
    cutoff_date TIMESTAMPTZ;
BEGIN
    FOR tenant_record IN SELECT id, retention_events_days FROM tenants LOOP
        cutoff_date := NOW() - (tenant_record.retention_events_days || ' days')::INTERVAL;
        
        DELETE FROM events 
        WHERE tenant_id = tenant_record.id 
        AND timestamp < cutoff_date;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
```

**Recommended Schedule**:
- Run `cleanup_old_events()` daily via pg_cron or external scheduler
- Expired sessions cleaned up every hour
- Old chunks dropped via `drop_chunks()` per retention policy

---

## Performance Optimizations

### Indexes

| Table | Index | Purpose |
|-------|-------|---------|
| tenants | `idx_tenants_slug` | Fast tenant lookup by slug |
| security_rules | `idx_security_rules_tenant_status` | Active rules lookup |
| security_rules | `idx_security_rules_logic GIN` | JSONLogic queries |
| events | `idx_events_tenant` | Tenant-scoped time queries |
| events | `idx_events_embedding ivfflat` | Vector similarity search |
| events | `idx_events_data GIN` | JSON data queries |
| decisions | `idx_decisions_tenant` | Analytics queries |

### Hypertable Chunking Strategy

```
`events` hypertable - current chunk (fast writes)
events_2024_02  ← Next month (pre-created)
events_2024_03  ← Pre-created
`events` hypertable - old chunk (dropped per retention)
```

**Benefits**:
- Fast time-range queries (only scan relevant chunks)
- Easy data retention (`drop_chunks` for old chunks)
- Parallel query execution across chunks

---

## Migration from Old Schema

### Step 1: Run New Migration

```bash
# Run the production schema migration
psql $DATABASE_URL -f common/migrations/002_production_schema.sql
```

### Step 2: Migrate Data

```sql
-- Create system tenant
INSERT INTO tenants (id, name, slug, plan)
VALUES ('00000000-0000-0000-0000-000000000000', 'System', 'system', 'enterprise');

-- Migrate existing rules
INSERT INTO security_rules (
    tenant_id, rule_key, name, description, logic, decision, priority, status
)
SELECT 
    '00000000-0000-0000-0000-000000000000',
    id::text,  -- Use old ID as key temporarily
    name,
    description,
    logic,
    decision,
    priority,
    CASE WHEN is_active THEN 'active' ELSE 'inactive' END
FROM security_rules_old;

-- Migrate events (batch insert recommended for large datasets)
INSERT INTO events (
    tenant_id, event_type, source, data, timestamp, created_at
)
SELECT 
    '00000000-0000-0000-0000-000000000000',
    event_type,
    source,
    data,
    timestamp,
    created_at
FROM events_old;
```

### Step 3: Update Application Code

```rust
// Old
let repo = Repository::new(db);

// New
let repo = RepositoryV2::new(Arc::new(db));
repo.rules.set_tenant_context(tenant_id).await?;
```

---

## Best Practices

### 1. Always Use Tenant Context

```rust
// ❌ Wrong - will fail due to RLS
let rules = sqlx::query_as::<_, SecurityRule>("SELECT * FROM security_rules")
    .fetch_all(&pool)
    .await?;

// ✅ Correct - set tenant context first
sqlx::query("SET LOCAL app.current_tenant = $1")
    .bind(tenant_id.to_string())
    .execute(&pool)
    .await?;
let rules = sqlx::query_as::<_, SecurityRule>("SELECT * FROM security_rules")
    .fetch_all(&pool)
    .await?;
```

### 2. Use Soft Deletes

```rust
// ❌ Wrong - hard delete
sqlx::query("DELETE FROM security_rules WHERE id = $1").await?;

// ✅ Correct - soft delete
sqlx::query("UPDATE security_rules SET deleted_at = NOW() WHERE id = $1").await?;
```

### 3. Batch Inserts for Events

```rust
// Use COPY for bulk inserts
let mut copy_in = sqlx::postgres::PgCopyIn::new(&mut conn);
copy_in.send("COPY events (tenant_id, event_type, ...) FROM STDIN").await?;
// ... stream events
```

---

## Schema Summary

| Feature | Implementation | Status |
|---------|---------------|--------|
| Multi-tenancy | `tenant_id` FK + RLS policies | ✅ |
| Table partitioning | Hypertables with 1-day chunks for events/decisions | ✅ |
| Soft deletes | `deleted_at` column on all tables | ✅ |
| Vector search | pgvector with IVFFLAT index | ✅ |
| Data retention | Automated cleanup functions | ✅ |
| Audit logging | Full trail in audit_logs | ✅ |
| Versioning | Rule versioning with parent_rule_id | ✅ |
| Statistics | match_count, decision_counts | ✅ |

---

## v4 Control Plane Tables

### cp_agents

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | TEXT | PRIMARY KEY | Agent identifier |
| tenant_id | TEXT | NOT NULL | Tenant isolation |
| name | TEXT | NOT NULL | Display name |
| tool_allowlist | JSONB | NOT NULL DEFAULT '{}' | Tool permissions map |
| risk_threshold | REAL | NOT NULL DEFAULT 0.5 | Risk score threshold |
| quota_max_daily | INTEGER | NOT NULL DEFAULT 10000 | Daily quota limit |
| quota_max_burst | INTEGER | NOT NULL DEFAULT 100 | Burst quota limit |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Creation time |
| updated_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Last update |
| deleted_at | TIMESTAMPTZ | NULL | Soft delete |

**Indexes:** `idx_cp_agents_tenant` on `tenant_id` WHERE `deleted_at IS NULL`

### cp_rules

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | TEXT | PRIMARY KEY | Rule identifier |
| tenant_id | TEXT | NOT NULL | Tenant isolation |
| name | TEXT | NOT NULL | Rule name |
| description | TEXT | NOT NULL DEFAULT '' | Rule description |
| logic | JSONB | NOT NULL | JSONLogic expression |
| decision | TEXT | NOT NULL DEFAULT 'Block' | Decision type |
| priority | INTEGER | NOT NULL DEFAULT 100 | Evaluation order |
| is_active | BOOLEAN | NOT NULL DEFAULT true | Enabled flag |
| version | INTEGER | NOT NULL DEFAULT 1 | Rule version |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Creation time |
| updated_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Last update |
| deleted_at | TIMESTAMPTZ | NULL | Soft delete |

**Indexes:** `idx_cp_rules_tenant` on `tenant_id` WHERE `deleted_at IS NULL`

### cp_agent_rule_bindings

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY DEFAULT uuid_generate_v4() | Binding identifier |
| agent_id | TEXT | NOT NULL REFERENCES cp_agents(id) | Agent reference |
| rule_id | TEXT | NOT NULL REFERENCES cp_rules(id) | Rule reference |
| priority_override | INTEGER | NULL | Override rule priority |

**Unique constraint:** `(agent_id, rule_id)`  
**Indexes:** `idx_cp_bindings_agent` on `agent_id`

### cp_revoked_tokens

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| jti | TEXT | PRIMARY KEY | Token JTI (JWT ID) |
| revoked_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Revocation time |

Auto-cleanup: rows older than 24 hours can be deleted.

### cp_bypass_alerts

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY DEFAULT uuid_generate_v4() | Alert identifier |
| tenant_id | TEXT | NOT NULL | Tenant isolation |
| agent_id | TEXT | NOT NULL | Agent reference |
| tool_name | TEXT | NOT NULL | Tool that was bypassed |
| reason | TEXT | NOT NULL | Bypass reason |
| timestamp | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Detection time |

**Indexes:** `idx_cp_bypass_alerts_tenant` on `(tenant_id, timestamp DESC)`, `idx_cp_bypass_alerts_agent` on `(agent_id, timestamp DESC)`

### cp_audit_events

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY DEFAULT uuid_generate_v4() | Audit event identifier |
| event_id | TEXT | NOT NULL | SDK-generated event ID |
| tenant_id | TEXT | NOT NULL | Tenant isolation |
| agent_id | TEXT | NOT NULL | Agent reference |
| session_id | TEXT | NULL | Session for reconstruction |
| tool_name | TEXT | NOT NULL | Tool that was called |
| decision | TEXT | NOT NULL | Decision type (Allow/Block/Flag/Handover) |
| risk_score | REAL | NOT NULL DEFAULT 0.0 | Risk score at decision time |
| processing_time_us | BIGINT | NOT NULL DEFAULT 0 | Processing latency in microseconds |
| reason | TEXT | NOT NULL DEFAULT '' | Decision reason |
| matched_rules | JSONB | NOT NULL DEFAULT '[]' | Rules that matched |
| timestamp | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Event timestamp |

**Indexes:** `idx_cp_audit_session` on `(session_id, timestamp DESC)`, `idx_cp_audit_tenant_agent` on `(tenant_id, agent_id, timestamp DESC)`

**Purpose:** Structured audit event storage for session state reconstruction. Every SDK decision is persisted here, enabling the Control Plane to reconstruct session state after SDK process restarts.

### cp_escalations

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY DEFAULT uuid_generate_v4() | Escalation identifier |
| tenant_id | TEXT | NOT NULL | Tenant isolation |
| agent_id | TEXT | NOT NULL | Agent reference |
| session_id | TEXT | NULL | Session reference |
| tool_name | TEXT | NOT NULL | Tool that triggered escalation |
| decision | TEXT | NOT NULL | Decision type (Flag/Handover) |
| risk_score | REAL | NOT NULL | Risk score at escalation |
| cumulative_risk | REAL | NOT NULL | Session cumulative risk |
| reason | TEXT | NOT NULL | Escalation reason |
| ai_insights | TEXT | NULL | AI analysis results (deferred to P2) |
| status | TEXT | NOT NULL DEFAULT 'pending' | Escalation status |
| created_at | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Creation time |

**Indexes:** `idx_cp_escalations_tenant` on `(tenant_id, created_at DESC)`

**Purpose:** Escalation records for Flag/Handover decisions. Stores AI analysis insights for suspicious activity requiring human review.

---

**Schema Version**: 3.1 (v3 + v4 CP tables + reliability gap tables)  
**Last Updated**: 2026-04-12  
**Status**: Production Ready
