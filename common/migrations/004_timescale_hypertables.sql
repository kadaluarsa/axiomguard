-- ============================================================================
-- TimescaleDB Migration: Convert events and decisions to hypertables
-- ============================================================================
-- This migration replaces native PostgreSQL range partitioning with
-- TimescaleDB hypertables for automatic chunking, compression,
-- and continuous aggregates.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================================================
-- 1. EVENTS -> Hypertable
-- ============================================================================

-- Drop native partitioned table (cascades triggers, policies, indexes)
DROP TABLE IF EXISTS events CASCADE;

-- Recreate as a regular table (will become hypertable)
CREATE TABLE events (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    data JSONB NOT NULL,
    session_id TEXT,
    user_id TEXT,
    embedding VECTOR(768),
    decision_type TEXT CHECK (decision_type IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    confidence REAL,
    processing_time_ms INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, timestamp)
);

-- Convert to hypertable with 1-day chunks
SELECT create_hypertable('events', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

-- Recreate indexes
CREATE INDEX idx_events_tenant ON events(tenant_id, timestamp DESC);
CREATE INDEX idx_events_type ON events(event_type, timestamp DESC);
CREATE INDEX idx_events_session ON events(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_events_decision ON events(decision_type, timestamp DESC) WHERE decision_type IS NOT NULL;
CREATE INDEX idx_events_embedding ON events USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX idx_events_data ON events USING GIN(data jsonb_path_ops);

-- Enable RLS and recreate policy
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_events ON events
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- Recreate LISTEN/NOTIFY trigger for real-time streaming
DROP TRIGGER IF EXISTS event_insert_notify ON events;
CREATE TRIGGER event_insert_notify
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION notify_event_inserted();

-- Compression: compress chunks after 7 days, segment by tenant_id for locality
ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'tenant_id');
SELECT add_compression_policy('events', INTERVAL '7 days');

-- ============================================================================
-- 2. DECISIONS -> Hypertable
-- ============================================================================

DROP TABLE IF EXISTS decisions CASCADE;

CREATE TABLE decisions (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    event_id UUID NOT NULL,
    decision_type TEXT NOT NULL CHECK (decision_type IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    reasoning TEXT,
    rules_applied JSONB,
    rule_versions JSONB,
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
);

SELECT create_hypertable('decisions', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

CREATE INDEX idx_decisions_tenant ON decisions(tenant_id, timestamp DESC);
CREATE INDEX idx_decisions_event ON decisions(event_id);
CREATE INDEX idx_decisions_type ON decisions(decision_type, timestamp DESC);

ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_decisions ON decisions
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- Compression for decisions
ALTER TABLE decisions SET (timescaledb.compress, timescaledb.compress_segmentby = 'tenant_id');
SELECT add_compression_policy('decisions', INTERVAL '7 days');

-- ============================================================================
-- 3. CONTINUOUS AGGREGATE: Event histogram (1-minute buckets)
-- ============================================================================

CREATE MATERIALIZED VIEW event_histogram_1min
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', timestamp) AS bucket,
    tenant_id,
    decision_type,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE data->>'action' = 'blocked') as blocked,
    COUNT(*) FILTER (WHERE data->>'action' = 'allowed') as allowed,
    COUNT(*) FILTER (WHERE data->>'action' = 'flagged') as flagged
FROM events
GROUP BY bucket, tenant_id, decision_type
WITH NO DATA;

SELECT add_continuous_aggregate_policy('event_histogram_1min',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 minute'
);

-- ============================================================================
-- 4. UPDATE cleanup function to use hypertable-friendly chunk dropping
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_events()
RETURNS void AS $$
DECLARE
    tenant_record RECORD;
    cutoff_date TIMESTAMPTZ;
    min_retention INTEGER;
BEGIN
    -- Find the shortest retention period among active tenants
    SELECT COALESCE(MIN(retention_events_days), 90)
    INTO min_retention
    FROM tenants
    WHERE status = 'active';

    -- Drop old chunks globally based on the shortest retention window
    PERFORM drop_chunks('events', NOW() - (min_retention || ' days')::INTERVAL);
    PERFORM drop_chunks('decisions', NOW() - (min_retention || ' days')::INTERVAL);

    -- Fine-grained per-tenant DELETE for any tenant with a shorter retention
    FOR tenant_record IN SELECT id, retention_events_days FROM tenants WHERE status = 'active' LOOP
        cutoff_date := NOW() - (tenant_record.retention_events_days || ' days')::INTERVAL;

        DELETE FROM events
        WHERE tenant_id = tenant_record.id
        AND timestamp < cutoff_date;

        DELETE FROM decisions
        WHERE tenant_id = tenant_record.id
        AND timestamp < cutoff_date;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
