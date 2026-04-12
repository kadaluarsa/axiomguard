-- ============================================================================
-- AxiomGuard 3.0 - Production Database Schema
-- 
-- Features:
-- - Multi-tenancy with row-level security
-- - Table partitioning for time-series data
-- - Soft deletes for audit compliance
-- - Optimized indexes for query performance
-- - Data retention policies
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;  -- Query performance monitoring

-- ============================================================================
-- 1. TENANTS (Multi-tenancy foundation)
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,  -- URL-friendly identifier
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    
    -- Configuration
    config JSONB DEFAULT '{}',
    features JSONB DEFAULT '["rules", "analytics", "api"]',  -- Feature flags
    
    -- Quotas and limits
    quota_events_per_day INTEGER DEFAULT 100000,
    quota_rules_max INTEGER DEFAULT 100,
    quota_api_keys_max INTEGER DEFAULT 10,
    
    -- Rate limiting
    rate_limit_requests_per_second INTEGER DEFAULT 1000,
    rate_limit_burst INTEGER DEFAULT 5000,
    
    -- Data retention (days)
    retention_events_days INTEGER DEFAULT 90,
    retention_audit_days INTEGER DEFAULT 365,
    
    -- Billing
    plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')),
    billing_email TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,  -- Soft delete
    
    -- Created by
    created_by UUID,
    updated_by UUID
);

CREATE INDEX idx_tenants_slug ON tenants(slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_tenants_status ON tenants(status) WHERE deleted_at IS NULL;

-- Trigger for updated_at
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 2. TENANT SETTINGS (Per-tenant configuration)
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- AI Configuration
    ai_enabled BOOLEAN DEFAULT true,
    ai_model_primary TEXT DEFAULT 'mistral-7b',
    ai_model_fallback TEXT DEFAULT 'gemini-flash',
    ai_confidence_threshold REAL DEFAULT 0.7,
    
    -- Rule engine settings
    decisive_timeout_ms INTEGER DEFAULT 80,
    cache_ttl_seconds INTEGER DEFAULT 300,
    max_rule_priority INTEGER DEFAULT 1000,
    
    -- Notification settings
    webhook_url TEXT,
    webhook_secret TEXT,
    alert_email TEXT,
    
    -- Custom fields
    custom_fields JSONB DEFAULT '{}',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

CREATE INDEX idx_tenant_settings_tenant ON tenant_settings(tenant_id);

-- ============================================================================
-- 3. API KEYS (Tenant-scoped authentication)
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,  -- SHA-256 hash of the key
    key_prefix TEXT NOT NULL,  -- First 8 chars for identification
    
    -- Permissions
    scopes TEXT[] DEFAULT '{"read", "write"}',
    allowed_ips INET[],  -- NULL = all IPs allowed
    
    -- Rate limiting (override tenant default)
    rate_limit_override INTEGER,
    
    -- Status
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    deleted_at TIMESTAMPTZ,  -- Soft delete
    
    CONSTRAINT unique_active_key UNIQUE (key_hash, deleted_at)
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- ============================================================================
-- 4. SECURITY RULES (Multi-tenant with versioning)
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Versioning
    rule_key TEXT NOT NULL,  -- Unique within tenant (e.g., "block-high-risk")
    version INTEGER NOT NULL DEFAULT 1,
    parent_rule_id UUID REFERENCES security_rules(id),
    
    -- Rule content
    name TEXT NOT NULL,
    description TEXT,
    logic JSONB NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    
    -- Metadata
    priority INTEGER NOT NULL DEFAULT 100,
    tags TEXT[] DEFAULT '{}',
    category TEXT DEFAULT 'custom',
    
    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'draft')),
    
    -- Statistics
    match_count BIGINT DEFAULT 0,
    last_matched_at TIMESTAMPTZ,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,  -- Soft delete
    
    created_by UUID,
    updated_by UUID,
    
    -- Ensure unique active rule per tenant+key
    UNIQUE(tenant_id, rule_key, deleted_at)
);

-- Optimized indexes
CREATE INDEX idx_security_rules_tenant_status ON security_rules(tenant_id, status, priority) 
    WHERE deleted_at IS NULL;
CREATE INDEX idx_security_rules_tenant_key ON security_rules(tenant_id, rule_key) 
    WHERE deleted_at IS NULL;
CREATE INDEX idx_security_rules_tags ON security_rules USING GIN(tags);

-- GIN index for JSONLogic queries
CREATE INDEX idx_security_rules_logic ON security_rules USING GIN(logic jsonb_path_ops);

-- Trigger for versioning
CREATE OR REPLACE FUNCTION increment_rule_version()
RETURNS TRIGGER AS $$
BEGIN
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_increment_rule_version
    BEFORE UPDATE ON security_rules
    FOR EACH ROW
    WHEN (OLD.logic IS DISTINCT FROM NEW.logic)
    EXECUTE FUNCTION increment_rule_version();

-- Trigger for updated_at
CREATE TRIGGER update_security_rules_updated_at
    BEFORE UPDATE ON security_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- LISTEN/NOTIFY trigger (updated for multi-tenancy)
CREATE OR REPLACE FUNCTION notify_rule_change()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('rules_updated', json_build_object(
        'type', TG_OP,
        'tenant_id', COALESCE(NEW.tenant_id::text, OLD.tenant_id::text),
        'rule_id', COALESCE(NEW.id::text, OLD.id::text),
        'rule_key', COALESCE(NEW.rule_key, OLD.rule_key)
    )::text);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER rule_change_event
    AFTER INSERT OR UPDATE OR DELETE ON security_rules
    FOR EACH ROW
    EXECUTE FUNCTION notify_rule_change();

-- ============================================================================
-- 5. EVENTS (Partitioned by time for performance)
-- ============================================================================

-- Parent table (partitioned)
CREATE TABLE IF NOT EXISTS events (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    data JSONB NOT NULL,
    
    -- Session tracking
    session_id TEXT,
    user_id TEXT,
    
    -- Vector embedding for semantic search
    embedding VECTOR(768),
    
    -- Classification result (denormalized for fast queries)
    decision_type TEXT CHECK (decision_type IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    confidence REAL,
    processing_time_ms INTEGER,
    
    -- Timestamps
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Partition key
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create partitions for last 3 months and next 3 months
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
BEGIN
    -- Create partitions for current month +/- 3 months
    FOR i IN -3..3 LOOP
        start_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL);
        end_date := start_date + INTERVAL '1 month';
        partition_name := 'events_' || TO_CHAR(start_date, 'YYYY_MM');
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF events
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        -- Create indexes on partition
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS %I ON %I (tenant_id, timestamp DESC)',
            partition_name || '_tenant_ts', partition_name
        );
        
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS %I ON %I (session_id) WHERE session_id IS NOT NULL',
            partition_name || '_session', partition_name
        );
    END LOOP;
END $$;

-- Indexes on parent (will be inherited by partitions)
CREATE INDEX idx_events_tenant ON events(tenant_id, timestamp DESC);
CREATE INDEX idx_events_type ON events(event_type, timestamp DESC);
CREATE INDEX idx_events_session ON events(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_events_decision ON events(decision_type, timestamp DESC) WHERE decision_type IS NOT NULL;

-- Vector similarity index
CREATE INDEX idx_events_embedding ON events USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- GIN index for JSON data queries
CREATE INDEX idx_events_data ON events USING GIN(data jsonb_path_ops);

-- ============================================================================
-- 6. DECISIONS (Partitioned by time)
-- ============================================================================

CREATE TABLE IF NOT EXISTS decisions (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    event_id UUID NOT NULL,
    
    -- Classification result
    decision_type TEXT NOT NULL CHECK (decision_type IN ('ALLOW', 'BLOCK', 'HANDOVER', 'FLAG')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    reasoning TEXT,
    
    -- What influenced the decision
    rules_applied JSONB,  -- Array of rule IDs that matched
    rule_versions JSONB,  -- Version numbers of rules at decision time
    ai_insights JSONB,
    
    -- Performance metrics
    processing_time_ms INTEGER,
    rule_eval_time_ms INTEGER,
    ai_time_ms INTEGER,
    cache_hit BOOLEAN DEFAULT false,
    
    -- Source (which model/engine)
    ai_model TEXT,
    ai_fallback_used BOOLEAN DEFAULT false,
    
    -- Timestamps
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Partition key
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create partitions for decisions
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
BEGIN
    FOR i IN -3..3 LOOP
        start_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL);
        end_date := start_date + INTERVAL '1 month';
        partition_name := 'decisions_' || TO_CHAR(start_date, 'YYYY_MM');
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF decisions
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS %I ON %I (tenant_id, timestamp DESC)',
            partition_name || '_tenant_ts', partition_name
        );
    END LOOP;
END $$;

CREATE INDEX idx_decisions_tenant ON decisions(tenant_id, timestamp DESC);
CREATE INDEX idx_decisions_event ON decisions(event_id);
CREATE INDEX idx_decisions_type ON decisions(decision_type, timestamp DESC);

-- ============================================================================
-- 7. SESSION CONTEXTS (Real-time session tracking)
-- ============================================================================

CREATE TABLE IF NOT EXISTS session_contexts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    session_id TEXT NOT NULL,
    
    -- Context vector (for similarity search)
    context_vector VECTOR(768),
    
    -- Aggregated metrics
    risk_score REAL DEFAULT 0.0,
    risk_score_history REAL[] DEFAULT '{}',  -- Last N scores
    event_count INTEGER DEFAULT 0,
    decision_counts JSONB DEFAULT '{"ALLOW": 0, "BLOCK": 0, "HANDOVER": 0, "FLAG": 0}',
    
    -- Timestamps
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    user_agent TEXT,
    ip_address INET,
    
    -- Tenant-scoped unique constraint
    UNIQUE(tenant_id, session_id)
);

CREATE INDEX idx_session_contexts_tenant ON session_contexts(tenant_id, last_seen DESC);
CREATE INDEX idx_session_contexts_expires ON session_contexts(expires_at) WHERE expires_at < NOW();

-- Auto-cleanup expired sessions
CREATE INDEX idx_session_contexts_cleanup ON session_contexts(expires_at);

-- ============================================================================
-- 8. AUDIT LOGS (Compliance trail)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    
    -- What happened
    action TEXT NOT NULL,  -- CREATE, UPDATE, DELETE, LOGIN, etc.
    resource_type TEXT NOT NULL,  -- rule, api_key, tenant, etc.
    resource_id TEXT NOT NULL,
    
    -- Before/after for changes
    old_values JSONB,
    new_values JSONB,
    
    -- Who did it
    actor_type TEXT NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user', 'api_key', 'system')),
    actor_id TEXT NOT NULL,
    actor_email TEXT,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    request_id TEXT,
    
    -- Classification (if this was a security event)
    severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
    
    -- Timestamps
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);

-- ============================================================================
-- 9. AGGREGATED METRICS (Time-series rollups)
-- ============================================================================

CREATE TABLE IF NOT EXISTS metrics_hourly (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    
    -- Time bucket
    hour TIMESTAMPTZ NOT NULL,  -- Truncated to hour
    
    -- Request metrics
    total_requests BIGINT DEFAULT 0,
    allowed_count BIGINT DEFAULT 0,
    blocked_count BIGINT DEFAULT 0,
    handed_over_count BIGINT DEFAULT 0,
    flagged_count BIGINT DEFAULT 0,
    
    -- Latency percentiles (stored as milliseconds)
    latency_p50 REAL,
    latency_p95 REAL,
    latency_p99 REAL,
    
    -- AI metrics
    ai_requests BIGINT DEFAULT 0,
    ai_fallback_count BIGINT DEFAULT 0,
    ai_avg_confidence REAL,
    
    -- Cache metrics
    cache_hits BIGINT DEFAULT 0,
    cache_misses BIGINT DEFAULT 0,
    
    -- Error metrics
    errors_total BIGINT DEFAULT 0,
    timeouts BIGINT DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, hour)
);

CREATE INDEX idx_metrics_hourly_tenant ON metrics_hourly(tenant_id, hour DESC);

-- ============================================================================
-- 10. ROW LEVEL SECURITY (Multi-tenant data isolation)
-- ============================================================================

-- Enable RLS on all tenant-scoped tables
ALTER TABLE security_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE metrics_hourly ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
CREATE POLICY tenant_isolation_security_rules ON security_rules
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY tenant_isolation_events ON events
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY tenant_isolation_decisions ON decisions
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY tenant_isolation_sessions ON session_contexts
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY tenant_isolation_audit ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY tenant_isolation_metrics ON metrics_hourly
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- ============================================================================
-- 11. DATA RETENTION FUNCTIONS
-- ============================================================================

-- Function to clean up old events based on tenant retention policy
CREATE OR REPLACE FUNCTION cleanup_old_events()
RETURNS void AS $$
DECLARE
    tenant_record RECORD;
    cutoff_date TIMESTAMPTZ;
BEGIN
    FOR tenant_record IN SELECT id, retention_events_days FROM tenants WHERE status = 'active' LOOP
        cutoff_date := NOW() - (tenant_record.retention_events_days || ' days')::INTERVAL;
        
        -- Delete old events for this tenant
        DELETE FROM events 
        WHERE tenant_id = tenant_record.id 
        AND timestamp < cutoff_date;
        
        -- Delete old decisions
        DELETE FROM decisions 
        WHERE tenant_id = tenant_record.id 
        AND timestamp < cutoff_date;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM session_contexts WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 12. ANALYTICS FUNCTIONS
-- ============================================================================

-- Function to get decision statistics for a tenant
CREATE OR REPLACE FUNCTION get_decision_stats(
    p_tenant_id UUID,
    p_start_time TIMESTAMPTZ,
    p_end_time TIMESTAMPTZ
)
RETURNS TABLE (
    decision_type TEXT,
    count BIGINT,
    avg_confidence REAL,
    avg_processing_time_ms REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.decision_type,
        COUNT(*)::BIGINT,
        AVG(d.confidence)::REAL,
        AVG(d.processing_time_ms)::REAL
    FROM decisions d
    WHERE d.tenant_id = p_tenant_id
    AND d.timestamp BETWEEN p_start_time AND p_end_time
    GROUP BY d.decision_type;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 13. DEFAULT DATA
-- ============================================================================

-- Create system tenant
INSERT INTO tenants (id, name, slug, plan, config) VALUES
(
    '00000000-0000-0000-0000-000000000000'::UUID,
    'System',
    'system',
    'enterprise',
    '{"is_system": true}'
)
ON CONFLICT (slug) DO NOTHING;

-- Create default tenant settings
INSERT INTO tenant_settings (tenant_id) VALUES
('00000000-0000-0000-0000-000000000000'::UUID)
ON CONFLICT (tenant_id) DO NOTHING;

-- Insert default rules for system tenant
INSERT INTO security_rules (
    tenant_id, rule_key, name, description, logic, decision, priority, tags
) VALUES
(
    '00000000-0000-0000-0000-000000000000'::UUID,
    'allow-health-check',
    'Allow Health Check',
    'Allow health check requests',
    '{"==": [{"var": "path"}, "/health"]}'::jsonb,
    'ALLOW',
    1,
    ARRAY['system', 'health']
),
(
    '00000000-0000-0000-0000-000000000000'::UUID,
    'block-high-risk',
    'Block High Risk Score',
    'Block requests with risk score > 0.9',
    '{">": [{"var": "risk_score"}, 0.9]}'::jsonb,
    'BLOCK',
    10,
    ARRAY['risk', 'auto']
)
ON CONFLICT (tenant_id, rule_key, deleted_at) DO NOTHING;
