-- PostgreSQL schema for The Mirror audit log
-- Replaces file-based audit.jsonl with queryable database

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Audit log table (main table for all agent actions)
CREATE TABLE IF NOT EXISTS audit_log (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Incident tracking
    incident_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Action details
    action_id VARCHAR(128) NOT NULL,
    action_name VARCHAR(256) NOT NULL,
    action_tier INTEGER,
    action_result VARCHAR(64) NOT NULL,  -- success, failed, skipped, simulated

    -- Action parameters (JSONB for flexible schema)
    parameters JSONB,

    -- Rollback information
    rollback_handle VARCHAR(256),
    expires_at TIMESTAMPTZ,

    -- Justification
    detection_confidence DECIMAL(3,2),
    detection_method VARCHAR(64),  -- rule_based, llm, hybrid
    evidence_refs JSONB,
    playbook_rule VARCHAR(128),
    reasoning TEXT,

    -- Context
    context JSONB,

    -- LLM information (if LLM was used)
    llm_consulted BOOLEAN DEFAULT FALSE,
    llm_model JSONB,
    llm_reasoning TEXT,

    -- Indexes for common queries
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_audit_incident_id ON audit_log(incident_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_action_id ON audit_log(action_id);
CREATE INDEX idx_audit_created_at ON audit_log(created_at DESC);
CREATE INDEX idx_audit_action_result ON audit_log(action_result);

-- GIN index for JSONB columns (enables fast searches)
CREATE INDEX idx_audit_parameters ON audit_log USING GIN (parameters);
CREATE INDEX idx_audit_context ON audit_log USING GIN (context);

-- Incidents summary table (denormalized for fast queries)
CREATE TABLE IF NOT EXISTS incidents (
    -- Primary key
    incident_id VARCHAR(64) PRIMARY KEY,

    -- Incident metadata
    first_seen TIMESTAMPTZ NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL,

    -- Attacker information
    attacker_ip INET NOT NULL,
    attacker_info JSONB,  -- OSINT data

    -- Detection information
    detection_signature TEXT,
    detection_confidence DECIMAL(3,2),
    detection_signals JSONB,

    -- Actions taken
    actions_count INTEGER DEFAULT 0,
    actions_summary JSONB,  -- List of actions taken

    -- Status
    status VARCHAR(32) DEFAULT 'active',  -- active, resolved, false_positive
    severity INTEGER,  -- 1=high, 2=medium, 3=low

    -- Post-mortem
    postmortem_generated BOOLEAN DEFAULT FALSE,
    postmortem_reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR(128),
    reviewed_at TIMESTAMPTZ,

    -- GitHub integration
    github_issue_url TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for incidents
CREATE INDEX idx_incidents_attacker_ip ON incidents(attacker_ip);
CREATE INDEX idx_incidents_first_seen ON incidents(first_seen DESC);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_postmortem ON incidents(postmortem_generated);

-- Evidence files table (references to OSINT data, PCAP, etc.)
CREATE TABLE IF NOT EXISTS evidence (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Foreign key to incident
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,

    -- Evidence metadata
    evidence_type VARCHAR(64) NOT NULL,  -- whois, shodan, pcap, honeypot_log, etc.
    file_path TEXT,
    file_size BIGINT,

    -- Evidence data (small data can be stored inline)
    data JSONB,

    -- Timestamps
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for evidence
CREATE INDEX idx_evidence_incident_id ON evidence(incident_id);
CREATE INDEX idx_evidence_type ON evidence(evidence_type);
CREATE INDEX idx_evidence_collected_at ON evidence(collected_at DESC);

-- VirtualServices tracking (Phase 4 - Istio integration)
CREATE TABLE IF NOT EXISTS virtualservices (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Foreign key to incident
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,

    -- VirtualService details
    vs_name VARCHAR(128) NOT NULL,
    vs_namespace VARCHAR(128) NOT NULL,

    -- Target information
    attacker_ip INET NOT NULL,
    honeypot_destination TEXT NOT NULL,

    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,

    -- Status
    status VARCHAR(32) DEFAULT 'active'  -- active, expired, deleted
);

-- Indexes for VirtualServices
CREATE INDEX idx_vs_incident_id ON virtualservices(incident_id);
CREATE INDEX idx_vs_attacker_ip ON virtualservices(attacker_ip);
CREATE INDEX idx_vs_status ON virtualservices(status);
CREATE INDEX idx_vs_expires_at ON virtualservices(expires_at);

-- Metrics/statistics table (for dashboard queries)
CREATE TABLE IF NOT EXISTS metrics (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,

    -- Metric metadata
    metric_name VARCHAR(128) NOT NULL,
    metric_value DECIMAL(10,2) NOT NULL,
    tags JSONB,

    -- Timestamp
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for metrics
CREATE INDEX idx_metrics_name_timestamp ON metrics(metric_name, timestamp DESC);

-- Create views for common queries

-- View: Recent incidents
CREATE OR REPLACE VIEW recent_incidents AS
SELECT
    i.incident_id,
    i.attacker_ip,
    i.first_seen,
    i.detection_signature,
    i.detection_confidence,
    i.actions_count,
    i.status,
    i.severity,
    COUNT(a.id) as audit_entries
FROM incidents i
LEFT JOIN audit_log a ON i.incident_id = a.incident_id
WHERE i.first_seen >= NOW() - INTERVAL '7 days'
GROUP BY i.incident_id, i.attacker_ip, i.first_seen,
         i.detection_signature, i.detection_confidence,
         i.actions_count, i.status, i.severity
ORDER BY i.first_seen DESC;

-- View: Action statistics
CREATE OR REPLACE VIEW action_stats AS
SELECT
    action_id,
    action_name,
    action_result,
    COUNT(*) as count,
    MIN(timestamp) as first_used,
    MAX(timestamp) as last_used
FROM audit_log
GROUP BY action_id, action_name, action_result
ORDER BY count DESC;

-- View: LLM usage statistics
CREATE OR REPLACE VIEW llm_stats AS
SELECT
    DATE(timestamp) as date,
    detection_method,
    COUNT(*) as total_detections,
    SUM(CASE WHEN llm_consulted THEN 1 ELSE 0 END) as llm_consultations,
    AVG(detection_confidence) as avg_confidence
FROM audit_log
WHERE action_id LIKE '%detect%' OR detection_method IS NOT NULL
GROUP BY DATE(timestamp), detection_method
ORDER BY date DESC;

-- Grant permissions (adjust user as needed)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mirror_agent;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO mirror_agent;

-- Comments for documentation
COMMENT ON TABLE audit_log IS 'Complete audit trail of all agent actions';
COMMENT ON TABLE incidents IS 'Summary of security incidents detected by The Mirror';
COMMENT ON TABLE evidence IS 'Evidence files and OSINT data for incidents';
COMMENT ON TABLE virtualservices IS 'Istio VirtualServices created for traffic redirection';
COMMENT ON TABLE metrics IS 'Time-series metrics for monitoring and dashboards';
