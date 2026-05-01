ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS inspection_metrics_json TEXT NULL AFTER inspection_last_error,
    ADD COLUMN IF NOT EXISTS cpu_usage FLOAT DEFAULT 0.0 AFTER last_seen,
    ADD COLUMN IF NOT EXISTS ram_usage FLOAT DEFAULT 0.0 AFTER cpu_usage;

ALTER TABLE gateways
    ADD COLUMN IF NOT EXISTS organization_id CHAR(36) NULL AFTER gateway_id,
    ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER capture_mode;

ALTER TABLE web_events
    ADD COLUMN IF NOT EXISTS search_query VARCHAR(255) NULL AFTER content_id,
    ADD COLUMN IF NOT EXISTS confidence_score FLOAT DEFAULT 0.0 AFTER snippet_hash,
    ADD COLUMN IF NOT EXISTS event_count INT DEFAULT 1 AFTER confidence_score,
    ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20) DEFAULT 'safe' AFTER last_seen,
    ADD COLUMN IF NOT EXISTS threat_msg VARCHAR(255) NULL AFTER risk_level;

CREATE INDEX idx_devices_org_last_seen
    ON devices (organization_id, last_seen);

CREATE INDEX idx_device_ip_history_org_last_seen
    ON device_ip_history (organization_id, last_seen);

CREATE UNIQUE INDEX uq_managed_agent_ip_org
    ON managed_devices (agent_id, device_ip, organization_id);

CREATE INDEX idx_managed_agent_last_seen
    ON managed_devices (agent_id, last_seen);

-- Existing databases with the legacy managed_devices primary key on agent_id
-- require the companion Python migration script to add the id column safely:
-- database/migrations/apply_20260417_runtime_schema_phase2.py
