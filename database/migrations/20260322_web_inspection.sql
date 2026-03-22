ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS inspection_enabled BOOLEAN DEFAULT FALSE AFTER version,
    ADD COLUMN IF NOT EXISTS inspection_status VARCHAR(32) DEFAULT 'disabled' AFTER inspection_enabled,
    ADD COLUMN IF NOT EXISTS inspection_proxy_running BOOLEAN DEFAULT FALSE AFTER inspection_status,
    ADD COLUMN IF NOT EXISTS inspection_ca_installed BOOLEAN DEFAULT FALSE AFTER inspection_proxy_running,
    ADD COLUMN IF NOT EXISTS inspection_browsers_json TEXT NULL AFTER inspection_ca_installed,
    ADD COLUMN IF NOT EXISTS inspection_last_error TEXT NULL AFTER inspection_browsers_json;

CREATE TABLE IF NOT EXISTS inspection_policies (
    agent_id VARCHAR(100) NOT NULL,
    device_ip VARCHAR(50) NOT NULL,
    organization_id CHAR(36) NULL,
    inspection_enabled BOOLEAN DEFAULT FALSE,
    allowed_processes_json TEXT,
    allowed_domains_json TEXT,
    snippet_max_bytes INT DEFAULT 256,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_id, device_ip),
    INDEX idx_inspection_policies_device (device_ip),
    INDEX idx_inspection_policies_org (organization_id)
);

CREATE TABLE IF NOT EXISTS web_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36) NULL,
    agent_id VARCHAR(100) NOT NULL,
    device_ip VARCHAR(50) NOT NULL,
    process_name VARCHAR(100) NOT NULL,
    browser_name VARCHAR(100) NOT NULL,
    page_url TEXT NOT NULL,
    base_domain VARCHAR(255) NOT NULL,
    page_title VARCHAR(255) DEFAULT 'Untitled',
    content_category VARCHAR(100) DEFAULT 'web',
    content_id VARCHAR(255) NULL,
    http_method VARCHAR(16) DEFAULT 'GET',
    status_code INT NULL,
    content_type VARCHAR(120) NULL,
    request_bytes INT DEFAULT 0,
    response_bytes INT DEFAULT 0,
    snippet_redacted TEXT NULL,
    snippet_hash VARCHAR(64) NULL,
    first_seen DATETIME NULL,
    last_seen DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_web_events_device_last_seen (device_ip, last_seen),
    INDEX idx_web_events_agent_last_seen (agent_id, last_seen),
    INDEX idx_web_events_org_last_seen (organization_id, last_seen),
    INDEX idx_web_events_base_domain_last_seen (base_domain, last_seen)
);
