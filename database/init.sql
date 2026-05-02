-- NetVisor MVP Database Schema
CREATE DATABASE IF NOT EXISTS network_security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE network_security;

CREATE TABLE IF NOT EXISTS organizations (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(20) DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    role VARCHAR(20) DEFAULT 'viewer',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP,
    organization_id CHAR(36),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(100),
    hostname VARCHAR(100),
    api_key TEXT,
    organization_id CHAR(36),
    ip_address VARCHAR(50),
    os_family VARCHAR(50),
    version VARCHAR(50),
    inspection_enabled BOOLEAN DEFAULT FALSE,
    inspection_status VARCHAR(32) DEFAULT 'disabled',
    inspection_proxy_running BOOLEAN DEFAULT FALSE,
    inspection_ca_installed BOOLEAN DEFAULT FALSE,
    inspection_browsers_json TEXT,
    inspection_last_error TEXT,
    inspection_metrics_json TEXT,
    last_seen DATETIME,
    cpu_usage FLOAT DEFAULT 0.0,
    ram_usage FLOAT DEFAULT 0.0,
    INDEX idx_agents_org_last_seen (organization_id, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS agent_enrollment_requests (
    request_id CHAR(36) PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    organization_id CHAR(36),
    hostname VARCHAR(100) DEFAULT 'Unknown',
    device_ip VARCHAR(50) DEFAULT '-',
    device_mac VARCHAR(50) DEFAULT '-',
    os_family VARCHAR(50) DEFAULT 'Unknown',
    agent_version VARCHAR(50) DEFAULT 'Unknown',
    bootstrap_method VARCHAR(32) DEFAULT 'bootstrap',
    source_ip VARCHAR(50),
    machine_fingerprint CHAR(64),
    status VARCHAR(20) NOT NULL DEFAULT 'pending_review',
    attempt_count INT NOT NULL DEFAULT 0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    reviewed_by VARCHAR(100),
    reviewed_at DATETIME NULL,
    review_reason TEXT,
    credential_issued_at DATETIME NULL,
    UNIQUE KEY uq_agent_enrollment_agent (agent_id),
    INDEX idx_agent_enrollment_status_last_seen (status, last_seen),
    INDEX idx_agent_enrollment_org_last_seen (organization_id, last_seen),
    INDEX idx_agent_enrollment_fingerprint (machine_fingerprint),
    INDEX idx_agent_enrollment_expires_at (expires_at),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    agent_id VARCHAR(100) NOT NULL,
    key_version INT NOT NULL,
    secret_salt VARCHAR(64) NOT NULL,
    secret_hash CHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    rotated_at DATETIME NULL,
    last_used_at DATETIME NULL,
    PRIMARY KEY (agent_id, key_version),
    INDEX idx_agent_credentials_status (status)
);

CREATE TABLE IF NOT EXISTS agent_request_nonces (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    key_version INT NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    UNIQUE KEY uq_agent_nonce (agent_id, key_version, nonce),
    INDEX idx_agent_nonce_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS managed_devices (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    organization_id CHAR(36),
    device_ip VARCHAR(50) NOT NULL,
    device_mac VARCHAR(50) DEFAULT '-',
    hostname VARCHAR(100) DEFAULT 'Unknown',
    os_family VARCHAR(50) DEFAULT 'Unknown',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_managed_agent_ip_org (agent_id, device_ip, organization_id),
    UNIQUE KEY uq_managed_ip_org (device_ip, organization_id),
    INDEX idx_managed_agent_last_seen (agent_id, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS gateways (
    gateway_id VARCHAR(100) PRIMARY KEY,
    organization_id CHAR(36) NULL,
    hostname VARCHAR(100) DEFAULT 'Unknown',
    capture_mode VARCHAR(50) DEFAULT 'promiscuous',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS flow_ingest_batches (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    source_type VARCHAR(16) NOT NULL,
    source_id VARCHAR(100),
    organization_id CHAR(36),
    batch_id CHAR(64) NOT NULL,
    batch_json LONGTEXT NOT NULL,
    flow_count INT NOT NULL DEFAULT 1,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt_count INT NOT NULL DEFAULT 0,
    available_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_by VARCHAR(100),
    claimed_at DATETIME NULL,
    processed_at DATETIME NULL,
    last_error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_flow_ingest_batch_id (batch_id),
    INDEX idx_flow_ingest_status_available (status, available_at, id),
    INDEX idx_flow_ingest_created_at (created_at),
    INDEX idx_flow_ingest_source (source_type, source_id, created_at),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id VARCHAR(100) PRIMARY KEY,
    worker_type VARCHAR(32) NOT NULL,
    last_seen DATETIME NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_worker_heartbeats_type_seen (worker_type, last_seen)
);

CREATE TABLE IF NOT EXISTS flow_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36),
    src_ip VARCHAR(50) NOT NULL,
    dst_ip VARCHAR(50) NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(10),
    start_time DATETIME,
    last_seen DATETIME,
    packet_count INT,
    byte_count BIGINT,
    duration FLOAT,
    average_packet_size FLOAT,
    domain VARCHAR(255),
    sni VARCHAR(255),
    src_mac VARCHAR(20),
    dst_mac VARCHAR(20),
    network_scope VARCHAR(20) NOT NULL DEFAULT 'unknown',
    internal_device_ip VARCHAR(50),
    external_endpoint_ip VARCHAR(50),
    session_id CHAR(40),
    application VARCHAR(50) NOT NULL DEFAULT 'Other',
    agent_id VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_flow_logs_org (organization_id),
    INDEX idx_flow_logs_src (src_ip),
    INDEX idx_flow_logs_dst (dst_ip),
    INDEX idx_flow_logs_last_seen (last_seen),
    INDEX idx_flow_logs_org_last_seen (organization_id, last_seen),
    INDEX idx_flow_logs_internal_last_seen (internal_device_ip, last_seen),
    INDEX idx_flow_logs_scope_last_seen (network_scope, last_seen),
    INDEX idx_flow_logs_org_app_last_seen (organization_id, application, last_seen),
    INDEX idx_flow_logs_app_src_last_seen (application, src_ip, last_seen),
    INDEX idx_flow_logs_domain_last_seen (domain, last_seen),
    INDEX idx_flow_logs_sni_last_seen (sni, last_seen),
    INDEX idx_flow_logs_session_id (session_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36),
    device_ip VARCHAR(50),
    severity VARCHAR(20),
    risk_score FLOAT,
    breakdown_json TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    INDEX idx_alerts_org (organization_id),
    INDEX idx_alerts_device (device_ip),
    INDEX idx_alerts_timestamp (timestamp),
    INDEX idx_alerts_org_device_severity_time (organization_id, device_ip, severity, timestamp),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(50) NOT NULL,
    mac VARCHAR(20) NOT NULL,
    hostname VARCHAR(255) DEFAULT 'Unknown',
    vendor VARCHAR(255) DEFAULT 'Unknown',
    device_type VARCHAR(50) DEFAULT 'Unknown',
    os_family VARCHAR(50) DEFAULT 'Unknown',
    is_online BOOLEAN DEFAULT TRUE,
    organization_id CHAR(36),
    agent_id VARCHAR(100),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_mac_org (mac, organization_id),
    INDEX idx_devices_ip (ip),
    INDEX idx_devices_org_last_seen (organization_id, last_seen),
    INDEX idx_devices_agent_org_last_seen (agent_id, organization_id, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS device_ip_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_mac VARCHAR(20) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    organization_id CHAR(36),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_device_ip_history (device_mac, ip_address, organization_id),
    INDEX idx_device_ip_history_org_last_seen (organization_id, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS external_endpoints (
    endpoint_ip VARCHAR(50) PRIMARY KEY,
    organization_id CHAR(36),
    last_domain VARCHAR(255),
    last_application VARCHAR(50),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_flows BIGINT DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    INDEX idx_external_endpoints_org_last_seen (organization_id, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id CHAR(40) PRIMARY KEY,
    organization_id CHAR(36),
    device_ip VARCHAR(50) NOT NULL,
    device_mac VARCHAR(20),
    external_ip VARCHAR(50),
    application VARCHAR(50) NOT NULL DEFAULT 'Other',
    domain VARCHAR(255),
    protocol VARCHAR(10),
    source_type VARCHAR(16) DEFAULT 'agent',
    total_packets BIGINT DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    duration FLOAT DEFAULT 0,
    INDEX idx_sessions_org_last_seen (organization_id, last_seen),
    INDEX idx_sessions_device_last_seen (device_ip, last_seen),
    INDEX idx_sessions_app_last_seen (application, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS inspection_policies (
    agent_id VARCHAR(100) NOT NULL,
    device_ip VARCHAR(50) NOT NULL,
    organization_id CHAR(36),
    inspection_enabled BOOLEAN DEFAULT FALSE,
    allowed_processes_json TEXT,
    allowed_domains_json TEXT,
    snippet_max_bytes INT DEFAULT 256,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_id, device_ip),
    INDEX idx_inspection_policies_device (device_ip),
    INDEX idx_inspection_policies_org (organization_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS web_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36),
    agent_id VARCHAR(100) NOT NULL,
    device_ip VARCHAR(50) NOT NULL,
    process_name VARCHAR(100) NOT NULL,
    browser_name VARCHAR(100) NOT NULL,
    page_url TEXT NOT NULL,
    base_domain VARCHAR(255) NOT NULL,
    page_title VARCHAR(255) DEFAULT 'Untitled',
    content_category VARCHAR(100) DEFAULT 'web',
    content_id VARCHAR(255),
    search_query VARCHAR(255),
    http_method VARCHAR(16) DEFAULT 'GET',
    status_code INT,
    content_type VARCHAR(120),
    request_bytes INT DEFAULT 0,
    response_bytes INT DEFAULT 0,
    snippet_redacted TEXT,
    snippet_hash VARCHAR(64),
    confidence_score FLOAT DEFAULT 0.0,
    event_count INT DEFAULT 1,
    first_seen DATETIME,
    last_seen DATETIME,
    risk_level VARCHAR(20) DEFAULT 'safe',
    threat_msg VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_web_events_device_last_seen (device_ip, last_seen),
    INDEX idx_web_events_agent_last_seen (agent_id, last_seen),
    INDEX idx_web_events_org_last_seen (organization_id, last_seen),
    INDEX idx_web_events_base_domain_last_seen (base_domain, last_seen),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS device_aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(50),
    device_name VARCHAR(100),
    organization_id CHAR(36),
    UNIQUE KEY uq_device_alias (ip_address, organization_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS device_risks (
    device_id VARCHAR(50) PRIMARY KEY,
    current_score FLOAT DEFAULT 0,
    risk_level VARCHAR(20) DEFAULT 'LOW',
    reasons TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_baselines (
    device_id VARCHAR(100) PRIMARY KEY,
    organization_id CHAR(36),
    ip_address VARCHAR(50),
    avg_connections_per_min FLOAT DEFAULT 0,
    avg_unique_destinations FLOAT DEFAULT 0,
    avg_flow_duration FLOAT DEFAULT 0,
    std_dev_connections FLOAT DEFAULT 0,
    last_computed DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value VARCHAR(20) NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36),
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_logs_org (organization_id),
    INDEX idx_audit_logs_created_at (created_at),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

INSERT INTO organizations (id, name, status)
VALUES ('default-org-id', 'Default Organization', 'active')
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    status = VALUES(status);

INSERT INTO system_settings (setting_key, setting_value)
VALUES
    ('monitoring_active', 'true'),
    ('maintenance_mode', 'false')
ON DUPLICATE KEY UPDATE
    setting_value = VALUES(setting_value);
