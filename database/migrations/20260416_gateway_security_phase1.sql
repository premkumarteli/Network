CREATE TABLE IF NOT EXISTS gateway_credentials (
    gateway_id VARCHAR(100) NOT NULL,
    key_version INT NOT NULL,
    secret_salt VARCHAR(64) NOT NULL,
    secret_hash CHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    rotated_at DATETIME NULL,
    last_used_at DATETIME NULL,
    PRIMARY KEY (gateway_id, key_version),
    INDEX idx_gateway_credentials_status (status)
);

CREATE TABLE IF NOT EXISTS gateway_request_nonces (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    gateway_id VARCHAR(100) NOT NULL,
    key_version INT NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    UNIQUE KEY uq_gateway_nonce (gateway_id, key_version, nonce),
    INDEX idx_gateway_nonce_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS gateways (
    gateway_id VARCHAR(100) PRIMARY KEY,
    organization_id CHAR(36) NULL,
    hostname VARCHAR(100) DEFAULT 'Unknown',
    capture_mode VARCHAR(50) DEFAULT 'promiscuous',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE gateways
    ADD COLUMN IF NOT EXISTS organization_id CHAR(36) NULL AFTER gateway_id,
    ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER capture_mode;
