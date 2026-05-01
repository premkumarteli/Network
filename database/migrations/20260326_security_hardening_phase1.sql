ALTER TABLE users
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active' AFTER role,
    ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0 AFTER status,
    ADD COLUMN IF NOT EXISTS locked_until DATETIME NULL AFTER failed_login_count,
    ADD COLUMN IF NOT EXISTS last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP AFTER locked_until;

UPDATE users
SET status = COALESCE(NULLIF(status, ''), 'active')
WHERE status IS NULL OR status = '';

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

UPDATE agents
SET api_key = NULL
WHERE api_key IS NOT NULL;
