ALTER TABLE flow_ingest_batches
    ADD COLUMN batch_id CHAR(64) NULL AFTER organization_id;

UPDATE flow_ingest_batches
SET batch_id = SHA2(batch_json, 256)
WHERE batch_id IS NULL OR batch_id = '';

ALTER TABLE flow_ingest_batches
    MODIFY COLUMN batch_id CHAR(64) NOT NULL;

ALTER TABLE flow_ingest_batches
    ADD UNIQUE KEY uniq_flow_ingest_batch_id (batch_id);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id VARCHAR(100) PRIMARY KEY,
    worker_type VARCHAR(32) NOT NULL,
    last_seen DATETIME NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_worker_heartbeats_type_seen (worker_type, last_seen)
);
