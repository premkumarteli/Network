ALTER TABLE flow_logs
    ADD COLUMN sni VARCHAR(255) NULL AFTER domain;

CREATE INDEX idx_flow_logs_sni_last_seen
    ON flow_logs (sni, last_seen);
