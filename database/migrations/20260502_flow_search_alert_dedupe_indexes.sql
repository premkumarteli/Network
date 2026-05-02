CREATE INDEX idx_flow_logs_dst
    ON flow_logs (dst_ip);

CREATE INDEX idx_flow_logs_org_last_seen
    ON flow_logs (organization_id, last_seen);

CREATE INDEX idx_flow_logs_domain_last_seen
    ON flow_logs (domain, last_seen);

CREATE INDEX idx_alerts_org_device_severity_time
    ON alerts (organization_id, device_ip, severity, timestamp);
