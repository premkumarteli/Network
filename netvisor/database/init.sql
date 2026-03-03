-- NetVisor Database Schema
CREATE DATABASE IF NOT EXISTS netvisor;
USE netvisor;
-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- Users
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    organization_id CHAR(36),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
-- Agents
CREATE TABLE IF NOT EXISTS agents (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(100),
    api_key TEXT,
    organization_id CHAR(36),
    last_seen DATETIME,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
-- Flow Logs
CREATE TABLE IF NOT EXISTS flow_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36),
    src_ip VARCHAR(50),
    dst_ip VARCHAR(50),
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
    agent_id VARCHAR(100),
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id CHAR(36),
    device_ip VARCHAR(50),
    severity VARCHAR(20),
    risk_score FLOAT,
    breakdown_json TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);