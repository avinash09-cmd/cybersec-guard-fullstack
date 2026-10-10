-- CyberSecGuard database schema (MySQL)
-- Note: tables are also auto-created by SQLAlchemy via database.init_db(),
-- this file is provided for reference / manual setup / resume talking points.

CREATE DATABASE IF NOT EXISTS cybersecguard;
USE cybersecguard;

CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    engine VARCHAR(32) DEFAULT 'nmap',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    port INT NOT NULL,
    service VARCHAR(64),
    banner TEXT,
    risk_note TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS traffic_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    engine VARCHAR(32) DEFAULT 'tshark',
    packet_count INT DEFAULT 0,
    protocol_summary TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS traffic_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id INT,
    alert_type VARCHAR(64),
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES traffic_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vault_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bcrypt_hash VARCHAR(255) NOT NULL,
    pbkdf2_salt VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    encrypted_password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
