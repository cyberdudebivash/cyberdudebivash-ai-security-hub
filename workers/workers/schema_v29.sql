-- CYBERDUDEBIVASH AI Security Hub — Schema v29.0.0 (FIXED)
-- Root cause: platform_metrics uses column `key` not `metric_key`,
-- and `value_int` not `metric_value` (confirmed from schema_v27.sql)
-- Safe: all IF NOT EXISTS / OR IGNORE

CREATE TABLE IF NOT EXISTS mcp_security_scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT UNIQUE NOT NULL,
  server_name  TEXT,
  server_url   TEXT,
  risk_score   INTEGER,
  risk_level   TEXT,
  grade        TEXT,
  vuln_count   INTEGER DEFAULT 0,
  result_json  TEXT,
  user_email   TEXT,
  scanned_at   TEXT NOT NULL,
  unlocked_at  TEXT,
  unlock_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_scans_email ON mcp_security_scans(user_email);
CREATE INDEX IF NOT EXISTS idx_mcp_scans_risk  ON mcp_security_scans(risk_level);

CREATE TABLE IF NOT EXISTS vibe_code_scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT UNIQUE NOT NULL,
  language     TEXT,
  line_count   INTEGER,
  risk_score   INTEGER,
  risk_level   TEXT,
  vuln_count   INTEGER DEFAULT 0,
  user_email   TEXT,
  scanned_at   TEXT NOT NULL,
  unlocked_at  TEXT,
  unlock_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_vibe_scans_email ON vibe_code_scans(user_email);
CREATE INDEX IF NOT EXISTS idx_vibe_scans_risk  ON vibe_code_scans(risk_level);

INSERT OR IGNORE INTO platform_metrics (key, value_int)
VALUES
  ('mcp_scans_total', 0),
  ('vibe_code_scans_total', 0);
