-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Threat Intelligence Schema v1.0
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_threat_intel.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- Threat intelligence entries (NVD CVEs, CISA KEV, RSS advisories)
CREATE TABLE IF NOT EXISTS threat_intel (
  id              TEXT PRIMARY KEY,           -- CVE-ID or advisory ID
  title           TEXT NOT NULL,              -- short title / vulnerability name
  severity        TEXT NOT NULL DEFAULT 'MEDIUM', -- CRITICAL | HIGH | MEDIUM | LOW
  cvss            REAL,                       -- CVSS v3 base score (0.0–10.0)
  cvss_vector     TEXT,                       -- CVSS vector string
  description     TEXT,                       -- plain-text description (≤500 chars)
  source          TEXT NOT NULL,              -- 'nvd' | 'cisa_kev' | 'rss' | 'github'
  source_url      TEXT,                       -- canonical URL at source
  published_at    TEXT,                       -- ISO date string (YYYY-MM-DD)
  exploit_status  TEXT DEFAULT 'unconfirmed', -- 'confirmed' | 'poc_available' | 'unconfirmed'
  known_ransomware INTEGER DEFAULT 0,         -- 1 if associated with ransomware campaigns
  tags            TEXT DEFAULT '[]',          -- JSON array of tag strings
  iocs            TEXT DEFAULT '[]',          -- JSON array of IOC objects
  affected_products TEXT DEFAULT '[]',        -- JSON array of CPE strings
  weakness_types  TEXT DEFAULT '[]',          -- JSON array of CWE IDs
  enriched          INTEGER DEFAULT 0,          -- 1 if enrichment pass has run
  epss_score        REAL,                       -- FIRST.org EPSS score (0.0–1.0)
  epss_percentile   REAL,                       -- EPSS percentile rank
  actively_exploited INTEGER DEFAULT 0,         -- 1 if confirmed exploited in the wild
  exploit_available  INTEGER DEFAULT 0,         -- 1 if exploit/PoC is publicly available
  ioc_list          TEXT DEFAULT '[]',          -- JSON array of extracted IOC objects (enriched)
  created_at        TEXT DEFAULT (datetime('now')),
  updated_at        TEXT DEFAULT (datetime('now'))
);

-- Correlation cache — stores CVE relationship results
CREATE TABLE IF NOT EXISTS cve_correlations (
  cve_id          TEXT PRIMARY KEY,
  related_cves    TEXT DEFAULT '[]',   -- JSON: [{ id, title, severity, score }]
  threat_actor    TEXT,
  campaign        TEXT,
  mitre_tactics   TEXT DEFAULT '[]',
  confidence      INTEGER DEFAULT 0,
  correlated_at   TEXT DEFAULT (datetime('now'))
);

-- Hunting alerts — stored results of hunting engine runs
CREATE TABLE IF NOT EXISTS hunting_alerts (
  id              TEXT PRIMARY KEY,
  type            TEXT NOT NULL,
  severity        TEXT NOT NULL,
  message         TEXT NOT NULL,
  evidence        TEXT DEFAULT '{}',
  resolved        INTEGER DEFAULT 0,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- IOC (Indicator of Compromise) registry — extracted from advisories
CREATE TABLE IF NOT EXISTS ioc_registry (
  id          TEXT PRIMARY KEY,     -- UUID
  intel_id    TEXT NOT NULL,        -- FK → threat_intel.id
  type        TEXT NOT NULL,        -- 'ip' | 'domain' | 'url' | 'md5' | 'sha256' | 'sha1'
  value       TEXT NOT NULL,        -- the actual IOC value
  confidence  REAL DEFAULT 0.8,     -- 0.0–1.0 confidence score
  created_at  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (intel_id) REFERENCES threat_intel(id) ON DELETE CASCADE
);

-- Ingestion run log — track cron job history
CREATE TABLE IF NOT EXISTS ingestion_runs (
  id            TEXT PRIMARY KEY,
  ran_at        TEXT DEFAULT (datetime('now')),
  sources       TEXT DEFAULT '[]',  -- JSON array of source names attempted
  inserted      INTEGER DEFAULT 0,
  updated       INTEGER DEFAULT 0,
  errors        TEXT DEFAULT '[]',  -- JSON array of error messages
  duration_ms   INTEGER,
  success       INTEGER DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_threat_intel_severity   ON threat_intel(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source     ON threat_intel(source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_published  ON threat_intel(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_created    ON threat_intel(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_exploit    ON threat_intel(exploit_status);
CREATE INDEX IF NOT EXISTS idx_threat_intel_epss       ON threat_intel(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_active     ON threat_intel(actively_exploited);
CREATE INDEX IF NOT EXISTS idx_ioc_type               ON ioc_registry(type);
CREATE INDEX IF NOT EXISTS idx_ioc_intel_id           ON ioc_registry(intel_id);
CREATE INDEX IF NOT EXISTS idx_correlation_cve        ON cve_correlations(cve_id);
CREATE INDEX IF NOT EXISTS idx_hunting_severity       ON hunting_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_hunting_resolved       ON hunting_alerts(resolved);

-- ═══════════════════════════════════════════════════════════════════════════
-- SOC Automation Tables (Sentinel APEX v3)
-- ═══════════════════════════════════════════════════════════════════════════

-- SOC Detection Alerts — output from detectionEngine.js
CREATE TABLE IF NOT EXISTS soc_alerts (
  id              TEXT PRIMARY KEY,
  alert_type      TEXT NOT NULL,
  severity        TEXT NOT NULL,
  cve_id          TEXT,
  title           TEXT,
  asset           TEXT,
  recommendation  TEXT,
  evidence        TEXT DEFAULT '{}',   -- JSON
  resolved        INTEGER DEFAULT 0,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- AI Decision Engine Results — output from decisionEngine.js
CREATE TABLE IF NOT EXISTS soc_decisions (
  id              TEXT PRIMARY KEY,
  cve_id          TEXT NOT NULL,
  decision        TEXT NOT NULL,   -- escalate | auto_contain | fast_patch | monitor_closely | low_priority
  priority        TEXT NOT NULL,   -- P1-CRITICAL | P2-HIGH | P3-MEDIUM | P4-LOW
  confidence      INTEGER DEFAULT 0,
  risk_score      INTEGER DEFAULT 0,
  reason          TEXT,
  factors         TEXT DEFAULT '{}',   -- JSON
  created_at      TEXT DEFAULT (datetime('now'))
);

-- SOC Response Actions — output from responseEngine.js
CREATE TABLE IF NOT EXISTS soc_response_actions (
  id              TEXT PRIMARY KEY,
  action          TEXT NOT NULL,    -- block_ip | patch_advisory | waf_rule | ...
  priority        TEXT NOT NULL,    -- immediate | high | medium | low
  alert_id        TEXT,
  cve_id          TEXT,
  status          TEXT DEFAULT 'recommended',
  payload         TEXT DEFAULT '{}',    -- JSON
  created_at      TEXT DEFAULT (datetime('now'))
);

-- Autonomous Defense Actions — output from defenseEngine.js
CREATE TABLE IF NOT EXISTS soc_defense_actions (
  id              TEXT PRIMARY KEY,
  rule_id         TEXT,
  defense_action  TEXT NOT NULL,    -- auto_block | waf_deploy | isolate_segment | ...
  target          TEXT,
  target_type     TEXT,
  duration        TEXT,
  status          TEXT DEFAULT 'triggered',
  payload         TEXT DEFAULT '{}',   -- JSON
  created_at      TEXT DEFAULT (datetime('now'))
);

-- SOC indexes
CREATE INDEX IF NOT EXISTS idx_soc_alerts_severity    ON soc_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_type        ON soc_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_created     ON soc_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_decisions_priority ON soc_decisions(priority);
CREATE INDEX IF NOT EXISTS idx_soc_decisions_created  ON soc_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_response_priority  ON soc_response_actions(priority);
CREATE INDEX IF NOT EXISTS idx_soc_defense_action     ON soc_defense_actions(defense_action);
CREATE INDEX IF NOT EXISTS idx_soc_defense_created    ON soc_defense_actions(created_at DESC);

-- Migration: add new columns to existing threat_intel table (safe — ignored if already exist)
-- Run these if upgrading from schema v1.0:
-- ALTER TABLE threat_intel ADD COLUMN epss_score REAL;
-- ALTER TABLE threat_intel ADD COLUMN epss_percentile REAL;
-- ALTER TABLE threat_intel ADD COLUMN actively_exploited INTEGER DEFAULT 0;
-- ALTER TABLE threat_intel ADD COLUMN exploit_available INTEGER DEFAULT 0;
-- ALTER TABLE threat_intel ADD COLUMN ioc_list TEXT DEFAULT '[]';
