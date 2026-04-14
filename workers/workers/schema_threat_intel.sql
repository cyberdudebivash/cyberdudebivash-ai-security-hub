-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Threat Intelligence Schema v1.0 (FIXED)
-- ═══════════════════════════════════════════════════════════════════════════
--
-- PRODUCTION-SAFE: Contains ONLY threat-intel-specific tables.
--
-- REMOVED (owned by schema_gtm_only.sql — already in live D1):
--   leads, funnel_events, email_sequences, email_tracking, content_queue,
--   api_usage_log, sales_outreach, billing_events, growth_analytics,
--   api_keys (owned by schema.sql)
--
-- All removed tables had index definitions referencing columns that do not
-- exist on the already-created versions of those tables in D1, causing
-- SQLITE_ERROR on D1 atomic transaction rollback.
--
-- ═══════════════════════════════════════════════════════════════════════════

-- ─── Threat Intelligence ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel (
  id                 TEXT PRIMARY KEY,
  title              TEXT NOT NULL,
  severity           TEXT NOT NULL DEFAULT 'MEDIUM',
  cvss               REAL,
  cvss_vector        TEXT,
  description        TEXT,
  source             TEXT NOT NULL,
  source_url         TEXT,
  published_at       TEXT,
  exploit_status     TEXT DEFAULT 'unconfirmed',
  known_ransomware   INTEGER DEFAULT 0,
  tags               TEXT DEFAULT '[]',
  iocs               TEXT DEFAULT '[]',
  affected_products  TEXT DEFAULT '[]',
  weakness_types     TEXT DEFAULT '[]',
  enriched           INTEGER DEFAULT 0,
  epss_score         REAL,
  epss_percentile    REAL,
  actively_exploited INTEGER DEFAULT 0,
  exploit_available  INTEGER DEFAULT 0,
  ioc_list           TEXT DEFAULT '[]',
  created_at         TEXT DEFAULT (datetime('now')),
  updated_at         TEXT DEFAULT (datetime('now'))
);

-- ─── CVE Correlations ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_correlations (
  cve_id         TEXT PRIMARY KEY,
  related_cves   TEXT DEFAULT '[]',
  threat_actor   TEXT,
  campaign       TEXT,
  mitre_tactics  TEXT DEFAULT '[]',
  confidence     INTEGER DEFAULT 0,
  correlated_at  TEXT DEFAULT (datetime('now'))
);

-- ─── Hunting Alerts ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hunting_alerts (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  severity   TEXT NOT NULL,
  message    TEXT NOT NULL,
  evidence   TEXT DEFAULT '{}',
  resolved   INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- ─── IOC Registry ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_registry (
  id         TEXT PRIMARY KEY,
  intel_id   TEXT NOT NULL,
  type       TEXT NOT NULL,
  value      TEXT NOT NULL,
  confidence REAL DEFAULT 0.8,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (intel_id) REFERENCES threat_intel(id) ON DELETE CASCADE
);

-- ─── Ingestion Runs ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingestion_runs (
  id          TEXT PRIMARY KEY,
  ran_at      TEXT DEFAULT (datetime('now')),
  sources     TEXT DEFAULT '[]',
  inserted    INTEGER DEFAULT 0,
  updated     INTEGER DEFAULT 0,
  errors      TEXT DEFAULT '[]',
  duration_ms INTEGER,
  success     INTEGER DEFAULT 1
);

-- ─── SOC Automation Tables ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_alerts (
  id             TEXT PRIMARY KEY,
  alert_type     TEXT NOT NULL,
  severity       TEXT NOT NULL,
  cve_id         TEXT,
  title          TEXT,
  asset          TEXT,
  recommendation TEXT,
  evidence       TEXT DEFAULT '{}',
  resolved       INTEGER DEFAULT 0,
  created_at     TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS soc_decisions (
  id          TEXT PRIMARY KEY,
  cve_id      TEXT NOT NULL,
  decision    TEXT NOT NULL,
  priority    TEXT NOT NULL,
  confidence  INTEGER DEFAULT 0,
  risk_score  INTEGER DEFAULT 0,
  reason      TEXT,
  factors     TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS soc_response_actions (
  id         TEXT PRIMARY KEY,
  action     TEXT NOT NULL,
  priority   TEXT NOT NULL,
  alert_id   TEXT,
  cve_id     TEXT,
  status     TEXT DEFAULT 'recommended',
  payload    TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS soc_defense_actions (
  id             TEXT PRIMARY KEY,
  rule_id        TEXT,
  defense_action TEXT NOT NULL,
  target         TEXT,
  target_type    TEXT,
  duration       TEXT,
  status         TEXT DEFAULT 'triggered',
  payload        TEXT DEFAULT '{}',
  created_at     TEXT DEFAULT (datetime('now'))
);

-- ─── Indexes (all threat-intel-owned tables only) ───────────────────────────
CREATE INDEX IF NOT EXISTS idx_threat_intel_severity   ON threat_intel(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source     ON threat_intel(source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_published  ON threat_intel(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_created    ON threat_intel(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_exploit    ON threat_intel(exploit_status);
CREATE INDEX IF NOT EXISTS idx_threat_intel_epss       ON threat_intel(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_active     ON threat_intel(actively_exploited);
CREATE INDEX IF NOT EXISTS idx_ioc_type                ON ioc_registry(type);
CREATE INDEX IF NOT EXISTS idx_ioc_intel_id            ON ioc_registry(intel_id);
CREATE INDEX IF NOT EXISTS idx_correlation_cve         ON cve_correlations(cve_id);
CREATE INDEX IF NOT EXISTS idx_hunting_severity        ON hunting_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_hunting_resolved        ON hunting_alerts(resolved);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_severity     ON soc_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_type         ON soc_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_created      ON soc_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_decisions_priority  ON soc_decisions(priority);
CREATE INDEX IF NOT EXISTS idx_soc_decisions_created   ON soc_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_response_priority   ON soc_response_actions(priority);
CREATE INDEX IF NOT EXISTS idx_soc_defense_action      ON soc_defense_actions(defense_action);
CREATE INDEX IF NOT EXISTS idx_soc_defense_created     ON soc_defense_actions(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════
-- END: schema_threat_intel.sql
-- GTM tables (leads, funnel_events, email_sequences, email_tracking,
-- content_queue, api_usage_log, sales_outreach, billing_events,
-- growth_analytics) are owned by schema_gtm_only.sql.
-- api_keys is owned by schema.sql.
-- These must NOT be redefined here.
-- ═══════════════════════════════════════════════════════════════════════════
