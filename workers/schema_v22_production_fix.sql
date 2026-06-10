-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v22.0 Production Fix
-- Adds missing columns to align deployed D1 with code expectations
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v22_production_fix.sql
-- ============================================================

-- Add missing columns to threat_intel (schema v15 → v22)
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS cvss REAL;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS known_ransomware INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS exploit_status TEXT DEFAULT 'unconfirmed';
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS iocs TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS affected_products TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS weakness_types TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS enriched INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS epss_score REAL;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS epss_percentile REAL;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS actively_exploited INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS exploit_available INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS solution_generated INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN IF NOT EXISTS product_id TEXT;

-- Sync cvss from cvss_score (deployed schema uses cvss_score, ingestion writes cvss)
UPDATE threat_intel SET cvss = cvss_score WHERE cvss IS NULL AND cvss_score IS NOT NULL;
UPDATE threat_intel SET cvss_score = cvss WHERE cvss_score IS NULL AND cvss IS NOT NULL;

-- Add missing columns to scan_jobs if not present
CREATE TABLE IF NOT EXISTS scan_jobs (
  id          TEXT PRIMARY KEY,
  module      TEXT NOT NULL DEFAULT 'domain',
  target      TEXT,
  status      TEXT NOT NULL DEFAULT 'pending',
  risk_level  TEXT,
  risk_score  REAL DEFAULT 0,
  result      TEXT,
  error       TEXT,
  user_id     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created  ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_module   ON scan_jobs(module);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_user     ON scan_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status   ON scan_jobs(status);

-- Add missing columns to scan_history if not present
CREATE TABLE IF NOT EXISTS scan_history (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id     TEXT,
  job_id      TEXT,
  scan_id     TEXT,
  target      TEXT,
  module      TEXT,
  risk_score  REAL DEFAULT 0,
  risk_level  TEXT,
  grade       TEXT,
  data_source TEXT,
  status      TEXT DEFAULT 'completed',
  scanned_at  TEXT NOT NULL DEFAULT (datetime('now')),
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sh_user     ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_sh_scanned  ON scan_history(scanned_at DESC);

-- Add platform_counters table for fast stat aggregation
CREATE TABLE IF NOT EXISTS platform_counters (
  key        TEXT PRIMARY KEY,
  value      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed initial counters
INSERT OR IGNORE INTO platform_counters (key, value) VALUES ('scans_total', 0);
INSERT OR IGNORE INTO platform_counters (key, value) VALUES ('threats_detected', 0);
INSERT OR IGNORE INTO platform_counters (key, value) VALUES ('rules_generated', 0);
INSERT OR IGNORE INTO platform_counters (key, value) VALUES ('revenue_inr', 0);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_ti_cvss_v22        ON threat_intel(cvss DESC);
CREATE INDEX IF NOT EXISTS idx_ti_exploit_status  ON threat_intel(exploit_status);
CREATE INDEX IF NOT EXISTS idx_ti_known_ransomware ON threat_intel(known_ransomware);

-- ============================================================
-- END OF MIGRATION
-- Run this once via wrangler d1 execute
-- ============================================================

-- ── defense_solutions: ensure table and missing columns exist ────────────────
CREATE TABLE IF NOT EXISTS defense_solutions (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id            TEXT NOT NULL,
  title             TEXT NOT NULL,
  description       TEXT NOT NULL,
  category          TEXT NOT NULL DEFAULT 'sigma_rule',
  price_inr         INTEGER NOT NULL DEFAULT 499,
  price_usd         INTEGER NOT NULL DEFAULT 6,
  demand_score      REAL NOT NULL DEFAULT 0.5,
  severity          TEXT NOT NULL DEFAULT 'MEDIUM',
  cvss_score        REAL,
  preview           TEXT NOT NULL DEFAULT '',
  full_content_key  TEXT NOT NULL DEFAULT '',
  difficulty        TEXT NOT NULL DEFAULT 'INTERMEDIATE',
  apt_groups        TEXT,
  mitre_techniques  TEXT,
  affected_systems  TEXT,
  purchase_count    INTEGER NOT NULL DEFAULT 0,
  view_count        INTEGER NOT NULL DEFAULT 0,
  is_active         INTEGER NOT NULL DEFAULT 1,
  is_featured       INTEGER NOT NULL DEFAULT 0,
  badge             TEXT,
  generated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE defense_solutions ADD COLUMN IF NOT EXISTS is_featured INTEGER DEFAULT 0;
ALTER TABLE defense_solutions ADD COLUMN IF NOT EXISTS badge TEXT;

CREATE INDEX IF NOT EXISTS idx_ds_severity   ON defense_solutions(severity);
CREATE INDEX IF NOT EXISTS idx_ds_active     ON defense_solutions(is_active);
CREATE INDEX IF NOT EXISTS idx_ds_cve        ON defense_solutions(cve_id);
CREATE INDEX IF NOT EXISTS idx_ds_featured   ON defense_solutions(is_featured);
CREATE INDEX IF NOT EXISTS idx_ds_purchases  ON defense_solutions(purchase_count DESC);

-- ── defense_purchases: track all marketplace transactions ───────────────────
CREATE TABLE IF NOT EXISTS defense_purchases (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  solution_id       TEXT NOT NULL,
  user_id           TEXT,
  email             TEXT,
  payment_id        TEXT,
  order_id          TEXT,
  amount_inr        INTEGER,
  plan              TEXT DEFAULT 'per_product',
  status            TEXT NOT NULL DEFAULT 'pending',
  download_token    TEXT,
  download_expires  TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dp_solution   ON defense_purchases(solution_id);
CREATE INDEX IF NOT EXISTS idx_dp_status     ON defense_purchases(status);
CREATE INDEX IF NOT EXISTS idx_dp_created    ON defense_purchases(created_at DESC);
