-- Targeted, drift-safe slice of schema_phase2.sql — creates ONLY the missing
-- owner-tool tables (soc_cases, soc_case_comments, mssp_customers) that crash
-- /api/soc/cases (500) and /api/mssp/* (no-response) in production.
-- Excludes the revenue_snapshots index that referenced a `period` column absent
-- from the already-existing (drifted) revenue_snapshots table, which caused the
-- full schema_phase2.sql / schema_master.sql applies to roll back.
-- Idempotent (CREATE TABLE/INDEX IF NOT EXISTS); touches no existing tables.

CREATE TABLE IF NOT EXISTS soc_cases (
  id            TEXT PRIMARY KEY,
  case_number   TEXT UNIQUE NOT NULL,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  status        TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','IN_PROGRESS','ESCALATED','RESOLVED','CLOSED')),
  assignee_id   TEXT,
  org_id        TEXT DEFAULT 'default',
  source        TEXT NOT NULL DEFAULT 'manual',
  alert_ids     TEXT DEFAULT '[]',
  ioc_list      TEXT DEFAULT '[]',
  mitre_tactics TEXT DEFAULT '[]',
  playbook_id   TEXT,
  summary       TEXT,
  resolution    TEXT,
  sla_hours     INTEGER DEFAULT 72,
  sla_due_at    TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_soc_cases_status   ON soc_cases(status);
CREATE INDEX IF NOT EXISTS idx_soc_cases_severity ON soc_cases(severity);
CREATE INDEX IF NOT EXISTS idx_soc_cases_org_id   ON soc_cases(org_id);
CREATE INDEX IF NOT EXISTS idx_soc_cases_created  ON soc_cases(created_at DESC);

CREATE TABLE IF NOT EXISTS soc_case_comments (
  id           TEXT PRIMARY KEY,
  case_id      TEXT NOT NULL REFERENCES soc_cases(id) ON DELETE CASCADE,
  author_id    TEXT NOT NULL DEFAULT 'system',
  author_name  TEXT,
  body         TEXT NOT NULL,
  comment_type TEXT DEFAULT 'note' CHECK(comment_type IN ('note','action','escalation','resolution','system')),
  visibility   TEXT DEFAULT 'internal' CHECK(visibility IN ('internal','external')),
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_comments_case_id ON soc_case_comments(case_id);
CREATE INDEX IF NOT EXISTS idx_comments_created ON soc_case_comments(created_at DESC);

CREATE TABLE IF NOT EXISTS mssp_customers (
  id               TEXT PRIMARY KEY,
  org_name         TEXT NOT NULL,
  org_slug         TEXT UNIQUE NOT NULL,
  contact_name     TEXT,
  contact_email    TEXT,
  tier             TEXT DEFAULT 'starter' CHECK(tier IN ('starter','pro','enterprise','custom')),
  status           TEXT DEFAULT 'active' CHECK(status IN ('active','inactive','onboarding','offboarding')),
  risk_score       INTEGER DEFAULT 50,
  compliance_score INTEGER DEFAULT 50,
  assigned_users   TEXT DEFAULT '[]',
  config_json      TEXT DEFAULT '{}',
  notes            TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  last_activity_at TEXT,
  contract_start   TEXT,
  contract_end     TEXT,
  mrr_cents        INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_slug ON mssp_customers(org_slug);
CREATE INDEX IF NOT EXISTS idx_customers_status      ON mssp_customers(status);
CREATE INDEX IF NOT EXISTS idx_customers_risk        ON mssp_customers(risk_score DESC);
