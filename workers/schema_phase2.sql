-- CYBERDUDEBIVASH® AI Security Hub
-- Phase 2 Schema Migration — ADDITIVE ONLY
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_phase2.sql
-- Safe to run multiple times (CREATE TABLE IF NOT EXISTS)
-- Zero modifications to any existing tables.

-- ── SOC Case Management ─────────────────────────────────────────────────────
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

CREATE INDEX IF NOT EXISTS idx_soc_cases_status    ON soc_cases(status);
CREATE INDEX IF NOT EXISTS idx_soc_cases_severity  ON soc_cases(severity);
CREATE INDEX IF NOT EXISTS idx_soc_cases_org_id    ON soc_cases(org_id);
CREATE INDEX IF NOT EXISTS idx_soc_cases_created   ON soc_cases(created_at DESC);

-- ── SOC Case Comments / Timeline ────────────────────────────────────────────
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

CREATE INDEX IF NOT EXISTS idx_comments_case_id  ON soc_case_comments(case_id);
CREATE INDEX IF NOT EXISTS idx_comments_created  ON soc_case_comments(created_at DESC);

-- ── CTI Threat Actors ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cti_actors (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  aliases           TEXT DEFAULT '[]',
  nation_state      TEXT,
  motivation        TEXT,
  sophistication    TEXT DEFAULT 'UNKNOWN',
  active_since      TEXT,
  known_techniques  TEXT DEFAULT '[]',
  known_tools       TEXT DEFAULT '[]',
  target_sectors    TEXT DEFAULT '[]',
  description       TEXT,
  mitre_group_id    TEXT,
  threat_level      TEXT DEFAULT 'MEDIUM',
  confidence_score  INTEGER DEFAULT 50,
  last_active       TEXT,
  source            TEXT DEFAULT 'sentinel_apex',
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_actors_threat_level ON cti_actors(threat_level);
CREATE INDEX IF NOT EXISTS idx_actors_nation       ON cti_actors(nation_state);

-- ── CTI IOC Database ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cti_iocs (
  id               TEXT PRIMARY KEY,
  ioc_type         TEXT NOT NULL CHECK(ioc_type IN ('IP','DOMAIN','HASH_MD5','HASH_SHA1','HASH_SHA256','URL','EMAIL','CVE','BITCOIN_ADDR')),
  value            TEXT NOT NULL,
  severity         TEXT DEFAULT 'MEDIUM' CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  source           TEXT DEFAULT 'manual',
  first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen        TEXT NOT NULL DEFAULT (datetime('now')),
  last_checked     TEXT,
  tags             TEXT DEFAULT '[]',
  related_actor_id TEXT REFERENCES cti_actors(id),
  related_campaign TEXT,
  confidence       INTEGER DEFAULT 50,
  reputation_score INTEGER DEFAULT 0,
  geo_country      TEXT,
  geo_asn          TEXT,
  whois_snapshot   TEXT,
  is_active        INTEGER DEFAULT 1,
  false_positive   INTEGER DEFAULT 0,
  notes            TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON cti_iocs(ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_severity          ON cti_iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_actor             ON cti_iocs(related_actor_id);
CREATE INDEX IF NOT EXISTS idx_iocs_created           ON cti_iocs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_active            ON cti_iocs(is_active);

-- ── MSSP Customer Registry ───────────────────────────────────────────────────
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

-- ── Revenue Snapshots (for trend charts) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS revenue_snapshots (
  id          TEXT PRIMARY KEY,
  snapshot_at TEXT NOT NULL,
  period      TEXT NOT NULL,
  mrr_cents   INTEGER DEFAULT 0,
  arr_cents   INTEGER DEFAULT 0,
  new_mrr     INTEGER DEFAULT 0,
  churned_mrr INTEGER DEFAULT 0,
  expansion   INTEGER DEFAULT 0,
  total_subscribers INTEGER DEFAULT 0,
  free_count  INTEGER DEFAULT 0,
  pro_count   INTEGER DEFAULT 0,
  enterprise_count INTEGER DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_period ON revenue_snapshots(period);
CREATE INDEX IF NOT EXISTS idx_snapshots_at ON revenue_snapshots(snapshot_at DESC);
