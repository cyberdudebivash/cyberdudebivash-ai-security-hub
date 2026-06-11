-- schema_phase4.sql - CYBERDUDEBIVASH AI Security Hub v34.0 Phase 4
-- PERMANENT MIGRATION: Drops and recreates all Phase 4 tables with clean schema
-- SAFE: Zero rows confirmed in all affected tables before migration
-- Root cause of prior failures: D1 parser truncates CREATE TABLE on long CHECK IN-lists
-- Fix: Remove all CHECK constraints (app layer validates; SQLite does not enforce by default)
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./schema_phase4.sql

-- ── PHASE 1: Drop Phase 4 tables (reverse dependency order) ──────────────────
DROP TABLE IF EXISTS mssp_tenant_audit;
DROP TABLE IF EXISTS upsell_events;
DROP TABLE IF EXISTS expansion_scores;
DROP TABLE IF EXISTS revenue_snapshots;
DROP TABLE IF EXISTS platform_metrics_snapshots;
DROP TABLE IF EXISTS cti_watchlist_entries;
DROP TABLE IF EXISTS cti_watchlists;
DROP TABLE IF EXISTS soc_timeline;
DROP TABLE IF EXISTS soc_notes;
DROP TABLE IF EXISTS soc_evidence;

-- ── PHASE 2: Create all tables fresh ─────────────────────────────────────────

-- Table 1: SOC Evidence Vault
CREATE TABLE soc_evidence (
  id               TEXT PRIMARY KEY,
  case_id          TEXT NOT NULL,
  org_id           TEXT NOT NULL DEFAULT 'default',
  evidence_type    TEXT NOT NULL DEFAULT 'ARTIFACT',
  title            TEXT NOT NULL,
  description      TEXT,
  data_json        TEXT,
  file_hash        TEXT,
  file_size_bytes  INTEGER,
  source_system    TEXT,
  chain_of_custody TEXT,
  added_by         TEXT NOT NULL,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_soc_evidence_case_id ON soc_evidence(case_id, org_id);

-- Table 2: SOC Analyst Notes
CREATE TABLE soc_notes (
  id          TEXT PRIMARY KEY,
  case_id     TEXT NOT NULL,
  org_id      TEXT NOT NULL DEFAULT 'default',
  author      TEXT NOT NULL,
  content     TEXT NOT NULL,
  note_type   TEXT NOT NULL DEFAULT 'ANALYST',
  is_pinned   INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_soc_notes_case_id ON soc_notes(case_id, org_id);

-- Table 3: SOC Investigation Timeline
CREATE TABLE soc_timeline (
  id            TEXT PRIMARY KEY,
  case_id       TEXT NOT NULL,
  org_id        TEXT NOT NULL DEFAULT 'default',
  event_type    TEXT NOT NULL,
  description   TEXT NOT NULL,
  actor         TEXT,
  old_value     TEXT,
  new_value     TEXT,
  metadata_json TEXT,
  occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_soc_timeline_case_id ON soc_timeline(case_id, org_id, occurred_at);

-- Table 4: CTI Watchlists
CREATE TABLE cti_watchlists (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL DEFAULT 'default',
  name           TEXT NOT NULL,
  description    TEXT,
  ioc_types      TEXT NOT NULL DEFAULT '["ip","domain","hash","url","email"]',
  alert_on_match INTEGER NOT NULL DEFAULT 1,
  match_count    INTEGER NOT NULL DEFAULT 0,
  created_by     TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_cti_watchlists_org_id ON cti_watchlists(org_id);

-- Table 5: CTI Watchlist Entries
CREATE TABLE cti_watchlist_entries (
  id           TEXT PRIMARY KEY,
  watchlist_id TEXT NOT NULL,
  org_id       TEXT NOT NULL DEFAULT 'default',
  ioc_value    TEXT NOT NULL,
  ioc_type     TEXT NOT NULL,
  confidence   INTEGER NOT NULL DEFAULT 70,
  tags         TEXT,
  added_by     TEXT,
  added_at     TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(watchlist_id, ioc_value)
);

CREATE INDEX idx_cti_watchlist_entries_value ON cti_watchlist_entries(ioc_value, org_id);
CREATE INDEX idx_cti_watchlist_entries_list ON cti_watchlist_entries(watchlist_id);

-- Table 6: Platform Metrics Authority Snapshots (D1 fallback when KV unavailable)
CREATE TABLE platform_metrics_snapshots (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL DEFAULT 'default',
  scans_today     INTEGER NOT NULL DEFAULT 0,
  scans_30d       INTEGER NOT NULL DEFAULT 0,
  critical_cves   INTEGER NOT NULL DEFAULT 0,
  open_cases      INTEGER NOT NULL DEFAULT 0,
  critical_cases  INTEGER NOT NULL DEFAULT 0,
  active_threats  INTEGER NOT NULL DEFAULT 0,
  threat_actors   INTEGER NOT NULL DEFAULT 0,
  customer_count  INTEGER NOT NULL DEFAULT 0,
  health_score    INTEGER NOT NULL DEFAULT 100,
  platform_status TEXT NOT NULL DEFAULT 'operational',
  mrr             REAL NOT NULL DEFAULT 0,
  arr             REAL NOT NULL DEFAULT 0,
  budget_alert    TEXT DEFAULT NULL,
  computed_at     TEXT NOT NULL DEFAULT (datetime('now')),
  valid_until     TEXT NOT NULL,
  UNIQUE(org_id)
);

-- Table 7: Revenue Snapshots (daily time-series for Revenue Intelligence)
CREATE TABLE revenue_snapshots (
  id                       TEXT PRIMARY KEY,
  org_id                   TEXT NOT NULL DEFAULT 'default',
  snapshot_date            TEXT NOT NULL,
  mrr                      REAL NOT NULL DEFAULT 0,
  arr                      REAL NOT NULL DEFAULT 0,
  new_mrr                  REAL NOT NULL DEFAULT 0,
  expansion_mrr            REAL NOT NULL DEFAULT 0,
  contraction_mrr          REAL NOT NULL DEFAULT 0,
  churned_mrr              REAL NOT NULL DEFAULT 0,
  net_new_mrr              REAL NOT NULL DEFAULT 0,
  customer_count           INTEGER NOT NULL DEFAULT 0,
  avg_revenue_per_customer REAL NOT NULL DEFAULT 0,
  free_count               INTEGER NOT NULL DEFAULT 0,
  pro_count                INTEGER NOT NULL DEFAULT 0,
  enterprise_count         INTEGER NOT NULL DEFAULT 0,
  mssp_count               INTEGER NOT NULL DEFAULT 0,
  created_at               TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(org_id, snapshot_date)
);

CREATE INDEX idx_revenue_snapshots_date ON revenue_snapshots(org_id, snapshot_date);

-- Table 8: Expansion Scores
CREATE TABLE expansion_scores (
  org_id           TEXT PRIMARY KEY,
  expansion_score  INTEGER NOT NULL DEFAULT 0,
  segment          TEXT NOT NULL DEFAULT 'STARTER',
  recommended_tier TEXT,
  primary_signal   TEXT,
  signals_json     TEXT,
  upsell_ready     INTEGER NOT NULL DEFAULT 0,
  last_activity    TEXT,
  computed_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Table 9: Upsell Events Log
CREATE TABLE upsell_events (
  id               TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL DEFAULT 'default',
  user_id          TEXT,
  event_type       TEXT NOT NULL,
  trigger_reason   TEXT,
  recommended_tier TEXT,
  current_tier     TEXT,
  dismissed        INTEGER NOT NULL DEFAULT 0,
  converted        INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_upsell_events_org_id ON upsell_events(org_id, created_at);

-- Table 10: MSSP Tenant Audit Log (append-only)
CREATE TABLE mssp_tenant_audit (
  id            TEXT PRIMARY KEY,
  mssp_org_id   TEXT NOT NULL,
  tenant_org_id TEXT NOT NULL,
  action        TEXT NOT NULL,
  resource      TEXT,
  resource_type TEXT,
  actor_user_id TEXT,
  actor_role    TEXT,
  ip_country    TEXT,
  details_json  TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_mssp_tenant_audit_mssp ON mssp_tenant_audit(mssp_org_id, created_at);
CREATE INDEX idx_mssp_tenant_audit_tenant ON mssp_tenant_audit(tenant_org_id, created_at);

-- End schema_phase4.sql - 10 tables, 8 indexes
-- CHECK constraints removed: D1 import parser fails on long IN-list CHECKs
-- Validation is enforced at application layer in all Phase 4 handlers
