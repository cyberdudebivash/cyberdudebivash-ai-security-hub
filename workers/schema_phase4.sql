-- ============================================================
-- CYBERDUDEBIVASH® AI Security Hub
-- schema_phase4.sql — God Mode Phase 4 Additive Schema
-- ALL CREATE TABLE IF NOT EXISTS — safe to run repeatedly
-- Never modifies existing tables
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_phase4.sql
-- ============================================================

-- ── 1. SOC Evidence Vault ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_evidence (
  id               TEXT PRIMARY KEY,
  case_id          TEXT NOT NULL,
  org_id           TEXT NOT NULL DEFAULT 'default',
  evidence_type    TEXT NOT NULL DEFAULT 'ARTIFACT'
                   CHECK(evidence_type IN ('FILE','LOG','SCREENSHOT','NETWORK_CAPTURE',
                                           'MEMORY_DUMP','IOC','NOTE','ARTIFACT','PCAP','REGISTRY')),
  title            TEXT NOT NULL,
  description      TEXT,
  data_json        TEXT,                    -- metadata, not raw file content
  file_hash        TEXT,                    -- SHA-256 of original artifact
  file_size_bytes  INTEGER,
  source_system    TEXT,                    -- e.g. 'SIEM', 'EDR', 'MANUAL'
  chain_of_custody TEXT,                    -- JSON array of custody events
  added_by         TEXT NOT NULL,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_evidence_case_id ON soc_evidence(case_id, org_id);

-- ── 2. SOC Analyst Notes ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_notes (
  id          TEXT PRIMARY KEY,
  case_id     TEXT NOT NULL,
  org_id      TEXT NOT NULL DEFAULT 'default',
  author      TEXT NOT NULL,
  content     TEXT NOT NULL,
  note_type   TEXT NOT NULL DEFAULT 'ANALYST'
              CHECK(note_type IN ('ANALYST','AUTOMATED','ESCALATION','RESOLUTION',
                                  'INTEL_UPDATE','PLAYBOOK','CLOSURE')),
  is_pinned   INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_notes_case_id ON soc_notes(case_id, org_id);

-- ── 3. SOC Investigation Timeline ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soc_timeline (
  id            TEXT PRIMARY KEY,
  case_id       TEXT NOT NULL,
  org_id        TEXT NOT NULL DEFAULT 'default',
  event_type    TEXT NOT NULL,              -- CREATED|ASSIGNED|ESCALATED|EVIDENCE_ADDED|NOTE_ADDED|STATUS_CHANGED|RESOLVED|CLOSED
  description   TEXT NOT NULL,
  actor         TEXT,                       -- user who triggered the event
  old_value     TEXT,                       -- for status changes: previous value
  new_value     TEXT,                       -- for status changes: new value
  metadata_json TEXT,
  occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_timeline_case_id ON soc_timeline(case_id, org_id, occurred_at);

-- ── 4. CTI Watchlists ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cti_watchlists (
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

CREATE INDEX IF NOT EXISTS idx_cti_watchlists_org_id ON cti_watchlists(org_id);

-- ── 5. CTI Watchlist Entries ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cti_watchlist_entries (
  id            TEXT PRIMARY KEY,
  watchlist_id  TEXT NOT NULL REFERENCES cti_watchlists(id) ON DELETE CASCADE,
  org_id        TEXT NOT NULL DEFAULT 'default',
  ioc_value     TEXT NOT NULL,
  ioc_type      TEXT NOT NULL CHECK(ioc_type IN ('ip','domain','hash','url','email','cidr','asn','cve')),
  confidence    INTEGER NOT NULL DEFAULT 70 CHECK(confidence BETWEEN 0 AND 100),
  tags          TEXT,                       -- JSON array
  added_by      TEXT,
  added_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(watchlist_id, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_cti_watchlist_entries_value ON cti_watchlist_entries(ioc_value, org_id);
CREATE INDEX IF NOT EXISTS idx_cti_watchlist_entries_list ON cti_watchlist_entries(watchlist_id);

-- ── 6. Platform Metrics Authority Snapshots ───────────────────────────────────
-- D1 fallback when KV is unavailable; primary cache is KV
CREATE TABLE IF NOT EXISTS platform_metrics_snapshots (
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
  budget_alert    TEXT DEFAULT NULL CHECK(budget_alert IS NULL OR budget_alert IN ('WARNING','CRITICAL')),
  computed_at     TEXT NOT NULL DEFAULT (datetime('now')),
  valid_until     TEXT NOT NULL,
  UNIQUE(org_id)
);

-- ── 7. Revenue Snapshots (Daily Time-Series) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS revenue_snapshots (
  id                          TEXT PRIMARY KEY,
  org_id                      TEXT NOT NULL DEFAULT 'default',
  snapshot_date               TEXT NOT NULL,             -- YYYY-MM-DD
  mrr                         REAL NOT NULL DEFAULT 0,
  arr                         REAL NOT NULL DEFAULT 0,
  new_mrr                     REAL NOT NULL DEFAULT 0,   -- new customers this period
  expansion_mrr               REAL NOT NULL DEFAULT 0,   -- upgrades this period
  contraction_mrr             REAL NOT NULL DEFAULT 0,   -- downgrades this period
  churned_mrr                 REAL NOT NULL DEFAULT 0,   -- cancellations this period
  net_new_mrr                 REAL NOT NULL DEFAULT 0,   -- new + expansion - contraction - churn
  customer_count              INTEGER NOT NULL DEFAULT 0,
  avg_revenue_per_customer    REAL NOT NULL DEFAULT 0,
  free_count                  INTEGER NOT NULL DEFAULT 0,
  pro_count                   INTEGER NOT NULL DEFAULT 0,
  enterprise_count            INTEGER NOT NULL DEFAULT 0,
  mssp_count                  INTEGER NOT NULL DEFAULT 0,
  created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(org_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_revenue_snapshots_date ON revenue_snapshots(org_id, snapshot_date DESC);

-- ── 8. Expansion Scores ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS expansion_scores (
  org_id            TEXT PRIMARY KEY,
  expansion_score   INTEGER NOT NULL DEFAULT 0 CHECK(expansion_score BETWEEN 0 AND 100),
  segment           TEXT NOT NULL DEFAULT 'STARTER'
                    CHECK(segment IN ('STARTER','GROWING','MATURE','CHAMPION')),
  recommended_tier  TEXT CHECK(recommended_tier IN ('PRO','BUSINESS','ENTERPRISE','MSSP')),
  primary_signal    TEXT,                   -- human-readable reason for top signal
  signals_json      TEXT,                   -- JSON array of all expansion signals
  upsell_ready      INTEGER NOT NULL DEFAULT 0,
  last_activity     TEXT,
  computed_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── 9. Upsell Events Log ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS upsell_events (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL DEFAULT 'default',
  user_id           TEXT,
  event_type        TEXT NOT NULL,          -- TRIGGER|IMPRESSION|CLICK|DISMISSED|CONVERTED
  trigger_reason    TEXT,                   -- e.g. 'SCAN_LIMIT_80PCT', 'FEATURE_GATE_HIT'
  recommended_tier  TEXT,
  current_tier      TEXT,
  dismissed         INTEGER NOT NULL DEFAULT 0,
  converted         INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_upsell_events_org_id ON upsell_events(org_id, created_at DESC);

-- ── 10. MSSP Tenant Audit Log ─────────────────────────────────────────────────
-- Append-only — no DELETE endpoint exposed
CREATE TABLE IF NOT EXISTS mssp_tenant_audit (
  id              TEXT PRIMARY KEY,
  mssp_org_id     TEXT NOT NULL,            -- the MSSP performing the action
  tenant_org_id   TEXT NOT NULL,            -- the tenant being acted upon
  action          TEXT NOT NULL,            -- VIEW_CLIENT|EDIT_CLIENT|ONBOARD|OFFBOARD|REPORT_GENERATED|THEME_CHANGED
  resource        TEXT,                     -- specific resource identifier
  resource_type   TEXT,                     -- CLIENT|REPORT|THEME|USER|SCAN
  actor_user_id   TEXT,
  actor_role      TEXT,
  ip_country      TEXT,
  details_json    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mssp_tenant_audit_mssp ON mssp_tenant_audit(mssp_org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mssp_tenant_audit_tenant ON mssp_tenant_audit(tenant_org_id, created_at DESC);

-- ============================================================
-- END schema_phase4.sql
-- Phase 4 adds 10 tables, 8 indexes
-- No existing tables modified
-- Safe to run on live D1 database
-- ============================================================
