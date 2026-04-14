-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v15.0 (GOD MODE)
-- God Mode Implementation:
--   Phase 1: Data Seeding (no schema required — PRNG based)
--   Phase 2: Automated Delivery Engine → delivery_tokens table
--   Phase 3: User State Engine → user_sessions, user_tool_access
--   Phase 5: Enterprise CRM → crm_leads, crm_notes, crm_pipeline_log
-- ============================================================
-- Run this migration via Wrangler:
--   wrangler d1 execute cyberdudebivash-db --file=workers/schema_v15.sql
-- ============================================================

-- ── PHASE 2: AUTOMATED DELIVERY ENGINE ──────────────────────────────────────

-- Stores all activated delivery tokens for purchased products.
-- Indexed for both token lookup (fast KV path) and admin queries.
CREATE TABLE IF NOT EXISTS delivery_tokens (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  payment_id       TEXT NOT NULL UNIQUE,        -- payment ref from CDB_PAY
  product_id       TEXT NOT NULL,               -- e.g. SOC_PLAYBOOK_2026
  product_name     TEXT NOT NULL,               -- human-readable label
  product_type     TEXT NOT NULL CHECK(product_type IN (
    'platform_access', 'report_access', 'training', 'bundle'
  )),
  payer_email      TEXT NOT NULL,
  user_id          TEXT,                         -- NULL for guest purchases
  token_hash       TEXT NOT NULL UNIQUE,         -- SHA-256 of cdb_dlv_ token
  delivery_method  TEXT NOT NULL CHECK(delivery_method IN (
    'instant_access', 'whatsapp_delivery', 'email_delivery', 'download_link'
  )),
  access_details   TEXT NOT NULL DEFAULT '{}',  -- JSON: links, instructions, files
  custom_notes     TEXT,
  status           TEXT NOT NULL DEFAULT 'activated' CHECK(status IN (
    'activated', 'expired', 'revoked', 'consumed'
  )),
  activated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT NOT NULL,               -- ISO8601 string
  access_count     INTEGER NOT NULL DEFAULT 0,
  last_accessed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_delivery_payment_id  ON delivery_tokens(payment_id);
CREATE INDEX IF NOT EXISTS idx_delivery_token_hash  ON delivery_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_delivery_email       ON delivery_tokens(payer_email);
CREATE INDEX IF NOT EXISTS idx_delivery_user_id     ON delivery_tokens(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_delivery_product     ON delivery_tokens(product_id, activated_at DESC);
CREATE INDEX IF NOT EXISTS idx_delivery_status      ON delivery_tokens(status, expires_at);


-- ── PHASE 3: USER STATE ENGINE ───────────────────────────────────────────────

-- Extended user sessions with device fingerprint + activity tracking.
-- Supplements existing auth_tokens table (does NOT replace it).
CREATE TABLE IF NOT EXISTS user_sessions (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  session_token    TEXT NOT NULL UNIQUE,         -- short-lived JWT session ID
  device_fp        TEXT,                         -- device fingerprint hash
  ip_address       TEXT,
  user_agent       TEXT,
  country          TEXT,
  city             TEXT,
  is_active        INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  last_active_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT NOT NULL,
  revoked_at       TEXT,
  revoke_reason    TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id   ON user_sessions(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_token     ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires   ON user_sessions(expires_at) WHERE is_active = 1;


-- Per-user access to tools, trainings, and reports.
-- Written when delivery is activated; read by /user-dashboard.
CREATE TABLE IF NOT EXISTS user_tool_access (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,                         -- NULL allowed for email-only lookups
  email            TEXT NOT NULL,
  product_id       TEXT NOT NULL,
  product_name     TEXT NOT NULL,
  access_type      TEXT NOT NULL CHECK(access_type IN (
    'training', 'report', 'tool', 'subscription', 'bundle'
  )),
  delivery_id      TEXT,                         -- FK → delivery_tokens.id
  payment_id       TEXT NOT NULL,
  granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT,                         -- NULL = lifetime
  is_active        INTEGER NOT NULL DEFAULT 1,
  last_accessed_at TEXT,
  access_count     INTEGER NOT NULL DEFAULT 0,
  metadata         TEXT DEFAULT '{}'             -- extra JSON: course progress, score, etc.
);

CREATE INDEX IF NOT EXISTS idx_uta_user_id     ON user_tool_access(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_uta_email       ON user_tool_access(email);
CREATE INDEX IF NOT EXISTS idx_uta_product     ON user_tool_access(product_id);
CREATE INDEX IF NOT EXISTS idx_uta_delivery    ON user_tool_access(delivery_id) WHERE delivery_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_uta_active      ON user_tool_access(is_active, expires_at);


-- ── PHASE 5: ENTERPRISE CRM ENGINE ──────────────────────────────────────────

-- Core CRM leads table with ICP scoring.
-- Extends existing growth.js lead storage with full pipeline state.
CREATE TABLE IF NOT EXISTS crm_leads (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  -- Identity
  name             TEXT NOT NULL,
  email            TEXT NOT NULL,
  company          TEXT,
  title            TEXT,
  phone            TEXT,
  linkedin_url     TEXT,
  website          TEXT,
  -- Lead origin
  source           TEXT NOT NULL DEFAULT 'organic' CHECK(source IN (
    'organic', 'paid_ad', 'referral', 'affiliate', 'linkedin',
    'cold_outreach', 'scan_signup', 'enterprise_contact', 'api'
  )),
  source_detail    TEXT,                         -- e.g. campaign name, referrer URL
  -- Pipeline state
  stage            TEXT NOT NULL DEFAULT 'NEW' CHECK(stage IN (
    'NEW', 'QUALIFIED', 'DEMO_BOOKED', 'DEMO_DONE',
    'PROPOSAL_SENT', 'NEGOTIATION', 'CLOSED_WON', 'CLOSED_LOST', 'CHURNED'
  )),
  stage_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  -- ICP Scoring (0–100 composite)
  icp_score        INTEGER NOT NULL DEFAULT 0,
  sector           TEXT,                         -- fintech, healthcare, saas, etc.
  company_size     TEXT CHECK(company_size IN (
    '1-10', '11-50', '51-200', '201-1000', '1000+'
  )),
  compliance_need  TEXT,                         -- PCI, HIPAA, SOC2, ISO27001, etc.
  budget_signal    TEXT CHECK(budget_signal IN (
    'none', 'low', 'medium', 'high', 'enterprise'
  )),
  urgency_signal   TEXT CHECK(urgency_signal IN (
    'low', 'medium', 'high', 'critical'
  )),
  -- Commercial
  deal_value_inr   INTEGER DEFAULT 0,            -- estimated deal value in INR
  plan_interest    TEXT,                         -- PRO, ENTERPRISE, MSSP, CUSTOM
  trial_started    INTEGER NOT NULL DEFAULT 0,
  -- Ownership
  assigned_to      TEXT,
  owner_notes      TEXT,
  -- Activity tracking
  last_contacted_at TEXT,
  next_follow_up_at TEXT,
  email_opened_count INTEGER NOT NULL DEFAULT 0,
  email_click_count  INTEGER NOT NULL DEFAULT 0,
  scan_count         INTEGER NOT NULL DEFAULT 0,
  -- Metadata
  tags             TEXT DEFAULT '[]',            -- JSON array
  utm_source       TEXT,
  utm_medium       TEXT,
  utm_campaign     TEXT,
  ip_address       TEXT,
  country          TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_crm_email         ON crm_leads(email);
CREATE INDEX IF NOT EXISTS idx_crm_stage         ON crm_leads(stage, icp_score DESC);
CREATE INDEX IF NOT EXISTS idx_crm_icp           ON crm_leads(icp_score DESC);
CREATE INDEX IF NOT EXISTS idx_crm_source        ON crm_leads(source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_crm_assigned      ON crm_leads(assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_crm_follow_up     ON crm_leads(next_follow_up_at) WHERE next_follow_up_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_crm_deal_value    ON crm_leads(deal_value_inr DESC) WHERE deal_value_inr > 0;
CREATE INDEX IF NOT EXISTS idx_crm_created       ON crm_leads(created_at DESC);


-- CRM pipeline activity log — immutable audit trail of every stage change.
CREATE TABLE IF NOT EXISTS crm_pipeline_log (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  lead_id          TEXT NOT NULL,               -- FK → crm_leads.id
  from_stage       TEXT,
  to_stage         TEXT NOT NULL,
  actor            TEXT,                         -- user_id of rep who moved it
  reason           TEXT,
  note             TEXT,
  deal_value_inr   INTEGER,                      -- snapshot at time of change
  icp_score        INTEGER,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pipeline_log_lead ON crm_pipeline_log(lead_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pipeline_log_stage ON crm_pipeline_log(to_stage, created_at DESC);


-- CRM notes — free-form notes per lead, supports calls / emails / demos.
CREATE TABLE IF NOT EXISTS crm_notes (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  lead_id          TEXT NOT NULL,               -- FK → crm_leads.id
  note_type        TEXT NOT NULL DEFAULT 'note' CHECK(note_type IN (
    'note', 'call', 'email', 'demo', 'proposal', 'objection', 'follow_up'
  )),
  content          TEXT NOT NULL,
  author           TEXT,                         -- user_id
  is_pinned        INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_crm_notes_lead ON crm_notes(lead_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_crm_notes_type ON crm_notes(note_type, created_at DESC);


-- ── SCHEMA VERSION MARKER ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS schema_versions (
  version    TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now')),
  description TEXT
);

INSERT OR IGNORE INTO schema_versions (version, description) VALUES
  ('v15.0', 'God Mode: delivery_tokens, user_sessions, user_tool_access, crm_leads, crm_pipeline_log, crm_notes');

-- ═══════════════════════════════════════════════════════════════════════════
-- SCHEMA v15.1 — Threat Intelligence, Defense Actions, Proposals,
--                Org Events, API Usage Metering, Revenue Snapshots
-- ═══════════════════════════════════════════════════════════════════════════

-- ─── THREAT INTELLIGENCE ─────────────────────────────────────────────────────
DROP TABLE IF EXISTS threat_intel;
CREATE TABLE threat_intel (
  id              TEXT    PRIMARY KEY,
  cve_id          TEXT    UNIQUE,
  title           TEXT    NOT NULL,
  description     TEXT,
  severity        TEXT    NOT NULL DEFAULT 'MEDIUM',
  cvss_score      REAL,
  cvss_vector     TEXT,
  vendor          TEXT,
  product         TEXT,
  published_at    TEXT,
  modified_at     TEXT,
  is_exploited    INTEGER NOT NULL DEFAULT 0,
  is_ransomware   INTEGER NOT NULL DEFAULT 0,
  apt_groups      TEXT,                           -- JSON array
  cisa_kev_date   TEXT,
  patch_available INTEGER NOT NULL DEFAULT 0,
  patch_url       TEXT,
  ref_urls        TEXT,                           -- JSON array of URLs
  source          TEXT    NOT NULL DEFAULT 'NVD',
  confidence      REAL    NOT NULL DEFAULT 0.5,
  ingested_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ti_cve       ON threat_intel(cve_id);
CREATE INDEX IF NOT EXISTS idx_ti_severity  ON threat_intel(severity);
CREATE INDEX IF NOT EXISTS idx_ti_cvss      ON threat_intel(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_ti_exploited ON threat_intel(is_exploited);
CREATE INDEX IF NOT EXISTS idx_ti_published ON threat_intel(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_ti_ingested  ON threat_intel(ingested_at DESC);

-- ─── AUTONOMOUS DEFENSE ACTIONS ──────────────────────────────────────────────
DROP TABLE IF EXISTS defense_actions;
CREATE TABLE defense_actions (
  id             TEXT    PRIMARY KEY,
  threat_id      TEXT    REFERENCES threat_intel(id) ON DELETE SET NULL,
  action_type    TEXT    NOT NULL,
  target         TEXT,
  status         TEXT    NOT NULL DEFAULT 'pending',
  confidence     REAL    NOT NULL DEFAULT 0.5,
  cvss_trigger   REAL,
  execution_mode TEXT    NOT NULL DEFAULT 'ASSISTED',
  triggered_by   TEXT    NOT NULL DEFAULT 'AUTO',
  approved_by    TEXT,
  executed_at    TEXT,
  result_summary TEXT,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_da_threat  ON defense_actions(threat_id);
CREATE INDEX IF NOT EXISTS idx_da_status  ON defense_actions(status);
CREATE INDEX IF NOT EXISTS idx_da_type    ON defense_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_da_created ON defense_actions(created_at DESC);

-- ─── PROPOSALS ───────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS proposals;
CREATE TABLE proposals (
  id               TEXT    PRIMARY KEY,
  lead_id          TEXT    REFERENCES crm_leads(id) ON DELETE SET NULL,
  title            TEXT    NOT NULL,
  client_name      TEXT    NOT NULL,
  client_email     TEXT    NOT NULL,
  client_company   TEXT    NOT NULL,
  tier_recommended TEXT    NOT NULL,
  deal_value_inr   INTEGER,
  status           TEXT    NOT NULL DEFAULT 'draft',
  pdf_url          TEXT,
  valid_until      TEXT,
  sent_at          TEXT,
  responded_at     TEXT,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_proposals_lead    ON proposals(lead_id);
CREATE INDEX IF NOT EXISTS idx_proposals_status  ON proposals(status);
CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals(created_at DESC);

-- ─── ORGANIZATION EVENTS ─────────────────────────────────────────────────────
DROP TABLE IF EXISTS org_events;
CREATE TABLE org_events (
  id          TEXT    PRIMARY KEY,
  org_id      TEXT    NOT NULL,
  event_type  TEXT    NOT NULL,
  module      TEXT,
  severity    TEXT,
  title       TEXT    NOT NULL,
  detail      TEXT,
  ip_address  TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_org_events_org     ON org_events(org_id);
CREATE INDEX IF NOT EXISTS idx_org_events_type    ON org_events(event_type);
CREATE INDEX IF NOT EXISTS idx_org_events_created ON org_events(created_at DESC);

-- ─── API USAGE METERING ───────────────────────────────────────────────────────
DROP TABLE IF EXISTS api_usage_log;
CREATE TABLE api_usage_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT,
  api_key_id  TEXT,
  endpoint    TEXT    NOT NULL,
  method      TEXT    NOT NULL DEFAULT 'GET',
  status_code INTEGER,
  latency_ms  INTEGER,
  ip_address  TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_usage_user    ON api_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_key     ON api_usage_log(api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_ep      ON api_usage_log(endpoint);
CREATE INDEX IF NOT EXISTS idx_usage_created ON api_usage_log(created_at DESC);

-- ─── REVENUE SNAPSHOTS ────────────────────────────────────────────────────────
DROP TABLE IF EXISTS revenue_snapshots;
CREATE TABLE revenue_snapshots (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_at TEXT    NOT NULL DEFAULT (datetime('now')),
  mrr_inr     REAL    NOT NULL DEFAULT 0,
  arr_inr     REAL    NOT NULL DEFAULT 0,
  active_subs INTEGER NOT NULL DEFAULT 0,
  new_subs    INTEGER NOT NULL DEFAULT 0,
  churned     INTEGER NOT NULL DEFAULT 0,
  total_users INTEGER NOT NULL DEFAULT 0,
  pro_users   INTEGER NOT NULL DEFAULT 0,
  ent_users   INTEGER NOT NULL DEFAULT 0,
  api_calls   INTEGER NOT NULL DEFAULT 0,
  scans_today INTEGER NOT NULL DEFAULT 0,
  meta_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_rev_snapshot ON revenue_snapshots(snapshot_at DESC);

INSERT OR IGNORE INTO schema_versions (version, description) VALUES
  ('v15.1', 'threat_intel, defense_actions, proposals, org_events, api_usage_log, revenue_snapshots');
