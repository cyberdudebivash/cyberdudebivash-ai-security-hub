-- ════════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Schema V8.0 (FIXED FOR D1 PRODUCTION)
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Organizations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
name TEXT NOT NULL,
slug TEXT UNIQUE NOT NULL,
plan TEXT NOT NULL DEFAULT 'STARTER'
CHECK (plan IN ('STARTER','PRO','ENTERPRISE')),
owner_id TEXT NOT NULL,
max_members INTEGER NOT NULL DEFAULT 5,
max_daily_scans INTEGER NOT NULL DEFAULT 100,
settings_json TEXT NOT NULL DEFAULT '{}',
logo_url TEXT,
domain TEXT,
industry TEXT,
created_at TEXT NOT NULL DEFAULT (datetime('now')),
updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_org_owner ON organizations(owner_id);
CREATE INDEX IF NOT EXISTS idx_org_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_org_plan ON organizations(plan);

-- ─── Org Members ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_members (
id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
org_id TEXT NOT NULL,
user_id TEXT NOT NULL,
role TEXT NOT NULL DEFAULT 'MEMBER'
CHECK (role IN ('OWNER','ADMIN','ANALYST','MEMBER','VIEWER')),
invited_by TEXT,
invite_email TEXT,
status TEXT NOT NULL DEFAULT 'active'
CHECK (status IN ('active','invited','suspended')),
joined_at TEXT NOT NULL DEFAULT (datetime('now')),
UNIQUE (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);

-- ─── Monitor Configs ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitor_configs (
id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
user_id TEXT NOT NULL,
org_id TEXT,
name TEXT NOT NULL,
module TEXT NOT NULL
CHECK (module IN ('domain','ai','redteam','identity','compliance')),
target_json TEXT NOT NULL,
schedule TEXT NOT NULL DEFAULT 'daily'
CHECK (schedule IN ('hourly','daily','weekly','monthly')),
enabled INTEGER NOT NULL DEFAULT 1,
alert_on_drift INTEGER NOT NULL DEFAULT 1,
alert_on_critical INTEGER NOT NULL DEFAULT 1,
drift_threshold INTEGER NOT NULL DEFAULT 10,
baseline_risk_score INTEGER,
last_scan_score INTEGER,
last_run_at TEXT,
next_run_at TEXT,
run_count INTEGER NOT NULL DEFAULT 0,
fail_count INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL DEFAULT (datetime('now')),
updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_monitor_user ON monitor_configs(user_id, enabled);

-- ─── Monitor Results ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitor_results (
id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
config_id TEXT NOT NULL,
user_id TEXT NOT NULL,
module TEXT NOT NULL,
target_summary TEXT,
risk_score INTEGER NOT NULL,
risk_level TEXT NOT NULL,
findings_count INTEGER NOT NULL DEFAULT 0,
critical_count INTEGER NOT NULL DEFAULT 0,
high_count INTEGER NOT NULL DEFAULT 0,
new_findings_count INTEGER NOT NULL DEFAULT 0,
resolved_count INTEGER NOT NULL DEFAULT 0,
drift_delta INTEGER NOT NULL DEFAULT 0,
drift_type TEXT NOT NULL DEFAULT 'none'
CHECK (drift_type IN ('improved','degraded','stable','new','none')),
ai_narrative TEXT,
alert_sent INTEGER NOT NULL DEFAULT 0,
scan_result_r2_key TEXT,
created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── Content Posts ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS content_posts (
id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
user_id TEXT NOT NULL,
org_id TEXT,
type TEXT NOT NULL DEFAULT 'blog'
CHECK (type IN ('blog','linkedin','telegram','executive_brief','threat_advisory')),
title TEXT NOT NULL,
body_md TEXT NOT NULL,
excerpt TEXT,
tags TEXT,
scan_job_id TEXT,
module TEXT,
target_summary TEXT,
published_to_telegram INTEGER NOT NULL DEFAULT 0,
published_to_linkedin INTEGER NOT NULL DEFAULT 0,
telegram_msg_id TEXT,
linkedin_post_id TEXT,
published_at TEXT,
view_count INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── API Requests ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_requests (
id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
api_key_id TEXT,
user_id TEXT,
endpoint TEXT NOT NULL,
method TEXT NOT NULL,
status_code INTEGER,
latency_ms INTEGER,
ip TEXT,
ua TEXT,
created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── Threat Intel Cache (FIXED COLUMN NAME) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel_cache (
cve_id TEXT PRIMARY KEY,
cvss_score REAL,
cvss_vector TEXT,
epss_score REAL,
epss_pct REAL,
is_kev INTEGER NOT NULL DEFAULT 0,
kev_added TEXT,
description TEXT,
cpe_list TEXT,
references_json TEXT,  -- ✅ FIXED
cached_at TEXT NOT NULL DEFAULT (datetime('now')),
expires_at TEXT NOT NULL
);

-- ════════════════════════════════════════════════════════════════════════════
-- V8.1 SCHEMA EXTENSIONS
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Gumroad Licenses ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gumroad_licenses (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  license_key      TEXT UNIQUE NOT NULL,
  product_permalink TEXT NOT NULL,
  product_name     TEXT NOT NULL,
  buyer_email      TEXT NOT NULL,
  buyer_name       TEXT,
  user_id          TEXT,
  tier_granted     TEXT NOT NULL DEFAULT 'PRO',
  credits_granted  INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','refunded')),
  purchase_id      TEXT,
  sale_id          TEXT,
  activated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_gumroad_email ON gumroad_licenses(buyer_email);
CREATE INDEX IF NOT EXISTS idx_gumroad_user ON gumroad_licenses(user_id);
CREATE INDEX IF NOT EXISTS idx_gumroad_product ON gumroad_licenses(product_permalink);

-- ─── User Credits ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_credits (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT NOT NULL,
  total        INTEGER NOT NULL DEFAULT 0,
  used         INTEGER NOT NULL DEFAULT 0,
  source       TEXT NOT NULL DEFAULT 'gumroad' CHECK (source IN ('gumroad','purchase','bonus','referral','promo')),
  reference_id TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_credits_user ON user_credits(user_id);

-- ─── Leads ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS leads (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email           TEXT UNIQUE NOT NULL,
  name            TEXT,
  company         TEXT,
  domain          TEXT,
  ip              TEXT,
  country         TEXT,
  source          TEXT DEFAULT 'scan',
  lead_score      INTEGER NOT NULL DEFAULT 0,
  is_enterprise   INTEGER NOT NULL DEFAULT 0,
  converted       INTEGER NOT NULL DEFAULT 0,
  unsubscribed    INTEGER NOT NULL DEFAULT 0,
  unsubscribed_at TEXT,
  drip_sequence   TEXT,
  drip_step       INTEGER NOT NULL DEFAULT 0,
  drip_enrolled_at TEXT,
  last_scan_at    TEXT,
  scan_count      INTEGER NOT NULL DEFAULT 0,
  metadata        TEXT DEFAULT '{}',
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_score ON leads(lead_score DESC);
CREATE INDEX IF NOT EXISTS idx_leads_enterprise ON leads(is_enterprise);
CREATE INDEX IF NOT EXISTS idx_leads_converted ON leads(converted);

-- ─── Email Tracking ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_tracking (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email       TEXT NOT NULL,
  sequence_id TEXT NOT NULL,
  step        INTEGER NOT NULL DEFAULT 0,
  event       TEXT NOT NULL CHECK (event IN ('sent','open','click','bounce','unsubscribe')),
  metadata    TEXT DEFAULT '{}',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_email_track_email ON email_tracking(email);
CREATE INDEX IF NOT EXISTS idx_email_track_seq ON email_tracking(sequence_id, step);

-- ─── Audit Log ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  action     TEXT NOT NULL,
  user_id    TEXT,
  ip         TEXT,
  user_agent TEXT,
  resource   TEXT,
  details    TEXT DEFAULT '{}',
  severity   TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warn','critical')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

-- ─── Affiliate Clicks ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS affiliate_clicks (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  program     TEXT NOT NULL,
  link_id     TEXT NOT NULL,
  link_url    TEXT NOT NULL,
  ref_page    TEXT,
  ip          TEXT,
  country     TEXT,
  user_agent  TEXT,
  converted   INTEGER NOT NULL DEFAULT 0,
  revenue     REAL NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_affiliate_program ON affiliate_clicks(program);
CREATE INDEX IF NOT EXISTS idx_affiliate_link ON affiliate_clicks(link_id);
CREATE INDEX IF NOT EXISTS idx_affiliate_conv ON affiliate_clicks(converted);

-- ─── Revenue Events ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS revenue_events (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  source      TEXT NOT NULL CHECK (source IN ('razorpay','gumroad','affiliate','subscription','api_credits')),
  amount_inr  REAL NOT NULL DEFAULT 0,
  amount_usd  REAL NOT NULL DEFAULT 0,
  user_id     TEXT,
  email       TEXT,
  product     TEXT,
  reference   TEXT,
  metadata    TEXT DEFAULT '{}',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_rev_source ON revenue_events(source);
CREATE INDEX IF NOT EXISTS idx_rev_created ON revenue_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_user ON revenue_events(user_id);

-- ─── AdSense Analytics ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS adsense_events (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type  TEXT NOT NULL CHECK (event_type IN ('impression','click','revenue')),
  slot_id     TEXT,
  page        TEXT,
  ip          TEXT,
  country     TEXT,
  revenue_usd REAL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_adsense_type ON adsense_events(event_type);
CREATE INDEX IF NOT EXISTS idx_adsense_page ON adsense_events(page);

