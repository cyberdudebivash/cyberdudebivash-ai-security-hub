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
