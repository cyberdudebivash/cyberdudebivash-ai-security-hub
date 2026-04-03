-- ════════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Schema V8.0 Additions
-- Run after schema.sql:
--   npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v8.sql
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Enterprise Multi-Tenant: Organizations ──────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
  id                TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name              TEXT    NOT NULL,
  slug              TEXT    UNIQUE NOT NULL,
  plan              TEXT    NOT NULL DEFAULT 'STARTER'
                              CHECK (plan IN ('STARTER','PRO','ENTERPRISE')),
  owner_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  max_members       INTEGER NOT NULL DEFAULT 5,
  max_daily_scans   INTEGER NOT NULL DEFAULT 100,
  settings_json     TEXT    NOT NULL DEFAULT '{}',
  logo_url          TEXT,
  domain            TEXT,
  industry          TEXT,
  created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_org_owner     ON organizations(owner_id);
CREATE INDEX IF NOT EXISTS idx_org_slug      ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_org_plan      ON organizations(plan);

-- ─── Org Members (roles: OWNER > ADMIN > ANALYST > MEMBER > VIEWER) ──────────
CREATE TABLE IF NOT EXISTS org_members (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  org_id      TEXT    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        TEXT    NOT NULL DEFAULT 'MEMBER'
                        CHECK (role IN ('OWNER','ADMIN','ANALYST','MEMBER','VIEWER')),
  invited_by  TEXT    REFERENCES users(id) ON DELETE SET NULL,
  invite_email TEXT,
  status      TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','invited','suspended')),
  joined_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_org    ON org_members(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user   ON org_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_role   ON org_members(org_id, role);

-- ─── Continuous Monitoring Configs ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitor_configs (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id              TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id               TEXT    REFERENCES organizations(id) ON DELETE SET NULL,
  name                 TEXT    NOT NULL,
  module               TEXT    NOT NULL
                                 CHECK (module IN ('domain','ai','redteam','identity','compliance')),
  target_json          TEXT    NOT NULL,  -- JSON payload for scan (e.g. {"domain":"example.com"})
  schedule             TEXT    NOT NULL DEFAULT 'daily'
                                 CHECK (schedule IN ('hourly','daily','weekly','monthly')),
  enabled              INTEGER NOT NULL DEFAULT 1,
  alert_on_drift       INTEGER NOT NULL DEFAULT 1,
  alert_on_critical    INTEGER NOT NULL DEFAULT 1,
  drift_threshold      INTEGER NOT NULL DEFAULT 10,  -- score delta to trigger drift alert
  baseline_risk_score  INTEGER,                       -- set after first run
  last_scan_score      INTEGER,
  last_run_at          TEXT,
  next_run_at          TEXT,
  run_count            INTEGER NOT NULL DEFAULT 0,
  fail_count           INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_monitor_user      ON monitor_configs(user_id, enabled);
CREATE INDEX IF NOT EXISTS idx_monitor_org       ON monitor_configs(org_id);
CREATE INDEX IF NOT EXISTS idx_monitor_next_run  ON monitor_configs(next_run_at, enabled);
CREATE INDEX IF NOT EXISTS idx_monitor_module    ON monitor_configs(module, enabled);

-- ─── Monitoring Results (time-series risk data) ───────────────────────────────
CREATE TABLE IF NOT EXISTS monitor_results (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  config_id            TEXT    NOT NULL REFERENCES monitor_configs(id) ON DELETE CASCADE,
  user_id              TEXT    NOT NULL,
  module               TEXT    NOT NULL,
  target_summary       TEXT,
  risk_score           INTEGER NOT NULL,
  risk_level           TEXT    NOT NULL,
  findings_count       INTEGER NOT NULL DEFAULT 0,
  critical_count       INTEGER NOT NULL DEFAULT 0,
  high_count           INTEGER NOT NULL DEFAULT 0,
  new_findings_count   INTEGER NOT NULL DEFAULT 0,  -- findings not in previous run
  resolved_count       INTEGER NOT NULL DEFAULT 0,  -- findings gone from previous run
  drift_delta          INTEGER NOT NULL DEFAULT 0,  -- signed change vs baseline
  drift_type           TEXT    NOT NULL DEFAULT 'none'
                                  CHECK (drift_type IN ('improved','degraded','stable','new','none')),
  ai_narrative         TEXT,    -- AI-generated plain-language summary
  alert_sent           INTEGER NOT NULL DEFAULT 0,
  scan_result_r2_key   TEXT,    -- R2 key for full result JSON
  created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_monitor_results_config   ON monitor_results(config_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_results_user     ON monitor_results(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_results_drift    ON monitor_results(drift_type, created_at DESC);

-- ─── Content / Auto-Generated Posts ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS content_posts (
  id                     TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id                TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id                 TEXT    REFERENCES organizations(id) ON DELETE SET NULL,
  type                   TEXT    NOT NULL DEFAULT 'blog'
                                   CHECK (type IN ('blog','linkedin','telegram','executive_brief','threat_advisory')),
  title                  TEXT    NOT NULL,
  body_md                TEXT    NOT NULL,
  excerpt                TEXT,
  tags                   TEXT,    -- JSON array
  scan_job_id            TEXT,
  module                 TEXT,
  target_summary         TEXT,
  published_to_telegram  INTEGER NOT NULL DEFAULT 0,
  published_to_linkedin  INTEGER NOT NULL DEFAULT 0,
  telegram_msg_id        TEXT,
  linkedin_post_id       TEXT,
  published_at           TEXT,
  view_count             INTEGER NOT NULL DEFAULT 0,
  created_at             TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_content_user      ON content_posts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_type      ON content_posts(type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_org       ON content_posts(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_published ON content_posts(published_at DESC);

-- ─── API Usage Tracking (enhanced for public API platform) ───────────────────
CREATE TABLE IF NOT EXISTS api_requests (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  api_key_id   TEXT    REFERENCES api_keys(id) ON DELETE SET NULL,
  user_id      TEXT    REFERENCES users(id) ON DELETE SET NULL,
  endpoint     TEXT    NOT NULL,
  method       TEXT    NOT NULL,
  status_code  INTEGER,
  latency_ms   INTEGER,
  ip           TEXT,
  ua           TEXT,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_api_req_key       ON api_requests(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_req_user      ON api_requests(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_req_endpoint  ON api_requests(endpoint, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_req_date      ON api_requests(created_at DESC);

-- ─── Threat Intelligence Cache (correlation engine) ───────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel_cache (
  cve_id       TEXT    PRIMARY KEY,
  cvss_score   REAL,
  cvss_vector  TEXT,
  epss_score   REAL,
  epss_pct     REAL,
  is_kev       INTEGER NOT NULL DEFAULT 0,
  kev_added    TEXT,
  description  TEXT,
  cpe_list     TEXT,   -- JSON array of affected CPEs
  references   TEXT,   -- JSON array
  cached_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_kev   ON threat_intel_cache(is_kev, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_epss  ON threat_intel_cache(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_exp   ON threat_intel_cache(expires_at);
