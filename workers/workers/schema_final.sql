-- ============================================================
-- CYBERDUDEBIVASH® AI Security Hub
-- schema_final.sql — Unified Production Schema
-- Generated: 2026-06-12
-- 
-- Apply with:
--   npx wrangler d1 execute cyberdudebivash-security-hub \
--     --file=./schema_final.sql --remote
--
-- This file consolidates all schema_*.sql files in correct
-- version order. Safe to re-apply (uses IF NOT EXISTS).
-- ============================================================

-- PRAGMA journal_mode=WAL;   -- D1 does not support PRAGMA in batch SQL
-- PRAGMA foreign_keys=ON;    -- D1 does not support PRAGMA in batch SQL


-- ============================================================
-- SOURCE: schema.sql
-- ============================================================

-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — D1 Database Schema v5.0
-- Deploy: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema.sql
-- ============================================================

-- NOTE: PRAGMA journal_mode and foreign_keys are managed by Cloudflare D1 internally.
-- Do NOT use PRAGMA statements — D1 blocks them with SQLITE_AUTH.

-- ─── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email           TEXT    NOT NULL UNIQUE,
  password_hash   TEXT    NOT NULL,
  password_salt   TEXT    NOT NULL,
  tier            TEXT    NOT NULL DEFAULT 'FREE' CHECK (tier IN ('FREE','PRO','ENTERPRISE')),
  status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','unverified')),
  full_name       TEXT,
  company         TEXT,
  telegram_chat_id TEXT,
  alert_email     TEXT,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login_at   TEXT,
  login_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_tier      ON users(tier);
CREATE INDEX IF NOT EXISTS idx_users_status    ON users(status);

-- ─── Refresh Tokens ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  revoked     INTEGER NOT NULL DEFAULT 0,
  ip_address  TEXT,
  user_agent  TEXT
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash   ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);

-- ─── Login Attempts (brute-force protection) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS login_attempts (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email       TEXT    NOT NULL,
  ip_address  TEXT,
  success     INTEGER NOT NULL DEFAULT 0,
  attempted_at TEXT   NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip    ON login_attempts(ip_address, attempted_at);

-- ─── API Keys ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT    NOT NULL UNIQUE,   -- SHA-256 of the raw key
  key_prefix   TEXT    NOT NULL,          -- first 12 chars, shown in UI (e.g. cdb_a3f9...)
  label        TEXT    NOT NULL DEFAULT 'Default Key',
  tier         TEXT    NOT NULL DEFAULT 'FREE' CHECK (tier IN ('FREE','PRO','ENTERPRISE')),
  daily_limit  INTEGER NOT NULL DEFAULT 5,
  monthly_limit INTEGER NOT NULL DEFAULT 100,
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at   TEXT    -- NULL = never expires
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user   ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

-- ─── API Key Usage (daily buckets for billing) ────────────────────────────────
CREATE TABLE IF NOT EXISTS api_key_usage (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  key_id       TEXT    NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  user_id      TEXT    NOT NULL,
  date_bucket  TEXT    NOT NULL,  -- YYYY-MM-DD
  module       TEXT    NOT NULL,  -- domain, ai, redteam, etc.
  request_count INTEGER NOT NULL DEFAULT 1,
  UNIQUE(key_id, date_bucket, module)
);

CREATE INDEX IF NOT EXISTS idx_key_usage_key    ON api_key_usage(key_id, date_bucket);
CREATE INDEX IF NOT EXISTS idx_key_usage_user   ON api_key_usage(user_id, date_bucket);

-- ─── Scan Jobs (async queue tracking) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_jobs (
  id            TEXT    PRIMARY KEY,   -- job_id (e.g. job_abc123)
  user_id       TEXT    REFERENCES users(id) ON DELETE SET NULL,
  identity      TEXT    NOT NULL,      -- api key identity or ip identity
  module        TEXT    NOT NULL,      -- domain, ai, redteam, identity, compliance
  target        TEXT    NOT NULL,
  priority      INTEGER NOT NULL DEFAULT 0,  -- 0=FREE, 1=PRO, 2=ENTERPRISE
  status        TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','processing','completed','failed')),
  risk_score    INTEGER,
  risk_level    TEXT,
  error_message TEXT,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  started_at    TEXT,
  completed_at  TEXT,
  r2_key        TEXT    -- path to full result in R2
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user     ON scan_jobs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status   ON scan_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_identity ON scan_jobs(identity, created_at);

-- ─── Scan History (structured, queryable) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_history (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  job_id       TEXT    REFERENCES scan_jobs(id) ON DELETE SET NULL,
  scan_id      TEXT,
  target       TEXT    NOT NULL,
  module       TEXT    NOT NULL,
  risk_score   INTEGER,
  risk_level   TEXT,
  grade        TEXT,
  data_source  TEXT,
  status       TEXT    NOT NULL DEFAULT 'completed',
  scanned_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_history_user   ON scan_history(user_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_module ON scan_history(user_id, module, scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_target ON scan_history(user_id, target);

-- ─── Alert Configurations ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_configs (
  id                TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id           TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  telegram_enabled  INTEGER NOT NULL DEFAULT 0,
  telegram_chat_id  TEXT,
  email_enabled     INTEGER NOT NULL DEFAULT 0,
  alert_email       TEXT,
  min_risk_score    INTEGER NOT NULL DEFAULT 70,   -- trigger threshold
  alert_on_blacklist INTEGER NOT NULL DEFAULT 1,
  alert_on_critical_cve INTEGER NOT NULL DEFAULT 1,
  created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_configs_user ON alert_configs(user_id);

-- ─── Alert Log (delivery tracking) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_log (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel     TEXT    NOT NULL CHECK (channel IN ('telegram','email')),
  trigger_type TEXT   NOT NULL,  -- high_risk, blacklist, critical_cve
  target      TEXT,
  message_preview TEXT,
  status      TEXT    NOT NULL DEFAULT 'sent' CHECK (status IN ('sent','failed','pending')),
  sent_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_log_user ON alert_log(user_id, sent_at);

-- ─── Deduplication Index ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_dedup (
  dedup_key   TEXT    PRIMARY KEY,   -- module:target (SHA-256 prefix)
  job_id      TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL
);

-- ─── Payments (Razorpay monetization) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payments (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id              TEXT    REFERENCES users(id) ON DELETE SET NULL,
  scan_id              TEXT,
  module               TEXT    NOT NULL,
  target               TEXT    NOT NULL,
  amount               INTEGER NOT NULL,          -- paise (INR × 100)
  currency             TEXT    NOT NULL DEFAULT 'INR',
  razorpay_order_id    TEXT    UNIQUE,
  razorpay_payment_id  TEXT,
  razorpay_signature   TEXT,
  status               TEXT    NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','paid','failed','refunded')),
  plan                 TEXT    NOT NULL DEFAULT 'pay_per_report',
  report_token         TEXT,
  ip                   TEXT,
  email                TEXT,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  paid_at              TEXT
);

CREATE INDEX IF NOT EXISTS idx_payments_user       ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_razorpay   ON payments(razorpay_order_id);
CREATE INDEX IF NOT EXISTS idx_payments_status     ON payments(status, created_at);
CREATE INDEX IF NOT EXISTS idx_payments_module     ON payments(module, status);
CREATE INDEX IF NOT EXISTS idx_payments_target     ON payments(target, module);

-- ─── Report Access Tokens ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS report_access (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  scan_id              TEXT,
  payment_id           TEXT    REFERENCES payments(id) ON DELETE CASCADE,
  user_id              TEXT    REFERENCES users(id) ON DELETE SET NULL,
  token                TEXT    NOT NULL UNIQUE,
  module               TEXT    NOT NULL,
  r2_key               TEXT,
  expires_at           TEXT    NOT NULL,
  downloaded_count     INTEGER NOT NULL DEFAULT 0,
  last_downloaded_at   TEXT,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_report_token        ON report_access(token);
CREATE INDEX IF NOT EXISTS idx_report_scan_id      ON report_access(scan_id);
CREATE INDEX IF NOT EXISTS idx_report_user         ON report_access(user_id);
CREATE INDEX IF NOT EXISTS idx_report_expires      ON report_access(expires_at);

-- ─── Analytics Events ──────────────────────────────────────────────────────────
-- Tracks: scan_started, scan_completed, payment_initiated, payment_completed,
--         report_downloaded, payment_signature_invalid, lead_captured, etc.
CREATE TABLE IF NOT EXISTS analytics_events (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type   TEXT    NOT NULL,
  module       TEXT,
  user_id      TEXT,
  ip           TEXT,
  metadata     TEXT,   -- JSON blob
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_analytics_type      ON analytics_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_module    ON analytics_events(module, created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_user      ON analytics_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_date      ON analytics_events(created_at);

-- ─── Seed: default admin placeholder ─────────────────────────────────────────
-- Real users created via signup API. This is a structural placeholder only.
-- INSERT INTO users (id, email, password_hash, password_salt, tier, full_name)
-- VALUES ('admin_seed_001', 'admin@cyberdudebivash.com', '', '', 'ENTERPRISE', 'Platform Admin');

-- ═══════════════════════════════════════════════════════════════════════════════
-- ADAPTIVE CYBER BRAIN — v21.0 Schema
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema.sql
-- These tables are additive — CREATE IF NOT EXISTS ensures zero regression.
-- ═══════════════════════════════════════════════════════════════════════════════

-- ─── brain_feedback ───────────────────────────────────────────────────────────
-- Stores every user action on a scan finding.
-- Drives per-user weight evolution in the Feedback Learning Engine.
CREATE TABLE IF NOT EXISTS brain_feedback (
  id               TEXT    PRIMARY KEY,
  user_id          TEXT    NOT NULL,
  target           TEXT,
  finding_id       TEXT,
  finding_type     TEXT    NOT NULL,
  severity         TEXT    NOT NULL DEFAULT 'MEDIUM'
                           CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  action           TEXT    NOT NULL
                           CHECK (action IN ('ignored','fixed','escalated','false_positive')),
  risk_score_at_time INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_brain_feedback_user       ON brain_feedback(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_brain_feedback_type       ON brain_feedback(finding_type, action);
CREATE INDEX IF NOT EXISTS idx_brain_feedback_action     ON brain_feedback(action, created_at);

-- ─── brain_weights ────────────────────────────────────────────────────────────
-- Persists learned risk weight per user per weight_key.
-- KV is the hot path; this is the durable audit record.
CREATE TABLE IF NOT EXISTS brain_weights (
  id               TEXT    PRIMARY KEY,
  user_id          TEXT    NOT NULL,
  weight_key       TEXT    NOT NULL,
  weight_value     REAL    NOT NULL DEFAULT 10.0,
  feedback_count   INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, weight_key)
);

CREATE INDEX IF NOT EXISTS idx_brain_weights_user        ON brain_weights(user_id);
CREATE INDEX IF NOT EXISTS idx_brain_weights_key         ON brain_weights(weight_key, weight_value);

-- ─── brain_global_signals ─────────────────────────────────────────────────────
-- Anonymised cross-tenant signals used to build the global intelligence heatmap.
-- No PII stored — only aggregated threat patterns.
CREATE TABLE IF NOT EXISTS brain_global_signals (
  id               TEXT    PRIMARY KEY,
  signal_type      TEXT    NOT NULL,   -- 'false_positive_pattern' | 'emerging_threat' | 'attack_pattern'
  finding_type     TEXT,
  severity         TEXT,
  source_tier      TEXT    DEFAULT 'UNKNOWN',
  sector           TEXT    DEFAULT 'general',
  metadata         TEXT,               -- JSON: additional context (no PII)
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_brain_signals_type        ON brain_global_signals(signal_type, created_at);
CREATE INDEX IF NOT EXISTS idx_brain_signals_finding     ON brain_global_signals(finding_type, signal_type);
CREATE INDEX IF NOT EXISTS idx_brain_signals_sector      ON brain_global_signals(sector, created_at);

-- ─── brain_predictions ────────────────────────────────────────────────────────
-- Persists attack path prediction summaries for audit + trend analysis.
-- Full prediction payloads cached in KV; only summary stored here.
CREATE TABLE IF NOT EXISTS brain_predictions (
  id                   TEXT    PRIMARY KEY,
  user_id              TEXT,
  target               TEXT,
  sector               TEXT    DEFAULT 'technology',
  breach_probability   REAL    NOT NULL DEFAULT 0,
  chain_count          INTEGER NOT NULL DEFAULT 0,
  ttb_hours            INTEGER,          -- predicted time-to-breach in hours
  top_chain_type       TEXT,
  adaptive_score       INTEGER,
  generated_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_brain_predictions_user    ON brain_predictions(user_id, generated_at);
CREATE INDEX IF NOT EXISTS idx_brain_predictions_sector  ON brain_predictions(sector, breach_probability);
CREATE INDEX IF NOT EXISTS idx_brain_predictions_date    ON brain_predictions(generated_at);

-- ─── brain_model_snapshots ────────────────────────────────────────────────────
-- Point-in-time weight snapshots for model drift analysis (ENTERPRISE).
-- Written daily by cron. Enables weight version history + rollback.
CREATE TABLE IF NOT EXISTS brain_model_snapshots (
  id               TEXT    PRIMARY KEY,
  user_id          TEXT    NOT NULL,
  snapshot_date    TEXT    NOT NULL,   -- YYYY-MM-DD
  weights_json     TEXT    NOT NULL,   -- full weights object as JSON
  feedback_count   INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_brain_snapshots_user      ON brain_model_snapshots(user_id, snapshot_date);

-- ============================================================
-- SOURCE: schema_v8.sql
-- ============================================================

-- ════════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Schema V8.0 (PRODUCTION-SAFE FIXED)
-- ════════════════════════════════════════════════════════════════════════════
--
-- ROOT CAUSE ANALYSIS (run failure "Apply v8 extensions"):
--
--   D1 executes each --file submission as a single atomic transaction.
--   If ANY statement fails, the ENTIRE file rolls back and exits code 1.
--
--   Three collisions existed between this file and earlier schema files:
--
--   1. api_keys       — also defined in schema_threat_intel.sql (different schema!)
--                       D1 cannot have two tables with the same name even with
--                       CREATE TABLE IF NOT EXISTS when indexes then reference columns
--                       that only exist on one variant. The index on key_hash fired
--                       the "no such column" error.
--
--   2. email_tracking — also defined in schema_threat_intel.sql with DIFFERENT
--                       column set (missing sequence_id TEXT NOT NULL). The
--                       CREATE TABLE IF NOT EXISTS silently succeeds on a non-empty
--                       DB (table already exists), but the UNIQUE index on
--                       (email, sequence_id, step, event) then finds the column
--                       does not exist on the pre-existing table → SQLITE_ERROR.
--
--   3. leads          — also defined in schema_threat_intel.sql. Same problem:
--                       this file's richer column set doesn't exist on the table
--                       that was already created by the earlier schema file.
--                       Indexes on missing columns (ip, country, drip_sequence etc.)
--                       cause SQLITE_ERROR.
--
--   FIX: Remove the three duplicate table definitions from this file entirely.
--   Those tables are already handled (and kept up-to-date) by:
--     - api_keys        → schema_threat_intel.sql (GTM section) + drift patch
--     - email_tracking  → schema_threat_intel.sql (GTM section)
--     - leads           → schema_threat_intel.sql (GTM section)
--
--   The v8-specific NEW columns on those tables are added below via idempotent
--   ALTER TABLE statements that are each individually safe to re-run.
--
-- IDEMPOTENCY GUARANTEE:
--   Every CREATE TABLE uses IF NOT EXISTS.
--   Every CREATE INDEX uses IF NOT EXISTS.
--   ALTER TABLE statements are handled in the workflow drift-patch step,
--   not in this file, to keep this file's transaction clean.
--
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Organizations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name             TEXT NOT NULL,
  slug             TEXT UNIQUE NOT NULL,
  plan             TEXT NOT NULL DEFAULT 'STARTER'
                     CHECK (plan IN ('STARTER','PRO','ENTERPRISE')),
  owner_id         TEXT NOT NULL,
  max_members      INTEGER NOT NULL DEFAULT 5,
  max_daily_scans  INTEGER NOT NULL DEFAULT 100,
  settings_json    TEXT NOT NULL DEFAULT '{}',
  logo_url         TEXT,
  domain           TEXT,
  industry         TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_org_owner ON organizations(owner_id);
CREATE INDEX IF NOT EXISTS idx_org_slug  ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_org_plan  ON organizations(plan);

-- ─── Org Members ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_members (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  org_id      TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'MEMBER'
                CHECK (role IN ('OWNER','ADMIN','ANALYST','MEMBER','VIEWER')),
  invited_by  TEXT,
  invite_email TEXT,
  status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','invited','suspended')),
  joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_org  ON org_members(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);

-- ─── Monitor Configs ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitor_configs (
  id                   TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id              TEXT NOT NULL,
  org_id               TEXT,
  name                 TEXT NOT NULL,
  module               TEXT NOT NULL
                         CHECK (module IN ('domain','ai','redteam','identity','compliance')),
  target_json          TEXT NOT NULL,
  schedule             TEXT NOT NULL DEFAULT 'daily'
                         CHECK (schedule IN ('hourly','daily','weekly','monthly')),
  enabled              INTEGER NOT NULL DEFAULT 1,
  alert_on_drift       INTEGER NOT NULL DEFAULT 1,
  alert_on_critical    INTEGER NOT NULL DEFAULT 1,
  drift_threshold      INTEGER NOT NULL DEFAULT 10,
  baseline_risk_score  INTEGER,
  last_scan_score      INTEGER,
  last_run_at          TEXT,
  next_run_at          TEXT,
  run_count            INTEGER NOT NULL DEFAULT 0,
  fail_count           INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_monitor_user ON monitor_configs(user_id, enabled);

-- ─── Monitor Results ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitor_results (
  id                  TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  config_id           TEXT NOT NULL,
  user_id             TEXT NOT NULL,
  module              TEXT NOT NULL,
  target_summary      TEXT,
  risk_score          INTEGER NOT NULL,
  risk_level          TEXT NOT NULL,
  findings_count      INTEGER NOT NULL DEFAULT 0,
  critical_count      INTEGER NOT NULL DEFAULT 0,
  high_count          INTEGER NOT NULL DEFAULT 0,
  new_findings_count  INTEGER NOT NULL DEFAULT 0,
  resolved_count      INTEGER NOT NULL DEFAULT 0,
  drift_delta         INTEGER NOT NULL DEFAULT 0,
  drift_type          TEXT NOT NULL DEFAULT 'none'
                        CHECK (drift_type IN ('improved','degraded','stable','new','none')),
  ai_narrative        TEXT,
  alert_sent          INTEGER NOT NULL DEFAULT 0,
  scan_result_r2_key  TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── Content Posts ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS content_posts (
  id                       TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id                  TEXT NOT NULL,
  org_id                   TEXT,
  type                     TEXT NOT NULL DEFAULT 'blog'
                             CHECK (type IN ('blog','linkedin','telegram','executive_brief','threat_advisory')),
  title                    TEXT NOT NULL,
  body_md                  TEXT NOT NULL,
  excerpt                  TEXT,
  tags                     TEXT,
  scan_job_id              TEXT,
  module                   TEXT,
  target_summary           TEXT,
  published_to_telegram    INTEGER NOT NULL DEFAULT 0,
  published_to_linkedin    INTEGER NOT NULL DEFAULT 0,
  telegram_msg_id          TEXT,
  linkedin_post_id         TEXT,
  published_at             TEXT,
  view_count               INTEGER NOT NULL DEFAULT 0,
  created_at               TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── API Requests ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_requests (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  api_key_id  TEXT,
  user_id     TEXT,
  endpoint    TEXT NOT NULL,
  method      TEXT NOT NULL,
  status_code INTEGER,
  latency_ms  INTEGER,
  ip          TEXT,
  ua          TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── Threat Intel Cache ──────────────────────────────────────────────────────
-- NOTE: This is distinct from the threat_intel table in schema_threat_intel.sql.
-- threat_intel_cache is a short-lived enrichment cache keyed by CVE ID.
-- threat_intel is the permanent advisory store.
CREATE TABLE IF NOT EXISTS threat_intel_cache (
  cve_id          TEXT PRIMARY KEY,
  cvss_score      REAL,
  cvss_vector     TEXT,
  epss_score      REAL,
  epss_pct        REAL,
  is_kev          INTEGER NOT NULL DEFAULT 0,
  kev_added       TEXT,
  description     TEXT,
  cpe_list        TEXT,
  references_json TEXT,
  cached_at       TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at      TEXT NOT NULL
);


-- ════════════════════════════════════════════════════════════════════════════
-- V8.1 SCHEMA EXTENSIONS
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Gumroad Licenses ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gumroad_licenses (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  license_key       TEXT UNIQUE NOT NULL,
  product_permalink TEXT NOT NULL,
  product_name      TEXT NOT NULL,
  buyer_email       TEXT NOT NULL,
  buyer_name        TEXT,
  user_id           TEXT,
  tier_granted      TEXT NOT NULL DEFAULT 'PRO',
  credits_granted   INTEGER NOT NULL DEFAULT 0,
  status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','disabled','refunded')),
  purchase_id       TEXT,
  sale_id           TEXT,
  activated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at        TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_gumroad_email   ON gumroad_licenses(buyer_email);
CREATE INDEX IF NOT EXISTS idx_gumroad_user    ON gumroad_licenses(user_id);
CREATE INDEX IF NOT EXISTS idx_gumroad_product ON gumroad_licenses(product_permalink);

-- ─── User Credits ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_credits (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT NOT NULL,
  total        INTEGER NOT NULL DEFAULT 0,
  used         INTEGER NOT NULL DEFAULT 0,
  source       TEXT NOT NULL DEFAULT 'gumroad'
                 CHECK (source IN ('gumroad','purchase','bonus','referral','promo')),
  reference_id TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_credits_user ON user_credits(user_id);

-- ─── Audit Log ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  action     TEXT NOT NULL,
  user_id    TEXT,
  ip         TEXT,
  user_agent TEXT,
  resource   TEXT,
  details    TEXT DEFAULT '{}',
  severity   TEXT NOT NULL DEFAULT 'info'
               CHECK (severity IN ('info','warn','critical')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);

-- ─── Affiliate Clicks ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS affiliate_clicks (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  program    TEXT NOT NULL,
  link_id    TEXT NOT NULL,
  link_url   TEXT NOT NULL,
  ref_page   TEXT,
  ip         TEXT,
  country    TEXT,
  user_agent TEXT,
  converted  INTEGER NOT NULL DEFAULT 0,
  revenue    REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_affiliate_program ON affiliate_clicks(program);
CREATE INDEX IF NOT EXISTS idx_affiliate_link    ON affiliate_clicks(link_id);
CREATE INDEX IF NOT EXISTS idx_affiliate_conv    ON affiliate_clicks(converted);

-- ─── Revenue Events ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS revenue_events (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  source     TEXT NOT NULL
               CHECK (source IN ('razorpay','gumroad','affiliate','subscription','api_credits')),
  amount_inr REAL NOT NULL DEFAULT 0,
  amount_usd REAL NOT NULL DEFAULT 0,
  user_id    TEXT,
  email      TEXT,
  product    TEXT,
  reference  TEXT,
  metadata   TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_rev_source  ON revenue_events(source);
CREATE INDEX IF NOT EXISTS idx_rev_created ON revenue_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_user    ON revenue_events(user_id);

-- ─── AdSense Events ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS adsense_events (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type  TEXT NOT NULL
                CHECK (event_type IN ('impression','click','revenue')),
  slot_id     TEXT,
  page        TEXT,
  ip          TEXT,
  country     TEXT,
  revenue_usd REAL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_adsense_type ON adsense_events(event_type);
CREATE INDEX IF NOT EXISTS idx_adsense_page ON adsense_events(page);

-- ════════════════════════════════════════════════════════════════════════════
-- END OF SCHEMA V8.0 / V8.1
--
-- TABLES INTENTIONALLY NOT IN THIS FILE (owned by other schema files):
--   api_keys        → schema_threat_intel.sql (GTM section)
--   email_tracking  → schema_threat_intel.sql (GTM section)
--   leads           → schema_threat_intel.sql (GTM section)
--
-- Extended columns for those tables are handled by the idempotent
-- ALTER TABLE drift-patch step in automation.yml (schema-migrate job),
-- which runs BEFORE this file and uses || true suppression.
-- ════════════════════════════════════════════════════════════════════════════

-- ============================================================
-- SOURCE: schema_v10.sql
-- ============================================================

-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v10.0
-- Sentinel APEX Defense Solutions + Revenue Snapshots
-- ============================================================

-- Defense Solutions Marketplace
CREATE TABLE IF NOT EXISTS defense_solutions (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id            TEXT NOT NULL,
  title             TEXT NOT NULL,
  description       TEXT NOT NULL,
  category          TEXT NOT NULL CHECK(category IN (
    'firewall_script','ids_signature','sigma_rule','yara_rule',
    'ir_playbook','hardening_script','threat_hunt_pack',
    'python_scanner','exec_briefing','api_module'
  )),
  price_inr         INTEGER NOT NULL DEFAULT 499,
  price_usd         INTEGER NOT NULL DEFAULT 6,
  demand_score      REAL NOT NULL DEFAULT 0.5,
  severity          TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  cvss_score        REAL,
  preview           TEXT NOT NULL,
  full_content_key  TEXT NOT NULL,
  difficulty        TEXT NOT NULL DEFAULT 'INTERMEDIATE' CHECK(difficulty IN ('BEGINNER','INTERMEDIATE','ADVANCED','EXPERT')),
  apt_groups        TEXT,
  mitre_techniques  TEXT,
  affected_systems  TEXT,
  purchase_count    INTEGER NOT NULL DEFAULT 0,
  view_count        INTEGER NOT NULL DEFAULT 0,
  is_featured       INTEGER NOT NULL DEFAULT 0,
  is_active         INTEGER NOT NULL DEFAULT 1,
  generated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_cve ON defense_solutions(cve_id);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_category ON defense_solutions(category);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_severity ON defense_solutions(severity);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_featured ON defense_solutions(is_featured) WHERE is_featured = 1;
CREATE INDEX IF NOT EXISTS idx_defense_solutions_demand ON defense_solutions(demand_score DESC);
CREATE INDEX IF NOT EXISTS idx_defense_solutions_created ON defense_solutions(created_at DESC);

-- Defense Solution Purchases
CREATE TABLE IF NOT EXISTS defense_purchases (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  solution_id       TEXT NOT NULL REFERENCES defense_solutions(id),
  user_id           TEXT,
  email             TEXT,
  razorpay_order_id TEXT,
  razorpay_payment_id TEXT,
  amount_inr        INTEGER NOT NULL,
  amount_usd        INTEGER,
  currency          TEXT NOT NULL DEFAULT 'INR',
  status            TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed','refunded')),
  access_key        TEXT,
  access_expires_at TEXT,
  ip_country        TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_defense_purchases_solution ON defense_purchases(solution_id);
CREATE INDEX IF NOT EXISTS idx_defense_purchases_user ON defense_purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_defense_purchases_status ON defense_purchases(status);
CREATE INDEX IF NOT EXISTS idx_defense_purchases_created ON defense_purchases(created_at DESC);

-- Revenue Snapshots (for trend charts)
CREATE TABLE IF NOT EXISTS revenue_snapshots (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  snapshot_date   TEXT NOT NULL UNIQUE,
  mrr_inr         REAL NOT NULL DEFAULT 0,
  arr_inr         REAL NOT NULL DEFAULT 0,
  daily_revenue   REAL NOT NULL DEFAULT 0,
  subscriptions   INTEGER NOT NULL DEFAULT 0,
  new_subs        INTEGER NOT NULL DEFAULT 0,
  churned_subs    INTEGER NOT NULL DEFAULT 0,
  defense_sales   INTEGER NOT NULL DEFAULT 0,
  defense_revenue REAL NOT NULL DEFAULT 0,
  api_revenue     REAL NOT NULL DEFAULT 0,
  affiliate_rev   REAL NOT NULL DEFAULT 0,
  adsense_rev     REAL NOT NULL DEFAULT 0,
  enterprise_rev  REAL NOT NULL DEFAULT 0,
  total_users     INTEGER NOT NULL DEFAULT 0,
  active_users    INTEGER NOT NULL DEFAULT 0,
  free_users      INTEGER NOT NULL DEFAULT 0,
  paid_users      INTEGER NOT NULL DEFAULT 0,
  total_scans     INTEGER NOT NULL DEFAULT 0,
  conversion_rate REAL NOT NULL DEFAULT 0,
  arpu            REAL NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_revenue_snapshots_date ON revenue_snapshots(snapshot_date DESC);

-- Enterprise Consultation Leads
CREATE TABLE IF NOT EXISTS enterprise_leads (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  company_name    TEXT NOT NULL,
  contact_name    TEXT,
  email           TEXT NOT NULL,
  phone           TEXT,
  domain          TEXT,
  requirements    TEXT,
  package_interest TEXT DEFAULT 'enterprise',
  team_size       TEXT,
  industry        TEXT,
  annual_budget   TEXT,
  urgency         TEXT DEFAULT 'normal' CHECK(urgency IN ('immediate','urgent','normal','exploratory')),
  source          TEXT DEFAULT 'website',
  status          TEXT DEFAULT 'new' CHECK(status IN ('new','contacted','qualified','proposal','closed_won','closed_lost')),
  notes           TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_enterprise_leads_email ON enterprise_leads(email);
CREATE INDEX IF NOT EXISTS idx_enterprise_leads_status ON enterprise_leads(status);
CREATE INDEX IF NOT EXISTS idx_enterprise_leads_created ON enterprise_leads(created_at DESC);

-- Custom Solution Requests
CREATE TABLE IF NOT EXISTS custom_solution_requests (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id         TEXT,
  email           TEXT NOT NULL,
  cve_id          TEXT,
  solution_types  TEXT,
  tech_stack      TEXT,
  description     TEXT NOT NULL,
  budget_range    TEXT,
  deadline        TEXT,
  status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewing','quoted','in_progress','delivered','closed')),
  quote_inr       INTEGER,
  quote_usd       INTEGER,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_custom_requests_email ON custom_solution_requests(email);
CREATE INDEX IF NOT EXISTS idx_custom_requests_status ON custom_solution_requests(status);

-- Blog Posts (for content automation pipeline)
CREATE TABLE IF NOT EXISTS blog_posts (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id          TEXT,
  slug            TEXT NOT NULL UNIQUE,
  title           TEXT NOT NULL,
  excerpt         TEXT,
  content         TEXT NOT NULL,
  html_content    TEXT,
  author          TEXT DEFAULT 'CYBERDUDEBIVASH AI',
  tags            TEXT,
  category        TEXT,
  seo_title       TEXT,
  seo_description TEXT,
  seo_keywords    TEXT,
  featured_image  TEXT,
  status          TEXT DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
  published_at    TEXT,
  linkedin_posted INTEGER DEFAULT 0,
  telegram_posted INTEGER DEFAULT 0,
  twitter_posted  INTEGER DEFAULT 0,
  views           INTEGER DEFAULT 0,
  solution_cta    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_blog_posts_cve ON blog_posts(cve_id);
CREATE INDEX IF NOT EXISTS idx_blog_posts_slug ON blog_posts(slug);
CREATE INDEX IF NOT EXISTS idx_blog_posts_status ON blog_posts(status);
CREATE INDEX IF NOT EXISTS idx_blog_posts_published ON blog_posts(published_at DESC);

-- FOMO / Social Proof counters
CREATE TABLE IF NOT EXISTS fomo_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type      TEXT NOT NULL CHECK(event_type IN ('purchase','scan','view','download','signup','upgrade')),
  entity_type     TEXT,
  entity_id       TEXT,
  display_name    TEXT,
  ip_country      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_fomo_events_type ON fomo_events(event_type);
CREATE INDEX IF NOT EXISTS idx_fomo_events_created ON fomo_events(created_at DESC);

-- ============================================================
-- D1 binding: SECURITY_HUB_DB (same as existing)
-- KV binding: SECURITY_HUB_KV (same as existing)
-- R2 binding: SECURITY_HUB_R2 (for large content storage)
-- ============================================================

-- ============================================================
-- SOURCE: schema_v12.sql
-- ============================================================

-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v12.0
-- System 1: Agentic AI Autonomous Remediation Engine
-- System 2: Behavioral Anomaly Detection Engine
-- System 3: Predictive Threat Intelligence Engine
-- ============================================================

-- ── AGENT SYSTEM ────────────────────────────────────────────

-- All agent action executions (immutable audit trail)
CREATE TABLE IF NOT EXISTS agent_actions (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  agent_type        TEXT NOT NULL CHECK(agent_type IN (
    'threat_response','credential_rotation','isolation','patching','composite'
  )),
  action_type       TEXT NOT NULL CHECK(action_type IN (
    'block_ip','rotate_credentials','disable_session','apply_virtual_patch',
    'quarantine_user','kill_process','revoke_token','rate_limit_ip',
    'alert_admin','escalate','rollback'
  )),
  target            TEXT NOT NULL,
  target_type       TEXT NOT NULL DEFAULT 'ip' CHECK(target_type IN (
    'ip','user_id','session_id','cve_id','domain','api_key','endpoint'
  )),
  trigger_source    TEXT NOT NULL CHECK(trigger_source IN (
    'cve_ingestion','anomaly_detected','manual','scheduled','threat_intel','api_call'
  )),
  trigger_id        TEXT,
  risk_level        TEXT NOT NULL DEFAULT 'HIGH' CHECK(risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  decision_score    REAL NOT NULL DEFAULT 0,
  execution_status  TEXT NOT NULL DEFAULT 'pending' CHECK(execution_status IN (
    'pending','executing','SUCCESS','FAILED','ROLLED_BACK','SKIPPED'
  )),
  execution_detail  TEXT,
  rollback_available INTEGER NOT NULL DEFAULT 1,
  rollback_action   TEXT,
  executed_by       TEXT NOT NULL DEFAULT 'autonomous_agent',
  user_id           TEXT,
  duration_ms       INTEGER,
  error_message     TEXT,
  metadata          TEXT DEFAULT '{}',
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_actions_type    ON agent_actions(action_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_actions_target  ON agent_actions(target);
CREATE INDEX IF NOT EXISTS idx_agent_actions_status  ON agent_actions(execution_status);
CREATE INDEX IF NOT EXISTS idx_agent_actions_risk    ON agent_actions(risk_level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_actions_trigger ON agent_actions(trigger_source, trigger_id);

-- Agent event bus queue (pending events awaiting processing)
CREATE TABLE IF NOT EXISTS agent_event_queue (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type   TEXT NOT NULL,
  payload      TEXT NOT NULL,
  priority     INTEGER NOT NULL DEFAULT 5,
  status       TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','done','failed')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  error        TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  processed_at TEXT,
  next_retry   TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_queue_status ON agent_event_queue(status, priority DESC, created_at);

-- IP blocklist (enforced on every request by middleware)
CREATE TABLE IF NOT EXISTS ip_blocklist (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  ip          TEXT NOT NULL UNIQUE,
  reason      TEXT NOT NULL,
  threat_type TEXT DEFAULT 'automated_agent',
  risk_level  TEXT NOT NULL DEFAULT 'HIGH',
  action_id   TEXT REFERENCES agent_actions(id),
  blocked_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT,
  is_active   INTEGER NOT NULL DEFAULT 1,
  block_count INTEGER NOT NULL DEFAULT 1,
  last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocklist_ip     ON ip_blocklist(ip, is_active);
CREATE INDEX IF NOT EXISTS idx_blocklist_active ON ip_blocklist(is_active, expires_at);

-- Session blacklist (JWT tokens that have been invalidated)
CREATE TABLE IF NOT EXISTS session_blacklist (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT NOT NULL,
  token_hash  TEXT UNIQUE,
  reason      TEXT NOT NULL DEFAULT 'agent_disable',
  action_id   TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_bl_user ON session_blacklist(user_id);
CREATE INDEX IF NOT EXISTS idx_session_bl_hash ON session_blacklist(token_hash);

-- Virtual WAF patches (applied by patching agent, enforced by middleware)
CREATE TABLE IF NOT EXISTS virtual_patches (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id       TEXT NOT NULL,
  patch_type   TEXT NOT NULL CHECK(patch_type IN (
    'header_injection','path_block','param_filter','rate_limit','redirect','custom_rule'
  )),
  rule_name    TEXT NOT NULL,
  rule_pattern TEXT NOT NULL,
  rule_action  TEXT NOT NULL DEFAULT 'block' CHECK(rule_action IN ('block','log','rate_limit','redirect')),
  priority     INTEGER NOT NULL DEFAULT 100,
  is_active    INTEGER NOT NULL DEFAULT 1,
  hit_count    INTEGER NOT NULL DEFAULT 0,
  last_hit     TEXT,
  action_id    TEXT,
  expires_at   TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vp_cve    ON virtual_patches(cve_id, is_active);
CREATE INDEX IF NOT EXISTS idx_vp_active ON virtual_patches(is_active, priority);

-- Rotated credentials log (audit only, no secrets stored)
CREATE TABLE IF NOT EXISTS credential_rotation_log (
  id             TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id        TEXT NOT NULL,
  rotation_type  TEXT NOT NULL CHECK(rotation_type IN ('api_key','session_token','all')),
  keys_rotated   INTEGER NOT NULL DEFAULT 0,
  sessions_killed INTEGER NOT NULL DEFAULT 0,
  action_id      TEXT,
  reason         TEXT NOT NULL,
  initiated_by   TEXT NOT NULL DEFAULT 'agent',
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cred_rot_user ON credential_rotation_log(user_id, created_at DESC);

-- ── ANOMALY DETECTION ENGINE ────────────────────────────────

-- User behavior baseline (rolling 30-day window)
CREATE TABLE IF NOT EXISTS user_behavior_baseline (
  user_id            TEXT PRIMARY KEY,
  avg_login_hour     REAL NOT NULL DEFAULT 9.0,
  stddev_login_hour  REAL NOT NULL DEFAULT 2.0,
  typical_ips        TEXT NOT NULL DEFAULT '[]',
  typical_countries  TEXT NOT NULL DEFAULT '[]',
  avg_api_calls_hr   REAL NOT NULL DEFAULT 10.0,
  stddev_api_calls   REAL NOT NULL DEFAULT 5.0,
  avg_scan_day       REAL NOT NULL DEFAULT 2.0,
  stddev_scans       REAL NOT NULL DEFAULT 1.5,
  total_sessions     INTEGER NOT NULL DEFAULT 0,
  failed_logins_avg  REAL NOT NULL DEFAULT 0.1,
  last_computed_at   TEXT NOT NULL DEFAULT (datetime('now')),
  data_points        INTEGER NOT NULL DEFAULT 0
);

-- Raw behavior events (used for baseline computation and scoring)
CREATE TABLE IF NOT EXISTS behavior_events (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT NOT NULL,
  event_type   TEXT NOT NULL CHECK(event_type IN (
    'login','logout','api_call','scan','download','payment','failed_login','password_change'
  )),
  ip           TEXT,
  country      TEXT,
  city         TEXT,
  hour_of_day  INTEGER,
  day_of_week  INTEGER,
  user_agent   TEXT,
  endpoint     TEXT,
  metadata     TEXT DEFAULT '{}',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_behav_user    ON behavior_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_behav_type    ON behavior_events(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_behav_ip      ON behavior_events(ip, created_at DESC);

-- Anomaly detection results
CREATE TABLE IF NOT EXISTS anomaly_events (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  anomaly_score    REAL NOT NULL,
  anomaly_types    TEXT NOT NULL DEFAULT '[]',
  features_vector  TEXT NOT NULL DEFAULT '{}',
  isolation_depth  REAL,
  z_scores         TEXT DEFAULT '{}',
  risk_level       TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
  auto_actioned    INTEGER NOT NULL DEFAULT 0,
  action_id        TEXT,
  resolved         INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_anomaly_user  ON anomaly_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_score ON anomaly_events(anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_risk  ON anomaly_events(risk_level, created_at DESC);

-- ── PREDICTIVE THREAT INTELLIGENCE ENGINE ──────────────────

-- Threat prediction records
CREATE TABLE IF NOT EXISTS threat_predictions (
  id                    TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id                TEXT NOT NULL,
  prediction_date       TEXT NOT NULL DEFAULT (date('now')),
  exploit_probability   REAL NOT NULL DEFAULT 0,
  impact_score          REAL NOT NULL DEFAULT 0,
  exposure_score        REAL NOT NULL DEFAULT 0,
  risk_score            REAL NOT NULL DEFAULT 0,
  probability_pct       REAL NOT NULL DEFAULT 0,
  expected_window_hrs   INTEGER NOT NULL DEFAULT 72,
  attack_window_label   TEXT NOT NULL DEFAULT '72h',
  apt_groups            TEXT DEFAULT '[]',
  mitre_techniques      TEXT DEFAULT '[]',
  recommended_action    TEXT NOT NULL,
  confidence            REAL NOT NULL DEFAULT 0.5,
  is_kev                INTEGER NOT NULL DEFAULT 0,
  cvss_score            REAL,
  epss_score            REAL,
  affected_systems_est  INTEGER DEFAULT 0,
  velocity_7d           REAL DEFAULT 0,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(cve_id, prediction_date)
);
CREATE INDEX IF NOT EXISTS idx_pred_risk     ON threat_predictions(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_pred_date     ON threat_predictions(prediction_date DESC);
CREATE INDEX IF NOT EXISTS idx_pred_cve      ON threat_predictions(cve_id);
CREATE INDEX IF NOT EXISTS idx_pred_prob     ON threat_predictions(probability_pct DESC);
CREATE INDEX IF NOT EXISTS idx_pred_window   ON threat_predictions(expected_window_hrs);

-- APT group profiles (seeded from threat intel)
CREATE TABLE IF NOT EXISTS apt_profiles (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  group_name      TEXT NOT NULL UNIQUE,
  aliases         TEXT DEFAULT '[]',
  origin_country  TEXT,
  target_sectors  TEXT DEFAULT '[]',
  typical_cves    TEXT DEFAULT '[]',
  mitre_ttps      TEXT DEFAULT '[]',
  activity_level  TEXT DEFAULT 'ACTIVE' CHECK(activity_level IN ('ACTIVE','DORMANT','RETIRED','UNKNOWN')),
  last_seen       TEXT,
  ioc_count       INTEGER DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── RBAC ROLES ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_roles (
  user_id    TEXT NOT NULL,
  role       TEXT NOT NULL CHECK(role IN ('SUPERADMIN','ADMIN','SOC_ANALYST','THREAT_HUNTER','VIEWER','API_USER')),
  granted_by TEXT,
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, role)
);
CREATE INDEX IF NOT EXISTS idx_roles_user ON user_roles(user_id);

-- ── RATE LIMIT STATE ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limit_state (
  key        TEXT PRIMARY KEY,
  count      INTEGER NOT NULL DEFAULT 1,
  window_end TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── SEED: Known APT Groups ──────────────────────────────────
INSERT OR IGNORE INTO apt_profiles (id, group_name, aliases, origin_country, target_sectors, typical_cves, mitre_ttps, activity_level, last_seen) VALUES
('apt1','APT28 (Fancy Bear)','["Fancy Bear","Sofacy","STRONTIUM"]','Russia','["Government","Defense","Energy"]','["CVE-2023-23397","CVE-2022-30190"]','["T1566","T1071","T1027","T1053","T1078"]','ACTIVE','2024-11-01'),
('apt2','APT41 (Double Dragon)','["Double Dragon","Winnti","BARIUM"]','China','["Healthcare","Technology","Financial"]','["CVE-2021-44228","CVE-2021-26855"]','["T1190","T1133","T1059","T1486","T1083"]','ACTIVE','2024-10-15'),
('apt3','Lazarus Group','["Hidden Cobra","ZINC","APT-C-26"]','North Korea','["Financial","Cryptocurrency","Defense"]','["CVE-2022-41040","CVE-2021-40444"]','["T1566","T1203","T1055","T1486"]','ACTIVE','2024-11-10'),
('apt4','Sandworm','["Voodoo Bear","Telebots","IRON VIKING"]','Russia','["Energy","Industrial","Government"]','["CVE-2022-30190","CVE-2023-36884"]','["T1190","T1486","T1070","T1561"]','ACTIVE','2024-09-20'),
('apt5','Scattered Spider','["UNC3944","Muddled Libra"]','Unknown','["Retail","Hospitality","Telecom"]','["CVE-2023-4966","CVE-2023-46747"]','["T1078","T1598","T1621","T1539"]','ACTIVE','2024-10-30');

-- ============================================================
-- SOURCE: schema_v15.sql
-- ============================================================

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

-- ============================================================
-- SOURCE: schema_v28.sql
-- ============================================================

-- ============================================================
-- CYBERDUDEBIVASH v28.0 — AI Security Platform Schema
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./schema_v28.sql
-- All IF NOT EXISTS — safe to run on live D1
-- ============================================================

-- PILLAR 1: AI ASSET INVENTORY (ASPM) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_assets (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  name            TEXT NOT NULL DEFAULT '',
  asset_type      TEXT NOT NULL DEFAULT 'model',
    -- model | agent | rag | api | dataset | pipeline | embedding
  provider        TEXT,  -- openai | anthropic | google | azure | huggingface | custom
  model_name      TEXT,
  version         TEXT,
  deployment      TEXT,  -- cloud | on-prem | hybrid | saas
  endpoint_url    TEXT,
  exposure        TEXT NOT NULL DEFAULT 'internal',  -- public | internal | restricted
  risk_score      INTEGER NOT NULL DEFAULT 0,
  security_score  INTEGER NOT NULL DEFAULT 100,
  status          TEXT NOT NULL DEFAULT 'active',  -- active | deprecated | retired
  owner_email     TEXT,
  tags            TEXT DEFAULT '[]',
  last_scanned    INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_assets_org        ON ai_assets(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_assets_type       ON ai_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_ai_assets_risk       ON ai_assets(risk_score);
CREATE INDEX IF NOT EXISTS idx_ai_assets_exposure   ON ai_assets(exposure);

-- AI Security findings per asset ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_findings (
  id              TEXT PRIMARY KEY,
  asset_id        TEXT NOT NULL DEFAULT '',
  scan_id         TEXT,
  category        TEXT NOT NULL DEFAULT 'LLM01',
    -- OWASP LLM: LLM01-LLM10 | NIST-GOVERN | NIST-MAP | ISO42001 | EU-AI-ACT
  title           TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  severity        TEXT NOT NULL DEFAULT 'MEDIUM',  -- CRITICAL | HIGH | MEDIUM | LOW | INFO
  cvss_score      REAL,
  cwe_id          TEXT,
  owasp_ref       TEXT,
  status          TEXT NOT NULL DEFAULT 'open',  -- open | accepted | mitigated | resolved
  remediation     TEXT,
  evidence        TEXT DEFAULT '{}',
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at     INTEGER,
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_findings_asset    ON ai_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_ai_findings_severity ON ai_findings(severity);
CREATE INDEX IF NOT EXISTS idx_ai_findings_category ON ai_findings(category);
CREATE INDEX IF NOT EXISTS idx_ai_findings_status   ON ai_findings(status);

-- PILLAR 2: AI GOVERNANCE ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_governance_assessments (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  email           TEXT NOT NULL DEFAULT '',
  framework       TEXT NOT NULL DEFAULT 'NIST_AI_RMF',
    -- NIST_AI_RMF | ISO_42001 | OWASP_LLM | EU_AI_ACT | DPDP | CUSTOM
  overall_score   INTEGER NOT NULL DEFAULT 0,    -- 0-100
  risk_tier       TEXT NOT NULL DEFAULT 'HIGH',  -- MINIMAL | LIMITED | HIGH | UNACCEPTABLE
  status          TEXT NOT NULL DEFAULT 'in_progress',
  answers         TEXT DEFAULT '{}',   -- JSON: question_id -> answer
  gaps            TEXT DEFAULT '[]',   -- JSON: gap objects
  roadmap         TEXT DEFAULT '[]',   -- JSON: remediation steps
  report_url      TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at    INTEGER,
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_gov_org       ON ai_governance_assessments(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_gov_framework ON ai_governance_assessments(framework);
CREATE INDEX IF NOT EXISTS idx_ai_gov_email     ON ai_governance_assessments(email);

-- AI Risk Register ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_risk_register (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  asset_id        TEXT,
  risk_title      TEXT NOT NULL DEFAULT '',
  risk_desc       TEXT NOT NULL DEFAULT '',
  risk_category   TEXT NOT NULL DEFAULT 'technical',
    -- technical | operational | reputational | legal | financial | strategic
  likelihood      INTEGER NOT NULL DEFAULT 3,  -- 1-5
  impact          INTEGER NOT NULL DEFAULT 3,  -- 1-5
  risk_score      INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
  risk_level      TEXT NOT NULL DEFAULT 'MEDIUM',
  owner           TEXT,
  controls        TEXT DEFAULT '[]',
  treatment       TEXT NOT NULL DEFAULT 'MITIGATE',  -- ACCEPT | MITIGATE | TRANSFER | AVOID
  status          TEXT NOT NULL DEFAULT 'open',
  due_date        INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  reviewed_at     INTEGER,
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_risk_org    ON ai_risk_register(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_risk_level  ON ai_risk_register(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_risk_status ON ai_risk_register(status);

-- PILLAR 3: AI RED TEAM ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_redteam_engagements (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  email           TEXT NOT NULL DEFAULT '',
  target_model    TEXT NOT NULL DEFAULT '',   -- model name / endpoint
  target_url      TEXT,
  attack_types    TEXT NOT NULL DEFAULT '[]', -- JSON array
    -- prompt_injection | jailbreak | tool_abuse | agent_takeover | rag_poisoning | data_exfil
  total_attempts  INTEGER NOT NULL DEFAULT 0,
  successful_attacks INTEGER NOT NULL DEFAULT 0,
  critical_findings  INTEGER NOT NULL DEFAULT 0,
  risk_score      INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'running',
  report_url      TEXT,
  started_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at    INTEGER,
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_rt_engagements_email  ON ai_redteam_engagements(email);
CREATE INDEX IF NOT EXISTS idx_rt_engagements_status ON ai_redteam_engagements(status);

CREATE TABLE IF NOT EXISTS ai_redteam_attempts (
  id              TEXT PRIMARY KEY,
  engagement_id   TEXT NOT NULL DEFAULT '',
  attack_type     TEXT NOT NULL DEFAULT '',
  payload         TEXT NOT NULL DEFAULT '',
  response        TEXT,
  success         INTEGER NOT NULL DEFAULT 0,
  severity        TEXT NOT NULL DEFAULT 'LOW',
  technique       TEXT,
  evidence        TEXT DEFAULT '{}',
  attempted_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_rt_attempts_engagement ON ai_redteam_attempts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_rt_attempts_success    ON ai_redteam_attempts(success);
CREATE INDEX IF NOT EXISTS idx_rt_attempts_type       ON ai_redteam_attempts(attack_type);

-- PILLAR 4: AI AGENT SECURITY ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_agent_inventory (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  name            TEXT NOT NULL DEFAULT '',
  framework       TEXT NOT NULL DEFAULT 'custom',
    -- openai_agents | claude | langchain | crewai | autogen | mcp | custom
  tools           TEXT NOT NULL DEFAULT '[]',  -- JSON: tool names/permissions
  permissions     TEXT NOT NULL DEFAULT '[]',  -- JSON: what the agent can do
  data_access     TEXT NOT NULL DEFAULT '[]',  -- JSON: what data it can read
  internet_access INTEGER NOT NULL DEFAULT 0,
  tool_count      INTEGER NOT NULL DEFAULT 0,
  risk_score      INTEGER NOT NULL DEFAULT 0,
  issues          TEXT DEFAULT '[]',
  status          TEXT NOT NULL DEFAULT 'active',
  last_reviewed   INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_agent_org       ON ai_agent_inventory(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_agent_framework ON ai_agent_inventory(framework);
CREATE INDEX IF NOT EXISTS idx_ai_agent_risk      ON ai_agent_inventory(risk_score);

-- PILLAR 5: AI THREAT INTELLIGENCE FEED ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_threat_feed (
  id              TEXT PRIMARY KEY,
  feed_type       TEXT NOT NULL DEFAULT 'vulnerability',
    -- vulnerability | attack_pattern | malware | prompt_attack | agent_threat | advisory
  title           TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  severity        TEXT NOT NULL DEFAULT 'MEDIUM',
  cve_id          TEXT,
  affected_models TEXT DEFAULT '[]',  -- JSON: affected model names/versions
  affected_frameworks TEXT DEFAULT '[]',
  iocs            TEXT DEFAULT '[]',
  mitigations     TEXT DEFAULT '[]',
  owasp_ref       TEXT,
  source_url      TEXT,
  published_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_feed_type       ON ai_threat_feed(feed_type);
CREATE INDEX IF NOT EXISTS idx_ai_feed_severity   ON ai_threat_feed(severity);
CREATE INDEX IF NOT EXISTS idx_ai_feed_published  ON ai_threat_feed(published_at);

-- PILLAR 6: AI SECURITY SERVICES (scoped from assessments) ───────────────────
-- Uses existing assessments table + adds service_type column linkage
CREATE TABLE IF NOT EXISTS ai_service_engagements (
  id              TEXT PRIMARY KEY,
  assessment_id   TEXT,
  email           TEXT NOT NULL DEFAULT '',
  company         TEXT,
  service_type    TEXT NOT NULL DEFAULT 'ai_security_assessment',
    -- ai_security_assessment | ai_governance | ai_redteam | managed_ai | ai_risk_advisory
  scope           TEXT DEFAULT '{}',    -- JSON: assets in scope, frameworks, depth
  status          TEXT NOT NULL DEFAULT 'scoping',
  price_inr       REAL NOT NULL DEFAULT 0,
  deliverables    TEXT DEFAULT '[]',
  analyst_email   TEXT,
  kickoff_at      INTEGER,
  delivery_at     INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_svc_email  ON ai_service_engagements(email);
CREATE INDEX IF NOT EXISTS idx_ai_svc_type   ON ai_service_engagements(service_type);
CREATE INDEX IF NOT EXISTS idx_ai_svc_status ON ai_service_engagements(status);

-- AI Security scores (time-series posture tracking) ───────────────────────────
CREATE TABLE IF NOT EXISTS ai_posture_scores (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL DEFAULT 'global',
  score_date      TEXT NOT NULL,   -- YYYY-MM-DD
  overall_score   INTEGER NOT NULL DEFAULT 0,    -- 0-100 (A/B/C/D/F)
  aspm_score      INTEGER NOT NULL DEFAULT 0,    -- PILLAR 1
  governance_score INTEGER NOT NULL DEFAULT 0,   -- PILLAR 2
  redteam_score   INTEGER NOT NULL DEFAULT 0,    -- PILLAR 3
  agent_score     INTEGER NOT NULL DEFAULT 0,    -- PILLAR 4
  intel_score     INTEGER NOT NULL DEFAULT 0,    -- PILLAR 5
  total_assets    INTEGER NOT NULL DEFAULT 0,
  critical_findings INTEGER NOT NULL DEFAULT 0,
  open_risks      INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_posture_date ON ai_posture_scores(org_id, score_date);

-- ============================================================
-- SOURCE: schema_v29.sql
-- ============================================================

-- CYBERDUDEBIVASH AI Security Hub — Schema v29.0.0 (FIXED)
-- Root cause: platform_metrics uses column `key` not `metric_key`,
-- and `value_int` not `metric_value` (confirmed from schema_v27.sql)
-- Safe: all IF NOT EXISTS / OR IGNORE

CREATE TABLE IF NOT EXISTS mcp_security_scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT UNIQUE NOT NULL,
  server_name  TEXT,
  server_url   TEXT,
  risk_score   INTEGER,
  risk_level   TEXT,
  grade        TEXT,
  vuln_count   INTEGER DEFAULT 0,
  result_json  TEXT,
  user_email   TEXT,
  scanned_at   TEXT NOT NULL,
  unlocked_at  TEXT,
  unlock_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_scans_email ON mcp_security_scans(user_email);
CREATE INDEX IF NOT EXISTS idx_mcp_scans_risk  ON mcp_security_scans(risk_level);

CREATE TABLE IF NOT EXISTS vibe_code_scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT UNIQUE NOT NULL,
  language     TEXT,
  line_count   INTEGER,
  risk_score   INTEGER,
  risk_level   TEXT,
  vuln_count   INTEGER DEFAULT 0,
  user_email   TEXT,
  scanned_at   TEXT NOT NULL,
  unlocked_at  TEXT,
  unlock_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_vibe_scans_email ON vibe_code_scans(user_email);
CREATE INDEX IF NOT EXISTS idx_vibe_scans_risk  ON vibe_code_scans(risk_level);

INSERT OR IGNORE INTO platform_metrics (key, value_int)
VALUES
  ('mcp_scans_total', 0),
  ('vibe_code_scans_total', 0);

-- ============================================================
-- SOURCE: schema_migrations_v2.sql
-- ============================================================

-- ═══════════════════════════════════════════════════════════════════════════
-- Sentinel APEX — Schema Migration v2  (PRODUCTION-SAFE REWRITE)
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ROOT CAUSE OF PRIOR FAILURE:
--   Bare ALTER TABLE statements have NO idempotency in SQLite/D1.
--   D1 runs each --file as a single atomic transaction.
--   If epss_score already exists (added in a prior run), the ALTER fires
--   "duplicate column name: epss_score: SQLITE_ERROR" and the ENTIRE file
--   rolls back → exit code 1.
--
--   SQLite / D1 does NOT support:
--     ALTER TABLE t ADD COLUMN c IF NOT EXISTS  ← SYNTAX ERROR
--
-- FIX:
--   All ALTER TABLE statements removed from this file.
--   They are now handled exclusively in the automation.yml drift-patch step
--   which runs each ALTER as an INDIVIDUAL wrangler API call with || true
--   suppression — making them permanently idempotent.
--
--   This file now contains ONLY:
--     - CREATE INDEX IF NOT EXISTS  (always safe to re-run)
--
--   The columns (epss_score, epss_percentile, actively_exploited,
--   exploit_available, ioc_list) are already present in the
--   CREATE TABLE IF NOT EXISTS block in schema_threat_intel.sql for
--   fresh installs, and are guaranteed by the drift patch for existing DBs.
--
-- ═══════════════════════════════════════════════════════════════════════════

-- Indexes already defined in schema_threat_intel.sql (CREATE INDEX IF NOT EXISTS).
-- Removed from this file to keep schema ownership unambiguous.
-- idx_threat_intel_epss and idx_threat_intel_active are owned by schema_threat_intel.sql.

-- ============================================================
-- SOURCE: schema_migration_missing_cols.sql
-- ============================================================

﻿-- Safe migration: add missing columns to threat_intel
-- Live D1 has: id, cve_id, title, description, severity, source, created_at, cvss,
--              exploit_status, iocs, epss_score, exploit_available, actively_exploited,
--              published_at, epss_percentile, ioc_list
-- Missing columns needed by storeInD1 INSERT:
ALTER TABLE threat_intel ADD COLUMN cvss_vector TEXT;
ALTER TABLE threat_intel ADD COLUMN source_url TEXT;
ALTER TABLE threat_intel ADD COLUMN known_ransomware INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN tags TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN affected_products TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN weakness_types TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN enriched INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN updated_at TEXT DEFAULT (datetime('now'));

-- ============================================================
-- SOURCE: schema_gtm_only.sql
-- ============================================================

-- ═══════════════════════════════════════════════════════════════════════════
-- Sentinel APEX — GTM Growth Engine Schema (v12.0)
-- Run this to add ONLY the new GTM tables to an existing database.
-- Safe to run on both local and remote:
--   LOCAL:  npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_gtm_only.sql
--   REMOTE: npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./schema_gtm_only.sql
-- All statements use CREATE TABLE IF NOT EXISTS — fully idempotent.
-- ═══════════════════════════════════════════════════════════════════════════

-- Leads — captured emails, plan info, lead score
CREATE TABLE IF NOT EXISTS leads (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  name            TEXT,
  domain          TEXT,
  source          TEXT DEFAULT 'scan',
  is_enterprise   INTEGER DEFAULT 0,
  plan            TEXT DEFAULT 'free',
  lead_score      INTEGER DEFAULT 0,
  funnel_stage    TEXT DEFAULT 'visitor',
  scan_count      INTEGER DEFAULT 0,
  converted_at    TEXT,
  created_at      TEXT DEFAULT (datetime('now')),
  updated_at      TEXT DEFAULT (datetime('now'))
);

-- Funnel events — granular event log per user
CREATE TABLE IF NOT EXISTS funnel_events (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  stage       TEXT NOT NULL,
  meta        TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Email sequences — drip enrollment tracker
CREATE TABLE IF NOT EXISTS email_sequences (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  sequence_id     TEXT NOT NULL,
  current_step    INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'active',
  meta            TEXT DEFAULT '{}',
  enrolled_at     TEXT DEFAULT (datetime('now')),
  next_send_at    TEXT,
  last_sent_at    TEXT
);

-- Email tracking — open/click/sent events
CREATE TABLE IF NOT EXISTS email_tracking (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  sequence_id TEXT,
  step        INTEGER DEFAULT 0,
  event       TEXT NOT NULL,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Content queue — generated content waiting to be published
CREATE TABLE IF NOT EXISTS content_queue (
  id          TEXT PRIMARY KEY,
  cve_id      TEXT,
  platform    TEXT NOT NULL,
  content     TEXT NOT NULL,
  status      TEXT DEFAULT 'pending',
  posted_at   TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- NOTE: api_keys is owned by schema.sql (user_id/key_hash/tier schema).
-- The GTM-style api_keys (email/api_key) was an alternate design that is no longer
-- used. Removed to prevent SQLITE_ERROR when CREATE INDEX fires on missing columns.

-- API usage log — per-request log
CREATE TABLE IF NOT EXISTS api_usage_log (
  id          TEXT PRIMARY KEY,
  api_key     TEXT NOT NULL,
  email       TEXT,
  endpoint    TEXT,
  status_code INTEGER,
  latency_ms  INTEGER DEFAULT 0,
  weight      INTEGER DEFAULT 1,
  logged_at   TEXT DEFAULT (datetime('now'))
);

-- Sales outreach — generated email/linkedin drafts
CREATE TABLE IF NOT EXISTS sales_outreach (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  outreach_type   TEXT,
  subject         TEXT,
  body            TEXT,
  status          TEXT DEFAULT 'draft',
  sent_at         TEXT,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- Billing events — payment history
CREATE TABLE IF NOT EXISTS billing_events (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  plan        TEXT,
  payment_id  TEXT,
  order_id    TEXT,
  event_type  TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Growth analytics — raw event stream
CREATE TABLE IF NOT EXISTS growth_analytics (
  id          TEXT PRIMARY KEY,
  event       TEXT NOT NULL,
  properties  TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Global expansion — region tracking
CREATE TABLE IF NOT EXISTS region_events (
  id          TEXT PRIMARY KEY,
  email       TEXT,
  country     TEXT,
  region      TEXT,
  currency    TEXT,
  timezone    TEXT,
  page        TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Upsell events — upgrade trigger log
CREATE TABLE IF NOT EXISTS upsell_events (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  trigger_type    TEXT NOT NULL,
  current_plan    TEXT,
  suggested_plan  TEXT,
  converted       INTEGER DEFAULT 0,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- A/B pricing experiments
CREATE TABLE IF NOT EXISTS pricing_experiments (
  id          TEXT PRIMARY KEY,
  variant     TEXT NOT NULL,
  email       TEXT,
  converted   INTEGER DEFAULT 0,
  revenue_inr INTEGER DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- GTM Indexes
CREATE INDEX IF NOT EXISTS idx_leads_email       ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_plan        ON leads(plan);
CREATE INDEX IF NOT EXISTS idx_leads_score       ON leads(lead_score DESC);
CREATE INDEX IF NOT EXISTS idx_leads_enterprise  ON leads(is_enterprise);
CREATE INDEX IF NOT EXISTS idx_leads_created     ON leads(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_funnel_email      ON funnel_events(email);
CREATE INDEX IF NOT EXISTS idx_funnel_stage      ON funnel_events(stage);
CREATE INDEX IF NOT EXISTS idx_funnel_created    ON funnel_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_seq_email   ON email_sequences(email);
CREATE INDEX IF NOT EXISTS idx_email_seq_status  ON email_sequences(status);
CREATE INDEX IF NOT EXISTS idx_email_seq_next    ON email_sequences(next_send_at);
CREATE INDEX IF NOT EXISTS idx_email_track_email ON email_tracking(email);
CREATE INDEX IF NOT EXISTS idx_email_track_event ON email_tracking(event);
CREATE INDEX IF NOT EXISTS idx_content_platform  ON content_queue(platform);
CREATE INDEX IF NOT EXISTS idx_content_status    ON content_queue(status);
CREATE INDEX IF NOT EXISTS idx_api_usage_email   ON api_usage_log(email);
CREATE INDEX IF NOT EXISTS idx_api_usage_logged  ON api_usage_log(logged_at DESC);
-- idx_api_keys_email / idx_api_keys_key removed — api_keys owned by schema.sql
CREATE INDEX IF NOT EXISTS idx_outreach_email    ON sales_outreach(email);
CREATE INDEX IF NOT EXISTS idx_outreach_status   ON sales_outreach(status);
CREATE INDEX IF NOT EXISTS idx_billing_email     ON billing_events(email);
CREATE INDEX IF NOT EXISTS idx_growth_event      ON growth_analytics(event);
CREATE INDEX IF NOT EXISTS idx_growth_created    ON growth_analytics(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_upsell_email      ON upsell_events(email);
CREATE INDEX IF NOT EXISTS idx_upsell_trigger    ON upsell_events(trigger_type);
CREATE INDEX IF NOT EXISTS idx_region_country    ON region_events(country);
CREATE INDEX IF NOT EXISTS idx_pricing_variant   ON pricing_experiments(variant);

-- ============================================================
-- SOURCE: schema_revenue_autopilot.sql
-- ============================================================

-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Revenue Autopilot Schema v18.0
-- Migration: Append-only. DO NOT modify any existing tables.
--
-- New tables:
--   mcp_revenue_events   — impression + click + purchase funnel tracking
--   mcp_cta_variants     — CTA A/B performance per module + user type
--   mcp_loss_prevention  — exit-intent / inactivity trigger outcomes
--   mcp_offer_log        — which offer was shown to whom + result
-- ═══════════════════════════════════════════════════════════════════════════

-- Phase 6: Revenue event funnel (impression → click → purchase)
CREATE TABLE IF NOT EXISTS mcp_revenue_events (
  id               TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id       TEXT,                                    -- client session fingerprint
  user_id          TEXT,                                    -- NULL = anonymous
  ip_hash          TEXT,
  event_type       TEXT    NOT NULL CHECK (event_type IN (
                     'impression','click','purchase','abandon','loss_prevent_shown',
                     'loss_prevent_converted','welcome_back_shown','welcome_back_converted'
                   )),
  offer_type       TEXT    NOT NULL CHECK (offer_type IN (
                     'single','bundle','dynamic_bundle','enterprise','upsell',
                     'loss_prevention','welcome_back','cta_only'
                   )),
  offer_id         TEXT    NOT NULL,                        -- item_id or bundle_id
  offer_name       TEXT,
  display_price    INTEGER DEFAULT 0,                       -- visual price shown (INR)
  actual_price     INTEGER DEFAULT 0,                       -- real price (for purchases)
  discount_pct     INTEGER DEFAULT 0,                       -- visual discount % shown
  cta_variant      TEXT    DEFAULT 'standard',              -- aggressive|standard|soft|enterprise
  urgency_level    TEXT    DEFAULT 'low',
  module           TEXT,
  risk_level       TEXT,
  user_type        TEXT    DEFAULT 'new',                   -- new|returning|buyer|churned|enterprise_icp
  context          TEXT    DEFAULT 'scan_result',
  revenue_inr      INTEGER DEFAULT 0,                       -- 0 unless purchase (server-verified)
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rev_events_offer    ON mcp_revenue_events(offer_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_events_user     ON mcp_revenue_events(user_id, event_type) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rev_events_type     ON mcp_revenue_events(offer_type, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_events_context  ON mcp_revenue_events(context, event_type);
CREATE INDEX IF NOT EXISTS idx_rev_events_date     ON mcp_revenue_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_events_purchase ON mcp_revenue_events(event_type, revenue_inr) WHERE event_type='purchase';

-- Phase 4: CTA variant performance tracking
CREATE TABLE IF NOT EXISTS mcp_cta_variants (
  id               TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  variant_id       TEXT    NOT NULL,                        -- 'aggressive'|'standard'|'soft'|'enterprise'
  module           TEXT    NOT NULL,
  user_type        TEXT    NOT NULL DEFAULT 'new',
  context          TEXT    NOT NULL DEFAULT 'scan_result',
  cta_text         TEXT    NOT NULL,
  impressions      INTEGER NOT NULL DEFAULT 0,
  clicks           INTEGER NOT NULL DEFAULT 0,
  purchases        INTEGER NOT NULL DEFAULT 0,
  click_rate       REAL    NOT NULL DEFAULT 0.0,
  purchase_rate    REAL    NOT NULL DEFAULT 0.0,
  revenue_inr      INTEGER NOT NULL DEFAULT 0,
  is_winner        INTEGER NOT NULL DEFAULT 0,
  updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(variant_id, module, user_type, context)
);

CREATE INDEX IF NOT EXISTS idx_cta_variants_module ON mcp_cta_variants(module, user_type, purchase_rate DESC);

-- Phase 7: Loss prevention tracking
CREATE TABLE IF NOT EXISTS mcp_loss_prevention (
  id               TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id       TEXT,
  user_id          TEXT,
  trigger_type     TEXT    NOT NULL CHECK (trigger_type IN ('exit_intent','inactivity','scroll_abandon')),
  offer_shown      TEXT,                                    -- offer_id shown
  discount_pct     INTEGER DEFAULT 0,
  converted        INTEGER NOT NULL DEFAULT 0,              -- 1 if user purchased after
  revenue_inr      INTEGER DEFAULT 0,
  module           TEXT,
  risk_level       TEXT,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_loss_prev_converted ON mcp_loss_prevention(converted, trigger_type);

-- Phase 6+9: Aggregated offer performance (fast KV sync target)
CREATE TABLE IF NOT EXISTS mcp_offer_performance (
  offer_id         TEXT    PRIMARY KEY,
  offer_type       TEXT    NOT NULL,
  offer_name       TEXT,
  total_impressions INTEGER NOT NULL DEFAULT 0,
  total_clicks      INTEGER NOT NULL DEFAULT 0,
  total_purchases   INTEGER NOT NULL DEFAULT 0,
  total_abandons    INTEGER NOT NULL DEFAULT 0,
  total_revenue_inr INTEGER NOT NULL DEFAULT 0,
  click_rate        REAL    NOT NULL DEFAULT 0.0,
  purchase_rate     REAL    NOT NULL DEFAULT 0.0,
  revenue_per_impression REAL NOT NULL DEFAULT 0.0,        -- RPI: key metric
  best_user_type    TEXT,                                   -- which user type converts best
  best_context      TEXT,                                   -- which context converts best
  best_cta_variant  TEXT,                                   -- which CTA converts best
  revenue_score     REAL    NOT NULL DEFAULT 50.0,          -- composite 0-100 revenue score
  last_updated      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_offer_perf_score  ON mcp_offer_performance(revenue_score DESC);
CREATE INDEX IF NOT EXISTS idx_offer_perf_rpi    ON mcp_offer_performance(revenue_per_impression DESC);

-- ============================================================
-- SOURCE: schema_threat_intel.sql
-- ============================================================

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

-- ============================================================
-- SOURCE: schema_mcp_learning.sql
-- ============================================================

-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — MCP Self-Learning Schema v17.0
-- Migration: Add self-learning tables to D1
--
-- Tables added:
--   mcp_feedback     — raw interaction events (click, purchase, ignore)
--   mcp_item_scores  — aggregated performance scores per item
--   user_profiles    — learned user preference profiles
--   mcp_ab_results   — A/B experiment tracking
--   mcp_context_stats— context performance (scan_result vs dashboard vs exit_intent)
--
-- DO NOT modify existing tables. Append-only migration.
-- ═══════════════════════════════════════════════════════════════════════════

-- Phase 1: Raw feedback events
CREATE TABLE IF NOT EXISTS mcp_feedback (
  id                  TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id             TEXT,                                          -- NULL for anonymous
  session_id          TEXT,                                          -- client session fingerprint
  ip_hash             TEXT,                                          -- hashed IP (privacy)
  action              TEXT    NOT NULL CHECK (action IN ('click','purchase','ignore','dismiss','share')),
  context             TEXT    NOT NULL DEFAULT 'scan_result',        -- scan_result | dashboard | exit_intent | post_payment
  recommendation_type TEXT    NOT NULL CHECK (recommendation_type IN ('tool','training','bundle','upsell','enterprise')),
  item_id             TEXT    NOT NULL,                              -- tool id, training id, bundle id
  item_name           TEXT,                                         -- display name (denormalized for fast reporting)
  module              TEXT,                                         -- domain | ai | redteam | identity | compliance
  risk_level          TEXT,                                         -- LOW | MEDIUM | HIGH | CRITICAL
  tier                TEXT    DEFAULT 'FREE',
  ab_variant          TEXT,                                         -- 'A' | 'B' (for experiment tracking)
  success             INTEGER NOT NULL DEFAULT 0,                   -- 1 = converted (purchase), 0 = other
  revenue_inr         INTEGER DEFAULT 0,                            -- 0 for non-purchase events
  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mcp_feedback_item      ON mcp_feedback(item_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_user      ON mcp_feedback(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_context   ON mcp_feedback(context, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_type      ON mcp_feedback(recommendation_type, action);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_module    ON mcp_feedback(module, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_success   ON mcp_feedback(success, created_at DESC) WHERE success = 1;

-- Phase 2: Aggregated item performance scores (synced from feedback)
CREATE TABLE IF NOT EXISTS mcp_item_scores (
  item_id             TEXT    PRIMARY KEY,
  item_name           TEXT,
  recommendation_type TEXT    NOT NULL,
  total_shown         INTEGER NOT NULL DEFAULT 0,
  total_clicks        INTEGER NOT NULL DEFAULT 0,
  total_purchases     INTEGER NOT NULL DEFAULT 0,
  total_ignores       INTEGER NOT NULL DEFAULT 0,
  total_dismisses     INTEGER NOT NULL DEFAULT 0,
  total_revenue_inr   INTEGER NOT NULL DEFAULT 0,
  click_rate          REAL    NOT NULL DEFAULT 0.0,   -- clicks / shown
  purchase_rate       REAL    NOT NULL DEFAULT 0.0,   -- purchases / shown
  ignore_rate         REAL    NOT NULL DEFAULT 0.0,   -- ignores / shown
  mcp_score           REAL    NOT NULL DEFAULT 50.0,  -- computed score 0-100
  last_updated        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mcp_scores_type  ON mcp_item_scores(recommendation_type, mcp_score DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_scores_score ON mcp_item_scores(mcp_score DESC);

-- Phase 4: Learned user preference profiles
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id             TEXT    PRIMARY KEY,
  preferred_tools     TEXT    DEFAULT '[]',       -- JSON array of item_ids ranked by score
  preferred_training  TEXT    DEFAULT '[]',       -- JSON array of item_ids ranked by score
  preferred_bundles   TEXT    DEFAULT '[]',       -- JSON array of bundle_ids
  risk_pattern        TEXT    DEFAULT 'unknown',  -- high_risk | low_risk | improving | volatile
  conversion_behavior TEXT    DEFAULT 'unknown',  -- quick_buyer | researcher | price_sensitive | browser
  top_module          TEXT,                       -- most scanned module
  avg_risk_score      REAL    DEFAULT 0.0,
  total_scans         INTEGER DEFAULT 0,
  total_purchases     INTEGER DEFAULT 0,
  total_revenue_inr   INTEGER DEFAULT 0,
  last_active         TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_behavior ON user_profiles(conversion_behavior);
CREATE INDEX IF NOT EXISTS idx_user_profiles_pattern  ON user_profiles(risk_pattern);

-- Phase 5: Context performance stats
CREATE TABLE IF NOT EXISTS mcp_context_stats (
  id                  TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  context             TEXT    NOT NULL,           -- scan_result | dashboard | exit_intent
  recommendation_type TEXT    NOT NULL,
  item_id             TEXT    NOT NULL,
  total_shown         INTEGER NOT NULL DEFAULT 0,
  total_conversions   INTEGER NOT NULL DEFAULT 0,
  conversion_rate     REAL    NOT NULL DEFAULT 0.0,
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(context, recommendation_type, item_id)
);

-- Phase 7: A/B experiment tracking
CREATE TABLE IF NOT EXISTS mcp_ab_results (
  id                  TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  experiment_id       TEXT    NOT NULL,           -- e.g. 'cta_variant_bundle_202601'
  variant             TEXT    NOT NULL,           -- 'A' | 'B'
  item_id             TEXT,
  cta_text            TEXT,
  context             TEXT,
  impressions         INTEGER NOT NULL DEFAULT 0,
  clicks              INTEGER NOT NULL DEFAULT 0,
  purchases           INTEGER NOT NULL DEFAULT 0,
  revenue_inr         INTEGER NOT NULL DEFAULT 0,
  click_rate          REAL    NOT NULL DEFAULT 0.0,
  purchase_rate       REAL    NOT NULL DEFAULT 0.0,
  winner              INTEGER DEFAULT NULL,       -- NULL=undecided, 1=this variant won
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(experiment_id, variant)
);

CREATE INDEX IF NOT EXISTS idx_mcp_ab_experiment ON mcp_ab_results(experiment_id, variant);

-- ============================================================
-- Schema version tracking (added if not present)
-- ============================================================
CREATE TABLE IF NOT EXISTS schema_versions (
  version     TEXT PRIMARY KEY,
  applied_at  TEXT NOT NULL DEFAULT (datetime('now')),
  description TEXT
);

INSERT OR IGNORE INTO schema_versions (version, description) VALUES
  ('schema_final_v1', 'Unified schema applied via schema_final.sql');
