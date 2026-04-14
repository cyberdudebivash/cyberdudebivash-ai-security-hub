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
