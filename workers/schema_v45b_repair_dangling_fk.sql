-- ============================================================
-- v45b — REPAIR: the v45 users-table rebuild (ALTER TABLE users RENAME TO
-- users_v44_backup) caused SQLite to auto-rewrite every OTHER table's
-- "REFERENCES users(id)" to "REFERENCES users_v44_backup(id)" in their
-- stored schema text. Dropping users_v44_backup afterward left 8 tables
-- with a foreign key pointing at a table that no longer exists, breaking
-- signup/login/scans/payments/etc with "no such table: users_v44_backup".
-- This rebuilds each affected table, repointing the FK at "users", with
-- zero data loss.
-- ============================================================

PRAGMA foreign_keys = OFF;

-- ── api_keys ──────────────────────────────────────────────────────────────
ALTER TABLE api_keys RENAME TO api_keys_v45_tmp;
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  tier TEXT DEFAULT 'free',
  created_at INTEGER NOT NULL, email TEXT, api_key TEXT, daily_limit INTEGER NOT NULL DEFAULT 5, monthly_limit INTEGER NOT NULL DEFAULT 100, label TEXT, active INTEGER NOT NULL DEFAULT 1, last_used_at TEXT, expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0, key_prefix TEXT,
  FOREIGN KEY(user_id) REFERENCES "users"(id)
);
INSERT INTO api_keys SELECT * FROM api_keys_v45_tmp;
DROP TABLE api_keys_v45_tmp;
CREATE INDEX idx_api_keys_user   ON api_keys(user_id);
CREATE INDEX idx_api_keys_key    ON api_keys(api_key);
CREATE INDEX idx_api_keys_hash   ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_email  ON api_keys(email);
CREATE INDEX idx_api_keys_tier   ON api_keys(tier);

-- ── api_key_usage (second-order: referenced api_keys, which we just renamed) ──
ALTER TABLE api_key_usage RENAME TO api_key_usage_v45_tmp;
CREATE TABLE api_key_usage (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  key_id       TEXT    NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  user_id      TEXT    NOT NULL,
  date_bucket  TEXT    NOT NULL,
  module       TEXT    NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 1,
  UNIQUE(key_id, date_bucket, module)
);
INSERT INTO api_key_usage SELECT * FROM api_key_usage_v45_tmp;
DROP TABLE api_key_usage_v45_tmp;
CREATE INDEX idx_key_usage_key  ON api_key_usage(key_id, date_bucket);
CREATE INDEX idx_key_usage_user ON api_key_usage(user_id, date_bucket);

-- ── scans ─────────────────────────────────────────────────────────────────
ALTER TABLE scans RENAME TO scans_v45_tmp;
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  risk_score INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES "users"(id)
);
INSERT INTO scans SELECT * FROM scans_v45_tmp;
DROP TABLE scans_v45_tmp;
CREATE INDEX idx_scans_user    ON scans(user_id);
CREATE INDEX idx_scans_created ON scans(created_at);

-- ── refresh_tokens ────────────────────────────────────────────────────────
ALTER TABLE refresh_tokens RENAME TO refresh_tokens_v45_tmp;
CREATE TABLE refresh_tokens (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT    NOT NULL REFERENCES "users"(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  revoked     INTEGER NOT NULL DEFAULT 0,
  ip_address  TEXT,
  user_agent  TEXT
);
INSERT INTO refresh_tokens SELECT * FROM refresh_tokens_v45_tmp;
DROP TABLE refresh_tokens_v45_tmp;
CREATE INDEX idx_refresh_tokens_user   ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash   ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expiry ON refresh_tokens(expires_at);

-- ── scan_jobs ─────────────────────────────────────────────────────────────
ALTER TABLE scan_jobs RENAME TO scan_jobs_v45_tmp;
CREATE TABLE scan_jobs (
  id            TEXT    PRIMARY KEY,
  user_id       TEXT    REFERENCES "users"(id) ON DELETE SET NULL,
  identity      TEXT    NOT NULL,
  module        TEXT    NOT NULL,
  target        TEXT    NOT NULL,
  priority      INTEGER NOT NULL DEFAULT 0,
  status        TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','processing','completed','failed')),
  risk_score    INTEGER,
  risk_level    TEXT,
  error_message TEXT,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  started_at    TEXT,
  completed_at  TEXT,
  r2_key        TEXT
);
INSERT INTO scan_jobs SELECT * FROM scan_jobs_v45_tmp;
DROP TABLE scan_jobs_v45_tmp;
CREATE INDEX idx_scan_jobs_user     ON scan_jobs(user_id, created_at);
CREATE INDEX idx_scan_jobs_status   ON scan_jobs(status, created_at);
CREATE INDEX idx_scan_jobs_identity ON scan_jobs(identity, created_at);

-- ── scan_history ──────────────────────────────────────────────────────────
ALTER TABLE scan_history RENAME TO scan_history_v45_tmp;
CREATE TABLE scan_history (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT    NOT NULL REFERENCES "users"(id) ON DELETE CASCADE,
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
INSERT INTO scan_history SELECT * FROM scan_history_v45_tmp;
DROP TABLE scan_history_v45_tmp;
CREATE INDEX idx_scan_history_user   ON scan_history(user_id, scanned_at);
CREATE INDEX idx_scan_history_module ON scan_history(user_id, module, scanned_at);
CREATE INDEX idx_scan_history_target ON scan_history(user_id, target);

-- ── alert_configs ─────────────────────────────────────────────────────────
ALTER TABLE alert_configs RENAME TO alert_configs_v45_tmp;
CREATE TABLE alert_configs (
  id                TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id           TEXT    NOT NULL REFERENCES "users"(id) ON DELETE CASCADE UNIQUE,
  telegram_enabled  INTEGER NOT NULL DEFAULT 0,
  telegram_chat_id  TEXT,
  email_enabled     INTEGER NOT NULL DEFAULT 0,
  alert_email       TEXT,
  min_risk_score    INTEGER NOT NULL DEFAULT 70,
  alert_on_blacklist INTEGER NOT NULL DEFAULT 1,
  alert_on_critical_cve INTEGER NOT NULL DEFAULT 1,
  created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO alert_configs SELECT * FROM alert_configs_v45_tmp;
DROP TABLE alert_configs_v45_tmp;
CREATE INDEX idx_alert_configs_user ON alert_configs(user_id);

-- ── alert_log ─────────────────────────────────────────────────────────────
ALTER TABLE alert_log RENAME TO alert_log_v45_tmp;
CREATE TABLE alert_log (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT    NOT NULL REFERENCES "users"(id) ON DELETE CASCADE,
  channel     TEXT    NOT NULL CHECK (channel IN ('telegram','email')),
  trigger_type TEXT   NOT NULL,
  target      TEXT,
  message_preview TEXT,
  status      TEXT    NOT NULL DEFAULT 'sent' CHECK (status IN ('sent','failed','pending')),
  sent_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO alert_log SELECT * FROM alert_log_v45_tmp;
DROP TABLE alert_log_v45_tmp;
CREATE INDEX idx_alert_log_user ON alert_log(user_id, sent_at);

-- ── payments ──────────────────────────────────────────────────────────────
ALTER TABLE payments RENAME TO payments_v45_tmp;
CREATE TABLE payments (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id              TEXT    REFERENCES "users"(id) ON DELETE SET NULL,
  scan_id              TEXT,
  module               TEXT    NOT NULL,
  target               TEXT    NOT NULL,
  amount               INTEGER NOT NULL,
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
INSERT INTO payments SELECT * FROM payments_v45_tmp;
DROP TABLE payments_v45_tmp;
CREATE INDEX idx_payments_user     ON payments(user_id);
CREATE INDEX idx_payments_razorpay ON payments(razorpay_order_id);
CREATE INDEX idx_payments_status   ON payments(status, created_at);
CREATE INDEX idx_payments_module   ON payments(module, status);
CREATE INDEX idx_payments_target   ON payments(target, module);

-- ── report_access ─────────────────────────────────────────────────────────
ALTER TABLE report_access RENAME TO report_access_v45_tmp;
CREATE TABLE report_access (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  scan_id              TEXT,
  payment_id           TEXT    REFERENCES payments(id) ON DELETE CASCADE,
  user_id              TEXT    REFERENCES "users"(id) ON DELETE SET NULL,
  token                TEXT    NOT NULL UNIQUE,
  module               TEXT    NOT NULL,
  r2_key               TEXT,
  expires_at           TEXT    NOT NULL,
  downloaded_count     INTEGER NOT NULL DEFAULT 0,
  last_downloaded_at   TEXT,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO report_access SELECT * FROM report_access_v45_tmp;
DROP TABLE report_access_v45_tmp;
CREATE INDEX idx_report_token   ON report_access(token);
CREATE INDEX idx_report_scan_id ON report_access(scan_id);
CREATE INDEX idx_report_user    ON report_access(user_id);
CREATE INDEX idx_report_expires ON report_access(expires_at);

PRAGMA foreign_keys = ON;
