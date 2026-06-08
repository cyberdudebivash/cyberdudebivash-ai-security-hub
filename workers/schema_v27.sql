-- ============================================================
-- CYBERDUDEBIVASH v27.0 — Enterprise Dominance Schema
-- Safe to run on live D1: all IF NOT EXISTS
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./schema_v27.sql
-- ============================================================

-- ── Trust Center ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_signals (
  id             TEXT PRIMARY KEY,
  type           TEXT NOT NULL,  -- 'testimonial' | 'case_study' | 'metric' | 'certification'
  title          TEXT NOT NULL DEFAULT '',
  content        TEXT NOT NULL DEFAULT '',
  company        TEXT,
  sector         TEXT,
  verified       INTEGER NOT NULL DEFAULT 0,  -- 1=admin-verified, 0=pending
  source_url     TEXT,
  display_order  INTEGER NOT NULL DEFAULT 0,
  visible        INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  verified_at    INTEGER
);

-- ── Assessments ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS assessments (
  id              TEXT PRIMARY KEY,
  lead_id         TEXT,
  email           TEXT NOT NULL DEFAULT '',
  company         TEXT,
  domain          TEXT,
  phone           TEXT,
  plan            TEXT NOT NULL DEFAULT 'standard',  -- standard|premium|enterprise
  price_inr       REAL NOT NULL DEFAULT 9999,
  status          TEXT NOT NULL DEFAULT 'booked',
    -- booked|paid|in_progress|delivered|completed|cancelled
  payment_ref     TEXT,
  razorpay_order  TEXT,
  report_url      TEXT,
  analyst_notes   TEXT,
  delivery_sla_h  INTEGER NOT NULL DEFAULT 72,
  booked_at       INTEGER NOT NULL DEFAULT (unixepoch()),
  paid_at         INTEGER,
  started_at      INTEGER,
  delivered_at    INTEGER,
  completed_at    INTEGER,
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_assessments_email      ON assessments(email);
CREATE INDEX IF NOT EXISTS idx_assessments_status     ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_assessments_booked_at  ON assessments(booked_at);

-- ── CEO Dashboard KPIs (daily snapshots) ─────────────────────
CREATE TABLE IF NOT EXISTS ceo_kpi_snapshots (
  id            TEXT PRIMARY KEY,
  snapshot_date TEXT NOT NULL,  -- YYYY-MM-DD
  mrr_inr       REAL NOT NULL DEFAULT 0,
  arr_inr       REAL NOT NULL DEFAULT 0,
  cash_inr      REAL NOT NULL DEFAULT 0,
  customers     INTEGER NOT NULL DEFAULT 0,
  assessments   INTEGER NOT NULL DEFAULT 0,
  reports_sold  INTEGER NOT NULL DEFAULT 0,
  api_revenue   REAL NOT NULL DEFAULT 0,
  mssp_revenue  REAL NOT NULL DEFAULT 0,
  conversion_pct REAL NOT NULL DEFAULT 0,
  retention_pct  REAL NOT NULL DEFAULT 0,
  churn_pct      REAL NOT NULL DEFAULT 0,
  ltv_inr        REAL NOT NULL DEFAULT 0,
  cac_inr        REAL NOT NULL DEFAULT 0,
  pipeline_inr   REAL NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ceo_kpi_date ON ceo_kpi_snapshots(snapshot_date);

-- ── Verified Metrics (replaces fake counters) ─────────────────
CREATE TABLE IF NOT EXISTS platform_metrics (
  key        TEXT PRIMARY KEY,
  value_int  INTEGER NOT NULL DEFAULT 0,
  value_real REAL,
  value_text TEXT,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
-- Seed with honest zero values (no inflation)
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES
  ('total_scans',      0),
  ('total_emails',     0),
  ('total_customers',  0),
  ('total_assessments',0),
  ('total_reports',    0),
  ('total_cves',       0),
  ('mrr_inr',          0),
  ('arr_inr',          0);

-- ── Customer Portal ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_portal_sessions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL DEFAULT '',
  email       TEXT NOT NULL DEFAULT '',
  token       TEXT UNIQUE NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_portal_token   ON customer_portal_sessions(token);
CREATE INDEX IF NOT EXISTS idx_portal_user_id ON customer_portal_sessions(user_id);

-- ── Subscription Management ───────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL DEFAULT '',
  email             TEXT NOT NULL DEFAULT '',
  plan              TEXT NOT NULL DEFAULT 'starter',
  status            TEXT NOT NULL DEFAULT 'active',
    -- active|paused|cancelled|expired|trial
  price_inr         REAL NOT NULL DEFAULT 499,
  billing_cycle     TEXT NOT NULL DEFAULT 'monthly',
  razorpay_sub_id   TEXT,
  current_period_start INTEGER,
  current_period_end   INTEGER,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  trial_end         INTEGER,
  created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at        INTEGER NOT NULL DEFAULT (unixepoch()),
  cancelled_at      INTEGER,
  metadata          TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_subs_email    ON subscriptions(email);
CREATE INDEX IF NOT EXISTS idx_subs_status   ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subs_plan     ON subscriptions(plan);

-- ── Refunds ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refund_requests (
  id            TEXT PRIMARY KEY,
  user_id       TEXT,
  email         TEXT NOT NULL DEFAULT '',
  payment_ref   TEXT NOT NULL DEFAULT '',
  amount_inr    REAL NOT NULL DEFAULT 0,
  reason        TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',
    -- pending|approved|rejected|processed
  admin_note    TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_refunds_email  ON refund_requests(email);
CREATE INDEX IF NOT EXISTS idx_refunds_status ON refund_requests(status);

-- ── License Management ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS licenses (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL DEFAULT '',
  email         TEXT NOT NULL DEFAULT '',
  product       TEXT NOT NULL DEFAULT '',  -- 'scanner_report'|'assessment'|'subscription'|'api'
  license_key   TEXT UNIQUE NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',  -- active|revoked|expired
  activations   INTEGER NOT NULL DEFAULT 0,
  max_activations INTEGER NOT NULL DEFAULT 1,
  expires_at    INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_licenses_email  ON licenses(email);
CREATE INDEX IF NOT EXISTS idx_licenses_key    ON licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);

-- ── Trust Center Metrics Cache ────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_metrics_cache (
  id         TEXT PRIMARY KEY DEFAULT 'singleton',
  scans      INTEGER NOT NULL DEFAULT 0,
  cves       INTEGER NOT NULL DEFAULT 0,
  customers  INTEGER NOT NULL DEFAULT 0,
  uptime_pct REAL NOT NULL DEFAULT 99.9,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT OR IGNORE INTO trust_metrics_cache (id, scans, cves, customers, uptime_pct)
  VALUES ('singleton', 0, 0, 0, 99.9);

