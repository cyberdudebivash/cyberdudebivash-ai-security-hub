-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — v24.0 Schema
-- Revenue Dominance: Billing Engine + Sales OS + Trust Center
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v24.sql --remote
-- ============================================================

-- ── PHASE 1: Billing Engine — missing tables ─────────────────
CREATE TABLE IF NOT EXISTS invoices (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  invoice_number  TEXT NOT NULL UNIQUE,
  customer_id     TEXT NOT NULL,
  user_id         TEXT,
  email           TEXT NOT NULL,
  company         TEXT,
  gstin           TEXT,
  billing_address TEXT DEFAULT '{}',
  line_items      TEXT NOT NULL DEFAULT '[]',
  subtotal_inr    INTEGER NOT NULL DEFAULT 0,
  gst_rate        REAL NOT NULL DEFAULT 18.0,
  gst_amount_inr  INTEGER NOT NULL DEFAULT 0,
  total_inr       INTEGER NOT NULL DEFAULT 0,
  currency        TEXT NOT NULL DEFAULT 'INR',
  status          TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','paid','overdue','cancelled','void')),
  payment_id      TEXT,
  payment_method  TEXT,
  due_date        TEXT,
  paid_at         TEXT,
  sent_at         TEXT,
  pdf_key         TEXT,
  notes           TEXT,
  period_start    TEXT,
  period_end      TEXT,
  subscription_id TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_inv_customer ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_inv_status   ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_inv_created  ON invoices(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_inv_number ON invoices(invoice_number);

-- ── Refunds ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refunds (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  payment_id      TEXT NOT NULL,
  invoice_id      TEXT,
  user_id         TEXT,
  email           TEXT,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  reason          TEXT DEFAULT 'customer_request' CHECK(reason IN ('customer_request','duplicate','fraud','service_failure','other')),
  reason_detail   TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','completed','failed','rejected')),
  razorpay_refund_id TEXT,
  stripe_refund_id TEXT,
  initiated_by    TEXT DEFAULT 'customer',
  processed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_refund_payment ON refunds(payment_id);
CREATE INDEX IF NOT EXISTS idx_refund_status  ON refunds(status);

-- ── Licenses ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS licenses (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  license_key     TEXT NOT NULL UNIQUE,
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  plan            TEXT NOT NULL DEFAULT 'STARTER',
  product         TEXT,
  seats           INTEGER NOT NULL DEFAULT 1,
  status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','suspended','revoked')),
  issued_at       TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at      TEXT,
  last_activated  TEXT,
  activation_count INTEGER NOT NULL DEFAULT 0,
  max_activations INTEGER NOT NULL DEFAULT 5,
  payment_id      TEXT,
  invoice_id      TEXT,
  metadata        TEXT DEFAULT '{}',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_lic_key    ON licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_lic_user          ON licenses(user_id);
CREATE INDEX IF NOT EXISTS idx_lic_status        ON licenses(status);

-- ── Failed Payment Recovery ───────────────────────────────────
CREATE TABLE IF NOT EXISTS payment_recovery (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  subscription_id TEXT,
  invoice_id      TEXT,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  failure_reason  TEXT,
  attempt_count   INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 3,
  next_retry_at   TEXT,
  last_attempt_at TEXT,
  resolved        INTEGER NOT NULL DEFAULT 0,
  resolved_at     TEXT,
  recovery_method TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','retrying','resolved','abandoned')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_recovery_user   ON payment_recovery(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_status ON payment_recovery(status);
CREATE INDEX IF NOT EXISTS idx_recovery_retry  ON payment_recovery(next_retry_at);

-- ── PayPal Transactions ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS paypal_transactions (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  paypal_order_id TEXT NOT NULL UNIQUE,
  paypal_payer_id TEXT,
  user_id         TEXT,
  email           TEXT,
  amount_usd      REAL NOT NULL DEFAULT 0,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  currency        TEXT NOT NULL DEFAULT 'USD',
  plan            TEXT,
  product         TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','completed','cancelled','failed')),
  completed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_paypal_order ON paypal_transactions(paypal_order_id);

-- ── PHASE 2: Enhanced CRM Fields ─────────────────────────────
-- Add missing columns to deal_pipeline
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS security_budget_inr INTEGER DEFAULT 0;
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS ai_adoption_level TEXT DEFAULT 'none';
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS compliance_needs TEXT DEFAULT '[]';
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS risk_exposure TEXT DEFAULT 'unknown';
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS opportunity_score INTEGER DEFAULT 0;
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS mssp_potential INTEGER DEFAULT 0;
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS current_security_tools TEXT DEFAULT '[]';
ALTER TABLE deal_pipeline ADD COLUMN IF NOT EXISTS pain_points TEXT DEFAULT '[]';

-- ── PHASE 3: Proposal Factory ─────────────────────────────────
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS roi_data TEXT DEFAULT '{}';
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS timeline_weeks INTEGER DEFAULT 4;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS success_metrics TEXT DEFAULT '[]';
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS exec_summary TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS threat_landscape TEXT DEFAULT '{}';
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS html_content TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS revision INTEGER DEFAULT 1;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS signed_at TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS signature_token TEXT;

-- ── PHASE 4: Scanner Revenue Tiers ───────────────────────────
CREATE TABLE IF NOT EXISTS scan_orders (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT,
  email           TEXT,
  target          TEXT NOT NULL,
  module          TEXT NOT NULL DEFAULT 'domain',
  tier            TEXT NOT NULL DEFAULT 'basic' CHECK(tier IN ('basic','pro','enterprise_review','security_assessment')),
  price_inr       INTEGER NOT NULL DEFAULT 199,
  payment_id      TEXT,
  order_id        TEXT,
  payment_status  TEXT NOT NULL DEFAULT 'pending' CHECK(payment_status IN ('pending','paid','failed','refunded')),
  report_key      TEXT,
  report_token    TEXT,
  report_expires  TEXT,
  scan_result     TEXT,
  delivered_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scanord_user    ON scan_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_scanord_status  ON scan_orders(payment_status);
CREATE INDEX IF NOT EXISTS idx_scanord_token   ON scan_orders(report_token);

-- ── PHASE 6: Defense Pipeline — approval workflow ─────────────
ALTER TABLE product_pipeline ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'pending';
ALTER TABLE product_pipeline ADD COLUMN IF NOT EXISTS approved_by TEXT;
ALTER TABLE product_pipeline ADD COLUMN IF NOT EXISTS approved_at TEXT;
ALTER TABLE product_pipeline ADD COLUMN IF NOT EXISTS rejection_reason TEXT;
ALTER TABLE product_pipeline ADD COLUMN IF NOT EXISTS products_pending_approval TEXT DEFAULT '[]';

-- ── PHASE 9: Trust Center ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_incidents (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL DEFAULT 'minor' CHECK(severity IN ('minor','major','critical')),
  status          TEXT NOT NULL DEFAULT 'investigating' CHECK(status IN ('investigating','identified','monitoring','resolved')),
  affected_systems TEXT DEFAULT '[]',
  description     TEXT,
  resolution      TEXT,
  started_at      TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at     TEXT,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS release_notes (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  version         TEXT NOT NULL,
  title           TEXT NOT NULL,
  type            TEXT NOT NULL DEFAULT 'feature' CHECK(type IN ('feature','fix','security','improvement','breaking')),
  description     TEXT NOT NULL,
  details         TEXT DEFAULT '[]',
  published_at    TEXT NOT NULL DEFAULT (datetime('now')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_release_version ON release_notes(version);
CREATE INDEX IF NOT EXISTS idx_release_date    ON release_notes(published_at);

CREATE TABLE IF NOT EXISTS uptime_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  service         TEXT NOT NULL DEFAULT 'api',
  status          TEXT NOT NULL DEFAULT 'operational' CHECK(status IN ('operational','degraded','partial_outage','major_outage')),
  latency_ms      INTEGER DEFAULT 0,
  checked_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_uptime_service ON uptime_log(service);
CREATE INDEX IF NOT EXISTS idx_uptime_checked ON uptime_log(checked_at);

CREATE TABLE IF NOT EXISTS testimonials (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  name            TEXT NOT NULL,
  title           TEXT,
  company         TEXT,
  avatar_initial  TEXT,
  quote           TEXT NOT NULL,
  rating          INTEGER NOT NULL DEFAULT 5,
  verified        INTEGER NOT NULL DEFAULT 0,
  featured        INTEGER NOT NULL DEFAULT 0,
  use_case        TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── PHASE 10: CEO Revenue Command Center ──────────────────────
CREATE TABLE IF NOT EXISTS revenue_streams (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  period          TEXT NOT NULL,
  stream          TEXT NOT NULL CHECK(stream IN ('subscriptions','marketplace','api','reports','consulting','training','mssp')),
  revenue_inr     INTEGER NOT NULL DEFAULT 0,
  transaction_count INTEGER NOT NULL DEFAULT 0,
  customer_count  INTEGER NOT NULL DEFAULT 0,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_revstream_period ON revenue_streams(period, stream);

CREATE TABLE IF NOT EXISTS renewal_queue (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  subscription_id TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  plan            TEXT NOT NULL,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  renewal_date    TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'upcoming' CHECK(status IN ('upcoming','processing','renewed','failed','churned')),
  notified_at     TEXT,
  renewed_at      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_renewal_date   ON renewal_queue(renewal_date);
CREATE INDEX IF NOT EXISTS idx_renewal_status ON renewal_queue(status);
