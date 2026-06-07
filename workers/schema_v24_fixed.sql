-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v24.0 FIXED
-- Compatible: Cloudflare D1 (SQLite 3.x strict)
-- Root-cause fix: D1 rejects IF NOT EXISTS on CREATE INDEX
-- All indexes use plain CREATE INDEX (idempotent via DROP first)
-- All tables use CREATE TABLE IF NOT EXISTS (D1-safe)
-- Author: CYBERDUDEBIVASH Principal Architect
-- ============================================================

-- ─────────────────────────────────────────────
-- PHASE 1: BILLING ENGINE
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS billing_invoices (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  plan          TEXT NOT NULL,
  amount_inr    REAL NOT NULL,
  gst_amount    REAL NOT NULL DEFAULT 0,
  total_inr     REAL NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'INR',
  status        TEXT NOT NULL DEFAULT 'pending',
  payment_method TEXT,
  transaction_id TEXT,
  license_key   TEXT,
  invoice_number TEXT,
  invoice_pdf_url TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  paid_at       INTEGER,
  metadata      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS billing_license_keys (
  key           TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  plan          TEXT NOT NULL,
  invoice_id    TEXT,
  status        TEXT NOT NULL DEFAULT 'active',
  activations   INTEGER NOT NULL DEFAULT 0,
  max_activations INTEGER NOT NULL DEFAULT 3,
  expires_at    INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS billing_paypal_orders (
  order_id      TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  plan          TEXT NOT NULL,
  amount_usd    REAL NOT NULL,
  status        TEXT NOT NULL DEFAULT 'created',
  capture_id    TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  captured_at   INTEGER
);

CREATE TABLE IF NOT EXISTS billing_refunds (
  id            TEXT PRIMARY KEY,
  invoice_id    TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  amount_inr    REAL NOT NULL,
  reason        TEXT,
  status        TEXT NOT NULL DEFAULT 'requested',
  approved_by   TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at   INTEGER
);

CREATE TABLE IF NOT EXISTS billing_recovery_queue (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  invoice_id    TEXT NOT NULL,
  attempt       INTEGER NOT NULL DEFAULT 1,
  next_retry_at INTEGER NOT NULL,
  last_error    TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- PHASE 2: SALES OS
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sales_opportunities (
  id            TEXT PRIMARY KEY,
  lead_id       TEXT,
  company       TEXT NOT NULL,
  contact_email TEXT,
  sector        TEXT,
  company_size  TEXT,
  budget_range  TEXT,
  urgency       TEXT,
  score         INTEGER NOT NULL DEFAULT 0,
  tier          TEXT NOT NULL DEFAULT 'D',
  deal_value    REAL NOT NULL DEFAULT 0,
  stage         TEXT NOT NULL DEFAULT 'lead',
  owner         TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS sales_pipeline_history (
  id            TEXT PRIMARY KEY,
  opportunity_id TEXT NOT NULL,
  from_stage    TEXT,
  to_stage      TEXT NOT NULL,
  changed_by    TEXT,
  note          TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- PHASE 3: PROPOSALS ENGINE
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS proposals (
  id            TEXT PRIMARY KEY,
  opportunity_id TEXT,
  company       TEXT NOT NULL,
  contact_email TEXT,
  sector        TEXT,
  org_size      TEXT,
  package       TEXT NOT NULL,
  type          TEXT NOT NULL DEFAULT 'enterprise',
  status        TEXT NOT NULL DEFAULT 'draft',
  html_content  TEXT,
  pdf_url       TEXT,
  total_inr     REAL NOT NULL DEFAULT 0,
  gst_inr       REAL NOT NULL DEFAULT 0,
  sent_at       INTEGER,
  viewed_at     INTEGER,
  accepted_at   INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

-- ─────────────────────────────────────────────
-- PHASE 4: SCANNER ORDERS
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scanner_orders (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  tier          TEXT NOT NULL,
  target        TEXT NOT NULL,
  scan_type     TEXT NOT NULL DEFAULT 'domain',
  amount_inr    REAL NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending_payment',
  token         TEXT,
  report_url    TEXT,
  payment_ref   TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at  INTEGER
);

-- ─────────────────────────────────────────────
-- PHASE 5: AFFILIATE ENGINE
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS affiliate_members (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT,
  type          TEXT NOT NULL DEFAULT 'individual',
  tier          TEXT NOT NULL DEFAULT 'AFFILIATE',
  ref_code      TEXT NOT NULL UNIQUE,
  commission_pct REAL NOT NULL DEFAULT 10.0,
  total_referrals INTEGER NOT NULL DEFAULT 0,
  total_conversions INTEGER NOT NULL DEFAULT 0,
  total_earnings REAL NOT NULL DEFAULT 0,
  pending_payout REAL NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'active',
  joined_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS affiliate_referrals (
  id            TEXT PRIMARY KEY,
  affiliate_id  TEXT NOT NULL,
  ref_code      TEXT NOT NULL,
  visitor_ip    TEXT,
  landing_page  TEXT,
  converted     INTEGER NOT NULL DEFAULT 0,
  conversion_invoice_id TEXT,
  commission_inr REAL NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  converted_at  INTEGER
);

CREATE TABLE IF NOT EXISTS affiliate_payouts (
  id            TEXT PRIMARY KEY,
  affiliate_id  TEXT NOT NULL,
  amount_inr    REAL NOT NULL,
  method        TEXT NOT NULL DEFAULT 'upi',
  upi_id        TEXT,
  bank_details  TEXT,
  status        TEXT NOT NULL DEFAULT 'requested',
  processed_at  INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- PHASE 6: PARTNER / MSSP REGISTRY
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mssp_partners (
  id            TEXT PRIMARY KEY,
  company       TEXT NOT NULL,
  contact_email TEXT NOT NULL UNIQUE,
  tier          TEXT NOT NULL DEFAULT 'RESELLER',
  plan          TEXT NOT NULL DEFAULT 'reseller',
  brand_name    TEXT,
  custom_domain TEXT,
  primary_color TEXT DEFAULT '#00d4ff',
  api_key       TEXT UNIQUE,
  client_count  INTEGER NOT NULL DEFAULT 0,
  max_clients   INTEGER NOT NULL DEFAULT 10,
  margin_pct    REAL NOT NULL DEFAULT 20.0,
  status        TEXT NOT NULL DEFAULT 'pending',
  onboarded_at  INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS mssp_clients (
  id            TEXT PRIMARY KEY,
  partner_id    TEXT NOT NULL,
  company       TEXT NOT NULL,
  domain        TEXT,
  sector        TEXT,
  contact_email TEXT,
  status        TEXT NOT NULL DEFAULT 'active',
  open_alerts   INTEGER NOT NULL DEFAULT 0,
  last_scan_at  INTEGER,
  onboarded_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

-- ─────────────────────────────────────────────
-- PHASE 7: CRM / LEAD TRACKING
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS crm_leads (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL,
  name          TEXT,
  company       TEXT,
  sector        TEXT,
  company_size  TEXT,
  budget_range  TEXT,
  urgency       TEXT,
  source        TEXT NOT NULL DEFAULT 'website',
  status        TEXT NOT NULL DEFAULT 'new',
  icp_score     INTEGER NOT NULL DEFAULT 0,
  icp_tier      TEXT NOT NULL DEFAULT 'D',
  notes         TEXT,
  assigned_to   TEXT,
  demo_booked   INTEGER NOT NULL DEFAULT 0,
  demo_at       INTEGER,
  converted     INTEGER NOT NULL DEFAULT 0,
  converted_at  INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS crm_activities (
  id            TEXT PRIMARY KEY,
  lead_id       TEXT NOT NULL,
  type          TEXT NOT NULL,
  note          TEXT,
  by_user       TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- PHASE 8: REVOS — REVENUE OPERATING SYSTEM
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS revos_mrr_snapshots (
  id            TEXT PRIMARY KEY,
  snapshot_date TEXT NOT NULL,
  mrr_inr       REAL NOT NULL DEFAULT 0,
  arr_inr       REAL NOT NULL DEFAULT 0,
  new_mrr       REAL NOT NULL DEFAULT 0,
  churned_mrr   REAL NOT NULL DEFAULT 0,
  expansion_mrr REAL NOT NULL DEFAULT 0,
  active_subs   INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS revos_revenue_streams (
  id            TEXT PRIMARY KEY,
  stream_name   TEXT NOT NULL,
  category      TEXT NOT NULL,
  amount_inr    REAL NOT NULL DEFAULT 0,
  period        TEXT NOT NULL,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- PHASE 9: TRUST CENTER
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS trust_incidents (
  id            TEXT PRIMARY KEY,
  title         TEXT NOT NULL,
  description   TEXT,
  severity      TEXT NOT NULL DEFAULT 'minor',
  status        TEXT NOT NULL DEFAULT 'investigating',
  affected      TEXT,
  started_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at   INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS trust_testimonials (
  id            TEXT PRIMARY KEY,
  author        TEXT NOT NULL,
  role          TEXT,
  company       TEXT,
  sector        TEXT,
  content       TEXT NOT NULL,
  rating        INTEGER NOT NULL DEFAULT 5,
  verified      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- PHASE 10: CEO DASHBOARD TARGETS
-- ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ceo_targets (
  id            TEXT PRIMARY KEY,
  metric        TEXT NOT NULL UNIQUE,
  target_value  REAL NOT NULL,
  current_value REAL NOT NULL DEFAULT 0,
  period        TEXT NOT NULL DEFAULT 'monthly',
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- INDEXES  
-- NOTE: D1 SQLite does NOT support CREATE INDEX IF NOT EXISTS
-- Use DROP INDEX + CREATE INDEX pattern for idempotency
-- ─────────────────────────────────────────────

-- billing_invoices
DROP INDEX IF EXISTS idx_billing_invoices_user;
CREATE INDEX idx_billing_invoices_user ON billing_invoices(user_id);

DROP INDEX IF EXISTS idx_billing_invoices_status;
CREATE INDEX idx_billing_invoices_status ON billing_invoices(status);

DROP INDEX IF EXISTS idx_billing_invoices_created;
CREATE INDEX idx_billing_invoices_created ON billing_invoices(created_at DESC);

-- billing_license_keys
DROP INDEX IF EXISTS idx_license_user;
CREATE INDEX idx_license_user ON billing_license_keys(user_id);

DROP INDEX IF EXISTS idx_license_status;
CREATE INDEX idx_license_status ON billing_license_keys(status);

-- billing_recovery_queue
DROP INDEX IF EXISTS idx_recovery_next_retry;
CREATE INDEX idx_recovery_next_retry ON billing_recovery_queue(next_retry_at);

DROP INDEX IF EXISTS idx_recovery_status;
CREATE INDEX idx_recovery_status ON billing_recovery_queue(status);

-- sales_opportunities
DROP INDEX IF EXISTS idx_opp_stage;
CREATE INDEX idx_opp_stage ON sales_opportunities(stage);

DROP INDEX IF EXISTS idx_opp_score;
CREATE INDEX idx_opp_score ON sales_opportunities(score DESC);

DROP INDEX IF EXISTS idx_opp_tier;
CREATE INDEX idx_opp_tier ON sales_opportunities(tier);

-- proposals
DROP INDEX IF EXISTS idx_proposals_status;
CREATE INDEX idx_proposals_status ON proposals(status);

DROP INDEX IF EXISTS idx_proposals_email;
CREATE INDEX idx_proposals_email ON proposals(contact_email);

-- scanner_orders
DROP INDEX IF EXISTS idx_scanner_user;
CREATE INDEX idx_scanner_user ON scanner_orders(user_id);

DROP INDEX IF EXISTS idx_scanner_status;
CREATE INDEX idx_scanner_status ON scanner_orders(status);

DROP INDEX IF EXISTS idx_scanner_token;
CREATE INDEX idx_scanner_token ON scanner_orders(token);

-- affiliate_members
DROP INDEX IF EXISTS idx_aff_email;
CREATE INDEX idx_aff_email ON affiliate_members(email);

DROP INDEX IF EXISTS idx_aff_tier;
CREATE INDEX idx_aff_tier ON affiliate_members(tier);

-- affiliate_referrals
DROP INDEX IF EXISTS idx_ref_affiliate;
CREATE INDEX idx_ref_affiliate ON affiliate_referrals(affiliate_id);

DROP INDEX IF EXISTS idx_ref_code;
CREATE INDEX idx_ref_code ON affiliate_referrals(ref_code);

-- mssp_partners
DROP INDEX IF EXISTS idx_mssp_status;
CREATE INDEX idx_mssp_status ON mssp_partners(status);

DROP INDEX IF EXISTS idx_mssp_api_key;
CREATE INDEX idx_mssp_api_key ON mssp_partners(api_key);

-- mssp_clients
DROP INDEX IF EXISTS idx_mssp_clients_partner;
CREATE INDEX idx_mssp_clients_partner ON mssp_clients(partner_id);

-- crm_leads
DROP INDEX IF EXISTS idx_crm_leads_status;
CREATE INDEX idx_crm_leads_status ON crm_leads(status);

DROP INDEX IF EXISTS idx_crm_leads_email;
CREATE INDEX idx_crm_leads_email ON crm_leads(email);

DROP INDEX IF EXISTS idx_crm_leads_score;
CREATE INDEX idx_crm_leads_score ON crm_leads(icp_score DESC);

-- crm_activities
DROP INDEX IF EXISTS idx_crm_activities_lead;
CREATE INDEX idx_crm_activities_lead ON crm_activities(lead_id);

-- revos
DROP INDEX IF EXISTS idx_revos_mrr_date;
CREATE INDEX idx_revos_mrr_date ON revos_mrr_snapshots(snapshot_date DESC);

-- trust
DROP INDEX IF EXISTS idx_trust_incidents_status;
CREATE INDEX idx_trust_incidents_status ON trust_incidents(status);

-- ─────────────────────────────────────────────
-- SEED: CEO TARGETS (idempotent via INSERT OR REPLACE)
-- ─────────────────────────────────────────────

INSERT OR REPLACE INTO ceo_targets (id, metric, target_value, period) VALUES
  ('ceo_mrr',         'mrr_inr',           100000, 'monthly'),
  ('ceo_arr',         'arr_inr',          1200000, 'annual'),
  ('ceo_leads',       'leads_per_month',       50, 'monthly'),
  ('ceo_demos',       'demos_per_month',       10, 'monthly'),
  ('ceo_deals',       'deals_won_per_month',    5, 'monthly'),
  ('ceo_churn',       'churn_rate_pct',        5.0,'monthly'),
  ('ceo_mssp',        'mssp_partners',          5, 'quarterly'),
  ('ceo_affiliates',  'active_affiliates',     25, 'quarterly');

-- ─────────────────────────────────────────────
-- DONE — v24.0 schema deployed successfully
-- ─────────────────────────────────────────────
