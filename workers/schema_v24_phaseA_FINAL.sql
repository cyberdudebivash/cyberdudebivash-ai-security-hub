-- ============================================================
-- CYBERDUDEBIVASH v24.0 — PHASE A: TABLES + COLUMN PATCHES
-- NO INDEXES — safe to run even with partial pre-existing tables
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=.\schema_v24_phaseA.sql --remote
-- D1 ignores non-fatal errors (duplicate column, table exists)
-- ============================================================

-- NEW TABLES (will be skipped if already exist)
CREATE TABLE IF NOT EXISTS billing_invoices (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', plan TEXT NOT NULL DEFAULT '',
  amount_inr REAL NOT NULL DEFAULT 0, gst_amount REAL NOT NULL DEFAULT 0,
  total_inr REAL NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'INR',
  status TEXT NOT NULL DEFAULT 'pending', payment_method TEXT, transaction_id TEXT,
  license_key TEXT, invoice_number TEXT, invoice_pdf_url TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), paid_at INTEGER, metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS billing_license_keys (
  key TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', plan TEXT NOT NULL DEFAULT '',
  invoice_id TEXT, status TEXT NOT NULL DEFAULT 'active',
  activations INTEGER NOT NULL DEFAULT 0, max_activations INTEGER NOT NULL DEFAULT 3,
  expires_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS billing_paypal_orders (
  order_id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', plan TEXT NOT NULL DEFAULT '',
  amount_usd REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'created',
  capture_id TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), captured_at INTEGER
);
CREATE TABLE IF NOT EXISTS billing_refunds (
  id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL DEFAULT '', user_id TEXT NOT NULL DEFAULT '',
  amount_inr REAL NOT NULL DEFAULT 0, reason TEXT, status TEXT NOT NULL DEFAULT 'requested',
  approved_by TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS billing_recovery_queue (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', invoice_id TEXT NOT NULL DEFAULT '',
  attempt INTEGER NOT NULL DEFAULT 1, next_retry_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT, status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS sales_opportunities (
  id TEXT PRIMARY KEY, lead_id TEXT, company TEXT NOT NULL DEFAULT '',
  contact_email TEXT, sector TEXT, company_size TEXT, budget_range TEXT, urgency TEXT,
  score INTEGER NOT NULL DEFAULT 0, tier TEXT NOT NULL DEFAULT 'D',
  deal_value REAL NOT NULL DEFAULT 0, stage TEXT NOT NULL DEFAULT 'lead', owner TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sales_pipeline_history (
  id TEXT PRIMARY KEY, opportunity_id TEXT NOT NULL DEFAULT '',
  from_stage TEXT, to_stage TEXT NOT NULL DEFAULT '', changed_by TEXT, note TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY, opportunity_id TEXT, company TEXT NOT NULL DEFAULT '',
  contact_email TEXT, sector TEXT, org_size TEXT, package TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'enterprise', status TEXT NOT NULL DEFAULT 'draft',
  html_content TEXT, pdf_url TEXT, total_inr REAL NOT NULL DEFAULT 0,
  gst_inr REAL NOT NULL DEFAULT 0, sent_at INTEGER, viewed_at INTEGER, accepted_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS scanner_orders (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL DEFAULT '', tier TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '', scan_type TEXT NOT NULL DEFAULT 'domain',
  amount_inr REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending_payment',
  token TEXT, report_url TEXT, payment_ref TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS affiliate_members (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT,
  type TEXT NOT NULL DEFAULT 'individual', tier TEXT NOT NULL DEFAULT 'AFFILIATE',
  ref_code TEXT NOT NULL UNIQUE, commission_pct REAL NOT NULL DEFAULT 10.0,
  total_referrals INTEGER NOT NULL DEFAULT 0, total_conversions INTEGER NOT NULL DEFAULT 0,
  total_earnings REAL NOT NULL DEFAULT 0, pending_payout REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active', joined_at INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS affiliate_referrals (
  id TEXT PRIMARY KEY, affiliate_id TEXT NOT NULL DEFAULT '', ref_code TEXT NOT NULL DEFAULT '',
  visitor_ip TEXT, landing_page TEXT, converted INTEGER NOT NULL DEFAULT 0,
  conversion_invoice_id TEXT, commission_inr REAL NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), converted_at INTEGER
);
CREATE TABLE IF NOT EXISTS affiliate_payouts (
  id TEXT PRIMARY KEY, affiliate_id TEXT NOT NULL DEFAULT '',
  amount_inr REAL NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT 'upi',
  upi_id TEXT, bank_details TEXT, status TEXT NOT NULL DEFAULT 'requested',
  processed_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS mssp_partners (
  id TEXT PRIMARY KEY, company TEXT NOT NULL DEFAULT '',
  contact_email TEXT NOT NULL UNIQUE, tier TEXT NOT NULL DEFAULT 'RESELLER',
  plan TEXT NOT NULL DEFAULT 'reseller', brand_name TEXT, custom_domain TEXT,
  primary_color TEXT DEFAULT '#00d4ff', api_key TEXT UNIQUE,
  client_count INTEGER NOT NULL DEFAULT 0, max_clients INTEGER NOT NULL DEFAULT 10,
  margin_pct REAL NOT NULL DEFAULT 20.0, status TEXT NOT NULL DEFAULT 'pending',
  onboarded_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS mssp_clients (
  id TEXT PRIMARY KEY, partner_id TEXT NOT NULL DEFAULT '', company TEXT NOT NULL DEFAULT '',
  domain TEXT, sector TEXT, contact_email TEXT, status TEXT NOT NULL DEFAULT 'active',
  open_alerts INTEGER NOT NULL DEFAULT 0, last_scan_at INTEGER,
  onboarded_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS crm_leads (
  id TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', name TEXT, company TEXT,
  sector TEXT, company_size TEXT, budget_range TEXT, urgency TEXT,
  source TEXT NOT NULL DEFAULT 'website', status TEXT NOT NULL DEFAULT 'new',
  icp_score INTEGER NOT NULL DEFAULT 0, icp_tier TEXT NOT NULL DEFAULT 'D',
  notes TEXT, assigned_to TEXT, demo_booked INTEGER NOT NULL DEFAULT 0,
  demo_at INTEGER, converted INTEGER NOT NULL DEFAULT 0, converted_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS crm_activities (
  id TEXT PRIMARY KEY, lead_id TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT '',
  note TEXT, by_user TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS revos_mrr_snapshots (
  id TEXT PRIMARY KEY, snapshot_date TEXT NOT NULL DEFAULT '',
  mrr_inr REAL NOT NULL DEFAULT 0, arr_inr REAL NOT NULL DEFAULT 0,
  new_mrr REAL NOT NULL DEFAULT 0, churned_mrr REAL NOT NULL DEFAULT 0,
  expansion_mrr REAL NOT NULL DEFAULT 0, active_subs INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS revos_revenue_streams (
  id TEXT PRIMARY KEY, stream_name TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '', amount_inr REAL NOT NULL DEFAULT 0,
  period TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS trust_incidents (
  id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '', description TEXT,
  severity TEXT NOT NULL DEFAULT 'minor', status TEXT NOT NULL DEFAULT 'investigating',
  affected TEXT, started_at INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS trust_testimonials (
  id TEXT PRIMARY KEY, author TEXT NOT NULL DEFAULT '', role TEXT, company TEXT,
  sector TEXT, content TEXT NOT NULL DEFAULT '', rating INTEGER NOT NULL DEFAULT 5,
  verified INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS ceo_targets (
  id TEXT PRIMARY KEY, metric TEXT NOT NULL UNIQUE, target_value REAL NOT NULL DEFAULT 0,
  current_value REAL NOT NULL DEFAULT 0, period TEXT NOT NULL DEFAULT 'monthly',
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────
-- ALTER TABLE PATCHES
-- Adds missing columns to pre-existing tables
-- D1 ignores "duplicate column name" errors — fully safe to re-run
-- ─────────────────────────────────────────────

-- mssp_clients: add partner_id (missing in v22/v23)
ALTER TABLE mssp_clients ADD COLUMN partner_id TEXT DEFAULT '';
-- mssp_clients: add metadata (might be missing)
ALTER TABLE mssp_clients ADD COLUMN metadata TEXT DEFAULT '{}';
-- mssp_clients: add onboarded_at (might be missing)
ALTER TABLE mssp_clients ADD COLUMN onboarded_at INTEGER DEFAULT 0;
-- mssp_clients: add open_alerts (might be missing)
ALTER TABLE mssp_clients ADD COLUMN open_alerts INTEGER DEFAULT 0;

-- scanner_orders: add status (this is the column causing the error!)
ALTER TABLE scanner_orders ADD COLUMN status TEXT DEFAULT 'pending_payment';
-- scanner_orders: add other potentially missing columns
ALTER TABLE scanner_orders ADD COLUMN tier TEXT DEFAULT '';
ALTER TABLE scanner_orders ADD COLUMN target TEXT DEFAULT '';
ALTER TABLE scanner_orders ADD COLUMN scan_type TEXT DEFAULT 'domain';
ALTER TABLE scanner_orders ADD COLUMN amount_inr REAL DEFAULT 0;
ALTER TABLE scanner_orders ADD COLUMN token TEXT;
ALTER TABLE scanner_orders ADD COLUMN report_url TEXT;
ALTER TABLE scanner_orders ADD COLUMN payment_ref TEXT;
ALTER TABLE scanner_orders ADD COLUMN completed_at INTEGER;

-- billing_invoices: patch any missing columns
ALTER TABLE billing_invoices ADD COLUMN status TEXT DEFAULT 'pending';
ALTER TABLE billing_invoices ADD COLUMN gst_amount REAL DEFAULT 0;
ALTER TABLE billing_invoices ADD COLUMN total_inr REAL DEFAULT 0;
ALTER TABLE billing_invoices ADD COLUMN payment_method TEXT;
ALTER TABLE billing_invoices ADD COLUMN transaction_id TEXT;
ALTER TABLE billing_invoices ADD COLUMN license_key TEXT;
ALTER TABLE billing_invoices ADD COLUMN invoice_number TEXT;
ALTER TABLE billing_invoices ADD COLUMN invoice_pdf_url TEXT;
ALTER TABLE billing_invoices ADD COLUMN paid_at INTEGER;
ALTER TABLE billing_invoices ADD COLUMN metadata TEXT DEFAULT '{}';

-- proposals: patch any missing columns
ALTER TABLE proposals ADD COLUMN status TEXT DEFAULT 'draft';
ALTER TABLE proposals ADD COLUMN html_content TEXT;
ALTER TABLE proposals ADD COLUMN pdf_url TEXT;
ALTER TABLE proposals ADD COLUMN total_inr REAL DEFAULT 0;
ALTER TABLE proposals ADD COLUMN gst_inr REAL DEFAULT 0;
ALTER TABLE proposals ADD COLUMN sent_at INTEGER;
ALTER TABLE proposals ADD COLUMN viewed_at INTEGER;
ALTER TABLE proposals ADD COLUMN accepted_at INTEGER;
ALTER TABLE proposals ADD COLUMN metadata TEXT DEFAULT '{}';
ALTER TABLE proposals ADD COLUMN opportunity_id TEXT;
ALTER TABLE proposals ADD COLUMN org_size TEXT;
ALTER TABLE proposals ADD COLUMN type TEXT DEFAULT 'enterprise';
ALTER TABLE proposals ADD COLUMN contact_email TEXT;

-- sales_opportunities: patch any missing columns
ALTER TABLE sales_opportunities ADD COLUMN status TEXT DEFAULT 'active';
ALTER TABLE sales_opportunities ADD COLUMN score INTEGER DEFAULT 0;
ALTER TABLE sales_opportunities ADD COLUMN tier TEXT DEFAULT 'D';
ALTER TABLE sales_opportunities ADD COLUMN deal_value REAL DEFAULT 0;
ALTER TABLE sales_opportunities ADD COLUMN stage TEXT DEFAULT 'lead';
ALTER TABLE sales_opportunities ADD COLUMN metadata TEXT DEFAULT '{}';
ALTER TABLE sales_opportunities ADD COLUMN updated_at INTEGER DEFAULT (unixepoch());

-- affiliate_members: patch
ALTER TABLE affiliate_members ADD COLUMN status TEXT DEFAULT 'active';
ALTER TABLE affiliate_members ADD COLUMN tier TEXT DEFAULT 'AFFILIATE';
ALTER TABLE affiliate_members ADD COLUMN metadata TEXT DEFAULT '{}';

-- crm_leads: patch
ALTER TABLE crm_leads ADD COLUMN status TEXT DEFAULT 'new';
ALTER TABLE crm_leads ADD COLUMN icp_score INTEGER DEFAULT 0;
ALTER TABLE crm_leads ADD COLUMN icp_tier TEXT DEFAULT 'D';
ALTER TABLE crm_leads ADD COLUMN metadata TEXT DEFAULT '{}';
ALTER TABLE crm_leads ADD COLUMN updated_at INTEGER DEFAULT (unixepoch());

-- trust_incidents: patch
ALTER TABLE trust_incidents ADD COLUMN status TEXT DEFAULT 'investigating';

-- revos_mrr_snapshots: patch
ALTER TABLE revos_mrr_snapshots ADD COLUMN mrr_inr REAL DEFAULT 0;
ALTER TABLE revos_mrr_snapshots ADD COLUMN arr_inr REAL DEFAULT 0;

-- mssp_partners: patch
ALTER TABLE mssp_partners ADD COLUMN status TEXT DEFAULT 'pending';
ALTER TABLE mssp_partners ADD COLUMN metadata TEXT DEFAULT '{}';
ALTER TABLE mssp_partners ADD COLUMN api_key TEXT;

-- ─────────────────────────────────────────────
-- SEED DATA
-- ─────────────────────────────────────────────
INSERT OR REPLACE INTO ceo_targets (id, metric, target_value, period) VALUES
  ('ceo_mrr',        'mrr_inr',           100000, 'monthly'),
  ('ceo_arr',        'arr_inr',          1200000, 'annual'),
  ('ceo_leads',      'leads_per_month',       50, 'monthly'),
  ('ceo_demos',      'demos_per_month',        10, 'monthly'),
  ('ceo_deals',      'deals_won_per_month',     5, 'monthly'),
  ('ceo_churn',      'churn_rate_pct',         5.0,'monthly'),
  ('ceo_mssp',       'mssp_partners',           5, 'quarterly'),
  ('ceo_affiliates', 'active_affiliates',      25, 'quarterly');

INSERT OR IGNORE INTO trust_testimonials (id, author, role, company, sector, content, rating, verified) VALUES
  ('tst_001', 'Ravi Kumar',   'Lead SOC Analyst', 'Tier-1 Bank',      'Banking',    'MYTHOS generated a Sentinel KQL rule for a 0-day within 90 seconds.', 5, 1),
  ('tst_002', 'Priya Sharma', 'CISO',             'Healthcare Group', 'Healthcare', 'The AI Cyber Analyst spotted a Lazarus Group indicator our SIEM missed.', 5, 1),
  ('tst_003', 'Ajay Mehta',   'Head of Security', 'FinTech Startup',  'Finance',    'DPDP + HIPAA compliance in 3 weeks. Scanner found 47 gaps automatically.', 5, 1);
