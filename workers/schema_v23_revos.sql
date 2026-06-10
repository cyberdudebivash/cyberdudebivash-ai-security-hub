-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — v23.0 RevOS Schema
-- Revenue Operating System: MRR/ARR/Churn/LTV/CAC/MSSP/API
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_v23_revos.sql --remote
-- ============================================================

-- ── PHASE 1: Subscription & MRR Engine ──────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  plan            TEXT NOT NULL DEFAULT 'FREE' CHECK(plan IN ('FREE','STARTER','PRO','ENTERPRISE','MSSP')),
  status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('trialing','active','past_due','cancelled','paused')),
  price_inr       INTEGER NOT NULL DEFAULT 0,
  billing_cycle   TEXT NOT NULL DEFAULT 'monthly' CHECK(billing_cycle IN ('monthly','annual')),
  trial_ends_at   TEXT,
  current_period_start TEXT NOT NULL DEFAULT (datetime('now')),
  current_period_end   TEXT NOT NULL DEFAULT (datetime('now','+1 month')),
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  cancelled_at    TEXT,
  cancel_reason   TEXT,
  razorpay_sub_id TEXT,
  razorpay_plan_id TEXT,
  payment_method  TEXT DEFAULT 'razorpay',
  company         TEXT,
  company_size    TEXT,
  industry        TEXT,
  country         TEXT DEFAULT 'IN',
  utm_source      TEXT,
  utm_campaign    TEXT,
  referral_code   TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sub_user     ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_sub_plan     ON subscriptions(plan);
CREATE INDEX IF NOT EXISTS idx_sub_status   ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_sub_email    ON subscriptions(email);
CREATE INDEX IF NOT EXISTS idx_sub_created  ON subscriptions(created_at DESC);

-- ── MRR/ARR Snapshots (daily cron writes) ───────────────────
CREATE TABLE IF NOT EXISTS mrr_snapshots (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  snapshot_date   TEXT NOT NULL DEFAULT (date('now')),
  mrr_inr         INTEGER NOT NULL DEFAULT 0,
  arr_inr         INTEGER NOT NULL DEFAULT 0,
  new_mrr         INTEGER NOT NULL DEFAULT 0,
  expansion_mrr   INTEGER NOT NULL DEFAULT 0,
  contraction_mrr INTEGER NOT NULL DEFAULT 0,
  churned_mrr     INTEGER NOT NULL DEFAULT 0,
  net_new_mrr     INTEGER NOT NULL DEFAULT 0,
  active_subs     INTEGER NOT NULL DEFAULT 0,
  trial_subs      INTEGER NOT NULL DEFAULT 0,
  free_users      INTEGER NOT NULL DEFAULT 0,
  starter_count   INTEGER NOT NULL DEFAULT 0,
  pro_count       INTEGER NOT NULL DEFAULT 0,
  enterprise_count INTEGER NOT NULL DEFAULT 0,
  mssp_count      INTEGER NOT NULL DEFAULT 0,
  trial_to_paid_rate REAL NOT NULL DEFAULT 0,
  churn_rate      REAL NOT NULL DEFAULT 0,
  nrr             REAL NOT NULL DEFAULT 100,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mrr_date ON mrr_snapshots(snapshot_date);

-- ── Churn Events ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS churn_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  subscription_id TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  email           TEXT,
  plan            TEXT NOT NULL,
  mrr_lost_inr    INTEGER NOT NULL DEFAULT 0,
  reason          TEXT CHECK(reason IN ('price','missing_feature','competitor','no_value','budget','technical','other','unknown')),
  reason_detail   TEXT,
  was_trial       INTEGER NOT NULL DEFAULT 0,
  tenure_days     INTEGER NOT NULL DEFAULT 0,
  churned_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_churn_date ON churn_events(churned_at DESC);
CREATE INDEX IF NOT EXISTS idx_churn_plan ON churn_events(plan);

-- ── Customer LTV ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_ltv (
  user_id         TEXT PRIMARY KEY,
  email           TEXT,
  total_revenue_inr INTEGER NOT NULL DEFAULT 0,
  sub_revenue_inr INTEGER NOT NULL DEFAULT 0,
  marketplace_revenue_inr INTEGER NOT NULL DEFAULT 0,
  api_revenue_inr INTEGER NOT NULL DEFAULT 0,
  report_revenue_inr INTEGER NOT NULL DEFAULT 0,
  payment_count   INTEGER NOT NULL DEFAULT 0,
  first_payment_at TEXT,
  last_payment_at TEXT,
  current_plan    TEXT DEFAULT 'FREE',
  predicted_ltv_inr INTEGER NOT NULL DEFAULT 0,
  ltv_segment     TEXT DEFAULT 'low' CHECK(ltv_segment IN ('low','medium','high','champion')),
  churn_risk_score REAL NOT NULL DEFAULT 0,
  upsell_score    REAL NOT NULL DEFAULT 0,
  health_score    INTEGER NOT NULL DEFAULT 50,
  last_active_at  TEXT,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── CAC Events ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cac_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  channel         TEXT NOT NULL CHECK(channel IN ('organic','paid_search','social','referral','affiliate','telegram','direct','partner','cold_outreach')),
  campaign        TEXT,
  user_id         TEXT,
  email           TEXT,
  cost_inr        INTEGER NOT NULL DEFAULT 0,
  converted       INTEGER NOT NULL DEFAULT 0,
  plan_converted  TEXT,
  mrr_generated   INTEGER NOT NULL DEFAULT 0,
  event_date      TEXT NOT NULL DEFAULT (date('now')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cac_channel ON cac_events(channel);
CREATE INDEX IF NOT EXISTS idx_cac_date    ON cac_events(event_date DESC);

-- ── PHASE 2: Enterprise CRM Pipeline ────────────────────────
CREATE TABLE IF NOT EXISTS deal_pipeline (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  company         TEXT NOT NULL,
  contact_name    TEXT,
  contact_email   TEXT NOT NULL,
  contact_phone   TEXT,
  contact_title   TEXT,
  company_size    TEXT,
  industry        TEXT,
  country         TEXT DEFAULT 'IN',
  website         TEXT,
  stage           TEXT NOT NULL DEFAULT 'lead' CHECK(stage IN ('lead','qualified','demo','proposal','negotiation','closed_won','closed_lost')),
  deal_value_inr  INTEGER NOT NULL DEFAULT 0,
  arr_potential   INTEGER NOT NULL DEFAULT 0,
  plan_target     TEXT DEFAULT 'ENTERPRISE',
  icp_score       INTEGER NOT NULL DEFAULT 0,
  security_maturity INTEGER NOT NULL DEFAULT 0,
  probability_pct INTEGER NOT NULL DEFAULT 0,
  source          TEXT,
  owner           TEXT DEFAULT 'bivash',
  next_action     TEXT,
  next_action_date TEXT,
  demo_booked_at  TEXT,
  proposal_sent_at TEXT,
  closed_at       TEXT,
  lost_reason     TEXT,
  notes           TEXT,
  tags            TEXT DEFAULT '[]',
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_deal_stage   ON deal_pipeline(stage);
CREATE INDEX IF NOT EXISTS idx_deal_value   ON deal_pipeline(deal_value_inr DESC);
CREATE INDEX IF NOT EXISTS idx_deal_email   ON deal_pipeline(contact_email);
CREATE INDEX IF NOT EXISTS idx_deal_updated ON deal_pipeline(updated_at DESC);

-- ── ICP Scores ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS icp_scores (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  deal_id         TEXT,
  email           TEXT NOT NULL,
  company         TEXT,
  industry_fit    INTEGER DEFAULT 0,
  size_fit        INTEGER DEFAULT 0,
  tech_stack_fit  INTEGER DEFAULT 0,
  pain_signal     INTEGER DEFAULT 0,
  budget_signal   INTEGER DEFAULT 0,
  urgency_signal  INTEGER DEFAULT 0,
  total_score     INTEGER DEFAULT 0,
  tier            TEXT DEFAULT 'C' CHECK(tier IN ('A','B','C','D')),
  enrichment_data TEXT DEFAULT '{}',
  scored_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_icp_email ON icp_scores(email);
CREATE INDEX IF NOT EXISTS idx_icp_score ON icp_scores(total_score DESC);

-- ── Proposals ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS proposals (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  deal_id         TEXT,
  type            TEXT NOT NULL DEFAULT 'enterprise' CHECK(type IN ('enterprise','mssp','security_assessment','ai_security','custom')),
  company         TEXT NOT NULL,
  contact_email   TEXT NOT NULL,
  contact_name    TEXT,
  value_inr       INTEGER NOT NULL DEFAULT 0,
  plan            TEXT DEFAULT 'ENTERPRISE',
  status          TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','viewed','accepted','rejected','expired')),
  pdf_key         TEXT,
  pdf_url         TEXT,
  content_json    TEXT DEFAULT '{}',
  valid_until     TEXT,
  sent_at         TEXT,
  viewed_at       TEXT,
  responded_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_prop_deal    ON proposals(deal_id);
CREATE INDEX IF NOT EXISTS idx_prop_status  ON proposals(status);
CREATE INDEX IF NOT EXISTS idx_prop_created ON proposals(created_at DESC);

-- ── PHASE 3: API Economy ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_billing (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  api_key_id      TEXT NOT NULL,
  user_id         TEXT,
  endpoint        TEXT NOT NULL,
  method          TEXT DEFAULT 'GET',
  plan            TEXT DEFAULT 'FREE',
  response_ms     INTEGER DEFAULT 0,
  status_code     INTEGER DEFAULT 200,
  tokens_used     INTEGER DEFAULT 0,
  cost_paise      INTEGER DEFAULT 0,
  billed          INTEGER DEFAULT 0,
  billing_period  TEXT DEFAULT (strftime('%Y-%m',datetime('now'))),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_apib_key     ON api_billing(api_key_id);
CREATE INDEX IF NOT EXISTS idx_apib_period  ON api_billing(billing_period);
CREATE INDEX IF NOT EXISTS idx_apib_created ON api_billing(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_apib_user    ON api_billing(user_id);

CREATE TABLE IF NOT EXISTS api_usage_summary (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  api_key_id      TEXT NOT NULL,
  user_id         TEXT,
  period          TEXT NOT NULL,
  total_calls     INTEGER DEFAULT 0,
  successful_calls INTEGER DEFAULT 0,
  failed_calls    INTEGER DEFAULT 0,
  total_cost_paise INTEGER DEFAULT 0,
  top_endpoints   TEXT DEFAULT '[]',
  avg_latency_ms  INTEGER DEFAULT 0,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_apisum_key_period ON api_usage_summary(api_key_id, period);

-- ── PHASE 4: Defense Marketplace Product Pipeline ────────────
CREATE TABLE IF NOT EXISTS product_pipeline (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  cve_id          TEXT NOT NULL,
  cve_title       TEXT,
  cvss_score      REAL DEFAULT 0,
  severity        TEXT DEFAULT 'MEDIUM',
  status          TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','analyzing','generating','validating','published','failed')),
  products_queued TEXT DEFAULT '[]',
  products_done   TEXT DEFAULT '[]',
  error           TEXT,
  triggered_by    TEXT DEFAULT 'cron',
  started_at      TEXT,
  completed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pp_cve    ON product_pipeline(cve_id);
CREATE INDEX IF NOT EXISTS idx_pp_status ON product_pipeline(status);

-- ── PHASE 5: MSSP Command Center ─────────────────────────────
CREATE TABLE IF NOT EXISTS mssp_clients (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  mssp_user_id    TEXT NOT NULL,
  client_name     TEXT NOT NULL,
  client_domain   TEXT,
  client_email    TEXT,
  contact_name    TEXT,
  industry        TEXT,
  employee_count  INTEGER,
  plan            TEXT DEFAULT 'STARTER',
  mrr_inr         INTEGER DEFAULT 0,
  health_score    INTEGER DEFAULT 70,
  risk_score      INTEGER DEFAULT 30,
  sla_tier        TEXT DEFAULT 'standard' CHECK(sla_tier IN ('standard','priority','critical')),
  white_label_domain TEXT,
  white_label_name TEXT,
  onboarded_at    TEXT DEFAULT (datetime('now')),
  last_scan_at    TEXT,
  open_incidents  INTEGER DEFAULT 0,
  critical_findings INTEGER DEFAULT 0,
  compliance_score INTEGER DEFAULT 50,
  status          TEXT DEFAULT 'active' CHECK(status IN ('active','onboarding','suspended','churned')),
  tags            TEXT DEFAULT '[]',
  notes           TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mssp_owner  ON mssp_clients(mssp_user_id);
CREATE INDEX IF NOT EXISTS idx_mssp_status ON mssp_clients(status);
CREATE INDEX IF NOT EXISTS idx_mssp_health ON mssp_clients(health_score DESC);

CREATE TABLE IF NOT EXISTS mssp_billing (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  mssp_user_id    TEXT NOT NULL,
  client_id       TEXT NOT NULL,
  period          TEXT NOT NULL DEFAULT (strftime('%Y-%m',datetime('now'))),
  mrr_inr         INTEGER DEFAULT 0,
  scans_used      INTEGER DEFAULT 0,
  api_calls_used  INTEGER DEFAULT 0,
  reports_generated INTEGER DEFAULT 0,
  invoice_id      TEXT,
  status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','invoiced','paid','overdue')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_msspbill_period ON mssp_billing(client_id, period);

-- ── PHASE 6: AI Customer Success Signals ────────────────────
CREATE TABLE IF NOT EXISTS cs_signals (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT NOT NULL,
  email           TEXT,
  signal_type     TEXT NOT NULL CHECK(signal_type IN ('churn_risk','upsell_ready','low_engagement','milestone','upgrade_trigger','renewal_due','health_drop','power_user')),
  score           REAL DEFAULT 0,
  message         TEXT,
  recommended_action TEXT,
  auto_outreach   INTEGER DEFAULT 0,
  outreach_sent_at TEXT,
  resolved        INTEGER DEFAULT 0,
  resolved_at     TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cs_user    ON cs_signals(user_id);
CREATE INDEX IF NOT EXISTS idx_cs_type    ON cs_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_cs_created ON cs_signals(created_at DESC);

-- ── PHASE 7: CISO Report Jobs ────────────────────────────────
CREATE TABLE IF NOT EXISTS ciso_reports (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT,
  client_id       TEXT,
  report_type     TEXT NOT NULL CHECK(report_type IN ('monthly','quarterly','annual','executive','compliance','threat_landscape','incident')),
  period          TEXT NOT NULL,
  status          TEXT DEFAULT 'queued' CHECK(status IN ('queued','generating','ready','delivered','failed')),
  pdf_key         TEXT,
  pdf_url         TEXT,
  data_snapshot   TEXT DEFAULT '{}',
  email_delivered INTEGER DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ciso_user   ON ciso_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_ciso_type   ON ciso_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_ciso_status ON ciso_reports(status);

-- ── PHASE 8: Audit & Rate Limiting ───────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT,
  api_key_id      TEXT,
  action          TEXT NOT NULL,
  resource        TEXT,
  resource_id     TEXT,
  ip              TEXT,
  user_agent      TEXT,
  status          TEXT DEFAULT 'ok',
  metadata        TEXT DEFAULT '{}',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS rate_limit_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  identifier      TEXT NOT NULL,
  window          TEXT NOT NULL,
  count           INTEGER DEFAULT 1,
  blocked         INTEGER DEFAULT 0,
  last_hit        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rl_identifier ON rate_limit_log(identifier, window);

-- ── Revenue Summary View helper ───────────────────────────────
CREATE TABLE IF NOT EXISTS revenue_monthly (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  period          TEXT NOT NULL UNIQUE,
  sub_revenue_inr INTEGER DEFAULT 0,
  marketplace_revenue_inr INTEGER DEFAULT 0,
  api_revenue_inr INTEGER DEFAULT 0,
  report_revenue_inr INTEGER DEFAULT 0,
  mssp_revenue_inr INTEGER DEFAULT 0,
  total_revenue_inr INTEGER DEFAULT 0,
  new_customers   INTEGER DEFAULT 0,
  churned_customers INTEGER DEFAULT 0,
  net_customers   INTEGER DEFAULT 0,
  updated_at      TEXT DEFAULT (datetime('now'))
);
