-- =============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Fix: 21 tables missing in production
-- =============================================================================
-- Generated after the nightly D1 Schema Drift Check (issue #70, run
-- 2026-07-07) found production missing 21 tables that schema_master.sql /
-- schema_v39_marketplace.sql define, and that live code already queries:
-- workers/src/index.js:2541/:8202 (renewal_queue, for the executive
-- dashboard's renewal/ARR-at-risk widgets), /api/billing/invoices
-- (invoices), plus handlers for AI governance, AI red-team, developer
-- webhooks, marketplace orders, and more (26 files reference these 21
-- table names — see the drift audit). Every query is wrapped in
-- `.catch(() => null)`, so instead of erroring these features have been
-- silently returning empty/zero in production.
--
-- Root cause: .github/workflows/db-migrate.yml — the repo's only sanctioned
-- path for applying a committed schema file to production — has 0 runs in
-- this repo's history. These tables were coded and committed but the
-- migration was never actually executed against the live D1 database.
--
-- Scope: ONLY the 21 confirmed-missing tables + their own indexes, extracted
-- verbatim (byte-for-byte CREATE statements) from schema_master.sql and
-- schema_v39_marketplace.sql. Deliberately excludes the 29 tables the same
-- drift report found with column-level drift — those already exist in
-- production, and this file must not touch them (an IF-NOT-EXISTS CREATE
-- INDEX on one of those could fail if the drifted table is missing the
-- indexed column, per lab-bootstrap-d1.mjs's own --heal comment about
-- exactly this failure mode). Also excludes the 15 tables production has
-- that aren't in any tracked schema file — a separate documentation gap,
-- not a missing-functionality bug.
--
-- 100% additive: every statement is CREATE TABLE/INDEX IF NOT EXISTS.
-- Applying this to production cannot drop or alter any existing table,
-- index, or row.
--
-- Verified before use: replayed byte-for-byte against a simulated
-- pre-fix production database (every other REPLAY file from
-- scripts/lab-bootstrap-d1.mjs applied first — 220 statements, 64 tables —
-- then this file on top) — 76/76 statements applied, 0 failures, exactly
-- the 21 target tables created, nothing else touched.
--
-- Apply via: Actions → "D1 Schema Migration (gated)" → schema_file =
-- workers/schema_migration_prod_missing_tables_2026_07.sql, confirm = APPLY.
-- Takes an automatic pre-migration backup first (90-day retention).
-- =============================================================================

PRAGMA foreign_keys = OFF;

-- ── Tables ──────────────────────────────────────────────────────────────────

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

CREATE TABLE IF NOT EXISTS platform_counters (
  key        TEXT PRIMARY KEY,
  value      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

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

CREATE TABLE IF NOT EXISTS revenue_streams (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  period          TEXT NOT NULL,
  stream          TEXT NOT NULL CHECK(stream IN ('subscriptions','marketplace','api','reports','consulting','training','mssp')),
  revenue_inr     INTEGER NOT NULL DEFAULT 0,
  transaction_count INTEGER NOT NULL DEFAULT 0,
  customer_count  INTEGER NOT NULL DEFAULT 0,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS revos_mrr_snapshots (
  id TEXT PRIMARY KEY, snapshot_date TEXT NOT NULL DEFAULT '',
  mrr_inr REAL NOT NULL DEFAULT 0, arr_inr REAL NOT NULL DEFAULT 0,
  new_mrr REAL NOT NULL DEFAULT 0, churned_mrr REAL NOT NULL DEFAULT 0,
  expansion_mrr REAL NOT NULL DEFAULT 0, active_subs INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

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

CREATE TABLE IF NOT EXISTS ai_model_registry (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0',
  model_type TEXT NOT NULL,
  data_classification TEXT NOT NULL,
  deployment_context TEXT NOT NULL,
  autonomy_level TEXT NOT NULL,
  impact_domain TEXT NOT NULL,
  explainability TEXT NOT NULL,
  bias_tested INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 0,
  risk_level TEXT NOT NULL DEFAULT 'LOW',
  eu_ai_act_category TEXT NOT NULL DEFAULT 'MINIMAL',
  owner_email TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  metadata TEXT DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_governance_policies (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  rules TEXT DEFAULT '[]',
  enforcement_level TEXT NOT NULL DEFAULT 'WARN',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_redteam_campaigns (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  target_model TEXT NOT NULL DEFAULT 'unknown',
  target_endpoint TEXT DEFAULT '',
  technique_ids TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_by TEXT DEFAULT 'anonymous',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS developer_webhooks (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  url TEXT NOT NULL,
  events TEXT DEFAULT '[]',
  secret TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  last_tested_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fair_risk_assessments (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  scenario_name TEXT NOT NULL DEFAULT 'Unnamed Scenario',
  inputs TEXT DEFAULT '{}',
  outputs TEXT DEFAULT '{}',
  risk_level TEXT NOT NULL DEFAULT 'LOW',
  ale INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS executive_kri_values (
  org_id TEXT NOT NULL,
  period TEXT NOT NULL,
  kri_values TEXT DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (org_id, period)
);

CREATE TABLE IF NOT EXISTS executive_reports (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  report_type TEXT NOT NULL DEFAULT 'BOARD',
  quarter TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_tenants (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  company_name     TEXT,
  tier             TEXT NOT NULL DEFAULT 'FREE'
                     CHECK(tier IN ('FREE','STARTER','PRO','TEAM','ENTERPRISE','MSSP')),
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','suspended','cancelled','trial')),
  trial_ends_at    TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS marketplace_orders (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,
  tenant_id        TEXT,
  product_id       TEXT NOT NULL,
  product_name     TEXT NOT NULL,
  sku              TEXT,
  category         TEXT NOT NULL,
  amount_usd       REAL NOT NULL DEFAULT 0,
  amount_inr       INTEGER NOT NULL DEFAULT 0,
  currency         TEXT NOT NULL DEFAULT 'USD',
  status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending','paid','failed','refunded','cancelled')),
  payment_provider TEXT,
  payment_ref      TEXT,
  razorpay_order_id TEXT,
  gumroad_sale_id  TEXT,
  download_url     TEXT,
  download_expires_at TEXT,
  invoice_number   TEXT UNIQUE,
  metadata         TEXT DEFAULT '{}',
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (tenant_id) REFERENCES customer_tenants(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS intel_subscriptions (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,
  tenant_id        TEXT,
  plan_id          TEXT NOT NULL,
  plan_name        TEXT NOT NULL,
  tier             TEXT NOT NULL DEFAULT 'FREE',
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','paused','cancelled','past_due','trialing','expired')),
  billing_period   TEXT NOT NULL DEFAULT 'monthly'
                     CHECK(billing_period IN ('monthly','annual','custom')),
  price_usd        REAL NOT NULL DEFAULT 0,
  price_inr        INTEGER NOT NULL DEFAULT 0,
  current_period_start TEXT,
  current_period_end   TEXT,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  trial_start      TEXT,
  trial_end        TEXT,
  payment_provider TEXT,
  subscription_ref TEXT,
  cancel_reason    TEXT,
  upgrade_from     TEXT,
  metadata         TEXT DEFAULT '{}',
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (tenant_id) REFERENCES customer_tenants(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS customer_entitlements (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  tenant_id        TEXT,
  feature          TEXT NOT NULL,
  source           TEXT NOT NULL DEFAULT 'subscription'
                     CHECK(source IN ('subscription','purchase','trial','manual','bundle')),
  source_ref       TEXT,
  tier_required    TEXT NOT NULL DEFAULT 'FREE',
  enabled          INTEGER NOT NULL DEFAULT 1,
  expires_at       TEXT,
  granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at       TEXT,
  revoke_reason    TEXT,
  metadata         TEXT DEFAULT '{}',
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES customer_tenants(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS provisioning_log (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,
  tenant_id        TEXT,
  trigger_type     TEXT NOT NULL
                     CHECK(trigger_type IN ('purchase','subscription','trial','manual','upgrade','downgrade','cancel','renewal')),
  trigger_ref      TEXT,
  actions_taken    TEXT NOT NULL DEFAULT '[]',
  entitlements_granted TEXT DEFAULT '[]',
  api_keys_created INTEGER NOT NULL DEFAULT 0,
  tenant_created   INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'success'
                     CHECK(status IN ('success','partial','failed')),
  error_detail     TEXT,
  duration_ms      INTEGER,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS report_catalog (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  title            TEXT NOT NULL,
  slug             TEXT NOT NULL UNIQUE,
  category         TEXT NOT NULL
                     CHECK(category IN ('cve','malware','threat_actor','industry','executive','ai_security','bundle')),
  severity         TEXT,
  summary          TEXT,
  preview_content  TEXT,
  full_content_url TEXT,
  price_usd        REAL NOT NULL DEFAULT 49,
  price_inr        INTEGER NOT NULL DEFAULT 3999,
  published_at     TEXT NOT NULL DEFAULT (datetime('now')),
  is_featured      INTEGER NOT NULL DEFAULT 0,
  is_active        INTEGER NOT NULL DEFAULT 1,
  download_count   INTEGER NOT NULL DEFAULT 0,
  purchase_count   INTEGER NOT NULL DEFAULT 0,
  tags             TEXT DEFAULT '[]',
  metadata         TEXT DEFAULT '{}',
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Indexes ─────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_inv_created  ON invoices(created_at);
CREATE INDEX IF NOT EXISTS idx_inv_customer ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_inv_status   ON invoices(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_inv_number ON invoices(invoice_number);

CREATE INDEX IF NOT EXISTS idx_recovery_retry  ON payment_recovery(next_retry_at);
CREATE INDEX IF NOT EXISTS idx_recovery_status ON payment_recovery(status);
CREATE INDEX IF NOT EXISTS idx_recovery_user   ON payment_recovery(user_id);

CREATE INDEX IF NOT EXISTS idx_paypal_order ON paypal_transactions(paypal_order_id);

CREATE INDEX IF NOT EXISTS idx_renewal_date   ON renewal_queue(renewal_date);
CREATE INDEX IF NOT EXISTS idx_renewal_status ON renewal_queue(status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_revstream_period ON revenue_streams(period, stream);

CREATE INDEX IF NOT EXISTS idx_revos_mrr_date ON revos_mrr_snapshots(snapshot_date);

CREATE INDEX IF NOT EXISTS idx_scanord_status  ON scan_orders(payment_status);
CREATE INDEX IF NOT EXISTS idx_scanord_token   ON scan_orders(report_token);
CREATE INDEX IF NOT EXISTS idx_scanord_user    ON scan_orders(user_id);

CREATE INDEX IF NOT EXISTS idx_ai_model_registry_org ON ai_model_registry(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_model_registry_risk ON ai_model_registry(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_model_registry_eu ON ai_model_registry(eu_ai_act_category);
CREATE INDEX IF NOT EXISTS idx_ai_model_registry_status ON ai_model_registry(status);

CREATE INDEX IF NOT EXISTS idx_ai_governance_policies_org ON ai_governance_policies(org_id);

CREATE INDEX IF NOT EXISTS idx_ai_redteam_campaigns_org ON ai_redteam_campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_redteam_campaigns_status ON ai_redteam_campaigns(status);

CREATE INDEX IF NOT EXISTS idx_developer_webhooks_org ON developer_webhooks(org_id);
CREATE INDEX IF NOT EXISTS idx_developer_webhooks_status ON developer_webhooks(status);

CREATE INDEX IF NOT EXISTS idx_fair_risk_assessments_org ON fair_risk_assessments(org_id);
CREATE INDEX IF NOT EXISTS idx_fair_risk_assessments_risk ON fair_risk_assessments(risk_level);
CREATE INDEX IF NOT EXISTS idx_fair_risk_assessments_ale ON fair_risk_assessments(ale DESC);

CREATE INDEX IF NOT EXISTS idx_executive_reports_org ON executive_reports(org_id);
CREATE INDEX IF NOT EXISTS idx_executive_reports_type ON executive_reports(report_type);

CREATE INDEX IF NOT EXISTS idx_tenants_user   ON customer_tenants(user_id);
CREATE INDEX IF NOT EXISTS idx_tenants_tier   ON customer_tenants(tier);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON customer_tenants(status);

CREATE INDEX IF NOT EXISTS idx_mktorders_user      ON marketplace_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_mktorders_status    ON marketplace_orders(status);
CREATE INDEX IF NOT EXISTS idx_mktorders_product   ON marketplace_orders(product_id);
CREATE INDEX IF NOT EXISTS idx_mktorders_created   ON marketplace_orders(created_at);
CREATE INDEX IF NOT EXISTS idx_mktorders_razorpay  ON marketplace_orders(razorpay_order_id);

CREATE INDEX IF NOT EXISTS idx_intelsub_user   ON intel_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_intelsub_status ON intel_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_intelsub_plan   ON intel_subscriptions(plan_id);
CREATE INDEX IF NOT EXISTS idx_intelsub_period ON intel_subscriptions(current_period_end);

CREATE INDEX IF NOT EXISTS idx_entitle_user    ON customer_entitlements(user_id);
CREATE INDEX IF NOT EXISTS idx_entitle_feature ON customer_entitlements(feature);
CREATE INDEX IF NOT EXISTS idx_entitle_enabled ON customer_entitlements(enabled);
CREATE INDEX IF NOT EXISTS idx_entitle_expires ON customer_entitlements(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_entitle_user_feat ON customer_entitlements(user_id, feature, source_ref);

CREATE INDEX IF NOT EXISTS idx_provlog_user    ON provisioning_log(user_id);
CREATE INDEX IF NOT EXISTS idx_provlog_trigger ON provisioning_log(trigger_type);
CREATE INDEX IF NOT EXISTS idx_provlog_created ON provisioning_log(created_at);

CREATE INDEX IF NOT EXISTS idx_reportcat_category  ON report_catalog(category);
CREATE INDEX IF NOT EXISTS idx_reportcat_severity  ON report_catalog(severity);
CREATE INDEX IF NOT EXISTS idx_reportcat_featured  ON report_catalog(is_featured);
CREATE INDEX IF NOT EXISTS idx_reportcat_active    ON report_catalog(is_active);
CREATE INDEX IF NOT EXISTS idx_reportcat_published ON report_catalog(published_at);
