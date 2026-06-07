-- ============================================================
-- CYBERDUDEBIVASH v23.0 RevOS — Safe Migration Script
-- Run AFTER schema_v23_tables.sql
-- Adds missing columns to existing tables + all indexes
-- Safe to re-run (IF NOT EXISTS + ADD COLUMN IF NOT EXISTS)
-- ============================================================

-- ── Fix proposals table (existed in v15 without v23 columns) ─────────────────
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS deal_id TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'enterprise';
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS company TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS contact_email TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS contact_name TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS value_inr INTEGER DEFAULT 0;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'ENTERPRISE';
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS pdf_key TEXT;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS content_json TEXT DEFAULT '{}';
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS viewed_at TEXT;

-- ── Fix audit_log table (existed in v8 without v23 columns) ──────────────────
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS api_key_id TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS resource_id TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ok';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS metadata TEXT DEFAULT '{}';

-- ── All indexes (IF NOT EXISTS = safe to re-run) ──────────────────────────────
CREATE INDEX IF NOT EXISTS idx_sub_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_sub_plan ON subscriptions(plan);
CREATE INDEX IF NOT EXISTS idx_sub_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_sub_email ON subscriptions(email);
CREATE INDEX IF NOT EXISTS idx_sub_created ON subscriptions(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mrr_date ON mrr_snapshots(snapshot_date);
CREATE INDEX IF NOT EXISTS idx_churn_date ON churn_events(churned_at);
CREATE INDEX IF NOT EXISTS idx_churn_plan ON churn_events(plan);
CREATE INDEX IF NOT EXISTS idx_cac_channel ON cac_events(channel);
CREATE INDEX IF NOT EXISTS idx_cac_date ON cac_events(event_date);
CREATE INDEX IF NOT EXISTS idx_deal_stage ON deal_pipeline(stage);
CREATE INDEX IF NOT EXISTS idx_deal_value ON deal_pipeline(deal_value_inr);
CREATE INDEX IF NOT EXISTS idx_deal_email ON deal_pipeline(contact_email);
CREATE INDEX IF NOT EXISTS idx_deal_updated ON deal_pipeline(updated_at);
CREATE INDEX IF NOT EXISTS idx_icp_email ON icp_scores(email);
CREATE INDEX IF NOT EXISTS idx_icp_score ON icp_scores(total_score);
CREATE INDEX IF NOT EXISTS idx_prop_deal ON proposals(deal_id);
CREATE INDEX IF NOT EXISTS idx_prop_status ON proposals(status);
CREATE INDEX IF NOT EXISTS idx_prop_created ON proposals(created_at);
CREATE INDEX IF NOT EXISTS idx_apib_key ON api_billing(api_key_id);
CREATE INDEX IF NOT EXISTS idx_apib_period ON api_billing(billing_period);
CREATE INDEX IF NOT EXISTS idx_apib_created ON api_billing(created_at);
CREATE INDEX IF NOT EXISTS idx_apib_user ON api_billing(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_apisum_key_period ON api_usage_summary(api_key_id, period);
CREATE INDEX IF NOT EXISTS idx_pp_cve ON product_pipeline(cve_id);
CREATE INDEX IF NOT EXISTS idx_pp_status ON product_pipeline(status);
CREATE INDEX IF NOT EXISTS idx_pp_created ON product_pipeline(created_at);
CREATE INDEX IF NOT EXISTS idx_mssp_owner ON mssp_clients(mssp_user_id);
CREATE INDEX IF NOT EXISTS idx_mssp_status ON mssp_clients(status);
CREATE INDEX IF NOT EXISTS idx_mssp_health ON mssp_clients(health_score);
CREATE UNIQUE INDEX IF NOT EXISTS idx_msspbill_period ON mssp_billing(client_id, period);
CREATE INDEX IF NOT EXISTS idx_cs_user ON cs_signals(user_id);
CREATE INDEX IF NOT EXISTS idx_cs_type ON cs_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_cs_created ON cs_signals(created_at);
CREATE INDEX IF NOT EXISTS idx_ciso_user ON ciso_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_ciso_type ON ciso_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_ciso_status ON ciso_reports(status);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rl_identifier ON rate_limit_log(identifier, window);
