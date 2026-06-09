-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema Migration v30.0
-- P0/P1 Remediation: Governance gate, subscription tiers, metrics hydration
-- ============================================================================
-- DEPLOYMENT NOTES (critical D1 constraints):
--   1. Run via: npx wrangler d1 execute cyberdudebivash-security-hub --file=schema_v30_p0p1.sql
--   2. D1 does NOT support CREATE INDEX IF NOT EXISTS — use DROP + CREATE pattern
--   3. D1 rolls back the ENTIRE batch on ANY error — every statement must be safe
--   4. All apostrophes in string literals use '' (double-single), never backslash
--   5. Confirm ground truth before running: SELECT name FROM sqlite_master WHERE type='table'
-- ============================================================================

-- ── 1. P0 Exceptions Table (Severity Governance violations) ─────────────────
CREATE TABLE IF NOT EXISTS p0_exceptions (
  id                  TEXT PRIMARY KEY,
  entry_id            TEXT NOT NULL,
  trigger_reason      TEXT NOT NULL
                        CHECK(trigger_reason IN ('active_exploitation_flag',
                                                 'cisa_kev_flag',
                                                 'cvss_9_threshold',
                                                 'policy_enforcement')),
  original_severity   TEXT NOT NULL,
  corrected_severity  TEXT NOT NULL
                        CHECK(corrected_severity IN ('HIGH', 'CRITICAL')),
  cvss_score          REAL,
  active_exploitation INTEGER NOT NULL DEFAULT 0 CHECK(active_exploitation IN (0,1)),
  cisa_kev            INTEGER NOT NULL DEFAULT 0 CHECK(cisa_kev IN (0,1)),
  logged_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── 2. Subscription Tiers Enum (reference table) ────────────────────────────
CREATE TABLE IF NOT EXISTS subscription_tier_defs (
  tier            TEXT PRIMARY KEY,
  label           TEXT NOT NULL,
  monthly_limit   INTEGER NOT NULL DEFAULT 3000,
  daily_limit     INTEGER NOT NULL DEFAULT 100,
  burst_per_min   INTEGER NOT NULL DEFAULT 5,
  price_inr       INTEGER NOT NULL DEFAULT 0,
  price_usd       INTEGER NOT NULL DEFAULT 0,
  scan_preview    INTEGER NOT NULL DEFAULT 2,
  features_json   TEXT
);

-- Upsert authoritative tier definitions
INSERT OR REPLACE INTO subscription_tier_defs
  (tier, label, monthly_limit, daily_limit, burst_per_min, price_inr, price_usd, scan_preview, features_json)
VALUES
  ('COMMUNITY',    'Community',    3000,    100,  5,      0,     0,   2,
   '["domain_scan_preview","sentinel_apex_feed","cve_tracker"]'),
  ('PROFESSIONAL', 'Professional', 10000,   340,  20,  1499,    18,  -1,
   '["full_scan","pdf_reports","mitre_mapping","api_access"]'),
  ('TEAM',         'Team',         100000,  3400, 40,  4999,    60,  -1,
   '["full_scan","pdf_reports","mitre_mapping","api_access","siem_integration","ciso_dashboard","team_seats_5"]'),
  ('BUSINESS',     'Business',     1000000, 34000,100, 14999,  180,  -1,
   '["full_scan","pdf_reports","mitre_mapping","unlimited_api","siem_integration","ciso_dashboard","dark_web_monitoring","sigma_yara_rules","team_seats_20","priority_support"]'),
  ('ENTERPRISE',   'Enterprise',   -1,      -1,   200, 49999,  600,  -1,
   '["everything","white_label","sso_saml","sla_99_9","dedicated_csm","custom_integrations","mssp_reseller"]');

-- ── 3. Subscriptions Table (ensure all required columns exist) ───────────────
CREATE TABLE IF NOT EXISTS subscriptions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'COMMUNITY',
  status        TEXT NOT NULL DEFAULT 'active'
                  CHECK(status IN ('active','cancelled_stripe_cancellation',
                                   'cancelled_razorpay_cancellation',
                                   'cancelled_admin','expired','pending')),
  processor     TEXT,
  external_id   TEXT,
  price_inr     INTEGER DEFAULT 0,
  activated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at    TEXT,
  cancelled_at  TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Add missing columns to subscriptions if upgrading from earlier schema
-- (D1 ADD COLUMN is safe even if column already exists in some SQLite versions,
--  but to be safe we use the IF NOT EXISTS workaround via pragma)
-- NOTE: Only run these if upgrading from pre-v30 schema:
-- ALTER TABLE subscriptions ADD COLUMN processor TEXT;
-- ALTER TABLE subscriptions ADD COLUMN external_id TEXT;
-- ALTER TABLE subscriptions ADD COLUMN price_inr INTEGER DEFAULT 0;

-- ── 4. API Keys Table ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  key_id      TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  tier        TEXT NOT NULL DEFAULT 'COMMUNITY',
  active      INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  label       TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_used   TEXT
);

-- ── 5. Platform Metrics Cache Table ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS platform_metrics (
  key         TEXT PRIMARY KEY,
  value_int   INTEGER,
  value_text  TEXT,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed metric keys (0 values — real data populated by background hydration)
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES
  ('total_scans',      0),
  ('total_cves',       0),
  ('total_customers',  0),
  ('scans_today',      0),
  ('critical_threats', 0),
  ('revenue_today',    0),
  ('revenue_month',    0);

-- ── 6. Trust Metrics Cache Table ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_metrics_cache (
  id          TEXT PRIMARY KEY DEFAULT 'singleton',
  uptime_pct  REAL NOT NULL DEFAULT 99.9,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO trust_metrics_cache (id, uptime_pct) VALUES ('singleton', 99.9);

-- ── 7. Scan Token Audit Log (optional but recommended for abuse analysis) ────
CREATE TABLE IF NOT EXISTS scan_token_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce       TEXT NOT NULL,
  ip_hash     TEXT NOT NULL,
  issued_at   TEXT NOT NULL,
  used_at     TEXT,
  status      TEXT NOT NULL DEFAULT 'issued'
                CHECK(status IN ('issued','consumed','expired','rejected')),
  reject_reason TEXT
);

-- ── 8. Indexes (DROP + CREATE — D1 does not support IF NOT EXISTS) ───────────
DROP INDEX IF EXISTS idx_p0_exceptions_entry_id;
CREATE INDEX idx_p0_exceptions_entry_id ON p0_exceptions(entry_id);

DROP INDEX IF EXISTS idx_p0_exceptions_logged_at;
CREATE INDEX idx_p0_exceptions_logged_at ON p0_exceptions(logged_at);

DROP INDEX IF EXISTS idx_subscriptions_email;
CREATE INDEX idx_subscriptions_email ON subscriptions(email);

DROP INDEX IF EXISTS idx_subscriptions_status;
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

DROP INDEX IF EXISTS idx_api_keys_email;
CREATE INDEX idx_api_keys_email ON api_keys(email);

DROP INDEX IF EXISTS idx_api_keys_tier;
CREATE INDEX idx_api_keys_tier ON api_keys(tier);

DROP INDEX IF EXISTS idx_scan_token_audit_nonce;
CREATE INDEX idx_scan_token_audit_nonce ON scan_token_audit(nonce);

DROP INDEX IF EXISTS idx_scan_token_audit_ip_hash;
CREATE INDEX idx_scan_token_audit_ip_hash ON scan_token_audit(ip_hash);

-- ============================================================================
-- END OF MIGRATION v30.0
-- ============================================================================
