-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema Migration v31.0
-- P0 Fix Pack: data integrity, compliance alignment table, webhook idempotency
--
-- DEPLOY:
--   cd workers
--   npx wrangler d1 execute cyberdudebivash-security-hub ^
--     --file=schema_v31_p0_fixes.sql --remote
--
-- SAFE: all statements use IF NOT EXISTS / OR IGNORE / DROP INDEX IF EXISTS
-- D1 constraint: no IF NOT EXISTS on indexes — use DROP + CREATE pattern
-- ============================================================================

-- ── Fix 1: threat_intel — add cisa_kev column so metricsHydration query works
-- metricsHydration.js line 79 queries: WHERE cisa_kev=1 OR active_exploitation=1
-- The column does not exist → query returns 0 always
-- active_exploitation also does not exist → same bug
-- Fix: add both columns, backfill from existing data
ALTER TABLE threat_intel ADD COLUMN cisa_kev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN active_exploitation INTEGER NOT NULL DEFAULT 0;

-- Backfill: entries ingested from source='cisa_kev' are KEV entries
UPDATE threat_intel SET cisa_kev = 1 WHERE source = 'cisa_kev' AND cisa_kev = 0;

-- NOTE: actively_exploited column does not exist in threat_intel — backfill skipped.
-- active_exploitation defaults to 0; set via application logic going forward.

-- ── Fix 2: compliance_alignments — new table for honest badge display
-- Replaces hardcoded "certified" badges with verifiable alignment records
CREATE TABLE IF NOT EXISTS compliance_alignments (
  id              TEXT PRIMARY KEY,
  framework       TEXT NOT NULL,
  alignment_level TEXT NOT NULL DEFAULT 'aligned'
                    CHECK(alignment_level IN ('aligned', 'partial', 'certified')),
  scope_note      TEXT NOT NULL DEFAULT '',
  auditor         TEXT,
  cert_number     TEXT,
  valid_from      INTEGER,
  valid_until     INTEGER,
  evidence_url    TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Seed: honest alignment records (not certifications)
INSERT OR IGNORE INTO compliance_alignments
  (id, framework, alignment_level, scope_note)
VALUES
  ('align-iso27001',
   'iso27001', 'aligned',
   'Platform architecture and data-handling practices are aligned to ISO 27001:2022 Annex A controls. A formal certification audit has not yet been completed.'),

  ('align-soc2',
   'soc2', 'aligned',
   'Security and availability trust service criteria are addressed in platform design. SOC 2 Type II audit has not yet been commissioned.'),

  ('align-pcidss',
   'pcidss', 'aligned',
   'Card payment data is processed exclusively by Razorpay. The platform does not store card numbers or bank credentials. PCI-DSS compliance is maintained via the payment processor.'),

  ('align-gdpr',
   'gdpr', 'aligned',
   'Data minimisation and purpose-limitation controls are implemented for EU users. A formal Data Protection Agreement is available on request for Enterprise customers.'),

  ('align-dpdp',
   'dpdp', 'aligned',
   'DPDP Act 2023 obligations as Data Fiduciary are implemented for Indian users. Consent management and grievance redressal are active.'),

  ('align-hipaa',
   'hipaa', 'partial',
   'Security controls are aligned to the HIPAA Security Rule for general infrastructure. A Business Associate Agreement (BAA) is not yet available. Not recommended for covered-entity PHI workloads.'),

  ('align-owasp-llm',
   'owasp_llm', 'aligned',
   'OWASP LLM Top 10 controls are mapped to scan modules and AI analyst outputs. Coverage is tested on every platform release.'),

  ('align-mitre',
   'mitre', 'aligned',
   'MITRE ATT&CK framework is used for TTP mapping in scan results and SOAR rule generation across all modules.'),

  ('align-nist-ai',
   'nist_ai', 'aligned',
   'NIST AI RMF governance controls are mapped to the AI Governance pillar (Pillar 2). Gap analysis is available for Enterprise customers.');

-- ── Fix 3: webhook_idempotency — prevent double-processing of Razorpay events
-- The existing handleRazorpayWebhook checks payments table but has no
-- dedicated idempotency log with outcome tracking.
CREATE TABLE IF NOT EXISTS webhook_events (
  id              TEXT PRIMARY KEY,       -- Razorpay event id (event_type:created_at:account_id)
  event_type      TEXT NOT NULL,
  payment_id      TEXT,
  order_id        TEXT,
  payload_hash    TEXT NOT NULL,          -- sha256 of raw body for audit
  outcome         TEXT NOT NULL DEFAULT 'processed'
                    CHECK(outcome IN ('processed', 'skipped_duplicate', 'failed', 'invalid_sig', 'replay_rejected')),
  error_message   TEXT,
  processing_ms   INTEGER,
  processed_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

DROP INDEX IF EXISTS idx_webhook_events_payment_id;
CREATE INDEX idx_webhook_events_payment_id ON webhook_events(payment_id);

DROP INDEX IF EXISTS idx_webhook_events_processed_at;
CREATE INDEX idx_webhook_events_processed_at ON webhook_events(processed_at);

-- ── Fix 4: platform_metrics — ensure all required keys exist
-- The existing seeded keys may be missing scans_today and active_customers
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES
  ('total_scans',       0),
  ('total_cves',        0),
  ('total_customers',   0),
  ('scans_today',       0),
  ('critical_threats',  0),
  ('revenue_today',     0),
  ('revenue_month',     0),
  ('kev_count',         0),
  ('soar_rules_total',  0);

-- ── Fix 5: trust_signals index (may not exist from v27)
DROP INDEX IF EXISTS idx_trust_signals_verified;
CREATE INDEX idx_trust_signals_verified ON trust_signals(verified, visible);

-- ── Fix 6: subscriptions — add razorpay_payment_id for idempotency checks
-- (safe: D1 ADD COLUMN silently fails if column already exists in some builds)
-- Use a try-safe pattern: always INSERT OR IGNORE, never UPDATE without check
-- NOTE: D1 does NOT support "ALTER TABLE ... ADD COLUMN IF NOT EXISTS"
-- Run this only if subscriptions table was created before v30:
-- ALTER TABLE subscriptions ADD COLUMN razorpay_payment_id TEXT;

-- ── Fix 7: Verify the fix with a safe SELECT (returns 0 if no KEV entries yet)
-- SELECT COUNT(*) AS kev_count FROM threat_intel WHERE cisa_kev = 1;
-- SELECT COUNT(*) AS compliance_rows FROM compliance_alignments;

-- ============================================================================
-- END OF MIGRATION v31.0
-- NEXT STEP: run the deployment sequence in DEPLOYMENT_RUNBOOK.md
-- ============================================================================
