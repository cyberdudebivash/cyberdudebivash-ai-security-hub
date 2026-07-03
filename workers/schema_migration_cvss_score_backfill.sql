-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Canonical CVSS backfill
-- ----------------------------------------------------------------------------
-- Business-truth fix: the primary threat-intel ingestion path (threatIngestion.js)
-- writes the CVSS score to `cvss`, but the CANONICAL column — the one 60+ readers
-- query (critical/high counts, risk sorting, the public feed, the frontend) and
-- the one indexed as idx_ti_cvss(cvss_score DESC) — is `cvss_score`. Existing rows
-- therefore have cvss populated but cvss_score NULL, so every CVSS-based metric
-- read NULL and silently returned 0.
--
-- The ingestion path now self-heals this on every cycle; this migration performs
-- the same backfill immediately against the live database so the fix does not
-- have to wait for the next ingestion cron.
--
-- Run once (idempotent — safe to re-run):
--   cd workers && npx wrangler d1 execute cyberdudebivash-security-hub --remote \
--     --file=./schema_migration_cvss_score_backfill.sql
-- ============================================================================

UPDATE threat_intel
   SET cvss_score = cvss
 WHERE cvss_score IS NULL
   AND cvss IS NOT NULL;

-- Canonical cve_id backfill: this ingestion path writes the CVE to the primary
-- key `id`, leaving the canonical `cve_id` column NULL. Readers keyed on cve_id
-- (single-CVE lookups, the vulnerability list identifiers) saw null.
UPDATE threat_intel
   SET cve_id = id
 WHERE (cve_id IS NULL OR cve_id = '')
   AND id LIKE 'CVE-%';

-- Verify (optional): both should report 0 remaining out-of-sync.
-- SELECT COUNT(*) AS cvss_null FROM threat_intel WHERE cvss_score IS NULL AND cvss IS NOT NULL;
-- SELECT COUNT(*) AS cveid_null FROM threat_intel WHERE (cve_id IS NULL OR cve_id='') AND id LIKE 'CVE-%';
