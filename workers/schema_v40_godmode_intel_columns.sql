-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema Migration v40.0
-- threat_intel: add the two columns required by the MYTHOS GOD MODE phase-1 query
--
-- ROOT CAUSE (verified against live D1 2026-06-15):
--   The live `threat_intel` table has 47 CRITICAL/HIGH rows and every writer +
--   reader column EXCEPT `threat_class` and `solution_generated`.
--   mythosGodMode.js phase1_intelSweep() runs:
--       SELECT ..., threat_class, ... FROM threat_intel
--        WHERE severity IN ('CRITICAL','HIGH')
--          AND (solution_generated = 0 OR solution_generated IS NULL)
--   Both columns are absent -> the SELECT throws "no such column: threat_class",
--   phase-1 returns ERROR, and God Mode reports "no_intel" — so the God Mode
--   dashboard (CISO / compliance / ASPM) renders empty despite 47 real CVEs.
--
-- FIX: additive ADD COLUMN only. Cannot break any existing reader or writer.
-- APPLY: each statement is independent; the schema_migrate CI job runs every
--   ALTER with `|| true`, so a re-run on an already-migrated DB is a safe no-op.
-- ============================================================================

-- ── threat_class: coarse category used by God Mode (category fallback) and
--    mythosRevenueEngine. NULL is tolerated by readers; default backfilled below.
ALTER TABLE threat_intel ADD COLUMN threat_class TEXT;

-- ── solution_generated: 0/1 flag — set to 1 by God Mode phase-3 once a defense
--    tool/solution has been generated for the CVE, so the phase-1 backlog query
--    advances to the next batch instead of reprocessing the same top-N.
ALTER TABLE threat_intel ADD COLUMN solution_generated INTEGER DEFAULT 0;

-- ── Backfill: give existing rows a sane category + an explicit unsolved flag ──
UPDATE threat_intel SET threat_class = 'vulnerability' WHERE threat_class IS NULL;
UPDATE threat_intel SET solution_generated = 0 WHERE solution_generated IS NULL;

-- ── Index: speeds the phase-1 backlog scan (severity + unsolved) ─────────────
CREATE INDEX IF NOT EXISTS idx_threat_intel_sev_solgen
  ON threat_intel(severity, solution_generated);

-- ── Verification (run after apply) ───────────────────────────────────────────
--   SELECT COUNT(*) FROM pragma_table_info('threat_intel')
--    WHERE name IN ('threat_class','solution_generated');   -- expect 2
--   Then trigger God Mode and confirm phase-1 returns the 47 CVEs:
--   curl -X POST https://cyberdudebivash.in/api/mythos/god-mode/run -H "x-api-key: $ADMIN_KEY"
-- ============================================================================
-- END: schema_v40_godmode_intel_columns.sql
-- ============================================================================
