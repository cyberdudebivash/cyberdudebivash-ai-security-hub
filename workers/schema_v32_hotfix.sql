-- ============================================================================
-- CYBERDUDEBIVASH — Schema v32 Hotfix
-- Fixes: mythos_runs table exists on live DB but is missing trigger_source
--        column (table was created by an earlier manual migration without it).
--
-- DEPLOY:
--   cd workers
--   npx wrangler d1 execute cyberdudebivash-security-hub ^
--     --file=schema_v32_hotfix.sql --remote
--
-- SAFE: ALTER TABLE ADD COLUMN with DEFAULT is always safe on existing rows.
--       INSERT OR IGNORE skips if seed row already exists.
-- ============================================================================

-- ── Step 1: Add missing column to existing table ───────────────────────────
-- SQLite allows ADD COLUMN with a DEFAULT even for NOT NULL columns.
-- This is safe to run — existing rows get DEFAULT value 'cron'.
ALTER TABLE mythos_runs ADD COLUMN trigger_source TEXT NOT NULL DEFAULT 'cron';

-- ── Step 2: Seed row — explicit column list avoids trigger_source ambiguity ─
INSERT OR IGNORE INTO mythos_runs
  (id, status, tools_generated, tools_published, tools_failed,
   duration_ms, intel_count, run_at)
VALUES
  ('mythos-seed-v32', 'completed', 0, 0, 0, 0, 0,
   '2026-01-01T00:00:00.000Z');

-- ============================================================================
-- END
-- ============================================================================
