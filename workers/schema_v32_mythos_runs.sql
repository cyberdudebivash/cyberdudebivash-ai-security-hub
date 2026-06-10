-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema Migration v32.0
-- MYTHOS Runs Table: required by mythosOrchestrator.js INSERT operations
--
-- ROOT CAUSE: mythosOrchestrator.js runs INSERT INTO mythos_runs on every
-- MYTHOS pipeline execution, but this table was never created in any prior
-- schema file. This causes MYTHOS runs to fail silently (DB error swallowed
-- in orchestrator try/catch, but metrics never persist).
--
-- DEPLOY (remote live DB):
--   cd workers
--   npx wrangler d1 execute cyberdudebivash-security-hub ^
--     --file=schema_v32_mythos_runs.sql --remote
--
-- DEPLOY (local preview):
--   npx wrangler d1 execute cyberdudebivash-security-hub ^
--     --file=schema_v32_mythos_runs.sql --local
--
-- SAFE: uses IF NOT EXISTS — idempotent, safe to re-run
-- ============================================================================

-- ── mythos_runs — MYTHOS AI orchestration run log ─────────────────────────
-- Populated by mythosOrchestrator.js after each 12-stage pipeline execution.
-- Used by handleMythosMetrics to calculate total_runs / tools_generated etc.
CREATE TABLE IF NOT EXISTS mythos_runs (
  id               TEXT    PRIMARY KEY,
  status           TEXT    NOT NULL DEFAULT 'completed'
                             CHECK(status IN ('running','completed','failed','partial')),
  tools_generated  INTEGER NOT NULL DEFAULT 0,
  tools_published  INTEGER NOT NULL DEFAULT 0,
  tools_failed     INTEGER NOT NULL DEFAULT 0,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  intel_count      INTEGER NOT NULL DEFAULT 0,
  trigger_source   TEXT    NOT NULL DEFAULT 'cron',  -- 'cron'|'manual_admin'|'ui-p13'
  error_message    TEXT,
  run_at           TEXT    NOT NULL DEFAULT (datetime('now'))  -- ISO-8601 from new Date().toISOString()
);

DROP INDEX IF EXISTS idx_mythos_runs_run_at;
CREATE INDEX idx_mythos_runs_run_at ON mythos_runs(run_at);

DROP INDEX IF EXISTS idx_mythos_runs_status;
CREATE INDEX idx_mythos_runs_status ON mythos_runs(status);

-- ── Seed: insert a placeholder row so metrics API never returns 0 ──────────
-- Represents the platform's inception state; real rows accumulate from cron.
INSERT OR IGNORE INTO mythos_runs
  (id, status, tools_generated, tools_published, tools_failed,
   duration_ms, intel_count, trigger_source, run_at)
VALUES
  ('mythos-seed-v32', 'completed', 0, 0, 0, 0, 0, 'seed',
   '2026-01-01T00:00:00.000Z');

-- ============================================================================
-- END OF MIGRATION v32.0
-- ============================================================================
