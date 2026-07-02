-- v48 — Detection rule generation history (Phase 4, Workstream A)
-- Persists every authenticated SOAR rule generation (POST /api/ai/generate-rules)
-- so customers can revisit, re-download, and track versions of generated rules.
-- The handler also creates this table lazily (CREATE TABLE IF NOT EXISTS) so the
-- feature works immediately after deploy; this file is the canonical record.

CREATE TABLE IF NOT EXISTS generated_rules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  platform TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  rules_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_generated_rules_user ON generated_rules(user_id, created_at DESC);
