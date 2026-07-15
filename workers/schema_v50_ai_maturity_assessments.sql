-- CYBERDUDEBIVASH® AI Security Hub
-- v50 — AI Security Maturity Assessment: orchestration + persistence tables (safe, additive, IF NOT EXISTS)
-- Apply: wrangler d1 execute cyberdudebivash-security-hub --remote --file schema_v50_ai_maturity_assessments.sql
--
-- Backs the ai-maturity-assessment feature (ESSP Wave 1, PR 1 — backend orchestration only,
-- no frontend yet). This wave wires only the AI Security Scorecard engine
-- (workers/src/handlers/aiSecurityScorecardHandler.js's generateScorecard). framework_scores_json
-- ships empty ('{}') until the NIST AI RMF / ISO27001 / GDPR / DevSecOps engines are wired in
-- their own follow-up PRs — do not assume that column is populated yet.

CREATE TABLE IF NOT EXISTS ai_maturity_assessments (
  id                     TEXT PRIMARY KEY,
  org_id                 TEXT NOT NULL,
  requested_by           TEXT NOT NULL,
  target_scope           TEXT NOT NULL,
  composite_score        INTEGER NOT NULL,
  maturity_level         TEXT NOT NULL,
  scorecard_json         TEXT NOT NULL DEFAULT '{}',
  framework_scores_json  TEXT NOT NULL DEFAULT '{}',
  status                 TEXT NOT NULL DEFAULT 'completed' CHECK(status IN ('pending','completed','failed')),
  created_at             TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_assessments_org     ON ai_maturity_assessments(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_assessments_created ON ai_maturity_assessments(created_at DESC);

CREATE TABLE IF NOT EXISTS ai_maturity_score_history (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  assessment_id   TEXT NOT NULL,
  composite_score INTEGER NOT NULL,
  maturity_level  TEXT NOT NULL,
  recorded_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_score_history_org        ON ai_maturity_score_history(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_score_history_assessment ON ai_maturity_score_history(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_score_history_recorded   ON ai_maturity_score_history(recorded_at DESC);

-- Not written by this PR (no wired engine produces roadmap items yet) — created now
-- so the follow-up PRs that wire the NIST/ISO/DevSecOps engines don't each need their
-- own migration just for this table. Empty and harmless until then.
CREATE TABLE IF NOT EXISTS ai_maturity_roadmap_items (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  assessment_id  TEXT NOT NULL,
  framework      TEXT NOT NULL,
  priority       TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(priority IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  title          TEXT NOT NULL,
  description    TEXT,
  status         TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','IN_PROGRESS','DONE','DISMISSED')),
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_roadmap_items_org        ON ai_maturity_roadmap_items(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_roadmap_items_assessment ON ai_maturity_roadmap_items(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ai_maturity_roadmap_items_status     ON ai_maturity_roadmap_items(status);
