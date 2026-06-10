-- ============================================================================
-- CYBERDUDEBIVASH — Schema v33.0 (MYTHOS God Mode v4.0)
-- Adds: mythos_god_mode_runs, revenue_opportunities metric key,
--       soar_rules_total and kev_count metric keys (safe re-seed)
--
-- DEPLOY:
--   cd workers
--   npx wrangler d1 execute cyberdudebivash-security-hub ^
--     --file=schema_v33_mythos_god_mode.sql --remote
--
-- SAFE: all IF NOT EXISTS / OR IGNORE — zero risk on live DB
-- ============================================================================

-- ── 1. God Mode run audit table ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mythos_god_mode_runs (
  id               TEXT PRIMARY KEY,
  status           TEXT NOT NULL DEFAULT 'RUNNING',
  trigger_source   TEXT NOT NULL DEFAULT 'cron',   -- cron | api | manual
  phases_complete  INTEGER NOT NULL DEFAULT 0,
  phases_errored   INTEGER NOT NULL DEFAULT 0,
  intel_processed  INTEGER NOT NULL DEFAULT 0,
  tools_generated  INTEGER NOT NULL DEFAULT 0,
  tools_published  INTEGER NOT NULL DEFAULT 0,
  threat_level     TEXT    NOT NULL DEFAULT 'MODERATE',
  posture_score    INTEGER NOT NULL DEFAULT 0,
  posture_grade    TEXT    NOT NULL DEFAULT 'N/A',
  mitre_ttps       INTEGER NOT NULL DEFAULT 0,
  hunt_sessions    INTEGER NOT NULL DEFAULT 0,
  zt_anomalies     INTEGER NOT NULL DEFAULT 0,
  compliance_risk  INTEGER NOT NULL DEFAULT 0,
  soar_rules       INTEGER NOT NULL DEFAULT 0,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  run_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_god_mode_runs_at     ON mythos_god_mode_runs(run_at);
CREATE INDEX IF NOT EXISTS idx_god_mode_runs_status ON mythos_god_mode_runs(status);

-- ── 2. Platform metrics — ensure all required keys exist ─────────────────────
-- These are idempotent — INSERT OR IGNORE skips if key already present.
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('soar_rules_total',      0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('kev_count',             0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('revenue_opportunities', 0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('god_mode_runs',         0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('hunt_sessions_total',   0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('zt_anomalies_total',    0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('compliance_gaps_total', 0);

-- ── 3. Seed platform AI asset (platform itself) for ASPM baseline ────────────
INSERT OR IGNORE INTO ai_assets
  (id, name, asset_type, provider, deployment, exposure, risk_score, security_score,
   status, owner_email, tags, created_at, updated_at, metadata)
VALUES
  ('asset-platform-api',
   'CYBERDUDEBIVASH API Engine',
   'api',
   'custom',
   'cloud',
   'public',
   15,
   85,
   'active',
   'bivash@cyberdudebivash.com',
   '["core","platform","api"]',
   unixepoch(), unixepoch(),
   '{"description":"Core API Worker on Cloudflare","region":"APAC","framework":"Cloudflare Workers"}'),

  ('asset-mythos-engine',
   'MYTHOS AI Orchestrator',
   'agent',
   'custom',
   'cloud',
   'internal',
   10,
   90,
   'active',
   'bivash@cyberdudebivash.com',
   '["ai","orchestrator","mythos"]',
   unixepoch(), unixepoch(),
   '{"description":"MYTHOS God Mode v4.0 autonomous AI engine","version":"4.0"}'),

  ('asset-sentinel-apex',
   'Sentinel APEX Threat Feed',
   'pipeline',
   'custom',
   'cloud',
   'internal',
   8,
   92,
   'active',
   'bivash@cyberdudebivash.com',
   '["intel","sentinel","feed"]',
   unixepoch(), unixepoch(),
   '{"description":"Threat intelligence ingestion and aggregation pipeline"}'),

  ('asset-cyber-brain-v3',
   'Cyber Brain Analysis Engine',
   'model',
   'custom',
   'cloud',
   'internal',
   12,
   88,
   'active',
   'bivash@cyberdudebivash.com',
   '["ai","analysis","brain"]',
   unixepoch(), unixepoch(),
   '{"description":"AI-powered cyber risk scoring and attack path prediction","version":"3.0"}');

-- ============================================================================
-- END OF MIGRATION v33.0
-- ============================================================================
