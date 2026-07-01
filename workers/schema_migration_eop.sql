-- EOP v1.0 — Enterprise Observability & Operations Platform
-- Applied live to production D1 via: npx wrangler d1 execute SECURITY_HUB_DB --remote --file=schema_migration_eop.sql

-- ── incidents: full lifecycle incident management ────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  title             TEXT NOT NULL,
  description       TEXT,
  severity          TEXT NOT NULL DEFAULT 'minor'
                      CHECK(severity IN ('critical','major','minor','maintenance')),
  status            TEXT NOT NULL DEFAULT 'investigating'
                      CHECK(status IN ('open','investigating','identified','monitoring','resolved')),
  affected_services TEXT NOT NULL DEFAULT '[]',
  root_cause        TEXT,
  resolution        TEXT,
  customer_message  TEXT,
  deployment_id     TEXT,
  started_at        TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at       TEXT,
  created_by        TEXT NOT NULL DEFAULT 'system',
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_started ON incidents(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, started_at DESC);

-- ── incident_timeline: ordered updates per incident ──────────────────────────
CREATE TABLE IF NOT EXISTS incident_timeline (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  incident_id TEXT NOT NULL,
  status      TEXT NOT NULL,
  message     TEXT NOT NULL,
  created_by  TEXT NOT NULL DEFAULT 'system',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_inc_timeline_incident ON incident_timeline(incident_id, created_at ASC);

-- ── deployments: deployment record with correlation to incidents ─────────────
CREATE TABLE IF NOT EXISTS deployments (
  id              TEXT PRIMARY KEY,
  version         TEXT NOT NULL,
  commit_sha      TEXT,
  commit_message  TEXT,
  deployed_by     TEXT NOT NULL DEFAULT 'ci',
  status          TEXT NOT NULL DEFAULT 'success'
                    CHECK(status IN ('deploying','success','failed','rolled_back')),
  duration_ms     INTEGER,
  test_count      INTEGER,
  deployed_at     TEXT NOT NULL DEFAULT (datetime('now')),
  notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_deployments_deployed ON deployments(deployed_at DESC);

-- ── operational_history: richer per-check snapshots for uptime engine ────────
-- Complements uptime_log (which the existing cron writes to). This table
-- captures multi-component checks with version/deployment correlation.
CREATE TABLE IF NOT EXISTS operational_history (
  id            TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  component     TEXT NOT NULL,
  status        TEXT NOT NULL CHECK(status IN ('operational','degraded','partial_outage','major_outage')),
  latency_ms    INTEGER DEFAULT 0,
  version       TEXT,
  deployment_id TEXT,
  error_detail  TEXT,
  checked_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ophist_component ON operational_history(component, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_ophist_checked   ON operational_history(checked_at DESC);

-- ── maintenance_windows: scheduled maintenance communication ─────────────────
CREATE TABLE IF NOT EXISTS maintenance_windows (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  title             TEXT NOT NULL,
  description       TEXT,
  affected_services TEXT NOT NULL DEFAULT '[]',
  scheduled_start   TEXT NOT NULL,
  scheduled_end     TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'scheduled'
                      CHECK(status IN ('scheduled','in_progress','completed','cancelled')),
  created_by        TEXT NOT NULL DEFAULT 'system',
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_maint_start ON maintenance_windows(scheduled_start DESC);

-- ── alert_log: rate-limit / dedup history for the alert engine ───────────────
CREATE TABLE IF NOT EXISTS alert_log (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  alert_type  TEXT NOT NULL,
  component   TEXT NOT NULL,
  message     TEXT,
  sent_via    TEXT NOT NULL DEFAULT 'telegram',
  sent_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alert_log_type ON alert_log(alert_type, component, sent_at DESC);
