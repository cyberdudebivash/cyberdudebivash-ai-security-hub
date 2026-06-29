-- CYBERDUDEBIVASH® AI Security Hub
-- v46 — Missing tables migration (safe, additive, IF NOT EXISTS)
-- Apply: wrangler d1 execute cyberdudebivash-security-hub --remote --file schema_v46_missing_tables.sql

-- ── scan_results (referenced by 10+ handlers, never created) ─────────────────
CREATE TABLE IF NOT EXISTS scan_results (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL DEFAULT 'default',
  target       TEXT NOT NULL,
  scan_type    TEXT NOT NULL DEFAULT 'domain',
  severity     TEXT DEFAULT 'LOW' CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  score        INTEGER DEFAULT 0,
  findings_json TEXT DEFAULT '[]',
  modules_json  TEXT DEFAULT '[]',
  status       TEXT DEFAULT 'completed' CHECK(status IN ('pending','running','completed','failed')),
  created_by   TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_results_org      ON scan_results(org_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_target   ON scan_results(target);
CREATE INDEX IF NOT EXISTS idx_scan_results_severity ON scan_results(severity);
CREATE INDEX IF NOT EXISTS idx_scan_results_created  ON scan_results(created_at DESC);

-- ── customer_health ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_health (
  id                 TEXT PRIMARY KEY,
  org_id             TEXT UNIQUE NOT NULL DEFAULT 'default',
  health_score       INTEGER DEFAULT 50,
  adoption_score     INTEGER DEFAULT 0,
  churn_risk         TEXT DEFAULT 'NONE',
  expansion_score    INTEGER DEFAULT 0,
  maturity_index     TEXT DEFAULT 'STARTER',
  last_scan_days_ago INTEGER DEFAULT 999,
  total_scans_30d    INTEGER DEFAULT 0,
  active_features    TEXT DEFAULT '[]',
  risk_triggers      TEXT DEFAULT '[]',
  playbook_id        TEXT,
  computed_at        TEXT NOT NULL DEFAULT (datetime('now')),
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_health_org   ON customer_health(org_id);
CREATE INDEX IF NOT EXISTS idx_health_churn ON customer_health(churn_risk);

-- ── workflows ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workflows (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  description   TEXT,
  trigger_type  TEXT NOT NULL,
  trigger_config TEXT DEFAULT '{}',
  steps_json    TEXT NOT NULL DEFAULT '[]',
  is_active     INTEGER DEFAULT 1,
  org_id        TEXT NOT NULL DEFAULT 'default',
  created_by    TEXT NOT NULL DEFAULT 'system',
  run_count     INTEGER DEFAULT 0,
  last_run_at   TEXT,
  is_template   INTEGER DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_workflows_org      ON workflows(org_id);
CREATE INDEX IF NOT EXISTS idx_workflows_active   ON workflows(is_active);
CREATE INDEX IF NOT EXISTS idx_workflows_template ON workflows(is_template);

-- ── workflow_executions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workflow_executions (
  id                   TEXT PRIMARY KEY,
  workflow_id          TEXT NOT NULL,
  status               TEXT DEFAULT 'RUNNING',
  triggered_by         TEXT DEFAULT 'manual',
  trigger_payload_json TEXT DEFAULT '{}',
  steps_log_json       TEXT DEFAULT '[]',
  error_message        TEXT,
  org_id               TEXT NOT NULL DEFAULT 'default',
  started_at           TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_executions_workflow ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_executions_org      ON workflow_executions(org_id);
CREATE INDEX IF NOT EXISTS idx_executions_started  ON workflow_executions(started_at DESC);

-- ── notification_log ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_log (
  id                 TEXT PRIMARY KEY,
  recipient_id       TEXT NOT NULL,
  org_id             TEXT DEFAULT 'default',
  channel            TEXT NOT NULL,
  event_type         TEXT NOT NULL,
  subject            TEXT,
  body_preview       TEXT,
  status             TEXT DEFAULT 'PENDING',
  delivery_attempts  INTEGER DEFAULT 0,
  error_message      TEXT,
  sent_at            TEXT,
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notif_log_org     ON notification_log(org_id);
CREATE INDEX IF NOT EXISTS idx_notif_log_status  ON notification_log(status);
CREATE INDEX IF NOT EXISTS idx_notif_log_created ON notification_log(created_at DESC);

-- ── cti_actors ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cti_actors (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  aliases           TEXT DEFAULT '[]',
  nation_state      TEXT,
  motivation        TEXT,
  sophistication    TEXT DEFAULT 'MEDIUM',
  threat_level      TEXT DEFAULT 'MEDIUM',
  confidence_score  INTEGER DEFAULT 50,
  target_sectors    TEXT DEFAULT '[]',
  known_techniques  TEXT DEFAULT '[]',
  known_tools       TEXT DEFAULT '[]',
  mitre_group_id    TEXT,
  description       TEXT,
  last_active       TEXT,
  source            TEXT DEFAULT 'user',
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_actors_threat  ON cti_actors(threat_level);
CREATE INDEX IF NOT EXISTS idx_actors_nation  ON cti_actors(nation_state);
CREATE INDEX IF NOT EXISTS idx_actors_conf    ON cti_actors(confidence_score DESC);

-- ── cti_iocs ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cti_iocs (
  id                TEXT PRIMARY KEY,
  ioc_type          TEXT NOT NULL,
  value             TEXT NOT NULL,
  severity          TEXT DEFAULT 'MEDIUM',
  source            TEXT DEFAULT 'user_submitted',
  tags              TEXT DEFAULT '[]',
  related_actor_id  TEXT,
  related_campaign  TEXT,
  notes             TEXT,
  reputation_score  INTEGER DEFAULT 0,
  geo_country       TEXT,
  is_active         INTEGER DEFAULT 1,
  first_seen        TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen         TEXT NOT NULL DEFAULT (datetime('now')),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_type     ON cti_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON cti_iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_active   ON cti_iocs(is_active);
CREATE INDEX IF NOT EXISTS idx_iocs_actor    ON cti_iocs(related_actor_id);
CREATE INDEX IF NOT EXISTS idx_iocs_last     ON cti_iocs(last_seen DESC);

-- ── notification_preferences ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id               TEXT PRIMARY KEY,
  org_id                TEXT DEFAULT 'default',
  email_enabled         INTEGER DEFAULT 1,
  inapp_enabled         INTEGER DEFAULT 1,
  slack_webhook         TEXT,
  teams_webhook         TEXT,
  custom_webhook        TEXT,
  webhook_secret        TEXT,
  event_subscriptions   TEXT DEFAULT '[]',
  escalation_delay_min  INTEGER DEFAULT 30,
  quiet_hours_json      TEXT DEFAULT '{}',
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── report_jobs ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS report_jobs (
  id                  TEXT PRIMARY KEY,
  report_type         TEXT NOT NULL,
  format              TEXT DEFAULT 'HTML',
  status              TEXT DEFAULT 'QUEUED',
  org_id              TEXT NOT NULL DEFAULT 'default',
  created_by          TEXT NOT NULL DEFAULT 'system',
  config_json         TEXT DEFAULT '{}',
  output_r2_key       TEXT,
  download_token      TEXT,
  download_expires_at TEXT,
  scheduled_cron      TEXT,
  last_run_at         TEXT,
  delivered_to        TEXT DEFAULT '[]',
  error_message       TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_report_jobs_org    ON report_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_report_jobs_status ON report_jobs(status);

-- ── saved_searches ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saved_searches (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  org_id      TEXT NOT NULL DEFAULT 'default',
  name        TEXT NOT NULL,
  query       TEXT NOT NULL,
  facets_json TEXT DEFAULT '{}',
  entity_types TEXT DEFAULT '[]',
  hit_count   INTEGER DEFAULT 0,
  last_run_at TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_saved_searches_user ON saved_searches(user_id);
CREATE INDEX IF NOT EXISTS idx_saved_searches_org  ON saved_searches(org_id);

-- ── tenant_themes ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant_themes (
  org_id          TEXT PRIMARY KEY,
  brand_name      TEXT DEFAULT 'CYBERDUDEBIVASH',
  logo_url        TEXT,
  favicon_url     TEXT,
  primary_color   TEXT DEFAULT '#6366f1',
  secondary_color TEXT DEFAULT '#0ea5e9',
  accent_color    TEXT DEFAULT '#22c55e',
  custom_css      TEXT,
  custom_domain   TEXT,
  support_email   TEXT,
  support_url     TEXT,
  hide_powered_by INTEGER DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
