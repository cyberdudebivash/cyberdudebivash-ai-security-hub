-- CYBERDUDEBIVASH® AI Security Hub
-- Phase 3 Schema Migration — ADDITIVE ONLY
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./workers/schema_phase3.sql
-- Safe to run multiple times (CREATE TABLE IF NOT EXISTS)
-- Zero modifications to any existing tables.

-- ── Customer Health Scores ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_health (
  id                 TEXT PRIMARY KEY,
  org_id             TEXT UNIQUE NOT NULL DEFAULT 'default',
  health_score       INTEGER DEFAULT 50 CHECK(health_score BETWEEN 0 AND 100),
  adoption_score     INTEGER DEFAULT 0  CHECK(adoption_score BETWEEN 0 AND 100),
  churn_risk         TEXT DEFAULT 'NONE' CHECK(churn_risk IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  expansion_score    INTEGER DEFAULT 0  CHECK(expansion_score BETWEEN 0 AND 100),
  maturity_index     TEXT DEFAULT 'STARTER' CHECK(maturity_index IN ('STARTER','DEVELOPING','MATURE','CHAMPION')),
  last_scan_days_ago INTEGER DEFAULT 999,
  total_scans_30d    INTEGER DEFAULT 0,
  active_features    TEXT DEFAULT '[]',
  risk_triggers      TEXT DEFAULT '[]',
  playbook_id        TEXT,
  computed_at        TEXT NOT NULL DEFAULT (datetime('now')),
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_health_org        ON customer_health(org_id);
CREATE INDEX IF NOT EXISTS idx_health_churn      ON customer_health(churn_risk);
CREATE INDEX IF NOT EXISTS idx_health_score      ON customer_health(health_score DESC);
CREATE INDEX IF NOT EXISTS idx_health_computed   ON customer_health(computed_at DESC);

-- ── Report Jobs ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS report_jobs (
  id                  TEXT PRIMARY KEY,
  report_type         TEXT NOT NULL CHECK(report_type IN ('SECURITY_POSTURE','BOARD','MSSP','CTI','COMPLIANCE','AI_SECURITY')),
  format              TEXT DEFAULT 'HTML' CHECK(format IN ('HTML','PDF','JSON')),
  status              TEXT DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','GENERATING','READY','FAILED','DELIVERED')),
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

CREATE INDEX IF NOT EXISTS idx_reports_org      ON report_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_reports_status   ON report_jobs(status);
CREATE INDEX IF NOT EXISTS idx_reports_type     ON report_jobs(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_created  ON report_jobs(created_at DESC);

-- ── Saved Searches ────────────────────────────────────────────────────────────
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

CREATE INDEX IF NOT EXISTS idx_searches_user    ON saved_searches(user_id);
CREATE INDEX IF NOT EXISTS idx_searches_org     ON saved_searches(org_id);
CREATE INDEX IF NOT EXISTS idx_searches_created ON saved_searches(created_at DESC);

-- ── Workflow Definitions ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workflows (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  description       TEXT,
  trigger_type      TEXT NOT NULL CHECK(trigger_type IN ('SCAN_CRITICAL','CASE_CREATED','CASE_ESCALATED','HEALTH_CHURN','IOC_MATCH','MANUAL','SCHEDULE')),
  trigger_config    TEXT DEFAULT '{}',
  steps_json        TEXT NOT NULL DEFAULT '[]',
  is_active         INTEGER DEFAULT 1,
  org_id            TEXT NOT NULL DEFAULT 'default',
  created_by        TEXT NOT NULL DEFAULT 'system',
  run_count         INTEGER DEFAULT 0,
  last_run_at       TEXT,
  is_template       INTEGER DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_workflows_org       ON workflows(org_id);
CREATE INDEX IF NOT EXISTS idx_workflows_trigger   ON workflows(trigger_type);
CREATE INDEX IF NOT EXISTS idx_workflows_active    ON workflows(is_active);
CREATE INDEX IF NOT EXISTS idx_workflows_template  ON workflows(is_template);

-- ── Workflow Executions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workflow_executions (
  id                    TEXT PRIMARY KEY,
  workflow_id           TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  status                TEXT DEFAULT 'RUNNING' CHECK(status IN ('RUNNING','COMPLETED','FAILED','CANCELLED')),
  triggered_by          TEXT DEFAULT 'manual',
  trigger_payload_json  TEXT DEFAULT '{}',
  steps_log_json        TEXT DEFAULT '[]',
  error_message         TEXT,
  org_id                TEXT NOT NULL DEFAULT 'default',
  started_at            TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_executions_workflow ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_executions_status   ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_org      ON workflow_executions(org_id);
CREATE INDEX IF NOT EXISTS idx_executions_started  ON workflow_executions(started_at DESC);

-- ── Tenant Themes (White Label) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant_themes (
  org_id           TEXT PRIMARY KEY,
  brand_name       TEXT DEFAULT 'CYBERDUDEBIVASH®',
  logo_url         TEXT,
  favicon_url      TEXT,
  primary_color    TEXT DEFAULT '#6366f1',
  secondary_color  TEXT DEFAULT '#0ea5e9',
  accent_color     TEXT DEFAULT '#22c55e',
  custom_css       TEXT,
  custom_domain    TEXT,
  support_email    TEXT,
  support_url      TEXT,
  hide_powered_by  INTEGER DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_themes_domain ON tenant_themes(custom_domain);

-- ── Product Analytics Events ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analytics_events (
  id             TEXT PRIMARY KEY,
  event_type     TEXT NOT NULL,
  user_id        TEXT,
  org_id         TEXT DEFAULT 'default',
  tier           TEXT DEFAULT 'FREE',
  session_id     TEXT,
  properties_json TEXT DEFAULT '{}',
  ip_country     TEXT,
  occurred_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_type      ON analytics_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_user      ON analytics_events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_org       ON analytics_events(org_id);
CREATE INDEX IF NOT EXISTS idx_events_occurred  ON analytics_events(occurred_at DESC);

-- Auto-prune: managed via cron endpoint POST /api/analytics/p3/prune
-- Keeps last 90 days of events

-- ── Notification Preferences ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id               TEXT PRIMARY KEY,
  org_id                TEXT DEFAULT 'default',
  email_enabled         INTEGER DEFAULT 1,
  inapp_enabled         INTEGER DEFAULT 1,
  slack_webhook         TEXT,
  teams_webhook         TEXT,
  custom_webhook        TEXT,
  webhook_secret        TEXT,
  event_subscriptions   TEXT DEFAULT '["scan.critical","case.created","case.escalated","health.churn"]',
  escalation_delay_min  INTEGER DEFAULT 30,
  quiet_hours_json      TEXT DEFAULT '{}',
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notif_prefs_org ON notification_preferences(org_id);

-- ── Notification Log ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_log (
  id                  TEXT PRIMARY KEY,
  recipient_id        TEXT NOT NULL,
  org_id              TEXT DEFAULT 'default',
  channel             TEXT NOT NULL CHECK(channel IN ('EMAIL','INAPP','SLACK','TEAMS','WEBHOOK')),
  event_type          TEXT NOT NULL,
  subject             TEXT,
  body_preview        TEXT,
  status              TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING','SENT','FAILED','SKIPPED')),
  delivery_attempts   INTEGER DEFAULT 0,
  error_message       TEXT,
  sent_at             TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notif_log_recipient ON notification_log(recipient_id);
CREATE INDEX IF NOT EXISTS idx_notif_log_org       ON notification_log(org_id);
CREATE INDEX IF NOT EXISTS idx_notif_log_status    ON notification_log(status);
CREATE INDEX IF NOT EXISTS idx_notif_log_created   ON notification_log(created_at DESC);

-- Auto-prune: keeps last 30 days managed via cron
