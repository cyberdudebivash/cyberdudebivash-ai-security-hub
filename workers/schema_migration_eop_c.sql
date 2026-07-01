-- EOP v1.0 Part C: maintenance_windows + ops_alert_log
-- Note: alert_log already exists (user notification logs). This is the
-- SEPARATE ops_alert_log table for operational alert dedup history.
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
CREATE INDEX IF NOT EXISTS idx_maint_start ON maintenance_windows(scheduled_start);

CREATE TABLE IF NOT EXISTS ops_alert_log (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  alert_type  TEXT NOT NULL,
  component   TEXT NOT NULL,
  message     TEXT,
  sent_via    TEXT NOT NULL DEFAULT 'telegram',
  sent_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ops_alert_log_sent ON ops_alert_log(sent_at);
CREATE INDEX IF NOT EXISTS idx_ops_alert_log_type ON ops_alert_log(alert_type, component);
