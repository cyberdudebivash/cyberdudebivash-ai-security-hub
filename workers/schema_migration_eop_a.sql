-- EOP v1.0 Part A: incidents + timeline
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
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_started  ON incidents(started_at);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, started_at);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  incident_id TEXT NOT NULL,
  status      TEXT NOT NULL,
  message     TEXT NOT NULL,
  created_by  TEXT NOT NULL DEFAULT 'system',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_inc_timeline_incident ON incident_timeline(incident_id, created_at);
