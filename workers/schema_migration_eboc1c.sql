-- EBOC-1 follow-up: Trust Center tables referenced by platformEngine.js but
-- missing from production D1 (same schema-drift class as refunds/support_tickets/
-- system_errors). Combined with the de-fabrication fix to getTrustCenterData(),
-- which previously defaulted to fake 99.9% uptime and three invented testimonials
-- whenever these tables had no data (they always had no data, because the
-- tables didn't exist).

CREATE TABLE IF NOT EXISTS release_notes (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  version         TEXT NOT NULL,
  title           TEXT NOT NULL,
  type            TEXT NOT NULL DEFAULT 'feature' CHECK(type IN ('feature','fix','security','improvement','breaking')),
  description     TEXT NOT NULL,
  details         TEXT DEFAULT '[]',
  published_at    TEXT NOT NULL DEFAULT (datetime('now')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS testimonials (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  name            TEXT NOT NULL,
  title           TEXT,
  company         TEXT,
  avatar_initial  TEXT,
  quote           TEXT NOT NULL,
  rating          INTEGER NOT NULL DEFAULT 5,
  verified        INTEGER NOT NULL DEFAULT 0,
  featured        INTEGER NOT NULL DEFAULT 0,
  use_case        TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS uptime_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  service         TEXT NOT NULL DEFAULT 'api',
  status          TEXT NOT NULL DEFAULT 'operational' CHECK(status IN ('operational','degraded','partial_outage','major_outage')),
  latency_ms      INTEGER DEFAULT 0,
  checked_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_uptime_log_service_time ON uptime_log(service, checked_at DESC);
