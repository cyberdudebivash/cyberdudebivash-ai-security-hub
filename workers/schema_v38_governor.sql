-- ─── CYBERDUDEBIVASH Schema v38 — MYTHOS Platform Governor ─────────────────
-- Creates governor_events audit table for Platform Governor Phase C

CREATE TABLE IF NOT EXISTS governor_events (
  id           TEXT PRIMARY KEY,
  subsystem    TEXT NOT NULL,
  status       TEXT NOT NULL,  -- HEALTHY | DEGRADED | CRITICAL | STALLED | REPAIRED | DRIFTED
  action       TEXT,           -- repair action taken (if any)
  detail       TEXT,           -- JSON or text details
  duration_ms  INTEGER DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_governor_events_subsystem   ON governor_events (subsystem);
CREATE INDEX IF NOT EXISTS idx_governor_events_status      ON governor_events (status);
CREATE INDEX IF NOT EXISTS idx_governor_events_created_at  ON governor_events (created_at);
