-- EBOC-1 follow-up (H-3): operator error-visibility table, applied live.
CREATE TABLE IF NOT EXISTS system_errors (
  id          TEXT PRIMARY KEY,
  area        TEXT NOT NULL,
  message     TEXT,
  context     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_system_errors_created ON system_errors(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_errors_area ON system_errors(area);
