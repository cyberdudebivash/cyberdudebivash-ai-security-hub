-- EOP v1.0 Part B: deployments + operational_history
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
CREATE INDEX IF NOT EXISTS idx_deployments_deployed ON deployments(deployed_at);

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
CREATE INDEX IF NOT EXISTS idx_ophist_component ON operational_history(component, checked_at);
CREATE INDEX IF NOT EXISTS idx_ophist_checked   ON operational_history(checked_at);
