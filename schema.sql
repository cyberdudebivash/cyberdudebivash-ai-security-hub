-- USERS
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- API KEYS
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  tier TEXT DEFAULT 'free',
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- SCANS
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  risk_score INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- LOGIN ATTEMPTS (BRUTE FORCE PROTECTION)
CREATE TABLE IF NOT EXISTS login_attempts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  attempt_time INTEGER NOT NULL
);

-- INDEXES (CRITICAL FOR PERFORMANCE)
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);


-- ══════════════════════════════════════════════════════════════════════
-- MYTHOS ORCHESTRATOR — Run Audit Log
-- Added v31: tracks every autonomous tool-generation run
-- ══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mythos_runs (
  id               TEXT    PRIMARY KEY,                         -- job_XXXXXXXX_XXXXXX
  status           TEXT    NOT NULL DEFAULT 'PENDING',          -- RUNNING | COMPLETE | FAILED
  tools_generated  INTEGER NOT NULL DEFAULT 0,
  tools_published  INTEGER NOT NULL DEFAULT 0,
  tools_failed     INTEGER NOT NULL DEFAULT 0,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  intel_count      INTEGER NOT NULL DEFAULT 0,
  run_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mythos_runs_run_at ON mythos_runs(run_at DESC);
CREATE INDEX IF NOT EXISTS idx_mythos_runs_status  ON mythos_runs(status);
