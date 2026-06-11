-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Targeted Migration v32
-- PURPOSE: Add ONLY new objects introduced in this release.
--          No ALTER TABLE — uses only columns that already exist.
--          Safe to run against the live remote DB multiple times.
-- ============================================================

-- ─── 1. platform_health_checks (Task #13 — 6h automated tests) ───────────────
CREATE TABLE IF NOT EXISTS platform_health_checks (
  id              TEXT    PRIMARY KEY,
  overall_status  TEXT    NOT NULL DEFAULT 'UNKNOWN',
  passing         INTEGER NOT NULL DEFAULT 0,
  failing         INTEGER NOT NULL DEFAULT 0,
  duration_ms     INTEGER,
  results_json    TEXT,
  checked_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_health_checks_time   ON platform_health_checks(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_health_checks_status ON platform_health_checks(overall_status);

-- ─── 2. platform_metrics seed rows ───────────────────────────────────────────
--    INSERT OR IGNORE — no-op if row already exists
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('total_scans',      0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('total_cves',       0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('scans_today',      0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('critical_threats', 0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('revenue_today',    0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('revenue_month',    0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('kev_count',        0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('soar_rules_total', 0);
INSERT OR IGNORE INTO platform_metrics (key, value_int) VALUES ('total_customers',  0);
