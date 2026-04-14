-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — v21.0 Adaptive CyberBrain
-- D1 Schema Migration — Adaptive Brain Engine Tables
-- ============================================================
-- Run with:
--   npx wrangler d1 execute cyberdudebivash-security-hub \
--     --file=./schema_v21_adaptive_brain.sql --remote
-- ============================================================

-- ── Table: brain_feedback ─────────────────────────────────────
-- Stores per-user feedback signals for adaptive learning
CREATE TABLE IF NOT EXISTS brain_feedback (
  id               INTEGER  PRIMARY KEY AUTOINCREMENT,
  user_id          TEXT     NOT NULL,
  scan_id          TEXT     NOT NULL,
  finding_id       TEXT     NOT NULL,
  severity         TEXT     NOT NULL DEFAULT 'MEDIUM',
  action           TEXT     NOT NULL,
  weight_delta     REAL     NOT NULL DEFAULT 0,
  cvss_score       REAL     DEFAULT 0,
  epss_score       REAL     DEFAULT 0,
  is_kev           INTEGER  NOT NULL DEFAULT 0,
  sector           TEXT     NOT NULL DEFAULT 'technology',
  tier             TEXT     NOT NULL DEFAULT 'FREE',
  created_at       TEXT     NOT NULL DEFAULT (datetime('now')),
  CONSTRAINT chk_bf_severity CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  CONSTRAINT chk_bf_action   CHECK (action   IN ('ignored','fixed','escalated','false_positive')),
  CONSTRAINT chk_bf_tier     CHECK (tier     IN ('FREE','STARTER','PRO','ENTERPRISE'))
);

-- ── Table: brain_weights ──────────────────────────────────────
-- Persists per-user adaptive weight profiles
CREATE TABLE IF NOT EXISTS brain_weights (
  user_id          TEXT     PRIMARY KEY,
  weights_json     TEXT     NOT NULL DEFAULT '{}',
  feedback_count   INTEGER  NOT NULL DEFAULT 0,
  last_updated     TEXT     NOT NULL DEFAULT (datetime('now')),
  version          INTEGER  NOT NULL DEFAULT 1
);

-- ── Table: brain_global_signals ───────────────────────────────
-- Aggregated global threat signal store (sector-level)
CREATE TABLE IF NOT EXISTS brain_global_signals (
  id               INTEGER  PRIMARY KEY AUTOINCREMENT,
  signal_type      TEXT     NOT NULL,
  sector           TEXT     NOT NULL DEFAULT 'technology',
  finding_type     TEXT     NOT NULL,
  occurrence_count INTEGER  NOT NULL DEFAULT 1,
  fp_count         INTEGER  NOT NULL DEFAULT 0,
  avg_cvss         REAL     DEFAULT 0,
  last_seen        TEXT     NOT NULL DEFAULT (datetime('now')),
  CONSTRAINT chk_bgs_signal CHECK (signal_type IN ('finding','fp_pattern','attack_pattern','cve_trend'))
);

-- ── Table: brain_predictions ──────────────────────────────────
-- Cached attack path prediction results
CREATE TABLE IF NOT EXISTS brain_predictions (
  id               INTEGER  PRIMARY KEY AUTOINCREMENT,
  user_id          TEXT     NOT NULL,
  sector           TEXT     NOT NULL DEFAULT 'technology',
  assets_hash      TEXT     NOT NULL,
  vulns_hash       TEXT     NOT NULL,
  breach_prob      REAL     NOT NULL DEFAULT 0,
  ttb_hours        INTEGER  NOT NULL DEFAULT 72,
  top_chain        TEXT     NOT NULL DEFAULT 'unknown',
  chain_count      INTEGER  NOT NULL DEFAULT 0,
  predictions_json TEXT     NOT NULL DEFAULT '{}',
  tier             TEXT     NOT NULL DEFAULT 'FREE',
  created_at       TEXT     NOT NULL DEFAULT (datetime('now')),
  CONSTRAINT chk_bp_tier CHECK (tier IN ('FREE','STARTER','PRO','ENTERPRISE'))
);

-- ── Table: brain_model_snapshots ──────────────────────────────
-- Periodic snapshots of the global adaptive model state
CREATE TABLE IF NOT EXISTS brain_model_snapshots (
  id               INTEGER  PRIMARY KEY AUTOINCREMENT,
  snapshot_date    TEXT     NOT NULL DEFAULT (date('now')),
  sector           TEXT     NOT NULL DEFAULT 'technology',
  total_feedbacks  INTEGER  NOT NULL DEFAULT 0,
  active_users     INTEGER  NOT NULL DEFAULT 0,
  top_findings     TEXT     NOT NULL DEFAULT '[]',
  fp_patterns      TEXT     NOT NULL DEFAULT '[]',
  global_risk_avg  REAL     NOT NULL DEFAULT 0,
  model_version    TEXT     NOT NULL DEFAULT '21.0',
  snapshot_json    TEXT     NOT NULL DEFAULT '{}'
);

-- ── Indexes: brain_feedback ───────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_bf_user_id      ON brain_feedback (user_id);
CREATE INDEX IF NOT EXISTS idx_bf_scan_id      ON brain_feedback (scan_id);
CREATE INDEX IF NOT EXISTS idx_bf_finding_id   ON brain_feedback (finding_id);
CREATE INDEX IF NOT EXISTS idx_bf_created_at   ON brain_feedback (created_at);
CREATE INDEX IF NOT EXISTS idx_bf_sector       ON brain_feedback (sector);

-- ── Indexes: brain_global_signals ────────────────────────────
CREATE INDEX IF NOT EXISTS idx_bgs_sector      ON brain_global_signals (sector);
CREATE INDEX IF NOT EXISTS idx_bgs_signal_type ON brain_global_signals (signal_type);
CREATE INDEX IF NOT EXISTS idx_bgs_last_seen   ON brain_global_signals (last_seen);

-- ── Indexes: brain_predictions ───────────────────────────────
CREATE INDEX IF NOT EXISTS idx_bp_user_id      ON brain_predictions (user_id);
CREATE INDEX IF NOT EXISTS idx_bp_sector       ON brain_predictions (sector);
CREATE INDEX IF NOT EXISTS idx_bp_created_at   ON brain_predictions (created_at);

-- ── Indexes: brain_model_snapshots ───────────────────────────
CREATE INDEX IF NOT EXISTS idx_bms_date        ON brain_model_snapshots (snapshot_date);
CREATE INDEX IF NOT EXISTS idx_bms_sector      ON brain_model_snapshots (sector);

-- ============================================================
-- END OF v21.0 ADAPTIVE BRAIN MIGRATION
-- ============================================================
