-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Email Dead Letter Queue (Task 3 Phase 1)
-- Migration: Append-only. DO NOT modify any existing tables.
--
-- Tracks the table self-bootstrapped at runtime by
-- workers/src/services/emailEngine.js (ensureEmailDlqTable via
-- CREATE TABLE IF NOT EXISTS). Added to the tracked replay immediately
-- (unlike the coupon tables, which were only documented after the nightly
-- D1 Schema Drift Check caught the gap) so this table never causes drift.
--
-- New table:
--   email_dlq — emails that failed on every provider in sendEmail()'s
--               cascade, held for a cron-driven retry sweep.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS email_dlq (
  id              TEXT PRIMARY KEY,
  to_email        TEXT NOT NULL,
  subject         TEXT NOT NULL,
  html            TEXT NOT NULL,
  text            TEXT,
  event_type      TEXT NOT NULL DEFAULT 'generic',
  attempts        INTEGER NOT NULL DEFAULT 1,
  last_error      TEXT,
  status          TEXT NOT NULL DEFAULT 'pending_retry',
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  last_attempt_at TEXT,
  resolved_at     TEXT
);
