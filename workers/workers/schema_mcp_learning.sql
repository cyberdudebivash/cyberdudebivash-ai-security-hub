-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — MCP Self-Learning Schema v17.0
-- Migration: Add self-learning tables to D1
--
-- Tables added:
--   mcp_feedback     — raw interaction events (click, purchase, ignore)
--   mcp_item_scores  — aggregated performance scores per item
--   user_profiles    — learned user preference profiles
--   mcp_ab_results   — A/B experiment tracking
--   mcp_context_stats— context performance (scan_result vs dashboard vs exit_intent)
--
-- DO NOT modify existing tables. Append-only migration.
-- ═══════════════════════════════════════════════════════════════════════════

-- Phase 1: Raw feedback events
CREATE TABLE IF NOT EXISTS mcp_feedback (
  id                  TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id             TEXT,                                          -- NULL for anonymous
  session_id          TEXT,                                          -- client session fingerprint
  ip_hash             TEXT,                                          -- hashed IP (privacy)
  action              TEXT    NOT NULL CHECK (action IN ('click','purchase','ignore','dismiss','share')),
  context             TEXT    NOT NULL DEFAULT 'scan_result',        -- scan_result | dashboard | exit_intent | post_payment
  recommendation_type TEXT    NOT NULL CHECK (recommendation_type IN ('tool','training','bundle','upsell','enterprise')),
  item_id             TEXT    NOT NULL,                              -- tool id, training id, bundle id
  item_name           TEXT,                                         -- display name (denormalized for fast reporting)
  module              TEXT,                                         -- domain | ai | redteam | identity | compliance
  risk_level          TEXT,                                         -- LOW | MEDIUM | HIGH | CRITICAL
  tier                TEXT    DEFAULT 'FREE',
  ab_variant          TEXT,                                         -- 'A' | 'B' (for experiment tracking)
  success             INTEGER NOT NULL DEFAULT 0,                   -- 1 = converted (purchase), 0 = other
  revenue_inr         INTEGER DEFAULT 0,                            -- 0 for non-purchase events
  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mcp_feedback_item      ON mcp_feedback(item_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_user      ON mcp_feedback(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_context   ON mcp_feedback(context, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_type      ON mcp_feedback(recommendation_type, action);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_module    ON mcp_feedback(module, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_feedback_success   ON mcp_feedback(success, created_at DESC) WHERE success = 1;

-- Phase 2: Aggregated item performance scores (synced from feedback)
CREATE TABLE IF NOT EXISTS mcp_item_scores (
  item_id             TEXT    PRIMARY KEY,
  item_name           TEXT,
  recommendation_type TEXT    NOT NULL,
  total_shown         INTEGER NOT NULL DEFAULT 0,
  total_clicks        INTEGER NOT NULL DEFAULT 0,
  total_purchases     INTEGER NOT NULL DEFAULT 0,
  total_ignores       INTEGER NOT NULL DEFAULT 0,
  total_dismisses     INTEGER NOT NULL DEFAULT 0,
  total_revenue_inr   INTEGER NOT NULL DEFAULT 0,
  click_rate          REAL    NOT NULL DEFAULT 0.0,   -- clicks / shown
  purchase_rate       REAL    NOT NULL DEFAULT 0.0,   -- purchases / shown
  ignore_rate         REAL    NOT NULL DEFAULT 0.0,   -- ignores / shown
  mcp_score           REAL    NOT NULL DEFAULT 50.0,  -- computed score 0-100
  last_updated        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mcp_scores_type  ON mcp_item_scores(recommendation_type, mcp_score DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_scores_score ON mcp_item_scores(mcp_score DESC);

-- Phase 4: Learned user preference profiles
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id             TEXT    PRIMARY KEY,
  preferred_tools     TEXT    DEFAULT '[]',       -- JSON array of item_ids ranked by score
  preferred_training  TEXT    DEFAULT '[]',       -- JSON array of item_ids ranked by score
  preferred_bundles   TEXT    DEFAULT '[]',       -- JSON array of bundle_ids
  risk_pattern        TEXT    DEFAULT 'unknown',  -- high_risk | low_risk | improving | volatile
  conversion_behavior TEXT    DEFAULT 'unknown',  -- quick_buyer | researcher | price_sensitive | browser
  top_module          TEXT,                       -- most scanned module
  avg_risk_score      REAL    DEFAULT 0.0,
  total_scans         INTEGER DEFAULT 0,
  total_purchases     INTEGER DEFAULT 0,
  total_revenue_inr   INTEGER DEFAULT 0,
  last_active         TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_behavior ON user_profiles(conversion_behavior);
CREATE INDEX IF NOT EXISTS idx_user_profiles_pattern  ON user_profiles(risk_pattern);

-- Phase 5: Context performance stats
CREATE TABLE IF NOT EXISTS mcp_context_stats (
  id                  TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  context             TEXT    NOT NULL,           -- scan_result | dashboard | exit_intent
  recommendation_type TEXT    NOT NULL,
  item_id             TEXT    NOT NULL,
  total_shown         INTEGER NOT NULL DEFAULT 0,
  total_conversions   INTEGER NOT NULL DEFAULT 0,
  conversion_rate     REAL    NOT NULL DEFAULT 0.0,
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(context, recommendation_type, item_id)
);

-- Phase 7: A/B experiment tracking
CREATE TABLE IF NOT EXISTS mcp_ab_results (
  id                  TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  experiment_id       TEXT    NOT NULL,           -- e.g. 'cta_variant_bundle_202601'
  variant             TEXT    NOT NULL,           -- 'A' | 'B'
  item_id             TEXT,
  cta_text            TEXT,
  context             TEXT,
  impressions         INTEGER NOT NULL DEFAULT 0,
  clicks              INTEGER NOT NULL DEFAULT 0,
  purchases           INTEGER NOT NULL DEFAULT 0,
  revenue_inr         INTEGER NOT NULL DEFAULT 0,
  click_rate          REAL    NOT NULL DEFAULT 0.0,
  purchase_rate       REAL    NOT NULL DEFAULT 0.0,
  winner              INTEGER DEFAULT NULL,       -- NULL=undecided, 1=this variant won
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(experiment_id, variant)
);

CREATE INDEX IF NOT EXISTS idx_mcp_ab_experiment ON mcp_ab_results(experiment_id, variant);
