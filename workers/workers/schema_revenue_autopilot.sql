-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Revenue Autopilot Schema v18.0
-- Migration: Append-only. DO NOT modify any existing tables.
--
-- New tables:
--   mcp_revenue_events   — impression + click + purchase funnel tracking
--   mcp_cta_variants     — CTA A/B performance per module + user type
--   mcp_loss_prevention  — exit-intent / inactivity trigger outcomes
--   mcp_offer_log        — which offer was shown to whom + result
-- ═══════════════════════════════════════════════════════════════════════════

-- Phase 6: Revenue event funnel (impression → click → purchase)
CREATE TABLE IF NOT EXISTS mcp_revenue_events (
  id               TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id       TEXT,                                    -- client session fingerprint
  user_id          TEXT,                                    -- NULL = anonymous
  ip_hash          TEXT,
  event_type       TEXT    NOT NULL CHECK (event_type IN (
                     'impression','click','purchase','abandon','loss_prevent_shown',
                     'loss_prevent_converted','welcome_back_shown','welcome_back_converted'
                   )),
  offer_type       TEXT    NOT NULL CHECK (offer_type IN (
                     'single','bundle','dynamic_bundle','enterprise','upsell',
                     'loss_prevention','welcome_back','cta_only'
                   )),
  offer_id         TEXT    NOT NULL,                        -- item_id or bundle_id
  offer_name       TEXT,
  display_price    INTEGER DEFAULT 0,                       -- visual price shown (INR)
  actual_price     INTEGER DEFAULT 0,                       -- real price (for purchases)
  discount_pct     INTEGER DEFAULT 0,                       -- visual discount % shown
  cta_variant      TEXT    DEFAULT 'standard',              -- aggressive|standard|soft|enterprise
  urgency_level    TEXT    DEFAULT 'low',
  module           TEXT,
  risk_level       TEXT,
  user_type        TEXT    DEFAULT 'new',                   -- new|returning|buyer|churned|enterprise_icp
  context          TEXT    DEFAULT 'scan_result',
  revenue_inr      INTEGER DEFAULT 0,                       -- 0 unless purchase (server-verified)
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rev_events_offer    ON mcp_revenue_events(offer_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_events_user     ON mcp_revenue_events(user_id, event_type) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rev_events_type     ON mcp_revenue_events(offer_type, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_events_context  ON mcp_revenue_events(context, event_type);
CREATE INDEX IF NOT EXISTS idx_rev_events_date     ON mcp_revenue_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rev_events_purchase ON mcp_revenue_events(event_type, revenue_inr) WHERE event_type='purchase';

-- Phase 4: CTA variant performance tracking
CREATE TABLE IF NOT EXISTS mcp_cta_variants (
  id               TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  variant_id       TEXT    NOT NULL,                        -- 'aggressive'|'standard'|'soft'|'enterprise'
  module           TEXT    NOT NULL,
  user_type        TEXT    NOT NULL DEFAULT 'new',
  context          TEXT    NOT NULL DEFAULT 'scan_result',
  cta_text         TEXT    NOT NULL,
  impressions      INTEGER NOT NULL DEFAULT 0,
  clicks           INTEGER NOT NULL DEFAULT 0,
  purchases        INTEGER NOT NULL DEFAULT 0,
  click_rate       REAL    NOT NULL DEFAULT 0.0,
  purchase_rate    REAL    NOT NULL DEFAULT 0.0,
  revenue_inr      INTEGER NOT NULL DEFAULT 0,
  is_winner        INTEGER NOT NULL DEFAULT 0,
  updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(variant_id, module, user_type, context)
);

CREATE INDEX IF NOT EXISTS idx_cta_variants_module ON mcp_cta_variants(module, user_type, purchase_rate DESC);

-- Phase 7: Loss prevention tracking
CREATE TABLE IF NOT EXISTS mcp_loss_prevention (
  id               TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id       TEXT,
  user_id          TEXT,
  trigger_type     TEXT    NOT NULL CHECK (trigger_type IN ('exit_intent','inactivity','scroll_abandon')),
  offer_shown      TEXT,                                    -- offer_id shown
  discount_pct     INTEGER DEFAULT 0,
  converted        INTEGER NOT NULL DEFAULT 0,              -- 1 if user purchased after
  revenue_inr      INTEGER DEFAULT 0,
  module           TEXT,
  risk_level       TEXT,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_loss_prev_converted ON mcp_loss_prevention(converted, trigger_type);

-- Phase 6+9: Aggregated offer performance (fast KV sync target)
CREATE TABLE IF NOT EXISTS mcp_offer_performance (
  offer_id         TEXT    PRIMARY KEY,
  offer_type       TEXT    NOT NULL,
  offer_name       TEXT,
  total_impressions INTEGER NOT NULL DEFAULT 0,
  total_clicks      INTEGER NOT NULL DEFAULT 0,
  total_purchases   INTEGER NOT NULL DEFAULT 0,
  total_abandons    INTEGER NOT NULL DEFAULT 0,
  total_revenue_inr INTEGER NOT NULL DEFAULT 0,
  click_rate        REAL    NOT NULL DEFAULT 0.0,
  purchase_rate     REAL    NOT NULL DEFAULT 0.0,
  revenue_per_impression REAL NOT NULL DEFAULT 0.0,        -- RPI: key metric
  best_user_type    TEXT,                                   -- which user type converts best
  best_context      TEXT,                                   -- which context converts best
  best_cta_variant  TEXT,                                   -- which CTA converts best
  revenue_score     REAL    NOT NULL DEFAULT 50.0,          -- composite 0-100 revenue score
  last_updated      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_offer_perf_score  ON mcp_offer_performance(revenue_score DESC);
CREATE INDEX IF NOT EXISTS idx_offer_perf_rpi    ON mcp_offer_performance(revenue_per_impression DESC);
