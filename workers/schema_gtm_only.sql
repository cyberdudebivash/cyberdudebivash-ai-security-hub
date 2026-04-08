-- ═══════════════════════════════════════════════════════════════════════════
-- Sentinel APEX — GTM Growth Engine Schema (v12.0)
-- Run this to add ONLY the new GTM tables to an existing database.
-- Safe to run on both local and remote:
--   LOCAL:  npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_gtm_only.sql
--   REMOTE: npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./schema_gtm_only.sql
-- All statements use CREATE TABLE IF NOT EXISTS — fully idempotent.
-- ═══════════════════════════════════════════════════════════════════════════

-- Leads — captured emails, plan info, lead score
CREATE TABLE IF NOT EXISTS leads (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  name            TEXT,
  domain          TEXT,
  source          TEXT DEFAULT 'scan',
  is_enterprise   INTEGER DEFAULT 0,
  plan            TEXT DEFAULT 'free',
  lead_score      INTEGER DEFAULT 0,
  funnel_stage    TEXT DEFAULT 'visitor',
  scan_count      INTEGER DEFAULT 0,
  converted_at    TEXT,
  created_at      TEXT DEFAULT (datetime('now')),
  updated_at      TEXT DEFAULT (datetime('now'))
);

-- Funnel events — granular event log per user
CREATE TABLE IF NOT EXISTS funnel_events (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  stage       TEXT NOT NULL,
  meta        TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Email sequences — drip enrollment tracker
CREATE TABLE IF NOT EXISTS email_sequences (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  sequence_id     TEXT NOT NULL,
  current_step    INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'active',
  meta            TEXT DEFAULT '{}',
  enrolled_at     TEXT DEFAULT (datetime('now')),
  next_send_at    TEXT,
  last_sent_at    TEXT
);

-- Email tracking — open/click/sent events
CREATE TABLE IF NOT EXISTS email_tracking (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  sequence_id TEXT,
  step        INTEGER DEFAULT 0,
  event       TEXT NOT NULL,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Content queue — generated content waiting to be published
CREATE TABLE IF NOT EXISTS content_queue (
  id          TEXT PRIMARY KEY,
  cve_id      TEXT,
  platform    TEXT NOT NULL,
  content     TEXT NOT NULL,
  status      TEXT DEFAULT 'pending',
  posted_at   TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- NOTE: api_keys is owned by schema.sql (user_id/key_hash/tier schema).
-- The GTM-style api_keys (email/api_key) was an alternate design that is no longer
-- used. Removed to prevent SQLITE_ERROR when CREATE INDEX fires on missing columns.

-- API usage log — per-request log
CREATE TABLE IF NOT EXISTS api_usage_log (
  id          TEXT PRIMARY KEY,
  api_key     TEXT NOT NULL,
  email       TEXT,
  endpoint    TEXT,
  status_code INTEGER,
  latency_ms  INTEGER DEFAULT 0,
  weight      INTEGER DEFAULT 1,
  logged_at   TEXT DEFAULT (datetime('now'))
);

-- Sales outreach — generated email/linkedin drafts
CREATE TABLE IF NOT EXISTS sales_outreach (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  outreach_type   TEXT,
  subject         TEXT,
  body            TEXT,
  status          TEXT DEFAULT 'draft',
  sent_at         TEXT,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- Billing events — payment history
CREATE TABLE IF NOT EXISTS billing_events (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  plan        TEXT,
  payment_id  TEXT,
  order_id    TEXT,
  event_type  TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Growth analytics — raw event stream
CREATE TABLE IF NOT EXISTS growth_analytics (
  id          TEXT PRIMARY KEY,
  event       TEXT NOT NULL,
  properties  TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Global expansion — region tracking
CREATE TABLE IF NOT EXISTS region_events (
  id          TEXT PRIMARY KEY,
  email       TEXT,
  country     TEXT,
  region      TEXT,
  currency    TEXT,
  timezone    TEXT,
  page        TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Upsell events — upgrade trigger log
CREATE TABLE IF NOT EXISTS upsell_events (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  trigger_type    TEXT NOT NULL,
  current_plan    TEXT,
  suggested_plan  TEXT,
  converted       INTEGER DEFAULT 0,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- A/B pricing experiments
CREATE TABLE IF NOT EXISTS pricing_experiments (
  id          TEXT PRIMARY KEY,
  variant     TEXT NOT NULL,
  email       TEXT,
  converted   INTEGER DEFAULT 0,
  revenue_inr INTEGER DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- GTM Indexes
CREATE INDEX IF NOT EXISTS idx_leads_email       ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_plan        ON leads(plan);
CREATE INDEX IF NOT EXISTS idx_leads_score       ON leads(lead_score DESC);
CREATE INDEX IF NOT EXISTS idx_leads_enterprise  ON leads(is_enterprise);
CREATE INDEX IF NOT EXISTS idx_leads_created     ON leads(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_funnel_email      ON funnel_events(email);
CREATE INDEX IF NOT EXISTS idx_funnel_stage      ON funnel_events(stage);
CREATE INDEX IF NOT EXISTS idx_funnel_created    ON funnel_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_seq_email   ON email_sequences(email);
CREATE INDEX IF NOT EXISTS idx_email_seq_status  ON email_sequences(status);
CREATE INDEX IF NOT EXISTS idx_email_seq_next    ON email_sequences(next_send_at);
CREATE INDEX IF NOT EXISTS idx_email_track_email ON email_tracking(email);
CREATE INDEX IF NOT EXISTS idx_email_track_event ON email_tracking(event);
CREATE INDEX IF NOT EXISTS idx_content_platform  ON content_queue(platform);
CREATE INDEX IF NOT EXISTS idx_content_status    ON content_queue(status);
CREATE INDEX IF NOT EXISTS idx_api_usage_email   ON api_usage_log(email);
CREATE INDEX IF NOT EXISTS idx_api_usage_logged  ON api_usage_log(logged_at DESC);
-- idx_api_keys_email / idx_api_keys_key removed — api_keys owned by schema.sql
CREATE INDEX IF NOT EXISTS idx_outreach_email    ON sales_outreach(email);
CREATE INDEX IF NOT EXISTS idx_outreach_status   ON sales_outreach(status);
CREATE INDEX IF NOT EXISTS idx_billing_email     ON billing_events(email);
CREATE INDEX IF NOT EXISTS idx_growth_event      ON growth_analytics(event);
CREATE INDEX IF NOT EXISTS idx_growth_created    ON growth_analytics(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_upsell_email      ON upsell_events(email);
CREATE INDEX IF NOT EXISTS idx_upsell_trigger    ON upsell_events(trigger_type);
CREATE INDEX IF NOT EXISTS idx_region_country    ON region_events(country);
CREATE INDEX IF NOT EXISTS idx_pricing_variant   ON pricing_experiments(variant);
