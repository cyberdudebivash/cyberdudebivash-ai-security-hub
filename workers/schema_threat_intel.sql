-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Threat Intelligence Schema v1.0
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_threat_intel.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- Threat intelligence entries (NVD CVEs, CISA KEV, RSS advisories)
CREATE TABLE IF NOT EXISTS threat_intel (
  id              TEXT PRIMARY KEY,           -- CVE-ID or advisory ID
  title           TEXT NOT NULL,              -- short title / vulnerability name
  severity        TEXT NOT NULL DEFAULT 'MEDIUM', -- CRITICAL | HIGH | MEDIUM | LOW
  cvss            REAL,                       -- CVSS v3 base score (0.0–10.0)
  cvss_vector     TEXT,                       -- CVSS vector string
  description     TEXT,                       -- plain-text description (≤500 chars)
  source          TEXT NOT NULL,              -- 'nvd' | 'cisa_kev' | 'rss' | 'github'
  source_url      TEXT,                       -- canonical URL at source
  published_at    TEXT,                       -- ISO date string (YYYY-MM-DD)
  exploit_status  TEXT DEFAULT 'unconfirmed', -- 'confirmed' | 'poc_available' | 'unconfirmed'
  known_ransomware INTEGER DEFAULT 0,         -- 1 if associated with ransomware campaigns
  tags            TEXT DEFAULT '[]',          -- JSON array of tag strings
  iocs            TEXT DEFAULT '[]',          -- JSON array of IOC objects
  affected_products TEXT DEFAULT '[]',        -- JSON array of CPE strings
  weakness_types  TEXT DEFAULT '[]',          -- JSON array of CWE IDs
  enriched          INTEGER DEFAULT 0,          -- 1 if enrichment pass has run
  epss_score        REAL,                       -- FIRST.org EPSS score (0.0–1.0)
  epss_percentile   REAL,                       -- EPSS percentile rank
  actively_exploited INTEGER DEFAULT 0,         -- 1 if confirmed exploited in the wild
  exploit_available  INTEGER DEFAULT 0,         -- 1 if exploit/PoC is publicly available
  ioc_list          TEXT DEFAULT '[]',          -- JSON array of extracted IOC objects (enriched)
  created_at        TEXT DEFAULT (datetime('now')),
  updated_at        TEXT DEFAULT (datetime('now'))
);

-- Correlation cache — stores CVE relationship results
CREATE TABLE IF NOT EXISTS cve_correlations (
  cve_id          TEXT PRIMARY KEY,
  related_cves    TEXT DEFAULT '[]',   -- JSON: [{ id, title, severity, score }]
  threat_actor    TEXT,
  campaign        TEXT,
  mitre_tactics   TEXT DEFAULT '[]',
  confidence      INTEGER DEFAULT 0,
  correlated_at   TEXT DEFAULT (datetime('now'))
);

-- Hunting alerts — stored results of hunting engine runs
CREATE TABLE IF NOT EXISTS hunting_alerts (
  id              TEXT PRIMARY KEY,
  type            TEXT NOT NULL,
  severity        TEXT NOT NULL,
  message         TEXT NOT NULL,
  evidence        TEXT DEFAULT '{}',
  resolved        INTEGER DEFAULT 0,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- IOC (Indicator of Compromise) registry — extracted from advisories
CREATE TABLE IF NOT EXISTS ioc_registry (
  id          TEXT PRIMARY KEY,     -- UUID
  intel_id    TEXT NOT NULL,        -- FK → threat_intel.id
  type        TEXT NOT NULL,        -- 'ip' | 'domain' | 'url' | 'md5' | 'sha256' | 'sha1'
  value       TEXT NOT NULL,        -- the actual IOC value
  confidence  REAL DEFAULT 0.8,     -- 0.0–1.0 confidence score
  created_at  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (intel_id) REFERENCES threat_intel(id) ON DELETE CASCADE
);

-- Ingestion run log — track cron job history
CREATE TABLE IF NOT EXISTS ingestion_runs (
  id            TEXT PRIMARY KEY,
  ran_at        TEXT DEFAULT (datetime('now')),
  sources       TEXT DEFAULT '[]',  -- JSON array of source names attempted
  inserted      INTEGER DEFAULT 0,
  updated       INTEGER DEFAULT 0,
  errors        TEXT DEFAULT '[]',  -- JSON array of error messages
  duration_ms   INTEGER,
  success       INTEGER DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_threat_intel_severity   ON threat_intel(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source     ON threat_intel(source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_published  ON threat_intel(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_created    ON threat_intel(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_exploit    ON threat_intel(exploit_status);
CREATE INDEX IF NOT EXISTS idx_threat_intel_epss       ON threat_intel(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_active     ON threat_intel(actively_exploited);
CREATE INDEX IF NOT EXISTS idx_ioc_type               ON ioc_registry(type);
CREATE INDEX IF NOT EXISTS idx_ioc_intel_id           ON ioc_registry(intel_id);
CREATE INDEX IF NOT EXISTS idx_correlation_cve        ON cve_correlations(cve_id);
CREATE INDEX IF NOT EXISTS idx_hunting_severity       ON hunting_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_hunting_resolved       ON hunting_alerts(resolved);

-- ═══════════════════════════════════════════════════════════════════════════
-- SOC Automation Tables (Sentinel APEX v3)
-- ═══════════════════════════════════════════════════════════════════════════

-- SOC Detection Alerts — output from detectionEngine.js
CREATE TABLE IF NOT EXISTS soc_alerts (
  id              TEXT PRIMARY KEY,
  alert_type      TEXT NOT NULL,
  severity        TEXT NOT NULL,
  cve_id          TEXT,
  title           TEXT,
  asset           TEXT,
  recommendation  TEXT,
  evidence        TEXT DEFAULT '{}',   -- JSON
  resolved        INTEGER DEFAULT 0,
  created_at      TEXT DEFAULT (datetime('now'))
);

-- AI Decision Engine Results — output from decisionEngine.js
CREATE TABLE IF NOT EXISTS soc_decisions (
  id              TEXT PRIMARY KEY,
  cve_id          TEXT NOT NULL,
  decision        TEXT NOT NULL,   -- escalate | auto_contain | fast_patch | monitor_closely | low_priority
  priority        TEXT NOT NULL,   -- P1-CRITICAL | P2-HIGH | P3-MEDIUM | P4-LOW
  confidence      INTEGER DEFAULT 0,
  risk_score      INTEGER DEFAULT 0,
  reason          TEXT,
  factors         TEXT DEFAULT '{}',   -- JSON
  created_at      TEXT DEFAULT (datetime('now'))
);

-- SOC Response Actions — output from responseEngine.js
CREATE TABLE IF NOT EXISTS soc_response_actions (
  id              TEXT PRIMARY KEY,
  action          TEXT NOT NULL,    -- block_ip | patch_advisory | waf_rule | ...
  priority        TEXT NOT NULL,    -- immediate | high | medium | low
  alert_id        TEXT,
  cve_id          TEXT,
  status          TEXT DEFAULT 'recommended',
  payload         TEXT DEFAULT '{}',    -- JSON
  created_at      TEXT DEFAULT (datetime('now'))
);

-- Autonomous Defense Actions — output from defenseEngine.js
CREATE TABLE IF NOT EXISTS soc_defense_actions (
  id              TEXT PRIMARY KEY,
  rule_id         TEXT,
  defense_action  TEXT NOT NULL,    -- auto_block | waf_deploy | isolate_segment | ...
  target          TEXT,
  target_type     TEXT,
  duration        TEXT,
  status          TEXT DEFAULT 'triggered',
  payload         TEXT DEFAULT '{}',   -- JSON
  created_at      TEXT DEFAULT (datetime('now'))
);

-- SOC indexes
CREATE INDEX IF NOT EXISTS idx_soc_alerts_severity    ON soc_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_type        ON soc_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_created     ON soc_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_decisions_priority ON soc_decisions(priority);
CREATE INDEX IF NOT EXISTS idx_soc_decisions_created  ON soc_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_response_priority  ON soc_response_actions(priority);
CREATE INDEX IF NOT EXISTS idx_soc_defense_action     ON soc_defense_actions(defense_action);
CREATE INDEX IF NOT EXISTS idx_soc_defense_created    ON soc_defense_actions(created_at DESC);

-- ── Migration: v2 columns for existing threat_intel table ────────────────────
-- IMPORTANT: Run schema_migrations_v2.sql FIRST if upgrading an existing DB.
-- The ALTER TABLE statements are in that file to avoid "no such column" errors
-- when creating indexes on a fresh schema run.
-- These columns are already present in the CREATE TABLE statement above (fresh installs).
-- schema_migrations_v2.sql handles the ALTER for existing production tables.

-- ═══════════════════════════════════════════════════════════════════════════
-- GTM Growth Engine Tables (Sentinel APEX GTM v1)
-- ═══════════════════════════════════════════════════════════════════════════

-- Leads — captured emails, plan info, lead score
CREATE TABLE IF NOT EXISTS leads (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  name            TEXT,
  domain          TEXT,
  source          TEXT DEFAULT 'scan',       -- 'scan' | 'blog' | 'linkedin' | 'api' | 'referral'
  is_enterprise   INTEGER DEFAULT 0,         -- 1 = corporate email domain
  plan            TEXT DEFAULT 'free',       -- 'free' | 'starter' | 'pro' | 'enterprise'
  lead_score      INTEGER DEFAULT 0,         -- 0–100
  funnel_stage    TEXT DEFAULT 'visitor',    -- visitor | scan_start | scan_done | email_captured | report_viewed | upgrade_cta_shown | converted | churned
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
  meta        TEXT DEFAULT '{}',             -- JSON: arbitrary event properties
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Email sequences — drip enrollment tracker
CREATE TABLE IF NOT EXISTS email_sequences (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL,
  sequence_id     TEXT NOT NULL,             -- 'welcome' | 'enterprise' | 'trial_expiry'
  current_step    INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'active',     -- 'active' | 'completed' | 'unsubscribed'
  meta            TEXT DEFAULT '{}',         -- JSON: scanData, etc.
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
  event       TEXT NOT NULL,                 -- 'sent' | 'open' | 'click' | 'unsubscribe'
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Content queue — generated content waiting to be published
CREATE TABLE IF NOT EXISTS content_queue (
  id          TEXT PRIMARY KEY,
  cve_id      TEXT,
  platform    TEXT NOT NULL,                 -- 'linkedin' | 'twitter' | 'telegram' | 'blog' | 'email'
  content     TEXT NOT NULL,                 -- JSON blob of generated content
  status      TEXT DEFAULT 'pending',        -- 'pending' | 'posted' | 'failed'
  posted_at   TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- NOTE: api_keys table is owned by schema.sql (different schema — user_id/key_hash/tier).
-- Removed from this file to prevent CREATE INDEX on non-existent columns (email, api_key)
-- which causes SQLITE_ERROR on D1 atomic transaction rollback.

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
  outreach_type   TEXT,                      -- 'send_email_and_linkedin' | 'send_proposal' | 'send_email'
  subject         TEXT,
  body            TEXT,
  status          TEXT DEFAULT 'draft',      -- 'draft' | 'sent' | 'replied' | 'closed'
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
  event_type  TEXT,                          -- 'payment_success' | 'subscription_cancelled' | 'refund'
  created_at  TEXT DEFAULT (datetime('now'))
);

-- Growth analytics — raw event stream
CREATE TABLE IF NOT EXISTS growth_analytics (
  id          TEXT PRIMARY KEY,
  event       TEXT NOT NULL,
  properties  TEXT DEFAULT '{}',
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
