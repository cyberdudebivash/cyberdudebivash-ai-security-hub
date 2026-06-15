-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Master Schema v38
-- Safe cumulative migration (all tables with IF NOT EXISTS)
-- Generated from 40 schema files
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_master.sql
-- ============================================================

PRAGMA foreign_keys = OFF;

-- From: schema.sql
CREATE TABLE IF NOT EXISTS users (
  id              TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email           TEXT    NOT NULL UNIQUE,
  password_hash   TEXT    NOT NULL,
  password_salt   TEXT    NOT NULL,
  tier            TEXT    NOT NULL DEFAULT 'FREE' CHECK (tier IN ('FREE','PRO','ENTERPRISE')),
  status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','unverified')),
  full_name       TEXT,
  company         TEXT,
  telegram_chat_id TEXT,
  alert_email     TEXT,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login_at   TEXT,
  login_count     INTEGER NOT NULL DEFAULT 0
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS organizations (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name             TEXT NOT NULL,
  slug             TEXT UNIQUE NOT NULL,
  plan             TEXT NOT NULL DEFAULT 'STARTER'
                     CHECK (plan IN ('STARTER','PRO','ENTERPRISE')),
  owner_id         TEXT NOT NULL,
  max_members      INTEGER NOT NULL DEFAULT 5,
  max_daily_scans  INTEGER NOT NULL DEFAULT 100,
  settings_json    TEXT NOT NULL DEFAULT '{}',
  logo_url         TEXT,
  domain           TEXT,
  industry         TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS api_keys (
  key_id      TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  tier        TEXT NOT NULL DEFAULT 'COMMUNITY',
  active      INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  label       TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_used   TEXT
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  revoked     INTEGER NOT NULL DEFAULT 0,
  ip_address  TEXT,
  user_agent  TEXT
);

-- From: schema_v22_production_fix.sql
CREATE TABLE IF NOT EXISTS scan_jobs (
  id          TEXT PRIMARY KEY,
  module      TEXT NOT NULL DEFAULT 'domain',
  target      TEXT,
  status      TEXT NOT NULL DEFAULT 'pending',
  risk_level  TEXT,
  risk_score  REAL DEFAULT 0,
  result      TEXT,
  error       TEXT,
  user_id     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS adsense_events (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type  TEXT NOT NULL
                CHECK (event_type IN ('impression','click','revenue')),
  slot_id     TEXT,
  page        TEXT,
  ip          TEXT,
  country     TEXT,
  revenue_usd REAL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS affiliate_clicks (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  program    TEXT NOT NULL,
  link_id    TEXT NOT NULL,
  link_url   TEXT NOT NULL,
  ref_page   TEXT,
  ip         TEXT,
  country    TEXT,
  user_agent TEXT,
  converted  INTEGER NOT NULL DEFAULT 0,
  revenue    REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS affiliate_members (
  id                TEXT PRIMARY KEY,
  email             TEXT NOT NULL UNIQUE,
  name              TEXT,
  type              TEXT NOT NULL DEFAULT 'individual',
  tier              TEXT NOT NULL DEFAULT 'AFFILIATE',
  ref_code          TEXT NOT NULL UNIQUE,
  commission_pct    REAL NOT NULL DEFAULT 10.0,
  total_referrals   INTEGER NOT NULL DEFAULT 0,
  total_conversions INTEGER NOT NULL DEFAULT 0,
  total_earnings    REAL NOT NULL DEFAULT 0,
  pending_payout    REAL NOT NULL DEFAULT 0,
  status            TEXT NOT NULL DEFAULT 'active',
  joined_at         INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata          TEXT DEFAULT '{}'
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS affiliate_payouts (
  id           TEXT PRIMARY KEY,
  affiliate_id TEXT NOT NULL DEFAULT '',
  amount_inr   REAL NOT NULL DEFAULT 0,
  method       TEXT NOT NULL DEFAULT 'upi',
  upi_id       TEXT,
  bank_details TEXT,
  status       TEXT NOT NULL DEFAULT 'requested',
  processed_at INTEGER,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS affiliate_referrals (
  id                    TEXT PRIMARY KEY,
  affiliate_id          TEXT NOT NULL DEFAULT '',
  ref_code              TEXT NOT NULL DEFAULT '',
  visitor_ip            TEXT,
  landing_page          TEXT,
  converted             INTEGER NOT NULL DEFAULT 0,
  conversion_invoice_id TEXT,
  commission_inr        REAL NOT NULL DEFAULT 0,
  created_at            INTEGER NOT NULL DEFAULT (unixepoch()),
  converted_at          INTEGER
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS agent_actions (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  agent_type        TEXT NOT NULL CHECK(agent_type IN (
    'threat_response','credential_rotation','isolation','patching','composite'
  )),
  action_type       TEXT NOT NULL CHECK(action_type IN (
    'block_ip','rotate_credentials','disable_session','apply_virtual_patch',
    'quarantine_user','kill_process','revoke_token','rate_limit_ip',
    'alert_admin','escalate','rollback'
  )),
  target            TEXT NOT NULL,
  target_type       TEXT NOT NULL DEFAULT 'ip' CHECK(target_type IN (
    'ip','user_id','session_id','cve_id','domain','api_key','endpoint'
  )),
  trigger_source    TEXT NOT NULL CHECK(trigger_source IN (
    'cve_ingestion','anomaly_detected','manual','scheduled','threat_intel','api_call'
  )),
  trigger_id        TEXT,
  risk_level        TEXT NOT NULL DEFAULT 'HIGH' CHECK(risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  decision_score    REAL NOT NULL DEFAULT 0,
  execution_status  TEXT NOT NULL DEFAULT 'pending' CHECK(execution_status IN (
    'pending','executing','SUCCESS','FAILED','ROLLED_BACK','SKIPPED'
  )),
  execution_detail  TEXT,
  rollback_available INTEGER NOT NULL DEFAULT 1,
  rollback_action   TEXT,
  executed_by       TEXT NOT NULL DEFAULT 'autonomous_agent',
  user_id           TEXT,
  duration_ms       INTEGER,
  error_message     TEXT,
  metadata          TEXT DEFAULT '{}',
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at      TEXT
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS agent_event_queue (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type   TEXT NOT NULL,
  payload      TEXT NOT NULL,
  priority     INTEGER NOT NULL DEFAULT 5,
  status       TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','done','failed')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  error        TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  processed_at TEXT,
  next_retry   TEXT
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_agent_inventory (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  name            TEXT NOT NULL DEFAULT '',
  framework       TEXT NOT NULL DEFAULT 'custom',
    -- openai_agents | claude | langchain | crewai | autogen | mcp | custom
  tools           TEXT NOT NULL DEFAULT '[]',  -- JSON: tool names/permissions
  permissions     TEXT NOT NULL DEFAULT '[]',  -- JSON: what the agent can do
  data_access     TEXT NOT NULL DEFAULT '[]',  -- JSON: what data it can read
  internet_access INTEGER NOT NULL DEFAULT 0,
  tool_count      INTEGER NOT NULL DEFAULT 0,
  risk_score      INTEGER NOT NULL DEFAULT 0,
  issues          TEXT DEFAULT '[]',
  status          TEXT NOT NULL DEFAULT 'active',
  last_reviewed   INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_assets (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  name            TEXT NOT NULL DEFAULT '',
  asset_type      TEXT NOT NULL DEFAULT 'model',
    -- model | agent | rag | api | dataset | pipeline | embedding
  provider        TEXT,  -- openai | anthropic | google | azure | huggingface | custom
  model_name      TEXT,
  version         TEXT,
  deployment      TEXT,  -- cloud | on-prem | hybrid | saas
  endpoint_url    TEXT,
  exposure        TEXT NOT NULL DEFAULT 'internal',  -- public | internal | restricted
  risk_score      INTEGER NOT NULL DEFAULT 0,
  security_score  INTEGER NOT NULL DEFAULT 100,
  status          TEXT NOT NULL DEFAULT 'active',  -- active | deprecated | retired
  owner_email     TEXT,
  tags            TEXT DEFAULT '[]',
  last_scanned    INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_findings (
  id              TEXT PRIMARY KEY,
  asset_id        TEXT NOT NULL DEFAULT '',
  scan_id         TEXT,
  category        TEXT NOT NULL DEFAULT 'LLM01',
    -- OWASP LLM: LLM01-LLM10 | NIST-GOVERN | NIST-MAP | ISO42001 | EU-AI-ACT
  title           TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  severity        TEXT NOT NULL DEFAULT 'MEDIUM',  -- CRITICAL | HIGH | MEDIUM | LOW | INFO
  cvss_score      REAL,
  cwe_id          TEXT,
  owasp_ref       TEXT,
  status          TEXT NOT NULL DEFAULT 'open',  -- open | accepted | mitigated | resolved
  remediation     TEXT,
  evidence        TEXT DEFAULT '{}',
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at     INTEGER,
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_governance_assessments (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  email           TEXT NOT NULL DEFAULT '',
  framework       TEXT NOT NULL DEFAULT 'NIST_AI_RMF',
    -- NIST_AI_RMF | ISO_42001 | OWASP_LLM | EU_AI_ACT | DPDP | CUSTOM
  overall_score   INTEGER NOT NULL DEFAULT 0,    -- 0-100
  risk_tier       TEXT NOT NULL DEFAULT 'HIGH',  -- MINIMAL | LIMITED | HIGH | UNACCEPTABLE
  status          TEXT NOT NULL DEFAULT 'in_progress',
  answers         TEXT DEFAULT '{}',   -- JSON: question_id -> answer
  gaps            TEXT DEFAULT '[]',   -- JSON: gap objects
  roadmap         TEXT DEFAULT '[]',   -- JSON: remediation steps
  report_url      TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at    INTEGER,
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_posture_scores (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL DEFAULT 'global',
  score_date      TEXT NOT NULL,   -- YYYY-MM-DD
  overall_score   INTEGER NOT NULL DEFAULT 0,    -- 0-100 (A/B/C/D/F)
  aspm_score      INTEGER NOT NULL DEFAULT 0,    -- PILLAR 1
  governance_score INTEGER NOT NULL DEFAULT 0,   -- PILLAR 2
  redteam_score   INTEGER NOT NULL DEFAULT 0,    -- PILLAR 3
  agent_score     INTEGER NOT NULL DEFAULT 0,    -- PILLAR 4
  intel_score     INTEGER NOT NULL DEFAULT 0,    -- PILLAR 5
  total_assets    INTEGER NOT NULL DEFAULT 0,
  critical_findings INTEGER NOT NULL DEFAULT 0,
  open_risks      INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_redteam_attempts (
  id              TEXT PRIMARY KEY,
  engagement_id   TEXT NOT NULL DEFAULT '',
  attack_type     TEXT NOT NULL DEFAULT '',
  payload         TEXT NOT NULL DEFAULT '',
  response        TEXT,
  success         INTEGER NOT NULL DEFAULT 0,
  severity        TEXT NOT NULL DEFAULT 'LOW',
  technique       TEXT,
  evidence        TEXT DEFAULT '{}',
  attempted_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_redteam_engagements (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  email           TEXT NOT NULL DEFAULT '',
  target_model    TEXT NOT NULL DEFAULT '',   -- model name / endpoint
  target_url      TEXT,
  attack_types    TEXT NOT NULL DEFAULT '[]', -- JSON array
    -- prompt_injection | jailbreak | tool_abuse | agent_takeover | rag_poisoning | data_exfil
  total_attempts  INTEGER NOT NULL DEFAULT 0,
  successful_attacks INTEGER NOT NULL DEFAULT 0,
  critical_findings  INTEGER NOT NULL DEFAULT 0,
  risk_score      INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'running',
  report_url      TEXT,
  started_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at    INTEGER,
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_risk_register (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,
  asset_id        TEXT,
  risk_title      TEXT NOT NULL DEFAULT '',
  risk_desc       TEXT NOT NULL DEFAULT '',
  risk_category   TEXT NOT NULL DEFAULT 'technical',
    -- technical | operational | reputational | legal | financial | strategic
  likelihood      INTEGER NOT NULL DEFAULT 3,  -- 1-5
  impact          INTEGER NOT NULL DEFAULT 3,  -- 1-5
  risk_score      INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
  risk_level      TEXT NOT NULL DEFAULT 'MEDIUM',
  owner           TEXT,
  controls        TEXT DEFAULT '[]',
  treatment       TEXT NOT NULL DEFAULT 'MITIGATE',  -- ACCEPT | MITIGATE | TRANSFER | AVOID
  status          TEXT NOT NULL DEFAULT 'open',
  due_date        INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  reviewed_at     INTEGER,
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_service_engagements (
  id              TEXT PRIMARY KEY,
  assessment_id   TEXT,
  email           TEXT NOT NULL DEFAULT '',
  company         TEXT,
  service_type    TEXT NOT NULL DEFAULT 'ai_security_assessment',
    -- ai_security_assessment | ai_governance | ai_redteam | managed_ai | ai_risk_advisory
  scope           TEXT DEFAULT '{}',    -- JSON: assets in scope, frameworks, depth
  status          TEXT NOT NULL DEFAULT 'scoping',
  price_inr       REAL NOT NULL DEFAULT 0,
  deliverables    TEXT DEFAULT '[]',
  analyst_email   TEXT,
  kickoff_at      INTEGER,
  delivery_at     INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v28.sql
CREATE TABLE IF NOT EXISTS ai_threat_feed (
  id              TEXT PRIMARY KEY,
  feed_type       TEXT NOT NULL DEFAULT 'vulnerability',
    -- vulnerability | attack_pattern | malware | prompt_attack | agent_threat | advisory
  title           TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  severity        TEXT NOT NULL DEFAULT 'MEDIUM',
  cve_id          TEXT,
  affected_models TEXT DEFAULT '[]',  -- JSON: affected model names/versions
  affected_frameworks TEXT DEFAULT '[]',
  iocs            TEXT DEFAULT '[]',
  mitigations     TEXT DEFAULT '[]',
  owasp_ref       TEXT,
  source_url      TEXT,
  published_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS alert_configs (
  id                TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id           TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  telegram_enabled  INTEGER NOT NULL DEFAULT 0,
  telegram_chat_id  TEXT,
  email_enabled     INTEGER NOT NULL DEFAULT 0,
  alert_email       TEXT,
  min_risk_score    INTEGER NOT NULL DEFAULT 70,   -- trigger threshold
  alert_on_blacklist INTEGER NOT NULL DEFAULT 1,
  alert_on_critical_cve INTEGER NOT NULL DEFAULT 1,
  created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS alert_log (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel     TEXT    NOT NULL CHECK (channel IN ('telegram','email')),
  trigger_type TEXT   NOT NULL,  -- high_risk, blacklist, critical_cve
  target      TEXT,
  message_preview TEXT,
  status      TEXT    NOT NULL DEFAULT 'sent' CHECK (status IN ('sent','failed','pending')),
  sent_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS analytics_events (
  id             TEXT PRIMARY KEY,
  event_type     TEXT NOT NULL,
  user_id        TEXT,
  org_id         TEXT DEFAULT 'default',
  tier           TEXT DEFAULT 'FREE',
  session_id     TEXT,
  properties_json TEXT DEFAULT '{}',
  ip_country     TEXT,
  occurred_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS anomaly_events (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  anomaly_score    REAL NOT NULL,
  anomaly_types    TEXT NOT NULL DEFAULT '[]',
  features_vector  TEXT NOT NULL DEFAULT '{}',
  isolation_depth  REAL,
  z_scores         TEXT DEFAULT '{}',
  risk_level       TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
  auto_actioned    INTEGER NOT NULL DEFAULT 0,
  action_id        TEXT,
  resolved         INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS api_billing (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  api_key_id      TEXT NOT NULL,
  user_id         TEXT,
  endpoint        TEXT NOT NULL,
  method          TEXT DEFAULT 'GET',
  plan            TEXT DEFAULT 'FREE',
  response_ms     INTEGER DEFAULT 0,
  status_code     INTEGER DEFAULT 200,
  tokens_used     INTEGER DEFAULT 0,
  cost_paise      INTEGER DEFAULT 0,
  billed          INTEGER DEFAULT 0,
  billing_period  TEXT DEFAULT '',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS api_key_usage (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  key_id       TEXT    NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  user_id      TEXT    NOT NULL,
  date_bucket  TEXT    NOT NULL,  -- YYYY-MM-DD
  module       TEXT    NOT NULL,  -- domain, ai, redteam, etc.
  request_count INTEGER NOT NULL DEFAULT 1,
  UNIQUE(key_id, date_bucket, module)
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS api_requests (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  api_key_id  TEXT,
  user_id     TEXT,
  endpoint    TEXT NOT NULL,
  method      TEXT NOT NULL,
  status_code INTEGER,
  latency_ms  INTEGER,
  ip          TEXT,
  ua          TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS api_usage_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT,
  api_key_id  TEXT,
  endpoint    TEXT    NOT NULL,
  method      TEXT    NOT NULL DEFAULT 'GET',
  status_code INTEGER,
  latency_ms  INTEGER,
  ip_address  TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS api_usage_summary (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  api_key_id      TEXT NOT NULL,
  user_id         TEXT,
  period          TEXT NOT NULL,
  total_calls     INTEGER DEFAULT 0,
  successful_calls INTEGER DEFAULT 0,
  failed_calls    INTEGER DEFAULT 0,
  total_cost_paise INTEGER DEFAULT 0,
  top_endpoints   TEXT DEFAULT '[]',
  avg_latency_ms  INTEGER DEFAULT 0,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS apt_profiles (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  group_name      TEXT NOT NULL UNIQUE,
  aliases         TEXT DEFAULT '[]',
  origin_country  TEXT,
  target_sectors  TEXT DEFAULT '[]',
  typical_cves    TEXT DEFAULT '[]',
  mitre_ttps      TEXT DEFAULT '[]',
  activity_level  TEXT DEFAULT 'ACTIVE' CHECK(activity_level IN ('ACTIVE','DORMANT','RETIRED','UNKNOWN')),
  last_seen       TEXT,
  ioc_count       INTEGER DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS asm_assets (
  id           TEXT PRIMARY KEY,
  target_id    TEXT NOT NULL,
  asset_type   TEXT NOT NULL,  -- subdomain | ip | cert | service | api_endpoint
  asset_value  TEXT NOT NULL,  -- the subdomain/IP/cert fingerprint/etc.
  ip_address   TEXT,
  open_ports   TEXT DEFAULT '[]',    -- JSON array
  technologies TEXT DEFAULT '[]',    -- JSON array: ['nginx','WordPress','PHP']
  cert_issuer  TEXT,
  cert_expiry  TEXT,
  cert_valid   INTEGER DEFAULT 1,
  http_status  INTEGER,
  http_title   TEXT,
  risk_level   TEXT DEFAULT 'LOW',   -- CRITICAL/HIGH/MEDIUM/LOW/INFO
  risk_reasons TEXT DEFAULT '[]',    -- JSON array of risk reason strings
  new_asset    INTEGER DEFAULT 1,    -- 1 = found in this scan, not seen before
  first_seen   TEXT DEFAULT (datetime('now')),
  last_seen    TEXT DEFAULT (datetime('now')),
  resolved     INTEGER DEFAULT 0,    -- 1 = user acknowledged
  FOREIGN KEY (target_id) REFERENCES asm_targets(id) ON DELETE CASCADE
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS asm_targets (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  domain       TEXT NOT NULL,
  org_name     TEXT,
  scan_status  TEXT DEFAULT 'pending',   -- pending | scanning | complete | failed
  asm_score    INTEGER DEFAULT 0,        -- 0-100 (higher = more exposed)
  risk_grade   TEXT DEFAULT 'UNKNOWN',   -- A/B/C/D/F
  total_assets INTEGER DEFAULT 0,
  open_ports   INTEGER DEFAULT 0,
  expired_certs INTEGER DEFAULT 0,
  exposed_services TEXT DEFAULT '[]',
  last_scan    TEXT,
  next_scan    TEXT,
  scan_interval_hours INTEGER DEFAULT 24,
  active       INTEGER DEFAULT 1,
  created_at   TEXT DEFAULT (datetime('now')),
  updated_at   TEXT DEFAULT (datetime('now'))
);

-- From: schema_v27.sql
CREATE TABLE IF NOT EXISTS assessments (
  id              TEXT PRIMARY KEY,
  lead_id         TEXT,
  email           TEXT NOT NULL DEFAULT '',
  company         TEXT,
  domain          TEXT,
  phone           TEXT,
  plan            TEXT NOT NULL DEFAULT 'standard',  -- standard|premium|enterprise
  price_inr       REAL NOT NULL DEFAULT 9999,
  status          TEXT NOT NULL DEFAULT 'booked',
    -- booked|paid|in_progress|delivered|completed|cancelled
  payment_ref     TEXT,
  razorpay_order  TEXT,
  report_url      TEXT,
  analyst_notes   TEXT,
  delivery_sla_h  INTEGER NOT NULL DEFAULT 72,
  booked_at       INTEGER NOT NULL DEFAULT (unixepoch()),
  paid_at         INTEGER,
  started_at      INTEGER,
  delivered_at    INTEGER,
  completed_at    INTEGER,
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS audit_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT,
  api_key_id      TEXT,
  action          TEXT NOT NULL,
  resource        TEXT,
  resource_id     TEXT,
  ip              TEXT,
  user_agent      TEXT,
  status          TEXT DEFAULT 'ok',
  metadata        TEXT DEFAULT '{}',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS behavior_events (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT NOT NULL,
  event_type   TEXT NOT NULL CHECK(event_type IN (
    'login','logout','api_call','scan','download','payment','failed_login','password_change'
  )),
  ip           TEXT,
  country      TEXT,
  city         TEXT,
  hour_of_day  INTEGER,
  day_of_week  INTEGER,
  user_agent   TEXT,
  endpoint     TEXT,
  metadata     TEXT DEFAULT '{}',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_gtm_only.sql
CREATE TABLE IF NOT EXISTS billing_events (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  plan        TEXT,
  payment_id  TEXT,
  order_id    TEXT,
  event_type  TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS billing_invoices (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL DEFAULT '',
  plan           TEXT NOT NULL DEFAULT '',
  amount_inr     REAL NOT NULL DEFAULT 0,
  gst_amount     REAL NOT NULL DEFAULT 0,
  total_inr      REAL NOT NULL DEFAULT 0,
  currency       TEXT NOT NULL DEFAULT 'INR',
  status         TEXT NOT NULL DEFAULT 'pending',
  payment_method TEXT,
  transaction_id TEXT,
  license_key    TEXT,
  invoice_number TEXT,
  invoice_pdf_url TEXT,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  paid_at        INTEGER,
  metadata       TEXT DEFAULT '{}'
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS billing_license_keys (
  key             TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL DEFAULT '',
  plan            TEXT NOT NULL DEFAULT '',
  invoice_id      TEXT,
  status          TEXT NOT NULL DEFAULT 'active',
  activations     INTEGER NOT NULL DEFAULT 0,
  max_activations INTEGER NOT NULL DEFAULT 3,
  expires_at      INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS billing_paypal_orders (
  order_id    TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL DEFAULT '',
  plan        TEXT NOT NULL DEFAULT '',
  amount_usd  REAL NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'created',
  capture_id  TEXT,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  captured_at INTEGER
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS billing_recovery_queue (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL DEFAULT '',
  invoice_id    TEXT NOT NULL DEFAULT '',
  attempt       INTEGER NOT NULL DEFAULT 1,
  next_retry_at INTEGER NOT NULL DEFAULT 0,
  last_error    TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS billing_refunds (
  id          TEXT PRIMARY KEY,
  invoice_id  TEXT NOT NULL DEFAULT '',
  user_id     TEXT NOT NULL DEFAULT '',
  amount_inr  REAL NOT NULL DEFAULT 0,
  reason      TEXT,
  status      TEXT NOT NULL DEFAULT 'requested',
  approved_by TEXT,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at INTEGER
);

-- From: schema_v10.sql
CREATE TABLE IF NOT EXISTS blog_posts (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id          TEXT,
  slug            TEXT NOT NULL UNIQUE,
  title           TEXT NOT NULL,
  excerpt         TEXT,
  content         TEXT NOT NULL,
  html_content    TEXT,
  author          TEXT DEFAULT 'CYBERDUDEBIVASH AI',
  tags            TEXT,
  category        TEXT,
  seo_title       TEXT,
  seo_description TEXT,
  seo_keywords    TEXT,
  featured_image  TEXT,
  status          TEXT DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),
  published_at    TEXT,
  linkedin_posted INTEGER DEFAULT 0,
  telegram_posted INTEGER DEFAULT 0,
  twitter_posted  INTEGER DEFAULT 0,
  views           INTEGER DEFAULT 0,
  solution_cta    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v21_adaptive_brain.sql
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

-- From: schema_v21_adaptive_brain.sql
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

-- From: schema_v21_adaptive_brain.sql
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

-- From: schema_v21_adaptive_brain.sql
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

-- From: schema_v21_adaptive_brain.sql
CREATE TABLE IF NOT EXISTS brain_weights (
  user_id          TEXT     PRIMARY KEY,
  weights_json     TEXT     NOT NULL DEFAULT '{}',
  feedback_count   INTEGER  NOT NULL DEFAULT 0,
  last_updated     TEXT     NOT NULL DEFAULT (datetime('now')),
  version          INTEGER  NOT NULL DEFAULT 1
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS brand_monitors (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL,
  brand_name     TEXT NOT NULL,        -- e.g. "ACME Corp"
  primary_domain TEXT NOT NULL,        -- e.g. "acme.com"
  keywords       TEXT DEFAULT '[]',   -- JSON array of protected keywords
  scan_status    TEXT DEFAULT 'active',
  total_threats  INTEGER DEFAULT 0,
  critical_threats INTEGER DEFAULT 0,
  last_scan      TEXT,
  created_at     TEXT DEFAULT (datetime('now')),
  updated_at     TEXT DEFAULT (datetime('now'))
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS brand_threats (
  id              TEXT PRIMARY KEY,
  monitor_id      TEXT NOT NULL,
  threat_type     TEXT NOT NULL,  -- typosquatting|lookalike|impersonation|fake_social|phishing
  domain          TEXT NOT NULL,
  registered      INTEGER DEFAULT 0,  -- 1 = domain actually resolves
  registrar       TEXT,
  registered_date TEXT,
  ip_address      TEXT,
  mx_records      INTEGER DEFAULT 0,  -- 1 = has email capability (phishing risk)
  risk_score      INTEGER DEFAULT 0,  -- 0-100
  category        TEXT DEFAULT 'suspicious',  -- active_phishing|parked|suspicious|monitoring
  status          TEXT DEFAULT 'open',  -- open|investigating|resolved|ignored
  first_detected  TEXT DEFAULT (datetime('now')),
  last_checked    TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (monitor_id) REFERENCES brand_monitors(id) ON DELETE CASCADE
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS cac_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  channel         TEXT NOT NULL CHECK(channel IN ('organic','paid_search','social','referral','affiliate','telegram','direct','partner','cold_outreach')),
  campaign        TEXT,
  user_id         TEXT,
  email           TEXT,
  cost_inr        INTEGER NOT NULL DEFAULT 0,
  converted       INTEGER NOT NULL DEFAULT 0,
  plan_converted  TEXT,
  mrr_generated   INTEGER NOT NULL DEFAULT 0,
  event_date      TEXT NOT NULL DEFAULT (date('now')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v27.sql
CREATE TABLE IF NOT EXISTS ceo_kpi_snapshots (
  id            TEXT PRIMARY KEY,
  snapshot_date TEXT NOT NULL,  -- YYYY-MM-DD
  mrr_inr       REAL NOT NULL DEFAULT 0,
  arr_inr       REAL NOT NULL DEFAULT 0,
  cash_inr      REAL NOT NULL DEFAULT 0,
  customers     INTEGER NOT NULL DEFAULT 0,
  assessments   INTEGER NOT NULL DEFAULT 0,
  reports_sold  INTEGER NOT NULL DEFAULT 0,
  api_revenue   REAL NOT NULL DEFAULT 0,
  mssp_revenue  REAL NOT NULL DEFAULT 0,
  conversion_pct REAL NOT NULL DEFAULT 0,
  retention_pct  REAL NOT NULL DEFAULT 0,
  churn_pct      REAL NOT NULL DEFAULT 0,
  ltv_inr        REAL NOT NULL DEFAULT 0,
  cac_inr        REAL NOT NULL DEFAULT 0,
  pipeline_inr   REAL NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS ceo_targets (
  id            TEXT PRIMARY KEY,
  metric        TEXT NOT NULL UNIQUE,
  target_value  REAL NOT NULL DEFAULT 0,
  current_value REAL NOT NULL DEFAULT 0,
  period        TEXT NOT NULL DEFAULT 'monthly',
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS churn_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  subscription_id TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  email           TEXT,
  plan            TEXT NOT NULL,
  mrr_lost_inr    INTEGER NOT NULL DEFAULT 0,
  reason          TEXT CHECK(reason IN ('price','missing_feature','competitor','no_value','budget','technical','other','unknown')),
  reason_detail   TEXT,
  was_trial       INTEGER NOT NULL DEFAULT 0,
  tenure_days     INTEGER NOT NULL DEFAULT 0,
  churned_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS ciso_reports (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT,
  client_id       TEXT,
  report_type     TEXT NOT NULL CHECK(report_type IN ('monthly','quarterly','annual','executive','compliance','threat_landscape','incident')),
  period          TEXT NOT NULL,
  status          TEXT DEFAULT 'queued' CHECK(status IN ('queued','generating','ready','delivered','failed')),
  pdf_key         TEXT,
  pdf_url         TEXT,
  data_snapshot   TEXT DEFAULT '{}',
  email_delivered INTEGER DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at    TEXT
);

-- From: schema_v31_p0_fixes.sql
CREATE TABLE IF NOT EXISTS compliance_alignments (
  id              TEXT PRIMARY KEY,
  framework       TEXT NOT NULL,
  alignment_level TEXT NOT NULL DEFAULT 'aligned'
                    CHECK(alignment_level IN ('aligned', 'partial', 'certified')),
  scope_note      TEXT NOT NULL DEFAULT '',
  auditor         TEXT,
  cert_number     TEXT,
  valid_from      INTEGER,
  valid_until     INTEGER,
  evidence_url    TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS content_posts (
  id                       TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id                  TEXT NOT NULL,
  org_id                   TEXT,
  type                     TEXT NOT NULL DEFAULT 'blog'
                             CHECK (type IN ('blog','linkedin','telegram','executive_brief','threat_advisory')),
  title                    TEXT NOT NULL,
  body_md                  TEXT NOT NULL,
  excerpt                  TEXT,
  tags                     TEXT,
  scan_job_id              TEXT,
  module                   TEXT,
  target_summary           TEXT,
  published_to_telegram    INTEGER NOT NULL DEFAULT 0,
  published_to_linkedin    INTEGER NOT NULL DEFAULT 0,
  telegram_msg_id          TEXT,
  linkedin_post_id         TEXT,
  published_at             TEXT,
  view_count               INTEGER NOT NULL DEFAULT 0,
  created_at               TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_gtm_only.sql
CREATE TABLE IF NOT EXISTS content_queue (
  id          TEXT PRIMARY KEY,
  cve_id      TEXT,
  platform    TEXT NOT NULL,
  content     TEXT NOT NULL,
  status      TEXT DEFAULT 'pending',
  posted_at   TEXT,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS credential_rotation_log (
  id             TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id        TEXT NOT NULL,
  rotation_type  TEXT NOT NULL CHECK(rotation_type IN ('api_key','session_token','all')),
  keys_rotated   INTEGER NOT NULL DEFAULT 0,
  sessions_killed INTEGER NOT NULL DEFAULT 0,
  action_id      TEXT,
  reason         TEXT NOT NULL,
  initiated_by   TEXT NOT NULL DEFAULT 'agent',
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS crm_activities (
  id         TEXT PRIMARY KEY,
  lead_id    TEXT NOT NULL DEFAULT '',
  type       TEXT NOT NULL DEFAULT '',
  note       TEXT,
  by_user    TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v24_phaseA_FINAL.sql
CREATE TABLE IF NOT EXISTS crm_leads (
  id TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', name TEXT, company TEXT,
  sector TEXT, company_size TEXT, budget_range TEXT, urgency TEXT,
  source TEXT NOT NULL DEFAULT 'website', status TEXT NOT NULL DEFAULT 'new',
  icp_score INTEGER NOT NULL DEFAULT 0, icp_tier TEXT NOT NULL DEFAULT 'D',
  notes TEXT, assigned_to TEXT, demo_booked INTEGER NOT NULL DEFAULT 0,
  demo_at INTEGER, converted INTEGER NOT NULL DEFAULT 0, converted_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS crm_notes (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  lead_id          TEXT NOT NULL,               -- FK → crm_leads.id
  note_type        TEXT NOT NULL DEFAULT 'note' CHECK(note_type IN (
    'note', 'call', 'email', 'demo', 'proposal', 'objection', 'follow_up'
  )),
  content          TEXT NOT NULL,
  author           TEXT,                         -- user_id
  is_pinned        INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS crm_pipeline_log (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  lead_id          TEXT NOT NULL,               -- FK → crm_leads.id
  from_stage       TEXT,
  to_stage         TEXT NOT NULL,
  actor            TEXT,                         -- user_id of rep who moved it
  reason           TEXT,
  note             TEXT,
  deal_value_inr   INTEGER,                      -- snapshot at time of change
  icp_score        INTEGER,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS crq_assessments (
  id                    TEXT PRIMARY KEY,
  user_id               TEXT NOT NULL,
  org_name              TEXT NOT NULL,
  industry              TEXT,
  employee_count        INTEGER,
  revenue_usd           REAL,
  annualized_loss_exp   REAL,  -- ALE in USD
  single_loss_exp       REAL,  -- SLE in USD
  threat_scenarios      TEXT DEFAULT '[]',  -- JSON scenarios with probability
  top_risk              TEXT,
  risk_band             TEXT,  -- LOW|MEDIUM|HIGH|CRITICAL
  insurance_gap_usd     REAL,  -- recommended cyber insurance coverage gap
  control_investment    REAL,  -- recommended security investment
  roi_security_controls REAL,  -- ROI of implementing controls
  assessment_version    INTEGER DEFAULT 1,
  created_at            TEXT DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS cs_signals (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT NOT NULL,
  email           TEXT,
  signal_type     TEXT NOT NULL CHECK(signal_type IN ('churn_risk','upsell_ready','low_engagement','milestone','upgrade_trigger','renewal_due','health_drop','power_user')),
  score           REAL DEFAULT 0,
  message         TEXT,
  recommended_action TEXT,
  auto_outreach   INTEGER DEFAULT 0,
  outreach_sent_at TEXT,
  resolved        INTEGER DEFAULT 0,
  resolved_at     TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase2.sql
CREATE TABLE IF NOT EXISTS cti_actors (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  aliases           TEXT DEFAULT '[]',
  nation_state      TEXT,
  motivation        TEXT,
  sophistication    TEXT DEFAULT 'UNKNOWN',
  active_since      TEXT,
  known_techniques  TEXT DEFAULT '[]',
  known_tools       TEXT DEFAULT '[]',
  target_sectors    TEXT DEFAULT '[]',
  description       TEXT,
  mitre_group_id    TEXT,
  threat_level      TEXT DEFAULT 'MEDIUM',
  confidence_score  INTEGER DEFAULT 50,
  last_active       TEXT,
  source            TEXT DEFAULT 'sentinel_apex',
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase2.sql
CREATE TABLE IF NOT EXISTS cti_iocs (
  id               TEXT PRIMARY KEY,
  ioc_type         TEXT NOT NULL CHECK(ioc_type IN ('IP','DOMAIN','HASH_MD5','HASH_SHA1','HASH_SHA256','URL','EMAIL','CVE','BITCOIN_ADDR')),
  value            TEXT NOT NULL,
  severity         TEXT DEFAULT 'MEDIUM' CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  source           TEXT DEFAULT 'manual',
  first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen        TEXT NOT NULL DEFAULT (datetime('now')),
  last_checked     TEXT,
  tags             TEXT DEFAULT '[]',
  related_actor_id TEXT REFERENCES cti_actors(id),
  related_campaign TEXT,
  confidence       INTEGER DEFAULT 50,
  reputation_score INTEGER DEFAULT 0,
  geo_country      TEXT,
  geo_asn          TEXT,
  whois_snapshot   TEXT,
  is_active        INTEGER DEFAULT 1,
  false_positive   INTEGER DEFAULT 0,
  notes            TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS cti_watchlist_entries (
  id           TEXT PRIMARY KEY,
  watchlist_id TEXT NOT NULL,
  org_id       TEXT NOT NULL DEFAULT 'default',
  ioc_value    TEXT NOT NULL,
  ioc_type     TEXT NOT NULL,
  confidence   INTEGER NOT NULL DEFAULT 70,
  tags         TEXT,
  added_by     TEXT,
  added_at     TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(watchlist_id, ioc_value)
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS cti_watchlists (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL DEFAULT 'default',
  name           TEXT NOT NULL,
  description    TEXT,
  ioc_types      TEXT NOT NULL DEFAULT '["ip","domain","hash","url","email"]',
  alert_on_match INTEGER NOT NULL DEFAULT 1,
  match_count    INTEGER NOT NULL DEFAULT 0,
  created_by     TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v10.sql
CREATE TABLE IF NOT EXISTS custom_solution_requests (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id         TEXT,
  email           TEXT NOT NULL,
  cve_id          TEXT,
  solution_types  TEXT,
  tech_stack      TEXT,
  description     TEXT NOT NULL,
  budget_range    TEXT,
  deadline        TEXT,
  status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewing','quoted','in_progress','delivered','closed')),
  quote_inr       INTEGER,
  quote_usd       INTEGER,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS customer_health (
  id                 TEXT PRIMARY KEY,
  org_id             TEXT UNIQUE NOT NULL DEFAULT 'default',
  health_score       INTEGER DEFAULT 50 CHECK(health_score BETWEEN 0 AND 100),
  adoption_score     INTEGER DEFAULT 0  CHECK(adoption_score BETWEEN 0 AND 100),
  churn_risk         TEXT DEFAULT 'NONE' CHECK(churn_risk IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  expansion_score    INTEGER DEFAULT 0  CHECK(expansion_score BETWEEN 0 AND 100),
  maturity_index     TEXT DEFAULT 'STARTER' CHECK(maturity_index IN ('STARTER','DEVELOPING','MATURE','CHAMPION')),
  last_scan_days_ago INTEGER DEFAULT 999,
  total_scans_30d    INTEGER DEFAULT 0,
  active_features    TEXT DEFAULT '[]',
  risk_triggers      TEXT DEFAULT '[]',
  playbook_id        TEXT,
  computed_at        TEXT NOT NULL DEFAULT (datetime('now')),
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS customer_ltv (
  user_id         TEXT PRIMARY KEY,
  email           TEXT,
  total_revenue_inr INTEGER NOT NULL DEFAULT 0,
  sub_revenue_inr INTEGER NOT NULL DEFAULT 0,
  marketplace_revenue_inr INTEGER NOT NULL DEFAULT 0,
  api_revenue_inr INTEGER NOT NULL DEFAULT 0,
  report_revenue_inr INTEGER NOT NULL DEFAULT 0,
  payment_count   INTEGER NOT NULL DEFAULT 0,
  first_payment_at TEXT,
  last_payment_at TEXT,
  current_plan    TEXT DEFAULT 'FREE',
  predicted_ltv_inr INTEGER NOT NULL DEFAULT 0,
  ltv_segment     TEXT DEFAULT 'low' CHECK(ltv_segment IN ('low','medium','high','champion')),
  churn_risk_score REAL NOT NULL DEFAULT 0,
  upsell_score    REAL NOT NULL DEFAULT 0,
  health_score    INTEGER NOT NULL DEFAULT 50,
  last_active_at  TEXT,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v27.sql
CREATE TABLE IF NOT EXISTS customer_portal_sessions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL DEFAULT '',
  email       TEXT NOT NULL DEFAULT '',
  token       TEXT UNIQUE NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS cve_correlations (
  cve_id         TEXT PRIMARY KEY,
  related_cves   TEXT DEFAULT '[]',
  threat_actor   TEXT,
  campaign       TEXT,
  mitre_tactics  TEXT DEFAULT '[]',
  confidence     INTEGER DEFAULT 0,
  correlated_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS deal_pipeline (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  company         TEXT NOT NULL,
  contact_name    TEXT,
  contact_email   TEXT NOT NULL,
  contact_phone   TEXT,
  contact_title   TEXT,
  company_size    TEXT,
  industry        TEXT,
  country         TEXT DEFAULT 'IN',
  website         TEXT,
  stage           TEXT NOT NULL DEFAULT 'lead' CHECK(stage IN ('lead','qualified','demo','proposal','negotiation','closed_won','closed_lost')),
  deal_value_inr  INTEGER NOT NULL DEFAULT 0,
  arr_potential   INTEGER NOT NULL DEFAULT 0,
  plan_target     TEXT DEFAULT 'ENTERPRISE',
  icp_score       INTEGER NOT NULL DEFAULT 0,
  security_maturity INTEGER NOT NULL DEFAULT 0,
  probability_pct INTEGER NOT NULL DEFAULT 0,
  source          TEXT,
  owner           TEXT DEFAULT 'bivash',
  next_action     TEXT,
  next_action_date TEXT,
  demo_booked_at  TEXT,
  proposal_sent_at TEXT,
  closed_at       TEXT,
  lost_reason     TEXT,
  notes           TEXT,
  tags            TEXT DEFAULT '[]',
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS defense_actions (
  id             TEXT    PRIMARY KEY,
  threat_id      TEXT    REFERENCES threat_intel(id) ON DELETE SET NULL,
  action_type    TEXT    NOT NULL,
  target         TEXT,
  status         TEXT    NOT NULL DEFAULT 'pending',
  confidence     REAL    NOT NULL DEFAULT 0.5,
  cvss_trigger   REAL,
  execution_mode TEXT    NOT NULL DEFAULT 'ASSISTED',
  triggered_by   TEXT    NOT NULL DEFAULT 'AUTO',
  approved_by    TEXT,
  executed_at    TEXT,
  result_summary TEXT,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v22_production_fix.sql
CREATE TABLE IF NOT EXISTS defense_purchases (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  solution_id       TEXT NOT NULL,
  user_id           TEXT,
  email             TEXT,
  payment_id        TEXT,
  order_id          TEXT,
  amount_inr        INTEGER,
  plan              TEXT DEFAULT 'per_product',
  status            TEXT NOT NULL DEFAULT 'pending',
  download_token    TEXT,
  download_expires  TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v22_production_fix.sql
CREATE TABLE IF NOT EXISTS defense_solutions (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id            TEXT NOT NULL,
  title             TEXT NOT NULL,
  description       TEXT NOT NULL,
  category          TEXT NOT NULL DEFAULT 'sigma_rule',
  price_inr         INTEGER NOT NULL DEFAULT 499,
  price_usd         INTEGER NOT NULL DEFAULT 6,
  demand_score      REAL NOT NULL DEFAULT 0.5,
  severity          TEXT NOT NULL DEFAULT 'MEDIUM',
  cvss_score        REAL,
  preview           TEXT NOT NULL DEFAULT '',
  full_content_key  TEXT NOT NULL DEFAULT '',
  difficulty        TEXT NOT NULL DEFAULT 'INTERMEDIATE',
  apt_groups        TEXT,
  mitre_techniques  TEXT,
  affected_systems  TEXT,
  purchase_count    INTEGER NOT NULL DEFAULT 0,
  view_count        INTEGER NOT NULL DEFAULT 0,
  is_active         INTEGER NOT NULL DEFAULT 1,
  is_featured       INTEGER NOT NULL DEFAULT 0,
  badge             TEXT,
  generated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS delivery_tokens (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  payment_id       TEXT NOT NULL UNIQUE,        -- payment ref from CDB_PAY
  product_id       TEXT NOT NULL,               -- e.g. SOC_PLAYBOOK_2026
  product_name     TEXT NOT NULL,               -- human-readable label
  product_type     TEXT NOT NULL CHECK(product_type IN (
    'platform_access', 'report_access', 'training', 'bundle'
  )),
  payer_email      TEXT NOT NULL,
  user_id          TEXT,                         -- NULL for guest purchases
  token_hash       TEXT NOT NULL UNIQUE,         -- SHA-256 of cdb_dlv_ token
  delivery_method  TEXT NOT NULL CHECK(delivery_method IN (
    'instant_access', 'whatsapp_delivery', 'email_delivery', 'download_link'
  )),
  access_details   TEXT NOT NULL DEFAULT '{}',  -- JSON: links, instructions, files
  custom_notes     TEXT,
  status           TEXT NOT NULL DEFAULT 'activated' CHECK(status IN (
    'activated', 'expired', 'revoked', 'consumed'
  )),
  activated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT NOT NULL,               -- ISO8601 string
  access_count     INTEGER NOT NULL DEFAULT 0,
  last_accessed_at TEXT
);

-- From: schema_gtm_only.sql
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

-- From: schema_gtm_only.sql
CREATE TABLE IF NOT EXISTS email_tracking (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  sequence_id TEXT,
  step        INTEGER DEFAULT 0,
  event       TEXT NOT NULL,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v10.sql
CREATE TABLE IF NOT EXISTS enterprise_leads (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  company_name    TEXT NOT NULL,
  contact_name    TEXT,
  email           TEXT NOT NULL,
  phone           TEXT,
  domain          TEXT,
  requirements    TEXT,
  package_interest TEXT DEFAULT 'enterprise',
  team_size       TEXT,
  industry        TEXT,
  annual_budget   TEXT,
  urgency         TEXT DEFAULT 'normal' CHECK(urgency IN ('immediate','urgent','normal','exploratory')),
  source          TEXT DEFAULT 'website',
  status          TEXT DEFAULT 'new' CHECK(status IN ('new','contacted','qualified','proposal','closed_won','closed_lost')),
  notes           TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS expansion_scores (
  org_id           TEXT PRIMARY KEY,
  expansion_score  INTEGER NOT NULL DEFAULT 0,
  segment          TEXT NOT NULL DEFAULT 'STARTER',
  recommended_tier TEXT,
  primary_signal   TEXT,
  signals_json     TEXT,
  upsell_ready     INTEGER NOT NULL DEFAULT 0,
  last_activity    TEXT,
  computed_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v10.sql
CREATE TABLE IF NOT EXISTS fomo_events (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type      TEXT NOT NULL CHECK(event_type IN ('purchase','scan','view','download','signup','upgrade')),
  entity_type     TEXT,
  entity_id       TEXT,
  display_name    TEXT,
  ip_country      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_gtm_only.sql
CREATE TABLE IF NOT EXISTS funnel_events (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  stage       TEXT NOT NULL,
  meta        TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v38_governor.sql
CREATE TABLE IF NOT EXISTS governor_events (
  id           TEXT PRIMARY KEY,
  subsystem    TEXT NOT NULL,
  status       TEXT NOT NULL,  -- HEALTHY | DEGRADED | CRITICAL | STALLED | REPAIRED | DRIFTED
  action       TEXT,           -- repair action taken (if any)
  detail       TEXT,           -- JSON or text details
  duration_ms  INTEGER DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_gtm_only.sql
CREATE TABLE IF NOT EXISTS growth_analytics (
  id          TEXT PRIMARY KEY,
  event       TEXT NOT NULL,
  properties  TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS gumroad_licenses (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  license_key       TEXT UNIQUE NOT NULL,
  product_permalink TEXT NOT NULL,
  product_name      TEXT NOT NULL,
  buyer_email       TEXT NOT NULL,
  buyer_name        TEXT,
  user_id           TEXT,
  tier_granted      TEXT NOT NULL DEFAULT 'PRO',
  credits_granted   INTEGER NOT NULL DEFAULT 0,
  status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','disabled','refunded')),
  purchase_id       TEXT,
  sale_id           TEXT,
  activated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at        TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS hunting_alerts (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  severity   TEXT NOT NULL,
  message    TEXT NOT NULL,
  evidence   TEXT DEFAULT '{}',
  resolved   INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS icp_scores (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  deal_id         TEXT,
  email           TEXT NOT NULL,
  company         TEXT,
  industry_fit    INTEGER DEFAULT 0,
  size_fit        INTEGER DEFAULT 0,
  tech_stack_fit  INTEGER DEFAULT 0,
  pain_signal     INTEGER DEFAULT 0,
  budget_signal   INTEGER DEFAULT 0,
  urgency_signal  INTEGER DEFAULT 0,
  total_score     INTEGER DEFAULT 0,
  tier            TEXT DEFAULT 'C' CHECK(tier IN ('A','B','C','D')),
  enrichment_data TEXT DEFAULT '{}',
  scored_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS ingestion_runs (
  id          TEXT PRIMARY KEY,
  ran_at      TEXT DEFAULT (datetime('now')),
  sources     TEXT DEFAULT '[]',
  inserted    INTEGER DEFAULT 0,
  updated     INTEGER DEFAULT 0,
  errors      TEXT DEFAULT '[]',
  duration_ms INTEGER,
  success     INTEGER DEFAULT 1
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS invoices (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  invoice_number  TEXT NOT NULL UNIQUE,
  customer_id     TEXT NOT NULL,
  user_id         TEXT,
  email           TEXT NOT NULL,
  company         TEXT,
  gstin           TEXT,
  billing_address TEXT DEFAULT '{}',
  line_items      TEXT NOT NULL DEFAULT '[]',
  subtotal_inr    INTEGER NOT NULL DEFAULT 0,
  gst_rate        REAL NOT NULL DEFAULT 18.0,
  gst_amount_inr  INTEGER NOT NULL DEFAULT 0,
  total_inr       INTEGER NOT NULL DEFAULT 0,
  currency        TEXT NOT NULL DEFAULT 'INR',
  status          TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','paid','overdue','cancelled','void')),
  payment_id      TEXT,
  payment_method  TEXT,
  due_date        TEXT,
  paid_at         TEXT,
  sent_at         TEXT,
  pdf_key         TEXT,
  notes           TEXT,
  period_start    TEXT,
  period_end      TEXT,
  subscription_id TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS ioc_enrichment_cache (
  id            TEXT PRIMARY KEY,        -- sha256(type:value)
  ioc_type      TEXT NOT NULL,           -- ip | domain | hash | email | url
  ioc_value     TEXT NOT NULL,
  verdict       TEXT NOT NULL DEFAULT 'unknown', -- clean | suspicious | malicious | unknown
  risk_score    INTEGER DEFAULT 0,       -- 0-100
  sources_hit   TEXT DEFAULT '[]',       -- JSON array of source names that returned data
  raw_data      TEXT DEFAULT '{}',       -- JSON: full enrichment details
  tags          TEXT DEFAULT '[]',       -- JSON array: ['C2','Phishing','Botnet',...]
  first_seen    TEXT,
  last_seen     TEXT,
  country       TEXT,
  asn           TEXT,
  org           TEXT,
  abuse_score   INTEGER DEFAULT 0,       -- AbuseIPDB confidence score
  vt_positives  INTEGER DEFAULT 0,       -- VirusTotal malicious detections
  internal_hits INTEGER DEFAULT 0,       -- matches in our own threat_intel table
  ttl_expires   TEXT NOT NULL,           -- cache expiry datetime
  created_at    TEXT DEFAULT (datetime('now')),
  updated_at    TEXT DEFAULT (datetime('now'))
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS ioc_registry (
  id         TEXT PRIMARY KEY,
  intel_id   TEXT NOT NULL,
  type       TEXT NOT NULL,
  value      TEXT NOT NULL,
  confidence REAL DEFAULT 0.8,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (intel_id) REFERENCES threat_intel(id) ON DELETE CASCADE
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS ioc_requests (
  id         TEXT PRIMARY KEY,
  user_id    TEXT,
  api_key_id TEXT,
  ioc_type   TEXT NOT NULL,
  ioc_value  TEXT NOT NULL,
  verdict    TEXT,
  latency_ms INTEGER,
  from_cache INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS ip_blocklist (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  ip          TEXT NOT NULL UNIQUE,
  reason      TEXT NOT NULL,
  threat_type TEXT DEFAULT 'automated_agent',
  risk_level  TEXT NOT NULL DEFAULT 'HIGH',
  action_id   TEXT REFERENCES agent_actions(id),
  blocked_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT,
  is_active   INTEGER NOT NULL DEFAULT 1,
  block_count INTEGER NOT NULL DEFAULT 1,
  last_seen   TEXT
);

-- From: schema_gtm_only.sql
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

-- From: schema_v27.sql
CREATE TABLE IF NOT EXISTS licenses (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL DEFAULT '',
  email         TEXT NOT NULL DEFAULT '',
  product       TEXT NOT NULL DEFAULT '',  -- 'scanner_report'|'assessment'|'subscription'|'api'
  license_key   TEXT UNIQUE NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',  -- active|revoked|expired
  activations   INTEGER NOT NULL DEFAULT 0,
  max_activations INTEGER NOT NULL DEFAULT 1,
  expires_at    INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS login_attempts (
  id          TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email       TEXT    NOT NULL,
  ip_address  TEXT,
  success     INTEGER NOT NULL DEFAULT 0,
  attempted_at TEXT   NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_mcp_learning.sql
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

-- From: schema_mcp_learning.sql
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

-- From: schema_revenue_autopilot.sql
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

-- From: schema_mcp_learning.sql
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

-- From: schema_mcp_learning.sql
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

-- From: schema_revenue_autopilot.sql
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

-- From: schema_revenue_autopilot.sql
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

-- From: schema_revenue_autopilot.sql
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

-- From: schema_v29.sql
CREATE TABLE IF NOT EXISTS mcp_security_scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT UNIQUE NOT NULL,
  server_name  TEXT,
  server_url   TEXT,
  risk_score   INTEGER,
  risk_level   TEXT,
  grade        TEXT,
  vuln_count   INTEGER DEFAULT 0,
  result_json  TEXT,
  user_email   TEXT,
  scanned_at   TEXT NOT NULL,
  unlocked_at  TEXT,
  unlock_token TEXT
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS monitor_configs (
  id                   TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id              TEXT NOT NULL,
  org_id               TEXT,
  name                 TEXT NOT NULL,
  module               TEXT NOT NULL
                         CHECK (module IN ('domain','ai','redteam','identity','compliance')),
  target_json          TEXT NOT NULL,
  schedule             TEXT NOT NULL DEFAULT 'daily'
                         CHECK (schedule IN ('hourly','daily','weekly','monthly')),
  enabled              INTEGER NOT NULL DEFAULT 1,
  alert_on_drift       INTEGER NOT NULL DEFAULT 1,
  alert_on_critical    INTEGER NOT NULL DEFAULT 1,
  drift_threshold      INTEGER NOT NULL DEFAULT 10,
  baseline_risk_score  INTEGER,
  last_scan_score      INTEGER,
  last_run_at          TEXT,
  next_run_at          TEXT,
  run_count            INTEGER NOT NULL DEFAULT 0,
  fail_count           INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS monitor_results (
  id                  TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  config_id           TEXT NOT NULL,
  user_id             TEXT NOT NULL,
  module              TEXT NOT NULL,
  target_summary      TEXT,
  risk_score          INTEGER NOT NULL,
  risk_level          TEXT NOT NULL,
  findings_count      INTEGER NOT NULL DEFAULT 0,
  critical_count      INTEGER NOT NULL DEFAULT 0,
  high_count          INTEGER NOT NULL DEFAULT 0,
  new_findings_count  INTEGER NOT NULL DEFAULT 0,
  resolved_count      INTEGER NOT NULL DEFAULT 0,
  drift_delta         INTEGER NOT NULL DEFAULT 0,
  drift_type          TEXT NOT NULL DEFAULT 'none'
                        CHECK (drift_type IN ('improved','degraded','stable','new','none')),
  ai_narrative        TEXT,
  alert_sent          INTEGER NOT NULL DEFAULT 0,
  scan_result_r2_key  TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS mrr_snapshots (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  snapshot_date   TEXT NOT NULL DEFAULT (date('now')),
  mrr_inr         INTEGER NOT NULL DEFAULT 0,
  arr_inr         INTEGER NOT NULL DEFAULT 0,
  new_mrr         INTEGER NOT NULL DEFAULT 0,
  expansion_mrr   INTEGER NOT NULL DEFAULT 0,
  contraction_mrr INTEGER NOT NULL DEFAULT 0,
  churned_mrr     INTEGER NOT NULL DEFAULT 0,
  net_new_mrr     INTEGER NOT NULL DEFAULT 0,
  active_subs     INTEGER NOT NULL DEFAULT 0,
  trial_subs      INTEGER NOT NULL DEFAULT 0,
  free_users      INTEGER NOT NULL DEFAULT 0,
  starter_count   INTEGER NOT NULL DEFAULT 0,
  pro_count       INTEGER NOT NULL DEFAULT 0,
  enterprise_count INTEGER NOT NULL DEFAULT 0,
  mssp_count      INTEGER NOT NULL DEFAULT 0,
  trial_to_paid_rate REAL NOT NULL DEFAULT 0,
  churn_rate      REAL NOT NULL DEFAULT 0,
  nrr             REAL NOT NULL DEFAULT 100,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS mssp_billing (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  mssp_user_id    TEXT NOT NULL,
  client_id       TEXT NOT NULL,
  period          TEXT NOT NULL DEFAULT '',
  mrr_inr         INTEGER DEFAULT 0,
  scans_used      INTEGER DEFAULT 0,
  api_calls_used  INTEGER DEFAULT 0,
  reports_generated INTEGER DEFAULT 0,
  invoice_id      TEXT,
  status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','invoiced','paid','overdue')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24_phaseA_FINAL.sql
CREATE TABLE IF NOT EXISTS mssp_clients (
  id TEXT PRIMARY KEY, partner_id TEXT NOT NULL DEFAULT '', company TEXT NOT NULL DEFAULT '',
  domain TEXT, sector TEXT, contact_email TEXT, status TEXT NOT NULL DEFAULT 'active',
  open_alerts INTEGER NOT NULL DEFAULT 0, last_scan_at INTEGER,
  onboarded_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);

-- From: schema_phase2.sql
CREATE TABLE IF NOT EXISTS mssp_customers (
  id               TEXT PRIMARY KEY,
  org_name         TEXT NOT NULL,
  org_slug         TEXT UNIQUE NOT NULL,
  contact_name     TEXT,
  contact_email    TEXT,
  tier             TEXT DEFAULT 'starter' CHECK(tier IN ('starter','pro','enterprise','custom')),
  status           TEXT DEFAULT 'active' CHECK(status IN ('active','inactive','onboarding','offboarding')),
  risk_score       INTEGER DEFAULT 50,
  compliance_score INTEGER DEFAULT 50,
  assigned_users   TEXT DEFAULT '[]',
  config_json      TEXT DEFAULT '{}',
  notes            TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  last_activity_at TEXT,
  contract_start   TEXT,
  contract_end     TEXT,
  mrr_cents        INTEGER DEFAULT 0,
  partner_id       TEXT  -- P0 #1: owning partner for per-tenant isolation (schema_v40)
);
CREATE INDEX IF NOT EXISTS idx_mssp_customers_partner ON mssp_customers(partner_id);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS mssp_partners (
  id            TEXT PRIMARY KEY,
  company       TEXT NOT NULL DEFAULT '',
  contact_email TEXT NOT NULL UNIQUE,
  tier          TEXT NOT NULL DEFAULT 'RESELLER',
  plan          TEXT NOT NULL DEFAULT 'reseller',
  brand_name    TEXT,
  custom_domain TEXT,
  primary_color TEXT DEFAULT '#00d4ff',
  api_key       TEXT UNIQUE,
  client_count  INTEGER NOT NULL DEFAULT 0,
  max_clients   INTEGER NOT NULL DEFAULT 10,
  margin_pct    REAL NOT NULL DEFAULT 20.0,
  status        TEXT NOT NULL DEFAULT 'pending',
  onboarded_at  INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS mssp_tenant_audit (
  id            TEXT PRIMARY KEY,
  mssp_org_id   TEXT NOT NULL,
  tenant_org_id TEXT NOT NULL,
  action        TEXT NOT NULL,
  resource      TEXT,
  resource_type TEXT,
  actor_user_id TEXT,
  actor_role    TEXT,
  ip_country    TEXT,
  details_json  TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v33_mythos_god_mode.sql
CREATE TABLE IF NOT EXISTS mythos_god_mode_runs (
  id               TEXT PRIMARY KEY,
  status           TEXT NOT NULL DEFAULT 'RUNNING',
  trigger_source   TEXT NOT NULL DEFAULT 'cron',   -- cron | api | manual
  phases_complete  INTEGER NOT NULL DEFAULT 0,
  phases_errored   INTEGER NOT NULL DEFAULT 0,
  intel_processed  INTEGER NOT NULL DEFAULT 0,
  tools_generated  INTEGER NOT NULL DEFAULT 0,
  tools_published  INTEGER NOT NULL DEFAULT 0,
  threat_level     TEXT    NOT NULL DEFAULT 'MODERATE',
  posture_score    INTEGER NOT NULL DEFAULT 0,
  posture_grade    TEXT    NOT NULL DEFAULT 'N/A',
  mitre_ttps       INTEGER NOT NULL DEFAULT 0,
  hunt_sessions    INTEGER NOT NULL DEFAULT 0,
  zt_anomalies     INTEGER NOT NULL DEFAULT 0,
  compliance_risk  INTEGER NOT NULL DEFAULT 0,
  soar_rules       INTEGER NOT NULL DEFAULT 0,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  run_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v32_mythos_runs.sql
CREATE TABLE IF NOT EXISTS mythos_runs (
  id               TEXT    PRIMARY KEY,
  status           TEXT    NOT NULL DEFAULT 'completed'
                             CHECK(status IN ('running','completed','failed','partial')),
  tools_generated  INTEGER NOT NULL DEFAULT 0,
  tools_published  INTEGER NOT NULL DEFAULT 0,
  tools_failed     INTEGER NOT NULL DEFAULT 0,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  intel_count      INTEGER NOT NULL DEFAULT 0,
  trigger_source   TEXT    NOT NULL DEFAULT 'cron',  -- 'cron'|'manual_admin'|'ui-p13'
  error_message    TEXT,
  run_at           TEXT    NOT NULL DEFAULT (datetime('now'))  -- ISO-8601 from new Date().toISOString()
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS notification_log (
  id                  TEXT PRIMARY KEY,
  recipient_id        TEXT NOT NULL,
  org_id              TEXT DEFAULT 'default',
  channel             TEXT NOT NULL CHECK(channel IN ('EMAIL','INAPP','SLACK','TEAMS','WEBHOOK')),
  event_type          TEXT NOT NULL,
  subject             TEXT,
  body_preview        TEXT,
  status              TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING','SENT','FAILED','SKIPPED')),
  delivery_attempts   INTEGER DEFAULT 0,
  error_message       TEXT,
  sent_at             TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id               TEXT PRIMARY KEY,
  org_id                TEXT DEFAULT 'default',
  email_enabled         INTEGER DEFAULT 1,
  inapp_enabled         INTEGER DEFAULT 1,
  slack_webhook         TEXT,
  teams_webhook         TEXT,
  custom_webhook        TEXT,
  webhook_secret        TEXT,
  event_subscriptions   TEXT DEFAULT '["scan.critical","case.created","case.escalated","health.churn"]',
  escalation_delay_min  INTEGER DEFAULT 30,
  quiet_hours_json      TEXT DEFAULT '{}',
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS org_events (
  id          TEXT    PRIMARY KEY,
  org_id      TEXT    NOT NULL,
  event_type  TEXT    NOT NULL,
  module      TEXT,
  severity    TEXT,
  title       TEXT    NOT NULL,
  detail      TEXT,
  ip_address  TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS org_members (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  org_id      TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'MEMBER'
                CHECK (role IN ('OWNER','ADMIN','ANALYST','MEMBER','VIEWER')),
  invited_by  TEXT,
  invite_email TEXT,
  status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','invited','suspended')),
  joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (org_id, user_id)
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS p0_exceptions (
  id                  TEXT PRIMARY KEY,
  entry_id            TEXT NOT NULL,
  trigger_reason      TEXT NOT NULL
                        CHECK(trigger_reason IN ('active_exploitation_flag',
                                                 'cisa_kev_flag',
                                                 'cvss_9_threshold',
                                                 'policy_enforcement')),
  original_severity   TEXT NOT NULL,
  corrected_severity  TEXT NOT NULL
                        CHECK(corrected_severity IN ('HIGH', 'CRITICAL')),
  cvss_score          REAL,
  active_exploitation INTEGER NOT NULL DEFAULT 0 CHECK(active_exploitation IN (0,1)),
  cisa_kev            INTEGER NOT NULL DEFAULT 0 CHECK(cisa_kev IN (0,1)),
  logged_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS payment_recovery (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  subscription_id TEXT,
  invoice_id      TEXT,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  failure_reason  TEXT,
  attempt_count   INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 3,
  next_retry_at   TEXT,
  last_attempt_at TEXT,
  resolved        INTEGER NOT NULL DEFAULT 0,
  resolved_at     TEXT,
  recovery_method TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','retrying','resolved','abandoned')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS payments (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id              TEXT    REFERENCES users(id) ON DELETE SET NULL,
  scan_id              TEXT,
  module               TEXT    NOT NULL,
  target               TEXT    NOT NULL,
  amount               INTEGER NOT NULL,          -- paise (INR × 100)
  currency             TEXT    NOT NULL DEFAULT 'INR',
  razorpay_order_id    TEXT    UNIQUE,
  razorpay_payment_id  TEXT,
  razorpay_signature   TEXT,
  status               TEXT    NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','paid','failed','refunded')),
  plan                 TEXT    NOT NULL DEFAULT 'pay_per_report',
  report_token         TEXT,
  ip                   TEXT,
  email                TEXT,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  paid_at              TEXT
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS paypal_transactions (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  paypal_order_id TEXT NOT NULL UNIQUE,
  paypal_payer_id TEXT,
  user_id         TEXT,
  email           TEXT,
  amount_usd      REAL NOT NULL DEFAULT 0,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  currency        TEXT NOT NULL DEFAULT 'USD',
  plan            TEXT,
  product         TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','completed','cancelled','failed')),
  completed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v22_production_fix.sql
CREATE TABLE IF NOT EXISTS platform_counters (
  key        TEXT PRIMARY KEY,
  value      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS platform_metrics (
  key         TEXT PRIMARY KEY,
  value_int   INTEGER,
  value_text  TEXT,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS platform_metrics_snapshots (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL DEFAULT 'default',
  scans_today     INTEGER NOT NULL DEFAULT 0,
  scans_30d       INTEGER NOT NULL DEFAULT 0,
  critical_cves   INTEGER NOT NULL DEFAULT 0,
  open_cases      INTEGER NOT NULL DEFAULT 0,
  critical_cases  INTEGER NOT NULL DEFAULT 0,
  active_threats  INTEGER NOT NULL DEFAULT 0,
  threat_actors   INTEGER NOT NULL DEFAULT 0,
  customer_count  INTEGER NOT NULL DEFAULT 0,
  health_score    INTEGER NOT NULL DEFAULT 100,
  platform_status TEXT NOT NULL DEFAULT 'operational',
  mrr             REAL NOT NULL DEFAULT 0,
  arr             REAL NOT NULL DEFAULT 0,
  budget_alert    TEXT DEFAULT NULL,
  computed_at     TEXT NOT NULL DEFAULT (datetime('now')),
  valid_until     TEXT NOT NULL,
  UNIQUE(org_id)
);

-- From: schema_gtm_only.sql
CREATE TABLE IF NOT EXISTS pricing_experiments (
  id          TEXT PRIMARY KEY,
  variant     TEXT NOT NULL,
  email       TEXT,
  converted   INTEGER DEFAULT 0,
  revenue_inr INTEGER DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS product_pipeline (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  cve_id          TEXT NOT NULL,
  cve_title       TEXT,
  cvss_score      REAL DEFAULT 0,
  severity        TEXT DEFAULT 'MEDIUM',
  status          TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','analyzing','generating','validating','published','failed')),
  products_queued TEXT DEFAULT '[]',
  products_done   TEXT DEFAULT '[]',
  error           TEXT,
  triggered_by    TEXT DEFAULT 'cron',
  started_at      TEXT,
  completed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24_phaseA_FINAL.sql
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY, opportunity_id TEXT, company TEXT NOT NULL DEFAULT '',
  contact_email TEXT, sector TEXT, org_size TEXT, package TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'enterprise', status TEXT NOT NULL DEFAULT 'draft',
  html_content TEXT, pdf_url TEXT, total_inr REAL NOT NULL DEFAULT 0,
  gst_inr REAL NOT NULL DEFAULT 0, sent_at INTEGER, viewed_at INTEGER, accepted_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), metadata TEXT DEFAULT '{}'
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS rate_limit_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  identifier      TEXT NOT NULL,
  window          TEXT NOT NULL,
  count           INTEGER DEFAULT 1,
  blocked         INTEGER DEFAULT 0,
  last_hit        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS rate_limit_state (
  key        TEXT PRIMARY KEY,
  count      INTEGER NOT NULL DEFAULT 1,
  window_end TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v27.sql
CREATE TABLE IF NOT EXISTS refund_requests (
  id            TEXT PRIMARY KEY,
  user_id       TEXT,
  email         TEXT NOT NULL DEFAULT '',
  payment_ref   TEXT NOT NULL DEFAULT '',
  amount_inr    REAL NOT NULL DEFAULT 0,
  reason        TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',
    -- pending|approved|rejected|processed
  admin_note    TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at   INTEGER
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS refunds (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  payment_id      TEXT NOT NULL,
  invoice_id      TEXT,
  user_id         TEXT,
  email           TEXT,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  reason          TEXT DEFAULT 'customer_request' CHECK(reason IN ('customer_request','duplicate','fraud','service_failure','other')),
  reason_detail   TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','completed','failed','rejected')),
  razorpay_refund_id TEXT,
  stripe_refund_id TEXT,
  initiated_by    TEXT DEFAULT 'customer',
  processed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_gtm_only.sql
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

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS release_notes (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  version         TEXT NOT NULL,
  title           TEXT NOT NULL,
  type            TEXT NOT NULL DEFAULT 'feature' CHECK(type IN ('feature','fix','security','improvement','breaking')),
  description     TEXT NOT NULL,
  details         TEXT DEFAULT '[]',
  published_at    TEXT NOT NULL DEFAULT (datetime('now')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS renewal_queue (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  subscription_id TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  email           TEXT NOT NULL,
  plan            TEXT NOT NULL,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  renewal_date    TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'upcoming' CHECK(status IN ('upcoming','processing','renewed','failed','churned')),
  notified_at     TEXT,
  renewed_at      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS report_access (
  id                   TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  scan_id              TEXT,
  payment_id           TEXT    REFERENCES payments(id) ON DELETE CASCADE,
  user_id              TEXT    REFERENCES users(id) ON DELETE SET NULL,
  token                TEXT    NOT NULL UNIQUE,
  module               TEXT    NOT NULL,
  r2_key               TEXT,
  expires_at           TEXT    NOT NULL,
  downloaded_count     INTEGER NOT NULL DEFAULT 0,
  last_downloaded_at   TEXT,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS report_jobs (
  id                  TEXT PRIMARY KEY,
  report_type         TEXT NOT NULL CHECK(report_type IN ('SECURITY_POSTURE','BOARD','MSSP','CTI','COMPLIANCE','AI_SECURITY')),
  format              TEXT DEFAULT 'HTML' CHECK(format IN ('HTML','PDF','JSON')),
  status              TEXT DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','GENERATING','READY','FAILED','DELIVERED')),
  org_id              TEXT NOT NULL DEFAULT 'default',
  created_by          TEXT NOT NULL DEFAULT 'system',
  config_json         TEXT DEFAULT '{}',
  output_r2_key       TEXT,
  download_token      TEXT,
  download_expires_at TEXT,
  scheduled_cron      TEXT,
  last_run_at         TEXT,
  delivered_to        TEXT DEFAULT '[]',
  error_message       TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at        TEXT
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS revenue_events (
  id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  source     TEXT NOT NULL
               CHECK (source IN ('razorpay','gumroad','affiliate','subscription','api_credits')),
  amount_inr REAL NOT NULL DEFAULT 0,
  amount_usd REAL NOT NULL DEFAULT 0,
  user_id    TEXT,
  email      TEXT,
  product    TEXT,
  reference  TEXT,
  metadata   TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v23_tables.sql
CREATE TABLE IF NOT EXISTS revenue_monthly (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  period          TEXT NOT NULL UNIQUE,
  sub_revenue_inr INTEGER DEFAULT 0,
  marketplace_revenue_inr INTEGER DEFAULT 0,
  api_revenue_inr INTEGER DEFAULT 0,
  report_revenue_inr INTEGER DEFAULT 0,
  mssp_revenue_inr INTEGER DEFAULT 0,
  total_revenue_inr INTEGER DEFAULT 0,
  new_customers   INTEGER DEFAULT 0,
  churned_customers INTEGER DEFAULT 0,
  net_customers   INTEGER DEFAULT 0,
  updated_at      TEXT DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS revenue_snapshots (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_at TEXT    NOT NULL DEFAULT (datetime('now')),
  mrr_inr     REAL    NOT NULL DEFAULT 0,
  arr_inr     REAL    NOT NULL DEFAULT 0,
  active_subs INTEGER NOT NULL DEFAULT 0,
  new_subs    INTEGER NOT NULL DEFAULT 0,
  churned     INTEGER NOT NULL DEFAULT 0,
  total_users INTEGER NOT NULL DEFAULT 0,
  pro_users   INTEGER NOT NULL DEFAULT 0,
  ent_users   INTEGER NOT NULL DEFAULT 0,
  api_calls   INTEGER NOT NULL DEFAULT 0,
  scans_today INTEGER NOT NULL DEFAULT 0,
  meta_json   TEXT
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS revenue_streams (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  period          TEXT NOT NULL,
  stream          TEXT NOT NULL CHECK(stream IN ('subscriptions','marketplace','api','reports','consulting','training','mssp')),
  revenue_inr     INTEGER NOT NULL DEFAULT 0,
  transaction_count INTEGER NOT NULL DEFAULT 0,
  customer_count  INTEGER NOT NULL DEFAULT 0,
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24_phaseA_FINAL.sql
CREATE TABLE IF NOT EXISTS revos_mrr_snapshots (
  id TEXT PRIMARY KEY, snapshot_date TEXT NOT NULL DEFAULT '',
  mrr_inr REAL NOT NULL DEFAULT 0, arr_inr REAL NOT NULL DEFAULT 0,
  new_mrr REAL NOT NULL DEFAULT 0, churned_mrr REAL NOT NULL DEFAULT 0,
  expansion_mrr REAL NOT NULL DEFAULT 0, active_subs INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS revos_revenue_streams (
  id          TEXT PRIMARY KEY,
  stream_name TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL DEFAULT '',
  amount_inr  REAL NOT NULL DEFAULT 0,
  period      TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS sales_opportunities (
  id            TEXT PRIMARY KEY,
  lead_id       TEXT,
  company       TEXT NOT NULL DEFAULT '',
  contact_email TEXT,
  sector        TEXT,
  company_size  TEXT,
  budget_range  TEXT,
  urgency       TEXT,
  score         INTEGER NOT NULL DEFAULT 0,
  tier          TEXT NOT NULL DEFAULT 'D',
  deal_value    REAL NOT NULL DEFAULT 0,
  stage         TEXT NOT NULL DEFAULT 'lead',
  owner         TEXT,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata      TEXT DEFAULT '{}'
);

-- From: schema_gtm_only.sql
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

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS sales_pipeline_history (
  id             TEXT PRIMARY KEY,
  opportunity_id TEXT NOT NULL DEFAULT '',
  from_stage     TEXT,
  to_stage       TEXT NOT NULL DEFAULT '',
  changed_by     TEXT,
  note           TEXT,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS saved_searches (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  org_id      TEXT NOT NULL DEFAULT 'default',
  name        TEXT NOT NULL,
  query       TEXT NOT NULL,
  facets_json TEXT DEFAULT '{}',
  entity_types TEXT DEFAULT '[]',
  hit_count   INTEGER DEFAULT 0,
  last_run_at TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema.sql
CREATE TABLE IF NOT EXISTS scan_dedup (
  dedup_key   TEXT    PRIMARY KEY,   -- module:target (SHA-256 prefix)
  job_id      TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL
);

-- From: schema_v22_production_fix.sql
CREATE TABLE IF NOT EXISTS scan_history (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id     TEXT,
  job_id      TEXT,
  scan_id     TEXT,
  target      TEXT,
  module      TEXT,
  risk_score  REAL DEFAULT 0,
  risk_level  TEXT,
  grade       TEXT,
  data_source TEXT,
  status      TEXT DEFAULT 'completed',
  scanned_at  TEXT NOT NULL DEFAULT (datetime('now')),
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS scan_orders (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  user_id         TEXT,
  email           TEXT,
  target          TEXT NOT NULL,
  module          TEXT NOT NULL DEFAULT 'domain',
  tier            TEXT NOT NULL DEFAULT 'basic' CHECK(tier IN ('basic','pro','enterprise_review','security_assessment')),
  price_inr       INTEGER NOT NULL DEFAULT 199,
  payment_id      TEXT,
  order_id        TEXT,
  payment_status  TEXT NOT NULL DEFAULT 'pending' CHECK(payment_status IN ('pending','paid','failed','refunded')),
  report_key      TEXT,
  report_token    TEXT,
  report_expires  TEXT,
  scan_result     TEXT,
  delivered_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS scan_token_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce       TEXT NOT NULL,
  ip_hash     TEXT NOT NULL,
  issued_at   TEXT NOT NULL,
  used_at     TEXT,
  status      TEXT NOT NULL DEFAULT 'issued'
                CHECK(status IN ('issued','consumed','expired','rejected')),
  reject_reason TEXT
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS scanner_orders (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL DEFAULT '',
  tier         TEXT NOT NULL DEFAULT '',
  target       TEXT NOT NULL DEFAULT '',
  scan_type    TEXT NOT NULL DEFAULT 'domain',
  amount_inr   REAL NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'pending_payment',
  token        TEXT,
  report_url   TEXT,
  payment_ref  TEXT,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at INTEGER
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS schema_versions (
  version    TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now')),
  description TEXT
);

-- From: schema_v36_service_catalog.sql
CREATE TABLE IF NOT EXISTS service_assessments (
  id                  TEXT PRIMARY KEY,
  order_id            TEXT NOT NULL,
  service_ref         TEXT NOT NULL,
  target              TEXT,
  status              TEXT DEFAULT 'pending',           -- pending|running|complete|failed
  risk_score          INTEGER DEFAULT 0,                -- 0-100
  risk_grade          TEXT DEFAULT 'UNKNOWN',           -- A/B/C/D/F
  findings_count      INTEGER DEFAULT 0,
  critical_count      INTEGER DEFAULT 0,
  high_count          INTEGER DEFAULT 0,
  findings_json       TEXT DEFAULT '[]',
  recommendations_json TEXT DEFAULT '[]',
  report_json         TEXT DEFAULT '{}',
  engine_version      TEXT DEFAULT '1.0',
  started_at          TEXT,
  completed_at        TEXT,
  created_at          TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (order_id) REFERENCES service_orders(id) ON DELETE CASCADE
);

-- From: schema_v36_service_catalog.sql
CREATE TABLE IF NOT EXISTS service_deliverables (
  id                  TEXT PRIMARY KEY,
  order_id            TEXT NOT NULL,
  deliverable_type    TEXT NOT NULL,                    -- json_report|action_plan|ioc_list|executive_summary|roadmap
  title               TEXT NOT NULL,
  content_json        TEXT DEFAULT '{}',
  download_count      INTEGER DEFAULT 0,
  created_at          TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (order_id) REFERENCES service_orders(id) ON DELETE CASCADE
);

-- From: schema_v36_service_catalog.sql
CREATE TABLE IF NOT EXISTS service_orders (
  id                  TEXT PRIMARY KEY,
  ref_id              TEXT NOT NULL,
  customer_name       TEXT NOT NULL,
  customer_email      TEXT NOT NULL,
  customer_phone      TEXT,
  company             TEXT,
  company_size        TEXT,                             -- startup|sme|enterprise
  target_domain       TEXT,                             -- domain/URL/system to assess
  target_industry     TEXT DEFAULT 'General',
  requirements        TEXT,                             -- customer free-text notes
  assessment_inputs   TEXT DEFAULT '{}',                -- JSON inputs for automated engines
  payment_status      TEXT DEFAULT 'pending',           -- pending|paid|processing|failed|refunded
  payment_method      TEXT DEFAULT 'razorpay',
  payment_ref         TEXT,
  payment_amount      INTEGER,
  order_status        TEXT DEFAULT 'new',               -- new|payment_pending|confirmed|in_progress|delivered|cancelled
  report_token        TEXT UNIQUE,                      -- secure download token (UUID)
  admin_notes         TEXT,
  source              TEXT DEFAULT 'website',
  utm_source          TEXT,
  created_at          TEXT DEFAULT (datetime('now')),
  updated_at          TEXT DEFAULT (datetime('now'))
);

-- From: schema_v36_service_catalog.sql
CREATE TABLE IF NOT EXISTS services (
  ref_id              TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  tier                INTEGER NOT NULL DEFAULT 1,       -- 1=ENTRY 2=SME 3=ENTERPRISE
  tier_name           TEXT NOT NULL DEFAULT 'ENTRY',
  price_inr           INTEGER NOT NULL,
  price_usd           REAL DEFAULT 0,
  short_desc          TEXT,
  deliverables        TEXT DEFAULT '[]',                -- JSON array
  ideal_for           TEXT DEFAULT '[]',                -- JSON array
  delivery_type       TEXT DEFAULT 'manual',            -- manual|automated|hybrid
  delivery_hours      INTEGER DEFAULT 72,               -- SLA in hours (0=instant)
  automated_engine    TEXT,                             -- ssl|cti_brief|cti_report|ai_security|ai_security_enterprise|compliance|threat_hunting|api_security|cloud_security|vuln_assessment
  highlight           INTEGER DEFAULT 0,                -- featured/bestseller flag
  active              INTEGER DEFAULT 1,
  sort_order          INTEGER DEFAULT 0,
  created_at          TEXT DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS session_blacklist (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT NOT NULL,
  token_hash  TEXT UNIQUE,
  reason      TEXT NOT NULL DEFAULT 'agent_disable',
  action_id   TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS soc_alerts (
  id             TEXT PRIMARY KEY,
  alert_type     TEXT NOT NULL,
  severity       TEXT NOT NULL,
  cve_id         TEXT,
  title          TEXT,
  asset          TEXT,
  recommendation TEXT,
  evidence       TEXT DEFAULT '{}',
  resolved       INTEGER DEFAULT 0,
  created_at     TEXT DEFAULT (datetime('now'))
);

-- From: schema_phase2.sql
CREATE TABLE IF NOT EXISTS soc_case_comments (
  id           TEXT PRIMARY KEY,
  case_id      TEXT NOT NULL REFERENCES soc_cases(id) ON DELETE CASCADE,
  author_id    TEXT NOT NULL DEFAULT 'system',
  author_name  TEXT,
  body         TEXT NOT NULL,
  comment_type TEXT DEFAULT 'note' CHECK(comment_type IN ('note','action','escalation','resolution','system')),
  visibility   TEXT DEFAULT 'internal' CHECK(visibility IN ('internal','external')),
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase2.sql
CREATE TABLE IF NOT EXISTS soc_cases (
  id            TEXT PRIMARY KEY,
  case_number   TEXT UNIQUE NOT NULL,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  status        TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','IN_PROGRESS','ESCALATED','RESOLVED','CLOSED')),
  assignee_id   TEXT,
  org_id        TEXT DEFAULT 'default',
  source        TEXT NOT NULL DEFAULT 'manual',
  alert_ids     TEXT DEFAULT '[]',
  ioc_list      TEXT DEFAULT '[]',
  mitre_tactics TEXT DEFAULT '[]',
  playbook_id   TEXT,
  summary       TEXT,
  resolution    TEXT,
  sla_hours     INTEGER DEFAULT 72,
  sla_due_at    TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at   TEXT
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS soc_decisions (
  id          TEXT PRIMARY KEY,
  cve_id      TEXT NOT NULL,
  decision    TEXT NOT NULL,
  priority    TEXT NOT NULL,
  confidence  INTEGER DEFAULT 0,
  risk_score  INTEGER DEFAULT 0,
  reason      TEXT,
  factors     TEXT DEFAULT '{}',
  created_at  TEXT DEFAULT (datetime('now'))
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS soc_defense_actions (
  id             TEXT PRIMARY KEY,
  rule_id        TEXT,
  defense_action TEXT NOT NULL,
  target         TEXT,
  target_type    TEXT,
  duration       TEXT,
  status         TEXT DEFAULT 'triggered',
  payload        TEXT DEFAULT '{}',
  created_at     TEXT DEFAULT (datetime('now'))
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS soc_evidence (
  id               TEXT PRIMARY KEY,
  case_id          TEXT NOT NULL,
  org_id           TEXT NOT NULL DEFAULT 'default',
  evidence_type    TEXT NOT NULL DEFAULT 'ARTIFACT',
  title            TEXT NOT NULL,
  description      TEXT,
  data_json        TEXT,
  file_hash        TEXT,
  file_size_bytes  INTEGER,
  source_system    TEXT,
  chain_of_custody TEXT,
  added_by         TEXT NOT NULL,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS soc_notes (
  id          TEXT PRIMARY KEY,
  case_id     TEXT NOT NULL,
  org_id      TEXT NOT NULL DEFAULT 'default',
  author      TEXT NOT NULL,
  content     TEXT NOT NULL,
  note_type   TEXT NOT NULL DEFAULT 'ANALYST',
  is_pinned   INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_threat_intel.sql
CREATE TABLE IF NOT EXISTS soc_response_actions (
  id         TEXT PRIMARY KEY,
  action     TEXT NOT NULL,
  priority   TEXT NOT NULL,
  alert_id   TEXT,
  cve_id     TEXT,
  status     TEXT DEFAULT 'recommended',
  payload    TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS soc_timeline (
  id            TEXT PRIMARY KEY,
  case_id       TEXT NOT NULL,
  org_id        TEXT NOT NULL DEFAULT 'default',
  event_type    TEXT NOT NULL,
  description   TEXT NOT NULL,
  actor         TEXT,
  old_value     TEXT,
  new_value     TEXT,
  metadata_json TEXT,
  occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS subscription_tier_defs (
  tier            TEXT PRIMARY KEY,
  label           TEXT NOT NULL,
  monthly_limit   INTEGER NOT NULL DEFAULT 3000,
  daily_limit     INTEGER NOT NULL DEFAULT 100,
  burst_per_min   INTEGER NOT NULL DEFAULT 5,
  price_inr       INTEGER NOT NULL DEFAULT 0,
  price_usd       INTEGER NOT NULL DEFAULT 0,
  scan_preview    INTEGER NOT NULL DEFAULT 2,
  features_json   TEXT
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS subscriptions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'COMMUNITY',
  status        TEXT NOT NULL DEFAULT 'active'
                  CHECK(status IN ('active','cancelled_stripe_cancellation',
                                   'cancelled_razorpay_cancellation',
                                   'cancelled_admin','expired','pending')),
  processor     TEXT,
  external_id   TEXT,
  price_inr     INTEGER DEFAULT 0,
  activated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at    TEXT,
  cancelled_at  TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS tenant_themes (
  org_id           TEXT PRIMARY KEY,
  brand_name       TEXT DEFAULT 'CYBERDUDEBIVASH®',
  logo_url         TEXT,
  favicon_url      TEXT,
  primary_color    TEXT DEFAULT '#6366f1',
  secondary_color  TEXT DEFAULT '#0ea5e9',
  accent_color     TEXT DEFAULT '#22c55e',
  custom_css       TEXT,
  custom_domain    TEXT,
  support_email    TEXT,
  support_url      TEXT,
  hide_powered_by  INTEGER DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS testimonials (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  name            TEXT NOT NULL,
  title           TEXT,
  company         TEXT,
  avatar_initial  TEXT,
  quote           TEXT NOT NULL,
  rating          INTEGER NOT NULL DEFAULT 5,
  verified        INTEGER NOT NULL DEFAULT 0,
  featured        INTEGER NOT NULL DEFAULT 0,
  use_case        TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS threat_actors (
  id               TEXT PRIMARY KEY,   -- e.g. "apt28", "lazarus-group"
  name             TEXT NOT NULL,      -- Display name
  aliases          TEXT DEFAULT '[]',  -- JSON array
  country          TEXT,               -- Attribution: CN, RU, KP, IR, etc.
  motivation       TEXT,               -- espionage|financial|sabotage|hacktivism
  sophistication   TEXT DEFAULT 'advanced', -- nation-state|advanced|intermediate|basic
  active           INTEGER DEFAULT 1,
  first_seen       TEXT,
  last_active      TEXT,
  target_sectors   TEXT DEFAULT '[]',  -- JSON: ["Finance","Defense","Energy"]
  target_countries TEXT DEFAULT '[]',  -- JSON: ["US","UK","DE"]
  ttps             TEXT DEFAULT '[]',  -- JSON: MITRE ATT&CK technique IDs
  iocs             TEXT DEFAULT '{}',  -- JSON: {domains:[],ips:[],hashes:[]}
  tools            TEXT DEFAULT '[]',  -- JSON: ["Cobalt Strike","Mimikatz"]
  campaigns        TEXT DEFAULT '[]',  -- JSON: recent campaign names
  description      TEXT,
  ref_urls         TEXT DEFAULT '[]',  -- JSON: source URLs
  mitre_group_id   TEXT,              -- MITRE ATT&CK group ID (e.g. G0007)
  created_at       TEXT DEFAULT (datetime('now')),
  updated_at       TEXT DEFAULT (datetime('now'))
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS threat_intel (
  id              TEXT    PRIMARY KEY,
  cve_id          TEXT    UNIQUE,
  title           TEXT    NOT NULL,
  description     TEXT,
  severity        TEXT    NOT NULL DEFAULT 'MEDIUM',
  cvss_score      REAL,
  cvss_vector     TEXT,
  vendor          TEXT,
  product         TEXT,
  published_at    TEXT,
  modified_at     TEXT,
  is_exploited    INTEGER NOT NULL DEFAULT 0,
  is_ransomware   INTEGER NOT NULL DEFAULT 0,
  apt_groups      TEXT,                           -- JSON array
  cisa_kev_date   TEXT,
  patch_available INTEGER NOT NULL DEFAULT 0,
  patch_url       TEXT,
  ref_urls        TEXT,                           -- JSON array of URLs
  source          TEXT    NOT NULL DEFAULT 'NVD',
  confidence      REAL    NOT NULL DEFAULT 0.5,
  ingested_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS threat_intel_cache (
  cve_id          TEXT PRIMARY KEY,
  cvss_score      REAL,
  cvss_vector     TEXT,
  epss_score      REAL,
  epss_pct        REAL,
  is_kev          INTEGER NOT NULL DEFAULT 0,
  kev_added       TEXT,
  description     TEXT,
  cpe_list        TEXT,
  references_json TEXT,
  cached_at       TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at      TEXT NOT NULL
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS threat_predictions (
  id                    TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id                TEXT NOT NULL,
  prediction_date       TEXT NOT NULL DEFAULT (date('now')),
  exploit_probability   REAL NOT NULL DEFAULT 0,
  impact_score          REAL NOT NULL DEFAULT 0,
  exposure_score        REAL NOT NULL DEFAULT 0,
  risk_score            REAL NOT NULL DEFAULT 0,
  probability_pct       REAL NOT NULL DEFAULT 0,
  expected_window_hrs   INTEGER NOT NULL DEFAULT 72,
  attack_window_label   TEXT NOT NULL DEFAULT '72h',
  apt_groups            TEXT DEFAULT '[]',
  mitre_techniques      TEXT DEFAULT '[]',
  recommended_action    TEXT NOT NULL,
  confidence            REAL NOT NULL DEFAULT 0.5,
  is_kev                INTEGER NOT NULL DEFAULT 0,
  cvss_score            REAL,
  epss_score            REAL,
  affected_systems_est  INTEGER DEFAULT 0,
  velocity_7d           REAL DEFAULT 0,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(cve_id, prediction_date)
);

-- From: schema_v35_revenue_features.sql
CREATE TABLE IF NOT EXISTS tprm_vendors (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL,
  vendor_name         TEXT NOT NULL,
  vendor_domain       TEXT NOT NULL,
  vendor_category     TEXT,            -- cloud|saas|infrastructure|payment|data_processor
  criticality         TEXT DEFAULT 'medium', -- critical|high|medium|low
  risk_score          INTEGER DEFAULT 0,     -- 0-100
  risk_grade          TEXT DEFAULT 'UNKNOWN',
  last_assessment     TEXT,
  assessment_findings TEXT DEFAULT '[]',     -- JSON findings
  data_access         TEXT DEFAULT '[]',     -- JSON: types of data vendor can access
  compliance_certs    TEXT DEFAULT '[]',     -- JSON: SOC2/ISO27001/etc
  open_issues         INTEGER DEFAULT 0,
  status              TEXT DEFAULT 'active',
  created_at          TEXT DEFAULT (datetime('now')),
  updated_at          TEXT DEFAULT (datetime('now'))
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS trust_incidents (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL DEFAULT '',
  description TEXT,
  severity    TEXT NOT NULL DEFAULT 'minor',
  status      TEXT NOT NULL DEFAULT 'investigating',
  affected    TEXT,
  started_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at INTEGER,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_v30_p0p1.sql
CREATE TABLE IF NOT EXISTS trust_metrics_cache (
  id          TEXT PRIMARY KEY DEFAULT 'singleton',
  uptime_pct  REAL NOT NULL DEFAULT 99.9,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v27.sql
CREATE TABLE IF NOT EXISTS trust_signals (
  id             TEXT PRIMARY KEY,
  type           TEXT NOT NULL,  -- 'testimonial' | 'case_study' | 'metric' | 'certification'
  title          TEXT NOT NULL DEFAULT '',
  content        TEXT NOT NULL DEFAULT '',
  company        TEXT,
  sector         TEXT,
  verified       INTEGER NOT NULL DEFAULT 0,  -- 1=admin-verified, 0=pending
  source_url     TEXT,
  display_order  INTEGER NOT NULL DEFAULT 0,
  visible        INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  verified_at    INTEGER
);

-- From: schema_v24_ZERO_ERRORS.sql
CREATE TABLE IF NOT EXISTS trust_testimonials (
  id         TEXT PRIMARY KEY,
  author     TEXT NOT NULL DEFAULT '',
  role       TEXT,
  company    TEXT,
  sector     TEXT,
  content    TEXT NOT NULL DEFAULT '',
  rating     INTEGER NOT NULL DEFAULT 5,
  verified   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_phase4.sql
CREATE TABLE IF NOT EXISTS upsell_events (
  id               TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL DEFAULT 'default',
  user_id          TEXT,
  event_type       TEXT NOT NULL,
  trigger_reason   TEXT,
  recommended_tier TEXT,
  current_tier     TEXT,
  dismissed        INTEGER NOT NULL DEFAULT 0,
  converted        INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v24.sql
CREATE TABLE IF NOT EXISTS uptime_log (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  service         TEXT NOT NULL DEFAULT 'api',
  status          TEXT NOT NULL DEFAULT 'operational' CHECK(status IN ('operational','degraded','partial_outage','major_outage')),
  latency_ms      INTEGER DEFAULT 0,
  checked_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS user_behavior_baseline (
  user_id            TEXT PRIMARY KEY,
  avg_login_hour     REAL NOT NULL DEFAULT 9.0,
  stddev_login_hour  REAL NOT NULL DEFAULT 2.0,
  typical_ips        TEXT NOT NULL DEFAULT '[]',
  typical_countries  TEXT NOT NULL DEFAULT '[]',
  avg_api_calls_hr   REAL NOT NULL DEFAULT 10.0,
  stddev_api_calls   REAL NOT NULL DEFAULT 5.0,
  avg_scan_day       REAL NOT NULL DEFAULT 2.0,
  stddev_scans       REAL NOT NULL DEFAULT 1.5,
  total_sessions     INTEGER NOT NULL DEFAULT 0,
  failed_logins_avg  REAL NOT NULL DEFAULT 0.1,
  last_computed_at   TEXT NOT NULL DEFAULT (datetime('now')),
  data_points        INTEGER NOT NULL DEFAULT 0
);

-- From: schema_v8.sql
CREATE TABLE IF NOT EXISTS user_credits (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id      TEXT NOT NULL,
  total        INTEGER NOT NULL DEFAULT 0,
  used         INTEGER NOT NULL DEFAULT 0,
  source       TEXT NOT NULL DEFAULT 'gumroad'
                 CHECK (source IN ('gumroad','purchase','bonus','referral','promo')),
  reference_id TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_mcp_learning.sql
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

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS user_roles (
  user_id    TEXT NOT NULL,
  role       TEXT NOT NULL CHECK(role IN ('SUPERADMIN','ADMIN','SOC_ANALYST','THREAT_HUNTER','VIEWER','API_USER')),
  granted_by TEXT,
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, role)
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS user_sessions (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  session_token    TEXT NOT NULL UNIQUE,         -- short-lived JWT session ID
  device_fp        TEXT,                         -- device fingerprint hash
  ip_address       TEXT,
  user_agent       TEXT,
  country          TEXT,
  city             TEXT,
  is_active        INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  last_active_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT NOT NULL,
  revoked_at       TEXT,
  revoke_reason    TEXT
);

-- From: schema_v15.sql
CREATE TABLE IF NOT EXISTS user_tool_access (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,                         -- NULL allowed for email-only lookups
  email            TEXT NOT NULL,
  product_id       TEXT NOT NULL,
  product_name     TEXT NOT NULL,
  access_type      TEXT NOT NULL CHECK(access_type IN (
    'training', 'report', 'tool', 'subscription', 'bundle'
  )),
  delivery_id      TEXT,                         -- FK → delivery_tokens.id
  payment_id       TEXT NOT NULL,
  granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at       TEXT,                         -- NULL = lifetime
  is_active        INTEGER NOT NULL DEFAULT 1,
  last_accessed_at TEXT,
  access_count     INTEGER NOT NULL DEFAULT 0,
  metadata         TEXT DEFAULT '{}'             -- extra JSON: course progress, score, etc.
);

-- From: schema_v29.sql
CREATE TABLE IF NOT EXISTS vibe_code_scans (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT UNIQUE NOT NULL,
  language     TEXT,
  line_count   INTEGER,
  risk_score   INTEGER,
  risk_level   TEXT,
  vuln_count   INTEGER DEFAULT 0,
  user_email   TEXT,
  scanned_at   TEXT NOT NULL,
  unlocked_at  TEXT,
  unlock_token TEXT
);

-- From: schema_v12.sql
CREATE TABLE IF NOT EXISTS virtual_patches (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cve_id       TEXT NOT NULL,
  patch_type   TEXT NOT NULL CHECK(patch_type IN (
    'header_injection','path_block','param_filter','rate_limit','redirect','custom_rule'
  )),
  rule_name    TEXT NOT NULL,
  rule_pattern TEXT NOT NULL,
  rule_action  TEXT NOT NULL DEFAULT 'block' CHECK(rule_action IN ('block','log','rate_limit','redirect')),
  priority     INTEGER NOT NULL DEFAULT 100,
  is_active    INTEGER NOT NULL DEFAULT 1,
  hit_count    INTEGER NOT NULL DEFAULT 0,
  last_hit     TEXT,
  action_id    TEXT,
  expires_at   TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- From: schema_v31_p0_fixes.sql
CREATE TABLE IF NOT EXISTS webhook_events (
  id              TEXT PRIMARY KEY,       -- Razorpay event id (event_type:created_at:account_id)
  event_type      TEXT NOT NULL,
  payment_id      TEXT,
  order_id        TEXT,
  payload_hash    TEXT NOT NULL,          -- sha256 of raw body for audit
  outcome         TEXT NOT NULL DEFAULT 'processed'
                    CHECK(outcome IN ('processed', 'skipped_duplicate', 'failed', 'invalid_sig', 'replay_rejected')),
  error_message   TEXT,
  processing_ms   INTEGER,
  processed_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS workflow_executions (
  id                    TEXT PRIMARY KEY,
  workflow_id           TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  status                TEXT DEFAULT 'RUNNING' CHECK(status IN ('RUNNING','COMPLETED','FAILED','CANCELLED')),
  triggered_by          TEXT DEFAULT 'manual',
  trigger_payload_json  TEXT DEFAULT '{}',
  steps_log_json        TEXT DEFAULT '[]',
  error_message         TEXT,
  org_id                TEXT NOT NULL DEFAULT 'default',
  started_at            TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at          TEXT
);

-- From: schema_phase3.sql
CREATE TABLE IF NOT EXISTS workflows (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  description       TEXT,
  trigger_type      TEXT NOT NULL CHECK(trigger_type IN ('SCAN_CRITICAL','CASE_CREATED','CASE_ESCALATED','HEALTH_CHURN','IOC_MATCH','MANUAL','SCHEDULE')),
  trigger_config    TEXT DEFAULT '{}',
  steps_json        TEXT NOT NULL DEFAULT '[]',
  is_active         INTEGER DEFAULT 1,
  org_id            TEXT NOT NULL DEFAULT 'default',
  created_by        TEXT NOT NULL DEFAULT 'system',
  run_count         INTEGER DEFAULT 0,
  last_run_at       TEXT,
  is_template       INTEGER DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_actors_active     ON threat_actors(active);

CREATE INDEX IF NOT EXISTS idx_actors_country    ON threat_actors(country);

CREATE INDEX IF NOT EXISTS idx_actors_motivation ON threat_actors(motivation);

CREATE INDEX IF NOT EXISTS idx_actors_nation       ON cti_actors(nation_state);

CREATE INDEX IF NOT EXISTS idx_actors_threat_level ON cti_actors(threat_level);

CREATE INDEX IF NOT EXISTS idx_adsense_page ON adsense_events(page);

CREATE INDEX IF NOT EXISTS idx_adsense_type ON adsense_events(event_type);

CREATE INDEX IF NOT EXISTS idx_aff_email ON affiliate_members(email);

CREATE INDEX IF NOT EXISTS idx_aff_tier ON affiliate_members(tier);

CREATE INDEX IF NOT EXISTS idx_affiliate_conv    ON affiliate_clicks(converted);

CREATE INDEX IF NOT EXISTS idx_affiliate_link    ON affiliate_clicks(link_id);

CREATE INDEX IF NOT EXISTS idx_affiliate_program ON affiliate_clicks(program);

CREATE INDEX IF NOT EXISTS idx_agent_actions_risk    ON agent_actions(risk_level, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_actions_status  ON agent_actions(execution_status);

CREATE INDEX IF NOT EXISTS idx_agent_actions_target  ON agent_actions(target);

CREATE INDEX IF NOT EXISTS idx_agent_actions_trigger ON agent_actions(trigger_source, trigger_id);

CREATE INDEX IF NOT EXISTS idx_agent_actions_type    ON agent_actions(action_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_agent_framework ON ai_agent_inventory(framework);

CREATE INDEX IF NOT EXISTS idx_ai_agent_org       ON ai_agent_inventory(org_id);

CREATE INDEX IF NOT EXISTS idx_ai_agent_risk      ON ai_agent_inventory(risk_score);

CREATE INDEX IF NOT EXISTS idx_ai_assets_exposure   ON ai_assets(exposure);

CREATE INDEX IF NOT EXISTS idx_ai_assets_org        ON ai_assets(org_id);

CREATE INDEX IF NOT EXISTS idx_ai_assets_risk       ON ai_assets(risk_score);

CREATE INDEX IF NOT EXISTS idx_ai_assets_type       ON ai_assets(asset_type);

CREATE INDEX IF NOT EXISTS idx_ai_feed_published  ON ai_threat_feed(published_at);

CREATE INDEX IF NOT EXISTS idx_ai_feed_severity   ON ai_threat_feed(severity);

CREATE INDEX IF NOT EXISTS idx_ai_feed_type       ON ai_threat_feed(feed_type);

CREATE INDEX IF NOT EXISTS idx_ai_findings_asset    ON ai_findings(asset_id);

CREATE INDEX IF NOT EXISTS idx_ai_findings_category ON ai_findings(category);

CREATE INDEX IF NOT EXISTS idx_ai_findings_severity ON ai_findings(severity);

CREATE INDEX IF NOT EXISTS idx_ai_findings_status   ON ai_findings(status);

CREATE INDEX IF NOT EXISTS idx_ai_gov_email     ON ai_governance_assessments(email);

CREATE INDEX IF NOT EXISTS idx_ai_gov_framework ON ai_governance_assessments(framework);

CREATE INDEX IF NOT EXISTS idx_ai_gov_org       ON ai_governance_assessments(org_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_level  ON ai_risk_register(risk_level);

CREATE INDEX IF NOT EXISTS idx_ai_risk_org    ON ai_risk_register(org_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_status ON ai_risk_register(status);

CREATE INDEX IF NOT EXISTS idx_ai_svc_email  ON ai_service_engagements(email);

CREATE INDEX IF NOT EXISTS idx_ai_svc_status ON ai_service_engagements(status);

CREATE INDEX IF NOT EXISTS idx_ai_svc_type   ON ai_service_engagements(service_type);

CREATE INDEX IF NOT EXISTS idx_alert_configs_user ON alert_configs(user_id);

CREATE INDEX IF NOT EXISTS idx_alert_log_user ON alert_log(user_id, sent_at);

CREATE INDEX IF NOT EXISTS idx_analytics_date      ON analytics_events(created_at);

CREATE INDEX IF NOT EXISTS idx_analytics_module    ON analytics_events(module, created_at);

CREATE INDEX IF NOT EXISTS idx_analytics_type      ON analytics_events(event_type, created_at);

CREATE INDEX IF NOT EXISTS idx_analytics_user      ON analytics_events(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_anomaly_risk  ON anomaly_events(risk_level, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_score ON anomaly_events(anomaly_score DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_user  ON anomaly_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_keys_email ON api_keys(email);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

CREATE INDEX IF NOT EXISTS idx_api_keys_tier ON api_keys(tier);

CREATE INDEX IF NOT EXISTS idx_api_keys_user   ON api_keys(user_id);

CREATE INDEX IF NOT EXISTS idx_api_usage_email   ON api_usage_log(email);

CREATE INDEX IF NOT EXISTS idx_api_usage_logged  ON api_usage_log(logged_at DESC);

CREATE INDEX IF NOT EXISTS idx_apib_created ON api_billing(created_at );

CREATE INDEX IF NOT EXISTS idx_apib_created ON api_billing(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_apib_created ON api_billing(created_at);

CREATE INDEX IF NOT EXISTS idx_apib_key     ON api_billing(api_key_id);

CREATE INDEX IF NOT EXISTS idx_apib_key ON api_billing(api_key_id);

CREATE INDEX IF NOT EXISTS idx_apib_period  ON api_billing(billing_period);

CREATE INDEX IF NOT EXISTS idx_apib_period ON api_billing(billing_period);

CREATE INDEX IF NOT EXISTS idx_apib_user    ON api_billing(user_id);

CREATE INDEX IF NOT EXISTS idx_apib_user ON api_billing(user_id);

CREATE INDEX IF NOT EXISTS idx_asm_assets_new      ON asm_assets(new_asset);

CREATE INDEX IF NOT EXISTS idx_asm_assets_risk     ON asm_assets(risk_level);

CREATE INDEX IF NOT EXISTS idx_asm_assets_target   ON asm_assets(target_id);

CREATE INDEX IF NOT EXISTS idx_asm_assets_type     ON asm_assets(asset_type);

CREATE INDEX IF NOT EXISTS idx_asm_targets_domain  ON asm_targets(domain);

CREATE INDEX IF NOT EXISTS idx_asm_targets_score   ON asm_targets(asm_score DESC);

CREATE INDEX IF NOT EXISTS idx_asm_targets_user    ON asm_targets(user_id);

CREATE INDEX IF NOT EXISTS idx_assessments_booked_at  ON assessments(booked_at);

CREATE INDEX IF NOT EXISTS idx_assessments_email      ON assessments(email);

CREATE INDEX IF NOT EXISTS idx_assessments_order  ON service_assessments(order_id);

CREATE INDEX IF NOT EXISTS idx_assessments_ref    ON service_assessments(service_ref);

CREATE INDEX IF NOT EXISTS idx_assessments_status     ON assessments(status);

CREATE INDEX IF NOT EXISTS idx_assessments_status ON service_assessments(status);

CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log(action);

CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);

CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at );

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);

CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

CREATE INDEX IF NOT EXISTS idx_behav_ip      ON behavior_events(ip, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_behav_type    ON behavior_events(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_behav_user    ON behavior_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_bf_created_at   ON brain_feedback (created_at);

CREATE INDEX IF NOT EXISTS idx_bf_finding_id   ON brain_feedback (finding_id);

CREATE INDEX IF NOT EXISTS idx_bf_scan_id      ON brain_feedback (scan_id);

CREATE INDEX IF NOT EXISTS idx_bf_sector       ON brain_feedback (sector);

CREATE INDEX IF NOT EXISTS idx_bf_user_id      ON brain_feedback (user_id);

CREATE INDEX IF NOT EXISTS idx_bgs_last_seen   ON brain_global_signals (last_seen);

CREATE INDEX IF NOT EXISTS idx_bgs_sector      ON brain_global_signals (sector);

CREATE INDEX IF NOT EXISTS idx_bgs_signal_type ON brain_global_signals (signal_type);

CREATE INDEX IF NOT EXISTS idx_billing_email     ON billing_events(email);

CREATE INDEX IF NOT EXISTS idx_billing_invoices_created ON billing_invoices(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_billing_invoices_created ON billing_invoices(created_at);

CREATE INDEX IF NOT EXISTS idx_billing_invoices_status ON billing_invoices(status);

CREATE INDEX IF NOT EXISTS idx_billing_invoices_user ON billing_invoices(user_id);

CREATE INDEX IF NOT EXISTS idx_blocklist_active ON ip_blocklist(is_active, expires_at);

CREATE INDEX IF NOT EXISTS idx_blocklist_ip     ON ip_blocklist(ip, is_active);

CREATE INDEX IF NOT EXISTS idx_blog_posts_cve ON blog_posts(cve_id);

CREATE INDEX IF NOT EXISTS idx_blog_posts_published ON blog_posts(published_at DESC);

CREATE INDEX IF NOT EXISTS idx_blog_posts_slug ON blog_posts(slug);

CREATE INDEX IF NOT EXISTS idx_blog_posts_status ON blog_posts(status);

CREATE INDEX IF NOT EXISTS idx_bms_date        ON brain_model_snapshots (snapshot_date);

CREATE INDEX IF NOT EXISTS idx_bms_sector      ON brain_model_snapshots (sector);

CREATE INDEX IF NOT EXISTS idx_bp_created_at   ON brain_predictions (created_at);

CREATE INDEX IF NOT EXISTS idx_bp_sector       ON brain_predictions (sector);

CREATE INDEX IF NOT EXISTS idx_bp_user_id      ON brain_predictions (user_id);

CREATE INDEX IF NOT EXISTS idx_brand_monitors_domain ON brand_monitors(primary_domain);

CREATE INDEX IF NOT EXISTS idx_brand_monitors_user   ON brand_monitors(user_id);

CREATE INDEX IF NOT EXISTS idx_brand_threats_domain   ON brand_threats(domain);

CREATE INDEX IF NOT EXISTS idx_brand_threats_monitor  ON brand_threats(monitor_id);

CREATE INDEX IF NOT EXISTS idx_brand_threats_risk     ON brand_threats(risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_brand_threats_type     ON brand_threats(threat_type);

CREATE INDEX IF NOT EXISTS idx_cac_channel ON cac_events(channel);

CREATE INDEX IF NOT EXISTS idx_cac_date    ON cac_events(event_date );

CREATE INDEX IF NOT EXISTS idx_cac_date    ON cac_events(event_date DESC);

CREATE INDEX IF NOT EXISTS idx_cac_date ON cac_events(event_date);

CREATE INDEX IF NOT EXISTS idx_churn_date ON churn_events(churned_at );

CREATE INDEX IF NOT EXISTS idx_churn_date ON churn_events(churned_at DESC);

CREATE INDEX IF NOT EXISTS idx_churn_date ON churn_events(churned_at);

CREATE INDEX IF NOT EXISTS idx_churn_plan ON churn_events(plan);

CREATE INDEX IF NOT EXISTS idx_ciso_status ON ciso_reports(status);

CREATE INDEX IF NOT EXISTS idx_ciso_type   ON ciso_reports(report_type);

CREATE INDEX IF NOT EXISTS idx_ciso_type ON ciso_reports(report_type);

CREATE INDEX IF NOT EXISTS idx_ciso_user   ON ciso_reports(user_id);

CREATE INDEX IF NOT EXISTS idx_ciso_user ON ciso_reports(user_id);

CREATE INDEX IF NOT EXISTS idx_comments_case_id  ON soc_case_comments(case_id);

CREATE INDEX IF NOT EXISTS idx_comments_created  ON soc_case_comments(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_content_platform  ON content_queue(platform);

CREATE INDEX IF NOT EXISTS idx_content_status    ON content_queue(status);

CREATE INDEX IF NOT EXISTS idx_correlation_cve         ON cve_correlations(cve_id);

CREATE INDEX IF NOT EXISTS idx_cred_rot_user ON credential_rotation_log(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_credits_user ON user_credits(user_id);

CREATE INDEX IF NOT EXISTS idx_crm_act_lead ON crm_activities(lead_id);

CREATE INDEX IF NOT EXISTS idx_crm_activities_lead ON crm_activities(lead_id);

CREATE INDEX IF NOT EXISTS idx_crm_created       ON crm_leads(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_crm_email         ON crm_leads(email);

CREATE INDEX IF NOT EXISTS idx_crm_icp           ON crm_leads(icp_score DESC);

CREATE INDEX IF NOT EXISTS idx_crm_leads_email ON crm_leads(email);

CREATE INDEX IF NOT EXISTS idx_crm_leads_score ON crm_leads(icp_score DESC);

CREATE INDEX IF NOT EXISTS idx_crm_leads_score ON crm_leads(icp_score);

CREATE INDEX IF NOT EXISTS idx_crm_leads_status ON crm_leads(status);

CREATE INDEX IF NOT EXISTS idx_crm_notes_lead ON crm_notes(lead_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_crm_notes_type ON crm_notes(note_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_crm_source        ON crm_leads(source, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_crm_stage         ON crm_leads(stage, icp_score DESC);

CREATE INDEX IF NOT EXISTS idx_crq_created ON crq_assessments(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_crq_user    ON crq_assessments(user_id);

CREATE INDEX IF NOT EXISTS idx_cs_created ON cs_signals(created_at );

CREATE INDEX IF NOT EXISTS idx_cs_created ON cs_signals(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cs_created ON cs_signals(created_at);

CREATE INDEX IF NOT EXISTS idx_cs_type    ON cs_signals(signal_type);

CREATE INDEX IF NOT EXISTS idx_cs_type ON cs_signals(signal_type);

CREATE INDEX IF NOT EXISTS idx_cs_user    ON cs_signals(user_id);

CREATE INDEX IF NOT EXISTS idx_cs_user ON cs_signals(user_id);

CREATE INDEX IF NOT EXISTS idx_cta_variants_module ON mcp_cta_variants(module, user_type, purchase_rate DESC);

CREATE INDEX IF NOT EXISTS idx_cti_watchlist_entries_list ON cti_watchlist_entries(watchlist_id);

CREATE INDEX IF NOT EXISTS idx_cti_watchlist_entries_value ON cti_watchlist_entries(ioc_value, org_id);

CREATE INDEX IF NOT EXISTS idx_cti_watchlists_org_id ON cti_watchlists(org_id);

CREATE INDEX IF NOT EXISTS idx_custom_requests_email ON custom_solution_requests(email);

CREATE INDEX IF NOT EXISTS idx_custom_requests_status ON custom_solution_requests(status);

CREATE INDEX IF NOT EXISTS idx_customers_risk        ON mssp_customers(risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_customers_status      ON mssp_customers(status);

CREATE INDEX IF NOT EXISTS idx_da_created ON defense_actions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_da_status  ON defense_actions(status);

CREATE INDEX IF NOT EXISTS idx_da_threat  ON defense_actions(threat_id);

CREATE INDEX IF NOT EXISTS idx_da_type    ON defense_actions(action_type);

CREATE INDEX IF NOT EXISTS idx_deal_email   ON deal_pipeline(contact_email);

CREATE INDEX IF NOT EXISTS idx_deal_email ON deal_pipeline(contact_email);

CREATE INDEX IF NOT EXISTS idx_deal_stage   ON deal_pipeline(stage);

CREATE INDEX IF NOT EXISTS idx_deal_stage ON deal_pipeline(stage);

CREATE INDEX IF NOT EXISTS idx_deal_updated ON deal_pipeline(updated_at );

CREATE INDEX IF NOT EXISTS idx_deal_updated ON deal_pipeline(updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_deal_updated ON deal_pipeline(updated_at);

CREATE INDEX IF NOT EXISTS idx_deal_value   ON deal_pipeline(deal_value_inr );

CREATE INDEX IF NOT EXISTS idx_deal_value   ON deal_pipeline(deal_value_inr DESC);

CREATE INDEX IF NOT EXISTS idx_deal_value ON deal_pipeline(deal_value_inr);

CREATE INDEX IF NOT EXISTS idx_defense_purchases_created ON defense_purchases(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_defense_purchases_solution ON defense_purchases(solution_id);

CREATE INDEX IF NOT EXISTS idx_defense_purchases_status ON defense_purchases(status);

CREATE INDEX IF NOT EXISTS idx_defense_purchases_user ON defense_purchases(user_id);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_category ON defense_solutions(category);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_created ON defense_solutions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_cve ON defense_solutions(cve_id);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_demand ON defense_solutions(demand_score DESC);

CREATE INDEX IF NOT EXISTS idx_defense_solutions_severity ON defense_solutions(severity);

CREATE INDEX IF NOT EXISTS idx_deliverables_order ON service_deliverables(order_id);

CREATE INDEX IF NOT EXISTS idx_delivery_email       ON delivery_tokens(payer_email);

CREATE INDEX IF NOT EXISTS idx_delivery_payment_id  ON delivery_tokens(payment_id);

CREATE INDEX IF NOT EXISTS idx_delivery_product     ON delivery_tokens(product_id, activated_at DESC);

CREATE INDEX IF NOT EXISTS idx_delivery_status      ON delivery_tokens(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_delivery_token_hash  ON delivery_tokens(token_hash);

CREATE INDEX IF NOT EXISTS idx_dp_created    ON defense_purchases(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_dp_solution   ON defense_purchases(solution_id);

CREATE INDEX IF NOT EXISTS idx_dp_status     ON defense_purchases(status);

CREATE INDEX IF NOT EXISTS idx_ds_active     ON defense_solutions(is_active);

CREATE INDEX IF NOT EXISTS idx_ds_cve        ON defense_solutions(cve_id);

CREATE INDEX IF NOT EXISTS idx_ds_featured   ON defense_solutions(is_featured);

CREATE INDEX IF NOT EXISTS idx_ds_purchases  ON defense_solutions(purchase_count DESC);

CREATE INDEX IF NOT EXISTS idx_ds_severity   ON defense_solutions(severity);

CREATE INDEX IF NOT EXISTS idx_email_seq_email   ON email_sequences(email);

CREATE INDEX IF NOT EXISTS idx_email_seq_next    ON email_sequences(next_send_at);

CREATE INDEX IF NOT EXISTS idx_email_seq_status  ON email_sequences(status);

CREATE INDEX IF NOT EXISTS idx_email_track_email ON email_tracking(email);

CREATE INDEX IF NOT EXISTS idx_email_track_event ON email_tracking(event);

CREATE INDEX IF NOT EXISTS idx_enterprise_leads_created ON enterprise_leads(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_enterprise_leads_email ON enterprise_leads(email);

CREATE INDEX IF NOT EXISTS idx_enterprise_leads_status ON enterprise_leads(status);

CREATE INDEX IF NOT EXISTS idx_event_queue_status ON agent_event_queue(status, priority DESC, created_at);

CREATE INDEX IF NOT EXISTS idx_events_occurred  ON analytics_events(occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_org       ON analytics_events(org_id);

CREATE INDEX IF NOT EXISTS idx_events_type      ON analytics_events(event_type);

CREATE INDEX IF NOT EXISTS idx_events_user      ON analytics_events(user_id);

CREATE INDEX IF NOT EXISTS idx_executions_org      ON workflow_executions(org_id);

CREATE INDEX IF NOT EXISTS idx_executions_started  ON workflow_executions(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_executions_status   ON workflow_executions(status);

CREATE INDEX IF NOT EXISTS idx_executions_workflow ON workflow_executions(workflow_id);

CREATE INDEX IF NOT EXISTS idx_fomo_events_created ON fomo_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_fomo_events_type ON fomo_events(event_type);

CREATE INDEX IF NOT EXISTS idx_funnel_created    ON funnel_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_funnel_email      ON funnel_events(email);

CREATE INDEX IF NOT EXISTS idx_funnel_stage      ON funnel_events(stage);

CREATE INDEX IF NOT EXISTS idx_god_mode_runs_at     ON mythos_god_mode_runs(run_at);

CREATE INDEX IF NOT EXISTS idx_god_mode_runs_status ON mythos_god_mode_runs(status);

CREATE INDEX IF NOT EXISTS idx_governor_events_created_at  ON governor_events (created_at);

CREATE INDEX IF NOT EXISTS idx_governor_events_status      ON governor_events (status);

CREATE INDEX IF NOT EXISTS idx_governor_events_subsystem   ON governor_events (subsystem);

CREATE INDEX IF NOT EXISTS idx_growth_created    ON growth_analytics(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_growth_event      ON growth_analytics(event);

CREATE INDEX IF NOT EXISTS idx_gumroad_email   ON gumroad_licenses(buyer_email);

CREATE INDEX IF NOT EXISTS idx_gumroad_product ON gumroad_licenses(product_permalink);

CREATE INDEX IF NOT EXISTS idx_gumroad_user    ON gumroad_licenses(user_id);

CREATE INDEX IF NOT EXISTS idx_health_churn      ON customer_health(churn_risk);

CREATE INDEX IF NOT EXISTS idx_health_computed   ON customer_health(computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_health_org        ON customer_health(org_id);

CREATE INDEX IF NOT EXISTS idx_health_score      ON customer_health(health_score DESC);

CREATE INDEX IF NOT EXISTS idx_hunting_resolved        ON hunting_alerts(resolved);

CREATE INDEX IF NOT EXISTS idx_hunting_severity        ON hunting_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_icp_email ON icp_scores(email);

CREATE INDEX IF NOT EXISTS idx_icp_score ON icp_scores(total_score );

CREATE INDEX IF NOT EXISTS idx_icp_score ON icp_scores(total_score DESC);

CREATE INDEX IF NOT EXISTS idx_icp_score ON icp_scores(total_score);

CREATE INDEX IF NOT EXISTS idx_inv_created  ON invoices(created_at);

CREATE INDEX IF NOT EXISTS idx_inv_customer ON invoices(customer_id);

CREATE INDEX IF NOT EXISTS idx_inv_status   ON invoices(status);

CREATE INDEX IF NOT EXISTS idx_ioc_cache_expiry   ON ioc_enrichment_cache(ttl_expires);

CREATE INDEX IF NOT EXISTS idx_ioc_cache_type     ON ioc_enrichment_cache(ioc_type);

CREATE INDEX IF NOT EXISTS idx_ioc_cache_value    ON ioc_enrichment_cache(ioc_value);

CREATE INDEX IF NOT EXISTS idx_ioc_cache_verdict  ON ioc_enrichment_cache(verdict);

CREATE INDEX IF NOT EXISTS idx_ioc_intel_id            ON ioc_registry(intel_id);

CREATE INDEX IF NOT EXISTS idx_ioc_requests_created ON ioc_requests(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_requests_user    ON ioc_requests(user_id);

CREATE INDEX IF NOT EXISTS idx_ioc_type                ON ioc_registry(type);

CREATE INDEX IF NOT EXISTS idx_iocs_active            ON cti_iocs(is_active);

CREATE INDEX IF NOT EXISTS idx_iocs_actor             ON cti_iocs(related_actor_id);

CREATE INDEX IF NOT EXISTS idx_iocs_created           ON cti_iocs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_iocs_severity          ON cti_iocs(severity);

CREATE INDEX IF NOT EXISTS idx_key_usage_key    ON api_key_usage(key_id, date_bucket);

CREATE INDEX IF NOT EXISTS idx_key_usage_user   ON api_key_usage(user_id, date_bucket);

CREATE INDEX IF NOT EXISTS idx_leads_created     ON leads(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_leads_email       ON leads(email);

CREATE INDEX IF NOT EXISTS idx_leads_enterprise  ON leads(is_enterprise);

CREATE INDEX IF NOT EXISTS idx_leads_plan        ON leads(plan);

CREATE INDEX IF NOT EXISTS idx_leads_score       ON leads(lead_score DESC);

CREATE INDEX IF NOT EXISTS idx_lic_status        ON licenses(status);

CREATE INDEX IF NOT EXISTS idx_lic_user          ON licenses(user_id);

CREATE INDEX IF NOT EXISTS idx_license_status ON billing_license_keys(status);

CREATE INDEX IF NOT EXISTS idx_license_user ON billing_license_keys(user_id);

CREATE INDEX IF NOT EXISTS idx_licenses_email  ON licenses(email);

CREATE INDEX IF NOT EXISTS idx_licenses_key    ON licenses(license_key);

CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);

CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email, attempted_at);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip    ON login_attempts(ip_address, attempted_at);

CREATE INDEX IF NOT EXISTS idx_loss_prev_converted ON mcp_loss_prevention(converted, trigger_type);

CREATE INDEX IF NOT EXISTS idx_mcp_ab_experiment ON mcp_ab_results(experiment_id, variant);

CREATE INDEX IF NOT EXISTS idx_mcp_feedback_context   ON mcp_feedback(context, action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_feedback_item      ON mcp_feedback(item_id, action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_feedback_module    ON mcp_feedback(module, action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_feedback_type      ON mcp_feedback(recommendation_type, action);

CREATE INDEX IF NOT EXISTS idx_mcp_scans_email ON mcp_security_scans(user_email);

CREATE INDEX IF NOT EXISTS idx_mcp_scans_risk  ON mcp_security_scans(risk_level);

CREATE INDEX IF NOT EXISTS idx_mcp_scores_score ON mcp_item_scores(mcp_score DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_scores_type  ON mcp_item_scores(recommendation_type, mcp_score DESC);

CREATE INDEX IF NOT EXISTS idx_monitor_user ON monitor_configs(user_id, enabled);

CREATE INDEX IF NOT EXISTS idx_mssp_api_key ON mssp_partners(api_key);

CREATE INDEX IF NOT EXISTS idx_mssp_clients_partner ON mssp_clients(partner_id);

CREATE INDEX IF NOT EXISTS idx_mssp_health ON mssp_clients(health_score );

CREATE INDEX IF NOT EXISTS idx_mssp_health ON mssp_clients(health_score DESC);

CREATE INDEX IF NOT EXISTS idx_mssp_health ON mssp_clients(health_score);

CREATE INDEX IF NOT EXISTS idx_mssp_owner  ON mssp_clients(mssp_user_id);

CREATE INDEX IF NOT EXISTS idx_mssp_owner ON mssp_clients(mssp_user_id);

CREATE INDEX IF NOT EXISTS idx_mssp_p_apikey ON mssp_partners(api_key);

CREATE INDEX IF NOT EXISTS idx_mssp_p_status ON mssp_partners(status);

CREATE INDEX IF NOT EXISTS idx_mssp_status ON mssp_clients(status);

CREATE INDEX IF NOT EXISTS idx_mssp_status ON mssp_partners(status);

CREATE INDEX IF NOT EXISTS idx_mssp_tenant_audit_mssp ON mssp_tenant_audit(mssp_org_id, created_at);

CREATE INDEX IF NOT EXISTS idx_mssp_tenant_audit_tenant ON mssp_tenant_audit(tenant_org_id, created_at);

CREATE INDEX IF NOT EXISTS idx_mythos_runs_run_at ON mythos_runs(run_at);

CREATE INDEX IF NOT EXISTS idx_mythos_runs_status ON mythos_runs(status);

CREATE INDEX IF NOT EXISTS idx_notif_log_created   ON notification_log(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_notif_log_org       ON notification_log(org_id);

CREATE INDEX IF NOT EXISTS idx_notif_log_recipient ON notification_log(recipient_id);

CREATE INDEX IF NOT EXISTS idx_notif_log_status    ON notification_log(status);

CREATE INDEX IF NOT EXISTS idx_notif_prefs_org ON notification_preferences(org_id);

CREATE INDEX IF NOT EXISTS idx_offer_perf_rpi    ON mcp_offer_performance(revenue_per_impression DESC);

CREATE INDEX IF NOT EXISTS idx_offer_perf_score  ON mcp_offer_performance(revenue_score DESC);

CREATE INDEX IF NOT EXISTS idx_opp_score ON sales_opportunities(score DESC);

CREATE INDEX IF NOT EXISTS idx_opp_score ON sales_opportunities(score);

CREATE INDEX IF NOT EXISTS idx_opp_stage ON sales_opportunities(stage);

CREATE INDEX IF NOT EXISTS idx_opp_tier ON sales_opportunities(tier);

CREATE INDEX IF NOT EXISTS idx_orders_created ON service_orders(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_orders_email   ON service_orders(customer_email);

CREATE INDEX IF NOT EXISTS idx_orders_ref     ON service_orders(ref_id);

CREATE INDEX IF NOT EXISTS idx_orders_status  ON service_orders(order_status);

CREATE INDEX IF NOT EXISTS idx_orders_token   ON service_orders(report_token);

CREATE INDEX IF NOT EXISTS idx_org_events_created ON org_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_org_events_org     ON org_events(org_id);

CREATE INDEX IF NOT EXISTS idx_org_events_type    ON org_events(event_type);

CREATE INDEX IF NOT EXISTS idx_org_members_org  ON org_members(org_id);

CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);

CREATE INDEX IF NOT EXISTS idx_org_owner ON organizations(owner_id);

CREATE INDEX IF NOT EXISTS idx_org_plan  ON organizations(plan);

CREATE INDEX IF NOT EXISTS idx_org_slug  ON organizations(slug);

CREATE INDEX IF NOT EXISTS idx_outreach_email    ON sales_outreach(email);

CREATE INDEX IF NOT EXISTS idx_outreach_status   ON sales_outreach(status);

CREATE INDEX IF NOT EXISTS idx_p0_exceptions_entry_id ON p0_exceptions(entry_id);

CREATE INDEX IF NOT EXISTS idx_p0_exceptions_logged_at ON p0_exceptions(logged_at);

CREATE INDEX IF NOT EXISTS idx_payments_module     ON payments(module, status);

CREATE INDEX IF NOT EXISTS idx_payments_razorpay   ON payments(razorpay_order_id);

CREATE INDEX IF NOT EXISTS idx_payments_status     ON payments(status, created_at);

CREATE INDEX IF NOT EXISTS idx_payments_target     ON payments(target, module);

CREATE INDEX IF NOT EXISTS idx_payments_user       ON payments(user_id);

CREATE INDEX IF NOT EXISTS idx_paypal_order ON paypal_transactions(paypal_order_id);

CREATE INDEX IF NOT EXISTS idx_pipeline_log_lead ON crm_pipeline_log(lead_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pipeline_log_stage ON crm_pipeline_log(to_stage, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_token   ON customer_portal_sessions(token);

CREATE INDEX IF NOT EXISTS idx_portal_user_id ON customer_portal_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_pp_created ON product_pipeline(created_at);

CREATE INDEX IF NOT EXISTS idx_pp_cve    ON product_pipeline(cve_id);

CREATE INDEX IF NOT EXISTS idx_pp_cve ON product_pipeline(cve_id);

CREATE INDEX IF NOT EXISTS idx_pp_status ON product_pipeline(status);

CREATE INDEX IF NOT EXISTS idx_pred_cve      ON threat_predictions(cve_id);

CREATE INDEX IF NOT EXISTS idx_pred_date     ON threat_predictions(prediction_date DESC);

CREATE INDEX IF NOT EXISTS idx_pred_prob     ON threat_predictions(probability_pct DESC);

CREATE INDEX IF NOT EXISTS idx_pred_risk     ON threat_predictions(risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_pred_window   ON threat_predictions(expected_window_hrs);

CREATE INDEX IF NOT EXISTS idx_pricing_variant   ON pricing_experiments(variant);

CREATE INDEX IF NOT EXISTS idx_prop_created ON proposals(created_at );

CREATE INDEX IF NOT EXISTS idx_prop_created ON proposals(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_prop_created ON proposals(created_at);

CREATE INDEX IF NOT EXISTS idx_prop_deal    ON proposals(deal_id);

CREATE INDEX IF NOT EXISTS idx_prop_deal ON proposals(deal_id);

CREATE INDEX IF NOT EXISTS idx_prop_status  ON proposals(status);

CREATE INDEX IF NOT EXISTS idx_prop_status ON proposals(status);

CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_proposals_email ON proposals(contact_email);

CREATE INDEX IF NOT EXISTS idx_proposals_lead    ON proposals(lead_id);

CREATE INDEX IF NOT EXISTS idx_proposals_status  ON proposals(status);

CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);

CREATE INDEX IF NOT EXISTS idx_recovery_next_retry ON billing_recovery_queue(next_retry_at);

CREATE INDEX IF NOT EXISTS idx_recovery_retry  ON payment_recovery(next_retry_at);

CREATE INDEX IF NOT EXISTS idx_recovery_retry ON billing_recovery_queue(next_retry_at);

CREATE INDEX IF NOT EXISTS idx_recovery_status ON billing_recovery_queue(status);

CREATE INDEX IF NOT EXISTS idx_recovery_status ON payment_recovery(status);

CREATE INDEX IF NOT EXISTS idx_recovery_user   ON payment_recovery(user_id);

CREATE INDEX IF NOT EXISTS idx_ref_affiliate ON affiliate_referrals(affiliate_id);

CREATE INDEX IF NOT EXISTS idx_ref_code ON affiliate_referrals(ref_code);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash   ON refresh_tokens(token_hash);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_refund_payment ON refunds(payment_id);

CREATE INDEX IF NOT EXISTS idx_refund_status  ON refunds(status);

CREATE INDEX IF NOT EXISTS idx_refunds_email  ON refund_requests(email);

CREATE INDEX IF NOT EXISTS idx_refunds_status ON refund_requests(status);

CREATE INDEX IF NOT EXISTS idx_region_country    ON region_events(country);

CREATE INDEX IF NOT EXISTS idx_release_date    ON release_notes(published_at);

CREATE INDEX IF NOT EXISTS idx_release_version ON release_notes(version);

CREATE INDEX IF NOT EXISTS idx_renewal_date   ON renewal_queue(renewal_date);

CREATE INDEX IF NOT EXISTS idx_renewal_status ON renewal_queue(status);

CREATE INDEX IF NOT EXISTS idx_report_expires      ON report_access(expires_at);

CREATE INDEX IF NOT EXISTS idx_report_scan_id      ON report_access(scan_id);

CREATE INDEX IF NOT EXISTS idx_report_token        ON report_access(token);

CREATE INDEX IF NOT EXISTS idx_report_user         ON report_access(user_id);

CREATE INDEX IF NOT EXISTS idx_reports_created  ON report_jobs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reports_org      ON report_jobs(org_id);

CREATE INDEX IF NOT EXISTS idx_reports_status   ON report_jobs(status);

CREATE INDEX IF NOT EXISTS idx_reports_type     ON report_jobs(report_type);

CREATE INDEX IF NOT EXISTS idx_rev_created ON revenue_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rev_events_context  ON mcp_revenue_events(context, event_type);

CREATE INDEX IF NOT EXISTS idx_rev_events_date     ON mcp_revenue_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rev_events_offer    ON mcp_revenue_events(offer_id, event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rev_events_type     ON mcp_revenue_events(offer_type, event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rev_snapshot ON revenue_snapshots(snapshot_at DESC);

CREATE INDEX IF NOT EXISTS idx_rev_source  ON revenue_events(source);

CREATE INDEX IF NOT EXISTS idx_rev_user    ON revenue_events(user_id);

CREATE INDEX IF NOT EXISTS idx_revenue_snapshots_date ON revenue_snapshots(org_id, snapshot_date);

CREATE INDEX IF NOT EXISTS idx_revenue_snapshots_date ON revenue_snapshots(snapshot_date DESC);

CREATE INDEX IF NOT EXISTS idx_revos_mrr_date ON revos_mrr_snapshots(snapshot_date DESC);

CREATE INDEX IF NOT EXISTS idx_revos_mrr_date ON revos_mrr_snapshots(snapshot_date);

CREATE INDEX IF NOT EXISTS idx_roles_user ON user_roles(user_id);

CREATE INDEX IF NOT EXISTS idx_rt_attempts_engagement ON ai_redteam_attempts(engagement_id);

CREATE INDEX IF NOT EXISTS idx_rt_attempts_success    ON ai_redteam_attempts(success);

CREATE INDEX IF NOT EXISTS idx_rt_attempts_type       ON ai_redteam_attempts(attack_type);

CREATE INDEX IF NOT EXISTS idx_rt_engagements_email  ON ai_redteam_engagements(email);

CREATE INDEX IF NOT EXISTS idx_rt_engagements_status ON ai_redteam_engagements(status);

CREATE INDEX IF NOT EXISTS idx_scan_history_module ON scan_history(user_id, module, scanned_at);

CREATE INDEX IF NOT EXISTS idx_scan_history_target ON scan_history(user_id, target);

CREATE INDEX IF NOT EXISTS idx_scan_history_user   ON scan_history(user_id, scanned_at);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created  ON scan_jobs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_identity ON scan_jobs(identity, created_at);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_module   ON scan_jobs(module);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status   ON scan_jobs(status);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status   ON scan_jobs(status, created_at);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user     ON scan_jobs(user_id);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user     ON scan_jobs(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_scan_token_audit_ip_hash ON scan_token_audit(ip_hash);

CREATE INDEX IF NOT EXISTS idx_scan_token_audit_nonce ON scan_token_audit(nonce);

CREATE INDEX IF NOT EXISTS idx_scanner_status ON scanner_orders(status);

CREATE INDEX IF NOT EXISTS idx_scanner_token ON scanner_orders(token);

CREATE INDEX IF NOT EXISTS idx_scanner_user ON scanner_orders(user_id);

CREATE INDEX IF NOT EXISTS idx_scanord_status  ON scan_orders(payment_status);

CREATE INDEX IF NOT EXISTS idx_scanord_token   ON scan_orders(report_token);

CREATE INDEX IF NOT EXISTS idx_scanord_user    ON scan_orders(user_id);

CREATE INDEX IF NOT EXISTS idx_searches_created ON saved_searches(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_searches_org     ON saved_searches(org_id);

CREATE INDEX IF NOT EXISTS idx_searches_user    ON saved_searches(user_id);

CREATE INDEX IF NOT EXISTS idx_services_active ON services(active);

CREATE INDEX IF NOT EXISTS idx_services_tier   ON services(tier);

CREATE INDEX IF NOT EXISTS idx_session_bl_hash ON session_blacklist(token_hash);

CREATE INDEX IF NOT EXISTS idx_session_bl_user ON session_blacklist(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_token     ON user_sessions(session_token);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id   ON user_sessions(user_id, is_active);

CREATE INDEX IF NOT EXISTS idx_sh_scanned  ON scan_history(scanned_at DESC);

CREATE INDEX IF NOT EXISTS idx_sh_user     ON scan_history(user_id);

CREATE INDEX IF NOT EXISTS idx_snapshots_at ON revenue_snapshots(snapshot_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_alerts_created      ON soc_alerts(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_alerts_severity     ON soc_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_soc_alerts_type         ON soc_alerts(alert_type);

CREATE INDEX IF NOT EXISTS idx_soc_cases_created   ON soc_cases(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_cases_org_id    ON soc_cases(org_id);

CREATE INDEX IF NOT EXISTS idx_soc_cases_severity  ON soc_cases(severity);

CREATE INDEX IF NOT EXISTS idx_soc_cases_status    ON soc_cases(status);

CREATE INDEX IF NOT EXISTS idx_soc_decisions_created   ON soc_decisions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_decisions_priority  ON soc_decisions(priority);

CREATE INDEX IF NOT EXISTS idx_soc_defense_action      ON soc_defense_actions(defense_action);

CREATE INDEX IF NOT EXISTS idx_soc_defense_created     ON soc_defense_actions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_evidence_case_id ON soc_evidence(case_id, org_id);

CREATE INDEX IF NOT EXISTS idx_soc_notes_case_id ON soc_notes(case_id, org_id);

CREATE INDEX IF NOT EXISTS idx_soc_response_priority   ON soc_response_actions(priority);

CREATE INDEX IF NOT EXISTS idx_soc_timeline_case_id ON soc_timeline(case_id, org_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_sub_created  ON subscriptions(created_at );

CREATE INDEX IF NOT EXISTS idx_sub_created  ON subscriptions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sub_created ON subscriptions(created_at);

CREATE INDEX IF NOT EXISTS idx_sub_email    ON subscriptions(email);

CREATE INDEX IF NOT EXISTS idx_sub_email ON subscriptions(email);

CREATE INDEX IF NOT EXISTS idx_sub_plan     ON subscriptions(plan);

CREATE INDEX IF NOT EXISTS idx_sub_plan ON subscriptions(plan);

CREATE INDEX IF NOT EXISTS idx_sub_status   ON subscriptions(status);

CREATE INDEX IF NOT EXISTS idx_sub_status ON subscriptions(status);

CREATE INDEX IF NOT EXISTS idx_sub_user     ON subscriptions(user_id);

CREATE INDEX IF NOT EXISTS idx_sub_user ON subscriptions(user_id);

CREATE INDEX IF NOT EXISTS idx_subs_email    ON subscriptions(email);

CREATE INDEX IF NOT EXISTS idx_subs_plan     ON subscriptions(plan);

CREATE INDEX IF NOT EXISTS idx_subs_status   ON subscriptions(status);

CREATE INDEX IF NOT EXISTS idx_subscriptions_email ON subscriptions(email);

CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);

CREATE INDEX IF NOT EXISTS idx_themes_domain ON tenant_themes(custom_domain);

CREATE INDEX IF NOT EXISTS idx_threat_intel_active     ON threat_intel(actively_exploited);

CREATE INDEX IF NOT EXISTS idx_threat_intel_active_exp ON threat_intel(actively_exploited);

CREATE INDEX IF NOT EXISTS idx_threat_intel_created    ON threat_intel(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intel_epss       ON threat_intel(epss_score DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intel_epss ON threat_intel(epss_score DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intel_exploit    ON threat_intel(exploit_status);

CREATE INDEX IF NOT EXISTS idx_threat_intel_exploit_status ON threat_intel(exploit_status);

CREATE INDEX IF NOT EXISTS idx_threat_intel_published  ON threat_intel(published_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intel_ransomware ON threat_intel(known_ransomware);

CREATE INDEX IF NOT EXISTS idx_threat_intel_severity   ON threat_intel(severity);

CREATE INDEX IF NOT EXISTS idx_threat_intel_source     ON threat_intel(source);

CREATE INDEX IF NOT EXISTS idx_ti_cve       ON threat_intel(cve_id);

CREATE INDEX IF NOT EXISTS idx_ti_cvss      ON threat_intel(cvss_score DESC);

CREATE INDEX IF NOT EXISTS idx_ti_cvss_v22        ON threat_intel(cvss DESC);

CREATE INDEX IF NOT EXISTS idx_ti_exploit_status  ON threat_intel(exploit_status);

CREATE INDEX IF NOT EXISTS idx_ti_exploited ON threat_intel(is_exploited);

CREATE INDEX IF NOT EXISTS idx_ti_ingested  ON threat_intel(ingested_at DESC);

CREATE INDEX IF NOT EXISTS idx_ti_known_ransomware ON threat_intel(known_ransomware);

CREATE INDEX IF NOT EXISTS idx_ti_published ON threat_intel(published_at DESC);

CREATE INDEX IF NOT EXISTS idx_ti_severity  ON threat_intel(severity);

CREATE INDEX IF NOT EXISTS idx_tprm_domain     ON tprm_vendors(vendor_domain);

CREATE INDEX IF NOT EXISTS idx_tprm_risk_score ON tprm_vendors(risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_tprm_user       ON tprm_vendors(user_id);

CREATE INDEX IF NOT EXISTS idx_trust_inc_status ON trust_incidents(status);

CREATE INDEX IF NOT EXISTS idx_trust_incidents_status ON trust_incidents(status);

CREATE INDEX IF NOT EXISTS idx_trust_signals_verified ON trust_signals(verified, visible);

CREATE INDEX IF NOT EXISTS idx_upsell_email      ON upsell_events(email);

CREATE INDEX IF NOT EXISTS idx_upsell_events_org_id ON upsell_events(org_id, created_at);

CREATE INDEX IF NOT EXISTS idx_upsell_trigger    ON upsell_events(trigger_type);

CREATE INDEX IF NOT EXISTS idx_uptime_checked ON uptime_log(checked_at);

CREATE INDEX IF NOT EXISTS idx_uptime_service ON uptime_log(service);

CREATE INDEX IF NOT EXISTS idx_usage_created ON api_usage_log(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_ep      ON api_usage_log(endpoint);

CREATE INDEX IF NOT EXISTS idx_usage_key     ON api_usage_log(api_key_id);

CREATE INDEX IF NOT EXISTS idx_usage_user    ON api_usage_log(user_id);

CREATE INDEX IF NOT EXISTS idx_user_profiles_behavior ON user_profiles(conversion_behavior);

CREATE INDEX IF NOT EXISTS idx_user_profiles_pattern  ON user_profiles(risk_pattern);

CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_status    ON users(status);

CREATE INDEX IF NOT EXISTS idx_users_tier      ON users(tier);

CREATE INDEX IF NOT EXISTS idx_uta_active      ON user_tool_access(is_active, expires_at);

CREATE INDEX IF NOT EXISTS idx_uta_email       ON user_tool_access(email);

CREATE INDEX IF NOT EXISTS idx_uta_product     ON user_tool_access(product_id);

CREATE INDEX IF NOT EXISTS idx_vibe_scans_email ON vibe_code_scans(user_email);

CREATE INDEX IF NOT EXISTS idx_vibe_scans_risk  ON vibe_code_scans(risk_level);

CREATE INDEX IF NOT EXISTS idx_vp_active ON virtual_patches(is_active, priority);

CREATE INDEX IF NOT EXISTS idx_vp_cve    ON virtual_patches(cve_id, is_active);

CREATE INDEX IF NOT EXISTS idx_webhook_events_payment_id ON webhook_events(payment_id);

CREATE INDEX IF NOT EXISTS idx_webhook_events_processed_at ON webhook_events(processed_at);

CREATE INDEX IF NOT EXISTS idx_workflows_active    ON workflows(is_active);

CREATE INDEX IF NOT EXISTS idx_workflows_org       ON workflows(org_id);

CREATE INDEX IF NOT EXISTS idx_workflows_template  ON workflows(is_template);

CREATE INDEX IF NOT EXISTS idx_workflows_trigger   ON workflows(trigger_type);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_posture_date ON ai_posture_scores(org_id, score_date);

CREATE UNIQUE INDEX IF NOT EXISTS idx_apisum_key_period ON api_usage_summary(api_key_id, period);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ceo_kpi_date ON ceo_kpi_snapshots(snapshot_date);

CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_slug ON mssp_customers(org_slug);

CREATE UNIQUE INDEX IF NOT EXISTS idx_inv_number ON invoices(invoice_number);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON cti_iocs(ioc_type, value);

CREATE UNIQUE INDEX IF NOT EXISTS idx_lic_key    ON licenses(license_key);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mrr_date ON mrr_snapshots(snapshot_date);

CREATE UNIQUE INDEX IF NOT EXISTS idx_msspbill_period ON mssp_billing(client_id, period);

CREATE UNIQUE INDEX IF NOT EXISTS idx_revstream_period ON revenue_streams(period, stream);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rl_identifier ON rate_limit_log(identifier, window);

CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_period ON revenue_snapshots(period);

PRAGMA foreign_keys = ON;

-- Schema master contains 198 tables and 540 indexes
-- ============================================================================
-- v20.0 GOD MODE: AI GOVERNANCE PRO TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS ai_model_registry (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0',
  model_type TEXT NOT NULL,
  data_classification TEXT NOT NULL,
  deployment_context TEXT NOT NULL,
  autonomy_level TEXT NOT NULL,
  impact_domain TEXT NOT NULL,
  explainability TEXT NOT NULL,
  bias_tested INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 0,
  risk_level TEXT NOT NULL DEFAULT 'LOW',
  eu_ai_act_category TEXT NOT NULL DEFAULT 'MINIMAL',
  owner_email TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  metadata TEXT DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_model_registry_org ON ai_model_registry(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_model_registry_risk ON ai_model_registry(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_model_registry_eu ON ai_model_registry(eu_ai_act_category);
CREATE INDEX IF NOT EXISTS idx_ai_model_registry_status ON ai_model_registry(status);

CREATE TABLE IF NOT EXISTS ai_governance_policies (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  rules TEXT DEFAULT '[]',
  enforcement_level TEXT NOT NULL DEFAULT 'WARN',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_governance_policies_org ON ai_governance_policies(org_id);

-- ============================================================================
-- v20.0 GOD MODE: AI RED TEAM PRO TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS ai_redteam_campaigns (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  target_model TEXT NOT NULL DEFAULT 'unknown',
  target_endpoint TEXT DEFAULT '',
  technique_ids TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_by TEXT DEFAULT 'anonymous',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_redteam_campaigns_org ON ai_redteam_campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_redteam_campaigns_status ON ai_redteam_campaigns(status);

-- ============================================================================
-- v20.0 GOD MODE: DEVELOPER PORTAL TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS developer_webhooks (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  url TEXT NOT NULL,
  events TEXT DEFAULT '[]',
  secret TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  last_tested_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_developer_webhooks_org ON developer_webhooks(org_id);
CREATE INDEX IF NOT EXISTS idx_developer_webhooks_status ON developer_webhooks(status);

-- api_keys table extends existing (add if not exist)
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL DEFAULT 'Default Key',
  key_hash TEXT NOT NULL,
  scopes TEXT DEFAULT '["read"]',
  expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);

-- ============================================================================
-- v20.0 GOD MODE: EXECUTIVE COMMAND CENTER TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS fair_risk_assessments (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  scenario_name TEXT NOT NULL DEFAULT 'Unnamed Scenario',
  inputs TEXT DEFAULT '{}',
  outputs TEXT DEFAULT '{}',
  risk_level TEXT NOT NULL DEFAULT 'LOW',
  ale INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fair_risk_assessments_org ON fair_risk_assessments(org_id);
CREATE INDEX IF NOT EXISTS idx_fair_risk_assessments_risk ON fair_risk_assessments(risk_level);
CREATE INDEX IF NOT EXISTS idx_fair_risk_assessments_ale ON fair_risk_assessments(ale DESC);

CREATE TABLE IF NOT EXISTS executive_kri_values (
  org_id TEXT NOT NULL,
  period TEXT NOT NULL,
  kri_values TEXT DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (org_id, period)
);

CREATE TABLE IF NOT EXISTS executive_reports (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  report_type TEXT NOT NULL DEFAULT 'BOARD',
  quarter TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_executive_reports_org ON executive_reports(org_id);
CREATE INDEX IF NOT EXISTS idx_executive_reports_type ON executive_reports(report_type);
