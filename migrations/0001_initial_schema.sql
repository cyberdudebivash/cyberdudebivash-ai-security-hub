-- ============================================================
-- Sentinel APEX + MYTHOS Platform — Production Schema
-- Migration: 0001_initial_schema.sql
-- Apply: wrangler d1 execute SENTINEL_DB --file=migrations/0001_initial_schema.sql
-- ============================================================

-- ── Subscriptions ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
  id                TEXT PRIMARY KEY,           -- uuid v4
  user_id           TEXT NOT NULL,
  email             TEXT NOT NULL,
  tier              TEXT NOT NULL CHECK(tier IN ('free','starter','pro','enterprise','mssp')),
  status            TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled','expired','suspended')),
  razorpay_order_id TEXT,
  razorpay_payment_id TEXT UNIQUE,
  amount_paise      INTEGER NOT NULL DEFAULT 0,
  currency          TEXT NOT NULL DEFAULT 'INR',
  activated_at      INTEGER,                    -- unix epoch seconds
  expires_at        INTEGER,                    -- unix epoch seconds
  cancelled_at      INTEGER,
  created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user    ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status  ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_tier    ON subscriptions(tier);
CREATE INDEX IF NOT EXISTS idx_subscriptions_payment ON subscriptions(razorpay_payment_id);

-- ── Webhook events (idempotency + audit) ─────────────────────
CREATE TABLE IF NOT EXISTS webhook_events (
  id              TEXT PRIMARY KEY,             -- razorpay event id
  event_type      TEXT NOT NULL,
  payment_id      TEXT,
  order_id        TEXT,
  payload_hash    TEXT NOT NULL,                -- sha256 of raw body
  processed_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  processing_ms   INTEGER,
  outcome         TEXT NOT NULL CHECK(outcome IN ('processed','skipped_duplicate','failed')),
  error_message   TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_webhook_payment ON webhook_events(payment_id);
CREATE INDEX IF NOT EXISTS idx_webhook_event   ON webhook_events(event_type);

-- ── CVE feed ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_feed (
  cve_id          TEXT PRIMARY KEY,             -- CVE-YYYY-NNNNN
  source          TEXT NOT NULL CHECK(source IN ('nvd','cisa_kev','manual')),
  severity        TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','unknown')),
  cvss_score      REAL,
  description     TEXT NOT NULL DEFAULT '',
  affected_vendor TEXT,
  affected_product TEXT,
  published_at    INTEGER,
  is_kev          INTEGER NOT NULL DEFAULT 0,   -- CISA Known Exploited
  kev_due_date    INTEGER,
  ingested_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_cve_severity    ON cve_feed(severity);
CREATE INDEX IF NOT EXISTS idx_cve_ingested    ON cve_feed(ingested_at);
CREATE INDEX IF NOT EXISTS idx_cve_kev         ON cve_feed(is_kev);
CREATE INDEX IF NOT EXISTS idx_cve_source      ON cve_feed(source);

-- ── Scans ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id              TEXT PRIMARY KEY,             -- uuid v4
  user_id         TEXT,                         -- null = anonymous
  target_domain   TEXT NOT NULL,
  scan_module     TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed')),
  threat_score    INTEGER,                      -- 0-100
  critical_count  INTEGER NOT NULL DEFAULT 0,
  high_count      INTEGER NOT NULL DEFAULT 0,
  medium_count    INTEGER NOT NULL DEFAULT 0,
  low_count       INTEGER NOT NULL DEFAULT 0,
  tier_at_scan    TEXT NOT NULL DEFAULT 'free',
  duration_ms     INTEGER,
  error_message   TEXT,
  started_at      INTEGER,
  completed_at    INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_scans_user      ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status    ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created   ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_domain    ON scans(target_domain);

-- ── SOAR rules ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_rules (
  id              TEXT PRIMARY KEY,             -- uuid v4
  rule_type       TEXT NOT NULL CHECK(rule_type IN ('sigma','yara','kql','suricata','splunk')),
  cve_id          TEXT,
  scan_id         TEXT,
  title           TEXT NOT NULL,
  content         TEXT NOT NULL,
  generated_by    TEXT NOT NULL DEFAULT 'mythos',
  customer_visible INTEGER NOT NULL DEFAULT 1,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_soar_type       ON soar_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_soar_cve        ON soar_rules(cve_id);

-- ── Platform health log ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS health_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  component       TEXT NOT NULL CHECK(component IN ('api','db','cache','sentinel_apex','mythos','cve_ingester','webhook')),
  status          TEXT NOT NULL CHECK(status IN ('ok','degraded','down')),
  latency_ms      INTEGER,
  detail          TEXT,
  checked_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_health_component ON health_log(component);
CREATE INDEX IF NOT EXISTS idx_health_checked   ON health_log(checked_at);

-- ── CRM pipeline ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS crm_leads (
  id              TEXT PRIMARY KEY,             -- uuid v4
  org_name        TEXT NOT NULL,
  contact_email   TEXT,
  contact_phone   TEXT,
  domain          TEXT,
  industry        TEXT,
  estimated_arr   INTEGER NOT NULL DEFAULT 0,   -- INR paise
  stage           TEXT NOT NULL DEFAULT 'new' CHECK(stage IN ('new','qualified','demo_booked','demo_done','proposal_sent','negotiation','closed_won','closed_lost')),
  source          TEXT DEFAULT 'organic',       -- scan, referral, organic, outbound
  scan_id         TEXT,                         -- linked scan if from scan
  threat_score    INTEGER,
  notes           TEXT,
  converted_at    INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_crm_stage        ON crm_leads(stage);
CREATE INDEX IF NOT EXISTS idx_crm_source       ON crm_leads(source);

-- ── Compliance alignments (replaces certification badges) ─────
CREATE TABLE IF NOT EXISTS compliance_alignments (
  id              TEXT PRIMARY KEY,
  framework       TEXT NOT NULL,                -- 'iso27001','soc2','pcidss','gdpr','dpdp','hipaa','owasp_llm','mitre','nist_ai'
  alignment_level TEXT NOT NULL CHECK(alignment_level IN ('aligned','partial','certified')),
  scope_note      TEXT NOT NULL,
  auditor         TEXT,
  cert_number     TEXT,
  valid_from      INTEGER,
  valid_until     INTEGER,
  evidence_url    TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Seed honest alignment records (not certification)
INSERT OR IGNORE INTO compliance_alignments (id, framework, alignment_level, scope_note) VALUES
  ('align-iso27001', 'iso27001',  'aligned', 'Platform architecture and data handling practices aligned to ISO 27001:2022 Annex A controls. Formal audit not yet completed.'),
  ('align-soc2',     'soc2',      'aligned', 'Security and availability trust service criteria addressed in platform design. SOC 2 Type II audit not yet completed.'),
  ('align-pcidss',   'pcidss',    'aligned', 'Payment data handled via Razorpay; platform itself does not store card data. PCI-DSS compliance via payment processor.'),
  ('align-gdpr',     'gdpr',      'aligned', 'Data minimization and purpose limitation controls implemented. DPA not yet appointed for EU operations.'),
  ('align-dpdp',     'dpdp',      'aligned', 'DPDP Act 2023 obligations as Data Fiduciary implemented for Indian users. Consent management active.'),
  ('align-hipaa',    'hipaa',     'partial', 'Security controls aligned to HIPAA Security Rule. BAA not yet available. Not recommended for covered entity PHI.'),
  ('align-owasp',    'owasp_llm', 'aligned', 'OWASP LLM Top 10 mapped to scan modules and AI analyst outputs.'),
  ('align-mitre',    'mitre',     'aligned', 'MITRE ATT&CK framework used for TTP mapping in scan results and SOAR rule generation.'),
  ('align-nist',     'nist_ai',   'aligned', 'NIST AI RMF governance controls mapped to AI Governance pillar.');
