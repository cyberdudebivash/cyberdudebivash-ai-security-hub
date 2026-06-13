-- ─────────────────────────────────────────────────────────────────────────────
-- SENTINEL APEX™ Intelligence Marketplace — Schema v39
-- Tables: marketplace_orders, customer_entitlements, intel_subscriptions,
--         customer_tenants, provisioning_log, report_catalog
-- ─────────────────────────────────────────────────────────────────────────────

-- Customer Tenants — one row per paying customer (multi-tenant isolation)
CREATE TABLE IF NOT EXISTS customer_tenants (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  company_name     TEXT,
  tier             TEXT NOT NULL DEFAULT 'FREE'
                     CHECK(tier IN ('FREE','STARTER','PRO','TEAM','ENTERPRISE','MSSP')),
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','suspended','cancelled','trial')),
  trial_ends_at    TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tenants_user   ON customer_tenants(user_id);
CREATE INDEX IF NOT EXISTS idx_tenants_tier   ON customer_tenants(tier);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON customer_tenants(status);

-- Marketplace Orders — every one-time purchase
CREATE TABLE IF NOT EXISTS marketplace_orders (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,
  tenant_id        TEXT,
  product_id       TEXT NOT NULL,
  product_name     TEXT NOT NULL,
  sku              TEXT,
  category         TEXT NOT NULL,   -- report|api_subscription|dashboard|service|bundle
  amount_usd       REAL NOT NULL DEFAULT 0,
  amount_inr       INTEGER NOT NULL DEFAULT 0,
  currency         TEXT NOT NULL DEFAULT 'USD',
  status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending','paid','failed','refunded','cancelled')),
  payment_provider TEXT,            -- razorpay|gumroad|stripe|manual
  payment_ref      TEXT,            -- provider order / payment ID
  razorpay_order_id TEXT,
  gumroad_sale_id  TEXT,
  download_url     TEXT,            -- secure report download link
  download_expires_at TEXT,         -- URL TTL
  invoice_number   TEXT UNIQUE,
  metadata         TEXT DEFAULT '{}',
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (tenant_id) REFERENCES customer_tenants(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_mktorders_user      ON marketplace_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_mktorders_status    ON marketplace_orders(status);
CREATE INDEX IF NOT EXISTS idx_mktorders_product   ON marketplace_orders(product_id);
CREATE INDEX IF NOT EXISTS idx_mktorders_created   ON marketplace_orders(created_at);
CREATE INDEX IF NOT EXISTS idx_mktorders_razorpay  ON marketplace_orders(razorpay_order_id);

-- Intel Subscriptions — recurring intelligence subscriptions
CREATE TABLE IF NOT EXISTS intel_subscriptions (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,
  tenant_id        TEXT,
  plan_id          TEXT NOT NULL,   -- api-free|api-pro|api-team|api-enterprise|feed-*
  plan_name        TEXT NOT NULL,
  tier             TEXT NOT NULL DEFAULT 'FREE',
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','paused','cancelled','past_due','trialing','expired')),
  billing_period   TEXT NOT NULL DEFAULT 'monthly'
                     CHECK(billing_period IN ('monthly','annual','custom')),
  price_usd        REAL NOT NULL DEFAULT 0,
  price_inr        INTEGER NOT NULL DEFAULT 0,
  current_period_start TEXT,
  current_period_end   TEXT,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  trial_start      TEXT,
  trial_end        TEXT,
  payment_provider TEXT,
  subscription_ref TEXT,           -- provider subscription ID
  cancel_reason    TEXT,
  upgrade_from     TEXT,
  metadata         TEXT DEFAULT '{}',
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (tenant_id) REFERENCES customer_tenants(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_intelsub_user   ON intel_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_intelsub_status ON intel_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_intelsub_plan   ON intel_subscriptions(plan_id);
CREATE INDEX IF NOT EXISTS idx_intelsub_period ON intel_subscriptions(current_period_end);

-- Customer Entitlements — what each user/tenant can access
CREATE TABLE IF NOT EXISTS customer_entitlements (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  tenant_id        TEXT,
  feature          TEXT NOT NULL,  -- api_access|report_download|dashboard_pro|threat_feed|siem_webhook|...
  source           TEXT NOT NULL DEFAULT 'subscription'
                     CHECK(source IN ('subscription','purchase','trial','manual','bundle')),
  source_ref       TEXT,           -- order_id or subscription_id
  tier_required    TEXT NOT NULL DEFAULT 'FREE',
  enabled          INTEGER NOT NULL DEFAULT 1,
  expires_at       TEXT,
  granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at       TEXT,
  revoke_reason    TEXT,
  metadata         TEXT DEFAULT '{}',
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES customer_tenants(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_entitle_user    ON customer_entitlements(user_id);
CREATE INDEX IF NOT EXISTS idx_entitle_feature ON customer_entitlements(feature);
CREATE INDEX IF NOT EXISTS idx_entitle_enabled ON customer_entitlements(enabled);
CREATE INDEX IF NOT EXISTS idx_entitle_expires ON customer_entitlements(expires_at);
-- Composite: fast per-user feature lookup
CREATE UNIQUE INDEX IF NOT EXISTS idx_entitle_user_feat ON customer_entitlements(user_id, feature, source_ref);

-- Provisioning Log — audit trail for every auto-provisioning event
CREATE TABLE IF NOT EXISTS provisioning_log (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT,
  tenant_id        TEXT,
  trigger_type     TEXT NOT NULL   -- purchase|subscription|trial|manual|upgrade|downgrade|cancel
                     CHECK(trigger_type IN ('purchase','subscription','trial','manual','upgrade','downgrade','cancel','renewal')),
  trigger_ref      TEXT,           -- order_id or subscription_id that caused this
  actions_taken    TEXT NOT NULL DEFAULT '[]',  -- JSON array of provisioning steps performed
  entitlements_granted TEXT DEFAULT '[]',       -- JSON array of features granted
  api_keys_created INTEGER NOT NULL DEFAULT 0,
  tenant_created   INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'success'
                     CHECK(status IN ('success','partial','failed')),
  error_detail     TEXT,
  duration_ms      INTEGER,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_provlog_user    ON provisioning_log(user_id);
CREATE INDEX IF NOT EXISTS idx_provlog_trigger ON provisioning_log(trigger_type);
CREATE INDEX IF NOT EXISTS idx_provlog_created ON provisioning_log(created_at);

-- Report Catalog — intelligence reports available for purchase/download
CREATE TABLE IF NOT EXISTS report_catalog (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  title            TEXT NOT NULL,
  slug             TEXT NOT NULL UNIQUE,
  category         TEXT NOT NULL   -- cve|malware|threat_actor|industry|executive|ai_security|bundle
                     CHECK(category IN ('cve','malware','threat_actor','industry','executive','ai_security','bundle')),
  severity         TEXT,
  summary          TEXT,
  preview_content  TEXT,           -- teaser shown to FREE users
  full_content_url TEXT,           -- protected S3/R2 URL (for paid users)
  price_usd        REAL NOT NULL DEFAULT 49,
  price_inr        INTEGER NOT NULL DEFAULT 3999,
  published_at     TEXT NOT NULL DEFAULT (datetime('now')),
  is_featured      INTEGER NOT NULL DEFAULT 0,
  is_active        INTEGER NOT NULL DEFAULT 1,
  download_count   INTEGER NOT NULL DEFAULT 0,
  purchase_count   INTEGER NOT NULL DEFAULT 0,
  tags             TEXT DEFAULT '[]',
  metadata         TEXT DEFAULT '{}',
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reportcat_category  ON report_catalog(category);
CREATE INDEX IF NOT EXISTS idx_reportcat_severity  ON report_catalog(severity);
CREATE INDEX IF NOT EXISTS idx_reportcat_featured  ON report_catalog(is_featured);
CREATE INDEX IF NOT EXISTS idx_reportcat_active    ON report_catalog(is_active);
CREATE INDEX IF NOT EXISTS idx_reportcat_published ON report_catalog(published_at);

-- Report Access — tracks which users have paid access to which reports
CREATE TABLE IF NOT EXISTS report_access (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id          TEXT NOT NULL,
  report_id        TEXT NOT NULL,
  order_id         TEXT,
  granted_via      TEXT NOT NULL DEFAULT 'purchase'
                     CHECK(granted_via IN ('purchase','subscription','trial','bundle','manual')),
  expires_at       TEXT,           -- NULL = perpetual
  download_count   INTEGER NOT NULL DEFAULT 0,
  last_downloaded  TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (report_id) REFERENCES report_catalog(id) ON DELETE CASCADE,
  FOREIGN KEY (order_id)  REFERENCES marketplace_orders(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reportaccess_user_report ON report_access(user_id, report_id);
CREATE INDEX IF NOT EXISTS idx_reportaccess_user  ON report_access(user_id);
CREATE INDEX IF NOT EXISTS idx_reportaccess_report ON report_access(report_id);

-- Seed: Initial Report Catalog (production intelligence products)
INSERT OR IGNORE INTO report_catalog (id, title, slug, category, severity, summary, price_usd, price_inr, is_featured, tags) VALUES
  ('rpt-cve-critical-2026', 'Critical CVE Intelligence Report — Q2 2026', 'critical-cve-q2-2026', 'cve', 'CRITICAL', 'Top 50 actively exploited CVEs tracked by SENTINEL APEX with EPSS scores, KEV status, patch availability, and SIGMA/YARA detection rules.', 49, 3999, 1, '["CVE","KEV","EPSS","SIGMA","YARA"]'),
  ('rpt-apt-russia-2026', 'APT Group Intelligence: Russian Threat Actors 2026', 'apt-russia-2026', 'threat_actor', 'HIGH', 'Full tactical dossiers on APT29, APT28, Sandworm — TTPs, kill chains, IOC feeds, MITRE ATT&CK mappings, and sector targeting analysis.', 79, 6499, 1, '["APT","Russia","MITRE","TTP"]'),
  ('rpt-ransomware-q2-2026', 'Ransomware Threat Landscape — Q2 2026', 'ransomware-q2-2026', 'malware', 'CRITICAL', 'LockBit4, BlackCat, Play, Cl0p — active campaigns, encryption methods, negotiation patterns, backup destruction TTPs, and defensive countermeasures.', 79, 6499, 1, '["Ransomware","Malware","LockBit","BlackCat"]'),
  ('rpt-exec-brief-jun2026', 'Executive Threat Intelligence Briefing — June 2026', 'exec-brief-jun-2026', 'executive', 'HIGH', 'Board-ready briefing: global threat landscape, sector risk matrix, AI weaponization trends, regulatory exposure, and strategic recommendations.', 149, 12499, 1, '["Executive","Board","CISO","Strategic"]'),
  ('rpt-fintech-india-2026', 'FinTech India Threat Report 2026', 'fintech-india-2026', 'industry', 'HIGH', 'BFSI sector targeting analysis: UPI fraud campaigns, RBI compliance gaps, API security failures, and sector-specific IOC feeds.', 99, 8199, 0, '["FinTech","India","BFSI","UPI"]'),
  ('rpt-ai-threats-2026', 'AI Security Threat Intelligence Report 2026', 'ai-threats-2026', 'ai_security', 'HIGH', 'LLM prompt injection campaigns, model poisoning incidents, agentic AI attack chains, OWASP LLM Top 10 exploitation observed in wild.', 99, 8199, 1, '["AI","LLM","OWASP","Agentic"]'),
  ('rpt-healthcare-2026', 'Healthcare Sector Threat Report — India 2026', 'healthcare-india-2026', 'industry', 'CRITICAL', 'AIIMS-class attack patterns, HIPAA/DPDP exposure analysis, ransomware targeting medical devices, and defensive playbooks.', 99, 8199, 0, '["Healthcare","HIPAA","DPDP","India"]'),
  ('rpt-bundle-all-q2', 'Complete Intelligence Bundle — Q2 2026', 'complete-bundle-q2-2026', 'bundle', 'CRITICAL', 'All 7 intelligence reports bundled: CVE, APT, Ransomware, Executive, FinTech, AI Security, Healthcare. Best value.', 349, 28999, 1, '["Bundle","AllReports","BestValue"]');
