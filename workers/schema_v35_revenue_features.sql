-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v35.0
-- High-Revenue Feature Tables: IOC Enrichment, ASM, Brand Protection,
-- Threat Actor Profiling, CRQ, TPRM
-- ============================================================================

-- ─── IOC Enrichment Cache ────────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ioc_cache_value    ON ioc_enrichment_cache(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_cache_type     ON ioc_enrichment_cache(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_cache_verdict  ON ioc_enrichment_cache(verdict);
CREATE INDEX IF NOT EXISTS idx_ioc_cache_expiry   ON ioc_enrichment_cache(ttl_expires);

-- ─── IOC Enrichment Request Log ──────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ioc_requests_user    ON ioc_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_ioc_requests_created ON ioc_requests(created_at DESC);

-- ─── ASM: Attack Surface Management Targets ──────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_asm_targets_user    ON asm_targets(user_id);
CREATE INDEX IF NOT EXISTS idx_asm_targets_domain  ON asm_targets(domain);
CREATE INDEX IF NOT EXISTS idx_asm_targets_score   ON asm_targets(asm_score DESC);

-- ─── ASM: Discovered Assets ──────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_asm_assets_target   ON asm_assets(target_id);
CREATE INDEX IF NOT EXISTS idx_asm_assets_type     ON asm_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_asm_assets_risk     ON asm_assets(risk_level);
CREATE INDEX IF NOT EXISTS idx_asm_assets_new      ON asm_assets(new_asset);

-- ─── Brand Protection: Monitors ──────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_brand_monitors_user   ON brand_monitors(user_id);
CREATE INDEX IF NOT EXISTS idx_brand_monitors_domain ON brand_monitors(primary_domain);

-- ─── Brand Protection: Threats ───────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_brand_threats_monitor  ON brand_threats(monitor_id);
CREATE INDEX IF NOT EXISTS idx_brand_threats_domain   ON brand_threats(domain);
CREATE INDEX IF NOT EXISTS idx_brand_threats_risk     ON brand_threats(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_brand_threats_type     ON brand_threats(threat_type);

-- ─── Threat Actor Profiling ───────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_actors_country    ON threat_actors(country);
CREATE INDEX IF NOT EXISTS idx_actors_motivation ON threat_actors(motivation);
CREATE INDEX IF NOT EXISTS idx_actors_active     ON threat_actors(active);

-- ─── TPRM: Third-Party Risk Management ────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_tprm_user       ON tprm_vendors(user_id);
CREATE INDEX IF NOT EXISTS idx_tprm_risk_score ON tprm_vendors(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_tprm_domain     ON tprm_vendors(vendor_domain);

-- ─── CRQ: Cyber Risk Quantification ──────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_crq_user    ON crq_assessments(user_id);
CREATE INDEX IF NOT EXISTS idx_crq_created ON crq_assessments(created_at DESC);

-- ============================================================================
-- END: schema_v35_revenue_features.sql
-- ============================================================================
