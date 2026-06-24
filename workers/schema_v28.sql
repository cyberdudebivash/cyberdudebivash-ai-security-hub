-- ============================================================
-- CYBERDUDEBIVASH v28.0 — AI Security Platform Schema
-- Run: npx wrangler d1 execute cyberdudebivash-security-hub --remote --file=./schema_v28.sql
-- All IF NOT EXISTS — safe to run on live D1
-- ============================================================

-- PILLAR 1: AI ASSET INVENTORY (ASPM) ─────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ai_assets_org        ON ai_assets(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_assets_type       ON ai_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_ai_assets_risk       ON ai_assets(risk_score);
CREATE INDEX IF NOT EXISTS idx_ai_assets_exposure   ON ai_assets(exposure);

-- AI Security findings per asset ──────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ai_findings_asset    ON ai_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_ai_findings_severity ON ai_findings(severity);
CREATE INDEX IF NOT EXISTS idx_ai_findings_category ON ai_findings(category);
CREATE INDEX IF NOT EXISTS idx_ai_findings_status   ON ai_findings(status);

-- PILLAR 2: AI GOVERNANCE ─────────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ai_gov_org       ON ai_governance_assessments(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_gov_framework ON ai_governance_assessments(framework);
CREATE INDEX IF NOT EXISTS idx_ai_gov_email     ON ai_governance_assessments(email);

-- AI Risk Register ────────────────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ai_risk_org    ON ai_risk_register(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_risk_level  ON ai_risk_register(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_risk_status ON ai_risk_register(status);

-- PILLAR 3: AI RED TEAM ───────────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_rt_engagements_email  ON ai_redteam_engagements(email);
CREATE INDEX IF NOT EXISTS idx_rt_engagements_status ON ai_redteam_engagements(status);

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
CREATE INDEX IF NOT EXISTS idx_rt_attempts_engagement ON ai_redteam_attempts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_rt_attempts_success    ON ai_redteam_attempts(success);
CREATE INDEX IF NOT EXISTS idx_rt_attempts_type       ON ai_redteam_attempts(attack_type);

-- PILLAR 4: AI AGENT SECURITY ─────────────────────────────────────────────────
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
CREATE INDEX IF NOT EXISTS idx_ai_agent_org       ON ai_agent_inventory(org_id);
CREATE INDEX IF NOT EXISTS idx_ai_agent_framework ON ai_agent_inventory(framework);
CREATE INDEX IF NOT EXISTS idx_ai_agent_risk      ON ai_agent_inventory(risk_score);

-- PILLAR 5: AI THREAT INTELLIGENCE FEED ──────────────────────────────────────
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
  attack_ref      TEXT,  -- MITRE ATT&CK Enterprise technique ID (e.g. T1190)
  atlas_ref       TEXT,  -- MITRE ATLAS technique ID (e.g. AML.T0051)
  source_url      TEXT,
  published_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  metadata        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ai_feed_type       ON ai_threat_feed(feed_type);
CREATE INDEX IF NOT EXISTS idx_ai_feed_severity   ON ai_threat_feed(severity);
CREATE INDEX IF NOT EXISTS idx_ai_feed_published  ON ai_threat_feed(published_at);

-- PILLAR 6: AI SECURITY SERVICES (scoped from assessments) ───────────────────
-- Uses existing assessments table + adds service_type column linkage
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
CREATE INDEX IF NOT EXISTS idx_ai_svc_email  ON ai_service_engagements(email);
CREATE INDEX IF NOT EXISTS idx_ai_svc_type   ON ai_service_engagements(service_type);
CREATE INDEX IF NOT EXISTS idx_ai_svc_status ON ai_service_engagements(status);

-- AI Security scores (time-series posture tracking) ───────────────────────────
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_posture_date ON ai_posture_scores(org_id, score_date);
