-- ============================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v12.0
-- System 1: Agentic AI Autonomous Remediation Engine
-- System 2: Behavioral Anomaly Detection Engine
-- System 3: Predictive Threat Intelligence Engine
-- ============================================================

-- ── AGENT SYSTEM ────────────────────────────────────────────

-- All agent action executions (immutable audit trail)
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
CREATE INDEX IF NOT EXISTS idx_agent_actions_type    ON agent_actions(action_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_actions_target  ON agent_actions(target);
CREATE INDEX IF NOT EXISTS idx_agent_actions_status  ON agent_actions(execution_status);
CREATE INDEX IF NOT EXISTS idx_agent_actions_risk    ON agent_actions(risk_level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_actions_trigger ON agent_actions(trigger_source, trigger_id);

-- Agent event bus queue (pending events awaiting processing)
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
CREATE INDEX IF NOT EXISTS idx_event_queue_status ON agent_event_queue(status, priority DESC, created_at);

-- IP blocklist (enforced on every request by middleware)
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
CREATE INDEX IF NOT EXISTS idx_blocklist_ip     ON ip_blocklist(ip, is_active);
CREATE INDEX IF NOT EXISTS idx_blocklist_active ON ip_blocklist(is_active, expires_at);

-- Session blacklist (JWT tokens that have been invalidated)
CREATE TABLE IF NOT EXISTS session_blacklist (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id     TEXT NOT NULL,
  token_hash  TEXT UNIQUE,
  reason      TEXT NOT NULL DEFAULT 'agent_disable',
  action_id   TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_bl_user ON session_blacklist(user_id);
CREATE INDEX IF NOT EXISTS idx_session_bl_hash ON session_blacklist(token_hash);

-- Virtual WAF patches (applied by patching agent, enforced by middleware)
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
CREATE INDEX IF NOT EXISTS idx_vp_cve    ON virtual_patches(cve_id, is_active);
CREATE INDEX IF NOT EXISTS idx_vp_active ON virtual_patches(is_active, priority);

-- Rotated credentials log (audit only, no secrets stored)
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
CREATE INDEX IF NOT EXISTS idx_cred_rot_user ON credential_rotation_log(user_id, created_at DESC);

-- ── ANOMALY DETECTION ENGINE ────────────────────────────────

-- User behavior baseline (rolling 30-day window)
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

-- Raw behavior events (used for baseline computation and scoring)
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
CREATE INDEX IF NOT EXISTS idx_behav_user    ON behavior_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_behav_type    ON behavior_events(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_behav_ip      ON behavior_events(ip, created_at DESC);

-- Anomaly detection results
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
CREATE INDEX IF NOT EXISTS idx_anomaly_user  ON anomaly_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_score ON anomaly_events(anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_risk  ON anomaly_events(risk_level, created_at DESC);

-- ── PREDICTIVE THREAT INTELLIGENCE ENGINE ──────────────────

-- Threat prediction records
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
CREATE INDEX IF NOT EXISTS idx_pred_risk     ON threat_predictions(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_pred_date     ON threat_predictions(prediction_date DESC);
CREATE INDEX IF NOT EXISTS idx_pred_cve      ON threat_predictions(cve_id);
CREATE INDEX IF NOT EXISTS idx_pred_prob     ON threat_predictions(probability_pct DESC);
CREATE INDEX IF NOT EXISTS idx_pred_window   ON threat_predictions(expected_window_hrs);

-- APT group profiles (seeded from threat intel)
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

-- ── RBAC ROLES ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_roles (
  user_id    TEXT NOT NULL,
  role       TEXT NOT NULL CHECK(role IN ('SUPERADMIN','ADMIN','SOC_ANALYST','THREAT_HUNTER','VIEWER','API_USER')),
  granted_by TEXT,
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, role)
);
CREATE INDEX IF NOT EXISTS idx_roles_user ON user_roles(user_id);

-- ── RATE LIMIT STATE ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limit_state (
  key        TEXT PRIMARY KEY,
  count      INTEGER NOT NULL DEFAULT 1,
  window_end TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── SEED: Known APT Groups ──────────────────────────────────
INSERT OR IGNORE INTO apt_profiles (id, group_name, aliases, origin_country, target_sectors, typical_cves, mitre_ttps, activity_level, last_seen) VALUES
('apt1','APT28 (Fancy Bear)','["Fancy Bear","Sofacy","STRONTIUM"]','Russia','["Government","Defense","Energy"]','["CVE-2023-23397","CVE-2022-30190"]','["T1566","T1071","T1027","T1053","T1078"]','ACTIVE','2024-11-01'),
('apt2','APT41 (Double Dragon)','["Double Dragon","Winnti","BARIUM"]','China','["Healthcare","Technology","Financial"]','["CVE-2021-44228","CVE-2021-26855"]','["T1190","T1133","T1059","T1486","T1083"]','ACTIVE','2024-10-15'),
('apt3','Lazarus Group','["Hidden Cobra","ZINC","APT-C-26"]','North Korea','["Financial","Cryptocurrency","Defense"]','["CVE-2022-41040","CVE-2021-40444"]','["T1566","T1203","T1055","T1486"]','ACTIVE','2024-11-10'),
('apt4','Sandworm','["Voodoo Bear","Telebots","IRON VIKING"]','Russia','["Energy","Industrial","Government"]','["CVE-2022-30190","CVE-2023-36884"]','["T1190","T1486","T1070","T1561"]','ACTIVE','2024-09-20'),
('apt5','Scattered Spider','["UNC3944","Muddled Libra"]','Unknown','["Retail","Hospitality","Telecom"]','["CVE-2023-4966","CVE-2023-46747"]','["T1078","T1598","T1621","T1539"]','ACTIVE','2024-10-30');
