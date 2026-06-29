-- v44b — Widen attack_library_techniques.category to cover the full MITRE
-- ATLAS tactic taxonomy, not just the 6 narrow LLM-attack categories the
-- table was originally seeded with. Needed because the live ingestion job
-- (services/attackLibraryIngestion.js) pulls the real ATLAS technique
-- catalog (170 techniques across 16 tactics), most of which don't fit the
-- original prompt-injection/jailbreak/agent-takeover/rag-poisoning/
-- data-exfil/model-abuse taxonomy — forcing them into those 6 buckets would
-- mis-categorize real attack data. SQLite can't ALTER a CHECK constraint
-- directly, so this rebuilds the table (same pattern as schema_v45_users).

ALTER TABLE attack_library_techniques RENAME TO attack_library_techniques_v44_backup;

CREATE TABLE attack_library_techniques (
  id                 TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  technique_id       TEXT    NOT NULL UNIQUE,
  name               TEXT    NOT NULL,
  category           TEXT    NOT NULL CHECK (category IN (
    'prompt-injection','jailbreak','agent-takeover','rag-poisoning','data-exfil','model-abuse',
    'reconnaissance','resource-development','ai-attack-staging','initial-access','execution',
    'persistence','defense-evasion','discovery','collection','impact',
    'privilege-escalation','credential-access','command-and-control','lateral-movement'
  )),
  severity           TEXT    NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  icon               TEXT    NOT NULL DEFAULT '🎯',
  description        TEXT    NOT NULL,
  full_description   TEXT,
  example_payload    TEXT,
  defenses           TEXT,
  tags               TEXT    NOT NULL DEFAULT '[]',
  complexity         TEXT    CHECK (complexity IN ('Low','Medium','High')),
  impact             TEXT    CHECK (impact IN ('Low','Medium','High','Critical')),
  detectability       TEXT   CHECK (detectability IN ('Easy','Medium','Hard')),
  mitre_atlas_id     TEXT,
  owasp_llm_id       TEXT,
  cwe_id             TEXT,
  published_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  source             TEXT    NOT NULL DEFAULT 'cyberdudebivash_research'
);

INSERT INTO attack_library_techniques
  (id, technique_id, name, category, severity, icon, description, full_description, example_payload, defenses,
   tags, complexity, impact, detectability, mitre_atlas_id, owasp_llm_id, cwe_id, published_at, updated_at, created_at, source)
SELECT
  id, technique_id, name, category, severity, icon, description, full_description, example_payload, defenses,
  tags, complexity, impact, detectability, mitre_atlas_id, owasp_llm_id, cwe_id, published_at, updated_at, created_at, source
FROM attack_library_techniques_v44_backup;

DROP TABLE attack_library_techniques_v44_backup;

CREATE INDEX IF NOT EXISTS idx_atklib_category ON attack_library_techniques(category);
CREATE INDEX IF NOT EXISTS idx_atklib_severity ON attack_library_techniques(severity);
CREATE INDEX IF NOT EXISTS idx_atklib_source   ON attack_library_techniques(source);
