-- Safe migration: add missing columns to threat_intel
-- Live D1 has: id, cve_id, title, description, severity, source, created_at, cvss,
--              exploit_status, iocs, epss_score, exploit_available, actively_exploited,
--              published_at, epss_percentile, ioc_list
-- Missing columns needed by storeInD1 INSERT:
ALTER TABLE threat_intel ADD COLUMN cvss_vector TEXT;
ALTER TABLE threat_intel ADD COLUMN source_url TEXT;
ALTER TABLE threat_intel ADD COLUMN known_ransomware INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN tags TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN affected_products TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN weakness_types TEXT DEFAULT '[]';
ALTER TABLE threat_intel ADD COLUMN enriched INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN updated_at TEXT DEFAULT (datetime('now'));
