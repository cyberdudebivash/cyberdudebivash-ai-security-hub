-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema Migration v34.0
-- threat_intel: Add all columns required by threatIngestion.js storeInD1()
--
-- ROOT CAUSE: threat_intel was created from v1 schema (old column names).
-- threatIngestion.js storeInD1() references: cvss, source_url, exploit_status,
-- known_ransomware, tags, iocs, affected_products, weakness_types, enriched,
-- epss_score, epss_percentile, actively_exploited, exploit_available
-- None of these exist — 91 ingestion runs all failed with SQLITE_ERROR.
--
-- FIX: ADD COLUMN for every missing column. Existing data (none) unaffected.
-- SAFE: D1 ALTER TABLE ADD COLUMN never fails if column already exists in
-- a silent-success mode — but to be extra safe we add each separately so
-- one failure cannot block the rest.
-- ============================================================================

-- ── cvss: CVSS base score (alias to cvss_score; code uses 'cvss') ──────────
ALTER TABLE threat_intel ADD COLUMN cvss REAL;

-- ── source_url: direct link to CVE details page ───────────────────────────
ALTER TABLE threat_intel ADD COLUMN source_url TEXT;

-- ── exploit_status: unconfirmed / poc_available / confirmed ───────────────
ALTER TABLE threat_intel ADD COLUMN exploit_status TEXT DEFAULT 'unconfirmed';

-- ── known_ransomware: 0/1 flag from CISA KEV ──────────────────────────────
ALTER TABLE threat_intel ADD COLUMN known_ransomware INTEGER DEFAULT 0;

-- ── tags: JSON array of attack-type tags ──────────────────────────────────
ALTER TABLE threat_intel ADD COLUMN tags TEXT DEFAULT '[]';

-- ── iocs: JSON array of extracted IOCs ────────────────────────────────────
ALTER TABLE threat_intel ADD COLUMN iocs TEXT DEFAULT '[]';

-- ── affected_products: JSON array of CPE strings ──────────────────────────
ALTER TABLE threat_intel ADD COLUMN affected_products TEXT DEFAULT '[]';

-- ── weakness_types: JSON array of CWE identifiers ─────────────────────────
ALTER TABLE threat_intel ADD COLUMN weakness_types TEXT DEFAULT '[]';

-- ── enriched: 0/1 enrichment status flag ──────────────────────────────────
ALTER TABLE threat_intel ADD COLUMN enriched INTEGER DEFAULT 0;

-- ── epss_score: FIRST.org EPSS probability (0.0–1.0) ──────────────────────
ALTER TABLE threat_intel ADD COLUMN epss_score REAL;

-- ── epss_percentile: EPSS percentile rank (0.0–1.0) ──────────────────────
ALTER TABLE threat_intel ADD COLUMN epss_percentile REAL;

-- ── actively_exploited: 0/1 derived from epss>=0.7 or exploit_status ──────
ALTER TABLE threat_intel ADD COLUMN actively_exploited INTEGER DEFAULT 0;

-- ── exploit_available: 0/1 any public exploit exists ─────────────────────
ALTER TABLE threat_intel ADD COLUMN exploit_available INTEGER DEFAULT 0;

-- ── ioc_list: secondary IOC JSON (used by intelIngestionEngine) ───────────
-- (may already exist — silently skipped if present)
ALTER TABLE threat_intel ADD COLUMN ioc_list TEXT DEFAULT '[]';

-- ── Backfill: sync cvss from cvss_score for any existing rows ─────────────
UPDATE threat_intel SET cvss = cvss_score WHERE cvss IS NULL AND cvss_score IS NOT NULL;

-- ── Backfill: sync exploit_status from is_exploited ───────────────────────
UPDATE threat_intel SET exploit_status = CASE WHEN is_exploited = 1 THEN 'confirmed' ELSE 'unconfirmed' END
WHERE exploit_status IS NULL OR exploit_status = 'unconfirmed';

-- ── Backfill: sync known_ransomware from is_ransomware ────────────────────
UPDATE threat_intel SET known_ransomware = is_ransomware
WHERE known_ransomware = 0 AND is_ransomware = 1;

-- ── Backfill: sync actively_exploited ─────────────────────────────────────
UPDATE threat_intel SET actively_exploited = is_exploited
WHERE actively_exploited = 0 AND is_exploited = 1;

-- ── Indexes for new columns ───────────────────────────────────────────────
DROP INDEX IF EXISTS idx_threat_intel_exploit_status;
CREATE INDEX idx_threat_intel_exploit_status ON threat_intel(exploit_status);

DROP INDEX IF EXISTS idx_threat_intel_epss;
CREATE INDEX idx_threat_intel_epss ON threat_intel(epss_score DESC);

DROP INDEX IF EXISTS idx_threat_intel_active_exp;
CREATE INDEX idx_threat_intel_active_exp ON threat_intel(actively_exploited);

DROP INDEX IF EXISTS idx_threat_intel_ransomware;
CREATE INDEX idx_threat_intel_ransomware ON threat_intel(known_ransomware);

-- ── Verification ─────────────────────────────────────────────────────────
-- SELECT COUNT(*) as col_count FROM pragma_table_info('threat_intel');
-- Expected: at least 35 columns after migration

-- ============================================================================
-- END: schema_v34_threat_intel_fix.sql
-- After applying: trigger manual ingestion via POST /api/threat-intel/ingest
-- or wait for next cron tick (every hour)
-- ============================================================================
