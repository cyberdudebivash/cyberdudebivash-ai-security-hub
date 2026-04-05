-- ═══════════════════════════════════════════════════════════════════════════
-- Sentinel APEX — Schema Migration v2
-- Run this ONCE on existing databases BEFORE running schema_gtm_only.sql
-- Safe to run on remote D1: npx wrangler d1 execute <db> --remote --file=./schema_migrations_v2.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- Add EPSS + exploit columns to threat_intel (added in Sentinel APEX v2)
ALTER TABLE threat_intel ADD COLUMN epss_score REAL;
ALTER TABLE threat_intel ADD COLUMN epss_percentile REAL;
ALTER TABLE threat_intel ADD COLUMN actively_exploited INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN exploit_available INTEGER DEFAULT 0;
ALTER TABLE threat_intel ADD COLUMN ioc_list TEXT DEFAULT '[]';

-- Indexes for new columns (idempotent)
CREATE INDEX IF NOT EXISTS idx_threat_intel_epss   ON threat_intel(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_active ON threat_intel(actively_exploited);
