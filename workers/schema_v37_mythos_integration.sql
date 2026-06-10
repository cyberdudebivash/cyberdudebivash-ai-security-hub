-- ─────────────────────────────────────────────────────────────────────────────
-- CYBERDUDEBIVASH AI Security Hub — Schema v37: MYTHOS Integration Patch
-- Adds mythos_enriched column + updates 8 services to hybrid/automated
-- ─────────────────────────────────────────────────────────────────────────────

-- ── 1. Add MYTHOS enrichment tracking to assessments table ───────────────────
ALTER TABLE service_assessments ADD COLUMN mythos_enriched INTEGER DEFAULT 0;
ALTER TABLE service_assessments ADD COLUMN mythos_confidence INTEGER DEFAULT 0;

-- ── 2. Upgrade formerly-manual services to hybrid/automated ──────────────────
-- CDB-SAASSEC-001: SaaS Security Assessment → automated (saas_security engine)
UPDATE services
SET delivery_type = 'automated', automated_engine = 'saas_security', delivery_hours = 0
WHERE ref_id = 'CDB-SAASSEC-001';

-- CDB-SCRA-001: Security Configuration Review → automated (config_review engine)
UPDATE services
SET delivery_type = 'automated', automated_engine = 'config_review', delivery_hours = 0
WHERE ref_id = 'CDB-SCRA-001';

-- CDB-AIGOV-001: AI Governance Consulting → hybrid (ai_governance engine + expert review)
UPDATE services
SET delivery_type = 'hybrid', automated_engine = 'ai_governance', delivery_hours = 48
WHERE ref_id = 'CDB-AIGOV-001';

-- CDB-DSO-001: DevSecOps Optimization → hybrid (devsecops engine + expert review)
UPDATE services
SET delivery_type = 'hybrid', automated_engine = 'devsecops', delivery_hours = 72
WHERE ref_id = 'CDB-DSO-001';

-- CDB-CONSULT-001: Cybersecurity Consultation → hybrid (consultation pre-assess + expert call)
UPDATE services
SET delivery_type = 'hybrid', automated_engine = 'consultation', delivery_hours = 24
WHERE ref_id = 'CDB-CONSULT-001';

-- CDB-AISEC-001: AI Security Consultation Premium → hybrid
UPDATE services
SET delivery_type = 'hybrid', automated_engine = 'consultation_aisec', delivery_hours = 24
WHERE ref_id = 'CDB-AISEC-001';

-- CDB-TI-001: Threat Intelligence Advisory Call → hybrid
UPDATE services
SET delivery_type = 'hybrid', automated_engine = 'consultation_ti', delivery_hours = 24
WHERE ref_id = 'CDB-TI-001';

-- CDB-SHC-001: Security Hiring & Career Guidance → hybrid
UPDATE services
SET delivery_type = 'hybrid', automated_engine = 'consultation_shc', delivery_hours = 24
WHERE ref_id = 'CDB-SHC-001';

-- ── 3. Verify all 18 services ────────────────────────────────────────────────
SELECT ref_id, name, delivery_type, automated_engine, delivery_hours
FROM services
ORDER BY sort_order ASC;
