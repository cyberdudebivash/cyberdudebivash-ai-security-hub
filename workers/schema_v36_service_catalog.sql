-- ============================================================================
-- CYBERDUDEBIVASH AI Security Hub — Schema v36.0
-- Service Catalog, Order Management, Automated Assessments & Deliverables
-- ============================================================================

-- ─── Service Catalog ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS services (
  ref_id              TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  tier                INTEGER NOT NULL DEFAULT 1,       -- 1=ENTRY 2=SME 3=ENTERPRISE
  tier_name           TEXT NOT NULL DEFAULT 'ENTRY',
  price_inr           INTEGER NOT NULL,
  price_usd           REAL DEFAULT 0,
  short_desc          TEXT,
  deliverables        TEXT DEFAULT '[]',                -- JSON array
  ideal_for           TEXT DEFAULT '[]',                -- JSON array
  delivery_type       TEXT DEFAULT 'manual',            -- manual|automated|hybrid
  delivery_hours      INTEGER DEFAULT 72,               -- SLA in hours (0=instant)
  automated_engine    TEXT,                             -- ssl|cti_brief|cti_report|ai_security|ai_security_enterprise|compliance|threat_hunting|api_security|cloud_security|vuln_assessment
  highlight           INTEGER DEFAULT 0,                -- featured/bestseller flag
  active              INTEGER DEFAULT 1,
  sort_order          INTEGER DEFAULT 0,
  created_at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_services_tier   ON services(tier);
CREATE INDEX IF NOT EXISTS idx_services_active ON services(active);

-- ─── Customer Service Orders ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS service_orders (
  id                  TEXT PRIMARY KEY,
  ref_id              TEXT NOT NULL,
  customer_name       TEXT NOT NULL,
  customer_email      TEXT NOT NULL,
  customer_phone      TEXT,
  company             TEXT,
  company_size        TEXT,                             -- startup|sme|enterprise
  target_domain       TEXT,                             -- domain/URL/system to assess
  target_industry     TEXT DEFAULT 'General',
  requirements        TEXT,                             -- customer free-text notes
  assessment_inputs   TEXT DEFAULT '{}',                -- JSON inputs for automated engines
  payment_status      TEXT DEFAULT 'pending',           -- pending|paid|processing|failed|refunded
  payment_method      TEXT DEFAULT 'razorpay',
  payment_ref         TEXT,
  payment_amount      INTEGER,
  order_status        TEXT DEFAULT 'new',               -- new|payment_pending|confirmed|in_progress|delivered|cancelled
  report_token        TEXT UNIQUE,                      -- secure download token (UUID)
  admin_notes         TEXT,
  source              TEXT DEFAULT 'website',
  utm_source          TEXT,
  created_at          TEXT DEFAULT (datetime('now')),
  updated_at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_orders_email   ON service_orders(customer_email);
CREATE INDEX IF NOT EXISTS idx_orders_status  ON service_orders(order_status);
CREATE INDEX IF NOT EXISTS idx_orders_ref     ON service_orders(ref_id);
CREATE INDEX IF NOT EXISTS idx_orders_token   ON service_orders(report_token);
CREATE INDEX IF NOT EXISTS idx_orders_created ON service_orders(created_at DESC);

-- ─── Service Deliverables ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS service_deliverables (
  id                  TEXT PRIMARY KEY,
  order_id            TEXT NOT NULL,
  deliverable_type    TEXT NOT NULL,                    -- json_report|action_plan|ioc_list|executive_summary|roadmap
  title               TEXT NOT NULL,
  content_json        TEXT DEFAULT '{}',
  download_count      INTEGER DEFAULT 0,
  created_at          TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (order_id) REFERENCES service_orders(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_deliverables_order ON service_deliverables(order_id);

-- ─── Assessment Execution Results ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS service_assessments (
  id                  TEXT PRIMARY KEY,
  order_id            TEXT NOT NULL,
  service_ref         TEXT NOT NULL,
  target              TEXT,
  status              TEXT DEFAULT 'pending',           -- pending|running|complete|failed
  risk_score          INTEGER DEFAULT 0,                -- 0-100
  risk_grade          TEXT DEFAULT 'UNKNOWN',           -- A/B/C/D/F
  findings_count      INTEGER DEFAULT 0,
  critical_count      INTEGER DEFAULT 0,
  high_count          INTEGER DEFAULT 0,
  findings_json       TEXT DEFAULT '[]',
  recommendations_json TEXT DEFAULT '[]',
  report_json         TEXT DEFAULT '{}',
  engine_version      TEXT DEFAULT '1.0',
  started_at          TEXT,
  completed_at        TEXT,
  created_at          TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (order_id) REFERENCES service_orders(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assessments_order  ON service_assessments(order_id);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON service_assessments(status);
CREATE INDEX IF NOT EXISTS idx_assessments_ref    ON service_assessments(service_ref);

-- ============================================================================
-- SEED: All 18 Official Services — CYBERDUDEBIVASH AI Security Hub™
-- ============================================================================

-- ─── TIER 1 — ENTRY SERVICES ─────────────────────────────────────────────────
INSERT OR IGNORE INTO services VALUES
  ('CDB-CONSULT-001',
   'Cybersecurity & AI Security Consultation',
   1,'ENTRY',999,12.0,
   '30-min expert consultation: security strategy, AI security guidance, SME recommendations, and action plan PDF.',
   '["30 Minute Expert Consultation","Security Strategy Review","AI Security Guidance","SME Business Recommendations","Action Plan PDF"]',
   '["Startups","Students","Founders","SMEs"]',
   'manual',48,NULL,0,1,10,datetime('now')),

  ('CDB-AISEC-001',
   'AI Security Consultation (Premium)',
   1,'ENTRY',1999,24.0,
   'Premium AI security consultation covering LLM security, prompt injection, AI governance, and regulatory alignment.',
   '["45-Minute Expert Call","LLM Security Guidance","AI Threat Review","Prompt Injection Assessment","AI Governance Recommendations","Follow-up Summary"]',
   '["AI Startups","SaaS Companies","AI Product Builders"]',
   'manual',48,NULL,1,1,20,datetime('now')),

  ('CDB-TI-001',
   'Threat Intelligence Advisory Call',
   1,'ENTRY',2999,36.0,
   'Expert briefing on current threat landscape, active attack campaigns, threat actors, and industry risk insights.',
   '["Current Threat Landscape Briefing","Attack Trend Analysis","Threat Actor Overview","Industry Risk Insights","Follow-up Summary Email"]',
   '["CISOs","Security Teams","Risk Managers"]',
   'manual',24,NULL,0,1,30,datetime('now')),

  ('CDB-SHC-001',
   'Security Hiring & Career Guidance',
   1,'ENTRY',999,12.0,
   'Expert cybersecurity career coaching: resume review, LinkedIn optimization, SOC roadmap, interview preparation.',
   '["Resume Review","LinkedIn Profile Review","SOC Career Roadmap","Interview Preparation Guide","1-Week Follow-up Support"]',
   '["Security Students","Career Switchers","Junior SOC Analysts"]',
   'manual',72,NULL,0,1,40,datetime('now')),

  ('CDB-SSL-001',
   'SSL & Website Security Health Check',
   1,'ENTRY',1499,18.0,
   'Instant automated SSL certificate and web security header analysis with detailed findings and remediation roadmap.',
   '["SSL Certificate Analysis","Security Headers Audit (HSTS, CSP, X-Frame-Options, Referrer-Policy)","HTTPS Redirect Check","Shodan Exposure Check","Risk Score & Grade","Remediation Recommendations"]',
   '["Website Owners","Developers","SMEs","E-commerce"]',
   'automated',0,'ssl',1,1,50,datetime('now')),

  ('CDB-CTI-PRO-001',
   'Premium CTI Intelligence Brief',
   1,'ENTRY',999,12.0,
   'AI-powered threat intelligence brief with critical CVEs, active exploits, threat actor insights, and 7-day outlook.',
   '["Top Critical CVEs (Industry-Specific)","Active Exploit Summary","Threat Actor Intelligence","IOC Summary","Industry Risk Analysis","7-Day Threat Outlook","PDF Executive Brief"]',
   '["Security Teams","SOC Analysts","IT Managers"]',
   'automated',0,'cti_brief',1,1,60,datetime('now')),

-- ─── TIER 2 — SME SERVICES ───────────────────────────────────────────────────
  ('CDB-TIR-001',
   'Threat Intelligence Report',
   2,'SME',4999,60.0,
   'Comprehensive 30-day custom threat intelligence report with deep CVE analysis, threat actor profiling, and IOC collection.',
   '["30-Day CVE Deep Analysis","Custom IOC Collection","Threat Actor Attribution","Attack Vector Mapping","Industry Threat Landscape","PDF Executive Brief","30-Day Monitoring Plan"]',
   '["CISOs","Security Managers","Enterprise IT"]',
   'automated',0,'cti_report',1,1,70,datetime('now')),

  ('CDB-AISS-001',
   'AI Security Scanner Assessment',
   2,'SME',7999,96.0,
   'Comprehensive AI security scan: AI exposure, prompt injection risks, OWASP AI Top 10, model security, and remediation roadmap.',
   '["AI Exposure Scan","Prompt Injection Risk Assessment","OWASP AI Top 10 Compliance Check","Model Security Review","AI Regulatory Alignment (EU AI Act)","Risk Report","Remediation Roadmap"]',
   '["AI Startups","SaaS Platforms","AI Product Teams"]',
   'automated',0,'ai_security',1,1,80,datetime('now')),

  ('CDB-VA-001',
   'Vulnerability Assessment',
   2,'SME',9999,120.0,
   'Automated vulnerability assessment: subdomain discovery, CVE matching, service exposure analysis, and remediation plan.',
   '["Domain & Subdomain Assessment","Known CVE Matching (NVD/CISA KEV)","Service Exposure Analysis","Open Port Risk Assessment","Risk Classification Report","Prioritized Remediation Plan"]',
   '["SMEs","Web App Owners","Development Teams"]',
   'automated',0,'vuln_assessment',0,1,90,datetime('now')),

  ('CDB-THR-001',
   'Threat Hunting Readiness Review',
   2,'SME',14999,180.0,
   'MITRE ATT&CK-based readiness assessment with detection gap analysis, hunting playbooks, and 90-day roadmap.',
   '["Log Source Review","Detection Gap Analysis","MITRE ATT&CK Coverage Map","Threat Hunting Playbooks","Detection Rule Recommendations","90-Day Roadmap","Executive Report"]',
   '["SOC Teams","IR Teams","Enterprise Security"]',
   'automated',0,'threat_hunting',1,1,100,datetime('now')),

  ('CDB-SAASSEC-001',
   'SaaS Security Assessment',
   2,'SME',12999,156.0,
   'Comprehensive SaaS security review: access controls, data exposure, OAuth/SSO security, vendor risk, and recommendations.',
   '["SaaS Risk Assessment","Access Control Review","Data Exposure Analysis","OAuth/SSO Security Review","Integration & API Security","Vendor Risk Summary","Security Recommendations"]',
   '["SaaS Companies","Product Managers","CISOs"]',
   'manual',96,NULL,0,1,110,datetime('now')),

  ('CDB-SCRA-001',
   'Security Configuration Review & Audit',
   2,'SME',4999,60.0,
   'Security configuration audit with CIS benchmark mapping, hardening recommendations, and prioritized findings report.',
   '["Configuration Audit Checklist","CIS Benchmark Mapping","Security Hardening Recommendations","Exposure Findings","Prioritized Audit Report"]',
   '["IT Admins","DevOps Teams","SMEs"]',
   'manual',72,NULL,0,1,120,datetime('now')),

-- ─── TIER 3 — ENTERPRISE SERVICES ────────────────────────────────────────────
  ('CDB-APISEC-001',
   'API Security Assessment',
   3,'ENTERPRISE',19999,240.0,
   'OWASP API Security Top 10 2023 assessment: authentication, authorization, injection, rate limiting, and data exposure review.',
   '["OWASP API Top 10 Assessment","Authentication & Authorization Testing","Injection Vulnerability Analysis","Rate Limiting & DoS Review","API Documentation Security Check","Detailed Findings & Remediation Report"]',
   '["API Developers","Backend Teams","Enterprise SaaS"]',
   'automated',0,'api_security',1,1,130,datetime('now')),

  ('CDB-AIGOV-001',
   'AI Governance Consulting',
   3,'ENTERPRISE',19999,240.0,
   'AI governance framework development: EU AI Act compliance, NIST AI RMF mapping, policy design, and risk controls.',
   '["AI Governance Framework Design","EU AI Act Compliance Assessment","NIST AI RMF Mapping","Policy & Procedure Templates","Risk Control Design","Compliance Roadmap","Expert Advisory Session"]',
   '["AI Companies","Enterprise CTOs","Legal & Compliance Teams"]',
   'manual',168,NULL,1,1,140,datetime('now')),

  ('CDB-CSAU-001',
   'Cloud Security Audit',
   3,'ENTERPRISE',9999,120.0,
   'Cloud security audit: IAM assessment, network exposure, data security controls, logging gaps, and compliance posture.',
   '["Cloud Security Controls Review","IAM & Privilege Assessment","Network Exposure Analysis","Data Security Assessment","Logging & Monitoring Gap Analysis","Cloud Security Roadmap"]',
   '["Cloud Teams","DevOps","Enterprise IT"]',
   'automated',0,'cloud_security',0,1,150,datetime('now')),

  ('CDB-COMP-001',
   'Compliance Readiness Assessment',
   3,'ENTERPRISE',24999,300.0,
   'ISO 27001:2022 and NIST CSF 2.0 compliance gap analysis with prioritized roadmap and board-ready executive report.',
   '["ISO 27001:2022 Controls Gap Analysis (93 Controls)","NIST CSF 2.0 Mapping","GDPR Article Assessment","Compliance Scorecard","Prioritized Remediation Roadmap","Executive Summary Report"]',
   '["CISOs","Compliance Officers","Enterprise Risk Teams"]',
   'automated',0,'compliance',1,1,160,datetime('now')),

  ('CDB-AISA-001',
   'AI Security Assessment (Enterprise)',
   3,'ENTERPRISE',39999,480.0,
   'Enterprise AI security assessment: AI attack surface, LLM security, model governance, EU AI Act, and board-level roadmap.',
   '["Enterprise AI Attack Surface Analysis","LLM Security & Adversarial Testing Framework","Prompt Injection & Jailbreak Risk Scoring","AI Model Governance Review","EU AI Act & NIST AI RMF Compliance","AI Security Roadmap","Executive Board Report"]',
   '["Enterprise CISOs","AI/ML Teams","Board-Level Risk"]',
   'automated',0,'ai_security_enterprise',1,1,170,datetime('now')),

  ('CDB-DSO-001',
   'DevSecOps Security Optimization',
   3,'ENTERPRISE',59999,720.0,
   'End-to-end DevSecOps optimization: CI/CD security, secrets management, SAST/DAST integration, IaC security, and strategy.',
   '["CI/CD Pipeline Security Review","Secrets Management Assessment","SAST/DAST Integration Analysis","Container Security Review","IaC Security Analysis","DevSecOps Strategy & Roadmap","Implementation Playbook"]',
   '["DevOps Teams","Platform Engineers","Enterprise CISOs"]',
   'manual',240,NULL,1,1,180,datetime('now'));

-- ============================================================================
-- END: schema_v36_service_catalog.sql
-- ============================================================================
