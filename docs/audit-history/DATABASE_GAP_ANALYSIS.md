# CYBERDUDEBIVASH® — DATABASE GAP ANALYSIS
**Date:** 2026-06-12 | **Database:** Cloudflare D1 (SQLite) — cyberdudebivash-security-hub

---

## SCHEMA FRAGMENTATION CRISIS

**10 different SQL schema files exist with no migration runner:**

| File | Version | Purpose | Applied? |
|------|---------|---------|---------|
| schema.sql | Base | Core tables | Unknown |
| schema_v8.sql | v8 | GTM + content tables | Unknown |
| schema_v10.sql | v10 | Defense products, MYTHOS | Unknown |
| schema_v12.sql | v12 | Anomaly + predictive | Unknown |
| schema_v15.sql | v15 | Compliance + auth | Unknown |
| schema_v28.sql | v28 | AI Security (ASPM, Gov, RT) | Unknown |
| schema_v29.sql | v29 | MCP scanner, Vibe Code | Unknown |
| schema_migrations_v2.sql | v2 | Migration patches | Unknown |
| schema_gtm_only.sql | GTM | Growth/Marketing tables | Unknown |
| schema_revenue_autopilot.sql | Revenue | Revenue tracking | Unknown |
| schema_threat_intel.sql | Intel | Threat intelligence tables | Unknown |

**CRITICAL**: There is no database migration runner. No `migrations/` directory with ordered files. No `db:migrate` script. No `schema_version` table. The actual production D1 state is UNKNOWN.

---

## EXPECTED TABLE INVENTORY (from handler code analysis)

### CORE TABLES (from schema.sql)
| Table | Used By | Status |
|-------|---------|--------|
| `users` | auth.js | Core — required |
| `api_keys` | apikeys.js | Core — required |
| `scan_results` | jobs.js | Core — required |
| `scan_jobs` | jobs.js | Core — required |
| `payments` | payments.js | Core — required |
| `subscriptions` | subscription.js | Core — required |
| `audit_log` | auditLog.js | Required for compliance |
| `organizations` | orgManagement.js | Required for multi-tenant |
| `org_members` | orgManagement.js | Required for multi-tenant |

### THREAT INTELLIGENCE TABLES
| Table | Used By | Status |
|-------|---------|--------|
| `threat_intel` | threatIntel.js | Required — cron seeded |
| `iocs` | threatIntel.js | Required — cron seeded |
| `threat_correlations` | correlationEngine.js | Required |
| `threat_graph_nodes` | graphEngine.js | Required |
| `threat_graph_edges` | graphEngine.js | Required |

### AI SECURITY TABLES (schema_v28.sql)
| Table | Used By | Status |
|-------|---------|--------|
| `ai_assets` | aiSecurityASPM.js | Required — PILLAR 1 |
| `ai_asset_scans` | aiSecurityASPM.js | Required |
| `governance_assessments` | aiGovernance.js | Required — PILLAR 2 |
| `governance_answers` | aiGovernance.js | Required |
| `redteam_engagements` | aiRedTeam.js | Required — PILLAR 3 |
| `redteam_findings` | aiRedTeam.js | Required |
| `registered_agents` | aiThreatIntel.js | Required — PILLAR 4 |
| `ai_services_engagements` | aiServices.js | Required — PILLAR 6 |

### REVENUE & SALES TABLES
| Table | Used By | Status |
|-------|---------|--------|
| `leads` | salesPipeline.js | Required |
| `demo_bookings` | salesPipeline.js | Required |
| `proposals` | proposalGenerator.js | Required |
| `enterprise_inquiries` | enterprise.js | Required |
| `affiliate_partners` | affiliateSystem.js | Required |
| `mrr_snapshots` | executiveReport.js | Required |
| `manual_payments` | manualPayments.js | Required |
| `defense_products` | defenseMarketplace.js | Required — empty |

### MONITORING & OPERATIONS TABLES
| Table | Used By | Status |
|-------|---------|--------|
| `monitors` | monitoring.js | Required |
| `monitor_results` | monitoring.js | Required |
| `soc_alerts` | soc.js | Required |
| `soc_decisions` | soc.js | Required |
| `defense_actions` | autoDefenseEngine.js | Required |
| `anomaly_events` | anomalyEngine.js | Required |
| `siem_integrations` | siemDeploy.js | Required |
| `integrations` | siemDeploy.js | Required |

---

## CRITICAL DATA GAPS

### GAP-DB-001: Empty Production Database
**Evidence:** Revenue = ₹0, intel hub shows static content, defense marketplace shows mocks.
**Impact:** All dynamic features fail silently.
**Fix:** Run `GET /api/seed/all` (admin) to seed initial data, then enable cron ingestion.

### GAP-DB-002: Missing Schema Application
**Evidence:** 10 schema files, no migration runner.
**Impact:** Tables referenced in handlers v28/v29 may not exist, causing 500 errors.
**Fix:** Create unified `schema_final.sql` and apply to D1:
```bash
npx wrangler d1 execute cyberdudebivash-security-hub --file=./schema_final.sql
```

### GAP-DB-003: No Schema Version Tracking
**Evidence:** No `schema_versions` table referenced in any code.
**Impact:** Cannot determine current D1 state without manual inspection.
**Fix:** Add migration tracking table and version each schema file.

### GAP-DB-004: defense_products Table Empty
**Evidence:** defenseMarketplace.js falls back to 3 mock objects when table is empty.
**Impact:** Marketplace shows fake products.
**Fix:** Run product generation via `/api/content/pipeline/run` (admin) after CVE seeding.

### GAP-DB-005: Threat Intel Table Depends on Cron
**Evidence:** threatIntel.js has fallback chain D1 → KV → seed data.
**Impact:** Shows 0 or seed data only — no live intelligence.
**Fix:** Manually trigger `/api/threat-intel/ingest` and confirm cron slots 2/4 are working.

---

## RECOMMENDED DATABASE ACTIONS (Priority Order)

1. **IMMEDIATE**: Audit actual D1 tables: `wrangler d1 execute --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"`
2. **IMMEDIATE**: Apply missing schema files in order: v8 → v10 → v12 → v15 → v28 → v29
3. **HIGH**: Run seed endpoint: `POST /api/seed/all` with admin token
4. **HIGH**: Run threat intel ingestion: `POST /api/threat-intel/ingest` with admin token
5. **HIGH**: Run product pipeline: `POST /api/content/pipeline/run` with admin token
6. **MEDIUM**: Create canonical `schema_final.sql` combining all versions
7. **MEDIUM**: Add `schema_versions` migration tracking
8. **LOW**: Set up automated daily backup of D1 to R2

---

*Database Gap Analysis v1.0 — CYBERDUDEBIVASH® Forensic Audit — 2026-06-12*
