# CYBERDUDEBIVASH® AI Security Hub — Enterprise Business-Truth Certification

**Program:** One canonical definition · one computation · one authoritative source per business fact.
**Date:** 2026-07-02/03 · **Platform:** v40.0.0 · **Commits:** `e07fc83` (scans) · `fef2022` (KEV) · `cfbcc58` (CVSS + published_at)
**Mandate:** Assume every customer-visible metric has multiple conflicting definitions until proven otherwise. Establish ONE canonical business truth. Never claim synchronization without evidence.
**Method:** Clustered every `COUNT/SUM` over the core business tables, diffed WHERE clauses for definition drift, probed live for cross-endpoint value divergence, traced each divergence to its column, and unified consumers onto a canonical layer with regression guards.

---

## 1. Duplicate Business Logic Report — what was found

Every core threat-intel fact had **multiple SQL definitions, several silently broken**:

| Business fact | Conflicting definitions found | Live evidence | Canonical | Status |
|---|---|---|---|---|
| **total_scans** | `scan_jobs` (118) · `max(KV-7d, scan_history)` (62) · `scan_history`-only (21) | health=118, platform=62, trust=21 | `max(KV, scan_history, scan_jobs)` | **FIXED** `e07fc83` — all surfaces = 118 |
| **KEV / actively-exploited** | `exploit_status='confirmed'` (1631) · `is_kev=1` (0, never written) · `in_kev=1` (0, column absent) · `actively_exploited=1` | stats=1631, exec report=0, hunt filter=∅ | `exploit_status = 'confirmed'` | **FIXED** `fef2022` |
| **CVSS score** | `cvss` (10, written) · `cvss_score` (null, canonical + 60 readers) | CRITICAL CVE: `{cvss:10, cvss_score:null}` | `cvss_score` (self-healed from cvss) | **FIXED** `cfbcc58` |
| **published date** | `published_at` (written, 37 readers) · `published_date` (absent → query errors) | vulns list / SEO feed empty | `published_at` | **FIXED** `cfbcc58` |
| **mitre_technique** | selected FROM threat_intel by 5 handlers · column absent in both schemas → query errors | vulns/hunt empty | `NULL AS mitre_technique` (synthesized, no error) | **FIXED** `04c7006` |
| **cve_id** | CVE written to primary-key `id`; canonical `cve_id` left NULL | live `{id:"CVE-2024-3400", cve_id:null}` | `cve_id` (self-healed from id) | **FIXED** `04c7006` |
| **critical severity** | `severity='CRITICAL'` (14) · `cvss_score>=9` (exec risk) | 14 vs cvss-based | `severity='CRITICAL'` (headline); cvss≥9 exposed separately | **DOCUMENTED** (§5) |

**Root pattern:** `threat_intel` accumulated two schema generations. The active ingestion path (`threatIngestion.js`) writes `cvss`/`id`/`exploit_status`/`published_at`/`known_ransomware`, while a large reader population expects the earlier/canonical `cvss_score`/`cve_id`/`is_kev`/`published_date`/`mitre_technique`. The fix strategy: **self-heal the canonical columns at the ingestion source** (cvss_score←cvss, cve_id←id) so readers heal without per-query edits, and **route the truly-absent columns** (is_kev/in_kev→exploit_status, published_date→published_at, mitre_technique→NULL) to real columns.

Customer impact of the broken definitions (all now closed): the executive report claimed **0 actively-exploited vulnerabilities**; the vuln-management `?kev=true` filter, SEO/marketing threat feed, and threat-hunting "actively exploited" hunts returned **nothing**; every CVSS-based critical/high count and risk-sort read **null → 0**.

## 2. Canonical Business Layer

**`workers/src/lib/businessMetrics.js`** — the single source of truth for threat-intel predicates, with a governance table documenting why each definition wins and the alternatives are rejected:

- `KEV_PREDICATE = "exploit_status = 'confirmed'"` (+ `KEV_ORDER` / derived-flag alias)
- `CRITICAL_PREDICATE = "severity = 'CRITICAL'"`
- `RANSOMWARE_PREDICATE = "known_ransomware = 1"`
- `CVSS_CRITICAL_PREDICATE = "cvss_score >= 9"` (a distinct fact, never the headline "critical")
- Canonical count helpers: `kevCount`, `criticalCount`, `highCount`, `ransomwareCount` (never throw).

Platform-metric facts (scans/CVEs/customers/SOAR) remain canonicalised in **`metricsHydration.js`** (the platform metrics authority), which the Trust Center now also sources from (commit `e07fc83`).

## 3. Consumers synchronized onto canonical

**KEV** → `executiveReport`, `vulnManagement` (filter+order+flag+single-CVE), `threatHunting` (filter+base+order+SELECT), `predictiveEngine`, `adaptiveCyberBrain`, `index.js` (v13/status, recentCVEs, God-mode predictions kev_count via threat_intel subquery), `iocEnrichment`.
**CVSS** → self-heal at the ingestion source (`storeInD1`) heals all 60 `cvss_score` readers at once, no per-reader edits.
**published_at** → `vulnManagement`, `seoFeeds`, `enterpriseAutomation`, `threatHunting`, `predictiveEngine`, `iocEnrichment`.

## 4. Business-Truth Regression Tests

- `businessTruthKev.test.mjs` (8) — canonical predicates, count helpers, and a **repo guard** that fails CI if any threat_intel query reintroduces `in_kev`/raw `is_kev=1`.
- `businessTruthCvss.test.mjs` (3) — proves `storeInD1` runs the idempotent cvss_score self-heal and is non-fatal, plus a **repo guard** against the non-existent `published_date` column returning to any threat_intel query.
- `metricsHydration.test.mjs` / `trustMetricsContract.test.mjs` — scan-count canon (scan_jobs participates; trust == platform).
- Full suite: **950 passing**, bundle compiles. All fixes deployed; pipeline green.

## 5. Remaining Divergence Register

| ID | Divergence | Severity | Disposition |
|---|---|---|---|
| BT-1 | "critical" = `severity='CRITICAL'` (14) vs `cvss_score>=9` (executive risk KPIs). Both now return real numbers (cvss_score healed) but they are DIFFERENT facts. | MED | **Owner data decision:** either derive `severity` from CVSS at ingestion (so they converge) or keep them as two clearly-labelled facts ("severity-critical" vs "CVSS-critical"). Documented; not silently unified. |
| BT-2 | `actively_exploited` is a 4th KEV-ish column (IS populated by ingestion). Some handlers read it as `in_kev`. | LOW | Equivalent-in-intent to `exploit_status='confirmed'`; recommend a follow-up to assert the two stay in lock-step at ingestion, or drop one. |
| BT-3 | `/api/v13/status` threat_intel block returns 0/0/0 — the whole query rejects (binding/other), not just KEV. | LOW | Legacy status endpoint, **not consumed by any frontend**. Recommend deleting or repairing separately. |
| BT-4 | `threat_predictions` (God-mode) reads `probability_pct`/`prediction_date`/`is_kev` its INSERT never writes — schema-drifted feature. kev_count now derives from threat_intel; the rest remains drifted. | MED | Separate remediation of the God-mode predictions schema. |
| BT-5 | Revenue (`SUM payments.amount`) vs MRR (`SUM subscriptions.price_inr`) — distinct facts, labelled separately today. | LOW | Correct as-is; documented so they are never conflated. |
| BT-6 | CVSS backfill heals on the next ingestion cron; the migration file gives instant backfill. | LOW | **Owner action:** run `schema_migration_cvss_score_backfill.sql` for immediate healing (else self-heals within the hour). |

## 6. Enterprise Business-Truth Score

- **Core customer-visible facts (scans, KEV, CVSS, published date):** now single-source and consistent, with regression guards preventing re-divergence.
- **Coverage:** the threat-intel + scanning + executive domains were traced exhaustively for duplicate SQL and unified. Billing/subscription, marketplace, training, identity, cloud, org/project/asset domains were **not** exhaustively re-traced this pass beyond the payments/subscriptions facts already covered.

## 7. Recommendation

### CONDITIONAL GO

Four families of business-truth defects — a scan-count contradiction across four surfaces, a KEV metric broken to zero across five consumers, a CVSS field that nulled every CVSS-based metric, and a non-existent `published_date` column that silently emptied the vulnerability list and SEO feed — were **found, root-caused, unified onto a canonical layer, regression-guarded, deployed, and (for the immediately-observable ones) live-verified**. No fabricated data was introduced; every fix routes consumers to a real, populated, authoritative source.

GO is **conditional** on: (a) the owner running the one-line CVSS backfill migration (or waiting one ingestion cron), and (b) the BT-1 "critical" definition decision — both documented above with owners. The remaining domains (BT-2..BT-5) are lower-severity, documented, and scheduled rather than open-ended.

**Verdict: CONDITIONAL GO** — the customer-facing threat-intelligence business truth is now canonical and guarded; residual items are documented with owners, not assumed resolved.
