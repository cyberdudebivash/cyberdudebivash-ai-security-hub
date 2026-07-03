# CYBERDUDEBIVASH® AI Security Hub — Data Lineage Forensic Audit

**Type:** Forensic investigation — prove the complete lineage of every customer-visible value. No assumptions; evidence only.
**Date:** 2026-07-03 · **Platform:** v40.0.0 · **HEAD:** `c8c58dd`
**Method:** Route/handler inventory of `src/index.js` (809 route predicates), competing-source clustering, live probes on `https://cyberdudebivash.in`, and frontend source tracing.
**Evidence key:** [M] measured live · [V] verified in source · [T] test-locked.

---

## 1. Data Lineage Map — canonical sources (customer-visible metrics)

| Metric | Canonical source (proven) | Cache | Background job | Status |
|---|---|---|---|---|
| total_scans | `metricsHydration.js` `max(KV, scan_history, scan_jobs)` | `platform:metrics:live` (45s) | hourly ingestion + metrics refresh | **CANONICAL** [T] |
| KEV / exploited | `exploit_status='confirmed'` (businessMetrics.js) | — | ingestion | **CANONICAL** [T] |
| CVSS score | `cvss_score` (self-healed from `cvss` at ingestion) | — | ingestion self-heal (proven live: IOC verdict UNKNOWN→MALICIOUS) | **CANONICAL** [M][T] |
| cve_id | self-healed from `id` at ingestion | — | ingestion self-heal | **CANONICAL** [M][T] |
| published date | `published_at` | — | ingestion | **CANONICAL** [T] |
| Trust Center metrics | shared hydrator (== platform) | `cache:trust:metrics:v2` (60s) | ingestion | **CANONICAL** [T] |
| Threat feed / stats | `threat_intel` catalog (severity/exploit_status) | — | hourly ingestion (ran 05:00 [M]) | **CANONICAL** [M] |
| Uptime | `uptime_log` availability basis | — | cron probe (306 samples/24h [M]) | **CANONICAL** [M][T] |
| Entitlements / gating | `PLAN_FEATURES` + `TIER_IMPLICIT_FEATURES` | `customer_entitlements` D1 | — | **CANONICAL** [T] |
| **Pricing (PRO/ENT)** | **DISPUTED — see PL-1** | — | — | **COMPETING SOURCES** |

## 2. Complete Route Inventory (findings)

- **809** route predicates in `src/index.js`.
- **True duplicate routes (same path+method) found: 3** — all had the 2nd definition DEAD (unreachable; first match returns). **REMOVED** (`c8c58dd`), guarded by `routeLineageGuard.test.mjs`.
  - `GET /api/billing/invoices` — dead → `handleGetInvoices`; live → `handleListInvoices`.
  - `GET /api/revenue/metrics` — dead → `isRealUser`+`revenue.js`; live → owner-gated. Dead copy would have weakened auth.
  - `GET /api/threat-intel/live` — identical dead copy.
- Method-differentiated same-path routes (GET+POST) are **not** duplicates — verified.

## 3. Competing / Duplicate Data Source Inventory

| Finding | Sources | Classification | Disposition |
|---|---|---|---|
| **PL-1 Pricing** (CRITICAL) | PRO shown as **₹1,499** by: frontend button (`index.html:2269`), SEO JSON-LD (`index.html:763`), `pricingConfig.js` (`/api/pricing`), `apiKeys.js` TIER_LIMITS, `commercialPlatformHandler` upgradeOpps — but **CHARGED ₹2,999** by `monetizationV2.js` (`/api/billing/*`, verified live Razorpay order). | Competing customer-facing source; advertised ≠ charged (false-advertising/legal risk) | **OWNER DECISION** — which value is canonical is a revenue call; NOT guessed. Documented; `pricingLineageGuard.test.mjs` pins the billing source and holds a pending PL-1 assertion that activates on consolidation. |
| total_scans (historical) | scan_jobs / scan_history / KV | Resolved earlier | CANONICAL via `max()` blend [T] |
| KEV (historical) | exploit_status / is_kev / in_kev | Resolved earlier | CANONICAL exploit_status [T] |
| Revenue metrics handler | index top-import vs `revenue.js` | Dead duplicate route removed | Owner-gated definition canonical |

## 4. Dead / Legacy Code Inventory

- 3 dead duplicate route blocks — **removed**.
- `handleGetInvoices` — now an orphaned import (handler unreferenced after dedup). Classified **DEAD**; left imported (harmless, no call site) — safe to prune in a follow-up.
- `pricingConfig.js` / `/api/pricing` — serves the stale ₹1,499; **not fetched by any frontend page** (frontend hardcodes the price). Classified **LEGACY** — reachable directly but not linked; part of PL-1.
- Note: many `is_kev`/`in_kev`/`mitre_technique` phantom-column reads were fixed in prior passes; repo guards prevent reintroduction.

## 5. Background Worker / Scheduled Job Audit (live evidence)

| Job | Evidence of execution | Status |
|---|---|---|
| Threat ingestion (hourly) | `last_ingestion.ran_at = 2026-07-03 05:00:41` [M] | **HEALTHY** |
| Uptime probe cron | 306 samples/24h [M] | **HEALTHY** |
| Platform metrics refresh | `hydrated_at = 05:22:57` [M] | **HEALTHY** |
| Scan queue consumer | async job completed ~35s [M] | **HEALTHY** |
| CVSS/cve_id self-heal | ran on 05:00 ingestion; IOC verdict flipped UNKNOWN→MALICIOUS [M] | **HEALTHY** |

No stalled crons, stuck queues, or stale background workers observed.

## 6. Cache Consistency Audit

- `platform:metrics:live` (45s) is the single hydration cache; Trust Center now sources from it (60s) — no divergent snapshot (resolved earlier).
- No stale-cache serving observed live (metrics `hydrated_at` fresh; uptime `age: fresh`).

## 7. Automated Protection Added

- `routeLineageGuard.test.mjs` (2) — no duplicate (path,method) route definitions.
- `pricingLineageGuard.test.mjs` (1 + 1 pending) — billing single-source; PL-1 reconciliation invariant codified.
- Prior guards retained: business-truth (KEV/CVSS/published_at), scan-count canon, upgrade-path truth.

## 8. Remaining Risks

| ID | Risk | Severity | Owner action |
|---|---|---|---|
| PL-1 | Advertised PRO ₹1,499 vs charged ₹2,999 (and ENTERPRISE ₹4,999 vs ₹24,999) across 5 surfaces | **CRITICAL** | Pick the canonical price; consolidate all sources; un-skip the guard. Legal/revenue exposure until resolved. |
| L-2 | `handleGetInvoices` orphaned import + `pricingConfig.js` legacy | LOW | Prune after PL-1 decision |
| L-3 | Tier sprawl (STARTER/MSSP defined in TIER_LIMITS/pricingConfig but billing sells FREE/PRO/ENTERPRISE) | MED | Consolidate tier catalog to one source |

## 9. Production Repository Health Score

- **Customer-visible metric lineage:** canonical and guarded for scans, KEV, CVSS, cve_id, published date, trust metrics, uptime, entitlements — every one traced to ONE proven source with a regression guard.
- **Router:** zero duplicate routes (was 3), guarded.
- **Crons/queues/workers:** all healthy with live evidence.
- **One CRITICAL open item:** PL-1 pricing (advertised ≠ charged) — a competing customer-facing source requiring an owner pricing decision, not an engineering fix.

## 10. Recommendation

### CONDITIONAL GO

Every customer-visible **metric** now has a verified, single, canonical lineage with automated protection — the forensic mandate's core is met for the data surfaces. The router's dead duplicates are removed and guarded; all background jobs proved live execution. **One CRITICAL finding blocks a clean bill of health: PL-1** — the PRO/ENTERPRISE price is advertised (₹1,499/₹4,999) at a different value than it is charged (₹2,999/₹24,999) across five customer-facing surfaces. This is a genuine false-advertising / revenue-integrity defect, but *which* price is canonical is a business-owner decision (change the ads down, or the charge up) — the audit refuses to guess a revenue-affecting value. It is documented with full lineage and a guard ready to enforce consistency the moment the owner decides.

**Verdict: CONDITIONAL GO** — the repository's data lineage is clean and canonical except for PL-1, which must be resolved by an owner pricing decision before unconditional GO. No customer-visible value was left with an unproven origin; PL-1's origin is fully proven — it simply has two of them, by design decision debt.
