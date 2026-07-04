# Phase IV Remediation Pass — Gap Closure Report

**Date:** 2026-07-04 (same day as the Phase IV certification) · **Authority:** Enterprise Release Authority
**Objective (owner-directed):** re-audit every registered gap/issue/flaw across the risk register, Phase I–IV reports, and dossier limitations; permanently fix everything fixable in code/CI/docs, with Fortune-500 global release as the target posture.
**Honesty boundary:** "100% production stable" is not certified — it is uncertifiable and is precisely the claim enterprise procurement rejects. What IS delivered: every code/CI/docs-closable gap closed with regression-locked permanent fixes; the remaining residue is owner-action by nature, listed in §4.

## 1. Re-audit method

Consolidated ledger built from: `docs/OPERATIONAL_RISK_REGISTER.md` (R-06…R-18, EA-01…EH-03), the Phase IV Global Release Decision conditions register (#1–8), the Customer Readiness Dossier limitations, and the Competitive Gap Matrix. Each item verified against source (production == certified `56ab74f`; live re-probe unavailable from this sandbox — egress policy-blocked, as disclosed in the Phase IV report §0). One matrix error found and corrected during verification (§3).

## 2. Fixed this pass (permanent, regression-locked)

| # | Gap (origin) | Root cause found | Permanent fix | Lock |
|---|---|---|---|---|
| 1 | Scan-ETA dishonesty (Dossier limitation; Decision cond. 3) | Homepage FAQ/hero/stat claimed "<30s"; **the API itself** returned `estimated_eta: '< 5s'/'< 10s'/'< 30s'` (queue.js) vs ~90s measured live | All three homepage claims → "~2 min"; API ETAs → measured "~1 min / 1–2 min / 1–3 min" by priority | `honestCopy.test.mjs` (3) |
| 2 | Advertised per-minute limits unenforced (Dossier limitation; Decision cond. 3) | v1 feed: `enforceDailyLimit` checked only the daily counter — `rate_per_min` from pricing.json was never enforced, **including on unlimited-daily ENTERPRISE/MSSP**; `/api/intel/*` economy: same, canonical burst/min ignored | Minute-window enforcement in both metered paths (KV counter, `Retry-After: 60`, distinct 429 bodies); fail-open on KV outage preserved (accepted R-14) | `intelRateLimitEnforcement.test.mjs` (8) |
| 3 | Capability-URL-only report downloads (Decision #4 condition 5) | No access metadata existed on stored reports | Opt-in `visibility:"private"` on `POST /api/report/generate` binds the report to the generating account; download then requires owner auth (401 anon / 403 other / 200 owner / admin allowed). Default shareable mode unchanged | `privateReportAccess.test.mjs` (5) |
| 4 | STIX entitlement contradictions (found during re-audit) | `/api/intel/*` responses' `stix_available` read a field the quota checker never returned (always undefined); internal tier flag said PRO `stix:false` while the public pricing matrix sells PRO `stix_export:true` | Quota checker returns the real `stix` flag; PRO aligned UP to the sold promise; responses now include `stix_endpoint: /api/v1/intel/stix.json` | `intelRateLimitEnforcement.test.mjs`, `honestCopy.test.mjs` |
| 5 | R-11 — no external uptime probe | All monitoring lived inside the monitored Worker | `external-uptime-probe.yml`: GitHub-hosted probe every 15 min (custom domain + workers.dev fallback, 3-attempt backoff); outage → auto-filed issue + failed-run notification | YAML validated; fires on schedule |
| 6 | R-06 — restore never drilled on a real artifact | Drill script existed but was never pointed at a real nightly dump | `d1-restore-drill.yml`: weekly automated drill downloads the newest successful nightly artifact and runs the proven drill script (≥50-table floor) | Drill script already locked by `restoreDrill.test.mjs` (6) |
| 7 | R-12 — 30-day backup ceiling | GitHub artifact default | Retention 30 → 90 days (platform max). Residual for >90d compliance archive disclosed | Workflow diff |
| 8 | R-13 — unguarded bundle growth | No size check anywhere | `bundle-size` job in the Test & Quality Gate: wrangler dry-run, **fail > 2.5 MB gzip** (measured 1.32 MB = 44% of the 3 MB cap) | CI gate itself |
| 9 | Decision #16 — stale canonical docs | v3-era `api-contract.md` (workers.dev, 5 req/day, ₹9,999 PRO) and deterministic-engine `architecture.md` | Both rewritten from verified v40 behavior, with supersession notices | Doc review |
| 10 | Procurement collateral gap (Commercial report §3) | No standard security-questionnaire answers | `docs/SECURITY_QUESTIONNAIRE_PACK.md` (CAIQ-lite), every answer evidence-bounded incl. the honest "no"s | Doc review |

## 3. Self-correction (audit integrity)

The Phase IV Competitive Gap Matrix marked "STIX/TAXII interchange" as **missing**. Re-verification proved STIX 2.1 export exists and is routed (`/api/v1/intel/stix.json` PRO+, `/api/cti/v2/stix/export` entitlement-gated) — the matrix cell was wrong and now carries an erratum. TAXII 2.1 (server protocol) remains genuinely absent. Evidence overrode the earlier conclusion, in both directions.

## 4. Cannot be closed by code — owner-action residue (unchanged, restated honestly)

1. **One live payment** (real card/UPI) — gate for paid-tier "verified live".
2. **One live SSO IdP round-trip** with a pilot tenant.
3. **Support continuity**: a named deputy/escalation human (R-10) — a workflow cannot hire a person.
4. **SOC 2 Type I** engagement — the regulated-segment unlock (quarters).
5. **First green scheduled runs** of the two new workflows (they run on `main` after merge; the probe additionally needs nothing, the drill needs an existing nightly artifact — both exist).
6. **>90-day compliance archive** (R-12 residual) — ship dumps to R2/external storage when a contract requires it.
7. D1 latency (R-08) and cron-plan confirmation (R-09) — infrastructure decisions, unchanged.

## 5. Verification

Full suite after all changes: **1,267 tests / 121 files passing** (+16 new across 3 files). All four touched workflows YAML-validated. Worker imports clean (`node --input-type=module -e 'import ./src/index.js'` via lint script semantics). Production remains on certified `56ab74f`; these fixes deploy through the gated pipeline on merge to `main`.

## 6. Release-decision deltas

- Decision #4 (reports): private mode now exists → regulated-tenant condition **met in code**; row advances to ENTERPRISE APPROVED without the sharing caveat once deployed.
- Decision #15/#14: external probe closes the monitoring half of the SLA gate; definition reconciliation (EA-03) and support staffing remain.
- Decision #16 (stale docs): **closed**.
- Conditions register: #3 (probe) done in CI, #5 (auth-gated reports) done, #6 (docs) done; #1, #2, #4, #7 remain owner-action.
