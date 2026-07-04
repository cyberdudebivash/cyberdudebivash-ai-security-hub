# Enterprise Customer Success Matrix — Living Document

> **Phase VII instrument.** Every customer workflow is executed as a real
> customer (HTTP only, no implementation knowledge) and certified from
> evidence. Statuses: CERTIFIED · PILOT READY · PRODUCTION READY ·
> APPROVED WITH LIMITATIONS · NEEDS IMPROVEMENT · BLOCKED.
>
> **Edition:** 3 · **Date:** 2026-07-04 · **Build evaluated:** `b81bce0` (live) + Phase IX RC fix
> (Edition 2 appended the Phase VIII 100-customer scale journeys J13–J19.
> Edition 3 appends the Phase IX Release Candidate journeys J20–J25, executed
> against **live production**. Prior journeys are retained; statuses change only
> with fresh evidence.)
>
> **Vantage points (disclosed):** production egress is policy-blocked from the
> engineering sandbox, so journeys were executed against a lab runtime of the
> exact deployed build (local D1/KV, secrets configured per DEPLOY.md), plus
> external evidence from the pipeline's post-deploy smoke (GitHub runners →
> live production) and the owner's same-day live capture. Journeys that
> require third-party systems no lab can fake (live payment, live IdP, Slack/
> Teams, customer SIEM) are marked NEEDS EVIDENCE, not passed.

## Journey certifications

| # | Journey (persona) | Status | Evidence highlights |
|---|-------------------|--------|---------------------|
| J1 | API discovery & free tier (developer) | **PRODUCTION READY** | `GET /api` self-docs; keyless `/api/v1/intel/kev.json` 200 with honest `data_source`/`live` labels; machine-readable `pricing.json`; clear 401s. Fixed this cycle: `/api` version said 10.0.0 (now 40.0.0); v1 401 sent FREE users on a dead-end key hunt (now names the required plan) |
| J2 | Signup → login → session (new customer) | **PRODUCTION READY** (lab) | Full chain 200 with token envelope. Fixed this cycle: a post-INSERT failure stranded a half-created account ("Email already registered" on retry) — signup now rolls back and says "no account was created". Residual: no email-verification step exists (see limitations) |
| J3 | API key issuance & use (integrator) | **PRODUCTION READY** | `POST /api/keys` 201, key shown once with save-now warning, tier limits in response; key works on entitled endpoints, 403 with upgrade path on PRO-gated ones |
| J4 | Domain scan → results (SOC analyst) | **PRODUCTION READY** (lab) | Scan 200 with structured findings + honest premium-lock preview. Fixed this cycle (S1-class): an unresolvable domain returned **grade A / risk LOW** (NaN-poisoned score) — now an explicit `unmeasurable` outcome with no fabricated verdict, not cached, history-safe; null TLS probe no longer 500s the scan |
| J5 | Report generation & download (analyst/manager) | **PRODUCTION READY** | 201 with shareable link, honest 7-day FREE retention, 24.7KB HTML downloads; private-report auth gate regression-locked since Phase V |
| J6 | AI analyst consultation (threat intel team) | **CERTIFIED (honesty)** | Asked about a CVE absent from the intel DB: *"No verified intelligence on record… I won't assert its severity — doing so would be guesswork."* The no-fabrication differentiator held under the exact condition that tempts fabrication. Answer accuracy with full data: evidence from live capture (source-attributed feeds), not lab |
| J7 | Offboarding & erasure (compliance officer) | **CERTIFIED** | `DELETE /api/auth/delete-account` 200 with per-category erasure receipt + honest tax-retention note; login 401 and API keys dead immediately after. Fixed this cycle: endpoint was undiscoverable (absent from `/api` docs) |
| J8 | Implementation engineer (fresh environment) | **APPROVED WITH LIMITATIONS** | Following the repo docs produced a deployment whose auth surface 500'd: required secrets were undocumented (now in DEPLOY.md) and `schema*.sql` files cannot bootstrap an empty DB (FKs reference `users_v44_backup`, a migration artifact). Supported path documented: restore the newest nightly backup (drill-validated weekly). Canonical bootstrap export queued |
| J9 | Procurement committee (Fortune 500) | **APPROVED WITH LIMITATIONS** | Positive: security questionnaire pack, honest attestation phrasing (fixed Phase VI), transparent Trust Center, external uptime probe, weekly restore drill, erasure receipts. Objections that stand: no SOC 2/ISO attestation, single-operator support (R-10), no live payment/SSO evidence, self-reported uptime only |
| J10 | Live payment → entitlement (buyer) | **NEEDS EVIDENCE (owner)** | Cryptographic verification path is regression-tested (real worker, real crypto, tamper rejected 400; no over-grant) — but no real transaction has ever been processed. GA gate 1 |
| J11 | SSO/SAML round-trip (enterprise IT) | **NEEDS EVIDENCE (owner)** | Endpoints exist; no live IdP round-trip has ever been executed. GA gate 2 |
| J12 | SIEM/webhook integration (SOC engineer) | **NEEDS IMPROVEMENT** | One-click SIEM deploy UI exists with deployment log; STIX 2.1 export live (PRO+); but no push to a real Splunk/Sentinel/Elastic instance has been evidenced, and TAXII remains absent (gap matrix) |

## Issues found & fixed this cycle (all regression-locked)

| Issue | Business impact | Root cause | Fix |
|-------|-----------------|------------|-----|
| Unresolvable domain scanned as "grade A / risk LOW" with a CRITICAL finding beside it | False assurance — customer scanning a typo'd/internal domain believes they're secure; procurement demo lands on a contradiction | Non-numeric DNSBL score NaN-poisoned the risk total; every grade boundary comparison failed downward to "A"; JSON serialized NaN as null | NaN-proof scoring; explicit `unmeasurable` verdict (no grade, INFO finding, honest summary); not cached; history stores UNKNOWN/N.A; null-TLS crash fixed |
| Duplicate scan-result builders (inline v4.0.0 vs exported v5.0.0) | Two sources of business truth; fixes applied to one path missed the other | Sync handler predated `buildRealResult` extraction | Single builder used by sync + async paths |
| Failed signup stranded a half-created account | Customer locked out of their own email address at first contact | Token issuance after user INSERT was unguarded | Rollback + honest `ERR_SIGNUP_INCOMPLETE` ("no account was created") |
| `/api` said version 10.0.0; deletion endpoint undocumented; v1 401 pointed FREE users to keys they can't use; upgrade URLs pointed at the tools store | Trust/discoverability erosion at exactly the moments customers evaluate | Stale strings; docs list never updated; wrong constant | All aligned; delete-account listed; 401 names required plan + free alternative; upgrade URLs → platform pricing |
| Required secrets undocumented; DB not bootstrappable from schema files | A fresh environment (staging, DR, self-host evaluation) fails immediately | DEPLOY.md never covered secrets; schema files are historical migrations | DEPLOY.md secrets table + failure modes + supported bootstrap path (backup restore); canonical bootstrap export queued |

## Standing limitations (owner-action; no commit can close)

1. **No email verification step** in signup — accounts activate on POST. Acceptable for self-serve free tier; enterprise RBAC/SSO onboarding is the paid path. Documented, not hidden.
2. **GA gates unchanged:** one live payment, one live SSO round-trip, external SLA measurement, support deputy (R-10), SOC 2 for regulated segments.
3. **Integration evidence** (J12) requires a customer-side system; first pilot tenant closes it.

## Phase VIII — scale simulation journeys (100 customers, six months)

Executed against 100 organizations across 10 enterprise archetypes over HTTP
only. Full detail in `PHASE_VIII_ENTERPRISE_OPERATIONS_REPORT.md`; objections in
`CUSTOMER_OBJECTION_REGISTER.md`.

| # | Journey (persona) | Status | Evidence highlights |
|---|-------------------|--------|---------------------|
| J13 | Onboard 100 orgs at scale (all archetypes) | **PRODUCTION READY** | 100/100 onboarded; TTFV p50 406 ms / p95 778 ms; 0 errors, 0 objections in the clean post-fix pass |
| J14 | Scan → report on an already-cached domain (SOC analyst) | **PRODUCTION READY** (fixed) | Was S1: cache-hit returned a stale `scan_id`, so report generation 422'd for any previously-scanned domain. Fixed (scan_id alignment); 90/90 reports generate; locked by `phase8CachedScanReportId` |
| J15 | Compare pricing across surfaces (evaluator) | **PRODUCTION READY** (fixed) | FREE 5 vs 3 vs 50 and STARTER shown worse-than-FREE reconciled; `/api` tiers now derived from enforced `TIER_LIMITS`; locked by `phase8EntitlementTruth` |
| J16 | Read plan entitlements (admin) | **PRODUCTION READY** (fixed) | Plan page said no AI / no reports while delivering both; now advertises what FREE actually ships; locked by `phase8EntitlementTruth` |
| J17 | Cross-tenant isolation probe (CISO) | **CERTIFIED** | Second tenant's token → 403 on another org's dashboard, record, and update; owner control → 200. No isolation breach |
| J18 | Sustained-load throttling (MSSP/SOC) | **APPROVED WITH LIMITATIONS** | FREE 2/min burst throttles heavy usage by-design; 429 names tier/reason/retry/upgrade — graceful, no 500s. Upgrade closes it |
| J19 | Fresh-environment DB bootstrap (impl. engineer) | **PRODUCTION READY** (fixed) | Phase VII J8's "canonical bootstrap queued" delivered: `schema_bootstrap.sql` stands up an empty DB to 228 tables, 0 errors, 0 phantom-table refs |

## Phase IX — Release Candidate journeys (live production, public workflows)

Executed as a paying customer over HTTP against **live production**
(`https://cyberdudebivash.in`), throwaway accounts deleted. Full detail in
`PHASE_IX_RELEASE_CANDIDATE_REPORT.md`.

| # | Journey (persona) | Status | Evidence highlights |
|---|-------------------|--------|---------------------|
| J20 | Full self-serve implementation (admin) | **RELEASE APPROVED** | signup 201 → login → org 201 → keys → MFA, all live, no engineering help; TTFV ~2.6 s |
| J21 | Org security dashboard (SOC manager) | **APPROVED W/ LIMITATIONS** (fixed) | Was **500 in production** (`created_at` vs canonical `scanned_at`); fixed + resilience; locked by `phase9OrgDashboardSchema`; prod re-verify pending deploy |
| J22 | Operations suite (SOC analyst) | **RELEASE APPROVED** | scan/unmeasurable-honesty/report+download/AI(conf 94)/history/threat-intel/KEV all green live |
| J23 | Support error-quality (support engineer) | **RELEASE APPROVED** | 401/401(plan)/402(plan+upgrade)/400(clear)/429(retry+upgrade) — every error self-explaining |
| J24 | Commercial & offboarding (buyer/compliance) | **RELEASE APPROVED** | plans consistent, entitlements truthful, order creates; delete → erasure receipt, credentials dead |
| J25 | SSO onboarding (enterprise IT) | **PILOT ONLY** | Endpoints implemented & respond (need `?org=`); no live IdP round-trip (GA gate 2) |

## Update protocol

Re-execute a journey whenever its surface changes; a journey's status may only
change with fresh evidence. New journeys append; statuses never silently edit.
Certification language per the Phase VII final rule: a workflow is not "working"
— it is "completed by a customer under production-like conditions with verified
evidence and no production-critical blockers within the validated scope."
Phase VIII adds the §8 Customer Adoption Rule: a capability is successful only
when a representative customer can discover, understand, configure, use, and
gain business value from it with acceptable operations — tracked via the
Customer Objection Register.
