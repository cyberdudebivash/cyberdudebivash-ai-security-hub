# Production Health Scorecard — Living Document

> **Canonical Phase VI instrument.** Updated every improvement cycle; each
> entry carries current state, trend, evidence, known risks, and recommended
> actions. Trends are relative to the previous edition. Nothing here is
> asserted without evidence — unknown is written as unknown.
>
> **Edition:** 9 · **Date:** 2026-07-06 · **Last deployed production commit:** `534bf14`; CEAP cycle 1 (Editions 8-9 are code + test evidence, not yet deployed — see below)
> Edition 2 (same day): cycle-2 truth audit executed — fabricated customer
> notifications eliminated, seed endpoints labeled synthetic, attestation
> badges reworded, MYTHOS labels aligned to the deployed engine, and a
> committed tool-banner corruption removed from the customer dashboard.
> **Edition 3 (Phase VIII, same day):** 100-customer × six-month live-operations
> simulation. Three customer-visible defects found at scale and fixed — the
> scan→report 422 on cached domains (S1-class), pricing that contradicted itself
> across three surfaces, and an entitlement display that under-sold the free
> tier. Fresh-environment DB bootstrap closed (`schema_bootstrap.sql`, 228
> tables/0 err on empty). Tenant isolation, AI honesty, and throttle-grace
> verified at scale. Suite 1,300 tests / 126 files.
> **Edition 4 (Phase IX RC, same day):** Release Candidate governance executed
> **against live production** with paying-customer journeys (throwaway
> accounts, full cleanup). One critical production defect found and fixed:
> org dashboard + org scan history 500'd (`scan_history.created_at` vs the
> canonical `scanned_at`; the lab had masked it via a heal-pass column —
> RC-B1). Fix ships with a production-faithful-schema regression lock plus
> per-aggregate dashboard degradation. Negative paths, measurement honesty,
> Phase VIII fixes, and SSO surface re-verified live. Per-capability release
> decisions + blocker board: `PHASE_IX_RELEASE_CANDIDATE_REPORT.md`.
> Suite 1,305 tests / 127 files.
> **Edition 5 (Phase X GA, same day):** GA Board certification. One GA
> blocker found and closed: **credential recovery did not exist** (all reset
> paths 404'd live; a forgotten password permanently lost the account —
> OBJ-08/GA-B1). Built enumeration-safe forgot/reset flow (hashed single-use
> KV tokens, session revocation, login-UI views), locked by 6 tests. Live
> verified this phase: full API-key rotation lifecycle, member
> invite→role-change→removal loop with RBAC denials, per-key usage
> reporting, AI trust consistency. GA decisions per capability:
> `GENERAL_AVAILABILITY_REPORT.md`. Permanent release lifecycle adopted
> (`docs/ENGINEERING_STANDARDS.md` §9) — phase-numbered programs end here.
> Suite 1,311 tests / 128 files.
> **Edition 6 (post-GA operations, same day):** first cycle under the
> permanent lifecycle — an operations audit, no code shipped. Full customer
> lifecycle re-executed live in one 15.7 s pass, all green; **zero new
> objections** (first such cycle). Verified operating: nightly backups (2/2
> green), external probe (5/5), 7 consecutive green gated deploys. Verified
> commercially: checkout creates a **live Razorpay order** — only settlement
> remains (GA-O1). Restore drill armed, first run Monday (dispatch is
> owner-only). Support playbook precision-fixed twice (429 header nuance,
> per-key usage semantics). Incident Review Register opened (IR-1/IR-2:
> both prior incidents were customer/audit-detected — error-rate alerting is
> improvement priority CI-1). Full record: `OPERATIONAL_EXCELLENCE_REPORT.md`.
> **Edition 7 (CEAP cycle 1, same day):** Continuous Enterprise Assurance
> stood up as the standing loop. Shipped `scripts/ceap-sweep.mjs` +
> `ceap-assurance.yml`: the 13-check customer lifecycle now re-executes
> against live production **every 6 hours** (cycle-1 run: 13/13 green on
> `534bf14`) — closing the journey half of the IR-1/IR-2 detection gap;
> error-rate alerting remains CI-1. Permanent Verifiable-Statement Rule
> codified (`docs/ENGINEERING_STANDARDS.md` §10): every customer-facing
> statement stays continuously verifiable against production, or is
> withdrawn.
> **Edition 8 (CI-1 alerting, same day):** Shipped the alerting half of CI-1.
> `scripts/error-rate-alert.mjs` + `.github/workflows/error-rate-alert.yml`
> poll Cloudflare's GraphQL Analytics API every 15 min for the Workers
> runtime error rate between CEAP sweeps, filing/refreshing a pinned incident
> issue on a real spike (same pattern as `external-uptime-probe.yml`).
> Unit-tested (`workers/test/errorRateAlert.test.mjs`, 12 tests: threshold
> math incl. exact-boundary, sample-size gating against quiet-period false
> positives, retry-then-fail, malformed/GraphQL-error responses) — full
> suite 1,414 tests / 135 files green, no regressions. **Known limitation:**
> measures Workers runtime exceptions / exceeded CPU-or-memory, not
> deliberately-returned 5xx from the app's own try/catch paths — full
> HTTP-status parity needs the zone-level `httpRequestsAdaptiveGroups`
> dataset + a real zone tag (not wired; future work if the owner wants full
> parity). **Not yet live-verified:** this is code + test evidence only —
> the first scheduled run against real production traffic, and confirmation
> that `CLOUDFLARE_API_TOKEN` carries Account `Analytics:Read`, are both
> still-outstanding, owner-observable evidence.
> **Edition 9 (CI-2 schema drift, same day):** Shipped the second CIP item:
> nightly D1 schema-drift detection, the exact class behind IR-1/RC-B1 (a
> column renamed in production without the committed reference following, or
> vice versa — invisible to a green test suite because the lab schema
> silently disagreed with production). `scripts/d1-schema-diff.mjs` parses
> live CREATE TABLE statements (via `wrangler d1 execute --json`) and the
> committed `workers/schema_bootstrap.sql`, diffing table existence and
> column-name sets. `.github/workflows/d1-schema-drift.yml` runs it nightly
> at 03:40 UTC, filing/refreshing a pinned issue on real drift. 19 unit tests
> (`workers/test/d1SchemaDiff.test.mjs`) include the RC-B1 scenario itself
> and a parse-correctness check against the real 227-table
> `schema_bootstrap.sql` — every table parses with a non-empty column set,
> spot-verified by hand against 3 tables. Full suite 136 files / 1,433 tests
> green. **Not yet live-verified:** same caveat as Edition 8 — first
> scheduled run against the real production database is still-outstanding,
> owner-observable evidence.
> **Edition 10 (commercial-readiness continuation, same day):** re-walked the
> live customer journey directly (a full internal-link crawl of all 78 public
> pages against production) rather than assuming prior editions' findings
> still hold. Found 20 unique dead destination paths (38 link instances
> across 22 pages) — most were the right word/slug but the wrong exact path.
> The two highest-impact clusters: the footer "Privacy"/"Terms" links (a
> security vendor's own legal/trust pages) 404'd on five public pages plus
> both MSSP-onboarding consent checkboxes, and "Dashboard"/upgrade CTAs
> 404'd on six pages. Also fixed: the footer "📡 API Docs" link (7 pages,
> `/api` 404s because the Worker's Cloudflare route `cyberdudebivash.in/api/*`
> only matches paths with a trailing slash), "Sign in" (soc-agents.html, 2
> places), "Go to MSSP Dashboard" (mssp-onboarding.html, 2 places), and four
> `sitemap.html` entries. Repointed all 38 instances to real, verified-working
> pages. **Left unfixed, explicitly not guessed:** 6 further `sitemap.html`
> entries and 1 more elsewhere reference pages that do not exist anywhere in
> `frontend/` under any name this audit could find — recorded as an open gap
> rather than repointed to a guess. Regression-locked
> (`workers/test/deadInternalLinks.test.mjs`, 15 tests); full suite
> 1,470/1,470 green, SEO structure lock 22/22 green. Full record:
> `CUSTOMER_OBJECTION_REGISTER.md` OBJ-13. Everything else this edition
> re-confirmed rather than changed: a fresh CEAP sweep run (15/15 green)
> verified IR-3's scan-token fix and the full paying-customer lifecycle are
> live and healthy on commit `6c24abb`. **Deployed and live-verified same
> day:** merged to `main` (`3c099d8`, PR #64), CI green end-to-end
> (unit/E2E/Lighthouse/accessibility/bundle-size/security), `deploy.yml` run
> `28813011718` completed successfully at 18:12 UTC. Live re-check confirms
> `/api/version` reports `3c099d8`, all nine real destination pages return
> 200, spot-checked source pages serve the corrected hrefs, and a second
> fresh CEAP sweep is 15/15 green on `3c099d8`. The four GA gates remain
> owner-action and unchanged.
>
> **Edition 11 (customer-journey functional sweep, same day):** extended the
> audit from "does the link resolve" to "does the feature actually do what
> it claims" — functionally drove Trust Center, Contact, and Book-a-Demo
> rather than just checking they load. Found the two most severe defects of
> this program to date: **both the Contact form and the Book-a-Demo form
> had been failing on every single submission**, wired to
> `/api/leads/capture` (a different feature — a pre-scan-results email gate)
> instead of the purpose-built endpoints already routed and waiting
> (`/api/enterprise/inquire`; `/api/sales/leads` + `/api/sales/demo/book`).
> The contact form's bug was worse than the booking form's: it showed a
> fake "✅ Message Sent!" confirmation with a ticket number on every
> failure (`fetch()` doesn't throw on 4xx/5xx), so customers believed their
> inquiry went through while it was silently lost; the booking form at
> least told the truth (100% honest "Submission failed"), just with no
> working path forward. Both now reach the real backend, and the contact
> form's success claim is gated on an actual confirmed response. Separately,
> found the Trust Center's own live API (`/api/trust-center`) asserting a
> trust signal — "All AI processing via Anthropic API" — that directly
> contradicted its own subprocessors list three lines below (Groq primary)
> and `wrangler.toml`'s explicit no-Anthropic-dependency note, plus two
> dead reference URLs (`policies_url`, `security_url`). Fixed all three;
> flagged one further inconsistency (data residency: the page says
> "India-region preference," the API says "Singapore primary") as needing
> owner confirmation of the actual Cloudflare region config rather than
> guessing which is correct. Regression-locked
> (`workers/test/truthClaims.test.mjs`, 14 new tests); full suite
> 1,481/1,481 green, SEO structure lock 22/22 green. Full record:
> `CUSTOMER_OBJECTION_REGISTER.md` OBJ-14, OBJ-15. **Deployed and
> live-verified same day:** merged to `main` (`3bd891f`, PR #65), CI green
> end-to-end, `deploy.yml` run `28814844058` completed successfully.
> Live re-check confirms `/api/version` reports `3bd891f`; `/contact` and
> `/booking` serve the corrected `fetch()` calls in their live HTML;
> `/api/enterprise/inquire`, `/api/sales/leads`, and `/api/sales/demo/book`
> all confirmed reachable (safe validation-path requests, no test data
> written); `/api/trust-center` serves the corrected `trust_signals`,
> `policies_url`, and `security_url`; a second fresh CEAP sweep is 15/15
> green on `3bd891f`.
>
> **Edition 12 (Enterprise Operations & Continuous Improvement cycle,
> 2026-07-09):** CORB review under the standing CEAP+CIP+CORB+CAB+Product
> Council system (`docs/ENGINEERING_STANDARDS.md` §12–13) — no new
> governance framework invented. Re-verified live rather than assumed:
> production healthy on build `38e9225` (`/api/health` all components `ok`,
> `/api/version` matches `main` HEAD, checked directly against
> `cyberdudebivash.in`, not just via CI proxy); 0 open PRs, 0 open issues, 0
> abandoned branches, 0 dependency vulnerabilities. **Closed two
> long-standing "code shipped, live-verification pending" gaps with real
> evidence:** CI-1 (error-rate alerting) has run clean 35 times on schedule
> with its real check step confirmed executing, not silently skipped; CI-2
> (schema-drift detection) already caught genuine drift on its first live
> run and the fix held — logged as IR-4 (`OPERATIONAL_EXCELLENCE_REPORT.md`
> §4). **New gap found and closed same cycle:** no CodeQL static-analysis
> workflow and no Dependabot configuration existed anywhere in the repo
> (verified by direct inspection of all 14 existing workflow files, not
> assumed) — both added, scoped to the Workers JS backend, the root Python
> services, the Dockerfile, and the Actions themselves. One non-incident
> closed out: an External Uptime Probe run showing top-level `failure`
> was, at job level, a clean `cancelled` run (concurrency guard superseding
> an overlapping scheduled trigger) — confirmed via zero corresponding
> outage issues filed and zero open issues repository-wide, not assumed
> benign. Full evidence and release-scorecard mapping: the Enterprise
> Release Readiness Board verdict compiled the same cycle. Governance
> instruments this edition updates: this scorecard (Action Queue below),
> `OPERATIONAL_EXCELLENCE_REPORT.md` (IR-4, CI-1/CI-2 closure),
> `KPI_DASHBOARD.md` (MTTD, documentation-accuracy rows).
>
> **Governance:** every action in the queue below must pass the Product
> Council gate (`docs/ENGINEERING_STANDARDS.md` §7), and every capability is now
> judged by the §8 Customer Adoption Rule via the Customer Objection Register.

## Summary

| # | Dimension | State | Trend | One-line basis |
|---|-----------|-------|-------|----------------|
| 1 | Product Quality | **GOOD** | ▲ | 1,300 tests/126 files green; Phase VIII fixed 3 customer-visible scale defects (scan→report 422, pricing drift, entitlement display) |
| 2 | Security | **GOOD** | ▲ | Phase IV/V security blockers closed; gitleaks + security-headers CI + CodeQL SAST (added 2026-07-09, JS/TS + Python) + Dependabot; no SOC 2 attestation (organizational) |
| 3 | Reliability | **GOOD** | ▲ | 30+ consecutive green deploys; external probe live; restore drill first run green 2026-07-06 (R-06 closed); CI-1/CI-2 detection loops both live-verified 2026-07-09, CI-2 already proved itself on a real incident (IR-4) |
| 4 | Performance | **GOOD (directional)** | ▬ | p50 44ms/p99 131ms local; bundle 1.32MB vs 2.5MB gate; no production APM yet |
| 5 | Scalability | **GOOD (directional)** | ▲ | 100 orgs / 10 archetypes onboarded cleanly (0 errors); tenant isolation held; sustained-load throttling graceful by-design. Still unproven against real production concurrency |
| 6 | Maintainability | **ADEQUATE** | ▲ | Standards doc + envelope for new code; 71% of legacy routes still unwrapped (accepted, migrating opportunistically) |
| 7 | AI Quality | **GOOD** | ▬ | Grounded, source-attributed intel; honest-uncertainty posture regression-locked; no automated eval harness yet |
| 8 | Customer Satisfaction | **UNKNOWN (real) / measured (simulated)** | ▬ | Zero *real* customer feedback still; but the 100-customer simulation now yields a structured Customer Objection Register (`CUSTOMER_OBJECTION_REGISTER.md`) — 6 objections, 5 resolved, 1 owner-open |
| 9 | Documentation | **GOOD** | ▲ | Contract/architecture docs rewritten from verified v40; index enforces one-canonical-doc rule |
| 10 | Operational Readiness | **GOOD** | ▲ | Runbooks + backups + probe + drill automation; single-operator on-call remains the top risk (R-10) |
| 11 | Commercial Readiness | **PILOT** | ▬ | ₹0 revenue, 0 paying customers; 4 owner-action gates to GA unchanged |

---

## 1. Product Quality — GOOD ▲

- **Evidence:** Full suite 1,271 tests / 122 files passing (2026-07-04, this
  cycle; +4 threat-level locks over the Phase V baseline of 1,267/121). The
  owner-captured live dashboard (2026-07-04 12:50 UTC) confirms the Phase V
  honesty fixes are serving in production: hero copy reads "Results in
  ~2 minutes" / "~2 min Typical Scan Time" (was "<30s").
- **Found & fixed this cycle:** the homepage displayed **three contradictory
  global threat levels simultaneously** (top bar MODERATE from the API,
  command-center header hardcoded HIGH, SOC rail CRITICAL recomputed from 8
  visible feed items). Unified on the server's `platform_threat_level` with
  a single writer and honest "—" placeholders; locked by
  `workers/test/threatLevelSingleSource.test.mjs`. On branch, pending release.
- **Known risks:** candidate metric contradictions observed in the same live
  capture, not yet code-verified (see Action Queue): defense-product counts
  ("3,628 AI-generated tools" vs "Products Generated 70"), daily-scan drift
  ("11 scans today" vs "+12 today"), KEV summary ("0 critical, 0 KEV
  exploited") contradicting the 8 CRITICAL/KEV items rendered beside it,
  MYTHOS GOD MODE header "v4.0" vs source label "v5.0".
- **Recommended action:** verify each candidate against code, fix the ones
  that are real single-truth violations (same class as the threat level).
- **Found & fixed this cycle (2026-07-06, Edition 10):** a full internal-link
  crawl of every public page found 20 unique dead destination paths (38 link
  instances, 22 pages) — most prominently the footer Privacy/Terms links (5
  pages) and Dashboard upgrade CTAs (6 pages) — see OBJ-13. Repointed all 38
  to real, working pages; 7 further references to pages that don't exist
  anywhere in the codebase were left unfixed rather than guessed. Locked by
  `workers/test/deadInternalLinks.test.mjs` (15 tests). Merged, deployed, and
  live-verified same day (commit `3c099d8`, `deploy.yml` run `28813011718`).

## 2. Security — GOOD ▲

- **Evidence:** Phase IV/V closures live in production: per-minute rate
  limits enforced on both metered intel paths, auth-gated private reports,
  CSV-injection and key-usage BOLA fixes (RB-1/RB-2). CI: gitleaks, security
  headers, bundle gate. `docs/SECURITY_QUESTIONNAIRE_PACK.md` (CAIQ-lite)
  published for procurement.
- **Known risks:** no SOC 2/ISO attestation (organizational, blocks regulated
  segments — owner action). The homepage's scrolling badge strip includes
  "SOC 2 Type II" among framework badges; elsewhere the page says
  "SOC 2 Ready Architecture" (honest). **Whether the badge strip reads as a
  certification claim needs review** — if it does, it is a truth-to-customer
  defect of the exact class this program exists to catch.
- **Recommended action:** audit the badge strip's context/labeling in code;
  if it implies attestation, reword to "aligned/ready" phrasing.

## 3. Reliability — GOOD ▲

- **Evidence:** deploy pipeline 30 consecutive green through #617; nightly
  D1 backups 2/2 successful (SHA-256 integrity-gated, 90-day retention);
  external uptime probe run #1 green (2026-07-04 11:57 UTC, from GitHub's
  vantage point outside the platform's failure domain); production smoke
  validated deployed version == pushed commit.
- **Known risks:** (a) **Probe cadence** — the workflow requests `*/15` cron
  but GitHub's scheduler is best-effort: one firing in the first ~2 hours.
  Effective outage-detection latency is currently unknown and likely far
  coarser than 15 min. (b) **Restore drill unproven** — automated
  (`d1-restore-drill.yml`), but the first run is Monday 05:00 UTC; manual
  dispatch from this session was denied (GitHub App lacks `actions: write`,
  403). R-06 stays open until that run is green. (c) Uptime numbers shown on
  the site ("99.7%") are platform-self-reported; no independent SLA
  measurement exists yet.
- **Recommended actions:** observe probe firing density over 48h; if
  effectively ~hourly, add the Cloudflare Healthcheck (owner, ~10 min) as the
  precise vantage point and treat the GitHub probe as the backstop. Watch
  Monday's drill; a red run is S1 per `DISASTER_RECOVERY_RUNBOOK.md` §3.0.

## 4. Performance — GOOD (directional) ▬

- **Evidence:** local runtime under 20-way burst: /api/health 100/100,
  p50 44ms / p99 131ms (directional, not production). Worker bundle 1.32MB
  gzip = 53% of the 2.5MB CI gate, 44% of Cloudflare's hard cap. Lighthouse
  job green in the quality gate.
- **Known risks:** no production APM/latency telemetry; live p99 under real
  traffic is unmeasured. AI-path latency (scan ~90s measured Phase II) is
  honest in copy but not continuously tracked.
- **Recommended action:** none urgent at current load (Product Council Q1:
  no verified customer problem). Revisit when traffic grows or a customer
  reports latency.

## 5. Scalability — ADEQUATE ▬

- **Evidence:** stateless Worker on Cloudflare edge + D1/KV; queue-based
  async scans. Current observed load is small (155 total scans, 1,257
  sessions) — architecture headroom is theoretical, not demonstrated.
- **Known risks:** D1 single-database write path and KV rate-limit counters
  are the first plausible bottlenecks; untested at 100× load.
- **Recommended action:** defer load testing until a customer-driven trigger
  (pilot tenant onboarding, MSSP deal) — fails Product Council Q1 today.

## 6. Maintainability — ADEQUATE ▲

- **Evidence:** `docs/ENGINEERING_STANDARDS.md` governs new code (canonical
  envelope, severity/status/timestamp conventions, §7 Product Council gate);
  regression suite is the executable spec; documentation index enforces
  one-canonical-doc-per-domain.
- **Known risks:** legacy surface — 71% of routes return unwrapped JSON, 8%
  mix styles in one file; `frontend/index.html` is a ~24k-line monolith
  (this cycle's threat-level fix required archaeology across 3 display
  sites). Accepted: migrate opportunistically when touching a handler, per
  the standards doc.
- **Recommended action:** continue opportunistic migration; no big-bang
  refactor (fails Product Council Q2/Q4 — high risk, unproven benefit).

## 7. AI Quality — GOOD ▬

- **Evidence:** intel responses are source-attributed (NVD, CISA KEV, EPSS,
  GitHub advisories, OSV.dev) with pipeline health surfaced in the UI; the
  metrics endpoint returns honest structured 503s with null values rather
  than fabricated numbers (verified Phase IV); honest-uncertainty copy is
  regression-locked. The provable "AI doesn't fabricate security facts"
  posture remains the platform's marketable differentiator.
- **Known risks:** no automated grounding/false-positive eval harness —
  AI-answer quality is verified by episodic audit, not continuous
  measurement. Model routing/fallback behavior lacks production telemetry.
- **Recommended action:** a lightweight grounding eval (sampled AI answers
  scored against their cited sources) is the highest-value AI investment;
  passes Product Council Q1 via the differentiator claim needing ongoing
  evidence. Candidate for a future cycle.

## 8. Customer Satisfaction — UNKNOWN ▬

- **Evidence of honesty, not of satisfaction:** the live site's testimonial
  section says "Early access. Verified customer feedback will appear here" —
  correctly empty. Case studies are labeled "capability demonstrations."
  Zero purchases, zero paying customers → zero verified feedback signals.
- **Known risks:** every feature decision is currently evidence-poor on Q1
  of the Product Council gate; the feedback loop the mission requires has no
  inputs yet.
- **Recommended action (owner):** the fastest path to real signal is the
  existing pilot authorization — one design partner using the platform
  weekly generates more truth than any further internal audit.

## 9. Documentation — GOOD ▲

- **Evidence:** `docs/api-contract.md` and `docs/architecture.md` rewritten
  from verified v40 behavior (Phase V); `PRODUCTION_OPERATIONS_MANUAL.md` is
  the operator entry point; `DOCUMENTATION_INDEX.md` enforces canonical-vs-
  historical separation; runbooks (IR, DR, deploy-recovery) current.
- **Known risks:** doc drift is a permanent hazard; the index's rules only
  work if every change lands in the canonical doc.
- **Recommended action:** each scorecard edition includes a drift spot-check
  of one canonical doc against live behavior.

## 10. Operational Readiness — GOOD ▲

- **Evidence:** nightly backups (2/2 green), weekly restore drill first run
  green (2026-07-06, R-06 closed), 15-min-requested external probe live, deploy pipeline gated with
  post-deploy smoke + version verification, incident/DR runbooks published,
  risk register maintained with owners.
- **Known risks:** **R-10 single-operator on-call (bus factor 1)** is now the
  most material operational risk — all alerting terminates at one person.
  Not fixable by any commit.
- **Recommended action (owner):** name a deputy + escalation path; even a
  non-technical "call the operator" secondary reduces MTTA risk.

## 11. Commercial Readiness — PILOT ▬

- **Evidence:** live funnel (owner capture, 2026-07-04): 1,257 sessions,
  155 scans, 0 purchases, ₹0 revenue, 0 solutions sold. Pricing, GST
  invoicing, Razorpay integration, proposal engine, and affiliate program
  are built; none has processed a real transaction.
- **Found & fixed this cycle (Edition 11):** the Contact and Book-a-Demo
  forms — the two most direct paths from prospect to pipeline — had been
  failing on every submission since at least this audit's ability to
  detect it (wrong backend endpoint; see OBJ-14). Given 1,257 recorded
  sessions and marketing effort driving prospects to these pages, this was
  very likely losing real inbound interest silently for some unknown prior
  period — a customer-acquisition leak with no error visible anywhere
  short of reading the handler code, which is exactly how it went
  undetected. Fixed, regression-locked, merged, deployed (`3bd891f`), and
  live-verified same day: both forms confirmed serving the corrected
  endpoints in production.
- **Known risks:** the four GA gates from the Global Release Decision are
  unchanged and all owner-action: (1) one live payment end-to-end, (2) one
  live SSO IdP round-trip, (3) external SLA measurement + definition
  reconciliation, (4) support escalation path. Regulated segments stay
  blocked pending SOC 2.
- **Recommended action (owner):** gate order matters — one live payment is
  the cheapest and unblocks the most (proves the entire monetization path).

---

## Action Queue (Product Council-gated)

| Priority | Action | Owner | Gate status |
|----------|--------|-------|-------------|
| ✅ Done | CodeQL static analysis + Dependabot version updates — neither existed anywhere in the repo (verified 2026-07-09); added `.github/workflows/codeql.yml` (JS/TS + Python) and `.github/dependabot.yml` (npm, pip, docker, github-actions) | Engineering | Closed 2026-07-09 |
| ✅ Done | CI-1 (error-rate alerting) live-verification — 35 clean scheduled runs, real check step confirmed executing | Engineering | Closed 2026-07-09 — see Edition 12 |
| ✅ Done | CI-2 (schema-drift detection) live-verification — caught real drift on first live run, fix confirmed held, logged as IR-4 | Engineering | Closed 2026-07-09 — see Edition 12 |
| ✅ Done | Threat-level single-source fix — **released, deploy #618 green** | — | Closed 2026-07-04 |
| ✅ Done | "SOC 2 Type II" badge audit — ticker + CISO-hub bar reworded to Aligned/Ready/Mapped; section badges & modals were already honest | — | Closed 2026-07-04, locked by `phase6TruthLocks.test.mjs` |
| ✅ Done | Metric contradiction audit: KEV trend no longer fabricates "0 critical, 0 KEV" for absent fields; products split into "Marketplace Solutions" (defense/stats) vs "generated across MYTHOS runs · N published" (mythos/status); MYTHOS v4.0/12-phase labels aligned to deployed v5.0/16-phase everywhere | — | Closed 2026-07-04, regression-locked |
| ✅ Done | **Found in audit:** customer notifications were fabricated from `/api/seed/threats` (PRNG demo; first 3 events always CRITICAL) — poller now reads the real NVD/KEV feed with per-CVE dedupe; all `/api/seed/*` responses now self-declare `synthetic: true` | — | Closed 2026-07-04 |
| ✅ Done | **Found in audit:** `user-dashboard.html` shipped with a committed tool-download banner BEFORE `<!DOCTYPE html>` (visible to every logged-in customer, forced quirks mode) — stripped; doctype lock added for all key pages | — | Closed 2026-07-04 |
| ✅ Code shipped | CI-1 alerting half — `error-rate-alert.mjs`/`.yml`, 12 unit tests, full suite green | Engineering | Live-verification pending: owner to confirm `CLOUDFLARE_API_TOKEN` Analytics:Read scope; first scheduled run is the closing evidence |
| ✅ Code shipped | CI-2 schema-drift check — `d1-schema-diff.mjs`/`.yml`, 19 unit tests incl. RC-B1 regression + real-file parse check, full suite green | Engineering | Live-verification pending: first scheduled 03:40 UTC run against production is the closing evidence |
| ✅ Done | Monday 05:00 UTC restore drill — first run green 2026-07-06 (run `28779799461`), R-06 closed | Engineering | Closed 2026-07-06 — reliability evidence requirement satisfied |
| ✅ Done | OBJ-13 — 38 dead internal link instances (22 pages: Privacy/Terms, Dashboard, API Docs, Sign in, MSSP Dashboard, sitemap) repointed to real pages, regression-locked | Engineering | Closed 2026-07-06 — merged, deployed (`3c099d8`), all fixed links confirmed 200 live |
| P3 | 7 sitemap/nav entries reference pages that don't exist anywhere in the codebase (`/affiliate-hub`, `/developer-portal`, `/enterprise/welcome`, `/enterprise/onboarding`, `/enterprise/contacts`, `/mssp-workspace`, `/ai-governance-dashboard.html`) | Product + Engineering | Open — needs a product decision (build the page vs. remove the entry), not a link fix |
| ✅ Done | OBJ-14 — Contact + Book-a-Demo forms repointed from the wrong lead-gate endpoint to the real `/api/enterprise/inquire` and `/api/sales/leads`+`/api/sales/demo/book`; contact form's fake unconditional success confirmation fixed to gate on a real response | Engineering | Closed 2026-07-06 — merged, deployed (`3bd891f`), both forms confirmed live-serving the correct endpoints, all three routes confirmed reachable |
| ✅ Done | OBJ-15 — Trust Center API's false "Anthropic-exclusive" trust signal corrected to match the real Groq-primary provider lineup; `policies_url`/`security_url` repointed to real, reachable pages | Engineering | Closed 2026-07-06 — merged, deployed (`3bd891f`), `/api/trust-center` confirmed serving the corrected fields live |
| P3 | OBJ-15 sub-finding: `platform_overview.data_residency` ("Singapore primary") contradicts the Trust Center page's own copy ("India-region preference") | Owner | Open — needs confirmation of the actual Cloudflare D1/KV region configuration; not guessed or code-fixed |
| P2 | Measure probe firing density over 48h; add Cloudflare Healthcheck if ~hourly | Owner + Eng | PASSED — outage-detection latency unknown |
| P3 | Lightweight AI grounding eval harness | Engineering | Q2/Q3 need design before commit |
| P3 | One live payment end-to-end (GA gate 1) | Owner | PASSED — blocks all commercial evidence |
| Deferred | "Scans today" 1-count drift (11 vs 12): three endpoints compute it from the same real counters at different instants (`/api/health`, `/api/intelligence/summary`, `/api/realtime/stats`). Not fabrication — timing skew. Consolidating to one shared helper is a backend refactor; revisit when touching those handlers | Engineering | Q2/Q4 weak — cost outweighs a 1-count cosmetic drift |
| Deferred | Load testing, big-bang envelope migration, new feature work | — | FAILED Q1 (no verified customer problem today) |

## Update protocol

1. Each improvement cycle re-scores every dimension **with evidence**; no
   score moves without a cited observation.
2. New findings enter the Action Queue only through the Product Council
   gate; deferred/rejected work is recorded, not silently dropped.
3. This document supersedes per-phase snapshot reports as the current-state
   view; point-in-time records continue to land in `docs/audit-history/`.
