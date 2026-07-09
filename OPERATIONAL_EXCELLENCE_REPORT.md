# Post-GA Operational Excellence Report

> **Enterprise Operations Board instrument.** First post-GA operations cycle,
> run under the permanent lifecycle (`docs/ENGINEERING_STANDARDS.md` §9).
> The question examined is no longer "does the software work?" but **"can the
> organization consistently deliver value, maintain customer trust, and
> operate the platform over time?"** Every claim traces to a live-production
> request, a pipeline run, or a named test lock.
>
> **Production build:** `34cd6c5` · **Date:** 2026-07-04 ·
> **Suite baseline:** 1,311 tests / 128 files green (unchanged — no code
> shipped this cycle; this is an operations audit)
>
> **Cycle 2 (2026-07-09) — CORB review under the CYBERDUDEBIVASH Enterprise
> Operations & Continuous Improvement Program.** No new customer-facing
> defect. Findings and actions this cycle: (1) **IR-4 logged** — CI-2's first
> live run caught real D1 schema drift and the fix held, see §4; (2) **CI-1
> and CI-2 both moved from "code shipped, live-verification pending" to
> closed**, with real evidence (§7); (3) **new gap found and closed same
> cycle:** no CodeQL static-analysis workflow and no Dependabot configuration
> existed anywhere in the repository — both added (`.github/workflows/codeql.yml`,
> `.github/dependabot.yml`), scoped to the two real source trees (Workers
> JS backend, root Python services) plus the Docker and GitHub Actions
> ecosystems; (4) production re-verified live and healthy on build `38e9225`
> (`/api/health` all components `ok`, `/api/version` matches `main` HEAD);
> zero open PRs, zero open issues, zero dependency vulnerabilities
> (`npm audit`, workers/). Full evidence and release-scorecard mapping:
> the Enterprise Release Readiness Board verdict compiled the same cycle.

---

## 1. Post-GA lifecycle reliability (live production, one consolidated pass)

Executed as a single continuous customer lifecycle with a throwaway account,
end to end in **15.7 s**, all steps green on the GA build:

| Lifecycle step | Result | Latency | Note |
|----------------|--------|---------|------|
| Signup (incl. auto key issue) | 201 | 2.3 s | |
| Entitlement display | 200 | 0.3 s | `reports=true`, `ai=true` — truthful |
| First scan (cold, live DNS) | 200 | 4.2 s | **TTFV 6.9 s from first request** |
| Usage visibility | 200 | 1.0 s | history row present; per-key counter semantics verified (§3) |
| Report generation | 201 | 0.4 s | |
| AI analysis | 200 | 0.7 s | confidence 94, grounded in own scan |
| Org create + dashboard | 200 | 1.4 s | aggregates reflect the scan |
| Subscription upgrade path | 200 | 1.3 s | **live Razorpay order created** (§5) |
| API key rotation | 201 | 0.9 s | replacement shown once |
| Credential recovery request | 200 | 0.8 s | enumeration-safe generic |
| Offboarding: delete → lockout | 200/401 | 2.4 s | erasure + immediate credential death |

Honest metric note: the Phase VIII "TTFV p50 406 ms" was measured against a
warm-cache lab; the **live cold-scan TTFV is ~7 s** (dominated by real DNS
work). Both are true; the live number is what a first-time customer feels,
and it is still an excellent first-session experience.

## 2. Production operations machinery (verified, not assumed)

| Process | Evidence | State |
|---------|----------|-------|
| Nightly backups | `d1-backup.yml` scheduled runs Jul 3 + Jul 4, both **success** | OPERATING |
| External uptime probe | `external-uptime-probe.yml` 5 scheduled runs, latest **success** (17:18 UTC today) | OPERATING |
| Restore drill | **First scheduled run green 2026-07-06 08:56 UTC** (run `28779799461`: located latest real nightly backup → downloaded → restored → integrity-checked, all 7 steps passed in 26s). Restore script itself is regression-tested both directions (`workers/test/restoreDrill.test.mjs`) | OPERATING (R-06 closed) |
| Deploy discipline | 7 consecutive green gated deploys today (#618–#624), each: test gate → deploy → post-deploy smoke; three releases this cycle went through the identical path with zero manual intervention | OPERATING |
| Rollback | Documented (`DEPLOY.md`); mechanism is the same pipeline (fast-forward to a known-good commit) — exercised implicitly by every deploy; no live rollback has been needed post-GA | DOCUMENTED, UNEXERCISED LIVE |
| Detection | External probe (availability) + post-deploy smoke (deploy sanity) + **CEAP synthetic customer sweep every 6 h** (`ceap-assurance.yml` running `scripts/ceap-sweep.mjs`: 13 lifecycle checks incl. the exact IR-1/IR-2 journeys; a FAIL = production incident) + **Workers error-rate alert every 15 min** (`error-rate-alert.yml`, code shipped + unit-tested this cycle, CI-1) — CEAP catches journey breakage within 6 h, the new alert targets runtime-error spikes between sweeps but has no live-traffic run yet | JOURNEY HALF OPERATING; ALERTING HALF (CI-1) CODE SHIPPED + TESTED, LIVE-VERIFICATION PENDING |

## 3. Support documentation accuracy audit

Each `SUPPORT_PLAYBOOK.md` diagnostic claim was re-executed against live
production this cycle:

| Playbook claim | Live result | Verdict |
|----------------|-------------|---------|
| Wrong password → 401; deleted account → 401 | 401 / 401 | ACCURATE |
| Invalid API key → 401; FREE key on `/api/v1` → 403 | verified prior cycles, unchanged build | ACCURATE (standing) |
| 429 carries `reason`, `retry_after`, `upgrade_url` | `burst_exceeded`, 60, present | ACCURATE |
| 429 carries `Retry-After` + `X-RateLimit-*` **headers** | **not present on the burst path** (body carries the data) | CORRECTED — playbook now says body-first, headers on daily-quota path only |
| Forgot-password: generic response, 3/hour limit | 200 generic (byte-identical known/unknown at release gate) | ACCURATE |
| Unmeasurable scan → `grade null / UNKNOWN` | standing lock + prior live verification | ACCURATE |
| Reset link email delivery | **unverifiable until `RESEND_API_KEY` owner action (GA-O5)** | HONESTLY CAVEATED in playbook |
| *(new)* per-key usage counts only key-authenticated calls | key-authed scan → `today.total=1`; session-token scan → counted in `/api/history`, not the key | ADDED to playbook this cycle |

## 4. Incident Review Register (post-incident reviews of production-found defects)

| ID | Incident | Customer impact window | Detection | Resolution | Lesson enforced |
|----|----------|------------------------|-----------|------------|-----------------|
| IR-1 (RC-B1) | Org dashboard + org scans 500 for every org customer | From feature ship until Phase IX (same day found→fixed→deployed→verified) | **Customer-first** (RC program journey) — not monitoring | Root-caused (schema-drift lab masking), fixed, production-faithful-schema lock, verified live | Production-first validation is now standard (§9 lifecycle); prod-schema CI diff (CI-2) shipped + unit-tested this cycle, nightly at 03:40 UTC — first live run still pending |
| IR-2 (GA-B1) | No credential recovery — any forgotten password = permanent lockout | Since launch until Phase X (found→built→deployed→verified same day) | **Board audit** — not a customer report (zero real customers yet) | Full flow built, 6-test lock, live verification | Lifecycle-completeness review added to GA checklist; support playbook updated |
| IR-3 | Every logged-in browser domain scan 403'd `token_already_used_or_expired` on **first use** — the free conversion funnel broken for JWT users (API-key callers unaffected by design) | Deploy of the scan-token enforcement (`b493d871`, 16:57 UTC 2026-07-06) until same-day fix | **CEAP synthetic sweep — first monitoring-first detection** (flagged ~11 min after the regressing deploy; no customer report needed) | Root cause: the single-use burn demanded read-your-write consistency from **eventually-consistent Workers KV** — verify's `kv.get` couldn't yet see issue's unawaited `kv.put`, so valid first-use tokens were rejected as replays. The perfectly-consistent KV mock in tests masked it (IR-1's lab-masking class, KV edition). Fix: missing record fails **open** (HMAC proves issuance; TTL + IP bind it) and verify writes the replay tombstone itself with full-window TTL; only a visible `used` tombstone rejects. Locked by 2 eventual-consistency tests in `scanTokenEngine.test.mjs`; sweep now exercises both real contracts (JWT+token handshake, `x-api-key` exempt) | Distributed-state rule: any control that round-trips KV must be tested with a **non-read-your-write** mock; CEAP sweep steps must follow the real customer contract, so contract changes break the sweep loudly at the next 6-h run |
| IR-4 | Live D1 schema drifted from `workers/schema_bootstrap.sql` on 9 tables (all `onlyInReference` — the reference documented columns production didn't have) | 2026-07-07T14:12Z (first detected) until 2026-07-08T08:56Z (owner-confirmed closed) | **CI-2 (nightly schema-drift check) — first live run, first real finding, monitoring-first detection** (GitHub issue #77, auto-filed and auto-refreshed while drift persisted) | Two-part root cause: (1) `discount_coupons`/`coupon_redemptions` are self-bootstrapped at runtime by `workers/src/lib/coupons.js` but were never added to the tracked reference — fixed in `#94`; (2) production's live tables were still on the old column set because `ensureCouponTables()`'s `ALTER TABLE` migration only runs lazily when coupon code actually executes, and no real request had hit that path since the v2 coupon system shipped — fixed by sending one safe, order-free request with a deliberately-invalid coupon code to trigger the migration. Confirmed clean: run `28930314111`, 242/242 tables match | **This is CI-2's investment thesis validated**: unlike IR-1/IR-2/IR-3, this incident was caught by the monitoring built specifically to catch it, before any customer-facing symptom existed. Closes the "first live run still pending" caveat on CI-1/CI-2 below. Lazily-triggered `ALTER TABLE` migrations tied to a rarely-hit code path are now a known drift source — worth a grep for other `ensureXTables()`-style lazy migrations if one is found elsewhere |
| IR-5 | Automated Razorpay Checkout (order → SDK → pay → verify → instant activation) — a complete, tested, production-grade implementation — silently failed on **every single attempt** on every self-serve pricing page, always falling back to the manual 2–4h payment path | Unknown start (at least since `frontend/_headers`' "P0 FIX" comment claiming Razorpay CSP coverage, unverified since) until 2026-07-09 (found→root-caused→fixed same session) | **Owner-supplied screenshots of the live manual-payment modal** — not monitoring; no automated check exercises a real checkout click-through against live production | Root cause: `frontend/_headers`' enforced CSP allowlisted Razorpay in `connect-src`/`frame-src`/`form-action` but never in `script-src` — the one directive gating `<script src="https://checkout.razorpay.com/v1/checkout.js">` itself. The browser silently blocked the SDK; the well-designed frontend correctly caught that failure and fell back to manual payment, exactly as coded — it just never reached the automated path it was built for. Fixed: one domain added to `script-src` (both enforced and report-only CSP). Reproduced directly in headless Chromium (failure reason `csp` before, zero CSP violations after) before trusting the fix. Full audit, fix, and verification: `docs/audit-history/` (session artifact) | This is very likely a real, material commercial finding, not just a UX bug: the KPI Dashboard and Operational Excellence Report have both stood for days recording **₹0 settled revenue despite a "verified" checkout** — this incident is the leading candidate explanation for why. No conversion-funnel monitoring previously existed that could have caught a payment SDK silently failing 100% of the time; a scheduled synthetic check that actually attempts the Razorpay SDK load (not just the order-creation API) is the natural next CIP item, matching CI-1/CI-2's pattern of turning a customer-first detection into a monitoring-first one |

Common thread across IR-1–IR-3: all three were **detection failures** before
they were code failures. IR-4 is the first counter-example — CI-2 (shipped
in direct response to that pattern) caught real drift on its first live run,
before a customer could. That is why CI-1 (error-rate alerting) remaining
un-spike-tested stays the next open item, not a new backlog entry.

## 5. Business & commercial operations

- **Payment rail is live-wired:** the upgrade journey produces a real
  Razorpay **live-mode** order (`order_T9W1y7c7…`, ₹1,499.00, `rzp_live_` key)
  directly from the customer checkout call. The remaining gap to commercial
  GA is exactly one owner action: complete one real payment and verify the
  webhook→tier-grant path with money moving (GA-O1). Order creation is now
  **verified**; settlement is not.
- **Pricing consistency:** plans page, entitlements, and enforced limits
  re-verified in the lifecycle pass — no drift since the Phase VIII single
  source of truth.
- **Support commitments:** the playbook promises no response-time SLA it
  cannot keep (single-operator constraint disclosed — GA-O3). No
  customer-facing statement was found this cycle that exceeds verified
  behavior.

## 6. Customer success & voice of customer

- **Objection Register trend (Edition 3):** 8 objections lifetime — 6
  RESOLVED with locks, 1 ACCEPTED boundary (OBJ-06), 1 OPEN owner (OBJ-05).
  **Zero new objections** surfaced by this cycle's lifecycle pass — the first
  full pass through all instruments with no new product defect found.
- **Recurring friction is now exclusively organizational:** every open item
  (payment, SSO round-trip, support depth, attestations, email delivery) is
  owner-action; none is code-closable. This is the correct post-GA shape.
- **Renewal readiness:** unprovable until a real customer exists; the
  measurable proxies (workflow reliability, honest limits, TTFV) are green.

## 7. Continuous Improvement Backlog (prioritized by observed customer impact)

| ID | Item | Why | Priority |
|----|------|-----|----------|
| CI-1 | Error-rate alerting on 5xx spikes (Workers analytics/logpush) | Both production incidents were customer-first detections. **Code shipped:** `scripts/error-rate-alert.mjs` + `.github/workflows/error-rate-alert.yml` poll Cloudflare's GraphQL Analytics API every 15 min for the Workers runtime error rate between the 6-hourly CEAP sweeps, and file/refresh a pinned incident issue on a real spike. Unit-tested (12 tests), full suite green at ship. **Live-verified 2026-07-09:** 35 scheduled runs since ship, all green at an observed ~3 h actual cadence (GitHub's cron is coarser than the requested 15 min); job-level inspection of the latest run confirms the real check step executes and correctly *skips* the alert-filing step (no spike found) rather than silently no-op'ing — proves the `CLOUDFLARE_API_TOKEN` Analytics scope is live and working. **Known limitation (unchanged):** measures Workers runtime exceptions / exceeded CPU-or-memory, not deliberately-returned 5xx JSON from the app's own try/catch paths — zone-level HTTP-status parity still needs `httpRequestsAdaptiveGroups` + a real zone tag, not yet wired. **Residual gap:** only the "no spike" path has fired for real; the alert-filing path itself has not yet been proven against a genuine spike | **Closed (live-verified) — zone-level HTTP-status parity carried as P3** |
| CI-2 | Nightly prod-schema export → CI diff vs `schema_bootstrap.sql` | Would have caught RC-B1 class before ship | **Code shipped:** `scripts/d1-schema-diff.mjs` + `.github/workflows/d1-schema-drift.yml` export the live D1 schema nightly and diff against `workers/schema_bootstrap.sql`. 19 unit tests, full suite green at ship. **Live-verified 2026-07-09 — and it already caught a real incident:** see IR-4. First live run (2026-07-07) found genuine drift on 9 tables, auto-filed GitHub issue #77, correctly kept refreshing while drift persisted across 5 more runs, and the owner-confirmed fix (`#94` + one triggering request) produced a clean 242/242-table run; the first genuinely-automatic nightly cron run after that (2026-07-09T07:03Z) stayed clean | **Closed (live-verified; validated by a real catch)** |
| CI-3 | ~~First restore drill~~ **Done 2026-07-06** (run `28779799461`, all green) — weekly cadence now the standing review | Backup trust requires restore proof | Closed; weekly monitoring continues automatically |
| CI-4 | `X-RateLimit-*` headers on burst-path 429s (parity with daily path) | Body is authoritative today; header parity helps API clients | P3 |
| CI-5 | APM/latency percentiles in production | Cold-scan TTFV ~7 s deserves tracking over time | P3 |
| CI-6 | Legacy route envelope migration (carried) | Localized 500 risk on old routes | P3 |

## 7a. CEAP — Continuous Enterprise Assurance (standing cadence)

This report is now maintained under CEAP: the representative customer
lifecycle re-executes against live production **every 6 hours** via
`scripts/ceap-sweep.mjs` (committed, dependency-free, reproducible by anyone:
`node scripts/ceap-sweep.mjs`). Cycle-1 evidence: **13/13 green** on build
`534bf14` (~12 s, throwaway account created and deleted; enumeration safety,
paid gates, id contracts, and IR-1/IR-2 journeys all asserted, not just
status codes). Any FAIL is treated as a production incident until disproven.
The governing principle is now permanent: `docs/ENGINEERING_STANDARDS.md`
**§10 — every customer-facing statement must remain continuously verifiable
against observed production behavior**.

## 8. Executive Operations Review

The organization operated the platform through a full post-GA cycle with no
new customer-facing defect, three same-day gated releases in the prior
cycles, running backups and probes, accurate support documentation (two
precision fixes made this cycle), and a payment rail verified to the last
step before money moves. Of the two structural weaknesses previously held
open, one moved this cycle: **detection depended on customers/audits rather
than alerting** (CI-1) for both lifetime incidents — a 15-minute Workers
error-rate alert shipped and passed 12 unit tests plus the full 1,414-test
suite this cycle, but has no live-production run yet, so treat detection as
still customer/audit-first until the owner confirms the token's Analytics
scope and a first real run is observed. **The support organization is one
person** (GA-O3), unchanged. Both are visible on the GA Blocker Board with
owners. Until the first paying customer arrives, the highest-value
operational act remains GA-O1: one real payment through the now-verified
order flow.
