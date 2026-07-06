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
| Restore drill | **Armed, never yet run** — first schedule fires Monday 05:00 UTC; manual dispatch attempted by this board and denied (integration lacks `workflow_dispatch` permission — owner-only). Restore script itself is regression-tested both directions (`workers/test/restoreDrill.test.mjs`) | ARMED / FIRST RUN PENDING |
| Deploy discipline | 7 consecutive green gated deploys today (#618–#624), each: test gate → deploy → post-deploy smoke; three releases this cycle went through the identical path with zero manual intervention | OPERATING |
| Rollback | Documented (`DEPLOY.md`); mechanism is the same pipeline (fast-forward to a known-good commit) — exercised implicitly by every deploy; no live rollback has been needed post-GA | DOCUMENTED, UNEXERCISED LIVE |
| Detection | External probe (availability) + post-deploy smoke (deploy sanity) + **CEAP synthetic customer sweep every 6 h** (`ceap-assurance.yml` running `scripts/ceap-sweep.mjs`: 13 lifecycle checks incl. the exact IR-1/IR-2 journeys; a FAIL = production incident). Error-rate alerting/APM still absent — CEAP catches journey breakage within 6 h, not error spikes between sweeps | PARTIALLY CLOSED (journey half); CI-1 (alerting half) remains |

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
| IR-1 (RC-B1) | Org dashboard + org scans 500 for every org customer | From feature ship until Phase IX (same day found→fixed→deployed→verified) | **Customer-first** (RC program journey) — not monitoring | Root-caused (schema-drift lab masking), fixed, production-faithful-schema lock, verified live | Production-first validation is now standard (§9 lifecycle); prod-schema CI diff on backlog (CI-2) |
| IR-2 (GA-B1) | No credential recovery — any forgotten password = permanent lockout | Since launch until Phase X (found→built→deployed→verified same day) | **Board audit** — not a customer report (zero real customers yet) | Full flow built, 6-test lock, live verification | Lifecycle-completeness review added to GA checklist; support playbook updated |

Common thread: both were **detection failures** before they were code
failures — nothing in monitoring would have caught either. That is why CI-1
(error-rate alerting) leads the improvement backlog.

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
| CI-1 | Error-rate alerting on 5xx spikes (Workers analytics/logpush) | Both production incidents were customer-first detections. **Partially addressed (CEAP cycle 1):** the 6-hourly synthetic customer sweep now auto-detects journey regressions (would have caught IR-1); error-*rate* alerting between sweeps still open | **P1 (remaining half)** |
| CI-2 | Nightly prod-schema export → CI diff vs `schema_bootstrap.sql` | Would have caught RC-B1 class before ship | P2 |
| CI-3 | First restore drill (Monday's scheduled run) — then weekly cadence review | Backup trust requires restore proof | P2 (automatic) |
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
step before money moves. The two structural weaknesses are unchanged and
honestly held: **detection depends on customers/audits rather than
alerting** (CI-1), and **the support organization is one person** (GA-O3).
Both are visible on the GA Blocker Board with owners. Until the first paying
customer arrives, the highest-value operational act remains GA-O1: one real
payment through the now-verified order flow.
