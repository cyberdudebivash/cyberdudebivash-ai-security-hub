# Production Release Gate — Phase II: Subscription Integrity & Revenue Protection

**Date:** 2026-07-14 (post-merge verification addendum appended same day)
**Scope:** Full repository validation of the subscription entitlement lifecycle (H5) and subscription plan validation (H8), following Phase I's release-gate validation of PRs #240–#244 (server-side pricing, marketplace GST invoicing, proposal authorization, PayPal validation, uptime logging).
**Status:** PR #245 (H5+H8) and PR #246 (Revenue Intelligence admin gate) are both **merged to `main`** (`d4db0eee`, `04c6dd1d`) and **deployed** (Cloudflare Deploy workflow run `29364632745` succeeded against `04c6dd1d`). Independently re-verified post-merge — see "Post-Merge Verification" addendum at the end of this document.

---

## Executive Summary

**RELEASE GATE: PASS WITH MINOR RISKS.**

Both flagged risks — H5 (subscription tier integrity) and H8 (subscription plan validation) — were **Verified** as real, live defects through full repository trace, not assumed from prior documentation. Both are now fixed, tested, **merged, and deployed to production** (PR #245: 293 files / 3054 tests passing at merge time). A third, unrelated but severe finding (an unauthenticated internal revenue dashboard) was discovered during the same trace and fixed separately in PR #246 — also merged and deployed (293 files / 3063 tests at merge time). Combined on `main` post-merge: 294 files / 3075 tests, independently re-run and confirmed 0 failures.

No scenario was found where a customer using the **live, shipped checkout flow** can pay and fail to receive their purchased subscription tier. The one confirmed "charged, zero entitlement" defect (H5's System B checkout) was on an endpoint confirmed unreachable from any shipped frontend page — real but contained. H8's defect (System A, the live checkout) was reachable by direct API call, even though no legitimate frontend traffic ever triggered it. Both are now closed.

**What keeps this from a clean PASS:** two residual, un-fixed items directly relevant to "does every successful payment result in the correct entitlement" — a real price inconsistency in the tier system this PR blocked (§5 below) and confirmed structural gaps in renewal/cancellation enforcement (§6) that pre-date this work and are explicitly out of scope for a "no new feature work" pass. Neither represents an active "customer paid, got nothing" incident today; both are documented, unimplemented technical debt requiring a product decision, not a code fix.

---

## Priority 1 — H5: Subscription Tier Integrity

### Trace performed

Checkout → Payment → Webhook → Subscription → Tier Mapping → Database Write → Entitlement Grant → Dashboard Access → API Access → Feature Gates, for every tier written by `subscriptionPaywallEngine.js`, `payments.js`, and the Razorpay webhook handler. Renewal and upgrade/downgrade handlers were also traced (§6) — no dedicated "downgrade handler" exists as a distinct code path; upgrade/downgrade both re-run the standard checkout flow.

### Verdict

**Verified, Fixed.** See `SUBSCRIPTION_REGISTRY_2026-07-14.md` §§2–3 for the full per-tier table (Checkout Name / Razorpay Product / Internal SKU / Stored Subscription / Database Tier / Entitlement Tier / Dashboard Tier / Feature Gates) — reproduced in summary here:

| System | Tier | Pre-fix status | Post-fix status |
|---|---|---|---|
| A (live) | STARTER/PRO/ENTERPRISE/MSSP | ✅ Already consistent | ✅ Unaffected |
| A (live) | ENTERPRISE_SOC | ❌ Priced, chargeable, never grantable | ✅ Checkout now rejected |
| B (orphaned) | COMMUNITY | ✅ Free, already rejected | ✅ Unaffected |
| B (orphaned) | PROFESSIONAL/TEAM/BUSINESS | ❌ Charges real money, `users.tier` write either violates schema CHECK constraint or resolves to no `TIER_LIMITS` entry (silent FREE-tier degradation) | ✅ Checkout now rejected (409 `PLAN_NOT_PROVISIONABLE`) |
| B (orphaned) | ENTERPRISE | ⚠️ Grants correctly but charges ₹49,999 vs. ₹4,999 charged for the identically-named plan everywhere else | ⚠️ **Unchanged** — flagged, not fixed (pricing decision, see below) |

### Why every tier value can now (mostly) persist successfully

`users.tier`'s live schema CHECK constraint accepts exactly `FREE/STARTER/PRO/ENTERPRISE/MSSP`. System A's checkout has always written only these values (confirmed consistent). System B's checkout previously wrote its own, incompatible vocabulary — now blocked for the 3 incompatible tiers. The one remaining case where a value can persist "successfully" but at the wrong price (System B's ENTERPRISE) is documented, not silently left as a customer-facing defect — see the Subscription Registry §5 for the two possible resolutions and their trade-offs.

---

## Priority 2 — H8: Subscription Plan Validation

### Trace performed

Every code path that accepts a client-supplied `plan` identifier for a subscription purchase: `payments.js handleCreateOrder` (order creation), `handleVerifyPayment` (verification, including the authoritative-order-lookup fallback path), the Razorpay webhook's two grant branches (tenant/plan-based and payments-row-fallback-based), and `subscriptionPaywallEngine.js handleSubscriptionCheckout` (already safe — invalid plans alias to the free `COMMUNITY` tier and get rejected).

### Verdict

**Verified, Fixed.** Root cause: `handleCreateOrder`'s `SUBSCRIPTION_PRICES[planKey] || SUBSCRIPTION_PRICES['STARTER']` fallback pattern silently coerced any unrecognized plan to STARTER pricing, while the *raw*, uncorrected string was what got persisted as the order's `plan`. That persisted value later failed an exact-match allow-list at the entitlement-grant step (`handleVerifyPayment` and the webhook's fallback grant both check `['STARTER','PRO','ENTERPRISE','MSSP'].includes(plan)`), so the grant block was silently skipped while the payment was still marked `'paid'`.

### Root cause analysis (as requested)

- **Why did unknown plans default to STARTER pricing?** A permissive `||` fallback chain (`body.plan || target || 'STARTER'`) written to avoid ever failing to compute *some* price, rather than fail-closed validation matching the sibling `package` module's pattern (which does reject an unrecognized `product_id`).
- **Why did unrecognized identifiers survive into subscription records?** The stored `payments.plan` (`planLabel`) was computed independently from the price-lookup key — `(body.plan || 'STARTER').toUpperCase()` — using the *raw* client value, not the corrected/fallback price-table key. Two separate, inconsistent computations of what should have been one value.
- **Why did entitlement mapping later fail?** The grant step's allow-list is an intentional, correct security control (added in an earlier pass to prevent arbitrary-tier injection) — it was never the bug. The bug was upstream: nothing prevented an invalid value from ever reaching that check in the first place, after a real charge had already happened.
- **Does this affect renewals/upgrades/downgrades/webhooks/retries?** Renewals/upgrades/downgrades all re-run the same `handleCreateOrder`/`handleVerifyPayment` flow — now uniformly protected by the same fix. The webhook's fallback grant uses the same shared allow-list constant (`GRANTABLE_SUBSCRIPTION_PLANS`) as the fix, so a retry or duplicate webhook delivery is equally protected — and confirmed independently idempotent (dedicated D1 `webhook_events` table keyed on Razorpay's event id, with a secondary re-check on `payments.status` before writing).

### Implementation

The authoritative product catalog (`SUBSCRIPTION_PRICES`, narrowed to the actually-grantable subset `GRANTABLE_SUBSCRIPTION_PLANS`) now validates the plan **before order creation** — unknown/unfulfillable plans are rejected with 400 before any Razorpay order, before any invoice, before any subscription record. No silent coercion.

---

## End-to-End Validation (all four customer journeys, current production baseline)

| Journey | Validated | Result |
|---|---|---|
| **Monthly subscription** (landing → pricing → checkout → payment → webhook → subscription → invoice → entitlements → dashboard → renewal → cancellation) | Yes (direct trace + Phase I agent research) | Checkout→entitlement chain now sound for System A (all 4 tiers) and System B (1 of 4, by design — see H5). Webhook idempotency Verified solid (D1-keyed dedup + secondary status re-check). **Renewal**: confirmed no automated recharge exists — reminder emails only; not a defect, a missing feature, out of scope. **Cancellation**: grace period correctly implemented; period-end downgrade enforcement confirmed absent — documented in the Subscription Registry, not implemented (feature gap, not this pass's scope). |
| **Marketplace purchase** (product → checkout → payment → GST invoice → download → history) | Yes (Phase I agent research) | Sound end to end. `download`/`my-purchases` correctly scoped and delivering (real API keys, real live-generated reports, honest `manual_pending` where no automation exists). One test-coverage gap noted (no positive isolation test for `my-purchases`, no router-shadowing regression test for `download`) — recommended, not implemented (test-only, no production behavior change needed). |
| **Enterprise purchase** (request → proposal → approval → payment → provisioning) | Yes (Phase I agent research) | No access is ever granted without a real, separately-verified Razorpay/PayPal payment — confirmed by absence: `triggerPostPurchase` (called on proposal-accept) never touches `users.tier`/`subscriptions`/`api_keys`. Real tier grants only ever happen through the standard self-serve verify path. One unrelated revenue-integrity bug found (`proposal.price_inr` always `undefined` → `amount_inr:0` on every proposal lifecycle event, suppressing affiliate-commission crediting for enterprise deals) — **not fixed this pass** (separate root cause from H5/H8; recommended as its own future PR). |
| **API subscription** (purchase → API key → rate limits → dashboard → usage tracking) | Yes (Phase I agent research) | Key issuance and per-tier key-count limits sound and tested. **Confirmed drift, not fixed this pass** (separate root cause): a fourth, disconnected rate-limit table (`middleware/auth.js TIERS`) only recognizes FREE/PRO/ENTERPRISE — a JWT-authenticated STARTER/MSSP/TEAM/BUSINESS customer hitting several real endpoints (`globalIntel.js`, `auditLog.js`, `threatHunting.js`, `threatIntelPro.js`, `vulnManagement.js`) gets FREE-tier throttling instead of their paid tier. Also: `pricingConfig.js`'s advertised STARTER `daily_scans:50` doesn't match the actually-enforced 20/day; marketplace `ai_agent` purchases (both the ₹9,999/30-day and ₹2,999/7-day products) are hardcoded to mint an `ENTERPRISE`-tier API key regardless of which was purchased; two of three "usage dashboard" endpoints are always-empty dead code (no writer ever populates the tables they read). All four are **documented in the Remaining Technical Debt register below, not implemented in this pass** — each is a distinct root cause deserving its own focused PR. |

---

## Security Validation

| Requirement | Result |
|---|---|
| No client-controlled tier assignment | ✅ Verified — `users.tier` is only ever written from server-resolved values (order-authoritative lookup, webhook-verified plan, or the now-validated checkout plan) |
| No client-controlled pricing | ✅ Verified across every `createRazorpayOrder`/`createPayPalOrder`/raw Razorpay API call site in the codebase (7 additional call sites checked this pass beyond the 5 already fixed in Phase I — all catalog-derived) |
| No unauthorized entitlement grants | ✅ Verified for the paths in scope this pass |
| No privilege escalation | ✅ Verified — the entitlement-grant allow-list (a pre-existing, correct control) was never the vulnerability; H8 closed the gap in front of it |
| No payment without provisioning | ✅ Fixed this pass (H5, H8) for the paths in scope. See §"Enterprise purchase" above for confirmation this already held for the proposal/manual-fulfillment path. |
| No provisioning without payment | ✅ Verified — no code path grants a tier without a genuinely HMAC-verified Razorpay/PayPal payment |
| No exposed commercial dashboards | ❌→✅ **New finding, fixed in PR #246** (separate from H5/H8): `GET /api/revenue/intel/history\|forecast\|waterfall\|cohorts\|tiermix` required only real-user authentication, not admin — any paying customer could read the platform's real MRR/ARR, revenue forecast, churn rate, cohort retention, and tier-mix data. Same vulnerability class as already-fixed `/api/revenue/dashboard` (PR #233) and `/v24/ceo/*` (PR #239), missed in this one file. Fixed with the same `requireAdmin()` gate its own sibling route already used. |

Also re-confirmed still open (documented previously, unchanged this pass, explicitly out of scope for "no new feature work"): `POST /api/v24/trust/uptime` has no authentication check at all (can write fabricated rows into the public uptime log) — low severity, data-integrity of a public status page only, already flagged in PR #244.

---

## Commercial Validation

| Check | Result |
|---|---|
| Advertised price = checkout price | ✅ Verified for System A's live, frontend-linked plans (spot-checked `STARTER ₹999`, `PRO ₹1,499` against `checkout-modal.js` → `SUBSCRIPTION_PRICES`) |
| Checkout price = invoice price | ✅ Verified — no separate invoice-pricing table for subscriptions; `createInvoice()` is fed the same charged amount |
| Invoice price = subscription value | ✅ Verified for System A |
| Subscription value = entitlement | ✅ **Now** verified for System A (all 4 tiers) and System B's ENTERPRISE only, after this pass's fixes. **Not yet true** for System B's ENTERPRISE specifically on the *price* dimension (₹49,999 charged vs. ₹4,999 elsewhere for the same name) — flagged, not resolved, pending a product decision (Subscription Registry §5). |
| Dashboard reflects purchased plan | ⚠️ **Partially** — `GET /api/user/plan` (the real, frontend-used dashboard) is correct. `GET /api/subscription/plan` (a second, System-B-vocabulary dashboard) mislabels System A customers' plan name/price/limits. Cosmetic (no entitlement is actually gated on this response) but a real "your plan" misreport — documented, not fixed this pass (separate root cause, low severity). |

---

## Billing Validation

| Check | Result |
|---|---|
| Invoice generation | ✅ Working (consolidated `createInvoice()` engine, Phase I PR #241) |
| GST numbering | ✅ Sequentially numbered, idempotent by `payment_id`, collision-retry logic Verified |
| Payment reconciliation | ✅ Order-authoritative lookup prevents plan/amount tampering at verify time (pre-existing fix, re-confirmed this pass) |
| Duplicate prevention | ✅ Webhook: D1-keyed `webhook_events` dedup + secondary status re-check. ⚠️ **Untested race condition** (documented, not fixed): concurrent `/api/payments/verify` calls for one order could insert two `subscriptions` rows — time-based non-unique id, no `UNIQUE` constraint on `razorpay_order_id`/`payment_id` in that table. |
| Webhook idempotency | ✅ Verified solid — see above |
| Renewal behavior | ❌ **No automated renewal exists at all** — confirmed via code trace (`runPaymentRecovery`'s own `TODO`, `runRenewalAutomation`'s reminder-only design, and a dead-code 35-day reminder seeder referencing a nonexistent schema column). Documented as a missing feature, explicitly not implemented this pass per "do not start new feature work." |

---

## Authorization Validation

Traced the anonymous → customer → partner → admin → owner privilege hierarchy across every route touched by this pass's investigation:

- **anonymous → customer**: `/api/payments/create-order` and `/verify` correctly require nothing beyond a valid signature for one-time products, and correctly require login for subscription grants (an anonymous subscription payment has nowhere to apply the upgrade — already guarded).
- **customer → partner/admin**: Revenue Intelligence routes (PR #246) previously granted *any* customer partner/admin-level visibility into aggregate business data — now correctly gated.
- **admin → owner**: Not touched this pass; no new findings at this boundary.

No new authorization-bypass or IDOR was found beyond the Revenue Intelligence finding (PR #246).

---

## Operational Validation

- **Logs**: no new noise introduced by this pass's changes (rejections are single, informative 400/409 responses, not verbose logging).
- **Monitoring/alerting**: re-confirmed (from Phase I) that `Alerts.paymentFailure`/`Alerts.workerError` helpers exist in `lib/alertEngine.js` but are never called anywhere — payment failures and unhandled worker errors currently have no active alerting path beyond passive log inspection. Documented, not implemented this pass (a monitoring-coverage feature, not a defect in the paths this pass fixed).
- **Audit trail**: `ops_alert_log`, `system_errors`, and the new `webhook_events` dedup table all provide a reasonable trail for the paths this pass touched.
- **Webhook/invoice/payment failures**: webhook signature failures are logged and rejected (401); invoice creation failures are caught and logged without failing the underlying payment verification (correct fail-open posture for a non-critical side effect); payment order-creation failures return a clear 502 with a support-contact fallback.
- **Retry handling**: Razorpay order creation in the *live* checkout path (`payments.js`) uses circuit-breaker + retry (`resilientFetch`); `revenue.js`'s parallel `/api/checkout` endpoint (Phase I, PR #240) and `subscriptionPaywallEngine.js`'s checkout both use a raw, non-resilient `fetch()` — an inconsistency in resilience coverage across the platform's multiple checkout paths, not introduced by this pass, not fixed (separate root cause).

---

## Regression Validation

Full automated suite, run on the exact commit each PR is based on:

| Suite | Files | Tests | Result |
|---|---|---|---|
| Full suite (post PR #245: H5+H8) | 293 | 3054 | **All passing, 0 failed, 0 skipped** |
| Full suite (post PR #246: Revenue Intel gate) | 293 | 3063 | **All passing, 0 failed, 0 skipped** |
| Payment-specific subset | 13 | 152 | All passing |
| Billing/invoice subset | 5 | 45 | All passing |
| Authorization subset | 33+1 | 372+21 | All passing |

New tests added this pass: 8 (H8, `subscriptionPlanAllowList.test.mjs`) + 3 (H5, `subscriptionCheckout.test.mjs`) + 1 (H5 webhook defense-in-depth, `paymentsWebhook.test.mjs`) + 21 (Revenue Intel admin gate, `revenueIntelAdminGate.test.mjs`) = **33 new regression tests**, covering: valid plans, invalid/malformed/unknown plans, a priced-but-ungrantable plan (`ENTERPRISE_SOC`), case-insensitivity, coupon-carrying invalid requests, duplicate/defense-in-depth verification paths, and admin-vs-customer-vs-anonymous access for the newly-gated dashboard routes. Two pre-existing tests were updated because they asserted the specific broken behavior these fixes correct (not regressions — intentional, documented updates).

Explicitly not covered by new tests this pass (documented as technical debt, §below): webhook replay for `subscription.*`/`invoice.*` Razorpay event types (none are handled at all — confirmed, not a gap in this pass's scope since no such events are processed); renewal/cancellation enforcement (no code exists to test); the concurrent-verify race condition (would require a concurrency-simulating test harness beyond this pass's scope).

---

## Remaining Technical Debt (classified, not implemented — per governance policy)

### Critical
*None.* No scenario was found where the live, shipped checkout flow lets a customer pay and receive nothing, after this pass's fixes.

### High
1. **System B's ENTERPRISE tier charges 10× the platform's real ENTERPRISE price** (₹49,999 vs ₹4,999) through a still-reachable-by-direct-API endpoint. *Repository evidence*: Subscription Registry §5. *Customer impact*: none today (zero frontend callers), but a live overcharge risk for any future integration. *Revenue impact*: could cut either way (overcharge risk vs. an intentionally higher-tier product never priced correctly). *Recommended next action*: product decision — retire System B or reprice/relaunch it; block the ENTERPRISE checkout path in the interim.
2. ~~**A fourth, disconnected rate-limit table**~~ — **RESOLVED, PR #248 (Production Engineering Phase III, merged `75baefff`).** `middleware/auth.js`'s `TIERS` (previously FREE/PRO/ENTERPRISE only) silently throttled JWT/IP-authenticated STARTER/MSSP customers to FREE-tier limits — confirmed live on `index.js`'s core scan pipeline (`/api/scan/domain|ai|redteam|identity`, `/api/generate/compliance`) in addition to the 5 handler files originally named here (the deeper trace found the real blast radius was larger than this entry originally scoped, and that all 6 dependents go through `middleware/rateLimit.js`, not `middleware/auth.js` directly). `TIERS` now derives its values from `TIER_LIMITS` instead of an independently-maintained copy, closing the drift permanently. 7 new regression tests added; full suite 294 files/3082 tests passing. See Phase III addendum below.
3. **No automated subscription renewal exists.** *Revenue impact*: potential involuntary churn at the end of every billing period since nothing re-charges the customer; "monthly" is currently a one-time-charge label. *Recommended next action*: scope a Razorpay recurring-subscription integration as a dedicated feature project — explicitly out of scope for a "no new feature work" pass.
4. **Cancellation doesn't enforce downgrade at period end** (both the DB-based and KV-based mechanisms). *Revenue impact*: cancelled customers may retain full paid entitlements indefinitely at zero cost. *Recommended next action*: a scheduled cron job to sweep expired `cancel_at_period_end` rows — own PR.

### Medium
5. **`proposal.price_inr` is always `undefined`** on every proposal accept/send/reject lifecycle event, writing `amount_inr:0` and suppressing affiliate-commission crediting for enterprise deals closed through the proposal-accept path. *Recommended next action*: fix the field reference (`proposal.pricing.final_price_inr`), own PR.
6. **`pricingConfig.js`'s advertised STARTER `daily_scans:50`** doesn't match the actually-enforced 20/day (`TIER_LIMITS.STARTER`) — same drift class as the already-fixed PR #232 price bug, this time in a limit field. *Recommended next action*: correct the constant, own PR.
7. **Marketplace `ai_agent` API-key purchases are hardcoded to `'ENTERPRISE'` tier** regardless of which of the two products (₹9,999/30-day vs ₹2,999/7-day trial) was bought. *Recommended next action*: differentiate tier by product, own PR.
8. **`GET /api/subscription/plan` mislabels System A customers** with System B's vocabulary/pricing (cosmetic — see §"Commercial Validation"). *Recommended next action*: either stop normalizing when the account's real tier is a System A value, or retire the endpoint alongside System B.

### Low
9. **Two of three "usage dashboard" endpoints are always-empty dead code** (`ops_usage_events`/`opsEngine.trackUsage` and `developer/rate-limits/usage`'s backing KV keys — never written). Not customer-harmful (they just show zeroes) but actively misleading if anyone relies on them operationally. *Recommended next action*: either wire the writers or remove the dashboards.
10. **`Alerts.paymentFailure`/`Alerts.workerError` are defined but never called anywhere** — no active alerting for payment failures or unhandled worker errors beyond passive logs. *Recommended next action*: wire these into the existing payment-failure and webhook-error catch blocks.
11. **Inconsistent resilience coverage**: `revenue.js`'s `/api/checkout` and `subscriptionPaywallEngine.js`'s checkout both use raw `fetch()` for Razorpay calls instead of the circuit-breaker-backed `resilientFetch()`/`createRazorpayOrder()` the main `payments.js` path uses. *Recommended next action*: consolidate onto the shared helper.
12. **Test-coverage gaps** (no positive isolation test for marketplace `my-purchases`; no router-shadowing regression test for `download`; `handleGenerateProposal`'s actual enforcing gate has zero test coverage). *Recommended next action*: add tests, no code change needed.

### Deferred (Business Decision — see next section)
13. **H2** — MSSP revenue-share percentage shown inconsistently across marketing pages (30%/50%/60%), and whether the 60%-flat ledger should honor the 30/40/50% tiered onboarding margins it separately promises. Not touched this pass.
14. **H7** — an internal-only MSSP "Pricing Reference" (per-sale commission, usage-metered billing, OEM tier) matching no backend code anywhere — real intent Not Verified. Not touched this pass.

---

## Business Decisions (documented, not implemented — repository evidence and implications only)

Per explicit instruction, these are kept separate from engineering work. Both are unchanged from `COMMERCIAL_RISK_AUDIT_2026-07-14.md` — cross-referenced here, not re-investigated, since nothing about them changed this pass.

### H2 — MSSP revenue-share percentage
- **Repository evidence**: `index.html:6211` shows 30% in a comparison table; `index.html:6475,6607` and `upgrade.html:202`/`mssp-onboarding.html:156` show 50%; `mssp.html`'s title/meta/og tags show 60%/"60-40". The actual, live payout ledger computes a flat 60% for every partner today — confirmed real and operating, not a false claim.
- **Implications of each decision**:
  - Standardize on 60% flat: requires correcting the 30%/50% figures on 3+ pages to stop promising a lower rate the ledger will never pay; simplest, matches current reality.
  - Honor the tiered 30/40/50% onboarding promise: requires new ledger logic to compute partner-tier-specific splits — a real billing-logic change, needs its own scoped project.
  - Do nothing: leaves a live, quotable discrepancy between marketing copy and the actual payout a partner receives — a partner-trust/dispute risk that grows with MSSP program adoption.

### H7 — Internal-only MSSP "Pricing Reference"
- **Repository evidence**: `frontend/mssp-command-center.html`'s internal partner-ops dashboard (gated, staff/partner-only) describes per-sale commission tracking, usage-metered overage billing (₹0.50/API-call over 10,000/mo), and a minimum-contract OEM tier — none of which exist in any handler, schema, or route found anywhere in `workers/`.
- **Implications of each decision**:
  - It's a real, informal arrangement never coded: needs an actual implementation project (usage metering + billing logic) if it's to be honored, or the content should be marked "coming soon"/removed if it isn't imminent.
  - It's stale/aspirational content never reconciled with the shipped self-serve tiers: should be replaced with the real, current MSSP program description to stop misinforming internal staff/partners who see this dashboard.
  - Needs a live conversation with the platform owner to determine which — repository evidence alone cannot resolve intent here.

---

## Release Recommendation

# PASS WITH MINOR RISKS

**Supporting evidence:**
- Both explicitly-flagged risks (H5, H8) are Verified, Fixed, and regression-tested (293 files / 3054–3063 tests, 0 failures, 0 skipped, across both PRs).
- No scenario exists today where the **live, shipped** checkout flow lets a customer pay and fail to receive their purchased subscription entitlement — the bar this gate's PRIMARY OBJECTIVE explicitly required to avoid a FAIL.
- One additional live, severe finding (exposed revenue dashboard) was found and fixed during the same trace, in its own PR, per governance policy.
- The "minor risks" preventing a clean PASS are: (a) a documented, contained (zero current traffic) pricing inconsistency in the tier system this pass just partially fixed, requiring a product decision rather than a code fix; (b) confirmed, pre-existing structural gaps in renewal/cancellation automation that are explicitly out of scope for a "no new feature work" pass and were never claimed to be fixed here; (c) a handful of Medium/Low severity drift and dead-code findings, each independently small, documented, and queued for their own future PRs per "one production problem per PR."

**Recommended next engineering milestone:** PR #245 and PR #246 are merged and deployed. Take up — in order of the register above — the fourth rate-limit table reconciliation (High #2) and the proposal-pricing-attribution bug (Medium #5), each as its own single-root-cause PR. The renewal-automation and cancellation-enforcement gaps (High #3, #4) warrant a scoped feature proposal to the platform owner rather than an engineering-initiated PR, given their size and the explicit "no new feature work" boundary of this pass.

---

## Post-Merge Verification (2026-07-14, same-day follow-up session)

Performed after a usage-limit interruption of the session that opened PR #245/#246. Per governance policy, verified against the repository and GitHub API directly rather than trusting this document's own prior self-report.

| Check | Result |
|---|---|
| PR #245 state | ✅ `merged: true`, merged 2026-07-14T20:03:44Z, commit `d4db0eee`. Zero unresolved review threads (the one CodeQL comment — incomplete URL substring check in a test's mock fetch — is `is_resolved: true`, `is_outdated: true`). |
| PR #246 state | ✅ `merged: true`, merged 2026-07-14T20:07:35Z, commit `04c6dd1d`. Zero review threads. |
| CI on both PRs | ✅ All check runs `completed`/`success`, including `CI Gate (All Required Jobs)` and `CodeQL`, on both PRs. |
| Open PRs remaining | ✅ Zero — `list_pull_requests(state=open)` returns an empty list. |
| `main` synchronization | ✅ Local checkout, `origin/main`, and this session's working branch all resolve to the identical commit `04c6dd1d`. No divergence, no stale unmerged commits. |
| Deployment | ✅ `Deploy to Cloudflare` workflow run `29364632745` for head commit `04c6dd1d` — `completed`/`success`. |
| Fix presence in code (direct grep, not PR-description trust) | ✅ `GRANTABLE_SUBSCRIPTION_PLANS` gate present and enforced at all 3 call sites in `workers/src/handlers/payments.js` (order creation, verify-payment defense-in-depth, webhook fallback grant). ✅ `TIER_LIMITS[tierKey]` guard present in `handleSubscriptionCheckout` (`subscriptionPaywallEngine.js`). ✅ `requireAdmin()` gate present on all 5 previously-open routes in `revenueIntelligence.js`. |
| Regression suite (independent re-run) | ✅ Clean `npm ci` + `npx vitest run` on current `main`: **294 files / 3075 tests, 0 failed, 0 skipped.** Reconciles exactly with the two PRs' independently-reported deltas (292 baseline + 2 new test files + 33 new tests = 294/3075). |
| Documentation | ✅ This document and `SUBSCRIPTION_REGISTRY_2026-07-14.md` updated/confirmed current; no new document created (living-document convention). |

**Observation (not a production defect, no action taken):** the repository carries roughly 90 other `claude/*` branches from prior sessions' work, most already reflected in `main` via merged history and some possibly abandoned exploration. Branch deletion is a destructive, hard-to-reverse operation outside this session's scope (subscription integrity / H5-H8) and was not performed; flagged for the repository owner's discretion, not queued as an engineering task.

**Conclusion: no change to the release gate decision.** PASS WITH MINOR RISKS is reconfirmed with fresh, independent evidence rather than carried forward on trust.

---

## Phase III — Entitlement & Rate-Limit Authority Consolidation (2026-07-14, follow-on session)

Closes Technical Debt register item **High #2** above. Full findings, root cause, and evidence are in PR #248's description; summarized here for the living-document record.

| Check | Result |
|---|---|
| Scope | `middleware/auth.js`'s `TIERS` (FREE/PRO/ENTERPRISE only) vs. the authoritative `TIER_LIMITS` (`auth/apiKeys.js`, all 5 real tiers). |
| Root cause | `TIERS` was a hardcoded snapshot of `TIER_LIMITS`'s FREE/PRO/ENTERPRISE values from before STARTER/MSSP were added there. `middleware/rateLimit.js`'s `checkRateLimitV2`/`checkRateLimitCost` do `TIERS[tier] \|\| TIERS.FREE`, so STARTER/MSSP silently fell back to FREE's 5/day, 2/min burst. |
| Precision correction vs. the original High #2 entry | The dependency is transitive (all 6 consumers go through `middleware/rateLimit.js`, not `middleware/auth.js` directly), and the blast radius is larger than originally scoped: it also gated `index.js`'s core scan pipeline (`/api/scan/domain\|ai\|redteam\|identity`, `/api/generate/compliance`, `/api/leads/capture`, `/api/contact/enterprise`, `/api/report/generate`) for every JWT/browser-session caller — not just the 5 intel-handler files originally named. API-key callers were unaffected (routed through `enforceQuota`→`TIER_LIMITS` correctly). |
| Fix | `TIERS` now derives `daily_limit`/`burst_per_min` from `TIER_LIMITS` instead of independent literals — one file changed (`middleware/auth.js`), zero changes needed in any consumer. FREE/PRO/ENTERPRISE values numerically unchanged (regression-tested); STARTER/MSSP corrected. |
| Tests added | 7 (STARTER burst/daily/cost-weighted, MSSP unlimited x2, `TIERS` completeness, `TIERS`-vs-`TIER_LIMITS` anti-drift guard) + 1 existing test corrected (a source-text-regex check that had the same blind spot as the bug itself, in `feedLimitsReportExpiry.test.mjs`). |
| Regression suite | 294 files / 3082 tests passing (3075 baseline + 7 new), 0 failed. |
| PR #248 | Merged `75baefff`, 2026-07-14T20:57:31Z. CI: all 33 check runs `completed`/`success` including CodeQL and both Analyze (python/javascript-typescript) jobs. Zero review comments. |
| Other tables examined, confirmed out of scope | `config/pricingConfig.js`'s advertised-vs-enforced STARTER `daily_scans` drift (already Medium #6 above, unrelated root cause) and `services/revos/apiEconomyEngine.js`'s dead `daily_limit`/`monthly_limit` sub-fields (a distinct, self-contained per-call billing product) — neither touched. |

**Conclusion: no change to the release gate decision.** PASS WITH MINOR RISKS stands; one High-severity item is now resolved and closed out of the open register.

---

*Cross-references: `COMMERCIAL_RISK_AUDIT_2026-07-14.md`, `ENTERPRISE_COMMERCIAL_PRODUCT_REGISTRY_2026-07-14.md`, `SUBSCRIPTION_REGISTRY_2026-07-14.md` (companion document, full per-tier table), PR #240–#244 (Phase I), PR #245 (H5/H8, merged `d4db0eee`), PR #246 (Revenue Intelligence admin gate, merged `04c6dd1d`), PR #247 (Phase II doc addendum, merged `eecc077e`), PR #248 (Phase III rate-limit authority consolidation, merged `75baefff`).*
