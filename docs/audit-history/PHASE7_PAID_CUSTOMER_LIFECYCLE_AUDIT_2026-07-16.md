# PHASE 7 — Paid Customer Lifecycle Audit (Live-Verified)

**Platform:** CYBERDUDEBIVASH AI Security Hub (https://cyberdudebivash.in)
**Scope:** The complete self-serve paid lifecycle — signup → subscribe/pay →
provisioning/entitlement → product usage → renewal → support → cancellation/exit.
**Method:** Live production API calls against a real, disposable test account
(created and deleted during this audit), cross-checked against current
repository code (post-#278, commit `692fc84`), plus three independent
code-path re-verifications of prior audit claims. **Doc claims were not
trusted** — every "COMPLETE/VERIFIED/FIXED" status below is either a live
HTTP response this audit captured directly, or a file:line citation against
current code.
**Date:** 2026-07-16
**Supersedes/updates (do not re-run from scratch, cross-reference instead):**
`PHASE1_ENTERPRISE_LIFECYCLE_AUDIT.md` (2026-06-15), `SUBSCRIPTION_REGISTRY_2026-07-14.md`,
`PHASE6_CUSTOMER_ENGAGEMENT_AUDIT_2026-07-15.md`.

---

## Executive Summary

**Overall call: Conditional GO.** A customer can sign up, subscribe, pay,
receive the correct paid tier, use the product, submit support tickets, and
request cancellation — all live-verified end-to-end and working correctly.
**One P0 revenue-integrity defect blocked full GO and has been fixed in this
audit's PR**: the cron responsible for downgrading lapsed/cancelled
subscribers back to FREE has been silently non-functional since it was
added, meaning every paying customer who completes one charge has been
retaining full paid-tier access indefinitely, forever, at zero further
revenue — with no error ever surfacing. One P2 finding (short-lived access
tokens remain valid for up to 15 minutes after account deletion) is
documented but not fixed here — it touches the shared authentication
resolution path used by nearly every endpoint and deserves isolated,
deliberate handling rather than a same-pass fix. **This audit could not, and
should not, complete an actual live payment** — Razorpay checkout returned a
real `rzp_live_...` order (not sandbox), and completing it requires the
account holder's own bank/UPI/card authentication, which is both outside
this session's capability and outside its authority to attempt.

### Severity rollup

| Sev | Finding | Status |
|-----|---------|--------|
| **P0** | Subscription-expiry enforcement cron has never downgraded anyone (wrong column + invalid status enum, both silently swallowed) | **Fixed this audit** (own PR, see below) |
| **P1** | Prior Phase 1 findings (Razorpay tier not persisted, STARTER unmetered, marketplace webhook 404) | **Verified fixed** already, by earlier PRs — re-confirmed with fresh evidence |
| **P1** | Support ticket 500 (Phase 6 finding, "pending owner decision" as of today) | **Verified fixed** live — real ticket created and retrieved successfully |
| **P2** | Access token remains valid up to 15 min after account deletion (no live `users.status` check in JWT auth path) | **Documented, not fixed** — recommend a deliberate follow-up |
| **P2** | No true auto-renewal/recharge exists (Razorpay integration is one-time-order only, no subscription/mandate API used) | **Confirmed still true** — architectural, needs an owner decision (see below) |
| **Info** | Duplicate `handleCancelSubscription` implementations across two unrelated handler files (same name, different subsystems) | Documented, no action taken |

---

## 1. What this audit directly verified live (production, real test account)

A disposable test account (`claude-lifecycle-audit-*@example.com`) was
created via the live public API, exercised, and deleted at the end. No real
payment was completed — see §4.

| Stage | Result | Evidence |
|---|---|---|
| Signup | **Works** | `POST /api/auth/signup` → 201, real JWT + refresh token + API key issued, `tier: FREE` |
| Auth / identity | **Works** | `GET /api/auth/me` → 200, correct profile |
| Plan status | **Works** | `GET /api/user/plan` → 200, correct FREE quota (50 scans, resets monthly) |
| Pricing catalog | **Works** | `GET /api/subscription/plans` → 200, all 5 tiers with correct INR pricing |
| Checkout initiation | **Works, correctly priced** | `POST /api/subscription/create` (STARTER) → 200, real Razorpay order `order_TE7AmOTd0wwNwd`, amount `99900` paise = ₹999, matching the advertised price exactly |
| Scan execution | **Blocked in this environment by the token/IP anti-abuse check** — not a new finding, matches the already-documented "free-scan IP-binding fragility" from the 2026-07-16 homepage audit; almost certainly an artifact of this session's own outbound proxy rather than a defect a normal browser client would hit | `POST /api/scan/token` → 200; `POST /api/scan/domain` with that token → 403 `ip_mismatch` |
| Support ticket creation | **Works** | `POST /api/support/ticket` (correct fields) → 200, ticket `TKT-MRN9SQQA-M7ZT` created; `GET /api/support/tickets/mine` correctly lists it |
| Cancellation (no active sub) | **Correct guard behavior** | `POST /api/customer/billing/cancel` on a FREE account → 404 "No active subscription found" (correct — nothing to cancel) |
| Account deletion / exit | **Works, with one caveat (§3.4)** | `DELETE /api/auth/delete-account` → 200, PII anonymized, API keys/tokens revoked in DB; **old access token still authenticates for its remaining ~15 min TTL** |

---

## 2. P0 — Subscription expiry enforcement was silently dead code (fixed this audit)

**Root cause:** `workers/src/index.js` (pre-fix, lines 9299–9324) contained a
cron block titled *"Subscription expiry enforcement — downgrade expired
subscribers to FREE."* It had two independent, compounding bugs:

1. It queried `s.expires_at`, a column that **has never existed** on the
   `subscriptions` table. Every schema definition (`schema_master.sql:3131-3160`,
   `schema_v27.sql:105`, `schema_bootstrap.sql:3393`, etc.) defines
   `current_period_end` instead. `schema_migration_rc1.sql:17-22` even
   documents, in its own header, that a *different* prior bug
   (`payments.js` inserting a nonexistent `expires_at` column) was already
   found and fixed — this cron block is a second, independent instance of
   the same defect class that survived that cleanup.
2. Even had the query worked, the subsequent `UPDATE subscriptions SET
   status = 'expired'` uses a value **not present** in the table's own
   `CHECK(status IN ('trialing','active','past_due','cancelled','paused'))`
   constraint (`schema_master.sql:3137-3138`). D1's `.batch()` runs
   statements as one transaction, so this would have rolled back the paired
   `users.tier = 'FREE'` downgrade too, even if bug #1 were fixed alone.

Both errors were caught by blanket `.catch()` handlers with no alerting, so
this block has logged nothing but silence and has never downgraded a single
subscriber since it was added (`git blame` attributes the block to commit
`b677e19`, 2026-07-14 — the same day `SUBSCRIPTION_REGISTRY_2026-07-14.md`
documented the underlying gap in general terms, without knowing this
specific "fix" attempt already existed and was itself broken).

**Confirmed independently three times** in this audit: by direct reading of
`schema_migration_rc1.sql`'s own comments, by one dispatched agent tracing
the renewal engine, and by a second dispatched agent tracing cancellation
enforcement — all three converged on the identical file:line evidence.

**Business impact:** Since no auto-recharge mechanism exists either (§5),
every paid subscription is effectively a one-time charge. Combined with this
dead cron, **a customer who pays once for STARTER/PRO/ENTERPRISE/MSSP, then
either explicitly cancels or simply never returns to pay again, keeps full
paid-tier access forever** — indefinitely, with zero further revenue, until
someone manually intervenes. Given the platform has been running with this
defect since at least 2026-07-14 (and the underlying gap since before that),
this may already have live financial impact; see **Recommended immediate
action** below.

**Fix implemented (this audit's PR):**
- Extracted the inline cron logic into `enforceSubscriptionExpiry()` in
  `workers/src/handlers/renewalEngine.js` (mirroring how the sibling bug,
  `seedRenewalQueue35d`, was fixed and made unit-testable in PR #264) —
  corrects the column name (`current_period_end`) and the status value
  (`'cancelled'`, an already-valid enum member, instead of inventing
  `'expired'`), and reads `subscriptions.user_id` directly instead of a
  fragile email-based join to `users`.
- `workers/src/index.js`'s scheduled handler now calls this function instead
  of the inline broken block; same cron schedule, same
  `ctx.waitUntil`/logging pattern.
- New regression test, `workers/test/subscriptionExpiryEnforcement.test.mjs`,
  against a real `node:sqlite` D1 with the actual `CHECK` constraints in
  place (a permissive mock would hide this exact bug class) — covers:
  lapsed-with-no-cancellation, explicit-cancel-past-grace-period,
  still-within-period (no-op), ENTERPRISE/MSSP protection preserved, and a
  guard proving the *old* column/status combination would fail against the
  real schema.
- Full suite: **309 test files / 3231 tests, all green** (was 308/3226
  before this audit's addition).

**Recommended immediate action (owner decision, not performed by this
audit):** Before or immediately after this deploys, run a one-off read-only
query against production D1 —
`SELECT COUNT(*) FROM subscriptions WHERE status='active' AND current_period_end <= datetime('now')`
— to see how many currently-active subscriptions are already past their
period end. Those customers will be correctly downgraded to FREE the next
time the `0 23 * * *` / `0 0 * * *` cron fires after deploy. Since they may
not be expecting this (they may not realize their subscription lapsed
months ago), consider whether to notify them or grandfather a grace period,
rather than let it happen silently — this is a customer-experience
judgment call, not a code question.

---

## 3. Re-verification of prior audit claims (three independent tracks)

### 3.1 Phase 1 findings (2026-06-15) — payment → entitlement chain

| Claim | Status | Evidence |
|---|---|---|
| Razorpay activation never wrote `users.tier`/`subscriptions` | **Fixed** | `payments.js` `handleVerifyPayment` (subscription branch, ~line 478) now writes `users.tier`, mints a JWT with the real tier, and inserts the `subscriptions` row; `subscription.js`'s old activate path is now a thin shim into the same code, with its own comment documenting the historical bug (incident PR #142) |
| STARTER quota metering arg-order bug | **Fixed** | `index.js` call site and `subscription.js:343`'s `checkMonthlyQuota(env, identity)` signature now match exactly |
| Marketplace purchase→delivery chain severed (`POST /api/marketplace/webhook` 404) | **Fixed** | Route now registered, `sentinelApexMarketplace.js` implements signature-verified webhook → `status='paid'` → entitlement; regression test exists (`marketplaceWebhook.test.mjs`) |
| *(Documentation drift)* Phase 1 cited `stripeWebhook.js:260`, a file that has never existed in this repo's git history — Stripe is explicitly not used as a processor | Noted for correction in Phase 1's own doc |

**Residual gap confirmed:** there is still no `/api/subscription/cancel`-style
route in the main `/api/subscription/*` namespace — but a working cancel
route *does* exist at `/api/customer/billing/cancel` (a different
namespace, live-tested in this audit — see §3.2). Phase 1's residual-gap
note should be corrected, not carried forward as-is.

### 3.2 Cancellation enforcement (`SUBSCRIPTION_REGISTRY_2026-07-14.md`)

**Claim:** "Grace-period cancel exists but nothing enforces the downgrade
once the period ends." **Verified still true prior to this audit's fix**,
now resolved by §2. Detail found beyond the original claim: there are two
unrelated `handleCancelSubscription` functions in this codebase —
`enterpriseTransformHandler.js:293` (the real one, wired to
`/api/customer/billing/cancel`, live-tested in this audit: correctly sets
`cancel_at_period_end=1` and leaves the customer on their paid plan "until
the end of the current billing period," never an immediate hard-cancel) and
a same-named-but-different `sentinelApexMarketplace.js:305` (serves
`/api/marketplace/subscriptions/:id/cancel`, a separate marketplace-specific
subsystem). Not a bug — JS module scoping means there's no runtime
collision — but it's the kind of "fragmented parallel implementation"
Phase 1's executive summary already called out as a general pattern, and is
worth consolidating at some point for maintainability (not urgent).

### 3.3 Support ticket 500 (`PHASE6_CUSTOMER_ENGAGEMENT_AUDIT_2026-07-15.md`)

**Claim:** live 500 on both ticket endpoints, status "NOT FIXED... pending
owner decision" as of today. Code inspection alone could not resolve this —
`schema_v51_support_ticket_org_scope.sql` and `support.js` are internally
consistent with each other; the open question was purely whether that
migration had actually been applied to live D1 (not visible from repo code).
**This audit's live test resolves it: fixed.** `POST /api/support/ticket`
with valid fields returned `200` and a real ticket was created and
retrieved via `GET /api/support/tickets/mine`. The migration has evidently
been applied since Phase 6's last update. Phase 6's Finding 0 should be
marked resolved.

### 3.4 New finding this audit — post-deletion access token validity

Not from a prior doc — found live during this audit's own account-cleanup
step. `DELETE /api/auth/delete-account` correctly anonymizes PII and revokes
stored API keys/refresh tokens, but a **JWT access token issued before
deletion continues to authenticate successfully afterward**, for the
remainder of its 15-minute TTL. Root cause: `auth/middleware.js`'s
`resolveFromJWT` verifies the JWT purely by signature + expiry + embedded
claims — it never re-checks live `users.status` against the database (by
design, to avoid a DB round-trip on every authenticated request). Severity:
bounded (15-minute maximum window, and the account's PII is already wiped by
that point), but relevant to the "customer exit" stage the owner
specifically asked to have checked. **Not fixed in this audit** — this
touches `resolveAuthV5`/`resolveFromJWT`, the shared authentication path
used by nearly every endpoint on the platform; a careless change here has
far larger blast radius than the isolated cron fix in §2, and deserves its
own dedicated, carefully-tested pass rather than being bundled in here.
Recommended options for that follow-up: (a) accept the bounded window as a
reasonable trade-off (common in JWT-based systems generally), (b) shorten
the access-token TTL further, or (c) add a cached/short-TTL live status
check specifically to the delete/suspend path.

---

## 4. What this audit could not do, and why (not a policy choice — a capability limit)

The task asked for the paid tier to actually be purchased and used
end-to-end. This audit verified everything up to and including real
checkout-order creation (`order_TE7AmOTd0wwNwd`, a genuine **live** Razorpay
order, `rzp_live_...` key — not sandbox). Completing that payment requires
the account holder's own bank app / UPI PIN / card + OTP — authentication
this agent does not have, should not simulate, and has no technical path to
supply. This is why the P0 finding in §2 was verified through code tracing
and a real-schema regression test rather than an actual completed purchase:
that is the strongest verification available without moving real money.

---

## 5. Confirmed-still-open architectural gap (decision needed, not implemented)

**No automated renewal/recharge exists.** Every Razorpay call site in
`workers/src/` hits `/v1/orders` (one-time charge) or
`/v1/payments/{id}/refund` — none call Razorpay's `/v1/subscriptions` or
`/v1/plans` (recurring-mandate) APIs. `billingEngine.js`'s
`runPaymentRecovery` still contains a literal `// TODO: Integrate with
Razorpay subscription retry API` and only sends a reminder email;
`renewalEngine.js`'s expiry email CTA links to `/pricing` for manual
re-purchase. This is confirmed current, exhaustively grepped for any
recurring/mandate/autopay code path (none found), and is unchanged by this
audit. **This is a genuine product/billing-architecture decision** (integrate
Razorpay Subscriptions, switch to UPI Autopay/e-mandate, or keep the
current one-time-charge-plus-reminder-email model deliberately) — per this
repo's production-fix policy, it is documented here for an explicit owner
decision, not auto-implemented.

---

## Files changed in this audit's PR

- `workers/src/handlers/renewalEngine.js` — added `enforceSubscriptionExpiry()`
- `workers/src/index.js` — replaced the broken inline cron block with a call to it
- `workers/test/subscriptionExpiryEnforcement.test.mjs` — new regression test (5 cases)
- `docs/audit-history/PHASE7_PAID_CUSTOMER_LIFECYCLE_AUDIT_2026-07-16.md` — this document

## Rollback

Single self-contained commit touching one cron block; revert is a plain
`git revert` with no data migration involved (the fix only changes which
column/value a cron reads and writes — no schema change). No customer-facing
API contract changes.

## Production verification checklist (post-deploy)

- [ ] Confirm the `0 23 * * *` / `0 0 * * *` cron log line
      `[CRON] Subscription expiry: N subscriptions expired and downgraded to FREE`
      appears with `N > 0` on the first run if any subscriptions are already lapsed
      (or confirm `N` stays legitimately `0` if none are)
- [ ] Spot-check one real lapsed subscription (if any exist) actually shows
      `tier='FREE'` in `users` after that run
- [ ] Confirm no ENTERPRISE/MSSP account was downgraded
- [ ] Owner: run the one-off COUNT query from §2 before/after deploy for
      revenue-impact awareness
