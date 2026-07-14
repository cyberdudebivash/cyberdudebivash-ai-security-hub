# Subscription Registry — Authoritative Definition

**Date:** 2026-07-14
**Status:** Living document. Reflects the repository state after PR #245 (H5/H8 fixes) and PR #246 (Revenue Intelligence admin gate).
**Purpose:** One authoritative table for every subscription plan on the platform — what it's called, what it costs, what tier value gets persisted, and what actually enforces access — so a future engineer never has to re-derive this by tracing five files.
**Method:** Static repository analysis, confirmed by direct code trace and cross-referenced against four parallel research passes (customer-journey trace, marketplace/enterprise-provisioning trace, API-subscription trace, price-catalog/security sweep). Every cell is Verified against current code unless marked otherwise.

---

## 1. The two parallel systems (why this table has two halves)

This platform has **two independently-evolved subscription systems** that were never reconciled:

- **System A — the real, live system.** Checkout: `POST /api/payment(s)/create-order` (module:`subscription`) → `handlers/payments.js`. Pricing: `SUBSCRIPTION_PRICES` (`lib/razorpay.js`). Tier vocabulary: `FREE/STARTER/PRO/ENTERPRISE/MSSP`. This is the only subscription vocabulary the live `users.tier` schema CHECK constraint, `auth/apiKeys.js`'s `TIER_LIMITS`/`PLAN_FEATURES` (the tables `enforceQuota()` and the dashboard actually consult), and every shipped frontend checkout button use.
- **System B — an orphaned, unreachable system.** Checkout: `POST /api/subscription/checkout` → `handlers/subscriptionPaywallEngine.js`. Pricing: `SUBSCRIPTION_TIERS`. Tier vocabulary: `COMMUNITY/PROFESSIONAL/TEAM/BUSINESS/ENTERPRISE`. Confirmed unreachable from any shipped frontend page (`grep -rn "api/subscription/checkout" frontend/` → 0 matches). `normalizeTier()` aliases System A's names *into* System B's vocabulary (`STARTER→PROFESSIONAL`, `PRO→PROFESSIONAL`, `MSSP→ENTERPRISE`, `FREE→COMMUNITY`) but nothing ever migrated the schema/`TIER_LIMITS`/`PLAN_FEATURES` to accept System B's own names going the other direction.

**As of PR #245**: System B's checkout now refuses to charge for any tier it cannot actually grant (`PROFESSIONAL`/`TEAM`/`BUSINESS`) — see §4. `ENTERPRISE` is the one System B tier name that happens to coincide with a System A name and still completes checkout through System B, but at System B's own (different, higher) price — flagged in §5 as unresolved.

---

## 2. System A — Live subscription plans (self-serve, frontend-wired)

| Field | STARTER | PRO | ENTERPRISE | MSSP | ENTERPRISE_SOC |
|---|---|---|---|---|---|
| **Product ID** | `STARTER` | `PRO` | `ENTERPRISE` | `MSSP` | `ENTERPRISE_SOC` |
| **Display Name** | Starter Plan | Pro Plan | Enterprise Plan | MSSP Plan | Autonomic Threat Intel API |
| **Billing Cycle** | Monthly | Monthly | Monthly | Monthly | Monthly |
| **Razorpay Mapping** | `SUBSCRIPTION_PRICES.STARTER` — ₹999 (99,900 paise) | `SUBSCRIPTION_PRICES.PRO` — ₹1,499 | `SUBSCRIPTION_PRICES.ENTERPRISE` — ₹4,999 | `SUBSCRIPTION_PRICES.MSSP` — ₹9,999 | `SUBSCRIPTION_PRICES.ENTERPRISE_SOC` — ₹41,199 |
| **Internal SKU / Checkout Name** | `STARTER` | `PRO` | `ENTERPRISE` | `MSSP` | `ENTERPRISE_SOC` |
| **Stored Subscription** (`payments.plan`, `subscriptions.plan`) | `'STARTER'` | `'PRO'` | `'ENTERPRISE'` | `'MSSP'` | N/A — checkout rejected (PR #245) |
| **Database Tier** (`users.tier`) | `'STARTER'` ✅ CHECK-constraint-compatible | `'PRO'` ✅ | `'ENTERPRISE'` ✅ | `'MSSP'` ✅ | N/A |
| **Entitlement Tier** (`TIER_LIMITS`/`PLAN_FEATURES`, `auth/apiKeys.js`) | `TIER_LIMITS.STARTER` — 20/day, 600/mo, burst 5/min, limited AI | `TIER_LIMITS.PRO` — 500/day, 10,000/mo, burst 20/min, full AI | `TIER_LIMITS.ENTERPRISE` — unlimited, burst 60/min, full AI | `TIER_LIMITS.MSSP` — unlimited, burst 120/min, full AI, unlimited API keys | No entry — never grantable, by design (was priced but ungrantable; checkout now blocked) |
| **Dashboard Access** | `GET /api/user/plan` reads `authCtx.tier` raw — **correct** | Correct | Correct | Correct | N/A |
| **API Limits** | `MAX_KEYS_BY_TIER.STARTER = 2` | `= 5` | `= 20` | `= Infinity` | N/A |
| **Renewal Support** | **None** — no automated recharge exists anywhere (see §6) | None | None | None | N/A |
| **Cancellation Support** | Grace-period cancel exists (`cancel_at_period_end`) but nothing enforces the downgrade once the period ends (see §6) | Same | Same | Same | N/A |
| **Upgrade Path** | Re-checkout at a higher tier via the same `create-order`/`verify` flow; overwrites `users.tier` directly | Same | Same | Same | N/A |
| **Downgrade Path** | Same mechanism as upgrade (no distinct code path) | Same | Same | Same | N/A |
| **Webhook Mapping** | Fallback grant matches `payments.plan` against `GRANTABLE_SUBSCRIPTION_PLANS` (PR #245) | Same | Same | Same | Excluded — no fallback grant attempted |
| **Entitlement Mapping Status** | ✅ Verified consistent end-to-end | ✅ | ✅ | ✅ | ✅ Fixed (PR #245) — was Verified inconsistent (priced, chargeable, never grantable; see `mssPartnerSkuRemoved.test.mjs`) |

**Known cosmetic-only defect (not fixed this pass):** `GET /api/subscription/plan` (`handleGetMyPlan`, System B's own "my plan" endpoint) always runs `authCtx.tier` through `normalizeTier()` before responding — so a real STARTER customer (`users.tier='STARTER'`, correctly enforced at 20/day by System A) who happens to call *this* endpoint is told `tier:'PROFESSIONAL'`, `price_inr:1499`, `monthly_limit:10000` — none of which matches what they paid or what's actually enforced. Not an entitlement bypass (nothing gates real access on this response), but a real, live "your plan" misreport. Flagged in §7 as technical debt.

---

## 3. System B — Orphaned subscription plans (`/api/subscription/checkout`, unreachable from any shipped frontend page)

| Field | COMMUNITY | PROFESSIONAL | TEAM | BUSINESS | ENTERPRISE |
|---|---|---|---|---|---|
| **Product ID** | `COMMUNITY` | `PROFESSIONAL` | `TEAM` | `BUSINESS` | `ENTERPRISE` |
| **Display Name** | Community | Professional | Team | Business | Enterprise |
| **Billing Cycle** | Monthly (free) | Monthly | Monthly | Monthly | Monthly |
| **Razorpay Mapping** | Free — checkout rejected (`def.free`) | `SUBSCRIPTION_TIERS.PROFESSIONAL` — ₹1,499 | `SUBSCRIPTION_TIERS.TEAM` — ₹4,999 | `SUBSCRIPTION_TIERS.BUSINESS` — ₹14,999 | `SUBSCRIPTION_TIERS.ENTERPRISE` — **₹49,999** |
| **Internal SKU / Checkout Name** | `COMMUNITY` | `PROFESSIONAL` | `TEAM` | `BUSINESS` | `ENTERPRISE` |
| **Stored Subscription** | N/A | N/A — checkout now blocked (PR #245) | N/A — blocked | N/A — blocked | `'ENTERPRISE'` |
| **Database Tier** | N/A | N/A | N/A | N/A | `'ENTERPRISE'` ✅ (coincides with System A's name) |
| **Entitlement Tier** | N/A | No `TIER_LIMITS` entry — **would never have been grantable even before this fix** | No `TIER_LIMITS` entry | No `TIER_LIMITS` entry | `TIER_LIMITS.ENTERPRISE` (same table System A's ENTERPRISE resolves to) |
| **Dashboard Access** | N/A | N/A | N/A | N/A | Same as System A's ENTERPRISE |
| **API Limits** | N/A | N/A | N/A | N/A | Same as System A's ENTERPRISE |
| **Renewal Support** | N/A | N/A | N/A | N/A | None (same gap as System A) |
| **Cancellation Support** | N/A | N/A | N/A | N/A | Same gap as System A |
| **Upgrade/Downgrade Path** | N/A | N/A | N/A | N/A | Same mechanism as System A |
| **Webhook Mapping** | N/A | Guarded — write skipped even if an old order somehow reaches the webhook (PR #245 defense in depth) | Guarded | Guarded | Writes `users.tier='ENTERPRISE'` — succeeds |
| **Entitlement Mapping Status** | N/A (never chargeable) | ✅ Fixed (PR #245) — was Verified: charges ₹1,499, tier grant unresolvable | ✅ Fixed — was Verified: charges ₹4,999, tier grant unresolvable | ✅ Fixed — was Verified: charges ₹14,999, tier grant unresolvable | ⚠️ **Not fixed** — grants correctly, but charges **₹49,999** vs. the ₹4,999 charged for an identically-named "ENTERPRISE" plan everywhere else on the platform (System A, marketing pages). A 10× price divergence for the same plan name. See §5. |

---

## 4. What PR #245 changed (H5 + H8)

- **H8** (`handlers/payments.js`, System A checkout): `handleCreateOrder` now validates `body.plan` against `GRANTABLE_SUBSCRIPTION_PLANS = ['STARTER','PRO','ENTERPRISE','MSSP']` *before* creating any Razorpay order. An unrecognized plan (or `ENTERPRISE_SOC`, priced but never actually grantable) is rejected with 400 — no silent coercion to STARTER pricing, no charge for something that can't be fulfilled. `handleVerifyPayment` gets the same check as defense in depth for the edge case where no D1 order row exists. The webhook's fallback grant reuses the same shared constant.
- **H5** (`handlers/subscriptionPaywallEngine.js`, System B checkout): `handleSubscriptionCheckout` now checks `TIER_LIMITS[tierKey]` (imported from `auth/apiKeys.js`) before creating a Razorpay order — refusing checkout for `PROFESSIONAL`/`TEAM`/`BUSINESS` (409 `PLAN_NOT_PROVISIONABLE`) since none of those tier names have a corresponding entitlement table entry. `ENTERPRISE` is unaffected (still completes checkout) since it's the one System B name `TIER_LIMITS` also recognizes.

## 5. Residual finding — not fixed in PR #245, needs a decision

**System B's `ENTERPRISE` checkout charges ₹49,999; every other "ENTERPRISE" reference on the platform charges ₹4,999.** This is a 10× price divergence for an identically-named plan, reachable today only via direct API call to the still-unreachable-from-frontend `/api/subscription/checkout` endpoint. PR #245 deliberately left this tier functional (rather than blocking all of System B) since it's the one tier that *can* be granted correctly — but its price is inconsistent with the rest of the platform. Resolving this requires a decision, not a code fix:

- **(a)** Retire System B's `SUBSCRIPTION_TIERS`/`normalizeTier`/`handleSubscriptionCheckout` entirely as superseded/dead code (recommended if System A is the intended permanent vocabulary), or
- **(b)** Treat System B as the platform's future tier system and migrate `users.tier`'s schema CHECK constraint, `TIER_LIMITS`, and `PLAN_FEATURES` to support `PROFESSIONAL`/`TEAM`/`BUSINESS` at their own distinct price points and entitlement levels, reconciling the ₹49,999 vs ₹4,999 ENTERPRISE conflict as part of that migration.

Until decided, recommend blocking System B's `ENTERPRISE` checkout too (same 409 pattern) purely to prevent the 10× overcharge risk — a two-line follow-up, not implemented here because it's a pricing-policy call (does anyone want to actually sell ENTERPRISE at ₹49,999 as a distinct, higher SKU?), not a pure integrity fix.

## 6. Confirmed gaps in renewal / cancellation (missing features, not defects — not implemented, per "do not start new feature work")

- **No automated renewal exists.** `runPaymentRecovery` (`services/v24/billingEngine.js`) has an explicit `// TODO: Integrate with Razorpay subscription retry API` and only sends a reminder email. `runRenewalAutomation` (`handlers/renewalEngine.js`) is a reminder-email dispatcher only — no code path re-charges a customer. "Monthly" plans are, in practice, one-time charges requiring manual re-purchase.
- **`seedRenewalQueue35d` is dead code** — queries a `subscriptions.expires_at` column that doesn't exist on the live schema (the real column is `current_period_end`); the query throws and is silently swallowed. Only 7-day and 1-day renewal reminders can realistically fire; the 30-day/14-day windows never do.
- **Cancellation doesn't enforce expiry.** `POST /api/customer/billing/cancel` correctly sets `cancel_at_period_end=1` and preserves access until then (not an immediate hard-cancel) — but no code anywhere reads a subscription whose `cancel_at_period_end=1` and `current_period_end` has passed and actually downgrades `users.tier` or flips `subscriptions.status`. A second, KV-only downgrade-request mechanism (`monetizationV2.js`) has the same gap — nothing ever consumes the KV flag to apply a downgrade. Net effect: once cancelled, a customer keeps paid-tier entitlements indefinitely with no further charge and no automatic downgrade.
- **Untested race condition:** concurrent `/api/payments/verify` calls for the same order could insert two `subscriptions` rows (time-based, non-unique id; no `UNIQUE` constraint on `razorpay_order_id`/`payment_id` in that table).
- **Upgrade/downgrade both re-run the same checkout flow** rather than updating an existing subscription record — each successful payment does `INSERT OR IGNORE INTO subscriptions` with a fresh time-based id, so a customer who upgrades twice accumulates multiple `subscriptions` rows rather than one row that transitions state. Not a correctness bug for `users.tier` (which is always overwritten correctly) but worth noting for anyone later building subscription-history reporting off that table.

## 7. Related dashboard/reporting inconsistency (cosmetic, not an entitlement bypass)

Three parallel "what's my plan" surfaces exist and can show contradictory information for the same account when System B's vocabulary leaks in:
- `GET /api/user/plan` (`subscription.js`) — reads `authCtx.tier` raw. **Correct** for System A customers.
- `GET /api/subscription/plan` (`subscriptionPaywallEngine.js`) — always normalizes via System B's vocabulary. **Mislabels** System A customers (see §2 note).
- `GET /api/v24/trust` and related v24 dashboards — a separate, largely-unreachable subsystem, out of scope here.

---

*Cross-references: `COMMERCIAL_RISK_AUDIT_2026-07-14.md` (H1–H8, C1–C5, D1–D19 — original finding numbering), `ENTERPRISE_COMMERCIAL_PRODUCT_REGISTRY_2026-07-14.md` (product/fulfillment registry), PR #245 (H5/H8 fixes), PR #246 (Revenue Intelligence admin gate, unrelated finding surfaced during this trace).*
