# Commercial Risk Audit — Pricing, Subscription Enforcement, Entitlements, API Quotas

**Date:** 2026-07-14
**Scope:** Focused, per explicit direction, on commercial-risk areas only — pricing tiers, subscription
enforcement, entitlement/paywall checks, API quotas. This is not a full sweep of every customer-visible
capability (see `docs/audit-history/COMMERCIALIZATION_GAP_REGISTER.md` and siblings for the broader,
lower-rigor inventory this audit partially supersedes).
**Method:** Static repository analysis (grep/read across `workers/src`, `frontend/`, `workers/schema_*.sql`,
`docs/audit-history/`) plus targeted reachability checks (confirming which backend routes a real frontend
button actually calls). No endpoint was executed against a live environment; anything requiring that is
flagged **Not Verified (operational)** below, per this repo's own governance policy in `CLAUDE.md`: code,
schema, and routing outrank documentation, and no "COMPLETE"/"VERIFIED" claim is accepted without a current
repository check.
**Fix status:** Evidence-gathering only. No code has been changed by this audit. See the Remediation
Roadmap for what's proposed as safe to fix immediately vs. what needs a decision first.

---

## Executive Summary

**Recommendation: Conditional GO.** The core product (scanning, AI analysis, core API quota enforcement)
is genuinely built and gated correctly. But this audit found **5 Critical and 6 High severity findings**,
several already live and reachable by real customers today, that should be resolved — or at minimum,
consciously accepted — before treating current commercial claims as reliable.

**Highest-risk findings, in one line each:**
1. Any customer who self-serve-purchases the ENTERPRISE tier (₹4,999/month) can read the platform's
   entire internal revenue dashboard — all customers' MRR/ARR/revenue-by-source, not just their own.
2. Paid "board-ready" AI Governance compliance PDF reports have no subscription check at all, and the
   download link itself requires no login — just the URL.
3. The AI Red Team product (prompt-injection/jailbreak/agent-takeover engagements) has zero tier
   enforcement — any free signup gets unlimited access to what's sold as a paid capability.
4. The Starter plan's real, live upgrade button charges **₹499**, not the ₹999 every other page,
   pricing table, and today's own "fix Starter platform-wide" commit says it should be.
5. API key provisioning after a paid purchase appears to silently fail — the insert targets a database
   column that no longer exists in the schema.

**Customer impact:** Starter-tier customers are being charged an inconsistent price depending on which
button they click. MSSP prospects are shown between ₹9,999 and ₹75,000/month for "the same" plan
depending which page they land on, and a revenue-share pitch of "60%" that the site's own calculator
contradicts with 35–45%. Enterprise prospects are sold SSO/SAML that doesn't exist (SAML was never built).

**Revenue impact:** At minimum, an under-charging bug on Starter (finding C4) and a fully unenforced
premium AI Red Team product (C3) are leaving money on the table right now. The parallel, much-higher-priced
subscription system (H5) is not currently reachable from any frontend button — it was quietly routed
around four days ago — but it's still live and callable directly, and its very existence is a landmine.

**Security/confidentiality impact:** C1 and C2 are the two most serious — internal financial data and
paid compliance deliverables are each reachable with far less authorization than their sensitivity
warrants.

**Compliance impact:** The SSO/SAML (H3) and uptime SLA (H4) gaps are the kind of claim an enterprise
buyer's procurement/legal team would specifically check before signing — both are live, both are
contradicted by the codebase.

---

## How to read this report

Every finding carries a **Confidence** tag:
- **Verified** — confirmed directly against current code/schema/frontend content in this repository.
- **Partially Verified** — part of the claim is confirmed, part rests on evidence I could not
  independently re-derive from source (e.g., a prior internal measurement).
- **Not Verified** — flagged as a real question, not resolved either way, because confirming it needs a
  live environment check this audit didn't have access to.

Findings are ordered by business risk, not file location. Each includes root cause, evidence with
`file:line` citations, customer/business impact, and a recommended action with an estimated complexity.

---

## Critical Findings

### C1 — Internal platform-wide revenue data exposed to any Enterprise self-signup
**Confidence:** Verified (code-level) · **Category:** Security / confidentiality

Any authenticated customer whose tier resolves to `ENTERPRISE` — obtainable via ordinary self-serve
checkout at ₹4,999/month — passes the gate on `GET /api/revenue/dashboard`.

- **Evidence:** `workers/src/handlers/revenue.js:59-65,71-94` — `requirePlan(authCtx, 'enterprise')` is
  the only check; `aggregateAllRevenue()` (`workers/src/services/revenueEngine.js:637+`) returns
  platform-wide MRR/ARR/revenue-by-source/conversion-funnel/ARPU with **zero scoping to the caller's own
  account**.
- **Root cause:** The gate correctly reads the live `.tier` field (not a dead/stale one — this isn't the
  auth-field bug class found elsewhere) — the bar itself is simply set far too low for what the data is.
- **Customer impact:** None directly, but a competitor or curious party can buy visibility into the
  vendor's own confidential business metrics for the price of one Enterprise subscription.
- **Business impact:** Confidential financial data exposure. High reputational/competitive risk if it's
  ever been accessed by someone outside the company.
- **Recommended action:** Scope this route to the caller's own account data, or move it behind an
  owner/staff-only check (`isOwner()`, already used elsewhere in this codebase for internal dashboards).
  This is a customer-facing commercial change to what Enterprise "includes" — flag for a decision, not an
  auto-fix, in case platform-wide visibility was an intentional (if under-priced) Enterprise perk.
- **Complexity:** Low (one route, one auth check) once the intended behavior is confirmed.

### C2 — Paid AI Governance compliance PDF reports have no access control
**Confidence:** Verified · **Category:** Revenue leak + potential data exposure

- **Evidence:** `workers/src/handlers/aiGovernancePdfHandler.js` — `handlePdfGenerate` (lines 38-41) only
  checks `isRealUser(authCtx)`, no tier check anywhere in the file, despite the product being marketed as
  "CISO-grade," "Board-ready" (EU AI Act / NIST AI RMF / ISO 42001 / OWASP-LLM / DPDP deliverables).
  `handlePdfDownload` (line 119) takes **no `authCtx` parameter at all** — access is a bare
  `crypto.randomUUID()` capability token in the URL.
- **Root cause:** `entitlementCheck.js` defines exactly the right feature flags (`PDF_REPORTS`,
  `BOARD_REPORTS`, `REPORT_DOWNLOAD`) but this handler never calls that gate — see H6 for the broader
  pattern this is one instance of.
- **Customer impact:** Any signed-in user (any tier) can generate these reports for free. If a download
  URL is ever shared, forwarded, logged, or appears in a referrer header, anyone with the link can pull a
  customer's own compliance report with no login at all.
- **Business impact:** Revenue leak on a premium deliverable, plus a real (if narrow) customer-data
  exposure path.
- **Recommended action:** Add the existing `PDF_REPORTS`/`BOARD_REPORTS` entitlement check to
  `handlePdfGenerate`; require the download route to verify the token against the requesting user, not
  just possession of the token.
- **Complexity:** Low-to-medium — the gating mechanism already exists (`entitlementCheck.js`), this is
  wiring it in, plus deciding whether download tokens need to become user-bound (slightly more work,
  touches how links are shared/emailed today).

### C3 — AI Red Team has zero subscription enforcement
**Confidence:** Verified · **Category:** Revenue leak

- **Evidence:** `workers/src/handlers/aiRedTeam.js:108-109,222-223,270-271,312-313` and
  `workers/src/handlers/aiRedTeamPro.js:142-178` check only that a user is logged in
  (`authCtx?.userId` / `isRealUser(authCtx)`) — no tier check anywhere. Contrast: the simpler
  `/api/scan/redteam` correctly flows through the quota-checked `SYNC_ROUTES` pipeline
  (`workers/src/index.js:902-969`).
- **Customer impact:** None negative — free users get more than they're paying for.
- **Business impact:** A capability marketed/priced as premium (prompt-injection, jailbreak,
  agent-takeover engagements, MITRE ATLAS campaigns) is free to every signup. Direct, ongoing revenue
  leak, plus removes any incentive to upgrade for this specific feature.
- **Recommended action:** Add a tier check consistent with how the rest of the platform gates premium AI
  features (e.g. `PLAN_FEATURES[tier].ai_simulate`, already defined and already correctly restricted to
  PRO+ elsewhere — see `apiKeys.js:31-45` — it's just never consulted here).
- **Complexity:** Low — this is adding a well-established pattern already used successfully elsewhere in
  the same auth layer, not inventing a new one.

### C4 — Starter plan real upgrade path charges ₹499, not ₹999
**Confidence:** Verified, live, reachable — the highest-confidence finding in this audit.

- **Evidence chain (confirmed end-to-end, not just statically):**
  - `frontend/billing-portal.html:536-539` — the real "Upgrade" button calls
    `POST /api/customer/billing/upgrade` with `{ target_plan: selectedUpgradePlan }`.
  - `workers/src/handlers/enterpriseTransformHandler.js:330-396` (`handleUpgradeInitiate`) computes the
    charge at line 356: `Math.round((TIER_LIMITS[newPlan]?.price_inr ?? 0) * 100)`, and displays the same
    figure to the customer before charging at line 223 (`price_inr_month: TIER_LIMITS[plan]?.price_inr`).
  - `workers/src/auth/apiKeys.js:14` — `TIER_LIMITS.STARTER.price_inr = 499`.
  - Every other source in the codebase says ₹999: `workers/src/lib/razorpay.js:60`,
    `workers/src/handlers/subscription.js:19-29` (whose own comment says mismatch here is a
    "commercial/accounting failure"), `workers/src/config/pricingConfig.js:26`,
    `workers/src/core/revenueGate.js:57`, `workers/src/handlers/commercialPlatformHandler.js:81`,
    `workers/src/services/globalScale.js:247`.
- **Root cause:** Commit `4ea96b3` ("fix(pricing): raise Starter plan to ₹999/month platform-wide (#228)",
  merged today at 15:27) touched **49 files** across backend, frontend, docs, and a Python script, with an
  explicit commit message calling out that Starter pricing was "independently hardcoded in at least 10
  separate backend files with no shared source of truth." `workers/src/auth/apiKeys.js` was **not** among
  the 49 files changed — the one commit meant to close this exact class of bug missed the one constant
  that happens to drive a live customer charge.
- **Customer impact:** A customer upgrading to Starter via the billing portal is shown and charged ₹499;
  a customer signing up via the main pricing page's checkout flow is charged ₹999 for the identical plan.
- **Business impact:** Direct, quantifiable under-charging (~50%) on every Starter upgrade through this
  path, and a real "why was I charged differently" support/trust problem for anyone who compares notes.
- **Recommended action:** Change `apiKeys.js:14`'s `price_inr: 499` to `999`. This is completing an
  already-made, already-communicated, already-merged-elsewhere business decision (commit #228's own
  message: "Per explicit direction, Starter now starts at ₹999/month everywhere, applied immediately to
  all customers including the one existing active subscriber") — not a new pricing decision.
- **Complexity:** Trivial (one constant) — but recommend pairing with a test, since `pricingLineageGuard.
  test.mjs` (`workers/test/pricingLineageGuard.test.mjs:44-70`) already exists as exactly this kind of
  guard for PRO price consistency across 5 files, and **does not currently check STARTER, ENTERPRISE, or
  MSSP at all**. Extending it would have caught this gap before merge.

### C5 — API key provisioning appears to silently fail after a paid purchase
**Confidence:** Verified (schema/code mismatch) · Not Verified (whether this is the only/live provisioning path)

- **Evidence:** `workers/src/handlers/provisioningEngine.js:131-151` (`generateAPIKey`, called from
  `handleProvisionPurchase`) does `INSERT INTO api_keys (..., plan_id, rate_limit_daily, ...)`. The
  current `api_keys` schema (`workers/schema_master.sql`, columns confirmed) has `daily_limit`/
  `monthly_limit` — no `plan_id` or `rate_limit_daily` column exists. The insert is wrapped in a
  try/catch (lines 142-150) that swallows the failure and returns `created:false`.
- **Root cause:** Schema drift — the schema was changed at some point after this handler was written, and
  nothing caught the mismatch because the failure path returns a "soft" `false` rather than surfacing an
  error.
- **Customer impact, if this is the live path:** a customer completes a paid purchase and never receives
  a working API key, with no visible error at time of purchase.
- **What's not yet confirmed:** whether `handleProvisionPurchase` is actually invoked on the real,
  current checkout completion path, or whether a different key-issuance mechanism has superseded it (this
  codebase has a documented pattern of parallel/superseded handlers — see H5, D6 — so this needs a direct
  check before assuming every API-key customer is affected).
- **Recommended action:** Confirm which code path real customers hit today; fix the column mismatch
  regardless (it's wrong either way); consider making the failure loud (log/alert) rather than silent.
- **Complexity:** Low for the column fix itself; the "which path is live" question needs a live-environment
  check, not a code read, before scoping the fix further.

---

## High Findings

### H1 — MSSP monthly price shown as 6 different numbers across marketing pages
**Confidence:** Verified

₹9,999 (`frontend/index.html` `#pricing`, Threat-Intel storefront, JSON-LD, `upgrade.html`,
`sentinel-apex-marketplace.html`, `services.html`'s own comparison table at `services.html:905`) · ₹49,999
(`index.html:6469` "MSSP White-Label" card, `index.html:6665` "MSSP Gold" option, `services.html:875` — on
the *same page* as the ₹9,999 figure 30 lines above — and `contact.html:961`'s FAQ answer) · ₹75,000
(`mssp.html:244-278`, labeled "MSSP PARTNER") · ₹25,000 (`mssp.html:244-259`, labeled "ENTERPRISE," in the
same pricing section as the ₹75,000 figure) · ₹14,999 (`index.html:6663`, `developer-onboarding.html:294`,
`mssp-onboarding.html:7`) · ₹29,999 (`index.html:6664`, "MSSP Silver").

**Business impact:** An MSSP prospect reading two different pages — or in `services.html`'s case, one page
— cannot know what they'd actually be charged. **Recommended action:** pick one number, one name, per
tier; audit every page listed above against it. **Complexity:** Medium — this is a content/consistency
pass across ~8 files, not a logic change, but needs a decision on which figure is authoritative first.

### H2 — MSSP revenue-share percentage shown as 5 different numbers, contradicting itself on one page
**Confidence:** Verified

30% (`index.html:6211` comparison table) · 50% (`index.html:6475,6607`, `upgrade.html:202`,
`mssp-onboarding.html:156`) · 60%/"60-40" (`mssp.html` — title tag, meta description, og:description,
twitter:description, hero stat, and pricing card: six separate mentions) · 35–45% tiered (`mssp.html:349`
— **the same page's own live, working revenue calculator**) · 40%/50% hedged (`mssp-onboarding.html:233`).

**Business impact:** `mssp.html` markets "you keep 60% of every subscription" in six places while its own
calculator, on the same page, computes 35–45%. This is the kind of concrete, provable discrepancy a
signing MSSP partner could reasonably treat as a broken promise. **Recommended action:** align the
marketing copy to whatever the calculator actually computes (or vice versa, if 60% is the intended real
number and the calculator is wrong). **Complexity:** Medium — same "which number is real" decision as H1.

### H3 — Enterprise tier advertises "SSO/SAML"; SAML does not exist
**Confidence:** Verified (both the live claim and the implementation gap)

- **Live claim:** `frontend/index.html:6197` (comparison table, Enterprise column) and
  `frontend/upgrade.html:186` both show "SSO/SAML" as an included Enterprise feature, today.
- **Implementation:** repo-wide search for `SAML` returns zero matches in `workers/`. Only OIDC exists
  (`workers/src/lib/oidc.js`, `handlers/ssoAuth.js`, `handlers/enterpriseSsoHandler.js`), and
  `oidc.js:8-10`'s own comment frames this as a deliberate choice: "not SAML 2.0... a hand-rolled SAML
  signature verifier is a security liability."
- **Business/compliance impact:** This is exactly the kind of claim an enterprise buyer's security/
  procurement review checks before signing. The underlying engineering decision (OIDC over hand-rolled
  SAML) is reasonable; advertising SAML anyway is not.
- **Recommended action:** Either change "SSO/SAML" to "SSO (OIDC)" on both pages, or scope and build real
  SAML support if it's a genuine deal-blocker for target customers — a commercial/product decision, not
  something to silently pick between.
- **Complexity:** Trivial for the copy fix; large (new protocol implementation) if SAML itself is required.

### H4 — 99.9% uptime SLA advertised; internal measurement puts it at ~95–96%
**Confidence:** Partially Verified — the claim being live today is Verified directly; the ~95–96% actual
figure is sourced from this platform's own recent internal audits, not independently re-measured here.

- **Live claim:** `frontend/index.html:6197`, `frontend/upgrade.html:186`, `frontend/mssp-onboarding.
  html:159` all show "99.9% Uptime" today, with no linked SLA document or uptime history to substantiate it.
- **Internal contradiction:** `docs/audit-history/ENTERPRISE_OPERATIONS_READINESS_2026-07.md` and
  `ENTERPRISE_ACCEPTANCE_CERTIFICATION_2026-07.md` both measured real uptime around 95–96% and flagged the
  marketed figure as an open "HIGH (trust)" gap, with an explicit "do not sign SLAs until closed" note.
  Separately, `FINAL_PRODUCTION_COMMERCIAL_RELEASE_2026-07.md` documents (and reports fixing) a case where
  the Trust Center hardcoded 99.9% and displayed it even when the real uptime API returned `no_data`.
- **Recommended action:** Before this claim is used in any contract or renewed marketing push, confirm
  current real uptime and either substantiate the number or soften the claim.
- **Complexity:** Low for the copy (if softening); the measurement/infrastructure work to genuinely hit
  99.9% is a separate, larger conversation.

### H5 — A second, parallel subscription/pricing system exists, with incompatible prices and a database-constraint mismatch
**Confidence:** Verified (mechanism) · Verified (currently unreachable from any frontend button I found)

- **What it is:** `workers/src/handlers/subscriptionPaywallEngine.js` defines its own tier taxonomy
  (COMMUNITY/PROFESSIONAL/TEAM/BUSINESS/ENTERPRISE — its own docblock, lines 14 and 25, calls this the
  "authoritative"/"single source of truth" definition), live-routed at `POST /api/subscription/checkout`
  (`workers/src/index.js:8039`). `normalizeTier()` (lines 99-106) maps the platform's real tier names onto
  it: `STARTER→PROFESSIONAL` (charged ₹1,499, not ₹499/999), `MSSP→ENTERPRISE` (charged ₹49,999, not
  ₹9,999), `ENTERPRISE→ENTERPRISE` unchanged (charged ₹49,999, not ₹4,999).
- **Database mismatch:** `users.tier` has `CHECK (tier IN ('FREE','STARTER','PRO','ENTERPRISE','MSSP'))`
  (`workers/schema_master.sql:38-43`). `'PROFESSIONAL'`/`'TEAM'`/`'BUSINESS'` are not valid values. The
  webhook that grants the tier after payment (`workers/src/handlers/payments.js:1056-1067`) catches and
  only logs any resulting SQL error — meaning, if this path were ever hit for a STARTER or PRO purchase,
  Razorpay would capture the payment and the tier grant would silently fail.
- **Reachability, confirmed:** I found exactly one frontend reference to a similarly-named endpoint
  (`frontend/user-dashboard.html:4839`), and its own comment states it was migrated **away** from
  `/api/subscription/create` four days ago (2026-07-10) onto a third, different endpoint
  (`/api/payments/create-order`) specifically because the subscription-family endpoints were "equally
  broken." No frontend file references `/api/subscription/checkout` at all. This finding is therefore a
  live, armed, but currently un-triggered risk from the UI's perspective — reachable only via a direct API
  call (a script, a partner integration, a future frontend change that reintroduces it).
- **Business impact:** If ever invoked — by a future frontend change, a direct integration, or a curious/
  malicious direct API call — this either overcharges a real customer by 3–10x, or charges them and fails
  to grant what they paid for.
- **Recommended action:** This is architectural (a whole second, incompatible pricing/tier system), not a
  small fix — per this repo's own governance policy, documenting and proposing a plan here rather than
  auto-implementing anything. Options worth deciding between: (a) delete the dead system if it's genuinely
  unused, (b) disable the route until it's reconciled with the real tier system, or (c) if PROFESSIONAL/
  TEAM/BUSINESS represent a real, intended *future* product line, reconcile the naming/pricing and fix the
  schema constraint before wiring it to anything.
- **Complexity:** Needs a decision before any implementation estimate is meaningful.

### H6 — The platform's apparent canonical entitlement-flag system is never actually consulted
**Confidence:** Verified

- **Evidence:** `PLAN_FEATURES` and `hasAccess(feature, plan)` (`workers/src/auth/apiKeys.js:31-52`) —
  named directly in this audit's own scoping request as "the" subscription-feature mechanism — is exported,
  imported exactly once (`workers/src/handlers/subscription.js:7`), and used there only to render
  self-service *display* text, never to actually block a request. A full-repo search found no other call
  site.
- **What this explains:** every real enforcement decision in the codebase is instead a separate, ad hoc
  `if (tier === ...) return 403` written per-handler — which is exactly why enforcement quality varies so
  much finding-to-finding in this report (some handlers got it right, some forgot, some check a stale
  field, some check the wrong table).
- **Recommended action:** Not a quick fix — either retire `PLAN_FEATURES`/`hasAccess()` since it isn't the
  real mechanism (and stop describing it as such anywhere it's documented that way), or make it the real
  mechanism by routing the ad hoc checks through it. Either is an architectural decision affecting many
  files; flagging for prioritization, not auto-implementing.
- **Complexity:** High if consolidating; low if simply correcting documentation to describe what's
  actually true today.

---

## Medium Findings

| # | Finding | Evidence | Confidence |
|---|---|---|---|
| M1 | Starter scan limit self-contradicts on one page: pricing card says "10 scans/month," the same page's comparison table says "50/day" (~1,500/month) — a 150x gap | `frontend/index.html:6099` vs `:6163` | Verified |
| M2 | Pro scan limit self-contradicts: card says "Unlimited," same-page table caps at 500/day | `frontend/index.html:6116` vs `:6163` | Verified |
| M3 | Three mutually irreconcilable API rate-limit schemes for "the API" across pages (different units, don't reconcile after conversion) | `index.html:6240-6306` + `sentinel-apex-marketplace.html:118-125` vs. `api-docs.html:391-416` vs. `developer-onboarding.html:260-294` | Verified |
| M4 | `checkRateLimitV2`/`checkRateLimitCost` read the wrong tier table (`TIERS`, 3 tiers) instead of the canonical `TIER_LIMITS` (6 tiers) — STARTER/MSSP/COMMUNITY customers silently capped at FREE's 5/day on routes gated this way (under-serves paying customers, not a bypass) | `workers/src/middleware/rateLimit.js:7,47-98,131-175` vs. `workers/src/middleware/auth.js:14-18` | Verified |
| M5 | `commercializationEngine.js`'s feature-gates display endpoint reads `authCtx.role` (an admin-role field, never a subscription tier) as if it were one — real paying customers see paid features reported as "denied"; appears display-only, not an actual block | `workers/src/handlers/commercializationEngine.js:313,336` (also 153, 259) | Verified (display bug) / Not Verified (whether anything ever consumes it to block a request) |
| M6 | `PLAN_PRICES.MSSP = 0` shown on the real `GET /api/customer/license` response | `workers/src/handlers/commercialPlatformHandler.js:81,218` | Verified |
| M7 | Post-scan upsell copy hardcodes wrong prices: "Upgrade to STARTER" quotes ₹199, "Upgrade to PRO" quotes ₹999 (should be ~999 and ~1,499 respectively) | `workers/src/core/cyberBrain.js:70,81,92` | Verified |
| M8 | Starter USD price self-contradicts within `index.html` itself ($12 in structured data vs. $6 in the actual upgrade-CTA string, from two different inline scripts on one page) | `frontend/assets/geo-currency-router.js:52,71` vs. `frontend/index.html:23228` | Verified |
| M9 | "Professional" used as a plan name for two different real prices depending on the page | `frontend/developer-onboarding.html:292` (₹1,499) vs. `frontend/mssp.html:325,348` (₹4,999) | Verified |
| M10 | `sentinel-apex-marketplace.html` self-contradicts: meta/hero/JSON-LD say Starter = ₹499/month; the same page's own rendered plan cards say ₹999 | `sentinel-apex-marketplace.html:16,355,62-67` vs. `:1059-1060,1072` | Verified |
| M11 | Vibe Code Scanner unlock CTA links to `/pricing`, a route that doesn't exist anywhere in routing | `frontend/api-docs.html:745-756` | Verified |
| M12 | MSSP tenant handlers `handleGetTenant`/`handleDeleteTenant` omit the tier re-check sibling handlers have (not cross-tenant exploitable, still scoped to caller's own records) | `workers/src/handlers/msspTenantPlatform.js:807-823` vs `:763-805` | Verified |
| M13 | Enterprise annual price inconsistency: promo modal claims "₹49,999/yr" vs. ₹59,988 actual (12×₹4,999/mo) and vs. the platform's own computed ₹49,990 | `frontend/index.html:22905` vs. `frontend/assets/geo-currency-router.js:25` | Verified |
| M14 | Two different "Red Team" branded one-time products (₹24,999 general pentest vs. ₹99,999 AI-specific) with no cross-reference between the pages that sell them | `frontend/services.html:823-824` vs. `frontend/ai-security-services.html:383` | Verified |
| M15 | Unsourced, suspiciously specific marketing statistics ("14% CAGR," "3.4 million unfilled positions," ROI calculator's "27% breach probability / 23% cost reduction") | `frontend/mssp.html:288`, `frontend/sentinel-apex-marketplace.html:471` | Not Verified — flagged on the same pattern as this repo's own previously-fixed "340%/12% YoY" fabrication |

---

## Documentation Drift Register

Per this repo's governance policy (`CLAUDE.md` §2): every "COMPLETE"/"VERIFIED" claim found in
`docs/audit-history/` that touches pricing, subscriptions, entitlements, or quotas, checked against
current code.

| # | Source doc | Claim | Status | Why |
|---|---|---|---|---|
| D1 | `COMMERCIALIZATION_GAP_REGISTER.md` | "Invoice Generation ✅ VERIFIED COMPLETE — `billing_invoices` table" | **Contradicted** | Real engine uses the `invoices` table, not `billing_invoices` — already corrected in PR #230 |
| D2 | `COMMERCIALIZATION_GAP_REGISTER.md` | "API Rate Limiting ✅ VERIFIED COMPLETE — `rate_limit_daily` column" | **Contradicted** | Column doesn't exist in current schema — same root cause as C5 |
| D3 | `COMMERCIALIZATION_GAP_REGISTER.md` / `SENTINEL_APEX_COMMERCIALIZATION_REPORT_V2.md` | "API Key Generation ✅ COMPLETE" | **Contradicted** | Same root cause as C5 |
| D4 | `COMMERCIALIZATION_GAP_REGISTER.md` | "Entitlement Schema/Grant/Expiry ✅ VERIFIED COMPLETE" | **Verified** | `customer_entitlements` schema genuinely matches its consumers |
| D5 | `COMMERCIALIZATION_GAP_REGISTER.md` | "Renewal Queue/Payment Recovery ✅ VERIFIED COMPLETE" | **Partially Verified** | Code exists; a later internal doc (`PHASE4_CUSTOMER_SUCCESS_READINESS_2026-07.md`) states no live renewal cycle has ever run |
| D6 | `RELEASE_BLOCKER_PROGRAM_2026-07.md` | "PL-1: PRO shown ₹1,499, charged ₹2,999 — CRITICAL, OPEN" | **Outdated/Superseded** | Now fixed; the ₹2,999 source (`monetizationV2.js`) is confirmed orphaned/unimported |
| D7 | Multiple June docs | "Starter ₹499/mo" | **Outdated** | Superseded by commit #228 today — though see C4, the fix was incomplete |
| D8 | `SENTINEL_APEX_COMMERCIALIZATION_REPORT_V2.md` | "100% Production-Grade · 100% Revenue-Ready · Entitlement System 10/10" | **Contradicted** | Directly at odds with C1–H6 above and with this platform's own later self-audits |
| D9 | `SENTINEL_APEX_COMMERCIALIZATION_REPORT_V2.md` | "SIEM export gate (TEAM+) ✅ COMPLETE" | **Outdated/Superseded** | TEAM isn't a purchasable tier; gate later moved to PRO |
| D10 | `EXECUTIVE_CERTIFICATION_SCORECARD.md` vs. `COMMERCIALIZATION_GAP_REGISTER.md` (48 hrs apart) | "MSSP Multi-Tenant: 1/7 FAIL" vs. "✅ VERIFIED COMPLETE" | **Contradicted (doc-internal)** | Two of the repo's own audits, two days apart, rate the same capability oppositely |
| D11 | `COMMERCIALIZATION_GAP_REGISTER.md` / `SENTINEL_APEX` v1+v2 | "MSSP White-Label ✅ COMPLETE/OPERATIONAL" | **Partially Verified** | Real code exists, but the MSSP admin console's actual access control was a hardcoded shared password for another month after "complete" |
| D12 | `RBAC_PHASE_0_REPORT_2026-07.md` | "...hardcoded shared password [on mssp-command-center.html]...Fixed" | **Verified** | Confirmed: `frontend/mssp-command-center.html:648-654` now uses a real server-verified session gate |
| D13 | `ENTERPRISE_READINESS_REPORT.md` | Enterprise sold with "SSO/SAML" | **Contradicted** | See H3 — confirmed still a live, active claim, not just historical |
| D14 | `FEATURE_COMPLETION_MATRIX.md` | "SSO/SAML — 5% — Broken/Fake" | **Partially Verified/Outdated** | SAML half still accurate; SSO/OIDC half has since been genuinely built and tested |
| D15 | `PHASE4_GLOBAL_RELEASE_DECISION_2026-07.md` | "SSO/OIDC + MFA — code-path proven, no live IdP round-trip yet" | **Verified (code) / Not Verified (operational)** | Test files genuinely exist; whether a live round-trip has since happened isn't determinable from source |
| D16 | `ENTERPRISE_READINESS_REPORT.md` | "99.9% uptime SLA," "99.94%/99.87% last 30/90 days" | **Contradicted** | See H4 |
| D17 | `ENTERPRISE_READINESS_REPORT.md` | Sales kit: SIEM integrations include "JIRA, ServiceNow" | **Partially Verified** | Splunk/Elastic/Sentinel/AWS Security Hub genuinely supported; JIRA/ServiceNow not found anywhere in code |
| D18 | `PHASE4_REMEDIATION_REPORT_2026-07.md` | "Per-minute limits unenforced on unlimited-daily tiers — Fixed" | **Verified** | Current `rateLimit.js` matches the claimed fix |
| D19 | `MASTER_PLATFORM_AUDIT.md` | "Subscription Management — PARTIAL, KV only, no persistent billing" | **Outdated** | Now D1/Razorpay-backed — though the *next* doc's "100%" framing of that build-out (D8) was itself premature |

---

## Confirmed Working

Not everything in scope is broken — recorded here per the governance policy's instruction to state
plainly when a section's outcome is "no significant findings," rather than padding it.

- **Core scan API quota enforcement** — real and correctly wired: every core scan/report route runs
  through `enforceQuota()`/`checkRateLimitV2()` before the handler executes (`workers/src/index.js:914-969`).
- **SSO/OIDC configuration endpoints** — properly gated to owner/admin only
  (`workers/src/auth/middleware.js:356-361`, applied at `index.js:1968-1973,2022-2025`).
- **White-label/MSSP branding** — two independent implementations both check live tier/role fields
  correctly (`handlers/whiteLabelMSSP.js:58-97`, `handlers/msspPanel.js:27-33`).
- **MSSP multi-tenancy** — ~20 handlers correctly scoped by `partner_id` (one minor gap, M12).
- **ADMIN_KEY bypass** — well-contained; no divergent copies found; never broadens what a customer can
  reach beyond an already-legitimate paid-tier path.
- **`customer_entitlements` schema** — genuinely matches its real consumers (D4).
- **PRO price (₹1,499)** — the one tier that's fully consistent everywhere checked, and the only one with
  a CI guard (`pricingLineageGuard.test.mjs:44-70`) actually protecting it.
- **One-time package pricing** (compliance packs, Security Assessment/Threat Intel Report/Annual Retainer)
  — consistent across every page checked.
- **Per-minute rate-limit enforcement** — confirmed fixed and correct (D18).
- **MSSP command-center access control** — confirmed fixed; no longer a hardcoded shared password (D12).

---

## Remediation Roadmap

**Proposed as safe to implement immediately** (self-contained, objectively correct, backward-compatible,
completes an already-approved decision) — each as its own small, separately-tested PR per governance
policy, not bundled together:
1. C4 — `apiKeys.js` Starter price 499→999, plus extend `pricingLineageGuard.test.mjs` to also cover
   STARTER/ENTERPRISE/MSSP (closing the exact gap that let C4 ship).
2. M6 — `commercialPlatformHandler.js` `PLAN_PRICES.MSSP` 0→9999.
3. M7 — `cyberBrain.js` upsell copy prices corrected to match `TIER_LIMITS`.

**Needs a decision before implementation** (architectural, or the "right" answer depends on business
intent this audit can't infer):
- H5 — what to do with the parallel `subscriptionPaywallEngine.js` system (delete / disable / reconcile).
- H6 — whether to retire or actually wire up `PLAN_FEATURES`/`hasAccess()`.
- C1 — what Enterprise's revenue-visibility perk was actually supposed to be, if anything.
- H1/H2 — which MSSP price and revenue-share number is the real one, across ~8-10 pages.
- H3/H4 — whether to fix the SSO/SAML and uptime copy, or invest in making the claims true.

**Needs a live-environment check before scoping further:**
- C5 — confirm whether `provisioningEngine.js`'s broken insert is on the actual current checkout path.
- H5 — confirm no non-frontend integration calls `/api/subscription/checkout`.
- D5/D15 — whether a real subscription renewal or live IdP round-trip has ever actually occurred.

**Recommended immediate fixes for C2, C3, M4, M5, M12** — each self-contained and low-risk once
prioritized, but not implemented in this pass; sequencing left to the roadmap above (one production
problem per PR).

---

## Scope note

This audit covered pricing/tier definitions, advertised commercial claims, and server-side entitlement/
quota enforcement — the areas prioritized as highest commercial/legal risk. It did not attempt the full
30-capability sweep this audit's originating brief described (AI modules, compliance frameworks, dashboard
widgets, digital downloads, etc.) — see this document's header for the explicit scoping decision behind
that. Several findings above (C5, H5) explicitly flag operational facts a live-environment check would be
needed to fully close.
