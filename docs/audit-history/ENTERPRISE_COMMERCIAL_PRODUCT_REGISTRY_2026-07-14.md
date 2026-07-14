# Enterprise Commercial Product Registry

**Date:** 2026-07-14
**Scope:** Every purchasable SKU on the platform — subscription tiers, MSSP partner program, one-time
reports/assessments, enterprise packages, the "v24" internal revenue subsystem, the Sentinel APEX
intelligence marketplace, and the two-and-a-half competing "defense solutions" systems. This document
supersedes nothing; it extends `COMMERCIAL_RISK_AUDIT_2026-07-14.md` (pricing/subscription/entitlement
scope, H1-H8/C1-C5/D1-D19) into product *delivery* and *fulfillment*, which that document's own scope note
explicitly did not cover.
**Method:** Static repository analysis (four parallel research passes covering ~90 files across
`workers/src/`, `frontend/`, `workers/schema_*.sql`) plus targeted reachability checks — confirming which
backend routes a real frontend button actually calls, and which routes are live but frontend-orphaned.
Every claim below is file:line-cited in the underlying research; this document reports conclusions, not raw
transcripts. No endpoint was executed against a live environment — anything requiring that is tagged **Not
Verified (operational)**.
**Fix status:** Three PRs landed during this pass (see "Fixes implemented this pass"). Everything else is
evidence-gathering; nothing described as a "finding" below has been auto-implemented without explicit
governance-policy justification.

---

## Executive Summary

**Recommendation: Conditional GO**, unchanged in direction from the prior commercial-risk audit but with a
materially different reason. The subscription/MSSP pricing questions (H1) are now resolved. The new
material risk this pass surfaced is **not pricing inconsistency — it's that several secondary,
frontend-orphaned checkout/fulfillment systems were built without the security hardening the main
`payments.js` path has**, and one of them (`v24Handler.js`) has two routes that let a caller get paid
content for free or mint fake tax invoices, with no auth at all.

**Highest-risk findings, one line each:**
1. **`POST /api/v24/scanner/fulfill`** has no authentication and no payment verification — it marks any
   order "paid" unconditionally, letting anyone self-issue and fetch a paid report for free.
2. **`POST /api/v24/billing/invoice/create`** requires only *any* logged-in user (not admin) and mints a
   real, sequentially-numbered GST tax invoice with `status='paid'` hardcoded — no payment check at all.
3. **`revenue.js`'s `handleCheckoutVerify`** could previously skip signature verification entirely by
   simply omitting `razorpay_order_id`/`razorpay_signature` from the request — **fixed this pass**.
4. **`revenue.js`'s `handleCheckoutInitiate`** trusts a client-supplied price with no catalog cross-check —
   the same vulnerability class this codebase already found and fixed once elsewhere (`payments.js`'s
   `module:'defense'` removal) has a second, still-open instance here.
5. Seven payment-verification handlers used a non-constant-time signature comparison instead of the
   already-existing, correct canonical helper — **fixed this pass**.
6. **`subscriptionPaywallEngine.js`** (H5, already known, still awaiting a disposition decision) — refreshed
   with exact schema evidence this pass: 3 of its 4 paid tiers would **always**, not intermittently, fail a
   live database CHECK constraint on grant, silently, after a real charge.

None of items 1, 2, 4, or 6 are fixed yet — see "Needs a decision" and "Needs prioritization" below. None of
the newly-found gaps are confirmed reachable from any shipped frontend page; all are reachable by direct
API call today, which is the same risk profile this codebase has already classified elsewhere (H5) as "a
live, armed risk rather than active harm" — real, but not yet a confirmed customer-impacting incident.

**Customer impact today:** Low-to-none confirmed — no shipped UI element triggers any of the four unfixed
critical items. **Revenue integrity impact:** Real but unquantified — items 1 and 2 could be used to obtain
free product or fabricate revenue-ledger entries if anyone finds and calls them directly; item 4 could
under-charge for a real purchase. **Compliance impact:** Item 2 (fabricated GST invoices) and the confirmed
GST-invoice gap in `marketplaceCheckoutHandler.js` (promised on-page, never generated) are both real,
concrete tax-documentation integrity problems, independent of whether anyone has exploited them yet.

---

## Part 1 — Payment-Verification Path Master Map

Sixteen distinct payment-verification code paths exist across the platform. Eight reuse the canonical,
tested `verifyPaymentSignature()`/`verifyWebhookSignature()` (`workers/src/lib/razorpay.js`). Seven
hand-rolled their own HMAC check — all seven now use the canonical constant-time comparison as of this
pass (see "Fixes implemented"). One (`v24Handler.js`'s scanner fulfillment) performs no verification at all.

| # | Handler : function | Route | Verification | Reachable from shipped UI? | Status |
|---|---|---|---|---|---|
| 1 | `payments.js handleVerifyPayment` (scan modules: domain/ai/redteam/identity/compliance) | `POST /api/payments/verify` | Canonical | Yes | Working, with one caveat (see Part 2) |
| 2 | `payments.js handleVerifyPayment` (subscription) | same | Canonical | Yes | Working (H8 allow-list gap fixed for `MSSP_PARTNER` in the previous session; `ENTERPRISE_SOC` still has it — see Part 4) |
| 3 | `payments.js handleRazorpayWebhook` | `POST /api/webhooks/razorpay` | Canonical | Razorpay-side | Working; partial safety net for subscription grants, none for report generation |
| 4 | `subscriptionPaywallEngine.js` → webhook tier-grant block | `POST /api/subscription/checkout` | Canonical | **No frontend caller found** | **Confirmed gap** — 3 of 4 tiers always fail a live DB CHECK constraint silently (H5, refreshed) |
| 5 | `marketplaceCheckoutHandler.js handleMarketplaceVerify` | `POST /api/marketplace/verify` | Canonical | Yes | Working, GST-invoice gap (Part 3) |
| 6 | `defenseMarketplace.js handleVerifyPurchase` | `POST /api/defense/verify/:id` | Was hand-rolled, non-constant-time → **fixed this pass** | Yes | Working; weak error handling on partial D1 failure (no reference given to a paying customer) |
| 7 | `msspOnboardingHandler.js handleMsspVerify` | `POST /api/mssp/onboarding/verify` | Canonical | Yes | Working; narrow edge case (`mssp_partners` linkage is best-effort, no webhook safety net) |
| 8 | `toolsMarketplace.js handleVerifyTool` | `POST /api/tools/verify` | Was hand-rolled, non-constant-time → **fixed this pass** | Yes | Working |
| 9 | `academyMarketplace.js handleVerifyAcademy` | `POST /api/academy/verify` | Was hand-rolled, non-constant-time → **fixed this pass** | Yes | Working (already self-hardened for delivery-tracking in a prior session) |
| 10 | `sentinelMarketplace.js handleSentinelVerify` | `POST /api/sentinel/verify` | Was hand-rolled, non-constant-time → **fixed this pass** | Yes | Working; entitlement is a bare KV flag, not an API-key/tier change — manual delivery by design |
| 11 | `growth.js handleBillingCallback` | `POST /api/billing/callback` | Was skippable (fail-open on missing secret) + a separate body-read-ordering bug that made the secure branch throw on every real call → **both fixed this pass** | No frontend/live caller found | Fixed; a further, structural design question (HMAC over a body that includes the signature field itself) is out of scope for this pass — see Part 4 |
| 12 | `revenue.js handleCheckoutVerify` | `POST /api/checkout/verify` | Was fully skippable by omitting order_id/signature → **fixed this pass** | No frontend caller found | Fixed |
| 13 | `enterpriseLayer.js handleVerifyEnterprisePayment` | `POST /api/enterprise/verify` | Was hand-rolled, non-constant-time → **fixed this pass** | No frontend caller found | Fixed; lower risk by design (manual/consultative fulfillment) |
| 14 | `sentinelApexMarketplace.js handleMarketplaceWebhook` | `POST /api/marketplace/webhook` | Canonical, or admin override | Confirmed live | Working |
| 15 | `v24Handler.js` scanner fulfillment | `POST /api/v24/scanner/fulfill` | **None at all** | No frontend caller found | **Confirmed critical gap — unfixed** |
| 16 | `v24Handler.js` PayPal capture | internal to `v24/billingEngine.js` | Real PayPal API call | No frontend caller found | Likely inert — `PAYPAL_CLIENT_ID`/`SECRET` not documented as provisioned in `wrangler.toml` (Not Verified against live secrets) |

---

## Part 2 — One-time Reports & Enterprise Packages

**Working, automated, no drift:** `domain` report (₹999) is the one product class with genuine automated,
instant delivery (report generated, stored to R2, download token issued) and honest failure handling if
storage or generation fails. `SECURITY_ASSESSMENT` (₹9,999), `THREAT_INTEL_REPORT` (₹14,999), and all 14
AI/MCP assessment SKUs in `razorpay.js PACKAGE_PRICES` (`AI_SECURITY_ASSESSMENT` ₹49,999 through
`ENTERPRISE_ASSESSMENT` ₹49,999 — full list in Appendix A) are price-consistent everywhere they're quoted
and route correctly to Razorpay, but fulfillment for all of them is an **acknowledged, honest manual
process** ("our team will contact you within 24–72 hours") — a real difference in kind from the automated
`domain` report, worth registry-flagging but not a bug.

**Drift found, contained:**
- `ai`/`redteam`/`identity`/`compliance` reports: the real charged price (`razorpay.js MODULE_PRICES`:
  ₹2,499/₹4,999/₹799/₹499) disagrees with `pricingConfig.js`'s `reports{}` block (₹999/₹999/₹699/₹799) —
  but that block is confirmed **not read by any live charge or display path** (orphaned/stale config that
  itself falsely comments "must match MODULE_PRICES exactly"). Recommend deleting or correcting it so it
  can't mislead a future engineer into trusting it — flagged, not touched this pass (content-only, low risk,
  but not part of the security-hardening this pass prioritized).
- Two independent post-scan upsell UI code blocks in `index.html` (`buildIntelligenceInsightPanel()`,
  `showUpgradeTrigger()`) pair the wrong price label with the wrong amount for `ai`/`identity`/`redteam` —
  contained because the server always re-prices by module from the real `MODULE_PRICES` table regardless of
  what the button displayed; the customer is never actually charged the mislabeled amount.
- A **paise-recorded-as-rupees bug**: if a customer falls back to manual payment from the post-scan upsell
  CTA specifically, the manual-payment ledger records the raw paise value as if it were rupees (~100x
  inflation of that one record's `amount_inr`), corrupting `total_revenue_inr` reporting for that path only.
  Real charges via the automated Razorpay flow are unaffected.

**Phantom SKUs — priced, unbuyable:** `cloudsec`, `darkscan`, `appsec`, `full` reports and the
`MSSP_WHITE_LABEL` package are defined with prices in `pricingConfig.js` (and, for the four reports, also in
`frontend/assets/geo-currency-router.js`) but have no `MODULE_PRICES`/`PACKAGE_PRICES` entry and no working
checkout button anywhere. `handleCreateOrder` would reject any of the four report modules outright with 400.
Classification: **Dead** (reports) / **Commercial Placeholder** (MSSP_WHITE_LABEL — has a real package
definition and a card on `index.html`, but the CTA is "Apply as MSSP Partner," a lead form, not a checkout).

**ID-naming mismatch (real risk, low likelihood):** `manualPayments.js` calls the two annual tiers
`STARTER_PLUS_ANNUAL`/`PROFESSIONAL_ANNUAL`; `proposalGenerator.js` calls the same-priced products
`STARTER_PLUS`/`PROFESSIONAL`. Since `manualPayments.js`'s activation lookup is an exact-key match, a manual
payment submitted under the proposal tool's ID spelling would silently fail to auto-activate the plan on
admin approval — the payment itself isn't lost, just the automation.

**Latent trap, not currently reachable:** `razorpay.js MODULE_PRICES.threat_intel`/`.red_team` (lowercase,
directly module-keyed, ₹14,999/₹24,999) can be create-ordered successfully but `handleVerifyPayment`'s
module allow-list doesn't include either key — a real charge that can never complete verification. No
frontend call site sets `module:'threat_intel'`/`'red_team'` directly today (the same-named uppercase
`package`-keyed products work fine and are what real buttons use).

---

## Part 3 — Sentinel APEX Marketplace & "Defense Solutions" (three systems sharing two names)

**Sentinel APEX** is actually three files: `intelMonetization.js` (tier/rate-limit engine for the read API,
`FEED_TIERS` numerically identical to the main platform's STARTER/PRO/ENTERPRISE/MSSP prices — Not Verified
whether that's an intentional unified ladder or coincidence), `sentinelApexMarketplace.js` (a USD
`PRODUCT_CATALOG` whose own code comment admits none of its 5 write-actions have a frontend caller —
**confirmed dead**), and `sentinelMarketplace.js` (the file the "Buy Report" buttons actually call — real,
server-trusted pricing, real HMAC verification now hardened this pass, working, but fulfillment is a bare
365-day KV access flag plus a 4-hour manual delivery promise, not an automated download or tier change).

**"Defense solutions"** turns out to be **three** competing systems, not one:
- **`marketplaceCheckoutHandler.js`** — actually the Sentinel APEX *Intelligence* Marketplace (detection
  packs, playbooks, intel reports, compliance packs, AI agents — 12 SKUs, ₹999–₹9,999). Real, tamper-tested
  pricing (explicit test asserts a ₹1 tamper attempt is rejected). Fulfillment is honest by category: real
  API keys minted for `ai_agent` SKUs, live-generated reports/compliance assessments for 2 categories, and
  an **honestly disclosed** `manual_pending` for `detection_pack`/`playbook` (no automated authoring engine
  exists — acknowledged in-code, not papered over). **Confirmed gap:** the checkout page tells customers
  *"Invoice sent automatically"* / *"GST invoice included"* but the verify handler never calls the shared
  `createInvoice()` — a real promise-vs-reality gap, same class as issues this codebase has fixed before.
  Only 2 of 12 SKUs have a confirmed live page link; the other 8 are reachable only by constructing the URL.
- **`defenseMarketplace.js`** — the more literally-named Defense Solutions catalog (5 real, D1-backed,
  per-CVE firewall/IDS/Sigma/YARA/hardening tools, ₹599–₹999). Confirmed frontend-wired from `index.html`
  and `tools.html`. Correctly calls `createInvoice()`. **Confirmed working**, with one weaker spot: a
  multi-write grant (`Promise.all` with no per-item error handling) means a partial D1 failure after
  Razorpay has already captured payment returns a bare 500 with no order reference for the customer to
  follow up with — worse UX than the main path's equivalent failure, not a lost payment.
- **`revenue.js`** — a third `/api/defense/catalog` + `/api/checkout` pathway. `handleCheckoutInitiate`
  reads the charge amount directly from `body.price` with **no cross-check against any catalog** — the
  exact vulnerability class this codebase already found and fixed once (the `payments.js module:'defense'`
  removal) has a second, unpatched instance here. No confirmed frontend caller, but reachable by direct
  call today. **Not fixed this pass** — flagged as the clear next priority (see Part 5).

---

## Part 4 — The "v24" Subsystem

A tenth-phase internal revenue engine (`v24Handler.js` + `services/v24/{billingEngine,platformEngine,
salesOS}.js`), live-routed at `/api/v24/*` but **confirmed unreachable from any shipped frontend page** —
exhaustive grep across `frontend/**/*.html` and `frontend/assets/**/*.js` found zero real callers. Its own
`/api/v24/health` endpoint over-reports capability: 4 of the 10 phases it advertises (`mssp`, `cs_ai`,
`defense_pipeline`, `api_economy`) have no route implementation in the file at all.

**What it does correctly:** `v24/billingEngine.js`'s `createInvoice()` is the genuine, canonical,
already-consolidated GST invoice engine for the *entire* platform (confirmed called from `payments.js`,
`gstInvoice.js`, `defenseMarketplace.js`, and three marketplace handlers) — this part is the opposite of a
"second system" risk; it's real, shared infrastructure, backed by its own dedicated test suite.

**What's duplicated, not fixed this pass (documentation only, per the "don't merge product families"
governance rule):**
- Its Scanner Revenue Engine (`basic`/`pro`/`enterprise_review`/`security_assessment`, ₹199–₹9,999)
  duplicates the concept of the main platform's report/package pricing via entirely separate, non-
  communicating tables.
- Its Proposal Factory (6 enterprise deal templates, ₹49,900–₹9,99,900) is a hand-maintained price list
  independent of `pricingConfig.js`, generating quote *documents* only — no payment/e-signature integration
  exists (the code's own comments confirm this explicitly).
- **Three** parallel Trust Center implementations and **two** parallel CEO/revenue dashboards exist across
  v24 and other subsystems, reading entirely different, independently-maintained table sets. Neither
  CEO dashboard is confirmed wired to a live frontend page.
- `GST_RATE = 0.18` is hardcoded independently in four separate files (all currently agree).

**What's a confirmed, live, critical security gap — unfixed this pass:**
- **`POST /api/v24/scanner/fulfill`** has no authentication and no payment-signature verification of any
  kind — it does `UPDATE scan_orders SET payment_status='paid'` unconditionally for any caller-supplied
  `order_id`/`payment_id`. Anyone who calls this directly can self-issue a "paid" order and pull the report
  for free.
- **`POST /api/v24/billing/invoice/create`** requires only `authCtx?.userId` (any logged-in user, not
  admin), accepts arbitrary line items, and hardcodes the inserted invoice's status as `'paid'` — no payment
  check — while also writing the fabricated amount into `revenue_streams` as if it were real revenue.
- **`POST /api/v24/sales/score`** has no authentication and allows any caller to write to a real
  `deal_pipeline` row.

These three are **not fixed in this pass** — see Part 5 for why, and the recommended next step.

---

## Part 5 — Fixes implemented this pass vs. deliberately not implemented

**Implemented** (both landed on this branch, PR #236 — see that PR for full root-cause/test detail):

1. Seven payment-verification handlers (`academyMarketplace.js`, `defenseMarketplace.js`,
   `enterpriseLayer.js`, `growth.js`, `revenue.js`, `sentinelMarketplace.js`, `toolsMarketplace.js`) now use
   the canonical constant-time signature comparison instead of a hand-rolled `!==`/`===` check. Pure
   hardening, zero behavior change for any legitimate caller.
2. `growth.js handleBillingCallback` and `revenue.js handleCheckoutVerify` — both had a *structural*
   verification-skipping gap beyond the comparison method (fail-open on missing secret; verification
   skippable by omitting fields). Both now fail closed. Fixing `growth.js` also surfaced and fixed a
   pre-existing, unrelated bug (`request.clone()` called after `request.json()` already consumed the body,
   which threw on every real call whenever the secret WAS configured — meaning only the insecure branch
   ever actually worked before this fix).
3. Test: `workers/test/paymentSignatureHardening.test.mjs`, 17 tests. Full suite: 286/286 files, 2989/2989
   tests pass.

**Deliberately NOT implemented this pass, with reasoning:**

- **v24Handler.js's three unauthenticated routes** (scanner/fulfill, billing/invoice/create, sales/score) —
  these are the most severe findings in this document, but per the master directive's explicit instruction
  ("Do not expose new products. Do not enable dormant products"), fixing a whole dormant subsystem's
  authorization model deserves its own dedicated, carefully-tested PR rather than being folded into this
  session's pricing/signature-hardening work — recommended as the clear next priority.
- **`revenue.js`'s `handleCheckoutInitiate`** client-trusted price — same reasoning; a well-understood,
  narrow fix (validate against a catalog, matching the pattern `handleCreateOrder`'s `package` branch and
  `marketplaceCheckoutHandler.js` already use correctly), but deserves its own PR and tests.
- **`marketplaceCheckoutHandler.js`'s missing GST invoice call** — narrow, safe, single-file fix (add a
  `createInvoice()` call matching `defenseMarketplace.js`'s already-correct pattern) — recommended as a
  quick, low-risk follow-up, not done this pass purely for scope/time, not because it's risky.
- **H2 (MSSP revenue-share policy) and H7 (internal Pricing Reference ambiguity)** — per explicit
  instruction, these remain fully undecided; nothing about them changed this pass beyond the gap-analysis
  documentation already added to `COMMERCIAL_RISK_AUDIT_2026-07-14.md`.
- **H5 (`subscriptionPaywallEngine.js` disposition)** — still awaiting a decision on delete/disable/
  reconcile; not touched, even though this pass refreshed and sharpened the evidence (100% grant-failure
  rate for 3 of 4 tiers, not merely latent).
- **`pricingConfig.js`'s stale `reports{}` block, phantom SKUs, and the two ID-naming mismatches** — low
  risk, content/config-only fixes; queued rather than bundled into a security-focused pass.

---

## Part 6 — Duplicate Business Logic Register

| Logic | Duplicated across | Status |
|---|---|---|
| Payment-signature HMAC verification | 8 files independently reimplemented before this pass | **Consolidated this pass** — all now use `lib/razorpay.js`'s `constantTimeEqual`; full HMAC-computation consolidation (not just the comparison step) is a further, larger refactor, proposed but not implemented — see Part 7 |
| GST rate (18%) | `v24/billingEngine.js`, `gstInvoice.js`, `pricingConfig.js`, `salesOS.js` (inline, not even referencing its own directory's constant) | Not consolidated; all currently agree |
| Invoice HTML/JSON rendering | `v24/billingEngine.js generateInvoiceHTML()` vs `gstInvoice.js buildInvoiceObject()` | Not consolidated; underlying data write path IS unified (`createInvoice()`) |
| Revenue/MRR ledger | v24's `revenue_streams`/`mrr_snapshots` vs RevOS's `revos_revenue_streams`/`revos_mrr_snapshots` | Two independently-maintained ledgers, not reconciled |
| Trust Center | `index.js handleEnterpriseTrustCenter` (live), `handlers/trustCenter.js` (v27, unreached), `v24/platformEngine.js getTrustCenterData` (unreached) | Three implementations, one actually used |
| CEO/executive dashboard | v24's `getCEODashboard` vs `ceoExecutiveDashboard.js` (v27) | Different table sets entirely; neither confirmed live-wired to a frontend page |
| "Reseller" as a commission-percentage name | MSSP onboarding (30% white-label margin) vs `affiliateSystem.js` (20% recurring referral commission) | Same word, two real, independently-paying programs, different numbers (H2 gap analysis) |
| Annual package IDs | `manualPayments.js` (`STARTER_PLUS_ANNUAL`/`PROFESSIONAL_ANNUAL`) vs `proposalGenerator.js` (`STARTER_PLUS`/`PROFESSIONAL`) | Same prices, different ID spelling — activation-matching risk, not pricing risk |
| Scanner/report pricing | v24's Scanner Revenue Engine vs `pricingConfig.js`/`razorpay.js`'s report and package prices | Separate, non-communicating tables; `security_assessment` happens to be priced identically (₹9,999) in both |

---

## Part 7 — Single-Source-of-Truth Registry: Design Proposal (not implemented)

Per the master directive, this is a design for future approval, not a change made now.

**Problem this solves:** the same commercial fact (a price, a feature flag, a GST rate, a signature-
verification routine) is currently maintained independently in anywhere from 2 to 8 places, discovered
piecemeal across two audit passes. Nothing enforces that they stay in sync except manual vigilance and
after-the-fact test guards (`pricingLineageGuard.test.mjs` and similar) added retroactively once a drift is
found.

**Proposed shape** (additive, non-breaking — existing call sites keep working during migration):

1. **`workers/src/registry/commercialRegistry.js`** — a single, frozen, exhaustively-keyed object covering
   every SKU class currently spread across `pricingConfig.js`, `razorpay.js` (`MODULE_PRICES`,
   `PACKAGE_PRICES`, `SUBSCRIPTION_PRICES`), `apiKeys.js` (`TIER_LIMITS`), `commercialPlatformHandler.js`
   (`PLAN_PRICES`/`PLAN_NAMES`), `manualPayments.js` (`PRODUCT_CATALOG`), `globalScale.js` (`MSSP_TIERS`),
   and `marketplaceCheckoutHandler.js` (`MARKETPLACE_CATALOG`). Each entry: `id`, `display_name`, `category`,
   `price_inr`, `price_paise`, `billing_model`, `billing_cycle`, `checkout_module`, `fulfillment_type`
   (`automated` | `manual` | `api_key_grant`), `gst_applicable`, `reachable_frontend_pages` (explicit list,
   so "is this dead?" becomes a registry query instead of a fresh grep every audit).
2. **Thin adapter exports** from each existing file (`pricingConfig.js`, `razorpay.js`, etc.) that read from
   the registry rather than defining their own copies — existing imports across ~60 call sites keep working
   unchanged during migration; only the *source* of the values moves.
3. **A single exported `verifyRazorpaySignature(env, orderId, paymentId, signature)`** already exists
   (`lib/razorpay.js`) and should become the *only* signature-check implementation — the 7 files hardened
   this pass would, in a follow-up PR, replace their local HMAC computation with a direct call to this
   function instead of just reusing its comparison helper. Deferred this pass specifically because it's a
   bigger diff per file with more room for subtle behavioral drift (different message formats, etc.) than
   the comparison-only swap — appropriate for its own careful, one-file-at-a-time follow-up, not a batch.
4. **Migration order** (smallest blast radius first, each its own PR): (a) GST rate → registry constant,
   4 files, zero behavior change since all 4 already agree; (b) subscription tier prices → registry, 4
   files, `pricingLineageGuard.test.mjs`-style guard already proves these agree today; (c) one-time
   report/package prices → registry, resolves the `pricingConfig.js reports{}` drift as a side effect;
   (d) MSSP tiers; (e) signature verification consolidation (item 3 above), last, because it's the highest-
   risk migration (touches live payment-verification code, not just constants).

**Explicitly not proposed:** merging the v24 Scanner Revenue Engine, Sentinel APEX marketplaces, or defense-
solutions systems into "one" product family. Per governance, whether these are meant to be genuinely
distinct product lines or consolidation candidates is a business decision this repository's evidence cannot
resolve alone — the registry's job is to make the *existing* facts about each one explicit and machine-
checkable, not to decide which of them should keep existing.

---

## Appendix A — Full SKU list referenced in this document

Subscription tiers: FREE, STARTER (₹999), PRO (₹1,499), ENTERPRISE (₹4,999), MSSP (₹9,999),
ENTERPRISE_SOC (₹41,199, unsold). MSSP partner tiers: Reseller (₹14,999), Silver (₹29,999), Gold (₹49,999).
MSSP packages: MSSP_WHITE_LABEL (₹49,999/mo), MSSP_COMMAND (₹14,99,900/yr). Reports: domain (₹999), ai
(₹2,499), redteam (₹4,999), identity (₹799), compliance (₹499), cloudsec/darkscan/appsec/full (phantom).
Core packages: SECURITY_ASSESSMENT (₹9,999), THREAT_INTEL_REPORT (₹14,999). AI/MCP assessments (14):
AI_SECURITY_ASSESSMENT (₹49,999), OWASP_LLM_ASSESSMENT (₹24,999), AI_GOVERNANCE_ASSESSMENT (₹49,999),
AI_RED_TEAM (₹99,999), MCP_SECURITY_REVIEW (₹24,999), AI_AGENT_SECURITY (₹34,999),
RAG_SECURITY_ASSESSMENT (₹19,999), AI_SECURITY_STARTER (₹49,999), AI_SECURITY_PROFESSIONAL (₹99,999),
ENTERPRISE_AI_SUITE (₹1,99,999), MCP_SECURITY_REPORT (₹999), MCP_ENTERPRISE_ASSESSMENT (₹24,999),
PROFESSIONAL_ASSESSMENT (₹24,999), ENTERPRISE_ASSESSMENT (₹49,999). Annual/legacy: ANNUAL_RETAINER
(₹99,999/yr), STARTER_PLUS_ANNUAL (₹49,900/yr), ENTERPRISE_SHIELD (₹4,99,900/yr), PROFESSIONAL_ANNUAL
(₹1,49,900/yr), CUSTOM_ENTERPRISE (custom). manualPayments-only: API_PROFESSIONAL (₹9,999, dead). v24
Scanner Revenue: basic (₹199), pro (₹999), enterprise_review (₹4,999), security_assessment (₹9,999). v24
Proposal Factory: ai_security (₹1,49,900), mssp (₹9,99,900), threat_intelligence (₹49,900), compliance
(₹99,900), retainer (₹9,99,900), enterprise (₹5,99,900). Sentinel intel: cve_report (₹3,999),
threat_actor_dossier (₹6,499), malware_intel (₹6,499), generic_report (₹3,999). Marketplace (Sentinel APEX
Intelligence): 12 SKUs, ₹999–₹9,999 (detection packs, playbooks, intel reports, compliance packs, AI
agents — see Part 3). Defense solutions (literal): 5 SKUs, ₹599–₹999. Affiliate/referral commission tiers:
AFFILIATE (10%), PARTNER (15%), RESELLER (20%), STRATEGIC (25%+MDF).

## Cross-references

- `docs/audit-history/COMMERCIAL_RISK_AUDIT_2026-07-14.md` — H1-H8, C1-C5, D1-D19, original pricing/
  entitlement scope. H1 and the pricing half of the picture in this document are now resolved there; H2,
  H5, H6, H7 remain open decisions.
- PR #236 — all code/test changes referenced in Part 5.
