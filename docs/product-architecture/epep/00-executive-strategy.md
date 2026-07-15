# CYBERDUDEBIVASH® AI SECURITY HUB — Enterprise Product Expansion Program (EPEP)

## Master Strategy Document

**Phase:** Product Architecture & Business Design (pre-implementation) — no new product code has shipped under this program.
**Date:** 2026-07-15 · **Evidence basis:** direct repository audit at commit `d7841aa` (branch `claude/epep-product-architecture-d177jl`), cross-referenced against `docs/capability-registry/` (living, CI-validated) and spot-checked against `docs/audit-history/*.md` (historical, treated as reference only per CLAUDE.md).
**Companion documents:** [`01-ai-agent-red-team-as-a-service.md`](01-ai-agent-red-team-as-a-service.md) · [`02-threat-intel-automation-pack.md`](02-threat-intel-automation-pack.md) · [`03-darkweb-brand-monitoring.md`](03-darkweb-brand-monitoring.md) · [`04-ai-security-maturity-assessment.md`](04-ai-security-maturity-assessment.md)

---

## 1. Executive Summary

This program was asked to design four new products — AI Agent Red Team as a Service (ARaaS), Threat Intelligence Automation Pack, Dark Web & Brand Monitoring Platform, and AI Security Maturity Assessment Framework — as **architecture and business design only**, on the explicit condition that nothing already-implemented be overstated and nothing planned be presented as built.

Five parallel repository audits (one per product, one cross-cutting) produced a picture that both **confirms and materially sharpens** the CEO's original sequencing instinct. The headline findings:

1. **All four products have real, reusable backend substrate already in production** — none of the four is a true greenfield build. The platform's own capability registry (101 cataloged capabilities, `docs/capability-registry/`) and this audit's direct code reads agree: reuse is high, but **every product also has at least one core promise that does not exist in any form today** and requires genuine new engineering (detailed per-product in the companion documents).
2. **One platform-wide gap affects all four products' commercial design equally and must be solved once, centrally, not four times:** Razorpay integration is real but is **Orders API only — there is no recurring-subscription billing anywhere in this codebase** (**Verified**, `workers/src/lib/razorpay.js`; a function literally named `createRazorpaySubscription()` in `subscriptionPaywallEngine.js:330-360` in fact creates a one-time order). "Monthly" plans require manual re-purchase today; there is no auto-renewal, no auto-retry, and cancellation does not enforce expiry. See §5.1.
3. **A real, already-scheduled continuous-monitoring engine exists** (`monitor_configs`/`runMonitoringCron`) that materially de-risks Product 3 specifically, and **a real, already-scheduled rule-generation-and-deployment pipeline exists** (`autonomousSocMode.js`) that materially de-risks Product 2 specifically — both were found one layer down from the files their own product concepts named, and both change the engineering-cost picture from the original rough draft.
4. **Product 1 (ARaaS) carries a qualitatively different kind of risk than the other three** — not just engineering effort, but genuine legal/abuse exposure from a live-attack-delivery feature that does not exist yet. This document recommends splitting it into a low-risk Stage A (productize what's real) and a separately-gated Stage B (build live attack execution only after a dedicated security/legal review).
5. **Zero real paying customers exist on the platform today** (`KPI_DASHBOARD.md`: CSAT/renewal/expansion all explicitly `UNKNOWN`). Every revenue figure in the four companion documents is labeled **Assumed**, not forecast from real conversion data, per CLAUDE.md's prohibition on fabricating market/financial claims.

**Recommended sequencing (confirmed, with evidence added):**

| Order | Product | Why |
|---|---|---|
| 1 | AI Security Maturity Assessment | Highest reuse (5 independent maturity-scoring engines already exist, never unified), lowest new-engineering estimate (~4-6 weeks), a real dormant paid-booking backend ready to reactivate |
| 2 | Threat Intel Automation Pack | Real, already-monetizing manual product to automate (proven demand); a real scheduled rule-generation pipeline already exists one layer down from the obvious files |
| 3 | AI Agent Red Team as a Service | Real guided-tier assets exist and can ship fast (Stage A); the flagship "live attack" capability (Stage B) is genuinely unbuilt and carries abuse/legal risk that must be reviewed separately, not rushed |
| 4 | Dark Web & Brand Monitoring | Engineering complexity is **lower than originally assumed** (a real scheduled monitoring engine just needs extending) — but its core commercial model (recurring monitoring subscription) is the **most exposed of the four** to the platform-wide recurring-billing gap in §5.1, which keeps it last despite the lower build cost |

**GO / Conditional GO / NO-GO by product:** Product 4 — Conditional GO. Product 2 — Conditional GO. Product 1 — Conditional GO for Stage A only; **NO-GO on Stage B pending dedicated legal/security review**. Product 3 — Conditional GO, contingent on resolving the "dark web" naming/positioning question (§2.4 of its companion doc) and adopting the interim pre-paid billing model in §5.1 below.

---

## 2. Repository-First: What This Program Reused vs. Built On Top Of

Per governance, this program audited the repository before designing anything. The audit used the platform's own **living capability registry** (`docs/capability-registry/domains/*.json` + generated `PRODUCTION_READINESS_REPORT.md`, 101 capabilities, CI-validated, `last_verified` dates as recent as 2026-07-14) as the primary evidence source — not the 58 point-in-time documents under `docs/audit-history/`, which are historical records only, per this repo's own `DOCUMENTATION_INDEX.md` and CLAUDE.md.

Two registry-quality findings surfaced independent of the four products, worth recording here once rather than four times:

- **The registry itself has gaps.** Two live, working capabilities relevant to this program — `aiSecurityScorecardHandler.js` (Product 4) and `brandProtectionEngine.js` (Product 3) — have **no capability-registry entry at all**. Neither is a false claim; both are simply uncatalogued. Recommend registering both once their respective products are approved (each companion document notes this in its own Phase 7).
- **The registry's illustrative documentation drifted.** `docs/capability-registry/SCHEMA.md` §3 cites "dark-web scanning" as its example of a capability with real backend and no frontend. That example is now stale — dark-web scanning has a real frontend tab today; Brand Protection is the accurate example. A small, low-cost correction, recorded here per CLAUDE.md §2's Documentation Drift requirement.

Per-product capability classification (Production Ready / Partial / Internal / Dormant / Legacy / Planned, each with file:line evidence) is in §2 of each companion document — this section does not repeat that detail, only the cross-cutting implications.

---

## 3. Cross-Cutting Architecture Findings

### 3.1 Payments — the load-bearing finding of this entire program

**Verified, directly from code (`workers/src/lib/razorpay.js`, `payments.js`, `subscriptionPaywallEngine.js`, `services/v24/billingEngine.js`, plus corroboration in `docs/audit-history/SUBSCRIPTION_REGISTRY_2026-07-14.md` §6):**

- Razorpay integration is real and creates genuine server-side charges — but **only via the Orders API** (`/v1/orders`). Every one of 12 call sites checked hits `/v1/orders`; zero hit the Subscriptions API.
- `subscriptionPaywallEngine.js:330-360`'s function is literally named `createRazorpaySubscription()` — its body creates a one-time order. "Subscription" today means: one-time order → HMAC-verified → a fixed 30/90-day entitlement window written to D1. Nothing re-charges the customer automatically.
- `billingEngine.js:390` contains a literal `// TODO: Integrate with Razorpay subscription retry API` — renewal is, today, an email reminder, not a re-charge.
- Cancellation sets a flag that nothing reads — cancelled customers keep paid access indefinitely (a live revenue-leak risk, not unique to these four new products, but one they must not silently inherit).
- **Two parallel, unreconciled subscription-tier systems exist** platform-wide (one live and frontend-wired, one orphaned with a live, unfixed 10× price bug on its "ENTERPRISE" tier) — a pre-existing platform issue, out of scope for this program to fix, but a hazard any new product must be built to avoid extending.

**Implication for all four products:** none of them can honestly market "subscription" or "recurring billing" as production-ready today. Each companion document's Commercial Plan launches on the **existing, proven one-time-order model** (matching how the platform's real `ANNUAL_RETAINER`/`MSSP_WHITE_LABEL` packages already work) with a manual-renewal reminder, and flags true recurring billing as a **shared platform Enhancement** — one fix benefiting all four products, not four separate workarounds. This is the single most important commercial-governance finding of the whole program.

### 3.2 Compute infrastructure — the Cloudflare cron ceiling

**Verified:** `workers/wrangler.toml`'s `[triggers].crons` block has exactly 5 entries — the Cloudflare Workers free-tier maximum — and all 5 are already in production use (one of them, `runAutoSocCron`, already carries real work relevant to Product 2). **Both Product 2 (scheduled pack refresh) and Product 3 (scheduled brand/dark-web re-checks) need recurring background execution**, and neither can simply request a new cron slot. Recommendation: both products fan out from existing ticks (Product 3 explicitly reuses the existing `runMonitoringCron` tick per its own architecture; Product 2 reuses `runAutoSocCron`'s tick), and this document flags — for a business decision, not an engineering one — whether a paid Workers plan (which lifts the 5-cron cap) should be budgeted once real usage from either product approaches the shared ceiling.

### 3.3 Event dispatch — one gap, two products waiting on it

**Verified:** `enterpriseAutomation.js`'s webhook system is Production Ready (real HMAC signing, real delivery log, working UI — confirmed fixed today under a separate, already-shipped change, PR #253) — but `dispatchWebhookEvent`, the function that would fire a **real** (non-test) event, has **zero callers anywhere in the repository**. Both Product 2 (pack-deployed events) and Product 3 (finding-detected events) need real event dispatch to make good on "webhook templates" / "breach alerts." Recommend wiring this once, as a shared platform fix, rather than each product inventing its own notification path.

### 3.4 Database — multi-tenancy convention is inconsistent by era, and these four products should not inherit the older pattern

**Verified:** legacy/core tables (`payments`, `subscriptions`, `scans`) are `user_id`-only; newer tables (`schema_v46_missing_tables.sql`) are properly `org_id`-scoped with dedicated indexes. Since all new tables proposed across the four companion documents are net-new, **every one of them is specified org_id-scoped from creation** — a free correctness win with no migration risk, because there is no legacy data to reconcile.

### 3.5 RBAC, marketplace, developer portal — solid, reusable foundations

**Verified Production Ready and directly reusable, unchanged, by all four products:** the two-tier RBAC model (platform staff + org-scoped OWNER/ADMIN/ANALYST/MEMBER/VIEWER, real tenant isolation confirmed at 15 query sites plus an 11-test isolation suite); the Sentinel APEX Marketplace checkout/entitlement model; `CAP-DEVPORTAL-001`'s canonical API-key system (note: 4 parallel, largely redundant API-key implementations also exist platform-wide — build any new API-access tier on the canonical one, not a 6th parallel system).

**Confirmed genuinely missing, not just unfinished:** `CAP-MSSP-004` (Delegated Admin Permissions) has zero backend, sized by the platform's own `PROGRAM_BOARD.md` as "large/new architecture." This affects Product 2 specifically (MSSP is a named persona needing multi-client delegation) — flagged as a pre-existing platform dependency, not something Product 2 should attempt to solve itself.

---

## 4. Cross-Product Risk Register

| Risk | Affects | Category | Mitigation |
|---|---|---|---|
| No recurring/subscription billing exists platform-wide | All 4 | Commercial | Launch all 4 on the existing one-time-order model; fix recurring billing once, centrally (Proposed platform initiative, not part of any single product's scope) |
| Cloudflare 5-cron-slot ceiling already fully consumed | Products 2, 3 | Operational | Fan out from existing ticks; budget decision on a paid Workers plan if usage grows |
| `dispatchWebhookEvent` has zero real callers | Products 2, 3 | Technical | Wire real event dispatch once, shared fix |
| Zero real paying customers platform-wide | All 4 | Commercial | Every revenue figure in every companion document is labeled Assumed; first commercial milestone for each product is "one real paying customer," mirroring the platform's own `GA-O1` framing |
| Live-attack feature (Product 1 Stage B) has no consent/scoping/rate-limiting controls | Product 1 only | Legal / Security / Abuse | Separate, explicit approval gate before any Stage B build — see Product 1 §17 |
| "Dark web" naming overstates real capability (no Tor/paste-site/forum access exists) | Product 3 only | Commercial / Legal (marketing accuracy) | Rename or clearly scope the claim before external marketing |
| Registry gaps recur for new capabilities the way they did for existing ones | All 4 | Operational | Each product's Phase 7 (Documentation) explicitly registers new CAP-IDs — a governance habit this program is establishing, not assuming |
| Fragmented/duplicate implementations (2 STIX builders, 4 IOC-enrichment paths, 5 API-key systems, 2 subscription-tier systems) create a rockier foundation to build on than a clean codebase would | Products 1, 2 mostly | Technical | Each affected companion document's Phase 1 includes consolidation before new build, not after |

---

## 5. Cross-Product Commercial Design

### 5.1 Pricing — extend the existing config, don't parallel it

`workers/src/config/pricingConfig.js` is explicitly commented **"IMMUTABLE SOURCE OF TRUTH"** and defines the platform's real, live pricing: subscription plans FREE/STARTER (₹999/mo)/PRO (₹1,499/mo)/ENTERPRISE (₹4,999/mo)/MSSP (₹9,999/mo); one-time packages from ₹9,999 to ₹99,999/year; pay-per-report ₹499–1,999. This is a **low-ticket, high-volume, self-serve commercial model**. The original rough draft's proposed pricing for these four products (₹24,999–₹2,99,999+ for ARaaS; ₹15,000–75,000/month for Dark Web monitoring; up to ₹5L for Maturity Assessment with consulting) represents a **materially higher price tier than anything this platform has sold at scale before** — not necessarily wrong, but unproven, and each companion document flags its premium tiers as sales-assisted/enterprise-quote rather than self-serve-button until a real pilot customer validates willingness-to-pay at that level.

**Recommendation:** every new SKU across all four products should be added as a new named entry inside `pricingConfig.js`'s existing `packages`/`plans` structure — never as a parallel pricing system. This is a direct application of CLAUDE.md's "no duplicated systems" rule to the commercial layer, not just the technical one.

### 5.2 Existing commercial proof points worth noting

Two real, already-live commercial signals materially reduce risk for two of the four products:
- Product 2's "packs" are **already being sold today**, manually fulfilled (`marketplaceCheckoutHandler.js` — real Razorpay checkout, honest `delivery: 'manual_pending'` disclosure). This is the strongest demand evidence of the four products.
- Product 1's premium tier has a **real, already-sellable manual analog** (`ai-security-services.html`'s ₹99,999 "AI Red Team Engagement," 14-day delivery, human-delivered "video evidence" and debrief). Formalize it; don't replace it.

Products 3 and 4 have no equivalent existing proof point — their commercial cases rest more on the platform's general credibility and the reuse case in §2/§3, not on an existing SKU already converting.

---

## 6. Cross-Product Executive Scorecard

| Product | Architecture completeness | New engineering estimate | Security/legal readiness | Commercial readiness | Sequencing |
|---|---|---|---|---|---|
| 4. AI Security Maturity Assessment | 🟡 Partial (5 engines, unintegrated) | 🟢 Low (4-6 wks) | 🟢 Strong | 🟡 Partial (entry tier fits; premium unproven) | **1st** |
| 2. Threat Intel Automation Pack | 🟡 Partial (strong substrate, thin generator) | 🟡 Moderate (6-9 wks) | 🟢 Strong | 🟢 Strong (already selling manually) | **2nd** |
| 1. AI Agent Red Team (Stage A) | 🟢 Strong | 🟢 Low (2-3 wks) | 🟢 Strong | 🟢 Strong (existing manual SKU) | **3rd** |
| 1. AI Agent Red Team (Stage B) | 🔴 Absent | 🔴 High (10-16 wks) | 🔴 New controls required | 🟡 Unproven at price point | **Gated, separate approval** |
| 3. Dark Web & Brand Monitoring | 🟡 Partial (two engines + one reusable scheduler) | 🟡 Moderate (5-7 wks), lower than originally assumed | 🟡 Needs SSRF review pass | 🔴 Weakest (most exposed to billing gap) | **4th** |

**Customer evidence for all four products: 🔴 None** — zero real paying customers exist on the platform today. This is not a product-specific weakness; it is a platform-stage fact every revenue and case-study claim in every companion document must be read against.

---

## 7. What This Program Deliberately Did Not Do

Consistent with CLAUDE.md's production-fix policy (architectural changes, customer-facing commercial changes, and multi-service extraction require explicit approval before implementation, not auto-execution):

- **No code was written for any of the four products.** This is architecture and business design only, as scoped.
- **No fix was made to the cross-cutting platform gaps identified** (recurring billing, `dispatchWebhookEvent` wiring, registry gaps) — these are recorded as findings and recommendations for separate, explicitly-approved work, not folded into this design pass.
- **Product 1 Stage B (live attack execution) is explicitly not recommended for auto-implementation** — it is the one recommendation in this entire program that requires a dedicated legal/security review round before any build begins, per its companion document §17.
- **No market-sizing (TAM/SAM/SOM) or revenue forecast figures were fabricated.** Where the master prompt asked for them, each companion document states plainly that no verified data exists in this repository and declines to invent numbers, per CLAUDE.md's explicit prohibition.

---

## 8. Next Steps (pending your direction)

1. Approve (or amend) the sequencing in §1/§6.
2. Decide the cross-cutting platform fixes in §3.1/§3.3 (recurring billing, webhook dispatch) — recommend scoping these as their own CAP-numbered production initiatives, following this repo's existing one-problem-per-PR discipline, rather than bundling them into any single product's build.
3. For Product 1 specifically: decide whether Stage B (live attack execution) should proceed to a dedicated security/legal review at all, independent of approving Stage A.
4. For Product 3 specifically: decide the "dark web" naming/positioning question and whether to procure a real breach-data source (HIBP key) or a third-party dark-web-intelligence feed.
5. On approval of any product, its Development Roadmap §18 (in the relevant companion document) is ready to move from Phase 1 (repository reuse confirmation) into Phase 2 (backend) under this repo's standard one-production-problem-per-PR, CI-gated workflow.
