# PHASE 1 — Enterprise Lifecycle Audit (Verified)

**Platform:** CYBERDUDEBIVASH AI Security Hub + Sentinel APEX
**Scope:** Customer · Tenant · Subscription · Billing · API · Report · Partner · MSSP lifecycles
**Method:** Code-level verification of the live Cloudflare Worker (`workers/src`), D1 schema (`workers/schema_*.sql`), route wiring (`workers/src/index.js`), and enforcement. **UI claims were NOT trusted.**
**Date:** 2026-06-15
**Classification legend:** PRODUCTION READY · PARTIAL · MISSING · MOCK · BROKEN

> Several findings below were independently re-verified by direct code reads (cited with ✓VERIFIED). The rest are auditor findings with `file:line` evidence pending fix-time re-confirmation.

> **2026-07-16 update — see `PHASE7_PAID_CUSTOMER_LIFECYCLE_AUDIT_2026-07-16.md` §3.1:**
> Re-verified against current code (post-#278). §2's three headline gaps are
> now **Fixed**: Razorpay activation persists `users.tier`/`subscriptions`
> correctly (traced end-to-end including what a subsequent scan request
> resolves), the STARTER quota arg-order mismatch is gone, and the
> marketplace purchase→webhook→entitlement chain is implemented and tested.
> The `stripeWebhook.js:260` citation in §2 points to a file with no match
> anywhere in this repo's git history — likely a stale/incorrect citation
> rather than a removed feature; Stripe is explicitly not used as a
> processor (`subscriptionPaywallEngine.js`). The §2 residual-gap note ("no
> upgrade/downgrade/cancel") needed correction: a working cancel route
> exists and was live-tested at `POST /api/customer/billing/cancel`
> (different namespace than `/api/subscription/*`, which is why the original
> search missed it) — see Phase 7 §3.2 for what it does and does not
> enforce.

---

## Executive Summary

The platform is **not** suffering a security-feature gap — the scanning/intel engines are substantial. The bottleneck is the **Enterprise Customer Operating System**: the layer that turns a payment into a provisioned, isolated, entitled, renewable customer. That layer is **largely built but broken at the seams** — fragmented across parallel implementations, with several silent defects that (a) leak revenue, (b) break tenant isolation, and (c) present fabricated data as live.

**Headline verdict:** Auth core, payment signature verification, and analytics computation are genuinely production-grade. But the **provisioning chain is severed in three places** (org context, marketplace fulfillment, Razorpay tier persistence), **multi-tenant isolation is not structurally enforced**, and **two customer-facing surfaces (CRM pipeline, catalog reports) are mock data**.

### Severity rollup

| Sev | Count | Theme |
|-----|-------|-------|
| **P0 — Critical** | 5 | Tenant data leakage; plaintext API keys; dead purchase→delivery; org/RBAC dead; STARTER unmetered |
| **P1 — High** | 4 | Razorpay tier not persisted; catalog reports are boilerplate; reseller economics unenforced; schema drift (duplicate `api_keys`/`mssp_clients`) |
| **P2 — Medium** | 4 | Missing CAC/LTV; absent `feed.json` routes; anomaly detection & audit-log silently disabled; renewal writer missing |

---

## 1. Identity & Tenancy Lifecycle

| Capability | Status | Evidence | Gap |
|---|---|---|---|
| Customer Accounts | **PRODUCTION READY** | `auth/password.js:45` PBKDF2-50k timing-safe; `auth/jwt.js:116-143` revocable refresh tokens in D1; `handlers/auth.js:34,122` | `users.tier` CHECK (`schema_master.sql:16`) allows FREE/PRO/ENTERPRISE only, but code emits `STARTER` (`auth/apiKeys.js:14`) → constraint violation risk |
| Organizations | **BROKEN** ✓VERIFIED | Routes wired `index.js:2268-2324`; handlers real `handlers/orgManagement.js:36-451`; **but bind `authCtx.userId` (`:59,75,79,107`) while `resolveAuthV5` sets `user_id` (`auth/middleware.js:65`)** | `authCtx.userId` is always `undefined` → org create writes NULL owner; all membership lookups fail. Org CRUD non-functional. |
| Multi-Tenant Isolation | **PARTIAL** | Scoped by membership join `orgManagement.js:99-107`; **but scans store only `user_id` (`queue.js:116`), no `org_id`** | Tenancy reconstructed, not persisted. Dual-org membership cross-contaminates. No structural `org_id`/`tenant_id` FK on data tables. |
| RBAC | **PARTIAL / unenforced** ✓VERIFIED | Roles defined `orgManagement.js:27-33`, checked `:255,319,410`; **`ROLE_PERMISSIONS` map never consulted; `authCtx.role` never set** | Role checks live only inside org handlers and are dead due to the `userId` bug. No other route enforces a role. |
| Customer Portals | **PARTIAL** | Authenticated portal = `/api/auth/me` (`auth.js:259`, real, user-scoped) | "Portals" at `index.js:3583,5386` are public docs/dev content, not a per-customer data portal. |

**Bonus defect (✓VERIFIED):** the same undefined `authCtx.userId` silently disables **anomaly detection** (`index.js:630`) and **nulls the request audit-log user** (`index.js:704`) — a security-observability gap.

---

## 2. Monetization Lifecycle (Subscription / Billing / Usage / API / Entitlement)

| Capability | Status | Evidence | Gap |
|---|---|---|---|
| Subscription Mgmt | **PARTIAL / BROKEN** | Razorpay activate writes KV session + `payments` only (`handlers/subscription.js:224-251`); proper persistence only via Stripe (`stripeWebhook.js:260`) & `subscriptionPaywallEngine.js:440` | Primary Razorpay path never writes `users.tier`/`subscriptions`; scan pipeline resolves tier from JWT/key/IP (`auth/middleware.js:108-153`) → paying Razorpay subscriber served as FREE. No upgrade/downgrade/cancel. |
| Billing Mgmt | **PRODUCTION READY** | Razorpay HMAC order+webhook sig constant-time (`lib/razorpay.js:61-91`, wired `index.js:1573`); GST invoices `v24/billingEngine.js:30-97`; PayPal + Stripe live | `runPaymentRecovery` Razorpay retry is `TODO` (`billingEngine.js:309`); overlapping `invoices`/`billing_invoices` tables |
| Usage Tracking / Metering | **PARTIAL** ✓VERIFIED | API-key (D1) + IP/JWT (KV) quotas enforced (`index.js:689-695`); **but STARTER monthly quota is a no-op: `checkMonthlyQuota(request, env)` called against signature `(env, identity)` (`index.js:684` vs `subscription.js:292`)** | STARTER (₹499) gets unmetered scans → revenue leak, cannibalizes PRO |
| API Key Mgmt | **PARTIAL / inconsistent** ✓VERIFIED | Safe path hashes SHA-256 (`auth/apiKeys.js:43,60`); **unsafe path stores RAW `sap_` key plaintext (`apiRevenueEngine.js:311`) and matches plaintext (`:347`)** | Two `api_keys` schemas (`schema_master.sql:48` & `:4380`); plaintext keys = breach exposure |
| Entitlement Enforcement | **PARTIAL** | Real gate `entitlementCheck.js:182-190` (`customer_entitlements`→tier), used `index.js:4379,4389`; per-finding paywall `monetization.js:75-123` | `checkEntitlement` swallows D1 errors → falls through to tier-implicit access (`:71-83`); entitlements only granted by Stripe/provisioning path, not Razorpay |

**No unsigned/mock webhooks in wired paths** — Razorpay, Stripe, Gumroad all verify signatures. Good.

---

## 3. Sentinel APEX Intelligence Commerce + Report Lifecycle

| Capability | Status | Evidence | Gap |
|---|---|---|---|
| Premium report types | **PARTIAL** | `ctiReportEngine.js:143,240` fetch live CISA KEV + NVD + Shodan/DoH → real deterministic content | The 7 catalog SKUs render **one static HTML template** with hardcoded APT29/Lazarus/LockBit sample data (`secureDownload.js:229-336`); `reportId` only swaps title/page-count (`:76`) |
| Lifecycle: Preview→Purchase→Entitlement→Delivery→Renewal | **BROKEN** | Purchase writes `status='pending'` (`sentinelApexMarketplace.js:447,511`); delivery requires `status='paid'` (`secureDownload.js:399`); **no code sets `marketplace_orders.status='paid'`** | Chain severs at Purchase→Entitlement. `POST /api/marketplace/webhook` documented (`:18`) but unimplemented → 404. `/api/provision/purchase` exists (`provisioningEngine.js:236,474`) but must be invoked manually. |
| Marketplace backend | **PARTIAL / MOCK fulfillment** | Catalog is a hardcoded 19-item JS object (`sentinelApexMarketplace.js:24-330`), not the `report_catalog` table; checkout returns a UPI ID + "email receipt for manual provisioning within 24h" (`:466-470`) | Fulfillment manual; no automated payment→provision link |
| Intel feeds / API delivery | **PARTIAL** | `/api/intel/{ioc,cve,actor,ttp,risk}` wired (`index.js:3541-3557`); STIX export real (`ctiPlatformV2.js`) | Advertised `/api/v1/intel/*.json` & `/api/feed.json` **routes do not exist**; IOC verdict is string-heuristic (`intelAPIHandlers.js:173`), not feed-backed |
| Report generation engine | **PARTIAL** | Two genuine engines (CTI live OSINT; on-demand HTML); LLM used only for ~250-token enrichment (PRO+) | Catalog reports templated/stubbed, not per-product generated |

---

## 4. MSSP / Partner + Revenue Analytics + Customer Success

| Capability | Status | Evidence | Gap |
|---|---|---|---|
| MSSP multi-client mgmt | **BROKEN** | `handlers/msspWorkspace.js:33-45,204` lists `mssp_customers WHERE status=?` with **no owner filter**; table (`schema_master.sql:1922-1941`) has **no `partner_id`** | Any `mssp_admin` sees/edits ALL tenants globally — confidentiality breach. Two rival `mssp_clients` schemas (`schema_master.sql:1914` vs `revos/msspEngine.js:68`) |
| White-label branding | **PARTIAL** | Per-org theme persisted to `tenant_themes` (`whiteLabelMSSP.js:60-104`, `schema_phase3.sql:117`) | `org_id` falls back to `'default'` (`:61`) → unscoped users share one theme; `custom_domain` stored but no DNS/routing |
| Reseller / revenue-share | **MOCK** | "50% margin/30% share" are static config (`globalScale.js:179-206`, `affiliateSystem.js:57`); `mssp_partners.margin_pct` column exists (`schema_master.sql:1956`) but **no code computes/pays margin** | Reseller economics unenforced — signed partners can't be paid or capped |
| Revenue analytics (MRR/ARR/churn/CAC/LTV/funnel) | **PARTIAL** | MRR/ARR/churn DB-computed (`analyticsEngine.js:23-49,129-153`); CEO dash reads `mrr_snapshots`/`subscriptions` (`revenueEngine.js:249-364`); cron writes snapshots (`index.js:5720`) | **CAC & LTV entirely absent**; MRR derived from `leads.plan` not actual payments (overstates); churn is crude |
| Customer Success / health | **PARTIAL** | Health from real `scan_results`/`soc_cases`/recency (`customerSuccess.js:62-80`); `cs_signals` table real | Playbooks static (no triggers fire); `renewal_queue` read but **no writer found** |

**FAKE CRM pipeline:** `frontend/index.html:19006-19015` `p4LoadPipeline()` renders a hardcoded `DEMO_PIPELINE` ("TechSecure ₹1,49,900" … "NexGen ₹14,99,900") and computes "% of ₹1CR" client-side. The real `/api/sales/pipeline` route (`index.js:4078`) exists but the marquee dashboard never calls it.

---

## Prioritized Remediation Roadmap

Ordered by charter priority (Security → Reliability → Customer → Revenue), each scoped as a **minimal, reversible, test-backed** change.

### P0 — Critical (do first)
1. **Tenant isolation for MSSP** *(Security)* — add `partner_id`/owner scoping to `mssp_customers` + every `msspWorkspace` query. *Stops cross-partner data leakage.*
2. **Hash the `sap_` API keys** *(Security)* — converge `apiRevenueEngine` onto the hashed `auth/apiKeys.js` store; migrate/)invalidate plaintext rows. *Removes credential-dump exposure.*
3. **Fix `authCtx.userId` → `user_id`** *(Reliability)* — unbreaks org CRUD, RBAC, anomaly detection, and audit logging in one cluster (with the `scan_history.target_summary`/schema-drift follow-ons).
4. **Wire purchase→delivery** *(Revenue)* — implement `POST /api/marketplace/webhook` (signature-verified) → existing `provisioningEngine` → set `status='paid'`. *Unlocks the ₹9,999–₹99,999 funnel.*
5. **Fix `checkMonthlyQuota` arg order** *(Revenue)* — restore STARTER metering. *One-line, stops unmetered ₹499 tier.*

### P1 — High
6. Persist tier/subscription on the Razorpay activate path (converge with Stripe/provisioning).
7. Back the 7 catalog report SKUs with type-aware `ctiReportEngine` content (kill the boilerplate template).
8. Enforce reseller margin/client-caps in the billing path, or stop advertising them.
9. Consolidate duplicate `api_keys` / `mssp_clients` schemas; pick one source of truth.

### P2 — Medium
10. Implement CAC & LTV; base MRR on actual `payments` not `leads.plan`.
11. Ship the advertised `/api/v1/intel/*.json` + `/api/feed.json` routes (or remove the claims).
12. Replace the fake `DEMO_PIPELINE` with a `/api/sales/pipeline` fetch (and an honest empty-state).

---

## Every-change requirements (per mandate)
For each remediation item: **tests** (unit + contract), **monitoring** (the change must be observable), **rollback** (isolated revertable commit; no destructive migration — additive columns only), **documentation** (this file + PR body), **validation** (CI green + local proof). **Zero-regression rule:** no item removes working functionality; schema changes are additive `ADD COLUMN`/new tables only.
