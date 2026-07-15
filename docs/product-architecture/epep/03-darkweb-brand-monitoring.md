# Product 3: Dark Web & Brand Monitoring Platform

**Program:** Enterprise Product Expansion Program (EPEP) · **Phase:** Product Architecture & Business Design (pre-implementation)
**Status of this document:** Proposed architecture. No new code has been written under this program yet — see §2 for what already exists.
**Evidence basis:** Direct repository audit, 2026-07-15 (commit `d7841aa`). Claims tagged **Verified** / **Assumed** / **Proposed** per CLAUDE.md.

> **Naming caveat (read first):** the audit found no code anywhere that accesses actual dark-web sources (Tor/I2P, paste sites, criminal forums/markets). What exists is Certificate-Transparency-log exposure checking, live typosquat/DNS recon, and a *disabled* breach-database integration. This document recommends the product either (a) be positioned honestly as an "Attack Surface & Brand Exposure Monitoring" product with dark-web coverage as a clearly-labeled future add-on via a third-party data provider, or (b) procure a real dark-web-intelligence data source before using the name externally. See §2.4.

---

## 1. Executive Summary

**Problem solved.** Enterprises need to know when their brand, executives, or credentials are exposed — today this platform can check exposure **once, on demand**, but cannot watch continuously or alert anyone automatically.

**Target customer.** Enterprise CISOs and brand-protection teams needing ongoing exposure monitoring, not a one-time check.

**Business value.** Converts two real, working, but disconnected pieces of backend capability (a one-shot exposure scanner and a genuinely-persisted-but-unsurfaced brand-monitoring watchlist) plus one already-built, already-scheduled generic continuous-monitoring engine into one coherent, alertable product.

**Revenue opportunity.** Originally assumed the highest engineering complexity of the four EPEP products (per the CEO's original sequencing). The audit **materially changes this**: a working, cron-scheduled continuous-monitoring engine already exists and only needs to be extended to two new module types, not built from scratch. This is a **positive correction** to the original complexity estimate — see §2.4.

**Market positioning.** "Continuous brand and exposure monitoring built on the same infrastructure that already watches your domains, AI agents, and compliance posture" — real, since the underlying `monitor_configs`/`runMonitoringCron` engine is shared platform infrastructure, not a new one-off system.

---

## 2. Repository-First Capability Audit

### 2.1 Dark Web Exposure Scanner (`darkWebScanEngine.js`) — real signal, not dark-web data, one-shot only

**Verified data sources (only two, both live):** (a) Certificate Transparency log lookup via crt.sh for subdomain/cert exposure (line 58); (b) live HTTP GET probes against 5 well-known leak paths — `.git/config`, `.env`, `.aws/credentials`, `id_rsa`, `.npmrc` (lines 81-96). **No paste-site, forum, or dark-web market access exists anywhere in this file.**

**HIBP breach-database integration is a disabled stub**, not a missing feature: the code path exists (line 156) but is gated on `env.HIBP_API_KEY`, which is **not configured anywhere** in `workers/wrangler.toml` or any docs — it honestly reports `data_source: 'not_configured'` (lines 137-143) rather than fabricating results. This is dormant, procurable capability (a business/procurement task — obtain an HIBP API key — not an engineering build).

**Shape: pure one-shot, zero persistence.** Confirmed **zero `env.DB` references anywhere in this file** — `runDarkWebScan()` computes and returns synchronously, same request→response shape as every other `CAP-SCAN-*` scanner. It has a real, dedicated frontend tab (`frontend/index.html:2240,2521-2542`) — the capability registry's `frontend: exists` claim for CAP-SCAN-007 is correct.

**Classification: Partial** — real signal, real UI, zero persistence/schedule/alerting.

### 2.2 Brand Protection Engine (`brandProtectionEngine.js`) — real watchlist, zero frontend, zero registry entry

**Verified data source:** local typosquat-candidate generation (pure string algorithms, lines 55-141) checked against **real live Cloudflare DoH DNS lookups** (A/MX records, lines 144-169) — genuine domain-squatting recon, not breach data.

**Shape: genuinely persists a watchlist**, unlike the dark-web scanner. `handleBrandAddMonitor` (`revenueFeatures.js:266-313`) inserts a real `brand_monitors` row and fires an async scan; `handleBrandTriggerScan` allows manual re-scan of the same monitor; results persist to a real `brand_threats` table (`brandProtectionEngine.js:258-274`; both tables confirmed in `workers/schema_bootstrap.sql:840-869`, **absent from root `schema.sql`/`migrations/`** — another instance of the platform's real schema living in the ungoverned `workers/schema_v*.sql` files rather than a clean migrations folder, per the cross-cutting DB audit).

**Re-check is 100% manual today** — no code path automatically re-triggers a scan.

**Zero frontend exists** — confirmed by an exhaustive grep of every `frontend/*.html` file for `brand_monitors`, `typosquat`, `/api/brand`, "Brand Protection," and "Brand Monitor": zero matches, not even a teaser mention. **Zero capability-registry entry exists either** — this capability is completely uncatalogued, a genuine Documentation Drift finding to record once this product's scope is approved.

**Classification: Internal/Dormant** — real backend, real persistence, no customer-facing surface at all.

### 2.3 The key positive finding: a real, scheduled, alerting-capable continuous-monitoring engine already exists — and structurally excludes this product today

**Verified:** `workers/src/handlers/monitoring.js`'s `runMonitoringCron()` (lines 309-360, cron-wired at `index.js:8969`) is genuine, working, scheduled infrastructure: it pulls due `monitor_configs` rows, re-executes the relevant scan, computes drift, and sends a real Telegram alert (lines 470-489) — this is not a proposal, it runs in production today for five module types.

**It structurally cannot be used for brand or dark-web targets today, by explicit design, not oversight:** `monitor_configs.module` carries a hard SQL `CHECK (module IN ('domain','ai','redteam','identity','compliance'))` constraint (`workers/schema_bootstrap.sql:2170-2171`), and `getScanHandlers()`'s dynamic-import map (`monitoring.js:544-551`) only wires those same five scan types. A brand or dark-web target **cannot even be inserted** into this system as it stands.

**This is the single most important finding for this product's roadmap:** extending a `CHECK` constraint and a handler map is a small, well-scoped, low-risk Enhancement — not the ground-up "Phase 1: Backend monitoring" build the original rough draft assumed.

**Alerting gap, confirmed by direct grep of every relevant file:** the *only* alert-dispatch mechanism anywhere in the monitoring stack is Telegram, and it fires exclusively for the five whitelisted modules. Zero matches for `notificationPlatform`, `emailEngine`, `sendEmail`, or `dispatchWebhookEvent` in `darkWebScanEngine.js`, `brandProtectionEngine.js`, or their callers. **A CRITICAL brand threat or dark-web finding sits completely inert today** until someone manually re-opens the dashboard.

### 2.4 Capability classification

| Capability | Class | Evidence |
|---|---|---|
| Dark Web Exposure Scanner (CAP-SCAN-007) | **Partial** | Real signals (CT logs + leak-path probes), real UI, zero persistence |
| HIBP breach-database search | **Planned** | Gated on unset `HIBP_API_KEY`, honestly self-disclosed as inert |
| Brand Protection watchlist (`brand_monitors`/`brand_threats`) | **Internal/Dormant** | Real backend + real persistence, zero frontend, zero registry entry |
| Continuous Monitoring engine (`monitor_configs`, domain/ai/redteam/identity/compliance only) | **Production Ready** | Cron-wired, real drift detection + Telegram alert |
| — same engine, extended to brand/darkweb | **Planned, but a small, scoped Enhancement, not a rebuild** | Blocked only by a `CHECK` constraint + a handler map, both easily extended |
| Real dark-web (Tor/paste-site/forum) coverage | **Does not exist; likely Buy, not Build** | No in-house crawling capability anywhere; recommend a commercial dark-web-intel data provider rather than building a crawler in-house (see note below) |
| Real alerting beyond Telegram (email/webhook) for any monitored module | **Enhancement** | `emailEngine.js` and `enterpriseAutomation.js`'s webhook system both already exist and work; they are simply not wired to the monitoring cron's alert dispatch yet |
| `docs/capability-registry/SCHEMA.md`'s illustrative claim ("dark-web scanning has no frontend") | **Stale** | Dark web now has a real frontend tab; Brand Protection is the accurate zero-frontend example today |

**Build-vs-buy note on "dark web":** genuine dark-web monitoring (paste sites, criminal forums, Tor-hosted markets) is a fundamentally different and much riskier engineering undertaking than anything else audited across all four EPEP products — it typically requires either direct, carefully-isolated crawling infrastructure or licensing a commercial feed (e.g., a breach-intelligence/dark-web-monitoring API vendor). **This document recommends buying that specific data source rather than building an in-house crawler**, and scoping this product's "dark web" claim initially to what's real: CT-log exposure + HIBP breach data (once the key is procured) + typosquat/brand recon. This is a commercial/procurement decision for the business, not an engineering one, and is flagged here rather than decided unilaterally.

---

## 3. Customer Personas

| Persona | Need | Value moment |
|---|---|---|
| Enterprise CISO | Continuous assurance, not a point-in-time check | First automated alert on a real drift/new finding |
| MSSP | Monitor multiple client brands from one pane | Multi-tenant watchlist dashboard |
| SOC Manager | Alerts land where the team already works (email/webhook/SIEM), not a dashboard nobody checks | Real email/webhook alert (net-new vs. today's Telegram-only, five-module-only reality) |
| Security Engineer | API-driven ingestion of new findings into existing tooling | Webhook payload consumable by `enterpriseAutomation.js`'s existing event vocabulary |
| Compliance Officer | Evidence of ongoing brand/credential monitoring for an audit | Weekly executive summary (New Build) |
| AI Team | Less directly applicable to this product | — |
| DevSecOps | Programmatic watchlist management | New API (§10) |
| Startup Founder | Cheap, simple brand-exposure baseline | Lower-tier automated check |

---

## 4. Value Proposition

- **Genuinely continuous, not a rebrand of a one-shot scan** — but only once the extension in §2.3 is built; this document does not recommend marketing "continuous monitoring" before that extension ships (Verifiable-Statement Rule).
- **Reuses a real, already-scheduled monitoring engine** rather than building new cron/scheduling infrastructure from scratch — a genuine cost/risk reduction versus the original assumption.
- **Honest scope:** exposure + brand recon + (once procured) breach-database matching — not an overclaimed "dark web crawler."

---

## 5. Feature Matrix

| Feature | Classification | Basis |
|---|---|---|
| One-shot exposure check (CT logs + leak paths) | **Existing** | `darkWebScanEngine.js` |
| One-shot typosquat/brand recon | **Existing** | `brandProtectionEngine.js` |
| Brand/dark-web frontend UI | **New Build** (dark-web tab exists; brand has none) | §2.1-2.2 |
| Persisted watchlist | **Existing (for brand only)** | `brand_monitors` — dark-web scanner has none, would need the same pattern |
| Scheduled re-check | **Enhancement** | Extend `monitor_configs` CHECK constraint + `getScanHandlers()` map |
| Real alerting (email/webhook) | **Enhancement** | Both channels exist platform-wide; neither is wired to this monitoring path |
| HIBP breach-database matching | **Enhancement (procurement-gated)** | Code exists, API key does not |
| Genuine dark-web (paste/forum/market) coverage | **New Build / Buy** | Confirmed absent; recommend third-party data provider |
| Weekly executive summary | **New Build** | No equivalent digest exists for this data today |
| Risk scoring on findings | **Enhancement** | `brand_threats` stores findings; a normalized risk score across both engines' output needs building |
| Multi-tenant/MSSP watchlist view | **New Build** | No existing UI for either engine |

---

## 6. Technical Architecture & Product Architecture

### 6.1 Services

```
   NEW: darkwebBrandOrchestrator.js
        │
   ┌────┴─────────────────────┐
   ▼                          ▼
darkWebScanEngine.js    brandProtectionEngine.js
(existing, extended     (existing, extended with
 with persistence —      auto re-check via cron)
 currently has none)
   │                          │
   └──────────┬───────────────┘
              ▼
   EXTENDED: monitor_configs / runMonitoringCron
   (existing engine — add 'brand','darkweb' to the
    CHECK constraint + getScanHandlers() map)
              ▼
   EXTENDED: sendMonitorAlert (existing, Telegram-only
   today — add email via emailEngine.js and webhook via
   enterpriseAutomation.js's existing dispatch)
```

This is a genuinely thin architecture precisely because most of the needed infrastructure already exists — the new work is almost entirely in the "EXTENDED" boxes, not new engines.

### 6.2 Background jobs

Reuses the existing `runMonitoringCron` tick — **no new cron slot required**, which matters given the platform's 5-slot Cloudflare free-tier cap is already fully consumed (shared constraint with Product 2 — see Master Strategy doc for the combined sizing across both products sharing this limit).

### 6.3 Database

```sql
-- Extend the existing CHECK constraint (schema change, not a new table)
-- ALTER: monitor_configs.module CHECK now includes 'brand','darkweb'

-- New persistence for dark-web scanner (currently has none)
CREATE TABLE darkweb_scan_results (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  monitor_id    TEXT,                  -- links to monitor_configs once extended
  domain        TEXT NOT NULL,
  findings      TEXT,                  -- JSON
  risk_score    INTEGER,
  scanned_at    TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_darkweb_org ON darkweb_scan_results(org_id, scanned_at);

-- brand_monitors / brand_threats already exist (workers/schema_bootstrap.sql) — reused as-is,
-- just needs org_id-scoped indexes confirmed present and a foreign key into monitor_configs.
```

### 6.4 RBAC

Standard org-scoped model. Watchlist management (add/remove monitored brand/domain) maps to org ADMIN+; viewing findings maps to ANALYST+.

### 6.5 Event flow, audit logs, monitoring

Every new finding is a natural `dispatchWebhookEvent` payload (shared dependency with Product 2 — wiring real event dispatch once benefits both products) and a natural email-digest input (weekly executive summary, New Build, §13).

---

## 7. Integration Plan

| Stage | Integration point | Status |
|---|---|---|
| AI Security Hub | New `brand-darkweb-monitoring.html`, extends existing dark-web tab in `index.html` | New Build + Enhancement |
| Sentinel APEX | Not a direct dependency | N/A |
| Threat Intelligence APIs | Optional cross-reference of found credentials against `iocEnrichmentEngine.js` for correlated compromise indicators | Enhancement, optional |
| Commercial Registry | New monitoring-subscription SKU (see §14) | Enhancement |
| Subscription Registry | This product's core commercial model (recurring monthly monitoring fee) is the **most exposed of all four products** to the platform-wide Razorpay recurring-billing gap — see §14 | Blocked (shared), high impact here specifically |
| Payments | Existing Razorpay Orders flow (one-time/manually-renewed) | Existing |
| Marketplace | Optional listing | Enhancement |
| Dashboard | New watchlist + findings widget | New Build |
| Reports | Weekly executive summary (new), on-demand findings report (extends existing) | New Build + Enhancement |
| Notifications | Email + webhook (both need wiring to the monitoring cron's alert dispatch, currently Telegram-only) | Enhancement |

---

## 8. Security Architecture

- **Authentication/Authorization:** standard platform patterns.
- **Tenant isolation:** new `darkweb_scan_results` table org_id-scoped from creation; confirm `brand_monitors`/`brand_threats` have proper org-scoped indexes (audit found the tables exist but did not confirm index completeness — verify during Phase 2).
- **Encryption/Secrets:** the procured `HIBP_API_KEY` (if the business decides to enable HIBP) must go through the platform's existing secret-binding convention, never hardcoded.
- **API security/Rate limiting:** standard middleware; watchlist-add endpoints should be capped per plan tier (reuse the `daily_scans`-style limit pattern from `pricingConfig.js`).
- **Audit logging:** watchlist changes (add/remove monitored brand) are security-relevant and must be audit-logged (who added what target).
- **Compliance logging:** the weekly executive summary itself is compliance evidence — retain per `ARTIFACT_RETENTION_POLICY.md`.
- **OWASP/NIST/ISO 27001/SOC 2/AI security controls:** no new control category; this product's own outbound DoH/HTTP probing (already implemented in `brandProtectionEngine.js`/`darkWebScanEngine.js`) should be reviewed once more for SSRF-adjacent risk given it now runs unattended on a schedule rather than only on a manual customer-triggered request — recommend the same SSRF-guard review applied to `enterpriseAutomation.js` be applied here.

---

## 9. Database Design

See §6.3. **Retention:** findings retained per `ARTIFACT_RETENTION_POLICY.md`; watchlist entries retained until customer removes them (no automatic expiry). **Audit tables:** watchlist add/remove events. **Soft deletes:** status-flag convention, consistent with platform-wide practice. **Multi-tenancy:** org_id-scoped throughout, per the newer (correct) schema convention — this product has no legacy baggage to inherit since it is entirely new tables/extensions.

---

## 10. API Specification

| Endpoint | Purpose | Auth | AuthZ | Rate limit | Versioning |
|---|---|---|---|---|---|
| `POST /api/brand-monitoring/watchlist` | Add a brand/domain/keyword to the watchlist | `requireAuth()` | org ADMIN+ | plan-tier capped | `v1` |
| `GET /api/brand-monitoring/watchlist` | List monitored targets | `requireAuth()` | org member | standard | `v1` |
| `DELETE /api/brand-monitoring/watchlist/:id` | Remove a monitored target | `requireAuth()` | org ADMIN+ | standard | `v1` |
| `GET /api/brand-monitoring/findings` | List findings across the org's watchlist | `requireAuth()` | org member | standard | `v1` |
| `POST /api/darkweb/scan` *(existing, unchanged)* | One-shot exposure check | `requireAuth()` | org member | plan-tier capped | existing |
| `GET /api/brand-monitoring/reports/weekly` | Weekly executive summary | `requireAuth()` | org ADMIN+ | standard | `v1` |

**Errors:** `WATCHLIST_LIMIT_EXCEEDED` (429, per plan tier), `TARGET_INVALID` (400).

---

## 11. UI/UX Blueprint

- **Alert dashboard with neon highlights for critical findings** (from the original rough draft) — genuinely consistent with the platform's real existing design language (**Verified** dark theme with `--danger:#ef4444`/`--warn:#f59e0b` accent variables already defined in `enterprise-dashboard.html`), not an invented flourish.
- **Watchlist management UI:** add/remove targets, view per-target scan history.
- **Findings view:** severity-sorted (canonical `SEVERITY` values), grouped by monitored target.
- **Weekly executive summary:** a new digest view/email template, distinct from the real-time findings dashboard.
- **Charts:** simple trend line (findings over time) — no novel visualization required.
- **Dark mode/Accessibility/Responsive:** inherits platform defaults, same axe-core CI bar.

---

## 12. Customer Journey

Visitor → new `brand-darkweb-monitoring.html` (or extend `attack-surface-management.html`, which already references dark-web scanning in passing) → Pricing → Purchase → Onboarding (add first watchlist target) → Configuration (alert channel preferences: email/webhook) → Execution (scheduled monitoring begins) → Reports (real-time findings + weekly summary) → Renewal (manual, pending platform-wide recurring-billing fix) → Expansion (add more monitored brands/domains, upgrade to MSSP multi-client tier) → Referral (existing affiliate program).

---

## 13. Reporting

Real-time findings dashboard, weekly executive summary (**New Build** — no equivalent digest exists today), risk-scored findings matrix, CSV/JSON export, API access, and (once wired) webhook/email alerts.

---

## 14. Commercial Plan

**This product's core commercial promise — a recurring monthly monitoring subscription — is the one most exposed to the platform-wide Razorpay recurring-billing gap** (see Master Strategy doc). A one-shot "exposure check" doesn't need recurring billing; *continuous monitoring* commercially only makes sense as a subscription. This is a hard dependency this document flags rather than papers over.

| Tier | Price (proposed) | Basis / Status |
|---|---|---|
| Basic monitoring (1 brand/domain, monthly digest only) | ₹15,000/month | Matches the rough draft's low end — **requires** either (a) real recurring billing, or (b) a manually-renewed quarterly/annual pre-paid structure as an interim model |
| Standard monitoring (multiple targets, real-time alerts) | ₹35,000–₹50,000/month | Mid-tier from the rough draft |
| Enterprise/MSSP multi-client monitoring | ₹75,000+/month | Top of the rough draft's range, positioned against the existing `MSSP_WHITE_LABEL` (₹49,999/mo) precedent |

**Recommended interim commercial model until recurring billing is fixed platform-wide:** sell as a **pre-paid quarterly or annual block** (same mechanism as the existing `ANNUAL_RETAINER` package) with a manual-renewal email reminder, exactly matching how "monthly" plans already function today per the cross-cutting audit (`SUBSCRIPTION_REGISTRY_2026-07-14.md` §6) — do not build a bespoke workaround specific to this product.

**Usage/Credits:** number of monitored targets could map to a usage-based credit model — **Proposed**, not built.

**Enterprise Licensing:** MSSP multi-client bundle.

**Professional Services:** manual dark-web-data-source procurement/setup (HIBP key, optional third-party feed) could be sold as an onboarding service line for enterprise customers.

**Marketplace:** optional listing.

**Bundle opportunities:** with Product 2 (shared alerting infrastructure investment) and Product 4 (combined risk-posture bundle).

---

## 15. Financial Model *(Assumed)*

| Line | Estimate | Basis |
|---|---|---|
| Development effort | 5–7 engineer-weeks | Extend monitoring engine (small), add persistence to dark-web scanner (small), build brand-monitoring UI from scratch (New Build), wire real alerting (shared cost with Product 2) |
| Operational cost | Low-to-moderate, dependent on HIBP/third-party data licensing cost if procured | Assumed — actual cost depends on a vendor decision this document does not make |
| Revenue streams | Monitoring subscription (pre-paid interim model), MSSP multi-client | — |
| Gross margin | High if HIBP-only; lower if a paid third-party dark-web feed is licensed per-lookup | — |
| Upsell/cross-sell | Product 2 bundle (shared alert infra), Product 4 bundle | — |
| Enterprise expansion | MSSP multi-client | — |

---

## 16. Go-To-Market & Launch Plan

"Protect Your Brand" campaign (from the original rough draft) is reasonable and low-cost, but should not launch until the naming caveat in §2.4 is resolved — market the real capability (exposure + brand recon + breach-database matching) rather than an unqualified "dark web monitoring" claim, per the Verifiable-Statement Rule. Case studies: blocked on zero real customers platform-wide.

---

## 17. Risk Assessment

| Risk | Category | Mitigation |
|---|---|---|
| "Dark web monitoring" name overstates actual crawling capability | Commercial / Legal (marketing accuracy) | Rename or clearly scope the claim; consider "Attack Surface & Brand Exposure Monitoring" as the accurate primary name with "dark web" as a roadmap item |
| Recurring-billing dependency blocks the core "subscription" commercial model | Commercial | Interim pre-paid quarterly/annual model (§14) |
| Cloudflare free-tier 5-cron-slot cap already fully consumed (shared with Product 2) | Operational | Both products must share the existing tick via fan-out; do not each request a new slot independently |
| Unattended, scheduled outbound DoH/HTTP probing increases SSRF-adjacent surface | Security | Apply the same SSRF-guard review already proven on `enterpriseAutomation.js` |
| HIBP/third-party data licensing cost is unknown pending a business decision | Commercial | Flag explicitly rather than assume a cost; do not commit to HIBP-based pricing before procurement confirms terms |
| Brand Protection engine has zero test coverage evidence found in the audit | Technical | Add test coverage in Phase 6 before relying on it as a paid product's core engine |

---

## 18. Development Roadmap

| Phase | Deliverables | Dependencies | Tests | Acceptance Criteria | Rollback |
|---|---|---|---|---|---|
| 1. Repository reuse | Confirm reuse map; business decision on HIBP/third-party dark-web data source | This document's approval | N/A | Reuse plan + data-source decision approved | N/A |
| 2. Backend | Extend `monitor_configs` CHECK + handler map; add `darkweb_scan_results` persistence; wire email/webhook alerting | Phase 1 | Unit tests | Brand/darkweb targets can be scheduled and re-checked automatically | Revert schema extension; existing 5 modules unaffected |
| 3. Frontend | `brand-darkweb-monitoring.html`, watchlist UI, findings dashboard | Phase 2 | Playwright smoke | Add-target-to-alert-received flow completes end-to-end | Feature-flag off |
| 4. RBAC | Org-scoping on all new tables/endpoints | Phase 2 | Isolation tests | Verified | N/A |
| 5. Commercial | Interim pre-paid SKU in `pricingConfig.js` | Phase 2-3 | Payment sandbox | Order flow works | Disable SKU |
| 6. Testing | Full regression; new tests for `brandProtectionEngine.js` (currently untested) and the extended monitoring cron | Phase 2-5 | Full suite green | Zero regressions | N/A |
| 7. Documentation | Register new CAP-IDs (including correcting `SCHEMA.md`'s stale example) | Phase 2-6 | `validate.mjs` | Registry entries present | N/A |
| 8. Release Candidate | Product Council + CAB gates | Phase 1-7 | Gated pipeline | CAB questions answered | Standard rollback |
| 9. Production | Deploy; Customer Verification | Phase 8 | `dynamic_browser` check | Verified | Standard rollback |

---

## 19. Testing Strategy

Unit tests for the extended `monitor_configs` handler map (brand/darkweb module types); regression tests confirming the existing 5 module types are unaffected by the schema extension; new coverage for `brandProtectionEngine.js` (none found in the audit); alert-dispatch tests for both new channels (email, webhook); SSRF regression tests for the now-scheduled (previously only manually-triggered) outbound probing.

---

## 20. Deployment Strategy

Standard gated pipeline. Schema extension (`CHECK` constraint change) requires the same production-faithful-schema testing discipline `docs/ENGINEERING_STANDARDS.md` §9 calls out (the RC-B1 lesson: a healed lab schema previously masked a production-only failure) — test the migration against a real D1 snapshot, not just a fresh local schema.

---

## 21. Customer Success Plan

Success milestone: first automated finding delivered via email/webhook (not just visible on next login). Expansion signal: customer adds a second monitored brand/domain, or upgrades to MSSP multi-client. Support: new "Monitoring Alert Delivery" ticket category (the most likely failure mode is a misconfigured webhook/email target, mirroring exactly the kind of gap this session already found and fixed once today for the unrelated CAP-NOTIF-003 webhook system).

---

## 22. Business Plan

**TAM/SAM/SOM:** not sized here (no verified figures exist in this repository). **ICP:** enterprises with recognizable brands/executives and prior phishing/impersonation incidents. **Competitor Analysis (Assumed):** dedicated brand-protection and dark-web-monitoring vendors are a mature, well-funded category (this is a Assumed, not verified, competitive landscape observation) — this product's differentiation is bundling into an existing security platform rather than being a point solution, and reusing already-scheduled monitoring infrastructure for a lower cost base. **Pricing Strategy:** §14. **Revenue Forecast:** not modeled with specific figures. **Sales Strategy:** self-serve basic tier; sales-assisted enterprise/MSSP tier. **Partner Strategy:** MSSP channel. **Marketing:** honest positioning per §2.4/§16. **Customer Success:** §21. **KPIs:** targets monitored, findings surfaced, alert-delivery success rate, time-to-alert — all `UNKNOWN` until real usage exists. **Expansion Strategy:** basic → standard → MSSP multi-client → Product 2 bundle (shared alerting investment).

---

## 23. Executive Product Scorecard

| Dimension | Rating | Basis |
|---|---|---|
| Architecture completeness | 🟡 Partial | Two real engines + one real scheduling engine exist, disconnected |
| Reuse of existing platform | 🟢 High (revised upward from the original assumption) | `runMonitoringCron` reuse is the single biggest de-risking finding of this audit |
| New engineering required | 🟡 Moderate | 5–7 engineer-weeks — lower than the original "highest complexity" assumption |
| Security readiness | 🟡 Needs review | Scheduled unattended outbound probing needs an SSRF review pass |
| Commercial readiness | 🔴 Weakest of the four products | Its core "subscription" promise is the one most blocked by the platform-wide recurring-billing gap |
| Customer evidence | 🔴 None | Zero real customers platform-wide |
| Recommended sequencing | **4th of 4, but re-evaluate** | The engineering-complexity case for going last has weakened materially; the commercial-readiness case for going last has strengthened — net, this document does not recommend moving it earlier despite the lower engineering cost, because the recurring-billing blocker is real and shared |

**GO / Conditional GO / NO-GO:** **Conditional GO** — proceed to Phase 1, but treat the naming/positioning decision (§2.4) and the interim billing model (§14) as prerequisites to any external marketing claim, not afterthoughts.
