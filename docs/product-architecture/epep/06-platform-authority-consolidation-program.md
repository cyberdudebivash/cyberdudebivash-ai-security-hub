# Platform Authority Consolidation Program (PACP)

**Program:** Prerequisite to the Enterprise Shared Services Platform (ESSP) and the Enterprise Product Expansion Program (EPEP) — the recommended engineering milestone before either.
**Objective (as scoped):** not to build new functionality. For each of 10 core platform concerns: identify the current production authority, classify every other implementation, and produce a migration plan. **Consolidation itself begins only after this plan exists and is approved** — nothing in this document has been implemented.
**Evidence basis:** synthesized from the nine repository audits already run today for the EPEP and ESSP documents (`00`–`05` in this directory), re-organized through the authority/derived/legacy/dormant/candidate-for-retirement lens this program specifically asks for. No new agents were dispatched — every finding below already has file:line evidence in this program's prior work; this document re-classifies it, it does not re-derive it.
**Classification vocabulary for this program (distinct from the vocabularies used in `00`–`05` — see note below):**
- **Authority** — the one implementation this document recommends treating as authoritative going forward.
- **Derived** — built on top of, delegates to, or correctly reuses the authority. Not a competing implementation.
- **Legacy** — a real, once-load-bearing (or still-partially-used) implementation that predates or duplicates the authority and should be migrated away from.
- **Dormant** — real, complete, functioning code with zero real callers/customers today.
- **Candidate for retirement** — this document's specific, actionable recommendation to remove an implementation (usually a Legacy or Dormant one where the removal case is already strong enough to act on, not just monitor).

> **Note on vocabulary drift across this program's own documents:** `00`–`04` used *Production Ready/Partial/Internal/Dormant/Legacy/Planned*; `05` used *Production Ready/Partial/Legacy/Candidate for Consolidation/New Build Required*; this document uses the four-value scheme above, per this specific request. All three are describing the same underlying evidence through different lenses (product-readiness, shared-service-design, and now production-authority) — they are not in conflict, but do not mix them when reading across documents.

---

## 1. Executive Summary

Every domain below already has a genuine backend that works, in isolation. The problem this program addresses is that **for at least 7 of the 10 domains, more than one implementation is real and none has been formally declared authoritative** — the same root cause behind the concrete defects already found and fixed this session (the SSO audit-log column typo, the CAP-NOTIF-003 webhook duplication) and the fragmentation cataloged in the ESSP document (14+ dashboards, 5 API-key systems, 2 subscription catalogs, 4 audit-logging mechanisms). PACP's job is to stop that pattern from being rediscovered domain-by-domain and instead resolve it once, deliberately, before ESSP builds a shared layer on top of whichever implementation happens to still be running.

**A methodological caveat, stated up front:** for 2 of the 10 domains (Executive Dashboards, Notifications), the evidence does not support naming one single authority — some of the "duplicate" implementations are actually serving legitimately distinct sub-concerns (CISO risk metrics are not a duplicate of MRR; email is not a duplicate of webhooks). Forcing a single false winner in those cases would repeat the exact mistake that produced `platformMetricsAuthority.js` — a file explicitly named and commented as *the* authority that is, in fact, just another independent, unvalidated computation with zero real consumers. Those two domains are handled as **per-sub-concern authorities** below, with the real duplicates called out precisely within each.

---

## 2. Executive Dashboards

**No single authority — this domain has (at least) four legitimate sub-concerns, each needing its own authority, plus one cross-cutting defect (the MRR number itself) that cuts across all of them.**

### 2.1 Sub-concern: current revenue (MRR/ARR)

| Implementation | Classification | Basis |
|---|---|---|
| `revenueOps.js` | **Authority** | Real aggregation directly off the `payments` table; no independent/fabricated price table; confirmed primary backend (most routes matched) for the live `revenue-command-center.html` |
| `revenueMetrics.js` | **Legacy — candidate for retirement** | Also wired to `revenue-command-center.html`, but computes MRR from `users.tier` against its own hardcoded price table (₹999/1,499/4,999/**9,999** for MSSP — a *different* number than `ceoExecutiveDashboard.js`'s ₹49,999 for the same tier). Duplicates `revenueOps.js`'s concern with a less-authoritative method |
| `revenueDashboard.js` | **Dormant — candidate for retirement** | No confirmed frontend caller anywhere in the repo |
| `revenueKPI.js` | **Dormant** | Sound methodology (real `payments`/`cac_events`/`proposals` tables, no fabricated price table) but no confirmed frontend caller — worth re-checking for a caller before retiring, since its CAC/LTV method is the best of the set |
| `ceoExecutiveDashboard.js` | **Legacy — candidate for retirement** | Zero frontend callers found anywhere; a comment in `revenue-engine-v14.js` explicitly documents it was never wired in |
| `enterpriseTransformHandler.js` | **Derived, with a defect** | Real consumer (`enterprise-kpi-dashboard.html`, staff-gated) — legitimate distinct "board/CEO export format" sub-concern, worth keeping, but its MRR figure should be re-sourced from `revenueOps.js` rather than its own 6th independent price table |
| `executiveReport.js` | **Legacy authority-by-default — must not stay authoritative as-is** | This is the one actually live at the collision-prone `/api/executive/dashboard` route (called by `index.html`) — but its MRR (`getMRRData()`) is read from a **manually-typed KV config blob**, not derived from billing data at all. It is the *de facto* production authority today by virtue of being the one thing customers see, and it is exactly the wrong one to keep: the number displayed is admin-entered, not computed |

**Migration plan:** re-point `executiveReport.js`'s MRR display at `revenueOps.js`'s real computation (or retire `executiveReport.js`'s own MRR section entirely in favor of embedding/calling `revenueOps.js`), retire `revenueMetrics.js`/`revenueDashboard.js`/`ceoExecutiveDashboard.js` after one final zero-callers confirmation, and re-point `enterpriseTransformHandler.js`'s MRR field at the same authority. `revenueKPI.js` gets a final caller check before its retirement is finalized.

### 2.2 Sub-concern: CISO / security risk metrics

| Implementation | Classification | Basis |
|---|---|---|
| `cisoMetrics.js` | **Authority** | Real `scan_history`/`compliance_results` aggregation, honestly returns `null`/`data_available:false` rather than fabricating, matches `CAP-DASH-001`, tested, real consumer (`user-dashboard.html`) |
| `executiveCommandCenter.js` | **Dormant — candidate for retirement** | Real FAIR risk/breach-cost/KRI computation, 595 lines, but zero frontend consumers anywhere; its own internal route case is dead code (shadowed by an earlier exact-match route) |
| `executiveRiskHandlers.js` | **Legacy — candidate for retirement** | Previously collided in production with `executiveReport.js` on the same route (documented in-code); moved to `/risk-dashboard`, zero frontend callers since the move |

**Migration plan:** confirm zero callers once more (both were already zero-caller at audit time), retire both after that confirmation. Neither has a real customer-facing gap to backfill — `cisoMetrics.js` already covers this sub-concern adequately.

### 2.3 Sub-concern: revenue intelligence / forecasting (churn, NRR, expansion)

| Implementation | Classification | Basis |
|---|---|---|
| `revenueIntelligenceHandler.js` | **Authority** | Cleanest of the fourteen — imports canonical `SUBSCRIPTION_TIERS` rather than hardcoding a price table, real churn/NRR/expansion-MRR logic against `customer_health`, 1:1 with the live `revenue-intelligence-dashboard.html` |
| `revenueIntelligence.js` | **Dormant / Derived-candidate** | Real `revenue_snapshots` writer, admin/API-only, no UI — worth checking whether it feeds data the authority above could consume before retiring outright |

**Migration plan:** confirm whether `revenueIntelligenceHandler.js` already reads `revenue_snapshots`; if so, `revenueIntelligence.js` is Derived (an ingestion path feeding the authority) and should stay; if not, it is Dormant and a candidate for retirement once one caller-check confirms no other consumer exists. **Separately, and higher priority:** `revenueIntelligenceHandler.js` currently imports `SUBSCRIPTION_TIERS` from `subscriptionPaywallEngine.js` — the **Subscriptions domain's Legacy/candidate-for-retirement catalog** (§4). This is a concrete, cross-domain migration dependency: this handler must be re-pointed at the Subscriptions domain's authority (`pricingConfig.js`) *before* `subscriptionPaywallEngine.js`'s catalog can be safely retired.

### 2.4 Sub-concern: decision summaries

| Implementation | Classification | Basis |
|---|---|---|
| `decisionHandler.js` | **Authority** | Explicitly reuses (its own header: "Reuses — NEVER duplicates") `decisionEngine.js`, `adaptiveCyberBrain.js`, `compositeRiskScoring.js`; best-architected of the fourteen; clean 1:1 with the live `decision-dashboard.html` | 

No other implementation competes in this sub-concern — nothing to migrate here.

### 2.5 The uncomfortable finding: the self-declared "authority" isn't one

`platformMetricsAuthority.js` is explicitly named and commented as *the* single source of truth ("eliminates data inconsistency") — direct inspection shows it is itself an independent computation over a disjoint table slice (`scan_results`, `soc_cases`, `cti_iocs`, plus an MRR figure read from `revenue_snapshots.mrr` without validating against any of the other writers of similarly-named tables), and it has **zero real frontend consumers today** (`frontend/platform-authority.js` is not loaded by any HTML page in the repo).

**Classification: Legacy — candidate for retirement, as currently implemented.** The *name and intent* are worth keeping — a genuine cross-domain metrics authority is exactly what this domain needs — but the current code should not be trusted as a foundation. **Recommendation:** once §2.1–2.4's per-sub-concern authorities are consolidated, rebuild `platformMetricsAuthority.js` as a thin composition layer over them (a real aggregator calling the four authorities, not a fifth independent computation), or retire it if no consumer need for a single composed view materializes.

---

## 3. Billing

**Authority: Razorpay Orders API, via `workers/src/lib/razorpay.js` + `payments.js`.** Real order creation, HMAC signature verification, D1 entitlement write — the live path behind most SKUs (marketplace, subscriptions, one-time packages). Note the scope of this authority precisely: **one-time orders only** — no Razorpay Subscriptions API integration exists anywhere in this codebase (see the EPEP master strategy doc §3.1 for the full evidence trail).

| Implementation | Classification | Basis |
|---|---|---|
| PayPal (`services/v24/billingEngine.js` + `v24Handler.js`) | **Derived (legitimate parallel rail, not a duplicate)** | Real PayPal Orders v2 integration, now correctly sources its amount from the server-side plan catalog (PR #242) rather than an independent one. This is an intentional second payment method, not a competing authority — no migration needed beyond keeping its pricing source in sync with §4's authority |
| Gumroad (`services/gumroadEngine.js`) | **Derived (narrow, by design)** | License-verify only; checkout happens externally on Gumroad's platform. Not a duplicate — a different distribution mechanism entirely |
| Manual UPI/bank/crypto (`manualPayments.js`) | **Derived (deliberate fallback, not a duplicate)** | Explicitly the "Primary Revenue Engine" per its own header comment, for customers Razorpay can't serve. Not a candidate for retirement — it is filling a real, intentional gap |
| `subscriptionPaywallEngine.js`'s `createRazorpaySubscription()` | **Legacy — candidate for retirement** | Misleadingly named: its body creates a one-time Razorpay Order, identical in kind to what `payments.js` already does, under a name that implies (falsely) recurring billing. This is the one genuine duplicate in this domain |

**Migration plan:** rename or remove `createRazorpaySubscription()`'s misleading name immediately (cheap, no functional change); once the Subscriptions domain (§4) is consolidated onto `pricingConfig.js`, delegate this function's order-creation call to the same shared helper `payments.js` uses, rather than maintaining a second implementation of "create a Razorpay order." Do not touch PayPal/Gumroad/Manual — they are correctly-scoped alternates, not consolidation targets.

---

## 4. Subscriptions (Tier/Plan Catalogs)

**Authority: `workers/src/config/pricingConfig.js`** — self-documented "IMMUTABLE SOURCE OF TRUTH," the live catalog behind `payments.js`/`lib/razorpay.js` (Plans: FREE/STARTER/PRO/ENTERPRISE/MSSP).

| Implementation | Classification | Basis |
|---|---|---|
| `subscriptionPaywallEngine.js`'s `SUBSCRIPTION_TIERS` (COMMUNITY/PROFESSIONAL/TEAM/BUSINESS/ENTERPRISE) | **Legacy — candidate for retirement** | Unreachable from any shipped frontend page; carries a live, unfixed **10× price bug** on its "ENTERPRISE" tier (₹49,999 vs. ₹4,999 for the identically-named plan elsewhere) |

**Migration plan (sequenced, since this catalog has a real, if narrow, dependent):**
1. Identify every caller of `subscriptionPaywallEngine.js`'s `SUBSCRIPTION_TIERS` — confirmed so far: the module itself, and **`revenueIntelligenceHandler.js`** (§2.3), which imports it specifically because it's the "canonical" catalog *within that file's context* — a good instinct pointed at the wrong catalog.
2. Re-point `revenueIntelligenceHandler.js` at `pricingConfig.js` instead.
3. Re-verify no other caller exists (repeat the same zero-callers discipline already proven for the CAP-NOTIF-003 webhook retirement).
4. Retire `subscriptionPaywallEngine.js`'s `SUBSCRIPTION_TIERS` and fix or remove `createRazorpaySubscription()`'s naming (§3) in the same wave, since both live in this file.
5. **Do not fix the 10× price bug in place** — the catalog is being retired, not corrected; fixing it first would be wasted effort on a system already scheduled for removal.

---

## 5. API Keys

**Authority: `CAP-DEVPORTAL-001`, `workers/src/auth/apiKeys.js` + `handlers/apikeys.js`** — canonical, `cdb_`-prefixed, SHA-256-hashed, per-tier count and quota limits, ownership-scoped.

| Implementation | Classification | Basis |
|---|---|---|
| `CAP-DEVPORTAL-003` (`developerPortal.js`) | **Derived** | Already delegates to the canonical handlers post-fix — no further migration needed |
| `CAP-DEVPORTAL-002` (`enterpriseAutomation.js` self-service keys) | **Legacy — candidate for consolidation** | An independent implementation, not yet delegating |
| `CAP-DEVPORTAL-004` (`apiRevenueEngine.js`/`growth.js`, `sap_`-prefixed) | **Legacy — candidate for retirement** | Different data model (email+plan, separate `api_usage_log` table); previously had a critical unauthenticated free-ENTERPRISE-key-minting vulnerability (fixed 2026-07-12) — the kind of risk a 5-way-duplicated auth surface invites |
| MSSP customer keys (`msspTenantPlatform.js`, `mssp_customer_api_keys`) | **Legacy today; target state is Derived, not deleted** | Serves a real, not-otherwise-served need (MSSP delegated sub-account key issuance) — the right end state is rebuilding this on top of the CAP-DEVPORTAL-001 primitives with MSSP-specific scoping added, not simple removal, since removing it without a replacement would regress real MSSP functionality |

**Migration plan:** consolidate `CAP-DEVPORTAL-002` onto the canonical handlers first (same shape as -003's already-completed migration — a proven, low-risk template to repeat). Retire `CAP-DEVPORTAL-004` next, migrating its email+plan model's real customers (if any exist — verify before assuming zero, since this one is growth/self-serve-tier and more likely to have real keys issued than the admin-only dashboards in §2) onto the canonical ownership-scoped model. MSSP key issuance is a **rebuild-on-authority** project, not a retirement — sequence it last, and treat it as related to (but not blocking) the pre-existing, separately-tracked `CAP-MSSP-004` delegated-admin-permissions gap. Three of the five implementations independently reimplement identical SHA-256 hashing logic — collapsing onto one hashing helper is a free, low-risk first step regardless of sequencing.

---

## 6. Campaign Orchestration

**No existing implementation is a clean authority — the closest-to-authority-quality *pattern* is `emailEngine.js`'s `DRIP_SEQUENCES`/`email_sequences` state machine** (real D1 persistence, atomic conditional enrollment avoiding TOCTOU races, cron-driven step advancement) — nominated as the **pattern authority** (the schema/engine other campaign types should be rebuilt on), while being explicit that it is channel-specific (email only) today, not yet a generic cross-domain authority.

| Implementation | Classification | Basis |
|---|---|---|
| `ai_redteam_campaigns` (`aiRedTeamPro.js`) | **Dormant** | Real schema, zero execution engine behind it (confirmed in the EPEP Product 1 audit) |
| `renewal_queue` (`renewalEngine.js`) | **Legacy — candidate for consolidation** | Same conceptual pattern as `email_sequences` (step-tracking, cron-driven), independently reimplemented in a separate table |
| `salesPipeline.js` KV stage tracker | **Legacy — candidate for consolidation** | Real, but manually-advanced only — no automatic trigger/step-progression, the weakest of the five |
| `content_queue` (`contentEngine.js`) | **Legacy — candidate for retirement** | One of two duplicate one-shot content pipelines |
| `blog_posts` (`contentPipeline.js`) | **Legacy — candidate for consolidation (keep this one)** | The more complete of the two (AI-authored via the real AI Orchestration Layer, own LinkedIn queueing) — nominate as the survivor between these two specifically |

**Migration plan:** this is the domain furthest from having a real authority, so the plan is closer to a new build informed by salvageable parts (matching the ESSP document's own assessment) than a simple pick-one-and-retire-the-rest: (1) retire `content_queue` in favor of `blog_posts`' pipeline (the one clean single-duplicate elimination available immediately); (2) generalize `email_sequences`' schema/engine to a channel-agnostic `campaigns`/`campaign_steps` shape (as specified in the ESSP document §6); (3) migrate `renewal_queue` and `salesPipeline`'s stage tracking onto the generalized shape; (4) give `ai_redteam_campaigns` a real execution engine on the same foundation only once ARaaS Stage A/B (EPEP Product 1) is approved to proceed.

---

## 7. Reports

**Authority: `reportingEngine.js`** — 6 templates including `AI_SECURITY`, the broadest and most template-driven of the three report-generation implementations.

| Implementation | Classification | Basis |
|---|---|---|
| `secureDownload.js` | **Legacy — candidate for consolidation** | Own bespoke HTML template + KV cache + signed-token store (574 lines) — real and working, but a parallel template system that should migrate into the authority's template list |
| `aiGovernancePdfHandler.js` | **Derived-candidate — preserve content, retire the standalone handler** | Real, genuinely strong CISO-grade template (board-ready PDF/HTML export) — the recommendation is to migrate this specific template *into* `reportingEngine.js` as a new template type, not simply delete it, since the content is a real asset worth keeping |

**Migration plan:** neither existing report engine writes to the platform's own real, production-grade blob storage (`workers/src/lib/r2.js`, currently scoped only to scan-job JSON) — route all three (post-consolidation, one) report engines' output through it, closing the storage gap and the duplication gap in the same wave, per the ESSP document §5.2's design.

---

## 8. Audit Logging

**Authority: the D1 `audit_log` table, written correctly via the pattern in `orgManagement.js`'s `writeOrgAuditLog()` (and `aiSecurityCopilot.js`'s equivalent `writeCopilotAuditLog()`).**

| Implementation | Classification | Basis |
|---|---|---|
| `enterpriseSsoHandler.js`'s writer | **Was Legacy (broken) → now Derived** | Fixed in a dedicated PR (#254/#255 lineage — see this session's separate SSO audit-log fix) to use the authority's real `metadata` column instead of a non-existent `detail` column. Now a correct, additional writer to the same authoritative table |
| `auditLog.js`'s KV mechanism (`writeAuditEvent`) | **Dormant — candidate for retirement** | Fully built (90-day TTL, integrity hash, a declared event-type taxonomy) but has zero real callers anywhere beyond its own admin-gated endpoint |
| `opsEngine.js`'s `writeOpsAudit` (KV) | **Legacy — candidate for consolidation, not immediate retirement** | Has real, active callers (e.g. feature-flag changes) — not dead like the one above — but its own header comment falsely claims to "wrap" `auditLog.js`'s mechanism when it in fact independently copy-pastes the same KV/integrity-hash pattern. A real parallel mechanism, not a dead one |
| `history.js` (scan history) | **Not part of this domain — explicitly excluded** | A legitimately distinct concept (customer-facing "my past scans," not a security audit trail) that happens to share the same fragmentation *pattern*. Do not sweep this into the audit-logging consolidation by proximity |

**Migration plan:** (1) the SSO fix is already done, standalone, low-risk (this session). (2) Retire `auditLog.js`'s KV mechanism outright — zero real callers means zero migration risk, the cleanest retirement in this entire program. (3) Migrate `opsEngine.js`'s real call sites (feature-flag changes, etc.) to write directly to the D1 `audit_log` table instead of its own KV mechanism; keep `handleAdminAudit()`'s KV+D1 merge logic only for the transition period (to avoid losing visibility into already-written KV entries), then retire the merge once new KV writes stop. (4) Leave `history.js` alone.

---

## 9. AI Orchestration

**Authority: `workers/src/core/aiProviderRouter.js` (`routeAICall`) + `mythosAIProvider.js` (`callClaude`, its backward-compat wrapper).** Confirmed real: 6-provider routing (Groq/DeepSeek/Together/CF-Workers-AI/OpenRouter/Anthropic), KV-backed circuit breaker, cross-provider deadline budget, imported by 23 distinct files including the platform's single highest-traffic route (`/api/scan/domain`). Two dedicated regression suites tied to real production incidents already protect it.

| Implementation | Classification | Basis |
|---|---|---|
| `mythosOrchestrator.js`, `mythosGodMode.js`, `mythosGovernor.js`, `mythosEnrichmentEngine.js`, and 14 other listed callers | **Derived, correctly** | These are consumers of the authority (they call `routeAICall`/`callClaude`), not competing orchestration layers — no migration needed, this is already the right shape |
| `multi-agent-os/` (standalone Python/FastAPI service, repo root) | **Candidate for retirement** | Definitively confirmed never deployed to production — its own CI config states "this has never executed on any push or PR"; zero references from `workers/src/` resolve to it; its own internal AI-router is a cruder duplicate (error-count failover only, no circuit breaker) of the authority already live. Zero migration risk since it never had real callers — the cleanest possible retirement candidate in this entire program |

**Migration plan:** nothing to migrate for the authority itself — this domain needs designation and documentation, not consolidation work. For `multi-agent-os/`: confirm with the business that no one intends to resume this project (a one-question check, not an engineering task) before deleting the directory; its 65+ agent-role class definitions may be worth mining as a taxonomy reference before removal, but the runtime itself should not be treated as infrastructure in any future architecture decision.

---

## 10. Notifications

**No single authority — three legitimate per-channel authorities, plus one narrow mechanism that should be migrated onto them rather than kept as a fourth permanent channel.**

| Implementation | Classification | Basis |
|---|---|---|
| `enterpriseAutomation.js` (outbound webhooks) | **Authority (webhook channel)** | Real HMAC-SHA256 signing, real delivery log, working UI (post `#253`) |
| `emailEngine.js` | **Authority (email channel)** | Production Ready, `GA APPROVED WITH DOCUMENTED LIMITATIONS` per the capability registry |
| In-app bell (`CAP-NOTIF-002`) | **Authority (in-app channel)** | Production Ready, isolated, working |
| Telegram (`monitoring.js`'s cron alerts, `sendMonitorAlert`) | **Legacy — candidate for migration, not retirement of the underlying alerting need** | The *only* channel the one real continuous-monitoring engine (`runMonitoringCron`) actually reaches — a narrow, bespoke, single-purpose mechanism that exists because the real channels were never wired to this specific cron job, not because Telegram is architecturally wrong |

**Migration plan:** this is not a "duplicate implementation" problem in the usual sense — it's a **missing-integration** problem. `dispatchWebhookEvent` (the webhook authority's real-event-dispatch function) has zero callers platform-wide; `runMonitoringCron`'s alerting only reaches Telegram. The fix for both is the same piece of work: wire real event dispatch once, so any engine's findings can reach webhook + email + in-app (and, optionally, keep Telegram as an *additional* channel for internal ops alerting specifically, not the only channel available to a customer-facing monitoring feature). This is already scoped as ESSP document §5.2's Notification Engine design and §9 Wave 8 — PACP's contribution here is confirming there is no hidden fourth "notifications" implementation competing with these three; there is one integration gap instead.

---

## 11. Usage Metering

**Authority: `auth/apiKeys.js`'s `trackApiKeyUsage()` / `checkDailyQuota()`** — real, D1-backed, atomic counting. Scope note: currently wired into **only** the API-key auth path.

| Implementation | Classification | Basis |
|---|---|---|
| `aiSecurityCopilot.js`'s own `checkDailyQuota()` (KV-based) | **Legacy — candidate for retirement** | An independently-built quota system scoped only to copilot chat messages, sharing nothing with the authority beyond a coincidentally identical function name |
| `pricingConfig.js`'s `daily_scans` field | **Not an implementation — a data/config inconsistency, handled differently** | This is a *number*, not competing code. It is the publicly advertised limit, but it is enforced by **nothing** anywhere in the codebase — the number actually enforced (`TIER_LIMITS.daily_limit` in `apiKeys.js`) is different and already flagged as an unfixed drift in this repo's own audit trail (`PRODUCTION_RELEASE_GATE_PHASE2_2026-07-14.md`). This needs a **business decision on which number is correct**, not a code migration |
| JWT/session (majority) web traffic | **Not an implementation — a genuine gap** | No quota enforcement of any kind exists on this path today. This is new work to extend the authority's reach, not a duplicate to consolidate |

**Migration plan:** (1) retire `aiSecurityCopilot.js`'s KV quota system, migrating its counting onto the D1 authority (small, low-risk — it's a narrower, single-purpose duplicate). (2) Flag the `daily_scans`-vs-`TIER_LIMITS.daily_limit` numeric drift to the business for a decision (this document does not pick a winner between two customer-facing numbers unilaterally — that is a commercial decision with revenue and customer-communication implications, not a code-quality one). (3) Once a number is confirmed, extend `checkDailyQuota()`'s enforcement to JWT/session traffic — the majority of real usage today has no ceiling at all, which is the actual production risk in this domain, larger than the duplication itself.

---

## 12. Cross-Domain Migration Sequencing

Following the same six-phase discipline already proven in this repository (validate → migration matrix → risk determination → implement with compatibility → migrate callers → retire only after), and the ESSP document's own wave-pacing SOP, recommended order:

| Wave | Domain(s) | Why this order |
|---|---|---|
| 1 | Audit Logging | Already substantially done (SSO fix shipped); cheapest remaining step (retire the zero-caller KV system) is genuinely zero-risk |
| 2 | AI Orchestration | Designation-only for the authority; the one retirement (`multi-agent-os/`) is zero-risk by confirmed zero-callers |
| 3 | API Keys | Proven template already exists (CAP-DEVPORTAL-003's completed migration) to repeat for -002 and -004 |
| 4 | Subscriptions → Billing | Subscriptions must move first (§4) because Billing's one real fix (§3) depends on it; both touch `subscriptionPaywallEngine.js` |
| 5 | Executive Dashboards | Largest single domain (14+ implementations); do after the smaller, faster wins above build momentum and process confidence |
| 6 | Reports | Depends on nothing else; can run in parallel with wave 5 if capacity allows |
| 7 | Notifications | The `dispatchWebhookEvent` wiring is shared prerequisite work for two EPEP products (Threat Intel Automation Pack, Dark Web & Brand Monitoring) — sequence before those products' own Phase 2 |
| 8 | Usage Metering | The business decision on the numeric drift should happen early (flag now), but the enforcement-extension engineering can land whenever capacity allows — not urgent relative to the others |
| 9 | Campaign Orchestration | Furthest from a real authority; genuinely closer to new construction than consolidation — sequence last, and treat as a joint effort with EPEP Product 1/2's own campaign needs rather than a pure infrastructure exercise |

**This document stops here.** Per the program's own framing, consolidation implementation begins only once this plan is reviewed and approved — no waves above have been started.

---

## 13. Relationship to ESSP and EPEP

This confirms and sharpens the sequencing already agreed for the broader program: **PACP → ESSP → EPEP products.** Concretely: ESSP's `05` document's per-component "target design" (§5.2 of that document) already assumed a single authority per shared engine; this document is what makes that assumption true rather than aspirational — e.g., ESSP's Notification Engine design (built on `enterpriseAutomation.js` + `emailEngine.js`) only works cleanly if this document's §10 findings (no hidden fourth notifications system, just a missing integration) hold up, which they do. Where this document identifies a *business* decision rather than an engineering one (the `daily_scans` drift, whether to keep developing `multi-agent-os/`), those are flagged for you rather than resolved here, consistent with this program's consistent practice across all six documents produced today.

---

## 14. Executive Scorecard

| Domain | Authority exists today? | Consolidation complexity | Zero-risk retirements available now |
|---|---|---|---|
| Executive Dashboards | Partial (4 sub-authorities, 1 cross-cutting MRR defect) | High (14+ implementations) | 4 (confirmed zero-caller) |
| Billing | Yes | Low | 1 (misleading function name/duplicate order-creation) |
| Subscriptions | Yes | Low-Medium (1 real dependent to re-point first) | 0 until §2.3's dependency is resolved |
| API Keys | Yes | Medium (2 real migrations, 1 rebuild-not-retire) | 0 (all have or may have real callers) |
| Campaign Orchestration | No — pattern authority only | High (closer to new build) | 1 (`content_queue`) |
| Reports | Yes | Medium (2 real migrations, 1 content-preserving) | 0 (both have real value to migrate, not just delete) |
| Audit Logging | Yes | Low (mostly done) | 1 (`auditLog.js`'s KV system) |
| AI Orchestration | Yes | Very low (designation only) | 1 (`multi-agent-os/`, if confirmed abandoned) |
| Notifications | Yes (3 per-channel) | Low (integration gap, not duplication) | 0 (nothing to retire, something to wire) |
| Usage Metering | Yes (narrow scope) | Low-Medium (1 retirement, 1 business decision, 1 real gap to close) | 1 (copilot's KV quota system) |

**GO / Conditional GO / NO-GO:** **Conditional GO** — proceed to Wave 1 (Audit Logging cleanup) and Wave 2 (AI Orchestration designation) immediately given their confirmed zero migration risk; Waves 3 onward proceed in the sequence in §12, each gated by its own regression-clean checkpoint; the two flagged business decisions (`daily_scans` vs. `TIER_LIMITS.daily_limit`, and `multi-agent-os/`'s fate) should be resolved before Waves 8 and 2 reach their retirement step, respectively, but do not block starting the program.
