# Enterprise Shared Services Platform (ESSP)

**Program:** Prerequisite to the Enterprise Product Expansion Program (EPEP) — recommended as the next engineering milestone, before any of the four premium products (ARaaS, Threat Intel Automation Pack, Dark Web & Brand Monitoring, AI Security Maturity Assessment) enters Phase 2 (Backend) of its own roadmap.
**Status of this document:** Proposed architecture. No new code has been written under this program yet.
**Evidence basis:** Direct repository audit, 2026-07-15 (commit `d7841aa`), combining nine parallel audits run across two passes today (five for the EPEP product docs, four new ones for this document) plus direct reads of `ARTIFACT_RETENTION_POLICY.md`, `docs/SECURITY_QUESTIONNAIRE_PACK.md`, and `docs/capability-registry/EXECUTION_PROCEDURE.md`. Claims tagged **Verified** / **Assumed** / **Proposed** per CLAUDE.md.

---

## 1. Executive Summary

**The case for ESSP is not hypothetical — it has already happened, repeatedly, in this codebase.** Before this document was written, this program's audits (across both the EPEP product docs and this one) found the *exact* four-parallel-implementations failure mode the mission statement warns about, already realized, independent of any of the four premium products:

| Concept | Parallel implementations found | Worst consequence found |
|---|---|---|
| Executive/revenue dashboards | **14+** independent backends, feeding at most 6 real frontend pages | "MRR for the PRO tier" resolves to **6 different hardcoded values** across files, mixing currencies; "composite risk score" has 5 independent methodologies; the one file named and commented as *the* fix (`platformMetricsAuthority.js`) is itself uncanonical and has zero real consumers |
| API key issuance | **5** independent systems, 2 incompatible data models | 3 of the 5 independently reimplement identical SHA-256 hashing logic; one had a critical unauthenticated free-tier-key-minting vulnerability (fixed 2026-07-12) |
| Subscription/pricing tiers | **2** parallel catalogs | One has a live, unfixed **10× price bug** on its "ENTERPRISE" tier |
| Audit logging | **4** parallel mechanisms (1 D1 table, 2 KV reimplementations, 1 unrelated "history" concept) | An SSO-login audit writer silently no-ops on every call (wrong column name, swallowed by a `try/catch`) — a real, previously-undetected defect this audit surfaced incidentally |
| Report/PDF generation | **3** independent implementations | None use the platform's own real, production-grade blob storage (`lib/r2.js`); all three fall back to browser-print-of-HTML because no binary PDF library exists |
| IOC enrichment | **4** parallel code paths (found in the EPEP Threat Intel audit) | Registry self-discloses none are reconciled |
| Campaign/sequence orchestration | **5** siloed implementations (email drips, renewals, sales stages, 2 content pipelines) | Zero shared schema; each reinvents step-tracking independently |

This is the strongest possible evidence for the mission statement's premise: **building four more products without a shared layer would not risk creating duplication — it would continue a pattern this specific codebase has already demonstrated, nine separate times, that it falls into by default.**

**The good news:** two of the fifteen proposed ESSP components are **already real, shared, production-grade infrastructure** and need only to be formally recognized and built upon, not built from scratch — RBAC and the AI Orchestration Layer (`aiProviderRouter.js`/`mythosAIProvider.js`, a genuine multi-provider-routing, circuit-broken, deadline-budgeted library already called by 15+ independent handlers on the platform's highest-traffic path). One further component, Assessment Engine, has abundant raw material (5+ independent maturity-scoring engines) that needs unifying rather than inventing. The rest range from Partial to New Build Required — detailed in §2.

**Recommendation:** proceed with ESSP as the next engineering milestone, paced as a **bounded, multi-wave program** using the exact same operational discipline this repository already proved out for exactly this kind of multi-session consolidation work (`docs/capability-registry/EXECUTION_PROCEDURE.md`) — not a new process, the existing one, applied to a new evidence store. See §9.

---

## 2. Repository-First Audit: Classification of All 15 Proposed ESSP Components

Taxonomy per this program's request: **Production Ready** (real, shared, no action needed) · **Partial** (real foundation, needs extension) · **Legacy** (real but wrong-shaped, should be phased out) · **Candidate for Consolidation** (2+ real parallel implementations, needs merging) · **New Build Required** (no reusable shared foundation exists).

| # | Component | Classification | Evidence |
|---|---|---|---|
| 1 | **Campaign Engine** | **Candidate for Consolidation** (bordering New Build for a true generic abstraction) | 5 siloed implementations, no shared schema: `ai_redteam_campaigns` (inert schema, AI red-team only); `emailEngine.js`'s `DRIP_SEQUENCES`/`email_sequences` (the most mature — real D1 state machine, atomic enrollment, cron-driven, but email-only, linear); `renewalEngine.js`'s independent `renewal_queue` (same conceptual pattern, zero code sharing); `salesPipeline.js`'s KV stage tracker (manually advanced only); two duplicate one-shot "content campaign" pipelines (`contentEngine.js` → `content_queue`, `contentPipeline.js` → `blog_posts`, both independently reimplementing Telegram-posting) |
| 2 | **Assessment Engine** | **Partial** | 5+ independent maturity/scoring engines, never unified: `aiSecurityScorecardHandler.js` (5-dimension composite, no level taxonomy), `aiGovernancePro.js` (real 5-level CMMI-style maturity, NIST-AI-RMF-scoped), `dpdpCompliance.js` (6-tier maturity, best prior art), `devSecOpsEngine.js` (5-level + sprint-phased roadmap, best prior art for remediation planning), `complianceEngine.js` (per-framework %). Full detail in EPEP Product 4 document §2 |
| 3 | **Workflow Engine** | **Partial** | `workflowAutomation.js`'s `executeStep()`/`handleExecuteWorkflow()` is a real, D1-backed, RBAC-gated, 5-action linear executor with execution history — a legitimate foundation, but no branching/approval gates. Two files both named `decisionEngine.js` (`workers/src/agents/` and `workers/src/services/`) share no code and use different taxonomies. `decisionHandler.js`'s "Decision Platform" naming is misleading — it is explicitly advisory-only (own comment: "no automated actions are taken") and should not be mistaken for workflow capability |
| 4 | **Scheduling Engine** | **Partial** | Real, working primitives exist (`monitor_configs`/`runMonitoringCron`, cron-wired, drift detection; `scan-jobs`/`scan-jobs-dlq` Cloudflare Queue, consumed by `lib/queue.js`) — but hardcoded to 5 module types via a SQL `CHECK` constraint, and the Cloudflare Workers free-tier **5-cron-slot ceiling is already fully consumed**. No generic "register any recurring job type" abstraction exists |
| 5 | **Notification Engine** | **Candidate for Consolidation** | 4 disconnected channels, no unified dispatch: `enterpriseAutomation.js` webhooks (real HMAC signing + delivery log, but `dispatchWebhookEvent` has zero real callers — manual test-fire only); `emailEngine.js` (real, GA-rated); Telegram (the *only* channel `monitoring.js`'s cron alerts actually reach); in-app bell (`CAP-NOTIF-002`, isolated). A finding in one engine (e.g. a brand-monitoring alert) cannot today reach a customer via more than one of these without bespoke per-engine wiring |
| 6 | **Reporting Engine** | **Candidate for Consolidation** | 3 independent report/PDF implementations with 3 different storage postures: `reportingEngine.js` (template-driven, 6 templates incl. `AI_SECURITY`, styled-HTML-to-browser-print, no storage layer used); `secureDownload.js` (own bespoke HTML template + KV cache + signed-token store, 574 lines, same browser-print pattern); `aiGovernancePdfHandler.js` (stateless render, no persistence at all). **None use the platform's own real R2 blob-storage primitive** |
| 7 | **Evidence Engine** | **New Build Required** | No shared evidence/citation object exists. Three incompatible shapes in live use: `ai_findings` (normalized rows), `service_assessments.findings_json` (denormalized JSON blob), `ai_governance_assessments.answers` (Q&A shape). The platform's one "evidence pack" artifact (`docs/SECURITY_QUESTIONNAIRE_PACK.md`) is hand-synced markdown, proven to drift — `trustCenter.js`'s own comment documents that this doc, `trustCenter.js`, and `enterprisePortalHandlers.js` each previously asserted a *different* data-residency claim before manual reconciliation |
| 8 | **Artifact Engine** | **Partial** | `workers/src/lib/r2.js` is a genuinely solid, production-grade blob-storage module (real R2 bucket `SCAN_RESULTS`, month-partitioned keys, KV fallback, list-by-user, GDPR delete) — but scoped only to async scan-job JSON, and unused by all three Reporting Engine implementations above. Note: `ARTIFACT_RETENTION_POLICY.md` uses "artifact" to mean **git/CI build artifacts** (zips, `dist/`, binaries) — a completely different vocabulary that does not apply to runtime business artifacts; ESSP needs its own definition, distinct from that policy |
| 9 | **Executive Dashboard Engine** | **Candidate for Consolidation — highest priority** | **14+ independently-computed backends** (`ceoExecutiveDashboard.js`, `executiveCommandCenter.js`, `executiveReport.js`, `executiveRiskHandlers.js`, `revenueDashboard.js`, `revenueIntelligence.js`, `revenueIntelligenceHandler.js`, `revenueKPI.js`, `revenueMetrics.js`, `revenueOps.js`, `cisoMetrics.js`, `platformMetricsAuthority.js`, `decisionHandler.js`, `enterpriseTransformHandler.js`, plus one inline computation with no handler file), feeding at most 6 real frontend pages — several have **zero confirmed frontend consumer at all**. See §3 for the full breakdown; this is the single largest consolidation opportunity found in the entire EPEP/ESSP audit |
| 10 | **Billing Adapter** | **New Build Required** | 5 separate payment mechanisms (Razorpay Orders-only, PayPal Orders, Gumroad license-verify, manual UPI/bank/crypto, plus 2 parallel subscription-tier catalogs — one with a live 10× price bug). Razorpay has **no Subscriptions API integration anywhere** — `createRazorpaySubscription()` in fact creates a one-time order. Full detail in the EPEP master strategy doc §3.1 and §5.1 below |
| 11 | **Usage Metering** | **Partial** | Real per-key counting exists (`auth/apiKeys.js`'s `trackApiKeyUsage`/`checkDailyQuota`, D1-backed) but is wired into **only** the API-key auth path; JWT/session traffic (the majority of dashboard usage) unconditionally passes with no verified daily-scan check. The customer-facing advertised limit (`pricingConfig.js`'s `daily_scans`) is enforced **nowhere** — the enforced number (`TIER_LIMITS.daily_limit`) is different and already flagged as an unfixed drift in this repo's own audit trail. A 4th, independent quota system exists in `aiSecurityCopilot.js` |
| 12 | **RBAC** | **Production Ready** | Two-tier model (platform staff + org-scoped OWNER/ADMIN/ANALYST/MEMBER/VIEWER), real `org_id`-scoped tenant isolation verified at 15+ query sites plus an 11-test dedicated isolation suite. Directly reusable as-is — the strongest existing asset among the 15 components |
| 13 | **Audit Logging** | **Candidate for Consolidation** | A real, shared D1 `audit_log` table exists in principle (genuinely reused by `orgManagement.js` and `aiSecurityCopilot.js`) but is undermined by: schema drift across 3 migration variants; a **silently broken writer** in `enterpriseSsoHandler.js` (wrong column name, wrapped in a swallowing `try/catch` — every SSO-login audit write has been a silent no-op); 2 independent KV audit reimplementations (one fully built but orphaned — zero real callers beyond its own admin endpoint; one that falsely claims in its own header comment to "wrap" the first, but actually copy-pastes it); a 4th, unrelated "history" (scan-history) concept sharing the same duplication pattern |
| 14 | **AI Orchestration Layer** | **Production Ready** | `workers/src/core/aiProviderRouter.js` (`routeAICall`) + `mythosAIProvider.js` (`callClaude`, backward-compat wrapper) is a real, shared, 6-provider routing library with a KV-backed circuit breaker and cross-provider deadline budget, imported by **23 distinct files** across the codebase, including the platform's single highest-traffic route (`/api/scan/domain`). This is the second-strongest existing asset among the 15 components. `multi-agent-os/` (the standalone Python/FastAPI service at the repo root) is **definitively confirmed orphaned** — its own CI config admits "this has never executed on any push or PR," no deploy workflow targets it, zero references from `workers/src/` resolve to it, and its own internal AI-router is a cruder, non-circuit-broken duplicate of the one already live. **ESSP's AI Orchestration Layer must explicitly exclude `multi-agent-os/` as usable infrastructure** |
| 15 | **Integration Gateway** | **New Build Required** | No unifying concept exists across the three real "external connection" patterns found: SIEM deployment targets (`siemDeploy.js`, KV-stored, **global per-platform, not per-org** — the file's own comment confirms this is CyberDudeBivash's own webhook, not a customer-facing feature, despite the `/api/integrations` route name); outbound webhooks (`org_webhooks`, D1, genuinely per-org with its own secret — the closest existing shape to reuse); and the 5 parallel API-key systems already noted under Billing Adapter's fragmentation |

---

## 3. Deep Dive: The Executive Dashboard Finding

This merits its own section given its scale. **At least 14 independently-computed "executive dashboard" backends exist, feeding at most 6 real frontend pages** (`revenue-command-center.html`, `revenue-intelligence-dashboard.html`, `enterprise-kpi-dashboard.html`, `decision-dashboard.html`, `user-dashboard.html`, `index.html`). Several — `ceoExecutiveDashboard.js`, `executiveCommandCenter.js`, `executiveRiskHandlers.js`, `revenueDashboard.js`, `revenueIntelligence.js`, `revenueKPI.js` — have **no confirmed frontend consumer anywhere in the repository**; they compute real numbers that no customer or executive ever sees through the product.

**The MRR consistency problem, concretely:** the same conceptual number — monthly recurring revenue for the PRO tier — resolves to at least six different hardcoded values depending on which file computes it (₹1,499 appears three times; other files hardcode $49, $99, $29, $999), reading from at least four different source tables (`subscriptions`, `users.tier`, `leads.plan`, a hand-typed KV config blob). "Composite risk score" independently exists in five methodologies. Two handlers (`executiveReport.js` and `executiveRiskHandlers.js`) previously collided on the exact same route (`/api/executive/dashboard`) in production — a comment in the code documents the incident ("every KPI rendered as '—'") and the fix was to move one handler to a different path, not to reconcile the duplicate computation.

**The irony this audit surfaced:** `platformMetricsAuthority.js` is explicitly named and commented as *the* single source of truth ("eliminates data inconsistency") — but is itself just another independent computation over a disjoint slice of tables, silently dependent on other handlers' writes it never validates against, and has **zero real frontend consumers today**. It is not canonical; it only claims to be. This is precisely the kind of self-certified-but-false claim CLAUDE.md's governance model exists to catch — the same failure mode as the historical `GENERAL_AVAILABILITY_REPORT.md` Organizations/Auth miscertification this repo's own capability registry was built to prevent.

**What a consolidated Executive Dashboard Engine needs:** one canonical MRR/ARR computation reading directly off `payments`/`subscriptions` (using `revenueIntelligenceHandler.js`'s pattern — it already imports canonical `SUBSCRIPTION_TIERS` rather than hardcoding a price table — as the template to generalize, since it's the cleanest of the fourteen), one canonical composite-risk-score service, and a deliberate decision on each of the 6+ frontend-less handlers: retire, or find and build the missing UI, but not leave them computing unread numbers indefinitely.

---

## 4. Master Consolidation Inventory (Both Audit Rounds)

Every "N parallel implementations" finding from this program to date, in one place, ranked by risk:

| Priority | Duplicate system | Count | Live customer/revenue impact today |
|---|---|---|---|
| P0 | Executive/revenue dashboards | 14+ | Inconsistent MRR/risk numbers across internal views (not yet customer-facing, but a governance/trust risk if any leaks into a customer-facing surface) |
| P0 | Subscription-tier catalogs | 2 | One has a live 10× price bug (unreachable from frontend today, but real) |
| P0 | Audit logging | 4 (incl. 1 silently broken) | SSO login events are not actually being audited today, despite the code appearing to do so |
| P1 | API key issuance | 5 | 3 reimplement identical hashing logic; 1 had a critical vuln (fixed) |
| P1 | Report/PDF generation | 3 | No functional bug found, but maintenance burden and inconsistent capability (e.g. only some support CSV/JSON export) |
| P2 | IOC enrichment (from EPEP Threat Intel audit) | 4 | Registry self-discloses non-reconciliation; quality/consistency risk for a paid product built on top |
| P2 | STIX/TAXII builders (from EPEP Threat Intel audit) | 2 | Maintenance duplication, no functional bug found |
| P2 | Campaign/sequence orchestration | 5 | No shared state model; each new "campaign" feature (e.g. ARaaS's) would be a 6th |
| P3 | Hunting/playbook engines (from EPEP Threat Intel audit) | 3 | Registry self-discloses fragmentation |

**Recommendation:** ESSP's implementation waves (§9) should be sequenced by this priority order, not by the engine list's original order — fix the highest live-risk duplication first.

---

## 5. Target Architecture

### 5.1 Deployment model — a decision this document makes explicitly

The mission statement's diagram shows ESSP as a distinct architectural layer between "AI Security Hub" and "Products." **This document recommends implementing ESSP as an internal shared module layer within the existing single Cloudflare Workers deployment** (`workers/src/services/shared/` or similar), consuming the same D1 database and the same deployment pipeline — **not** as a separately-deployed microservice.

Reasoning: this platform's entire architecture today is one Workers deployment (`workers/wrangler.toml`'s `main = "src/index.js"`) with 169 handler files and ~70 service files inside it. Extracting ESSP into a second deployable service would itself be a "multi-service extraction" — exactly the class of architectural change CLAUDE.md reserves for explicit approval, and it would introduce new operational surface (a second thing to deploy, monitor, and keep in sync) for no evidenced benefit, since nothing in this audit found a scaling or isolation reason that requires a separate service. The `multi-agent-os/` finding (§2, row 14) is a direct cautionary example: a second service was stood up once before in this repository and never made it to production. ESSP should not repeat that pattern. If a genuine scaling need is later evidenced (not assumed), extraction can be revisited then — but that is a future, separately-approved decision, not this one.

### 5.2 Per-component target design

| Component | Target design | Migration approach |
|---|---|---|
| Billing Adapter | One interface (`BillingProvider`) with `Razorpay`/`PayPal`/`Gumroad`/`Manual` implementations behind it; callers stop importing provider-specific code directly | Strangler pattern: new interface wraps existing provider calls unchanged first (zero behavior change), callers migrate one at a time, old direct-call sites removed only after migration — see §8 |
| Usage Metering | Extend `auth/apiKeys.js`'s existing D1 `api_key_usage` counting to cover JWT/session traffic (the majority path currently unmetered); retire the `aiSecurityCopilot.js` 4th quota system onto the same table; resolve the `daily_scans` vs. `TIER_LIMITS.daily_limit` drift by picking ONE authoritative number (a product decision, not an engineering one — flagged, not decided here) | Additive first (start counting JWT traffic without enforcing), verify counts look sane against real usage, then flip enforcement on |
| Executive Dashboard Engine | One canonical metrics-computation service reading directly off `payments`/`subscriptions`/`scan_history` (generalizing `revenueIntelligenceHandler.js`'s canonical-import pattern); each of the 14 existing handlers becomes either a thin view over this service or is retired | Per CAP-NOTIF-003's proven migration discipline (§7): validate all 14, build the canonical service, migrate frontend-connected handlers first, retire orphaned ones only after confirming zero real callers (already done for 6 of them by this audit) |
| Notification Engine | One dispatch function accepting `(org_id, event_type, payload)` that fans out to whichever of {webhook, email, in-app bell, (future SMS)} the org has configured, replacing today's per-engine bespoke wiring and finally giving `dispatchWebhookEvent` real callers | Wire real event dispatch once; every EPEP product's "webhook templates"/"breach alerts" need becomes a caller of this one function, not a new integration each |
| Reporting Engine | Consolidate `reportingEngine.js`, `secureDownload.js`, and `aiGovernancePdfHandler.js`'s report-rendering logic behind one template-driven service; route all output through `lib/r2.js` (already real, already production-grade) instead of ad hoc KV caching | `reportingEngine.js` is the strongest existing base (6 templates already); extend it, don't replace it; migrate `secureDownload.js`'s catalog and `aiGovernancePdfHandler.js`'s CISO template into it as additional template types |
| Evidence Engine | One `evidence_items` shape (id, org_id, source_capability, severity, citation, created_at) that `ai_findings`, `service_assessments.findings_json`, and `ai_governance_assessments.answers` all populate going forward, without forcing a backfill/rewrite of historical data | New table, new writes only; existing tables remain readable as-is for historical reports |
| Artifact Engine | Generalize `lib/r2.js` beyond scan-job JSON to cover PDFs/reports/exports from every engine, with the same month-partitioned key convention and GDPR-delete support it already has | Additive — no existing R2 usage needs to change, only new callers adopt it |
| Audit Logging | Fix the schema drift (pick the superset shape already present in `schema_master.sql`/`schema_bootstrap.sql`), fix `enterpriseSsoHandler.js`'s silently-broken writer (wrong column name), retire both KV reimplementations onto the one D1 table, merge `history.js`'s concept in or explicitly document it as a separate, legitimate "customer-facing scan history" concept (not audit logging) | The SSO fix is small, isolated, and backward-compatible — a candidate for its own tiny PR ahead of the broader consolidation wave, not bundled with it |
| Integration Gateway | New `org_integrations` table generalizing `org_webhooks`'s proven per-org/credentialed shape to also cover SIEM targets and (eventually) API key issuance as one "external connection" concept | Migrate `siemDeploy.js`'s global KV config to per-org D1 rows first (the highest-value fix, since today ALL customers share one global SIEM config — a real customer-isolation gap, not just a style issue); consolidate the 5 API-key systems onto the canonical one (`CAP-DEVPORTAL-001`) in a later wave |
| Campaign Engine | Generalize `emailEngine.js`'s `email_sequences` state-machine pattern (real, atomic, cron-driven — the most mature of the five siloed implementations) into a `campaigns`/`campaign_steps` shape usable by ARaaS's red-team campaigns, Threat Intel's actor/theme packs, and marketing/renewal sequences alike | New shared tables; `ai_redteam_campaigns` and `renewal_queue` migrate onto them; the two content pipelines consolidate into one |
| Workflow Engine | Extend `workflowAutomation.js` with conditional branching and a larger action vocabulary; rename/reconcile the two colliding `decisionEngine.js` files (different directories, same name, no shared code — a maintainability hazard independent of any functional bug) | Extend, don't replace; the two `decisionEngine.js` files should be reconciled (renamed or merged) in the same wave that touches either |
| Scheduling Engine | A generic `scheduled_jobs` registration table any engine can insert into, fanned out from the existing cron ticks (no new cron slot — the 5-slot ceiling is already fully consumed) | Extend `monitor_configs`'s `CHECK` constraint and `getScanHandlers()` map (already planned in the Dark Web & Brand Monitoring product doc) as the first real generalization step |
| Assessment Engine | See EPEP Product 4 document §6 — a new `aiMaturityHandler.js` orchestration layer unifying the 5 existing scoring engines' output, without replacing any of them | As designed in Product 4's document |
| RBAC | No change — reuse as-is | N/A |
| Audit Logging | (see above) | (see above) |
| AI Orchestration Layer | No change to the routing library itself — formally document `aiProviderRouter.js`/`mythosAIProvider.js` as the ESSP-designated shared AI Orchestration Layer so future product work imports it by default instead of ever considering a new one; explicitly exclude `multi-agent-os/` from any future architecture decision | Documentation/designation only |

---

## 6. Database Design (New Shared Tables)

All new tables are `org_id`-scoped from creation, per the newer (correct) schema convention already established in this program's other documents:

```sql
-- Integration Gateway
CREATE TABLE org_integrations (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL,
  integration_type  TEXT NOT NULL,     -- 'siem' | 'webhook' | 'api_key' (unifies 3 today-separate concepts)
  platform          TEXT,              -- e.g. 'splunk', 'elastic' (for siem type)
  config            TEXT NOT NULL,     -- JSON, shape depends on integration_type
  secret_ref        TEXT,              -- reference into existing secret storage, never plaintext
  active            INTEGER NOT NULL DEFAULT 1,
  created_by        TEXT NOT NULL,
  created_at        TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_org_integrations_org ON org_integrations(org_id, integration_type);

-- Campaign Engine
CREATE TABLE campaigns (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  campaign_type   TEXT NOT NULL,      -- 'redteam' | 'threat_pack' | 'renewal' | 'content' | ...
  status          TEXT NOT NULL DEFAULT 'active',
  current_step    INTEGER NOT NULL DEFAULT 0,
  next_action_at  TEXT,
  created_at      TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE TABLE campaign_steps (
  id            TEXT PRIMARY KEY,
  campaign_id   TEXT NOT NULL,
  step_number   INTEGER NOT NULL,
  action_type   TEXT NOT NULL,
  payload       TEXT,
  executed_at   TEXT,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
CREATE INDEX idx_campaign_steps ON campaign_steps(campaign_id, step_number);

-- Evidence Engine
CREATE TABLE evidence_items (
  id                 TEXT PRIMARY KEY,
  org_id             TEXT NOT NULL,
  source_capability  TEXT NOT NULL,   -- e.g. 'ai_maturity_assessment', 'darkweb_scan'
  severity           TEXT,            -- canonical SEVERITY from lib/contracts.js
  citation           TEXT NOT NULL,   -- the evidence text/reference itself
  metadata           TEXT,            -- JSON, capability-specific
  created_at         TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_evidence_org ON evidence_items(org_id, source_capability);

-- Executive Dashboard Engine (canonical metrics snapshot, replacing per-handler ad hoc queries)
CREATE TABLE executive_metrics_snapshot (
  id              TEXT PRIMARY KEY,
  org_id          TEXT,               -- NULL for platform-wide snapshots
  metric_name     TEXT NOT NULL,      -- 'mrr', 'arr', 'composite_risk_score', ...
  metric_value    REAL NOT NULL,
  computed_from   TEXT NOT NULL,      -- which canonical source table(s), for auditability
  snapshot_at     TEXT NOT NULL
);
CREATE INDEX idx_exec_metrics ON executive_metrics_snapshot(metric_name, snapshot_at);

-- Notification Engine (dispatch log, unifying today's per-channel logging)
CREATE TABLE notification_dispatch_log (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  channel       TEXT NOT NULL,        -- 'webhook' | 'email' | 'in_app' | 'sms' (future)
  status        TEXT NOT NULL,        -- 'sent' | 'failed' | 'skipped_not_configured'
  dispatched_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_notif_dispatch_org ON notification_dispatch_log(org_id, dispatched_at);
```

**Audit logging fix (not a new table — a correction to the existing one):** reconcile `audit_log`'s schema to the superset already present in `schema_master.sql`/`schema_bootstrap.sql` (columns: `details`, `severity`, `resource_id`, `metadata`), and fix `enterpriseSsoHandler.js`'s insert to use `details` (plural) instead of the non-existent `detail` column that has silently no-op'd every SSO audit write to date.

---

## 7. Security Architecture

- **RBAC:** ESSP components are consumed by every product and every existing engine — they must never introduce a *weaker* permission check than the platform default. Each new shared table follows the existing org-scoped RBAC pattern verified Production Ready in §2 row 12.
- **Tenant isolation:** every new table above is `org_id`-scoped from creation. The Integration Gateway migration explicitly closes a real isolation gap: `siemDeploy.js`'s current global (not per-org) SIEM config means, today, all customers configured against the same admin-managed integration set — the `org_integrations` migration is as much a security fix as an architecture improvement.
- **Secrets:** `org_integrations.secret_ref` follows the same never-plaintext convention already proven in `org_webhooks.secret`.
- **Audit logging:** fixing the SSO silent-failure bug (§5.2, §6) is itself a security-relevant correction — SSO login events are a natural target for compliance/forensic review and have not actually been captured.
- **API security:** the Billing Adapter's provider-abstraction interface must not weaken any of the existing payment-verification logic (HMAC signature checks, server-side price derivation from `pricingConfig.js` — both already hardened by prior fixes in this repo's history, e.g. PR #240/#242) — the adapter wraps existing verified logic, it does not reimplement it.
- **Compliance logging / OWASP / NIST / ISO 27001 / SOC 2:** ESSP introduces no new control category; it consolidates existing ones. The consolidation itself, done carefully, *improves* the platform's compliance posture (e.g., a single auditable MRR computation is more defensible under a SOC 2 review than 14 disagreeing ones).

---

## 8. Consolidation Discipline — Reusing This Repository's Own Proven Migration Playbook

This repository has already executed exactly this kind of "retire a duplicate, keep the customer-facing one working" migration once today, for the CAP-NOTIF-003 webhook system (two live webhook implementations, one retired only after validating both, building a migration matrix, determining risk, and confirming zero remaining callers before removal). **Every "Candidate for Consolidation" row in §2 should follow the same six-phase discipline, per consolidation, not a big-bang rewrite:**

1. **Validate** every parallel implementation (capabilities, security, current real callers) — not assumed, checked, exactly as this audit did.
2. **Migration matrix** — legacy → target, mapping APIs/events/secrets/DB/UI/tests.
3. **Risk determination** — Zero/Low/Medium/High, with repository evidence (several of the findings above, e.g. the 6 frontend-less executive dashboard handlers, are already Zero Risk to retire — this audit already confirmed zero real callers).
4. **Implement only with backward compatibility preserved** — compatibility shims where a real caller exists.
5. **Migrate callers**, verify each one.
6. **Retire the legacy implementation only after** all callers have migrated and a compatibility period has passed — never before.

Applying this per finding in §4's priority order, rather than attempting all fifteen components' consolidation simultaneously, is what keeps ESSP itself from becoming the kind of large, risky, single-PR rewrite CLAUDE.md's production-fix policy exists to prevent.

---

## 9. Implementation Roadmap — Wave-Paced, Reusing This Repo's Own Proven SOP

Rather than inventing a new planning framework, this document recommends ESSP implementation follow **the exact same operational SOP already proven in this repository for pacing multi-session, must-not-rush consolidation work**: `docs/capability-registry/EXECUTION_PROCEDURE.md`'s bounded-wave procedure (Recover → Inspect → Plan → Execute → Validate → Test → Checkpoint → Stop, one wave per session, commit at small granularity, `git ls-remote`-verified recovery, never loop into a second wave in the same session regardless of remaining quota). That SOP exists specifically because this repository already lost real, verified work once to an uncommitted session cutoff — the same risk applies to ESSP's multi-session build-out.

**Proposed wave plan** (each wave = one architectural concern = one PR, per the mission statement's explicit instruction):

| Wave | Scope | Priority basis |
|---|---|---|
| 0 | Repository reuse confirmation (this document) + register a `docs/capability-registry/domains/essp.json` tracking file for the 15 components going forward, so this audit's findings don't go stale the way `platformMetricsAuthority.js`'s false-canonical claim did | Foundational |
| 1 | Fix the SSO audit-log silent failure (§5.2) — small, isolated, backward-compatible, matches this repo's own auto-fix criteria | §4 P0, cheapest fix available |
| 2 | Audit Logging consolidation (schema reconciliation, retire 2 KV reimplementations onto the fixed D1 table) | §4 P0 |
| 3 | Executive Dashboard Engine — retire the 6 confirmed-zero-caller handlers first (Zero Risk per this audit), then build the canonical MRR/risk-score service | §4 P0, largest finding |
| 4 | Subscription-tier catalog reconciliation (resolve the 10× price bug; pick one canonical tier catalog) | §4 P0 |
| 5 | Billing Adapter interface (wrap existing Razorpay/PayPal/Gumroad/Manual calls, zero behavior change) + Usage Metering extension to JWT traffic | §4 P1, prerequisite to all 4 EPEP products' commercial model |
| 6 | API key system consolidation onto `CAP-DEVPORTAL-001` | §4 P1 |
| 7 | Integration Gateway (`org_integrations` table; migrate SIEM config from global-KV to per-org-D1 first — closes a real tenant-isolation gap) | §4 P1 |
| 8 | Notification Engine unification (wire real `dispatchWebhookEvent` callers; fan out to email/webhook/in-app from one function) | Prerequisite to EPEP Products 2 and 3 |
| 9 | Reporting + Artifact Engine consolidation (route all report generation through `lib/r2.js`) | §4 P1 |
| 10 | Campaign Engine + Workflow Engine generalization | §4 P2, prerequisite to EPEP Products 1 and 2 |
| 11 | Evidence Engine (new `evidence_items` table, additive) | §4 P2 |
| 12 | Scheduling Engine generalization (extend `monitor_configs`) | Prerequisite to EPEP Product 3 |
| 13 | AI Orchestration Layer — documentation/designation only, no code | Lowest effort, do anytime |
| 14 | Recurring billing (Razorpay Subscriptions API or UPI Autopay/eMandate — a business decision on mechanism, flagged not made here) | Highest-value but highest-effort; can run in parallel with waves 6-12 once Wave 5's adapter interface exists to build on |

Each wave: Execute → full regression suite → `scripts/registry/validate.mjs` (once Wave 0's `essp.json` exists) → CI green → checkpoint commit/push → session-log entry → stop. No wave should be combined with another "to save time" — that is precisely the discipline this repository's own history (§0 of `EXECUTION_PROCEDURE.md`) shows fails under real session-length constraints.

---

## 10. Testing Strategy

- Full regression suite (currently ~297 files / ~3,100+ tests) run after every wave, per standing practice.
- **Zero-caller verification before any retirement**: this audit already performed the callers-check for several candidates (e.g., the 6 orphaned executive dashboard handlers); re-verify at implementation time in case new callers were added since this audit.
- **The SSO audit-log fix (Wave 1) needs a regression test proving the write actually lands** — the exact class of test this repository's `docs/ENGINEERING_STANDARDS.md` §5 already mandates for contract-drift fixes: assert the real column exists and is populated, not just that the code runs without throwing (which is precisely how the bug went undetected — the `try/catch` swallowed the failure silently).
- Migration-matrix-driven compatibility tests for every consolidation wave, per §8.

## 11. Deployment Strategy

Standard existing gated pipeline (`ci.yml` → `test.yml` → `deploy.yml`), no new infrastructure per §5.1's deployment-model decision. Schema changes (Audit Logging fix, new tables) follow `docs/ENGINEERING_STANDARDS.md` §9's production-faithful-schema testing discipline.

---

## 12. Risk Assessment

| Risk | Category | Mitigation |
|---|---|---|
| ESSP itself becomes a big-bang rewrite | Technical / Operational | Bounded waves per §9, one architectural concern per PR, exactly as requested |
| Retiring a "duplicate" that turns out to have a real caller this audit missed | Technical | Re-verify zero-callers at implementation time, not just trust this audit's snapshot; follow §8's six-phase discipline every time |
| Consolidating executive dashboards surfaces which historical MRR number was "right," with commercial/reporting consequences | Commercial / Governance | Treat this as a data-quality finding to resolve transparently, not to paper over — flag to the business before Wave 3 ships |
| The SSO audit-log bug has existed for an unknown period — compliance/forensic gap for that window | Security / Compliance | Fix in Wave 1 (fast); document the gap window honestly rather than imply retroactive coverage that doesn't exist |
| Integration Gateway migration (SIEM config from global to per-org) could disrupt the one existing SIEM integration in current use | Technical | Migrate additively first (new per-org rows alongside the old global config), cut over only after confirming parity |
| Recurring billing mechanism choice (Razorpay Subscriptions API vs. UPI Autopay/eMandate vs. another approach) is a business decision this document does not make | Commercial | Flagged explicitly in Wave 14; requires an explicit decision before implementation, consistent with CLAUDE.md's gate on billing-redesign-class changes |

---

## 13. Executive Product Scorecard — ESSP

| Dimension | Rating | Basis |
|---|---|---|
| Architecture completeness | 🔴 Fragmented today | 9 distinct "N parallel implementations" patterns found across 15 proposed components |
| Reuse of existing platform | 🟡 Mixed but real | 2 of 15 components (RBAC, AI Orchestration) are already Production Ready; several others have strong raw material to generalize rather than invent |
| New engineering required | 🟡 Substantial but bounded | Sized in 14 discrete waves, each independently schedulable and testable |
| Security/compliance impact | 🟢 Net positive if executed | Surfaces and fixes a real silent audit-logging failure and a real tenant-isolation gap (global SIEM config) as part of the same consolidation work |
| Commercial impact | 🟢 High | Directly unblocks the recurring-billing gap flagged as shared across all 4 EPEP products |
| Customer evidence | 🔴 None | Zero real paying customers platform-wide (unchanged from every other document in this program) |
| Recommended sequencing | **Before any of the 4 EPEP products' Phase 2 (Backend)** | Confirms this program's own recommendation |

**GO / Conditional GO / NO-GO:** **Conditional GO** — proceed to Wave 0 (this document + registry tracking) and Wave 1 (the SSO audit-log fix, which is small enough to ship immediately on its own merits) now; Waves 2 onward proceed in the priority order in §4/§9, each gated by its own CI-green + regression-clean checkpoint, not a single all-at-once approval.
