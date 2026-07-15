# Product 4: AI Security Maturity Assessment Framework

**Program:** Enterprise Product Expansion Program (EPEP) · **Phase:** Product Architecture & Business Design (pre-implementation)
**Status of this document:** Proposed architecture. No new code has been written under this program yet — see §2 for what already exists.
**Evidence basis:** Direct repository audit, 2026-07-15 (commit `d7841aa`, branch `claude/epep-product-architecture-d177jl`). Every claim below is tagged **Verified** (read directly from code), **Assumed** (a planning input, not sourced from measured data), or **Proposed** (new work this document recommends).

---

## 1. Executive Summary

**Problem solved.** Enterprises adopting LLMs/AI agents have no standard way to answer "how mature is our AI security posture, and what should we fix first?" Compliance frameworks (NIST AI RMF, ISO 42001, EU AI Act) exist but are self-attestation questionnaires with no unified score, and the platform's own scanning/governance engines each independently compute a maturity signal that has never been merged into one product.

**Target customer.** Enterprise CISOs and AI/ML platform teams under board or regulatory pressure to demonstrate AI governance (EU AI Act, board risk committees); mid-market companies adopting their first LLM features who need a defensible baseline before an audit or customer security questionnaire.

**Business value.** A repeatable, sellable assessment product with a low-friction automated entry point (self-serve scorecard) and a high-margin services upsell (consulting session) — the same "freemium scan → paid report → paid consulting" motion the platform already runs successfully for domain/compliance scans (`packages.SECURITY_ASSESSMENT`, ₹9,999 one-time, **Verified** in `workers/src/config/pricingConfig.js:71-78`).

**Revenue opportunity.** Highest-reuse, lowest-engineering-risk of the four EPEP products (confirmed below — five separate engines already compute pieces of this; the work is unification, not invention). This validates the CEO's original sequencing recommendation and, per the evidence in §2, makes the case *stronger* than originally assumed.

**Market positioning.** "The only AI security maturity score backed by live technical signal, not just a questionnaire" — differentiated from pure-paper assessments (which is what most competitors — internal audit firms, generic GRC tools — actually sell) by combining `aiSecurityScorecardHandler.js`'s live external signal collection with `aiGovernancePro.js`'s framework-mapped maturity levels.

---

## 2. Repository-First Capability Audit

Per CLAUDE.md governance, every claim below was checked against code, not against `docs/audit-history/*.md` (historical, unverified) or assumed from the capability registry alone. Two discrepancies were specifically investigated and resolved:

### 2.1 Resolved discrepancy — CAP-CRM-006 "Security Assessment Booking"

`docs/capability-registry/PRODUCTION_READINESS_REPORT.md` lists this as `backend ✗ frontend ✗ NOT READY`. Direct code read shows this is **not wrong, but the top-line table is lossy**: the full registry JSON entry (`docs/capability-registry/domains/sales-crm.json`, `PROGRAM_BOARD.md:433-438`) correctly marks backend status as `"duplicate"`, not `"missing"` — the ✗/✓ table generator collapses that nuance away.

**Verified:** `workers/src/handlers/assessmentBooking.js` is complete, working, non-stub code: `handleBookAssessment` creates a real Razorpay order (`createRazorpayOrder`, line 56), inserts into a real `assessments` D1 table (lines 71–79), tracks funnel events, and queues a confirmation email. `handleConfirmAssessment` performs real `verifyPaymentSignature` (line 131) then a real D1 update. All five routes are live at `workers/src/index.js:7918-7930` (imported at line 167). **No test file references it** (`grep -rn assessmentBooking workers/test/` → zero hits), and **no frontend page calls it** — `frontend/booking.html` posts to a completely different flow (`/api/sales/leads`, `/api/sales/demo/book`, handled by `enterpriseLayer.js`'s free lead-capture path).

**Classification: Dormant.** This is a real, paid, Razorpay-integrated booking backend sitting completely unused — an unusually good reuse opportunity for this product rather than a gap to build around.

### 2.2 Resolved discrepancy — no "scorecard" capability-registry entry

**Confirmed genuine registry gap**, not a naming miss: `workers/src/handlers/aiSecurityScorecardHandler.js` (694 lines, live routes at `index.js:449-455,5589-5608`) and `frontend/ai-security-scorecard.html` exist and are live, but have no CAP-ID anywhere in `docs/capability-registry/domains/*.json`. This document does not attempt to backfill the registry (out of scope for a design doc), but the finding is recorded here as a **Documentation Drift** item for engineering to register once this product's scope is approved.

### 2.3 Capability classification

| Capability | File(s) | Class | Evidence |
|---|---|---|---|
| AI Security Scorecard | `aiSecurityScorecardHandler.js` | **Production Ready** (uncatalogued) | Real 5-*dimension* composite (D1–D5, 20 pts each → 100) from live signal collection (CT subdomain enumeration, DNS, HTTP headers, SPF/DMARC, Shodan InternetDB, cert/latency), lines 151–428. Single 0–100 score → letter grade A+…F, lines 53–60. **This is a dimension score, not a 5-level maturity model** — no Initial/Managed/Optimizing progression concept in this file. |
| NIST AI RMF maturity | `aiGovernancePro.js` (`nistAiRmfAssessment`) | **Production Ready** | Real per-function `maturityLevel`: OPTIMIZING/MANAGED/DEFINED/INITIAL/INCOMPLETE by score band, lines 421, 426. A genuine 5-level CMMI-style model, live today, scoped to one framework. |
| DPDP maturity | `dpdpCompliance.js` | **Production Ready**, best prior art | `MATURITY_LEVELS` (lines 116–123): explicit 6-tier (0–5) Non-existent → Optimised with score bands; `maturityFromScore()` lines 125–131. |
| DevSecOps maturity + roadmap | `devSecOpsEngine.js` | **Production Ready**, best prior art | `computeDevSecOpsMaturity()` (lines 128–134): 5-level INITIAL→OPTIMIZING **plus** a genuine sprint-phased remediation playbook (`sprint_1/2/3`, severity-grouped, tool recommendations), lines 137–173 — the strongest existing template for "prioritized roadmap." |
| Per-framework compliance % | `complianceEngine.js` (`runComplianceAssessment`) | **Production Ready** | Real ISO 27001 domain `compliance_percent`, GDPR `gdpr_readiness`/`readiness_score`, lines 285, 327, 348 — genuine, not yet unified into one taxonomy. |
| Governance self-attestation | `aiGovernance.js` | **Production Ready** | Weighted-control scoring (NIST AI RMF/ISO 42001/EU AI Act) with `gaps` + `roadmap` arrays, lines 194–228; roadmap items carry `priority`/`effort_days`. |
| Governance PDF export | `aiGovernancePdfHandler.js` | **Production Ready** | Real CISO-grade PDF/HTML export (score, gaps, roadmap), lines 231–539 — reusable template for the Executive PDF deliverable. |
| Consulting upsell hook | `consultationPreAssessEngine.js` | **Production Ready**, narrow scope | Real branching logic for 4 paid consult SKUs, generates agendas/briefs/checklists, writes to `service_assessments`/`service_orders`, lines 210–331. Directly reusable, but preps generic consults today, not a maturity-scorecard-specific follow-on. |
| Executive report aggregation | `reportingEngine.js` (`AI_SECURITY` template) | **Production Ready**, best-fit asset | Joins `ai_assets`/`ai_findings`/`ai_redteam_attempts`/`ai_governance_assessments` into one report with a genuine severity-prioritized Remediation Plan section, lines 575–681. Closest existing thing to "executive report + prioritized roadmap" for AI security specifically. |
| Sales proposal generator | `proposalGenerator.js` | **Production Ready**, wrong shape | Real ROI calc, packages, e-sign CTA, lines 173–408 — but `key_gaps` (lines 212–218) are hardcoded boilerplate, not derived from any actual assessment. Not reusable as a findings-driven roadmap. |
| Executive report (generic) | `executiveReport.js` | **Production Ready**, thin | Real KV/D1 posture+MRR aggregation, honest MTTD/MTTR labeling, lines 151–217 — only ~5 canned heuristic findings, not a real prioritized list. |
| Assessment booking (payment) | `assessmentBooking.js` | **Dormant** | See §2.1 — real, paid, unused. |
| Radar/spider chart UI | none | **Does not exist** | Every "radar" hit in `frontend/*.html` is the "Cyber Signal Radar™" brand name or a plain HTML table (`customer-dashboard.html:532-552`, `renderRadar()` emits `<table>` rows). Chart.js loads in exactly one file (`threat-intel-workbench.html:16`), no radar type configured. |

**Bottom line:** roughly 60–70% of the *engineering* already exists, scattered across five unconnected engines that independently reinvented a maturity-scoring pattern. The real work is **unification**, not invention: (1) merge the scorecard's 5 *dimensions* with a proper 5 *level* taxonomy — these are two axes that have never been combined; (2) build the radar/spider chart frontend (genuinely absent); (3) build a real multi-item prioritized roadmap tied to specific findings (not boilerplate); (4) decide whether to wire up or retire the dormant `assessmentBooking.js` Razorpay flow before building new paid-tier logic on top of it (recommendation: wire it up — it is fully functional and duplicating it would violate the repo's own anti-duplication standard).

---

## 3. Customer Personas

| Persona | Need from this product | Primary value moment |
|---|---|---|
| Enterprise CISO | A board-ready, defensible maturity score with a remediation roadmap and a paper trail | Executive PDF with score trend + peer framing |
| MSSP | White-labelable assessment they can resell to clients as a managed offering | Bulk/multi-tenant assessment + their own branding on the report |
| SOC Manager | Operational detail behind the score (which control gaps map to which alerts) | Drill-down from score to underlying finding |
| Security Engineer | Concrete, prioritized technical remediation items, not just a grade | Sprint-phased roadmap (reuse of `devSecOpsEngine.js` pattern) |
| AI/ML Team | A framework-mapped view (NIST AI RMF / ISO 42001) they can show to a platform review board | Per-framework maturity breakdown |
| DevSecOps | API-triggerable assessment as part of a release-gate or CI check | Programmatic scorecard API (§10) |
| Compliance Officer | Mapping from technical findings to regulatory language (EU AI Act, ISO 42001) | Compliance-framework crosswalk in the PDF |
| Startup Founder | A cheap, fast, credible signal to put in front of an enterprise customer's security questionnaire | Free/low-cost automated tier, same-day PDF |

---

## 4. Value Proposition

- **Live technical signal, not just a questionnaire.** Competing "AI maturity assessments" in the market are almost universally consulting-led paper exercises. This product's automated tier is backed by the same live signal-collection code (`aiSecurityScorecardHandler.js`) already running in production.
- **Framework-mapped, not generic.** Reuses real NIST AI RMF / ISO 42001 / EU AI Act scoring already built (`aiGovernancePro.js`, `aiGovernance.js`) instead of inventing a proprietary rubric nobody recognizes.
- **Measurable outcome:** a single 0–100 score, a 5-level maturity label per control domain, and a sprint-phased remediation plan — matching the `devSecOpsEngine.js` pattern already proven to produce actionable output.
- **Land-and-expand:** automated tier is the top of funnel; the real, already-built, currently-idle `consultationPreAssessEngine.js` and `assessmentBooking.js` flows are the paid expansion path — no new payment plumbing required.

---

## 5. Feature Matrix

| Feature | Classification | Basis |
|---|---|---|
| 0–100 composite technical score | **Existing** | `aiSecurityScorecardHandler.js` |
| 5-level maturity taxonomy (Initial→Optimizing) | **Enhancement** | Exists 3× independently (`aiGovernancePro.js`, `dpdpCompliance.js`, `devSecOpsEngine.js`) — needs unifying into one product-level taxonomy, not building from scratch |
| Per-framework crosswalk (NIST AI RMF/ISO 42001/EU AI Act) | **Existing** | `aiGovernance.js`, `aiGovernancePro.js` |
| Prioritized, sprint-phased remediation roadmap | **Enhancement** | Pattern exists in `devSecOpsEngine.js`; needs adapting from DevSecOps findings to AI-security findings |
| Executive PDF report | **Enhancement** | `aiGovernancePdfHandler.js` is a strong template; needs the unified score/roadmap wired in |
| Maturity radar/spider chart | **New Build** | Confirmed absent anywhere in the frontend |
| Paid assessment booking + payment | **Existing (Dormant)** | `assessmentBooking.js` — fully built, just needs a live frontend caller |
| Optional consulting session upsell | **Existing** | `consultationPreAssessEngine.js` |
| CSV/JSON export | **Enhancement** | Reporting engine already emits structured JSON internally; a public export endpoint is new but thin |
| Programmatic/API access to scorecard | **New Build** | No versioned public API exists for this specifically today |
| MSSP white-label report branding | **Enhancement** | White-label pattern exists for MSSP partners (`whiteLabelMSSP.js`) elsewhere in the platform; not yet wired to this report |
| Recurring (subscription) re-assessment billing | **Blocked by platform gap** | See Master Strategy doc §Cross-Cutting: no Razorpay recurring-billing capability exists platform-wide (**Verified**, `subscriptionPaywallEngine.js:330-360`) |

---

## 6. Technical Architecture & Product Architecture

### 6.1 Services (reuse-first)

```
                         ┌────────────────────────────────┐
                         │   NEW: aiMaturityHandler.js     │
                         │   (orchestration layer only)    │
                         └───────────────┬─────────────────┘
             ┌────────────┬──────────────┼───────────────┬─────────────────┐
             ▼            ▼              ▼               ▼                 ▼
   aiSecurityScorecard  aiGovernancePro  complianceEngine  devSecOpsEngine  consultationPreAssessEngine
   Handler.js (dims)    .js (levels)     .js (framework %)  .js (roadmap    .js (consulting upsell)
                                                             pattern only,
                                                             adapted)
             │            │              │               │                 │
             └────────────┴──────┬───────┴───────────────┴─────────────────┘
                                  ▼
                       reportingEngine.js (AI_SECURITY template, extended)
                                  ▼
                       aiGovernancePdfHandler.js (PDF/HTML export, extended)
                                  ▼
                    NEW: frontend radar chart + roadmap UI
```

**New service: `aiMaturityHandler.js`** (Proposed). Does not reimplement scoring — calls the four existing engines above, merges their outputs into one unified 5-level-per-dimension model, and hands off to `reportingEngine.js`. This is an orchestration/aggregation layer, consistent with the platform's existing `reportingEngine.js` pattern of joining multiple engines' output.

### 6.2 Background jobs

- **Re-assessment reminder** (Proposed): a scheduled check for assessments older than 90 days, emailing a re-assessment prompt via the existing `emailEngine.js` (**Verified** Production Ready, GA APPROVED WITH DOCUMENTED LIMITATIONS per registry). No new cron slot needed — this is a daily D1 query, not a scan; it can run inside one of the 5 existing cron ticks (see Master Strategy doc for the cron-slot constraint).
- No new queue consumer is required — scorecard computation is fast enough (live external signal collection, same shape as the existing `CAP-SCAN-*` scanners) to run synchronously per the existing `scan-jobs` queue pattern if async execution is wanted for the paid/deep tier.

### 6.3 Database

New tables (Proposed — see §9 for full schema) follow the **newer, correct convention** found in the audit (`schema_v46_missing_tables.sql`: org_id-scoped with dedicated indexes), not the legacy user_id-only pattern found in `migrations/0001_initial_schema.sql`.

### 6.4 RBAC

Reuses the existing two-tier model as-is (**Verified** Production Ready: org-level OWNER/ADMIN/ANALYST/MEMBER/VIEWER via `orgManagement.js`, real `org_id`-scoped tenant isolation confirmed at 15 query sites). No new roles are needed; assessment creation/viewing maps to ANALYST+, report purchase/booking maps to ADMIN+.

### 6.5 Event flow, audit logs, monitoring

- Every assessment run writes to the existing org-scoped `audit_log` table (**Verified** pattern from `orgManagement.js`'s `writeOrgAuditLog`).
- Assessment completion is a candidate event for the (currently dead-code) `dispatchWebhookEvent` in `enterpriseAutomation.js` — wiring a real `assessment.completed` event here is a natural, low-cost addition once that dispatch gap is fixed platform-wide (see Master Strategy doc).
- Monitoring: reuse existing `/api/health` and `X-Request-ID` correlation conventions (`docs/ENGINEERING_STANDARDS.md` §3, §6) — no bespoke observability needed.

---

## 7. Integration Plan

| Stage | Integration point | Status |
|---|---|---|
| AI Security Hub | New `ai-maturity-assessment.html` page, linked from `ai-security.html` and `ciso-hub.html` nav | New Build (UI), reuses existing nav pattern |
| Sentinel APEX | Consumes `aiThreatRadar.js` CVE signal only indirectly (via existing scanner reuse); no direct APEX dependency | N/A |
| Threat Intelligence APIs | Not required for this product | N/A |
| Commercial Registry | New SKU(s) added to `workers/src/config/pricingConfig.js` `packages` — extends the existing immutable config rather than creating a parallel one | Enhancement |
| Subscription Registry | Recurring re-assessment tier depends on the platform-wide Razorpay-subscription gap (see Master Strategy doc); launch on the existing one-time-order model first | Blocked (shared) / Existing (one-time) |
| Payments | Reuses `assessmentBooking.js`'s existing Razorpay Orders integration (Dormant → activated) | Existing (Dormant) |
| Marketplace | Optional secondary listing in Sentinel APEX Marketplace alongside existing `SECURITY_ASSESSMENT` package | Enhancement |
| Dashboard | New scorecard widget on `ciso-hub.html` / `enterprise-dashboard.html` | New Build |
| Reports | Extends `reportingEngine.js` + `aiGovernancePdfHandler.js` | Enhancement |
| Notifications | Assessment-complete email via `emailEngine.js`; optional webhook via `enterpriseAutomation.js` once dispatch is wired | Existing / Enhancement |

---

## 8. Security Architecture

- **Authentication:** existing `requireAuth()` middleware (**Verified** pattern reused platform-wide) — no new auth mechanism.
- **Authorization:** org-scoped RBAC as above; assessment data never crosses `org_id` boundaries (reuse of the tenant-isolation pattern verified in `orgManagement.js` and its 11-test `orgRbacIsolation.test.mjs` suite).
- **Tenant isolation:** every new table carries `org_id NOT NULL` with an index — no exceptions, correcting the legacy user_id-only pattern found elsewhere.
- **Encryption:** D1 at-rest encryption (Cloudflare-managed, platform default); no new secret material is introduced by this product beyond what `assessmentBooking.js` already handles (Razorpay key ID/secret, already in existing secret store).
- **Secrets:** none new. Reuses existing `RAZORPAY_KEY_ID`/`RAZORPAY_KEY_SECRET` bindings.
- **API security:** existing input validation middleware, existing rate-limit middleware (`CAP-PROD-002`, **Verified** PILOT ONLY — inherits the platform's current limitation, not a new gap introduced by this product).
- **Rate limiting:** per-plan daily-scan limits already defined in `pricingConfig.js` (`daily_scans`) apply unchanged.
- **Audit logging:** org-scoped `audit_log` table, as above.
- **Compliance logging:** assessment PDF output itself doubles as a compliance evidence artifact (this is the product's core value), consistent with `SECURITY_QUESTIONNAIRE_PACK.md`'s existing CAIQ-lite approach.
- **OWASP / NIST / ISO 27001 / SOC 2 / AI security controls:** the product's own subject matter (NIST AI RMF, ISO 42001, EU AI Act) is the control framework being assessed; the platform's *own* handling of this product's data follows the same OWASP ASVS-aligned conventions as every other handler (input validation, parameterized D1 queries — no new pattern required).

---

## 9. Database Design

**New tables (Proposed), org_id-scoped from day one:**

```sql
-- Unified assessment run (one row per scorecard execution)
CREATE TABLE ai_maturity_assessments (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL,
  requested_by      TEXT NOT NULL,          -- user_id
  target_scope      TEXT NOT NULL,          -- domain / asset identifier assessed
  composite_score   INTEGER,                -- 0-100, from aiSecurityScorecardHandler.js
  maturity_level    TEXT,                   -- INITIAL|MANAGED|DEFINED|OPTIMIZING (unified taxonomy)
  framework_scores  TEXT,                   -- JSON: {nist_ai_rmf: {...}, iso42001: {...}, eu_ai_act: {...}}
  status            TEXT NOT NULL DEFAULT 'pending', -- pending|complete|failed
  created_at        TEXT NOT NULL,
  completed_at      TEXT,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_ai_maturity_org ON ai_maturity_assessments(org_id);
CREATE INDEX idx_ai_maturity_created ON ai_maturity_assessments(org_id, created_at);

-- Individual remediation roadmap items tied to specific findings
CREATE TABLE ai_maturity_roadmap_items (
  id              TEXT PRIMARY KEY,
  assessment_id   TEXT NOT NULL,
  org_id          TEXT NOT NULL,
  finding_ref     TEXT,                     -- links to underlying ai_findings / governance gap row
  severity        TEXT NOT NULL,            -- CRITICAL|HIGH|MEDIUM|LOW (canonical, per lib/contracts.js)
  sprint          INTEGER,                  -- 1|2|3, per devSecOpsEngine.js pattern
  recommendation  TEXT NOT NULL,
  effort_days     INTEGER,
  status          TEXT NOT NULL DEFAULT 'open', -- open|in_progress|resolved
  FOREIGN KEY (assessment_id) REFERENCES ai_maturity_assessments(id)
);
CREATE INDEX idx_roadmap_assessment ON ai_maturity_roadmap_items(assessment_id);
CREATE INDEX idx_roadmap_org_status ON ai_maturity_roadmap_items(org_id, status);

-- History table for score trend over time (retention: 24 months, then archive)
CREATE TABLE ai_maturity_score_history (
  id              TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  assessment_id   TEXT NOT NULL,
  composite_score INTEGER NOT NULL,
  recorded_at     TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_score_history_org ON ai_maturity_score_history(org_id, recorded_at);
```

**Reused, not duplicated:** `assessments` (from `assessmentBooking.js`, Dormant → activated for payment/booking), `ai_assets`/`ai_findings`/`ai_redteam_attempts`/`ai_governance_assessments` (read by `reportingEngine.js`'s existing `AI_SECURITY` template), `service_assessments`/`service_orders` (from `consultationPreAssessEngine.js`, for the consulting upsell).

**Soft deletes:** `status` flag convention (matching the platform's existing pattern — no `deleted_at` column, consistent with what the audit found elsewhere; a genuine platform-wide inconsistency this product should not attempt to unilaterally fix).

**Retention:** assessment PDFs retained per `ARTIFACT_RETENTION_POLICY.md`'s existing rules; score history retained 24 months for trend charting, then archived (not deleted, for audit-trail continuity).

---

## 10. API Specification

All new endpoints use the canonical response envelope (`ok`/`fail`/`paginated` from `workers/src/lib/response.js`) and `lib/contracts.js` severity/status/timestamp helpers per `docs/ENGINEERING_STANDARDS.md` §2–3 — this product does **not** introduce a new response shape.

| Endpoint | Purpose | Auth | AuthZ | Request | Response | Rate limit | Versioning |
|---|---|---|---|---|---|---|---|
| `POST /api/ai-maturity/assess` | Run a new assessment | `requireAuth()` | org ANALYST+ | `{target_scope, frameworks[]}` | `{assessment_id, status:'pending'}` | 1/day on FREE, plan `daily_scans` limit otherwise | `v1` (new namespace) |
| `GET /api/ai-maturity/assessments/:id` | Fetch assessment result | `requireAuth()` | org member (own org only) | — | `{composite_score, maturity_level, framework_scores, roadmap[]}` | standard | `v1` |
| `GET /api/ai-maturity/assessments` | List org's assessment history | `requireAuth()` | org member | query: `page,limit` | paginated list | standard | `v1` |
| `GET /api/ai-maturity/assessments/:id/report.pdf` | Executive PDF | `requireAuth()` | org ADMIN+ (paid tiers) | — | PDF/HTML stream | standard | `v1` |
| `GET /api/ai-maturity/assessments/:id/export.csv` \| `.json` | Structured export | `requireAuth()` | org ADMIN+ | — | CSV/JSON | standard | `v1` |
| `POST /api/ai-maturity/assessments/:id/book-consultation` | Trigger consulting upsell | `requireAuth()` | org ADMIN+ | `{consult_type}` | reuses `consultationPreAssessEngine.js` response shape | standard | `v1` |
| `POST /api/assessments/book` *(reactivate existing)* | Paid booking + Razorpay order | `requireAuth()` | org ADMIN+ | unchanged from `assessmentBooking.js` | unchanged | standard | existing |

**Errors:** standard platform error codes (`fail(request, message, httpStatus, code)`), e.g. `ASSESSMENT_NOT_FOUND` (404), `ASSESSMENT_LIMIT_EXCEEDED` (429), `FRAMEWORK_NOT_SUPPORTED` (400).

---

## 11. UI/UX Blueprint

- **Dashboard:** new `ai-maturity-assessment.html`, following the existing dark theme CSS variables verified in `enterprise-dashboard.html` (`--bg:#060614`, `--accent:#00d4ff`, etc.) — no new design system, extends the existing one.
- **Wizard:** a 3-step flow (scope selection → framework selection → run) matching the existing scan-trigger UX pattern used by the other `CAP-SCAN-*` pages.
- **Maturity radar/spider chart:** **New Build.** Recommend Chart.js (already a platform dependency, currently used in exactly one file) with its native radar chart type — five axes for the five score dimensions, or per-framework axes; no new charting library needed.
- **Reports:** extend `aiGovernancePdfHandler.js`'s existing board-ready PDF template.
- **Risk views:** roadmap items rendered as a severity-sorted table (reusing canonical `SEVERITY` values from `lib/contracts.js`), grouped by sprint per the `devSecOpsEngine.js` pattern.
- **Notifications:** in-app bell (existing `CAP-NOTIF-002`) on assessment completion.
- **Dark mode:** inherits platform default (the entire frontend is dark-themed by default; no light-mode toggle exists platform-wide today — out of scope to add one for a single product).
- **Accessibility:** must pass the existing axe-core CI gate (`test.yml`'s Accessibility job) — the same bar every other page in this repo clears.
- **Responsive:** match existing single-file-page responsive breakpoints already in use across `frontend/*.html`.

---

## 12. Customer Journey

Visitor → `ai-security-assessment.html` (existing marketing/SEO page, retarget its CTA) → Pricing (new SKU, see §14) → Purchase (`assessmentBooking.js`, reactivated) → Onboarding (target scope entry) → Configuration (framework selection) → Execution (assessment run, live signal collection) → Reports (PDF + radar chart + roadmap) → Renewal (90-day re-assessment reminder, manual re-purchase given the platform-wide recurring-billing gap) → Expansion (consulting session upsell via `consultationPreAssessEngine.js`) → Referral (existing affiliate program, `CAP-AFF-001`, applies unchanged).

---

## 13. Reporting

| Deliverable | Status |
|---|---|
| Executive PDF | Enhancement of `aiGovernancePdfHandler.js` |
| Technical report (per-finding detail) | Enhancement of `reportingEngine.js`'s `AI_SECURITY` template |
| Risk matrix | New (severity × sprint grid, data already shaped correctly by roadmap items) |
| Recommendations | Enhancement — upgrade from `proposalGenerator.js`'s boilerplate to real per-finding recommendations |
| CSV export | New (thin wrapper over existing structured data) |
| JSON export | New (thin wrapper) |
| API access | New, see §10 |

---

## 14. Commercial Plan

**Pricing** extends the existing immutable `PRICING_CONFIG.packages` (**Verified** `workers/src/config/pricingConfig.js`), following its established shape rather than inventing a parallel pricing system:

| Tier | Price (proposed) | Basis |
|---|---|---|
| Automated Scorecard (self-serve) | ₹9,999 one-time | Anchored to the existing `SECURITY_ASSESSMENT` package price (₹9,999) — same price point, AI-specific scope |
| Automated + Executive PDF + Roadmap | ₹24,999 one-time | New tier — **Proposed**, not yet in `pricingConfig.js` |
| Full Assessment + Consulting Session | ₹1,50,000 – ₹5,00,000 | Matches the rough draft's original intent; justified only once a pilot customer exists (see §15) — priced meaningfully above anything currently in `pricingConfig.js`, so treat as an enterprise-quote SKU, not a self-serve button, until proven |

**Subscription:** quarterly/annual re-assessment as a recurring add-on is **Blocked** by the platform-wide Razorpay-subscription gap (§6, Master Strategy doc) — launch with one-time purchase + email renewal reminder (matches how "Monthly" plans already work today per the audit).

**Usage/Credits:** not applicable at launch — one-time assessment purchase model only.

**Enterprise Licensing:** MSSP white-label of the PDF report (existing `whiteLabelMSSP.js` pattern, Enhancement).

**Professional Services / Consulting:** reuses `consultationPreAssessEngine.js` as-is.

**Marketplace:** optional secondary Sentinel APEX Marketplace listing.

**Training / Certification:** out of scope for v1 — flagged as a future bundle opportunity with the existing Academy (`academyMarketplace.js`, CAP-ACAD-001/002).

**Bundle opportunities:** package with Product 2 (Threat Intel Automation Pack) for a combined "AI Security Posture + Automation" enterprise bundle — **Proposed**, not costed here.

---

## 15. Financial Model *(Assumed — no real customers exist platform-wide today per `KPI_DASHBOARD.md`; treat every figure below as a planning input, not a forecast)*

| Line | Estimate | Basis |
|---|---|---|
| Development effort | 4–6 engineer-weeks | Unification work across 5 existing engines + 1 new frontend chart + 1 new orchestration handler; no net-new scanning engine required |
| Incremental operational cost | Low | No new external data-provider dependency (unlike Product 3's HIBP/dark-web needs); reuses existing D1/Workers infra |
| Revenue streams | One-time automated tier, one-time premium tier, consulting-session referral fee/split | — |
| Gross margin | High on automated tier (near-zero marginal cost per run); services-typical on consulting tier | — |
| Upsell/cross-sell | Consulting session (existing hook); Product 2 bundle | — |
| Enterprise expansion | MSSP white-label resale | Existing pattern (`whiteLabelMSSP.js`) |

---

## 16. Go-To-Market & Launch Plan

- **Landing/Sales page:** retarget existing `ai-security-assessment.html` and `ai-security-scorecard.html` (both already live, already SEO-positioned) rather than building new pages.
- **Pricing page:** add the new SKU to the existing pricing table pattern.
- **Demo:** short recorded walkthrough of the automated scorecard (reuses the real, already-working live signal collection — no simulated demo needed).
- **Case studies:** **cannot be produced yet** — zero real customers platform-wide (**Verified**, `KPI_DASHBOARD.md`). First real case study becomes possible only after the first paying customer, consistent with the platform's own GA-O1 blocker.
- **Documentation:** extend `SECURITY_QUESTIONNAIRE_PACK.md`-style evidence packaging.
- **SEO:** the existing `ai-security-assessment.html`/`ai-security-scorecard.html` pages already carry SEO structure per `SEO_VISIBILITY_PLAYBOOK.md`'s locked conventions — extend, don't replace.
- **Email campaign:** reuse `emailEngine.js`.
- **Partner program:** MSSP white-label resale.
- **Affiliate strategy:** existing affiliate program applies unchanged.
- **Launch plan:** gated behind the Development Roadmap's Phase 9 (Production) acceptance criteria below — no marketing push before the Product Council gate (`docs/ENGINEERING_STANDARDS.md` §7) is passed.

---

## 17. Risk Assessment

| Risk | Category | Mitigation |
|---|---|---|
| Unifying 5 independent maturity engines introduces scoring inconsistency vs. each engine's existing standalone output | Technical | Keep each engine's native output intact and additive; the unified score is a new derived field, not a replacement, so nothing existing regresses |
| `assessmentBooking.js` reactivation surfaces a latent bug never caught because it's never been used in production | Technical | Full regression + manual QA pass before wiring a frontend caller to it; add the test coverage the audit found missing |
| Recurring-billing gap blocks the "subscription" framing the master prompt requests | Commercial | Launch one-time-purchase only; document the gap explicitly rather than overstate subscription readiness (see Master Strategy doc) |
| Premium tier (₹1.5L–5L) has no proof point without a real customer | Commercial | Price-gate behind a manual sales-assisted flow (like existing enterprise packages), not a self-serve button, until a pilot lands |
| No real dynamic_browser verification exists yet for the new UI | Operational | Follow the platform's own Permanent Release Lifecycle (`ENGINEERING_STANDARDS.md` §9) — Customer Verification step before GA claim |
| Registry gap (uncatalogued scorecard capability) could recur for this new product too | Operational | Register new CAP-IDs in `docs/capability-registry/domains/` as part of Phase 7 (Documentation) below |

---

## 18. Development Roadmap

| Phase | Deliverables | Dependencies | Tests | Acceptance Criteria | Rollback |
|---|---|---|---|---|---|
| 1. Repository reuse | Confirm reuse map above; no code yet | This document's approval | N/A | Reviewed & approved reuse plan | N/A |
| 2. Backend | `aiMaturityHandler.js` orchestration layer; new tables (§9); reactivate `assessmentBooking.js` route wiring | Phase 1 | Unit tests per handler function | All new endpoints return canonical envelope; existing engines' output unchanged | Revert new handler; existing engines untouched throughout |
| 3. Frontend | `ai-maturity-assessment.html`; radar chart; roadmap table | Phase 2 APIs live | Playwright smoke test | Page renders, wizard completes, chart displays real data | Feature-flag off; existing pages unaffected |
| 4. RBAC | Confirm org-scoping on all new endpoints/tables | Phase 2 | `orgRbacIsolation.test.mjs`-style cross-org rejection tests | 403/404 on cross-org access, verified by test | N/A (additive only) |
| 5. Commercial | New `pricingConfig.js` SKU entries; checkout wiring | Phase 2–3 | Payment flow test against Razorpay sandbox | Order creation + verification succeed end-to-end | Disable SKU; existing packages unaffected |
| 6. Testing | Full regression suite run; new test files for all new handlers | Phase 2–5 | Full suite (currently 297 files / ~3,100+ tests) stays green | Zero regressions | N/A |
| 7. Documentation | Register new CAP-IDs in `docs/capability-registry/domains/`; update `DOCUMENTATION_INDEX.md` if a new canonical doc is created | Phase 2–6 | `scripts/registry/validate.mjs` passes | Registry entries present with real file:line evidence | N/A |
| 8. Release Candidate | Product Council gate (`ENGINEERING_STANDARDS.md` §7) answered; CAB's six questions answered | Phase 1–7 | Gated pipeline (test → deploy → smoke) | All CAB questions answered in the PR record | Standard gated-pipeline rollback |
| 9. Production | Deploy; Customer Verification pass (real click-through, not just API check) | Phase 8 | `dynamic_browser` verification | Registry entry can honestly claim `customer_journey_complete: true` only after this | Standard deploy rollback runbook |

---

## 19. Testing Strategy

- Unit tests for `aiMaturityHandler.js`'s aggregation logic (mock each upstream engine's output, verify correct unification).
- Integration test: full assessment run against a test target, verifying all four upstream engines are actually called and their outputs land in `framework_scores`.
- RBAC/tenant-isolation tests matching the `orgRbacIsolation.test.mjs` pattern.
- Payment flow test for the reactivated `assessmentBooking.js` path (Razorpay sandbox).
- Accessibility (axe-core) and Lighthouse tests for the new frontend page, matching the existing CI gate every other page passes.
- Regression lock: assert the four upstream engines' *existing* standalone endpoints are unchanged (per `docs/ENGINEERING_STANDARDS.md` §5's contract-drift-test pattern).

---

## 20. Deployment Strategy

Standard existing pipeline: feature branch → CI (`ci.yml`) → gated `test.yml` → `deploy.yml` (Cloudflare Workers + Pages) → post-deploy smoke. No new infrastructure, no new Cloudflare bindings beyond the existing D1 database and existing Razorpay secret bindings. No new cron slot required (§6.2).

---

## 21. Customer Success Plan

- Onboarding: guided 3-step wizard (§11); time-to-first-value target: one assessment cycle (~minutes, matching the existing scanners' ~7s cold-scan TTFV per `KPI_DASHBOARD.md`, plus report-generation time).
- Success milestone: first PDF report downloaded/viewed.
- Expansion signal: roadmap item marked "resolved" → prompt for re-assessment to show score improvement (a genuine, evidence-backed upsell trigger, not a cold nudge).
- Support: extend `SUPPORT_PLAYBOOK.md`'s existing ticket taxonomy with an "AI Maturity Assessment" category.

---

## 22. Business Plan

**TAM/SAM/SOM (Assumed — not sourced from a licensed market report; treat as a planning input):** Global AI governance/security-assessment services is a fast-growing but fragmented category; no verified sizing exists in this repository's prior documents (the cross-cutting audit confirmed no TAM/SAM/SOM figures exist anywhere in `docs/audit-history/`). Recommend commissioning or citing a named third-party estimate (e.g., a public Gartner/IDC AI governance market figure) before publishing any number externally — this document deliberately does not fabricate one.

**ICP:** Mid-market to enterprise companies (200–5,000 employees) that have shipped at least one customer-facing LLM feature, in regulated or reputation-sensitive sectors (fintech, healthtech, SaaS selling into enterprise).

**Competitor Analysis (Assumed):** Most competitors are either (a) generic GRC/compliance platforms bolting on an "AI module" with no live technical signal, or (b) boutique consulting firms selling a manual audit with no repeatable product. This product's differentiation (§4) is real and defensible *if* the unification work in §2/§6 is completed — it is not yet a shipped differentiator.

**Pricing Strategy:** see §14 — anchor to existing `pricingConfig.js` price points for the entry tier; treat the premium tier as unproven until a pilot customer exists.

**Revenue Forecast:** not modeled with specific figures here — per CLAUDE.md, fabricating a forecast against zero real customers would be a false-precision claim. Recommend the first commercial milestone be "one real paid automated-tier assessment," mirroring the platform's own GA-O1 blocker framing in `KPI_DASHBOARD.md`.

**Sales Strategy:** self-serve for the automated tier; sales-assisted (existing `booking.html` / `enterpriseLayer.js` consultation flow) for the premium tier.

**Partner Strategy:** MSSP white-label resale.

**Marketing Strategy:** content marketing off the existing `ai-security-assessment.html`/`ai-security-scorecard.html` SEO base; CISO-targeted LinkedIn thought leadership (per the original rough draft's instinct, which is reasonable and low-cost, but should wait until a real automated tier exists to demo).

**Customer Success:** see §21.

**KPIs:** assessments run, PDF downloads, roadmap-item resolution rate, re-assessment rate, consulting-upsell conversion rate — all currently `UNKNOWN` per `KPI_DASHBOARD.md`'s own convention, to be populated only with real evidence once live.

**Expansion Strategy:** consulting upsell → Product 2 bundle → MSSP white-label resale, in that order of engineering readiness.

---

## 23. Executive Product Scorecard

| Dimension | Rating | Basis |
|---|---|---|
| Architecture completeness | 🟡 Partial | Five engines exist; unification layer does not |
| Reuse of existing platform | 🟢 High | Highest reuse of the four EPEP products |
| New engineering required | 🟢 Low | ~4–6 engineer-weeks estimated |
| Security/compliance readiness | 🟢 Strong | Inherits proven RBAC/tenant-isolation/audit patterns unchanged |
| Commercial readiness | 🟡 Partial | Entry tier fits existing pricing model; premium tier unproven; recurring billing blocked platform-wide |
| Customer evidence | 🔴 None | Zero real customers platform-wide today |
| Recommended sequencing | **1st of 4** | Confirms and strengthens the original CEO recommendation |

**GO / Conditional GO / NO-GO:** **Conditional GO** — proceed to Phase 2 (Backend unification) on approval of this document; commercial launch (Phase 9) is conditional on the platform's Razorpay recurring-billing gap being explicitly acknowledged (not silently assumed solved) and on Product Council gate sign-off per `ENGINEERING_STANDARDS.md` §7.
