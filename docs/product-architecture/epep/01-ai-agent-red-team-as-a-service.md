# Product 1: AI Agent Red Team as a Service (ARaaS)

**Program:** Enterprise Product Expansion Program (EPEP) · **Phase:** Product Architecture & Business Design (pre-implementation)
**Status of this document:** Proposed architecture. No new code has been written under this program yet — see §2 for what already exists.
**Evidence basis:** Direct repository audit, 2026-07-15 (commit `d7841aa`). Claims tagged **Verified** / **Assumed** / **Proposed** per CLAUDE.md.

> **Read this before the rest of the document:** this is the only one of the four EPEP products whose core promise — automated adversarial testing against a *live* customer AI agent — introduces a genuine legal/abuse-risk surface (the platform would be sending attack traffic somewhere). That risk, not raw engineering effort, is why this document recommends a staged rollout rather than building "Live Attack Mode" first. See §17.

---

## 1. Executive Summary

**Problem solved.** Enterprises deploying AI agents / MCP tools / LLM apps need adversarial testing (prompt injection, tool abuse, RCE chaining) but today can only get either a generic compliance questionnaire or a fully manual, expensive pentest engagement.

**Target customer.** Enterprises and AI teams shipping customer-facing or internally-privileged AI agents; security engineers responsible for pre-launch AI risk sign-off.

**Business value.** A tiered offering: a low-cost automated/guided self-assessment tier (customer supplies the transcript, platform grades it — **this already exists and works today**) building up to a premium, human-delivered "Live Attack" engagement (**which also already exists today, as a manual professional service**). The product opportunity is formalizing and productizing what's already real, then — carefully, and later — automating the highest tier.

**Revenue opportunity.** Highest price ceiling of the four EPEP products, but also the highest engineering *and* liability complexity — confirming the CEO's original sequencing (build this third, after the platform's foundational assessment/automation products are strengthened).

**Market positioning.** "Graded by the same platform that already tracks MITRE ATLAS and OWASP LLM Top 10 techniques" — real differentiation, since the attack-technique reference library is genuinely current and actively ingested (**Verified**, see §2).

---

## 2. Repository-First Capability Audit

### 2.1 The central finding: no live attack-execution capability exists anywhere today

A repository-wide audit of every AI/agent-security-adjacent handler, service, and the entire autonomous-agent framework found **zero code paths that deliver adversarial payloads to a live, customer-designated target and grade the response.** What exists instead:

| What's real today | What it is NOT |
|---|---|
| `aiRedTeam.js` — real D1-backed engagement/attempt tracking with negation-aware regex grading (`REFUSAL_PATTERNS`/`POSITIVE_SIGNALS`) | Not an attacker: its own text states *"CYBERDUDEBIVASH does not send live attack traffic to your AI system... you submit the real transcript"* (line 129) — the **customer** attacks their own system and pastes the transcript in for grading |
| `aiRedTeamPro.js` — a real `ai_redteam_campaigns` DB entity (confirmed in `schema_master.sql:4674`) with genuine create/list/get/run routes, real auth | `runCampaign` is simulation-only: *"Probes are NOT sent to target_endpoint here — live attack traffic requires the Enterprise 'Live Attack Mode'"* (lines 286-297) — and that mode **does not exist anywhere in the codebase** (3 comment references, zero implementation) |
| `redteam.js` / `redteamEngine()` in `engine.js` | Fully static 8-scenario array; the code's own metadata says `result:'NOT_TESTED'`, `assessment_mode:'STATIC'`, `live_verification:false` (lines 364-366) |
| `mcpSecurityScanner.js` | Real static vulnerability-catalog scoring, **plus one genuine live call**: a single SSRF-guarded GET of `/.well-known/mcp-manifest.json` (lines 281-307) — manifest/config discovery, not tool-call attack execution |
| `aiSecurityEngine.js`'s `probeAIExposure()` | Real live outbound fetches checking whether an AI endpoint *exists* (`/api/chat`, `/v1/chat/completions`, etc., lines 130-159) — reachability only, not payload delivery. Its "adversarial tests" (ADV-001…005) are scored from **self-reported booleans**, not actual probing |
| `simulationEngine.js`'s `runAttackSimulation()` | A templated MITRE ATT&CK "kill chain" **narrative generator** from static per-module templates (lines 288-355) — a report, not an execution |

**The workers/src/agents/\* swarm (9 files) is 100% defensive, confirmed by direct read of every file, and is not reusable for offense**: `actionExecutor.js` performs remediation (block IP, rotate credentials, apply virtual patch); `decisionEngine.js` maps attack patterns to *remediation* actions; `isolationAgent.js`/`patchingAgent.js`/`credentialRotationAgent.js`/`threatResponseAgent.js` all contain threats, none generate them; `plannerAgent.js` generates *defensive* artifacts (firewall scripts, Sigma/YARA rules) for the MYTHOS product, not attack plans. This entire swarm would need to be built new for ARaaS — it cannot be repurposed.

### 2.2 What IS strong and reusable

| Capability | File(s) | Class | Evidence |
|---|---|---|---|
| Attack technique reference library | `attackLibrary.js` | **Production Ready** | Real D1 CRUD; real counts replacing a prior fabricated "87 techniques" stat (lines 1-10, 104-131) — a good precedent of this codebase self-correcting an overstated claim |
| MITRE ATLAS ingestion | `attackLibraryIngestion.js` | **Production Ready** | Real live fetch of the MITRE ATLAS YAML catalog from GitHub (lines 154-213) |
| AI/ML CVE threat radar | `aiThreatRadar.js` | **Production Ready** | Real live ingestion from OSV.dev, NVD, GitHub Advisories (lines 110-231) |
| Vibe Code (SAST) scanner | `vibe-code/*.js` | **Production Ready** | Real static heuristic engine on pasted source code (`engine.js` `scanVibeCode` lines 160-218) — operates on submitted text, not a live target, but genuinely useful as-is |
| Governance self-attestation + 5-level maturity | `aiGovernance.js`, `aiGovernancePro.js` | **Production Ready** | Real weighted scoring across NIST AI RMF/ISO 42001/EU AI Act (see Product 4 doc for detail — shared asset) |
| Transcript-grading heuristics | `aiRedTeam.js` | **Partial**, usable as v0 judge | Real negation-aware regex grading — a legitimate starting point for automated grading, upgradeable later to an LLM-judge |
| Campaign data model | `aiRedTeamPro.js`'s `ai_redteam_campaigns` schema | **Partial**, usable skeleton | Real schema, no execution engine behind it yet |
| Report data aggregation | `reportingEngine.js` (`AI_SECURITY` template) | **Production Ready** | Genuinely joins `ai_redteam_attempts`/`ai_redteam_engagements`/`ai_findings`/`ai_governance_assessments` into one report (lines 577-662) |
| MCP manifest/config recon | `mcpSecurityScanner.js` | **Partial** | Real, narrow (manifest discovery only) |
| Human-delivered "Live Attack" service | `ai-security-services.html` (₹99,999 SKU) | **Existing (manual/human service, not platform code)** | 14-day delivery, "video evidence," 120-minute debrief — a real, already-sellable professional-services SKU. This explains why "video" appears nowhere in the codebase: it's fulfilled by a human today, not generated |

**Confirmed: no PDF binary engine.** `reportingEngine.js` itself documents *"Workers has no binary PDF library"* (lines 122-177) — reports are styled HTML rendered to PDF via the browser's print function, not a server-side PDF engine. This is a real, load-bearing platform constraint, not unique to this product (Product 4 shares it).

**No registry staleness found** for this product's capabilities — CAP-SCAN-002/003/009/010 (PILOT ONLY) and CAP-MASOC-001 (NOT READY) all match what the code actually does; if anything the registry is charitable given the scanners' own self-declared `STATIC`/`live_verification:false` metadata.

### 2.3 Bottom line

Real, live adversarial testing against a live AI agent **does not exist today in any form.** What's genuinely new engineering: (1) a live HTTP/MCP-protocol attack-delivery client, (2) a stateful multi-turn campaign orchestrator (the `ai_redteam_campaigns` schema is a usable skeleton, not a finished engine), (3) response-grading logic upgraded past regex, (4) **safety/consent/scoping tooling** — a customer must prove ownership/authorization of the target before the platform sends anything to it, precisely the same category of concern any breach-and-attack-simulation (BAS) or pentest SaaS product must solve, (5) a real PDF pipeline (shared constraint with Product 4). Reusable: attack/technique libraries, the transcript-grading heuristic as a v0 judge, the campaign DB schema, `reportingEngine.js`'s aggregation pattern, and the existing human-delivered premium SKU as the top of a tiered offering.

---

## 3. Customer Personas

| Persona | Need | Value moment |
|---|---|---|
| Enterprise CISO | Pre-launch sign-off evidence for a new AI agent | Risk score mapped to OWASP LLM Top 10 + MITRE ATLAS |
| MSSP | Resell red-team engagements to clients | White-labelable report |
| SOC Manager | Understand blast radius if an agent is compromised | Attack-chain narrative (existing `simulationEngine.js` output, upgraded) |
| Security Engineer | Concrete remediation steps per finding | Per-finding recommendation, not just a score |
| AI Team | Self-serve testing during development, not just pre-launch | Guided/self-attack tier (existing `aiRedTeam.js` transcript-grading, productized) |
| DevSecOps | CI-gated agent security check | Programmatic API (guided tier only — see §17 on why Live Attack Mode is not CI-safe) |
| Compliance Officer | Mapping to a recognized framework | OWASP LLM Top 10 + MITRE ATLAS mapping (existing) |
| Startup Founder | Affordable proof of due diligence for an enterprise customer | Low-cost guided tier |

---

## 4. Value Proposition

- **Real technique currency:** the attack library is live-ingested from MITRE ATLAS, not a static list someone wrote once (**Verified**, `attackLibraryIngestion.js`).
- **Tiered, honest capability:** a guided (customer-runs-the-attack, platform-grades) tier that's real today, and a premium human-delivered engagement that's also real today — no tier in the initial launch claims automation the platform doesn't have.
- **Path to differentiation:** once Live Attack Mode is built (carefully, per §17), this becomes the only platform combining a live-tested MITRE ATLAS/OWASP LLM Top 10 score with the rest of the platform's existing threat intel and compliance tooling.

---

## 5. Feature Matrix

| Feature | Classification | Basis |
|---|---|---|
| Guided self-attack + transcript grading | **Existing** | `aiRedTeam.js` |
| MITRE ATLAS / OWASP LLM Top 10 risk scoring | **Existing** | `attackLibrary.js`, `attackLibraryIngestion.js` |
| Campaign tracking (metadata only) | **Existing** | `aiRedTeamPro.js` schema |
| Live attack-delivery client | **New Build** | Confirmed absent anywhere |
| Multi-turn stateful campaign orchestrator | **New Build** (schema exists, engine doesn't) | `ai_redteam_campaigns` is a skeleton |
| Consent/scoping/authorization-to-test workflow | **New Build** | Does not exist; required before any live-attack feature ships |
| LLM-judge grading (upgrade from regex) | **Enhancement** | `aiRedTeam.js`'s regex grading is a real v0 |
| Attack timeline visualization | **New Build** | No chart/timeline UI exists for this data today |
| PDF report | **Existing, with a known platform constraint** | Browser print-to-PDF of styled HTML; no binary PDF engine exists platform-wide |
| Video debrief | **Existing (human-delivered service only)** | Manual professional-services SKU; not a platform automation feature, and this document does not recommend building one (see §17) |
| Rate limiting / circuit breaker on live attack traffic | **New Build** | Required specifically for the abuse-risk reasons in §17, not present anywhere today |

---

## 6. Technical Architecture & Product Architecture

### 6.1 Staged architecture (per §17's risk-driven sequencing)

**Stage A — Guided tier (productize what exists):**
```
Customer's own AI agent (never contacted by the platform)
        │ (customer manually runs prompts, pastes transcript)
        ▼
   aiRedTeam.js (existing, real) ── grading ──▶ ai_findings, ai_redteam_attempts
        │
        ▼
   reportingEngine.js (AI_SECURITY template, existing) ──▶ PDF/HTML report
```
This stage requires **no new attack-execution engineering** — only frontend/commercial productization of what's already real.

**Stage B — Live Attack Mode (new, gated, later):**
```
NEW: consent/scoping capture (authorization-to-test record, signed, scoped to named endpoints)
        │
        ▼
NEW: liveAttackClient.js (HTTP/MCP protocol client, rate-limited, circuit-breaker)
        │  sends real payloads only to customer-attested, owned endpoints
        ▼
Customer's AI agent / MCP endpoint (only after consent capture)
        │
        ▼
NEW: response grading (upgrade of aiRedTeam.js's heuristic, possibly LLM-judge)
        │
        ▼
   ai_redteam_campaigns (existing schema, extended) ──▶ reportingEngine.js (existing)
```

### 6.2 Background jobs

Stage A needs none (synchronous grading, same shape as existing scanners). Stage B's multi-turn campaigns are natural Cloudflare Queue consumers (reuse the existing `scan-jobs` queue pattern, per Product 2's precedent) rather than long-running synchronous requests, given Workers' execution-time limits.

### 6.3 Database

Extends `ai_redteam_campaigns` (existing) with the new consent/scoping and per-turn state needed for Stage B; org_id-scoped from any new table (see Product 4 doc §9 for the mandated convention).

### 6.4 RBAC

Guided tier: standard org ANALYST+ access. **Live Attack Mode should require a higher-privilege, explicitly-granted permission** (e.g., `redteam:live-attack:execute`), separate from normal scan permissions, gated at org ADMIN+ or above — this is a deliberate, additional RBAC control specific to this product's risk profile, not the platform default.

### 6.5 Event flow, audit logs, monitoring

Every Live Attack Mode execution must produce an immutable audit record (who authorized, what scope, what was sent, when) — a materially stronger audit requirement than any other scanner on the platform, given the real-world consequence of sending attack traffic.

---

## 7. Integration Plan

| Stage | Integration point | Status |
|---|---|---|
| AI Security Hub | Extends `ai-red-team.html`, `mcp-security.html` | Enhancement |
| Sentinel APEX | Consumes `aiThreatRadar.js`/`attackLibrary.js` | Existing |
| Threat Intelligence APIs | Cross-references `mitreAttackService.js` (shared with Product 2) for technique metadata | Existing |
| Commercial Registry | New SKU tier structure (see §14) | Enhancement |
| Subscription Registry | Guided tier could be subscription-eligible once platform-wide recurring billing exists; premium tiers are one-time/services today regardless | Blocked (shared) for subscription framing |
| Payments | Existing Razorpay Orders flow | Existing |
| Marketplace | Optional listing alongside existing `SECURITY_ASSESSMENT`-style packages | Enhancement |
| Dashboard | New attack-timeline widget | New Build |
| Reports | Extends `reportingEngine.js` | Enhancement |
| Notifications | Campaign-complete webhook/email (same shared dispatch-wiring dependency as Products 2/3) | Enhancement |

---

## 8. Security Architecture

- **Authentication/Authorization:** standard platform patterns for Stage A; a dedicated elevated permission for Stage B (§6.4).
- **Tenant isolation:** standard org_id scoping.
- **Consent/scoping (Stage B only, new control category for this platform):** a signed authorization-to-test record, scoped to named endpoints/domains the customer attests to owning or having written permission to test — modeled on how real pentest/BAS vendors handle this, since the platform would otherwise risk being used to attack third parties.
- **Rate limiting / circuit breaker (Stage B only):** hard per-target and per-org caps on live attack traffic volume, plus an emergency kill-switch — a new control class this platform has not needed before now.
- **Encryption/Secrets:** no new secret material for Stage A; Stage B may need to store customer-supplied target credentials (e.g., an MCP auth token to test with) — must use the platform's existing secret-handling convention, never logged in plaintext.
- **API security:** standard middleware; Stage B endpoints should be excluded from any CI/automated-trigger path (a live-attack action should never be programmatically schedulable without a human confirming scope each time, given the abuse risk).
- **Audit/compliance logging:** as in §6.5, materially stronger than the platform default.
- **OWASP/NIST/ISO 27001/SOC 2/AI security controls:** this product's *subject matter* is OWASP LLM Top 10 and MITRE ATLAS; the platform's *own* handling of Stage B is itself a security-sensitive feature requiring its own threat model before build — recommend a dedicated security review (not just the standard PR review) before Stage B implementation begins.

---

## 9. Database Design

```sql
-- Extends existing ai_redteam_campaigns; new consent/scoping record
CREATE TABLE ai_redteam_authorizations (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL,
  campaign_id       TEXT,                    -- links to ai_redteam_campaigns
  target_endpoint   TEXT NOT NULL,
  attested_by       TEXT NOT NULL,           -- user_id who signed the authorization
  scope_description TEXT NOT NULL,
  signed_at         TEXT NOT NULL,
  revoked_at        TEXT,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX idx_redteam_auth_org ON ai_redteam_authorizations(org_id);

-- Per-turn state for Stage B live campaigns
CREATE TABLE ai_redteam_campaign_turns (
  id             TEXT PRIMARY KEY,
  campaign_id    TEXT NOT NULL,
  turn_number    INTEGER NOT NULL,
  payload_sent   TEXT,
  response_recv  TEXT,
  graded_result  TEXT,                       -- REFUSED|SUCCEEDED|PARTIAL, from grading logic
  created_at     TEXT NOT NULL
);
CREATE INDEX idx_campaign_turns ON ai_redteam_campaign_turns(campaign_id, turn_number);
```

**Retention:** authorization records retained indefinitely (legal/audit value); turn-level payload/response data retained per a stricter policy than general scan data, given it may contain sensitive prompts — recommend a shorter default retention with customer-configurable extension, distinct from the platform's general `ARTIFACT_RETENTION_POLICY.md` default.

---

## 10. API Specification

| Endpoint | Purpose | Auth | AuthZ | Notes |
|---|---|---|---|---|
| `POST /api/ai-redteam/guided/submit-transcript` | Grade a customer-run attack transcript | `requireAuth()` | org ANALYST+ | Formalizes existing `aiRedTeam.js` behavior into a versioned, product-facing endpoint |
| `GET /api/ai-redteam/campaigns/:id` | Campaign status/results | `requireAuth()` | org member | Existing `aiRedTeamPro.js` route, extended |
| `POST /api/ai-redteam/authorizations` | Record consent/scoping for Live Attack Mode | `requireAuth()` | org ADMIN+ | **New**, Stage B only |
| `POST /api/ai-redteam/live/execute` | Execute a live campaign turn | `requireAuth()` + `redteam:live-attack:execute` permission | org ADMIN+, valid unexpired authorization record required | **New**, Stage B only — must reject if no matching `ai_redteam_authorizations` row exists |
| `GET /api/ai-redteam/campaigns/:id/report.pdf` | Report | `requireAuth()` | org ADMIN+ | Reuses `reportingEngine.js` |

**Errors:** `AUTHORIZATION_REQUIRED` (403, Stage B specific — a deliberately named error distinct from generic `forbidden()`), `TARGET_SCOPE_MISMATCH` (400), `RATE_LIMIT_EXCEEDED` (429).

---

## 11. UI/UX Blueprint

- **Dashboard:** matches the existing dark cyberpunk theme (**Verified** consistent with `enterprise-dashboard.html`'s real CSS variables — this is not an invented aesthetic, it is the platform's actual design language).
- **Guided-tier wizard:** attack-technique picker (from the real `attackLibrary.js` catalog) → customer runs it manually → transcript paste → grade.
- **Attack timeline visualization:** **New Build** — no charting exists for this data today; recommend a simple horizontal swimlane (per-turn outcome) rather than a novel visualization, kept consistent with the platform's minimal chart-library footprint (Chart.js, currently used in one file).
- **Stage B UI:** must surface the authorization/scoping step as a hard gate in the flow, not an afterthought — the UI itself is a control, not just a convenience.
- **Reports/Notifications/Dark mode/Accessibility/Responsive:** inherits platform conventions.

---

## 12. Customer Journey

Visitor → `ai-red-team.html` (existing) → Pricing (see §14) → Purchase → Onboarding (guided tier: technique selection; Stage B: authorization capture) → Configuration → Execution (guided: customer self-attacks; Stage B: platform executes within scope) → Reports → Renewal → Expansion (guided → premium human engagement → Stage B once available) → Referral.

---

## 13. Reporting

Executive PDF (via `reportingEngine.js`, browser-print constraint noted), technical per-finding report, MITRE ATLAS/OWASP LLM Top 10 risk matrix, remediation recommendations, CSV/JSON export, API access (guided tier only at launch).

---

## 14. Commercial Plan

| Tier | Price (proposed) | Basis / Status |
|---|---|---|
| Guided self-attack + grading | ₹9,999–₹24,999 one-time | Anchored near existing `SECURITY_ASSESSMENT` (₹9,999) / `THREAT_INTEL_REPORT` (₹14,999) price points in `pricingConfig.js` — **not** the rough draft's ₹24,999 starter price for a fundamentally lighter capability; recommend pricing honestly below the eventual Live Attack tier |
| Full guided campaign + expert review | ₹79,999 | Matches the rough draft's original "Pro" price — justified once the guided tier is proven, by adding a human expert review layer on top (services, not new engineering) |
| Live Attack Mode (Stage B, future) + quarterly managed service | ₹2,99,999+/year | Matches the rough draft's Enterprise tier — **do not launch this tier before Stage B's consent/scoping/rate-limiting controls are built and reviewed** (§17) |
| Existing manual "AI Red Team Engagement" | ₹99,999 (already live) | Keep as-is; this is the real top-of-funnel premium proof point today |

**Subscription:** blocked by the platform-wide Razorpay recurring-billing gap for any recurring framing; all tiers launch as one-time or existing-manual-service purchases.

**Enterprise Licensing / Professional Services:** the existing ₹99,999 manual engagement **is** the professional-services line — formalize it, don't replace it.

**Marketplace / Training / Certification:** out of scope for v1.

**Bundle opportunities:** with Product 4 (combined AI governance + red-team bundle).

---

## 15. Financial Model *(Assumed)*

| Line | Estimate | Basis |
|---|---|---|
| Development effort (Stage A only) | 2–3 engineer-weeks | Pure productization of existing `aiRedTeam.js`/`attackLibrary.js`, no new attack engine |
| Development effort (Stage B) | 10–16 engineer-weeks + dedicated security review | Live attack client, consent/scoping system, rate limiting/circuit breaker, upgraded grading — the highest-effort single component across all four EPEP products |
| Operational cost | Low (Stage A), moderate-to-high (Stage B, given outbound traffic monitoring needs) | — |
| Revenue streams | Guided tier, expert-review upsell, existing manual premium engagement, future Stage B managed service | — |
| Gross margin | High (Stage A, software-only); services-typical (existing manual engagement); TBD (Stage B, pending abuse-monitoring cost) | — |

---

## 16. Go-To-Market & Launch Plan

Launch Stage A first and market it honestly as "guided" — do not imply live automated attack capability before it exists (Verifiable-Statement Rule, `ENGINEERING_STANDARDS.md` §10). Retarget existing `ai-red-team.html`/`owasp-llm-security.html`/`prompt-injection-defense.html`. Case studies: blocked on zero real customers platform-wide. Stage B launch (if approved) should be preceded by a visible, published testing-authorization policy — both a trust signal and a legal safeguard.

---

## 17. Risk Assessment — read this section before approving Stage B

| Risk | Category | Mitigation |
|---|---|---|
| **Platform used to attack a target the requester does not own/control** | **Legal / Security / Abuse** | Hard gate: no Stage B execution without a signed, scoped `ai_redteam_authorizations` record; recommend legal review of the authorization language before launch, same category of diligence a real pentest firm applies |
| Live attack traffic causes real damage/outage to a customer's production AI agent | Technical / Legal | Rate limiting, circuit breakers, and a documented "non-destructive testing only" scope boundary; consider a sandboxed/staging-only requirement for early Stage B customers |
| Grading logic (regex or LLM-judge) produces false negatives, giving customers false assurance | Technical | Treat grading accuracy as a measured, published limitation (per Verifiable-Statement Rule), not an implicit guarantee |
| No case studies possible before a real customer | Commercial | Launch Stage A on its own honest merits; do not delay Stage A waiting for Stage B |
| Premium tier priced far above anything the platform has sold at scale before | Commercial | Sales-assisted only, not self-serve, until proven |
| "Video debrief" expectation from the rough draft cannot be automated today | Product scope | Keep it as the existing human-delivered service line item; do not build automated video generation — out of scope, low value relative to cost |
| Building an unreviewed live-attack feature under normal engineering velocity | Governance | This is exactly the class of change CLAUDE.md reserves for explicit approval ("customer-facing... changes," high blast radius) — Stage B must not be auto-implemented; it requires its own sign-off round separate from this document's approval of Stage A |

---

## 18. Development Roadmap

| Phase | Deliverables | Dependencies | Tests | Acceptance Criteria | Rollback |
|---|---|---|---|---|---|
| 1. Repository reuse (Stage A) | Confirm reuse of `aiRedTeam.js`/`attackLibrary.js`/`reportingEngine.js` | This document's approval | N/A | Reuse plan approved | N/A |
| 2. Backend (Stage A) | Versioned guided-tier API surface wrapping existing handlers | Phase 1 | Unit tests | Endpoints return canonical envelope | Revert new wrapper; existing handlers untouched |
| 3. Frontend (Stage A) | Guided wizard UI, timeline visualization | Phase 2 | Playwright smoke | Full guided flow completes | Feature-flag off |
| 4. RBAC (Stage A) | Standard org-scoping | Phase 2 | Isolation tests | Verified | N/A |
| 5. Commercial (Stage A) | New pricing SKUs | Phase 2-3 | Payment sandbox | Order flow works | Disable SKU |
| 6. Testing (Stage A) | Full regression | Phase 2-5 | Full suite green | Zero regressions | N/A |
| 7. Documentation (Stage A) | Register CAP-IDs | Phase 2-6 | `validate.mjs` | Registry entries present | N/A |
| 8. Release Candidate (Stage A) | Product Council + CAB gates | Phase 1-7 | Gated pipeline | CAB questions answered | Standard rollback |
| 9. Production (Stage A) | Deploy, Customer Verification | Phase 8 | `dynamic_browser` check | Verified | Standard rollback |
| **Stage B (separate approval required, not auto-sequenced)** | Consent/scoping system, live attack client, rate limiting, security review | Stage A live + explicit new sign-off | Dedicated security review + all of the above | Legal/security review passed **in addition to** standard gates | Kill-switch disables Stage B entirely without affecting Stage A |

---

## 19. Testing Strategy

Stage A: standard unit/integration/regression, matching Product 4's pattern. Stage B (if approved): dedicated abuse-simulation testing (attempt to use the feature against an out-of-scope target and verify hard rejection), rate-limit/circuit-breaker load testing, and a formal security review distinct from normal code review.

---

## 20. Deployment Strategy

Stage A: standard gated pipeline, no new infrastructure. Stage B: recommend a feature-flagged, allow-listed rollout (specific approved customers only) before any general availability claim, given the risk profile in §17.

---

## 21. Customer Success Plan

Stage A success milestone: first graded transcript report delivered. Expansion signal: repeat guided assessments → expert-review upsell → existing manual premium engagement. Support: new "Red Team Grading Accuracy" ticket category, given grading-quality questions are the most likely support load.

---

## 22. Business Plan

**TAM/SAM/SOM:** not sized here (no verified data, per CLAUDE.md — treat as future work with a named source). **ICP:** enterprises with at least one production customer-facing or tool-using LLM agent. **Competitor Analysis (Assumed):** a small but growing set of dedicated LLM red-team/BAS vendors exist; this platform's differentiation is bundling with existing compliance/governance tooling rather than being a point solution. **Pricing Strategy:** §14. **Revenue Forecast:** not modeled with specific figures. **Sales Strategy:** self-serve (guided tier), sales-assisted (premium/Stage B). **Partner Strategy:** MSSP resale of the guided tier. **Marketing:** lead with real MITRE ATLAS currency, not unproven live-attack claims. **Customer Success:** §21. **KPIs:** guided assessments completed, expert-review upsell rate, existing-manual-engagement volume — all `UNKNOWN` until real usage exists. **Expansion Strategy:** guided → expert review → existing manual engagement → Stage B (long-term, contingent on separate approval).

---

## 23. Executive Product Scorecard

| Dimension | Rating | Basis |
|---|---|---|
| Architecture completeness (Stage A) | 🟢 Strong | Real, working transcript-grading + attack library |
| Architecture completeness (Stage B) | 🔴 Absent | Confirmed zero live-attack capability anywhere |
| Reuse of existing platform | 🟡 Moderate | Strong for Stage A, minimal for Stage B |
| New engineering required | 🟢 Low (Stage A) / 🔴 High (Stage B) | 2-3 vs. 10-16 engineer-weeks |
| Security/liability readiness | 🔴 Requires new controls | Consent/scoping/rate-limiting do not exist and are non-optional for Stage B |
| Commercial readiness | 🟢 Strong (Stage A + existing manual tier) | Real SKUs already sellable today |
| Customer evidence | 🔴 None | Zero real customers platform-wide |
| Recommended sequencing | **3rd of 4** (Stage A could move earlier; Stage B stays last) | Confirms the original CEO recommendation, with an explicit split this document adds |

**GO / Conditional GO / NO-GO:** **Conditional GO for Stage A only.** Stage B is **NO-GO pending a dedicated legal/security review** — this document explicitly declines to recommend auto-implementing live attack-execution capability, consistent with CLAUDE.md's requirement that customer-facing, high-blast-radius changes wait for explicit approval.
