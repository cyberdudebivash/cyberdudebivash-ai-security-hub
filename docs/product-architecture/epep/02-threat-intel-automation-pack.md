# Product 2: Threat Intelligence Automation Pack

**Program:** Enterprise Product Expansion Program (EPEP) · **Phase:** Product Architecture & Business Design (pre-implementation)
**Status of this document:** Proposed architecture. No new code has been written under this program yet — see §2 for what already exists.
**Evidence basis:** Direct repository audit, 2026-07-15 (commit `d7841aa`). Claims tagged **Verified** / **Assumed** / **Proposed** per CLAUDE.md.

---

## 1. Executive Summary

**Problem solved.** MSSPs and SOC teams need threat intelligence converted into deployable detection content (Sigma/YARA/KQL/SPL rules) and automated delivery into their SIEM/SOAR, not another dashboard to read. Today this platform already **sells** exactly this ("APT Detection Sigma Pack," "Ransomware Detection Pack 2025" — real, live SKUs in `toolsMarketplace.js` and `marketplaceCheckoutHandler.js`) but fulfills every order **manually, by a human, within 24 hours** (**Verified** — `marketplaceCheckoutHandler.js` self-documents this: *"no automated rule/playbook-authoring engine exists... routes to manual fulfillment," `delivery: 'manual_pending'`*).

**Target customer.** MSSPs (multi-tenant, need to push detection content across many client SIEMs), SOC teams needing a faster mean-time-to-detection-content, and security engineers who want live threat data delivered as ready-to-deploy rules, not PDFs.

**Business value.** Directly automates a **real, already-selling** product line. This is the strongest commercial proof-of-demand of the four EPEP products: customers are already paying for "packs" today; the opportunity is to replace the 24-hour manual-email fulfillment with same-second automated generation and direct SIEM push (the deployment pipe, `siemDeploy.js`, is already Production Ready).

**Revenue opportunity.** Convert an existing manually-fulfilled SKU into a scalable, margin-improving automated product, plus a new recurring "Automation Pack" subscription tier layered on top of the existing one-time pack SKUs.

**Market positioning.** "The only threat intel subscription that ships as a rule, not a report" — differentiated by the fact that a genuine, already-scheduled, already-working rule-generation-and-deployment pipeline exists in production today (`autonomousSocMode.js`), just not exposed as a customer-facing product.

---

## 2. Repository-First Capability Audit

### 2.1 The central finding: a working generator already exists, one layer down from where the obvious files suggested

The obvious places to look (`siemExport.js`, `threatHuntingEngine.js`, `threatHunting.js`) turned out to be either thin single-format tools or static template shelves (see §2.2). The **real, working, already-scheduled** rule generator is in a file the product concept's own framing did not name:

**`workers/src/handlers/autonomousSocMode.js`** — `buildDetectionRules()` (lines 151–250) genuinely generates **four distinct, syntactically correct DSL outputs per CVE** — Sigma, YARA, KQL, and SPL — parametrized on CVE ID, CVSS score, KEV status, and one of 12 vendor keywords. `executePipeline()` (line 279) runs detect → generate rules → **persist to D1** → **auto-call `siemDeploy.js`'s `handleDeploy()`** (lines 423–437) to push to whichever SIEM integrations a customer has configured → Telegram alert. This fires **unconditionally on every cron tick** (`index.js:9404-9411`) — it is already live and scheduled, not dormant.

**Caveat (important for scope):** the detection *condition* logic is one fixed, generic heuristic ("contains cve-id / product-hint / `jndi:` / `cmd.exe` / `bin/sh`") reused for every CVE regardless of vulnerability class. It is parametrized, not vulnerability-*class*-aware — a SQLi CVE and a deserialization CVE get structurally the same rule shape. **Classification: Partial**, not Production Ready, for this reason — real and scheduled, but not yet precise enough to be the sole content behind a paid "Automation Pack" without quality work.

### 2.2 Full capability classification

| Capability | File(s) | Class | Evidence |
|---|---|---|---|
| Per-CVE Sigma+YARA+KQL+SPL generation + auto-deploy | `autonomousSocMode.js` | **Partial** (real & scheduled, generic condition logic) | `buildDetectionRules()` L151-250; cron-fired `index.js:9404-9411`; auto-deploys via `siemDeploy.js` L423-437 |
| STIX 2.1 / CEF export | `siemExport.js` (`buildSTIX`) | **Production Ready** | L322-635, genuine per-record derivation |
| Sigma export (single-format) | `siemExport.js` (`buildSigma`) | **Partial** | L638-683 — real per-record derivation, but single-field `selection` only, no boolean composition |
| YARA / KQL / SPL export | `siemExport.js` | **Absent** | Confirmed 0 matches by grep |
| SIEM/SOAR deployment pipe | `siemDeploy.js` | **Production Ready**, consumer not generator | `buildPayload()` L143-298, real outbound `fetch()` to Splunk/Elastic/Sentinel/QRadar/SecOps/XSOAR/PagerDuty; expects caller to already supply rule text |
| Hunting playbooks | `threatHuntingEngine.js` | **Legacy** | Static 5-entry array (L99-182); `hunt_queries` are plain-English sentences, not executable syntax; hardcoded `sigma_ready` booleans with no rule bodies |
| Canned rule template shelf | `threatHunting.js` (`HUNT_TEMPLATES`) | **Partial** (honest, shallow) | L40-117: exactly 10 static base64-encoded rules (5 KQL/3 Sigma/2 YARA) for generic mimikatz/psexec/cobalt-strike/ransomware TTPs. `handleRunHunt` doesn't execute submitted rules — it regex-mines free text and runs a hand-written D1 SELECT; its own `next_steps` (L440) tells the customer to copy the query into their own SIEM manually |
| Threat correlation/anomaly detection | `huntingEngine.js` | **Production Ready**, different capability | Real clustering/anomaly detectors (L67-381) — not a rule generator, a correlator; don't conflate with "rule generation" |
| STIX/TAXII builder (2nd, unreconciled) | `stix21Engine.js` (`buildSTIXBundle`) | **Production Ready**, duplicate | L229 — independent full STIX2.1+TAXII2.1 builder, duplicates `siemExport.js`'s STIX logic |
| MITRE ATT&CK mapping | `mitreAttackService.js` (`mapToAttack`) | **Production Ready** | L147, real CWE-table + keyword scoring |
| IOC extraction | `iocExtractor.js` (`extractIOCsFromText`) | **Production Ready** | L112, real regex + bogon/FP filtering |
| IOC enrichment | `iocEnrichmentEngine.js` (`enrichIOC`) | **Production Ready**, strongest asset | L276, real multi-source (AbuseIPDB, VirusTotal, Shodan, DNSBL, DNS) + D1 cache |
| CVE/IOC/actor correlation | `correlationEngine.js` (`correlateEntry`) | **Production Ready** | L250, real scoring, 8-actor static map |
| Detection alerting | `detectionEngine.js` (`runDetection`) | **Production Ready** | L272, 9 real detectors → `soc_alerts` |
| Live feed ingestion | `threatFusionEngine.js` (`aggregateThreatFeed`) | **Production Ready** | L224, real live ThreatFox/URLhaus/CISA-KEV fetchers; explicitly removed a prior fabricated dark-web generator (self-documented honesty fix, L17-21) |
| Guidance/mitigation generator | `mitigationPlaybook.js` (`buildPlaybook`) | **Production Ready**, read-only | L72, genuine per-CVE guidance; nothing executes |
| SOAR-style step executor | `workflowAutomation.js` (`executeStep`) | **Partial** | L75-147, real sequential D1-backed executor, 5 real actions incl. genuine outbound `WEBHOOK_CALL`; but only 4 built-in templates (L15-63), no conditional branching, 5-verb vocabulary |
| Outbound webhook delivery | `enterpriseAutomation.js` | **Production Ready** (post CAP-NOTIF-003) | Real HMAC-SHA256 signing, real delivery log, working Create/Pause/Logs/Delete/Test UI. **`dispatchWebhookEvent` confirmed still 0 callers repo-wide** — fires on manual test only, not on real platform events |
| "Rule packs" as a sellable bundle | Marketplace SKUs only | **Dormant/Planned** (sold, unautomated) | `toolsMarketplace.js:27`, `marketplaceCheckoutHandler.js:44/61/78/95` — real SKUs, real checkout, **self-documented manual 24h fulfillment**, `delivery: 'manual_pending'` |

**Registry corroboration:** `docs/capability-registry/domains/threat-hunting-intel.json`'s CAP-TIH-001/009/010 entries are fresh (`last_verified` 2026-07-11/12/14) and self-disclose the fragmentation found above — CAP-TIH-001 notes "one of three parallel hunting implementations"; CAP-TIH-010 notes **four parallel IOC-enrichment code paths**, none reconciled. This is a real, registry-acknowledged consolidation risk, not a new finding — echoing the same duplicate-system pattern this session already resolved once today for the webhook system (CAP-NOTIF-003).

**Documentation-drift flag:** `mythosGodMode.js:716` outputs marketing copy referencing *"MYTHOS-generated Sigma/YARA/KQL rule packs from Defense Marketplace"* with **no backing artifact anywhere in the codebase**. Recommend this copy be corrected or the claim retired independent of this program.

**Infrastructure constraint (Verified, load-bearing for this product's roadmap):** `workers/wrangler.toml`'s `[triggers].crons` block has **exactly 5 slots — the Cloudflare Workers free-tier cap — and all 5 are already in use**, one of which (`runAutoSocCron`) already carries the rule-generation-and-deploy pipeline above. Any new recurring job this product needs (e.g., scheduled pack refresh) must either fan out from an existing cron tick or require a paid Workers plan. See Master Strategy doc for the cross-product sizing of this constraint (Product 3 shares it).

**Bottom line:** ~40% of "AI-powered rule generator producing real Sigma/YARA/KQL/SPL, plus SOAR playbooks" already exists and runs on a schedule. The IOC/STIX/MITRE/correlation substrate underneath is genuinely strong. What's missing: (1) vulnerability-class-aware detection logic in `buildDetectionRules` (today: one heuristic for every CVE); (2) actually automating the "pack" bundling that's already being sold manually — the single biggest gap between pitch and reality; (3) conditional branching + larger action vocabulary in `workflowAutomation.js` before "SOAR" is an accurate claim; (4) reconciling 3–4 parallel hunting/IOC-enrichment implementations before packaging this at scale; (5) wiring `dispatchWebhookEvent` to real events (currently dead code) so "webhook templates" actually fire automatically.

---

## 3. Customer Personas

| Persona | Need | Value moment |
|---|---|---|
| MSSP | Push detection content across many client SIEMs at once | Multi-tenant pack deployment to N configured SIEM integrations |
| SOC Manager | Reduce mean-time-to-detection-content from 24h (today's manual fulfillment) to minutes | Automated pack generation replacing the human-email step |
| Security Engineer | Real, deployable rule syntax, not a PDF description of a threat | Direct `siemDeploy.js` push into their actual SIEM |
| AI Team | Detection content for AI/agent-specific threats (prompt injection indicators, etc.) | Cross-sell with Product 1's attack library |
| DevSecOps | API-triggerable pack generation as part of CI/CD threat-response automation | Programmatic pack API |
| Compliance Officer | Evidence that detection content maps to a named framework (MITRE ATT&CK) | ATT&CK-mapped rule metadata (already real, `mitreAttackService.js`) |
| Enterprise CISO | Assurance that "we automatically deploy detections for actively exploited CVEs" | KEV-prioritized auto-generation (already partially real) |
| Startup Founder | Affordable, no-SOC-team-required baseline detection coverage | Lower-tier pre-built pack subscription |

---

## 4. Value Proposition

- **Already-proven demand:** these exact SKUs sell today, manually fulfilled — this product removes the 24-hour human bottleneck, not invents a new market.
- **Genuinely automated, genuinely scheduled:** `autonomousSocMode.js` already runs this end-to-end for CVE-based detections on a live cron — the core mechanism is real, not aspirational.
- **Deploys where customers work:** `siemDeploy.js` already speaks Splunk/Elastic/Sentinel/QRadar/SecOps/XSOAR/PagerDuty natively.
- **Measurable outcome:** mean-time-from-CVE-disclosure-to-deployed-detection, a number MSSPs already track internally and will pay to improve.

---

## 5. Feature Matrix

| Feature | Classification | Basis |
|---|---|---|
| Per-CVE Sigma/YARA/KQL/SPL generation | **Existing** (needs quality enhancement) | `autonomousSocMode.js::buildDetectionRules()` |
| Vulnerability-class-aware rule logic (not one generic heuristic) | **Enhancement** | Current logic is CVE-parametrized but class-blind |
| Automated "pack" bundling (per actor/campaign) | **New Build** | Confirmed: "pack" exists only as a marketplace SKU name today, fulfillment is 100% manual |
| Direct SIEM/SOAR deployment | **Existing** | `siemDeploy.js` |
| STIX/TAXII export | **Existing** (needs de-duplication) | `siemExport.js` + `stix21Engine.js` — two parallel builders |
| IOC enrichment | **Existing** | `iocEnrichmentEngine.js` (though 4 parallel implementations exist platform-wide — consolidate before scaling) |
| SOAR playbooks with conditional logic | **New Build** | `workflowAutomation.js` today has fixed step lists, no branching |
| Webhook template delivery on real events | **Enhancement** | Webhook infra is Production Ready; `dispatchWebhookEvent` has zero real callers |
| Subscription/recurring pack delivery | **Blocked by platform gap** | No Razorpay recurring billing exists platform-wide (see Master Strategy doc) |
| Multi-tenant/MSSP bulk deployment | **New Build** | No existing code fans a pack out across multiple client SIEM configs at once |
| Scheduled pack refresh | **Enhancement**, cron-constrained | Must fan out from an existing cron tick — see §2.1 infrastructure constraint |

---

## 6. Technical Architecture & Product Architecture

### 6.1 Services

```
   Live threat feeds (ThreatFox, URLhaus, CISA-KEV)
                    │  threatFusionEngine.js (existing)
                    ▼
        NEW: packGenerationOrchestrator.js
                    │
   ┌────────────────┼─────────────────────────┐
   ▼                ▼                         ▼
mitreAttackService  buildDetectionRules()   iocEnrichmentEngine.js
.js (ATT&CK map)    (autonomousSocMode.js,  (existing, pick ONE of
                    extended: vuln-class-   the 4 parallel impls)
                    aware conditions)
   │                │                         │
   └────────────────┴───────────┬─────────────┘
                                 ▼
                    NEW: pack assembly layer
                    (bundles N rules + ATT&CK
                     metadata + mitigationPlaybook.js
                     guidance into one "Pack")
                                 ▼
              siemDeploy.js (existing, extended for
              multi-tenant fan-out) + enterpriseAutomation.js
              webhook dispatch (existing infra, wire real events)
```

**New: `packGenerationOrchestrator.js`** (Proposed). Does not reimplement rule generation — calls the extended `buildDetectionRules()`, tags output with `mitreAttackService.js` metadata, and assembles a "Pack" (a named bundle of N rules + guidance) replacing today's manual-email fulfillment in `marketplaceCheckoutHandler.js`.

### 6.2 Background jobs

- Reuses the existing `runAutoSocCron` cron tick (no new cron slot — see §2.1 constraint) but extends its output to also populate purchasable Pack inventory, not just auto-deployed detections for existing customers.
- Multi-tenant fan-out for MSSP bulk deployment (Proposed): a queue-consumer pattern reusing the existing `scan-jobs` Cloudflare Queue infrastructure (**Verified** real queue exists, consumed by `processQueueBatch`/`processJob` in `workers/src/lib/queue.js`) rather than inventing a second queue.

### 6.3 Database

New tables (Proposed, org_id-scoped from day one — see Product 4 doc §9 for the same convention applied consistently):

```sql
CREATE TABLE threat_packs (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,          -- e.g. "APT Lazarus Detection Pack"
  actor_or_theme  TEXT,                   -- links to aptActorProfiles.js data where applicable
  rule_count      INTEGER NOT NULL,
  frameworks      TEXT,                   -- JSON: which of sigma/yara/kql/spl included
  generated_at    TEXT NOT NULL,
  auto_generated  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE threat_pack_rules (
  id            TEXT PRIMARY KEY,
  pack_id       TEXT NOT NULL,
  format        TEXT NOT NULL,           -- sigma|yara|kql|spl
  rule_body     TEXT NOT NULL,
  cve_ref       TEXT,
  mitre_ttp     TEXT,
  FOREIGN KEY (pack_id) REFERENCES threat_packs(id)
);

CREATE TABLE org_pack_subscriptions (
  id               TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL,
  pack_id          TEXT NOT NULL,
  deployed_targets TEXT,                 -- JSON: which SIEM integrations this was pushed to
  purchased_at     TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id),
  FOREIGN KEY (pack_id) REFERENCES threat_packs(id)
);
CREATE INDEX idx_pack_sub_org ON org_pack_subscriptions(org_id);
```

### 6.4 RBAC

Reuses the existing org-scoped model unchanged. Pack purchase maps to org ADMIN+; pack deployment to a customer's own SIEM integration credentials requires the same permission level that configures `siemDeploy.js` integrations today.

### 6.5 Event flow, audit logs, monitoring

- Pack generation and deployment events are natural `dispatchWebhookEvent` payloads once that dead-code path is wired to fire on real events (a shared fix with Product 3 — see Master Strategy doc).
- Every deployment attempt logs to the existing `webhook_delivery_log`-equivalent pattern already proven in `enterpriseAutomation.js`.

---

## 7. Integration Plan

| Stage | Integration point | Status |
|---|---|---|
| AI Security Hub | New `threat-automation-pack.html` linked from `threat-intel-workbench.html` and `mssp-command-center.html` | New Build |
| Sentinel APEX | Direct consumer of `threatFusionEngine.js` live feeds and `aptActorProfiles.js` | Existing |
| Threat Intelligence APIs | Extends `intelAPIHandlers.js`/CAP-TIH-009 (API Economy) with a pack-specific endpoint | Enhancement |
| Commercial Registry | New pack SKUs replace/automate the existing manual `toolsMarketplace.js`/`marketplaceCheckoutHandler.js` entries | Enhancement |
| Subscription Registry | Recurring pack-refresh subscription blocked by platform-wide Razorpay gap; launch one-time per-pack purchase first | Blocked (shared) / Existing |
| Payments | Reuses existing Razorpay Orders flow already wired to these SKUs | Existing |
| Marketplace | Directly replaces manual fulfillment in the existing marketplace checkout | Enhancement |
| Dashboard | New widget on `mssp-command-center.html`: packs deployed, targets covered | New Build |
| Reports | Pack manifest (which rules, which ATT&CK techniques, which targets) via `reportingEngine.js` | Enhancement |
| Notifications | Webhook-on-deploy (once `dispatchWebhookEvent` wired) + existing email | Enhancement |

---

## 8. Security Architecture

- **Authentication/Authorization:** unchanged platform patterns (`requireAuth()`, org-scoped RBAC).
- **Tenant isolation:** `org_pack_subscriptions.org_id` scoping, consistent with the newer-era schema convention (see cross-cutting DB note in Master Strategy doc).
- **SSRF protection:** `siemDeploy.js`'s outbound fetch to customer-configured SIEM endpoints must reuse the exact SSRF-guard pattern already implemented and verified today in `enterpriseAutomation.js` (the same defense-in-depth this session's earlier CAP-NOTIF-003 work confirmed) — **do not re-derive a weaker check**, reuse the existing regex/pattern verbatim.
- **Secrets:** customer-supplied SIEM API tokens/webhook secrets stored using the same secret-handling convention already in place for `org_webhooks.secret`.
- **API security / rate limiting:** standard platform middleware; pack-generation endpoints should be rate-limited more conservatively than read endpoints given the compute cost of live feed correlation.
- **Audit logging:** every pack deployment writes an audit entry — this is a security-relevant action (pushing content into a customer's SIEM) and must be traceable.
- **Compliance logging:** ATT&CK-technique tagging on every rule (already real via `mitreAttackService.js`) doubles as compliance evidence for detection-coverage audits.
- **OWASP/NIST/ISO 27001/SOC 2:** no new control category introduced; this product's own outbound-integration surface (calling customer SIEMs) is the highest-sensitivity new attack surface and must inherit the existing SSRF-guard + auth pattern without exception.

---

## 9. Database Design

See §6.3 for full schema. **Retention:** pack/rule content retained indefinitely (it's reusable IP, not per-customer PII); `org_pack_subscriptions` retained per the platform's standard billing-record retention. **Audit tables:** deployment attempts logged via the existing webhook-delivery-log pattern. **Soft deletes:** status-flag convention, consistent with platform-wide practice.

---

## 10. API Specification

| Endpoint | Purpose | Auth | AuthZ | Request | Response | Rate limit | Versioning |
|---|---|---|---|---|---|---|---|
| `POST /api/threat-packs/generate` | Generate a new pack (actor/theme/CVE-driven) | `requireAuth()` (internal/admin for now — see Phase 1 below) | Platform staff initially, org ADMIN+ once self-serve generation ships | `{theme, cve_refs[]?, actor_ref?}` | `{pack_id, rule_count}` | Compute-conservative | `v1` |
| `GET /api/threat-packs` | Browse available packs | `requireAuth()` | org member | query filters | paginated list | standard | `v1` |
| `POST /api/threat-packs/:id/deploy` | Deploy a pack to configured SIEM targets | `requireAuth()` | org ADMIN+ | `{target_integration_ids[]}` | `{deployed: [...], failed: [...]}` | standard | `v1` |
| `GET /api/threat-packs/:id/export` | STIX/CEF/rule-text export | `requireAuth()` | org member | query: `format` | file stream | standard | `v1` |
| `POST /api/threat-packs/:id/subscribe` | Purchase/subscribe to a pack | `requireAuth()` | org ADMIN+ | `{plan}` | Razorpay order (one-time today) | standard | `v1` |

**Errors:** `PACK_NOT_FOUND` (404), `DEPLOYMENT_TARGET_INVALID` (400), `SIEM_UNREACHABLE` (502, from `siemDeploy.js`'s existing error handling).

---

## 11. UI/UX Blueprint

- **Dashboard:** pack catalog (browse by actor/theme/CVE), deployment status per configured SIEM target.
- **Wizard:** "Generate Pack" 3-step flow (theme/actor selection → format selection → deploy targets) — matches the rough draft's original "Simple 'Generate Pack' dashboard... with export buttons" intent, now grounded in real backend capability.
- **Charts:** deployment coverage (which of N configured SIEMs have this pack live), rule-count-by-format breakdown.
- **Risk views:** KEV-flagged CVEs prioritized visually (reusing existing KEV-priority data from `threatFusionEngine.js`).
- **Notifications:** deploy success/failure per target.
- **Dark mode / Accessibility / Responsive:** inherits platform defaults, same bar as every other page (axe-core CI gate).

---

## 12. Customer Journey

Visitor → `threat-intel-workbench.html` (existing) or new `threat-automation-pack.html` → Pricing → Purchase (existing Razorpay Orders flow) → Onboarding (configure SIEM integration credentials, reusing `siemDeploy.js`'s existing integration-config UI if present, else new) → Configuration (select pack theme/targets) → Execution (generate + deploy) → Reports (pack manifest, ATT&CK coverage) → Renewal (manual re-purchase, pending platform-wide recurring-billing fix) → Expansion (MSSP multi-client fan-out) → Referral (existing affiliate program).

---

## 13. Reporting

Pack manifest (rules included, ATT&CK techniques covered, CVE/KEV references), deployment status report, CSV/JSON export of rule bodies, API access for CI/CD pipeline consumption.

---

## 14. Commercial Plan

| Tier | Price (proposed) | Basis |
|---|---|---|
| Single Pack (one-time) | Matches existing marketplace SKU prices already live in `marketplaceCheckoutHandler.js` (e.g. "Ransomware Detection Pack 2025") | Existing — no change, just automate fulfillment |
| Automation Pack Subscription (monthly refresh) | **Proposed**, new tier — anchor near `PRICING_CONFIG.packages.ANNUAL_RETAINER` (₹99,999/yr) for an annual variant, or a new monthly SKU | Blocked from being a true recurring *charge* by the platform-wide Razorpay gap — must launch as a manually-renewed annual/quarterly purchase |
| MSSP Multi-Client Bundle | Enterprise-quote, matches `MSSP_WHITE_LABEL` (₹49,999/mo) positioning | Enhancement of existing MSSP commercial pattern |

**Subscription/Usage/Credits:** not viable as true recurring billing until the platform-wide Razorpay Subscriptions gap is closed (see Master Strategy doc) — launch on the existing one-time-order model.

**Enterprise Licensing:** MSSP multi-tenant fan-out license.

**Professional Services:** custom pack generation for a named actor/campaign on request (reuses `consultationPreAssessEngine.js`-style intake, Enhancement).

**Marketplace:** this product **is** largely a marketplace automation — no new storefront needed, automate the existing one.

**Training/Certification:** out of scope for v1.

**Bundle opportunities:** with Product 4 (combined "AI Security Posture + Automation" bundle) and Product 1 (AI/agent-specific detection content cross-sell).

---

## 15. Financial Model *(Assumed)*

| Line | Estimate | Basis |
|---|---|---|
| Development effort | 6–9 engineer-weeks | Vulnerability-class-aware rule logic + pack assembly layer + multi-tenant fan-out + de-duplicating 2 parallel STIX builders |
| Operational cost | Moderate | Live feed correlation compute; outbound SIEM calls at scale |
| Revenue streams | Automated one-time packs (replacing manual fulfillment margin loss), MSSP bundle, custom-pack services | — |
| Gross margin | Improves materially vs. today's manual-fulfillment cost structure (removes the 24h human labor cost per order) | — |
| Upsell/cross-sell | Product 4 bundle, Product 1 AI-detection content | — |
| Enterprise expansion | MSSP multi-client licensing | — |

---

## 16. Go-To-Market & Launch Plan

Retarget `threat-intel-workbench.html` and MSSP-specific pages (`mssp-command-center.html`, `mssp.html`). Lead the launch narrative with the *automation* angle specifically — "what used to take 24 hours now takes seconds" is a concrete, evidence-backed claim this product can make honestly, unlike claims requiring customer proof. SEO/email/partner/affiliate: reuse existing infrastructure per the pattern in Product 4's doc §16. Case studies: blocked on zero real customers platform-wide today (same caveat as all four products).

---

## 17. Risk Assessment

| Risk | Category | Mitigation |
|---|---|---|
| Generic (class-blind) detection heuristic ships as "AI-powered" and produces low-quality/noisy rules | Technical | Gate GA claim on measured false-positive rate, not on the generator merely running |
| Two parallel STIX builders + four parallel IOC-enrichment implementations create maintenance drift | Technical | Consolidate to one canonical implementation before scaling pack volume (Phase 1 of roadmap) |
| Outbound SIEM deployment is a real SSRF/credential-handling attack surface | Security | Reuse the already-verified SSRF guard pattern from `enterpriseAutomation.js` exactly, no new implementation |
| Cloudflare free-tier 5-cron-slot cap already fully consumed | Operational | Fan out from existing `runAutoSocCron` tick, or budget for a paid Workers plan if Product 3 also needs new scheduled capacity |
| Recurring billing claim in the master prompt's governance list cannot be honestly met | Commercial | Launch one-time-purchase; document the gap plainly rather than imply subscription billing works |
| Existing manual-fulfillment revenue (real, working today) is disrupted mid-migration | Commercial | Keep manual fulfillment as a fallback path until automated generation is quality-verified; don't retire it prematurely (mirrors this repo's own CAP-NOTIF-003 migration discipline: verify before retiring) |

---

## 18. Development Roadmap

| Phase | Deliverables | Dependencies | Tests | Acceptance Criteria | Rollback |
|---|---|---|---|---|---|
| 1. Repository reuse | Consolidate to one STIX builder, one IOC-enrichment path; confirm reuse map | This document's approval | N/A | Reuse plan approved | N/A |
| 2. Backend | `packGenerationOrchestrator.js`; extend `buildDetectionRules()` with class-aware logic; new tables | Phase 1 | Unit tests per rule format | Generated rules pass syntax validation for each of Sigma/YARA/KQL/SPL | Revert new handler; existing auto-SOC cron unaffected |
| 3. Frontend | `threat-automation-pack.html`, pack catalog + deploy wizard | Phase 2 | Playwright smoke | Full generate→deploy flow completes | Feature-flag off |
| 4. RBAC | Org-scoping on all new tables/endpoints | Phase 2 | Cross-org isolation tests | 403/404 verified | N/A |
| 5. Commercial | Pack SKUs in `pricingConfig.js`; checkout wiring; keep manual-fulfillment fallback live | Phase 2–3 | Payment sandbox test | Order → generation → deployment succeeds end-to-end | Fall back to manual fulfillment |
| 6. Testing | Full regression; SSRF regression tests reusing existing suite pattern | Phase 2–5 | Full suite green | Zero regressions | N/A |
| 7. Documentation | Register new CAP-IDs; correct the `mythosGodMode.js` unbacked-claim copy | Phase 2–6 | `validate.mjs` passes | Registry entries present | N/A |
| 8. Release Candidate | Product Council gate; CAB six questions | Phase 1–7 | Gated pipeline | All CAB questions answered | Standard rollback |
| 9. Production | Deploy; retire manual fulfillment only after automated quality is proven over a real order volume | Phase 8 | Live SIEM deployment smoke test | False-positive rate measured and acceptable | Re-enable manual fulfillment fallback |

---

## 19. Testing Strategy

Rule-syntax validators for each of the four DSLs (parse-check, not just string presence); SSRF regression tests matching the existing `enterpriseAutomation.js` suite; SIEM-deployment integration tests against sandboxed/mocked Splunk/Elastic endpoints; multi-tenant fan-out isolation tests; full-suite regression run.

---

## 20. Deployment Strategy

Standard gated pipeline. No new cron slot (reuses existing tick — see §2.1). New Cloudflare Queue consumer for multi-tenant fan-out reuses the existing `scan-jobs` queue infrastructure rather than provisioning a new queue.

---

## 21. Customer Success Plan

Success milestone: first pack successfully deployed to a real SIEM target. Expansion signal: customer configures a second SIEM integration target (multi-tool coverage) or upgrades to MSSP multi-client tier. Support: extend `SUPPORT_PLAYBOOK.md` with a "Pack Deployment Failures" diagnostic category (SIEM connectivity is the most likely failure mode).

---

## 22. Business Plan

**TAM/SAM/SOM:** not sized here (Assumed-category caveat as in Product 4's doc — no verified figures exist in this repository). **ICP:** MSSPs managing 5+ client SIEMs; in-house SOC teams at mid-market+ companies. **Competitor Analysis (Assumed):** commercial TIP (threat intelligence platform) vendors and SOAR vendors both partially compete; this product's differentiation is being bundled inside a platform customers may already use for scanning/compliance, not a standalone TIP purchase. **Pricing Strategy:** see §14. **Revenue Forecast:** not modeled with specific figures — zero real customers platform-wide today. **Sales Strategy:** self-serve single-pack purchase; sales-assisted for MSSP multi-client bundles. **Partner Strategy:** MSSP channel. **Marketing:** lead with the "24 hours → seconds" automation story. **Customer Success:** see §21. **KPIs:** packs generated, packs deployed, deployment success rate, mean-time-from-CVE-to-deployed-detection (the platform's own headline metric candidate) — all `UNKNOWN` until real usage exists. **Expansion Strategy:** single pack → MSSP multi-client → custom-pack services → Product 4 bundle.

---

## 23. Executive Product Scorecard

| Dimension | Rating | Basis |
|---|---|---|
| Architecture completeness | 🟡 Partial | Strong substrate (IOC/STIX/MITRE/correlation), generation/bundling layer thin |
| Reuse of existing platform | 🟢 High | `autonomousSocMode.js` pipeline already scheduled and running |
| New engineering required | 🟡 Moderate | 6–9 engineer-weeks estimated |
| Security readiness | 🟢 Strong | Reuses proven SSRF-guard pattern |
| Commercial readiness | 🟢 Strong | Already selling manually — real, proven demand |
| Customer evidence | 🟡 Partial | Real paying orders exist for the manual product; zero for the automated version yet |
| Recommended sequencing | **2nd of 4** | Confirms the original CEO recommendation |

**GO / Conditional GO / NO-GO:** **Conditional GO** — proceed to Phase 1 (consolidation) immediately given the real, already-monetizing manual product this automates; commercial claims of "SOAR" and "AI-powered" must not ship until the class-aware rule-quality work in Phase 2 is measured, per the Verifiable-Statement Rule (`ENGINEERING_STANDARDS.md` §10).
