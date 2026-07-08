# Phase X — General Availability Report & GA Decision Matrix

> **GA Board instrument.** Phase X asks a different question than every prior
> phase: not "does the software work?" but **"is the organization ready to
> support paying enterprise customers?"** Every conclusion below traces to a
> live-production request, a named regression lock, or a living register.
> Baseline: the Phase IX Release Candidate program (`PHASE_IX_RELEASE_CANDIDATE_REPORT.md`);
> previously verified evidence remains valid and is not re-litigated.
>
> **Build under review:** `bf12e10` (production) + Phase X GA fix ·
> **Date:** 2026-07-04 · **Suite:** 1,311 tests / 128 files green
> **Decision vocabulary (only these):** GA APPROVED ·
> GA APPROVED WITH DOCUMENTED LIMITATIONS · PILOT ONLY · NOT READY · BLOCKED

---

## 1. What Phase X examined (and found)

The GA Board exercised the operational scenarios **not yet covered** by prior
verified evidence, on live production with throwaway accounts and full
cleanup:

| Scenario | Result |
|----------|--------|
| API key lifecycle: list → usage → **rotate** → old key dead → new key live (`x-api-key`) | All green (200/201; revocation immediate) |
| User provisioning: invite → member access → RBAC over-privilege denial → role change → removal → post-removal lockout | All green (201/200/403/200/200/403) |
| Per-key usage reporting (daily/monthly) | 200, clean structured data |
| AI trust consistency: malformed input → clean 400; real scan → confidence + attack chain + MITRE grounded in the customer's own findings | Green (fabrication-honesty already locked, held) |
| **Credential recovery** | **GA gap found: did not exist** — see GA-B1 |

### GA-B1 — No credential recovery (found, fixed this phase)

Every standard password-reset path returned **404 in live production** and the
login UI had no "Forgot password?" affordance. A customer who forgot their
password permanently lost their account, org, keys, and subscription — with
no support tool as a fallback. For a security vendor this is a GA-blocking
customer-operations failure (full record: `CUSTOMER_OBJECTION_REGISTER.md`
OBJ-08).

**Fix (this phase):** enumeration-safe `POST /api/auth/forgot-password`
(generic response either way, 3/hour per-email rate limit, 32-byte single-use
token stored SHA-256-hashed in KV, 30-minute TTL, no schema migration) →
emailed link (Resend primary / MailChannels fallback) →
`POST /api/auth/reset-password` (strength-validated, consume-before-write,
revokes all prior sessions) → login-UI forgot/reset views. Locked by
`workers/test/phase10PasswordReset.test.mjs` (6 tests). Production endpoint
verification recorded in §7. **Residual owner evidence:** one real inbox
round-trip (needs `RESEND_API_KEY` set in production).

## 2. Customer Trust Certification (stage by stage)

| Trust stage | State | Evidence |
|-------------|-------|----------|
| Discover the product | YES (self-serve) | Public site + docs live; SEO/demand-gen not evaluated by evidence — no claim made |
| Understand the value | YES | Pricing/entitlement truth verified live (Phases VIII–IX); docs derive from enforcement |
| Evaluate the platform | YES | Free tier delivers the real core loop in seconds (TTFV p50 406 ms); honest limits |
| Deploy successfully | YES | 100/100 simulated onboardings + live RC journeys; `IMPLEMENTATION_PLAYBOOK.md` |
| Integrate successfully | PARTIAL | REST/keys/webhooks/SIEM-export verified at API level; no packaged vendor connectors (documented limitation) |
| Operate independently | YES | Org admin, RBAC, key rotation, usage reporting — all exercised live with no engineering help |
| Receive timely support | PARTIAL | Playbooks + honest error contract (`request_id` everywhere); **single-operator support** is the constraint (owner) |
| Recover from incidents | PARTIAL | Runbooks + backups + drill automation + rollback (verified pipeline); no *real* customer-facing incident has tested the loop end-to-end yet |
| Recover their own access | YES (new) | Credential recovery built + locked this phase (email delivery = owner evidence) |
| Renew confidently | NOT YET PROVABLE | Zero real customers; renewal evidence cannot exist before the first one |
| Recommend the platform | NOT YET PROVABLE | Same — requires real customers |

## 3. GA Decision Matrix (per capability)

| Capability | GA decision | Basis |
|-----------|-------------|-------|
| Auth: signup / login / session / logout / change-password | **NOT READY** *(corrected 2026-07-08, was: GA APPROVED)* | Prior basis ("live-verified incl. negative paths") was API-level (`dynamic_api`) — real, but never a browser-driven check of whether a customer can find sign-in. `frontend/index.html`'s only homepage sign-in affordance is a dead-end modal (OK button removes it, links nowhere); the real, working login form exists but is reachable only via a small footer link on `frontend/user-dashboard.html`, not primary navigation. Corrected per `docs/ENGINEERING_STANDARDS.md` §10.3 transparent revision — see `docs/capability-registry/domains/identity.json` (CAP-IDN-001) for full evidence. |
| **Credential recovery (forgot/reset password)** | **GA APPROVED WITH DOCUMENTED LIMITATIONS** | Flow + UI + locks verified; email *delivery* awaits owner inbox round-trip (RESEND_API_KEY) |
| Account deletion / offboarding (GDPR/DPDP) | **GA APPROVED** | Erasure receipt + immediate credential death, live-verified repeatedly |
| Domain scanning + measurement honesty | **GA APPROVED** | Live-verified; honesty (null grade / UNKNOWN) locked |
| Scan → report lifecycle | **GA APPROVED** | Live-verified incl. cache-HIT path; regression-locked |
| AI analyze (grounded threat correlation) | **GA APPROVED** | Live-verified: confidence, attack chain, MITRE, honest 400s; fabrication-refusal locked |
| AI simulate / forecast (paid gates) | **GA APPROVED** | 402 with plan named, verified across phases |
| Pricing & entitlement truth | **GA APPROVED** | Single source of truth; advertised == enforced; locked. *Evidence extended 2026-07-06 (OBJ-11): the anonymous free-feed branch was found unenforced by a 100-org scale simulation and aligned to the promise the same cycle — certification retained per §10.3 transparent revision.* |
| API key lifecycle (issue / rotate / revoke / usage) | **GA APPROVED** | Full lifecycle live-verified this phase |
| Organizations: create / members / RBAC / dashboard / scan history | **NOT READY** *(corrected 2026-07-08, was: GA APPROVED)* | Prior basis ("full admin loop live-verified") was `scripts/ceap-sweep.mjs` calling `/api/orgs*` directly (`dynamic_api`) — real, but API-only. Zero frontend pages call any `/api/orgs*` endpoint; no UI exists to create, view, join, or manage an organization. Backend (RBAC, CRUD, RC-B1 fix) remains genuinely solid — this is a frontend gap, not a backend regression. Corrected per `docs/ENGINEERING_STANDARDS.md` §10.3 transparent revision — see `docs/capability-registry/domains/organizations.json` (CAP-ORG-001) for full evidence. |
| Rate limiting & quota degradation | **GA APPROVED WITH DOCUMENTED LIMITATIONS** | Graceful, honest 429s; FREE tier not SOC-volume by design |
| SSO (OIDC / enterprise) | **PILOT ONLY** | Surface live; no live-IdP round-trip (owner) |
| Billing / payments / subscription lifecycle | **PILOT ONLY** | Surfaces implemented + locked; **zero live payments ever** (owner) |
| Monitoring / alerting / backups / restore / rollback | **GA APPROVED WITH DOCUMENTED LIMITATIONS** | Pipeline-verified rollback + nightly backups + probe; no APM; single operator |
| Support organization | **NOT READY** | Single operator, no deputy/coverage — organizational, not code |
| Regulated-segment adoption (bank/health/gov) | **BLOCKED** | No SOC 2 / external SLA — owner actions, honestly disclosed |

## 4. The GA governance question, answered honestly

*"If an enterprise customer experiences a problem tomorrow, do we have
verified evidence that we can detect it, understand it, communicate clearly,
resolve it, and maintain the customer's trust?"*

- **Detect:** PARTIAL — external uptime probe + post-deploy smoke + honest
  `request_id` errors exist; there is no APM/alerting on error-rate spikes,
  so a partial-surface failure (like RC-B1) is detected by customers first.
- **Understand:** YES — every phase has demonstrated reproduce → root-cause
  within hours, with `request_id` correlation; production-faithful-schema
  tests now close the lab-masking class.
- **Resolve:** YES — the gated pipeline ships a verified fix in minutes
  (demonstrated live in Phases VIII, IX, X); rollback runbook exists.
- **Communicate:** PARTIAL — templates/runbooks exist; never exercised with a
  real customer.
- **Maintain trust:** the platform's honesty posture (honest errors, honest
  limits, honest uncertainty) is the strongest asset; the single-operator
  support model is the weakest.

**Verdict:** the *software* sustains GA for self-serve and non-regulated paid
use. The *organization* is the gating factor — support depth, first live
payment, first live SSO, attestations. Therefore:

> **GA recommendation: GA for free/self-serve (global). GA WITH DOCUMENTED
> LIMITATIONS for non-regulated paid (self-serve support model disclosed).
> PILOT ONLY for billing-dependent expansion until the first real payment
> clears. BLOCKED for regulated segments pending SOC 2 + external SLA.**
> Unchanged in shape from Phase IX — Phase X closed one genuine GA blocker
> (credential recovery) and verified the operational loops around keys,
> provisioning, and AI trust.

## 5. GA Blocker Board (open items — all owner-level)

| ID | Blocker | Blocks | Owner action required |
|----|---------|--------|----------------------|
| GA-O1 | Zero live payments | Paid GA beyond pilot | Execute one real payment end-to-end (highest leverage) |
| GA-O2 | No live-IdP SSO round-trip | Enterprise SSO GA | One OIDC round-trip with a real tenant |
| GA-O3 | Single-operator support | Support readiness for paid GA | Deputy + coverage calendar |
| GA-O4 | No SOC 2 / ISO attestation, no externally measured SLA | Regulated segments | Engage auditor; commission external SLA measurement |
| GA-O5 | `RESEND_API_KEY` unconfirmed in production | Credential-recovery email delivery | Set secret + one inbox round-trip |

No open **code-level** GA blockers remain: every code-closable blocker found
in Phases VIII–X (S1 scan→report, pricing drift, entitlement display, RC-B1
org dashboard, GA-B1 credential recovery) was fixed, regression-locked, and
production-verified.

## 6. Deliverable map (GA package)

| Mandated deliverable | Location |
|----------------------|----------|
| General Availability Report / GA Decision Matrix | this document (§3) |
| Enterprise Operations Manual | `PRODUCTION_OPERATIONS_MANUAL.md` |
| Customer Success Handbook | `CUSTOMER_SUCCESS_PLAYBOOK.md` |
| Support Operations Handbook | `SUPPORT_PLAYBOOK.md` |
| Implementation Handbook | `IMPLEMENTATION_PLAYBOOK.md` |
| Incident Response Handbook | `INCIDENT_RESPONSE_RUNBOOK.md` |
| Business Continuity Handbook | `DISASTER_RECOVERY_RUNBOOK.md` |
| Customer Trust Report | §2 + `CUSTOMER_OBJECTION_REGISTER.md` (Ed. 3) |
| Executive Launch Review | §4 (extends Phase IX §10) |
| Commercial Readiness Report | `PHASE_IX_RELEASE_CANDIDATE_REPORT.md` §4 (unchanged: ₹0 revenue) |
| Release Risk Register | `PHASE_IX_RELEASE_CANDIDATE_REPORT.md` §7 + §5 above |
| Known Limitations Register | `PHASE_IX_RELEASE_CANDIDATE_REPORT.md` §8 (+ no vendor connectors, no APM — restated §2) |
| Customer Adoption Dashboard | `PHASE_IX_RELEASE_CANDIDATE_REPORT.md` §6 (no new real-customer data can exist yet) |
| Operational Readiness / Production Health Dashboard | `PRODUCTION_HEALTH_SCORECARD.md` (Ed. 5) |

## 7. Release Verification Addendum — GA-B1 **Verified** in production

**Release:** `main` fast-forwarded `bf12e10 → 94dcb07` · Test & Quality Gate
passed · Deploy to Cloudflare run **#624** completed/success (includes
post-deploy smoke) · production `/api/version` **and** `/version.json` both
served `94dcb07` ~165 s after push.

**Live production verification** (2026-07-04, fresh throwaway account, full
cleanup):

| Probe | Pre-release | Post-release (`94dcb07`) |
|-------|-------------|--------------------------|
| `POST /api/auth/forgot-password` (real account) | **404** | **200** generic |
| Same request for a nonexistent email | 404 | **200, byte-identical** to the real-account response — no enumeration oracle |
| Malformed email | 404 | **400** with clear message |
| `POST /api/auth/reset-password` invalid token | 404 | **400** — "Invalid or expired reset link. Request a new one." |
| Weak password | 404 | **400** (strength enforced) |
| Login UI | no affordance | "Forgot password?" link, forgot + reset views, endpoints wired |
| Auth regression control | — | login with unchanged password still **200**; account delete 200 |

GA-B1 verification status: **Verified** (flow, endpoints, UI). Credential
recovery: **GA APPROVED WITH DOCUMENTED LIMITATIONS** — the single remaining
limitation is GA-O5: email *delivery* needs one real inbox round-trip with
`RESEND_API_KEY` configured (owner). The happy-path token journey is
regression-locked end-to-end in `phase10PasswordReset.test.mjs`.

---

## 8. Permanent release lifecycle (adopted)

Phase-numbered programs end here. The operating model from this point is the
permanent lifecycle codified in `docs/ENGINEERING_STANDARDS.md` §9:

**Development → Engineering Verification → Customer Verification → Release
Candidate → GA Decision → Post-GA Customer Operations → Continuous
Improvement.**

Post-GA, the default posture is *operating*, not *building*: production-first
validation, the Customer Objection Register as the voice-of-customer intake,
the gated pipeline as the only path to production, and evidence-backed
decisions using the GA vocabulary above.
