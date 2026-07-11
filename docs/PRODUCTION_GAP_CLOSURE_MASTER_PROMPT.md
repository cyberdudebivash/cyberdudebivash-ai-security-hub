# CyberDudeBivash AI Security Hub — Master Production Gap Closure Prompt

**Purpose of this document:** a self-contained execution brief for Claude
Code (this session or a fresh one) to drive the platform's *entire* tracked
gap backlog toward closure, at the same rigor already proven across every
wave logged in `docs/capability-registry/PROGRAM_BOARD.md`. Paste this whole
document as the opening prompt of a session — it assumes zero prior
conversation memory.

**Relationship to the other master prompt:** `docs/
ENTERPRISE_PARITY_MASTER_PROMPT.md` is a *scoped sub-initiative* of this one
— the customer/user/admin/CRM account-management gaps found via a direct
comparison against CrowdStrike, SentinelOne, Palo Alto Cortex, Recorded
Future, Google Mandiant, and ThreatConnect. Run that document's waves as
part of this backlog; don't duplicate its content here.

---

## 0. An honest framing of "100%" — read this before anything else

The user's mandate is to close every gap to the highest achievable
production-grade quality. Taken literally, "100% complete, zero gaps,
forever" is not a real, falsifiable end-state for any live, evolving
platform — and this codebase's own standards deliberately forbid claiming
it: `docs/ENGINEERING_STANDARDS.md` §9's fixed vocabulary explicitly bans
*"100% complete"*, *"bug free"*, and *"guaranteed"* as claims, precisely
because unfalsifiable claims are how "production ready" reports drift away
from what a real customer actually experiences — which is exactly the
failure mode this whole registry was built to catch and correct (see
`PROGRAM_BOARD.md`'s repeated pattern: a doc claimed "GA APPROVED,
live-verified," and the real customer-facing path was actually a dead end).

So this prompt's real target — the honest, rigorous, and *harder* version of
"100%" — is:

> **Zero Critical (P1) gaps. Zero High (P2) gaps. Every capability at
> `operational_status: GA APPROVED` (with or without documented, genuinely
> minor limitations — never silently-broken limitations). Every claim of
> "fixed" backed by a real `dynamic_browser` or `dynamic_api` verification
> against live production, not a static read of the code.**

Chase that bar. State progress in that vocabulary — "9 Critical → 0
Critical, live-verified" is a claim a skeptical enterprise buyer's own
security team could re-derive and check. "100% complete" is not. Do not let
the user's phrasing pull you into writing an unverifiable claim into the
registry, a commit message, or a customer-facing page — translate the
mandate faithfully into what's actually checkable, and say so plainly if
asked, the way this note does.

---

## 1. Non-negotiable operating discipline

1. **Read real code before writing any fix.** Trace the actual root cause
   — never patch a symptom you haven't traced to its source.
2. **Fixes are additive and backward-compatible by default.** Don't touch
   working code paths outside the fix's scope.
3. **Schema migrations are prepared, never self-applied.** Write the
   migration file (naming convention: `workers/schema_migration_*.sql`) and
   update `workers/schema_master.sql`'s canonical table definition, but the
   actual `wrangler d1 execute --remote` against production only ever runs
   via the human-gated `.github/workflows/db-migrate.yml` (the operator
   must type `APPLY`). Ship code that is a **safe no-op** until the
   migration runs (try the richer read/write first, fall back cleanly if
   the schema element doesn't exist yet) so the feature self-activates the
   moment the owner applies it, with zero second deploy.
4. **Every fix gets real dynamic verification, not static assertions
   alone.**
   - Backend: a real in-memory SQL engine (`node:sqlite`, `DatabaseSync`)
     executing the actual handler functions — see
     `workers/test/orgRbacIsolation.test.mjs` / `orgAuditLog.test.mjs` for
     the harness pattern.
   - Frontend: a real headless-Chromium Playwright session. Sandboxed
     Chromium has no direct network access — relay requests through
     Node's own `fetch()` (reconstruct the `pw-helper.mjs` relay pattern
     from prior sessions' scratchpad if it isn't already present). Hit
     routes that already exist in production for real; for a genuinely new
     route that can't exist pre-merge, verify against a response shaped
     field-for-field to match the already-tested real handler, and say so
     explicitly, then re-verify with zero mocking after merge.
5. **The full existing test suite must stay green** before any wave is
   claimed done. Never weaken or delete an existing test to make a change
   pass.
6. **Ship via the full pipeline, every time:** commit → push → PR → all
   CI checks (~32) individually confirmed green (not just combined status)
   → squash merge → poll for the Cloudflare deploy to land → one final live
   Playwright/production check with zero mocking on anything that now
   exists in production. Not done until this loop closes.
7. **Update the capability registry every wave.** Amend the relevant
   `docs/capability-registry/domains/*.json` entry, prepend a dated
   session-log entry to `PROGRAM_BOARD.md` (Trigger / Method / Root cause /
   Fix / Verified / Commits / Validator / Tests / Risks-follow-ups), run
   `node scripts/registry/validate.mjs` and
   `node scripts/registry/generate-report.mjs`. This registry is the only
   durable memory across sessions.
8. **Regenerate before trusting.** The severity counts and per-capability
   table in §3 below are a snapshot as of this writing. Always run
   `node scripts/registry/generate-report.mjs` fresh at the start of a wave
   and read the *current* `PRODUCTION_READINESS_REPORT.md` — this document
   will not be kept in sync with it.
9. **State scope decisions out loud**, in both the chat response and the
   registry entry. A wave that turns out bigger than expected gets its
   overflow explicitly deferred and logged, not silently dropped or
   silently ballooned into an unreviewable PR.
10. **No fabricated data, no unearned abstraction, no dead code.** An
    honest empty state beats a plausible fake number, every time.
11. **Branch discipline:** after any squash-merge, the branch's own
    pre-squash commit is superseded — restart from `origin/main`
    (`git checkout -B <branch> origin/main`) or rebase
    (`git rebase --onto origin/main <old-base> <branch>`), confirm the diff
    against the new base is empty/expected, then
    `git push --force-with-lease`.
12. **One wave, one PR** (or a tightly-related fix-PR + docs-verification-
    addendum-PR pair, matching the pattern already used throughout
    `PROGRAM_BOARD.md`). Never combine unrelated capabilities into one PR —
    reviewability and bisectability both suffer, and this backlog is large
    enough that partial progress must stay safely mergeable at every step.

---

## 2. Ground truth sources — read these before touching code

- `docs/capability-registry/PROGRAM_BOARD.md` — session log, most recent
  first, the durable memory of what's already fixed and why.
- `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — **generated**,
  regenerate via `node scripts/registry/generate-report.mjs`, never
  hand-edit. The authoritative current severity/parity numbers.
- `docs/capability-registry/domains/*.json` — per-capability evidence:
  backend/frontend/RBAC/test-coverage status, `operational_status`,
  `notes` with full root-cause detail, `contradicts_doc` where an existing
  doc overclaimed something. **A capability's own `notes` field is more
  authoritative than the summary table for "is this actually still
  broken" — read the entry, don't stop at the table row.**
- `docs/ENGINEERING_STANDARDS.md` — CEAP/CIP/CORB/CAB architecture, §9's
  claim vocabulary, §11 Production Truth Law, §12 KPI Dashboard authority.
- `docs/ENTERPRISE_PARITY_MASTER_PROMPT.md` — the competitor-parity
  sub-initiative (org-RBAC pervasiveness, support ticketing, SSO
  self-service, API-key consolidation, billing/admin UI gaps).

---

## 3. Current backlog snapshot (regenerate before trusting — see §1.8)

As of this writing: **67 capabilities across 18 domains.** Backend 83.6%
complete, frontend 67.9%, parity (both exist) 62.7%, dynamic_browser-verified
customer journeys 0%. **Rollup: Critical 9 · High 15 · Medium 5 · Low 38.**
Verdict: **NOT READY** (computed — any P1 present or parity below 80% forces
this; see the report's own verdict-rule footnote).

**Three domains have never been audited at all** —
`compliance-store.json`, `mythos-godmode.json`, `threat-hunting-intel.json`
are empty stub files. Their real gap count is unknown, not zero. Run an
audit-only wave on each (same evidence discipline as every populated
domain: read the real handlers/frontend, don't assume) before treating the
67-capability count as the whole platform.

### 3.1 — Critical (P1, 9) — start here

| ID | Capability | Domain |
|---|---|---|
| CAP-DEVPORTAL-002 | Self-Service Automation API Keys | developer-portal-apikeys |
| CAP-DEVPORTAL-003 | Developer Portal (API Explorer/SDK/OpenAPI/Key Self-Serve) | developer-portal-apikeys |
| CAP-DEVPORTAL-004 | Growth/Plan API Key Provisioning (`sap_` keys — provisionable but cannot authenticate any live request; see the entry's own disclosed residual gap) | developer-portal-apikeys |
| CAP-IDN-001 | Login / Sign-in Entry Point | identity |
| CAP-IDN-002 | Sign-Up / Account Creation Entry Point | identity |
| CAP-IDN-003 | MFA Second-Factor Login Completion | identity |
| CAP-MSSP-001 | MSSP Partner Onboarding (Checkout / Free Trial → Portal Access) | mssp |
| CAP-CRM-007 | Conversion Trigger & Funnel Tracking (field-name mismatches vs. the real backend contract) | sales-crm |
| CAP-MKT-005 | Sentinel APEX Marketplace Mega-Dispatcher (Subscriptions, Entitlements, ROI Calculator) | sentinel-apex-marketplace |

Several of these (IDN-001/002/003, MSSP-001) were already substantially
fixed in prior waves — read each entry's `notes` and `verification.evidence`
before re-diagnosing; their remaining P1/PILOT-ONLY status typically means
"fixed, but not yet closed with a live production dynamic_browser pass,"
not "still broken." Confirm which before acting — don't assume either way.

### 3.2 — High (P2, 15) — backend exists, frontend missing or non-functional

| ID | Capability | Domain |
|---|---|---|
| CAP-ADMIN-004 | Admin Surfaces — Marketplace/Academy/Affiliate/CRM/Support still missing | administration |
| CAP-DASH-003 | Product & Growth Analytics (Funnel, Feature Adoption) | dashboard-personalization |
| CAP-MSSP-003 | Multi-Tenant Sub-Account Drill-Down (partial) | mssp |
| CAP-MSSP-004 | Delegated Admin Permissions (MSSP Staff Sub-Accounts) | mssp |
| CAP-NAV-001 | Server-Driven Navigation Engine (role/plan/feature-flag-based) | navigation |
| CAP-NOTIF-001 | Multi-Channel Notification Preferences & Delivery Log | notifications |
| CAP-NOTIF-003 | Outbound Webhooks (Developer + Organization) | notifications |
| CAP-ORG-001 | Organization Management (org-wide paginated scan history still unwired) | organizations |
| CAP-PROD-003 | Distributed Tracing / APM | production-readiness |
| CAP-CRM-004 | Customer Success Health Scoring (duplicate of an already-wired concept — reconcile, don't build a second UI) | sales-crm |
| CAP-CRM-006 | Security Assessment Booking (duplicate — real flow is elsewhere, see entry) | sales-crm |
| CAP-CRM-008 | Growth & Revenue Automation Suite (27 functions, zero frontend) | sales-crm |
| CAP-BILL-002 | Coupon Administration | commercial-billing |
| CAP-PORTAL-004 | Support Ticket System (mailto: links only — see `ENTERPRISE_PARITY_MASTER_PROMPT.md` Wave B1) | customer-portal |
| CAP-MKT-006 | Threat Intel Programmatic API (IOC/CVE/Actor/TTP/Risk) | sentinel-apex-marketplace |

### 3.3 — Medium (5) and Low (38)

Medium = P3 (nav missing despite working backend+frontend, 2 items) + P4
(RBAC not enforced, 3 items — includes `CAP-RBAC-002`, `CAP-MASOC-001`,
`CAP-ORG-002`). Low = P6 (no test coverage, 26 items) + P7 (docs missing
only, 12 items). Don't hand-enumerate these here — pull the live list from
the regenerated report. **P6 (no test coverage) is the highest
safety-margin, lowest-product-risk bucket in the whole backlog** — 26 items
where the fix is "add real tests to already-correct, already-shipped code,"
no design decision, no migration, no new UI. Good filler work between
larger waves, and good onboarding work for a session new to this codebase.

---

## 4. Prioritization logic

Severity (Critical → High → Medium → Low) is the default order, but weight
it against real customer-facing impact and effort/blast-radius, the same
judgment applied all session:

- A Critical item that's "mostly fixed, needs one live-verification pass"
  is a faster, safer win than a High item requiring a new schema + new UI.
  Do the cheap-and-real ones first within a severity band.
- A Low (P6, no-tests) item guarding a payment webhook or an auth boundary
  matters more than a P7 (docs-only) item on an internal tool, despite the
  "Low" label — read what the gap actually touches, don't sort mechanically.
- Duplicate-system findings (`CAP-CRM-004`, `CAP-CRM-006`, and others
  marked `backend.status: "duplicate"` in their JSON) need a **reconcile
  decision** (retire one, or merge) before building anything — building a
  second UI on top of an already-served concept compounds the duplication
  instead of fixing it. Flag these for an explicit decision rather than
  guessing which implementation is canonical.
- The 3 unaudited domains (§3, `compliance-store`/`mythos-godmode`/
  `threat-hunting-intel`) should get an audit-only wave early — you cannot
  correctly prioritize gaps you haven't measured yet.

---

## 5. Recommended wave sequencing

1. **Audit the 3 unpopulated domains** — cheap, fast, de-risks every
   downstream prioritization decision.
2. **Close the 9 Critical items**, starting with whichever are "mostly
   fixed, needs live-verification" per §3.1's note — fastest path to
   dropping the readiness verdict's forcing condition.
3. **Close the 15 High items**, grouping by domain where that avoids
   re-loading the same context (e.g., the three `sales-crm` duplicates
   together, once their reconcile decisions are made).
4. **Run `ENTERPRISE_PARITY_MASTER_PROMPT.md`'s Wave A** (admin test
   coverage, pervasive org-RBAC, orphaned API-key resolution) — it
   overlaps directly with several P2/P4 items above (`CAP-ADMIN-004`,
   `CAP-RBAC-002`, `CAP-DEVPORTAL-004`); don't fix these twice under two
   different initiative names.
5. **Sweep the P6 no-test-coverage bucket** in batches — high volume, low
   risk, good use of a session with less context budget for a big feature.
6. **Medium (P3 nav-discoverability, P4 remaining RBAC) and P7 (docs-only)**
   — opportunistic, lowest urgency.

---

## 6. Guardrails — do not

- Do not run the D1 schema migration workflow yourself. Prepare it; the
  repository owner applies it.
- Do not force-push over unmerged, non-superseded work. Confirm the diff
  is empty/expected before any `--force-with-lease`.
- Do not skip or bypass CI, and do not merge with fewer than all ~32
  checks individually confirmed green.
- Do not write "100% complete," "bug free," or "guaranteed" into any
  commit, PR, registry entry, or customer-facing page — see §0.
- Do not build a second UI or a second system on top of a capability
  already flagged `duplicate` — reconcile first.
- Do not claim a wave verified live until you've re-checked it against
  production, post-deploy, with zero mocking on anything that now exists
  there.
- Do not expand a wave's scope mid-flight without saying so explicitly in
  both the chat response and the registry entry.

---

## 7. How to start

Read `docs/capability-registry/PROGRAM_BOARD.md`'s latest entries and
regenerate `PRODUCTION_READINESS_REPORT.md` before writing any code, to
confirm the real current state matches (or has moved on from) §3's
snapshot. Then start with §5's step 1 (the 3 unaudited domains) or step 2
(the Critical-9 sweep) unless the user directs otherwise.
