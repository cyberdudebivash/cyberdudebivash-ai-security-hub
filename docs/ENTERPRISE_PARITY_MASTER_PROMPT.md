# CyberDudeBivash AI Security Hub — Enterprise Parity Master Execution Prompt

**Purpose of this document:** a self-contained instruction set for Claude Code
(this session or a fresh one) to close the customer/user/admin account-
management gaps between this platform and CrowdStrike Falcon, SentinelOne
Singularity, Palo Alto Cortex/XSIAM, Recorded Future, Google Mandiant
Advantage, and ThreatConnect — so a global enterprise buyer evaluating this
platform against any of them finds no gap in how accounts, roles, billing,
support, and audit are handled. Paste this whole document as the opening
prompt of a session (it assumes zero prior conversation memory) or use it as
the standing brief for a sequence of sessions.

This is an execution brief, not a design doc to re-litigate. The gap list,
priority order, and acceptance criteria below were derived from (a) a
structured public-documentation comparison of the six named vendors across 8
account-management dimensions, and (b) a direct, evidence-based audit of this
platform's actual current code (not assumptions). Both are recorded in
`docs/capability-registry/PROGRAM_BOARD.md`'s 2026-07-11 "Competitor gap
analysis" session log entry — **read that entry first**, every time, before
starting a wave. It is the ground truth for what's already fixed vs. still
open; this document will not be kept in sync with it going forward.

---

## 1. Non-negotiable operating discipline

This platform's codebase has an established, proven execution discipline.
Every wave of this initiative follows it exactly — it is not optional
process overhead, it is why prior waves shipped correct, tested,
production-verified fixes instead of plausible-looking regressions.

1. **Read real code before writing any fix.** Trace the actual root cause
   (read the handler, the schema, the existing frontend caller if any) —
   never patch a symptom you haven't traced to its source. Several of the
   worst bugs found on this platform were "backend fully built, zero
   frontend caller" or "two parallel systems that drifted apart" — you will
   not find those by guessing.
2. **Fixes are additive and backward-compatible by default.** Don't touch
   working code paths outside the scope of the fix. Prefer extending an
   existing pattern in the file over inventing a new one.
3. **Schema migrations are prepared, never self-applied.** If a fix needs a
   new column/table, write the migration file (see
   `workers/schema_migration_*.sql` for the naming/format convention) and
   update `workers/schema_master.sql`'s canonical definition — but the
   actual `wrangler d1 execute --remote` against production only ever runs
   via the human-gated `.github/workflows/db-migrate.yml` (operator must
   type `APPLY`). You do not run it, and you do not wait for it to be run
   before shipping the code: ship code that reads/writes the new
   column/table defensively (try the richer query/write first, fall back
   cleanly if the schema element doesn't exist yet) so the feature is a
   verifiably safe no-op until the owner applies the migration, and
   self-activates the moment they do, with no second deploy required.
4. **Every fix gets real dynamic verification, not just static assertions.**
   - Backend logic: a real in-memory SQL engine (`node:sqlite`,
     `DatabaseSync`) executing the actual handler functions — see
     `workers/test/orgRbacIsolation.test.mjs` or `orgAuditLog.test.mjs` for
     the exact harness pattern. Static-parse tests (regex/substring checks
     against source text) are acceptable *in addition*, never as a
     replacement, for logic that can be exercised dynamically.
   - Frontend: a real headless-Chromium Playwright session (see
     `pw-helper.mjs` pattern in prior sessions' scratchpad — reconstruct it
     if not present: sandboxed Chromium has no direct network access, so
     requests are relayed through Node's own `fetch()`). Routes that
     already exist in production are hit for real. A genuinely new route
     that cannot exist in production until the PR merges is verified via a
     locally-mocked response shaped field-for-field to match the
     already-tested real handler's output — state this explicitly when you
     do it, and follow up with a zero-mocking live re-check after merge.
5. **The full existing test suite must stay green.** Run it before
   claiming any wave done. Do not weaken or delete an existing test to make
   your change pass.
6. **Ship via the full pipeline, every time:** commit → push → PR → wait
   for all CI checks (~32) individually confirmed green, not just the
   combined status → squash merge → poll for the Cloudflare deploy to land
   → one final live Playwright/production check with zero local-file or
   response mocking on anything that now exists in production. A fix is
   not "done" until this loop closes.
7. **Update the capability registry every wave.** Add or amend the relevant
   `docs/capability-registry/domains/*.json` entry (new capability ID if
   it's a genuinely new capability) and prepend a dated session-log entry to
   `PROGRAM_BOARD.md` following the existing entries' template (Trigger /
   Method / Root cause / Fix / Verified / Commits / Validator / Tests /
   Risks-follow-ups). Run `node scripts/registry/validate.mjs` and
   `node scripts/registry/generate-report.mjs` before committing. This
   registry is the only durable memory across sessions — a future session
   with no memory of this one will rely on it being accurate.
8. **State scope decisions out loud, in both the chat response and the
   registry entry.** If a wave's real finding turns out bigger than
   expected, say what you're deferring and why, rather than either quietly
   shrinking the fix or quietly ballooning the PR.
9. **No fabricated data, no unearned abstraction, no dead code.** If a
   metric/value isn't real, show an honest empty state, not a plausible
   fake number. Don't build a generic framework for a problem that has one
   concrete instance today.
10. **Branch discipline:** develop on the assigned branch. After any
    squash-merge, the branch's own pre-squash commit is superseded —
    restart it from `origin/main` (`git checkout -B <branch> origin/main`)
    or rebase (`git rebase --onto origin/main <old-base> <branch>`) as
    appropriate, confirm the diff against the new base is empty/expected
    before force-pushing, then `git push --force-with-lease`.

---

## 2. Ground truth sources — read these before touching code

- `docs/capability-registry/PROGRAM_BOARD.md` — session log, most recent
  first. The 2026-07-11 "Competitor gap analysis" entry has the full
  cross-vendor pattern summary and this initiative's original prioritization.
- `docs/capability-registry/domains/*.json` — per-capability evidence
  (backend status, frontend status, RBAC, test coverage, `operational_status`,
  `notes` with root-cause detail). Domains most relevant to this initiative:
  `organizations.json`, `rbac.json`, `sales-crm.json`,
  `developer-portal-apikeys.json`, `identity.json`, `administration.json`,
  `commercial-billing.json`, `customer-portal.json`, `mssp.json`.
- `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — auto-generated,
  never hand-edit; regenerate via `node scripts/registry/generate-report.mjs`.
- `docs/ENGINEERING_STANDARDS.md` — the CEAP/CIP/CORB/CAB architecture and
  §11 Production Truth Law, §12 KPI Dashboard authority.

Do not re-derive what these already establish. Do not start a wave without
re-reading the relevant domain file(s) — a "fixed" label in the registry
means fixed; don't rebuild it.

---

## 3. The gap backlog

Ranked by (a) how universal the violated pattern is across the six vendors,
(b) how customer/trust-visible the gap is to an enterprise buyer, (c)
effort/blast-radius. **Already closed** items are listed for context (don't
redo them); **open** items are this initiative's actual remaining work.

### 3.1 — CLOSED (context, do not redo)
| Gap | Status |
|---|---|
| No customer-facing audit log (org OWNER/ADMIN activity trail) | **Fixed** — CAP-ORG-002, PR #161/#162. Reused the existing `audit_log` table, zero new schema. |
| 2 of 4 duplicate API-key systems | **Fixed in prior waves** — CAP-DEVPORTAL-002/003 now delegate to the canonical `workers/src/auth/apiKeys.js`. |

### 3.2 — OPEN — Wave A (recommended next, no schema migration needed)
**A1. Pervasive org-RBAC enforcement.** `CAP-RBAC-002` / `CAP-ORG-001`.
Org roles (OWNER/ADMIN/ANALYST/MEMBER/VIEWER, `ROLE_PERMISSIONS` in
`workers/src/handlers/orgManagement.js`) are real and enforced *within org
management itself*, but nowhere else — a VIEWER has identical scan
execution, API-key, and billing access to an OWNER on every other page.
Every competitor enforces named roles pervasively, not scoped to one
settings page.
- **A proven, safe pattern for this already exists in this codebase** —
  `workers/src/handlers/aiSecurityCopilot.js`'s `ROLE_RANK` /
  org-role-RBAC layer: queries `org_members` directly, fails **open** (no
  restriction) when the caller has no org membership row, so it's additive
  and can't lock out existing non-org personal accounts. Extend that exact
  pattern to the highest-value gated actions first (scan execution,
  API-key creation/revocation, billing/subscription changes) rather than
  boiling the ocean in one PR — each action is its own bounded, testable,
  shippable increment.
- **Acceptance criteria:** a VIEWER-role org member attempting a
  write/mutating action they don't have permission for gets a clear 403
  from the backend (not just a hidden button — the enforcement must be
  server-side and independently testable), a personal (non-org) account's
  existing behavior is provably unaffected, and each increment ships with
  its own real in-memory-SQL test proving both the positive and negative
  case.

**A2. Zero test coverage on already-shipped admin/ops surfaces.**
`CAP-ADMIN-001`/`002`/`003`. 12+ entry points (incident/maintenance/
deployment tracking, SSO config CRUD, revenue BI) have real, working,
already-gated backend logic with **zero regression tests** — cheapest,
lowest-risk, highest-safety-margin item in this whole backlog. No product
decision needed, no new UI, just tests.
- **Acceptance criteria:** every `handleAdmin*`/ops-engine entry point
  listed in those three registry entries as untested gets a real
  dynamic test (auth-gate positive/negative, and the core logic where
  feasible without excessive mocking).

**A3. Resolve the one remaining orphaned API-key system.**
`CAP-DEVPORTAL-004`. The `sap_`-prefixed growth/plan key system is
provisionable but **cannot authenticate any live request** —
`workers/src/middleware/auth.js`'s `resolveApiKey` has no recognition
branch for the `sap_` prefix, and there's a KV hash/raw key mismatch even
if it did. The registry's own existing recommendation: **confirm with the
business owner whether this is still a live external integration before
investing further** — do not silently wire it up or silently delete it.
If confirmed dead: retire cleanly (remove the provisioning routes,
document the retirement in the registry). If confirmed live: wire the
`sap_` branch into `resolveApiKey`, fix the KV key mismatch, and add real
auth tests — same rigor as the canonical key system.

### 3.3 — OPEN — Wave B (needs a schema migration, prepare using the safe-no-op pattern from §1.3)
**B1. In-product support ticketing.** `CAP-PORTAL-004`. Currently
`mailto:` links only — the single most universally-expected-by-competitors
capability this platform is missing entirely (every one of the six vendors
has at minimum a support-portal case system). Needs:
- New tables (`support_tickets`, `support_ticket_messages` or similar —
  design the schema, don't assume the exact shape above).
- Customer-facing: submit a ticket, see status, add a reply, see staff
  responses, in `frontend/user-dashboard.html`.
- Staff-facing: list/triage/respond/close, in `frontend/admin-portal.html`
  or a new dedicated staff page if that one is already overloaded — check
  first.
- **Acceptance criteria:** a customer can open, track, and get a reply to a
  support ticket without leaving the product; a staff member can see and
  respond to all open tickets; both directions covered by real dynamic
  tests; the whole feature ships as a safe no-op if the migration hasn't
  run yet, and self-activates once it has.

**B2. Invoice/receipt self-service download.** `CAP-BILL-003`'s disclosed
follow-up. Customers currently only receive invoices by email attachment
— there's no in-portal download link, despite `billingEngine.js`'s
`createInvoice` already generating them. Check whether the generated
invoice is retrievable by ID from wherever it's currently stored before
assuming a new table/migration is needed — this may turn out to be a
wiring gap (backend artifact exists, no customer-facing retrieval route)
rather than a genuine schema gap, matching this session's most common bug
pattern. Trace before scoping the fix.

### 3.4 — OPEN — Wave C (needs a product/security decision before implementation)
**C1. Enterprise SSO self-service configuration.** `CAP-ADMIN-002`.
`workers/src/handlers/ssoAuth.js` has real SAML-config CRUD
(`handleSSOConfigGet/Upsert/Delete`), but it's gated `isOwner`-only (the
platform owner, not even an org's own admin) and has **zero UI anywhere**.
Every competitor has at minimum admin-configurable SAML for their own
tenant. Before implementing: this requires a deliberate decision on the
new authorization model (which org role(s) should be allowed to configure
their own org's SSO — likely OWNER-only, mirroring org deletion's bar) and
a security review of what loosening the current single-operator-only gate
implies. Do not implement without that decision made explicit in the
registry entry first.

**C2. MSSP delegated admin sub-accounts.** `CAP-MSSP-004`. No
implementation exists at all today (not a wiring gap — genuinely missing).
Lets an MSSP partner grant scoped access to their own staff instead of
every login sharing one partner-level credential. Lower priority than C1:
the research showed MSSP multi-tenancy itself is a differentiator, not a
baseline, for pure threat-intel platforms — and this platform's MSSP
tooling (CAP-MSSP-001/002/003) is already comparatively strong. Revisit
after Waves A and B.

### 3.5 — Smaller, disclosed, lower-priority items (sweep opportunistically)
- Coupon administration UI (`CAP-BILL-002`) — backend fully gated and
  tested, zero UI.
- Refund admin UI (disclosed in `CAP-BILL-003`'s notes) — refunds work via
  raw API calls only.
- Webhook/idempotency ledger admin viewer (also `CAP-BILL-003`'s notes).
- Org-wide paginated scan history browser (`CAP-ORG-001`'s disclosed gap —
  `handleOrgScans` exists, no full UI beyond the 5-most-recent dashboard
  summary).

---

## 4. Recommended sequencing

1. **Wave A2 first if you want the single lowest-risk starting point** —
   pure test-coverage additions to already-correct, already-gated code.
   Zero product ambiguity, zero migration dependency, builds momentum and
   re-familiarizes with the codebase's real auth/RBAC shape before A1 needs
   to extend it.
2. **Wave A1 next** — the highest-leverage, most competitively-material
   gap, and now proceeds with real, tested knowledge of the existing
   `ROLE_RANK`-style pattern to extend.
3. **Wave A3** — resolve the orphan (a single confirm-then-act decision,
   fast either way).
4. **Wave B1 (support ticketing)** — the biggest single greenfield build;
   do this once the RBAC layer from A1 exists, since ticket visibility
   likely wants to respect org roles too (don't build it twice).
5. **Wave B2 (invoices)** — likely small once traced.
6. **Wave C1 (SSO self-service)** — after an explicit decision is recorded.
7. **Wave C2 (MSSP delegation)** and **§3.5's smaller items** — opportunistic,
   lowest urgency.

Each wave is its own PR (or tightly-related pair of PRs, matching the
established "fix PR + docs-verification-addendum PR" pattern already used
throughout `PROGRAM_BOARD.md`). Do not combine multiple waves into one PR —
reviewability and bisectability both suffer, and this backlog is large
enough that partial progress must be safely mergeable at every step.

---

## 5. Definition of done — the global-parity bar

This initiative is complete when all of the following are independently,
dynamically, live-verified true — not just "code exists":

- [ ] A VIEWER-role org member cannot execute a write action an ADMIN/OWNER
      can, anywhere on the platform, and this is enforced server-side.
- [ ] Every admin/ops backend entry point in `administration.json` has real
      test coverage.
- [ ] The `sap_` API-key system either authenticates real requests
      end-to-end or has been cleanly retired — no third state.
- [ ] A customer can open, track, and receive a reply to a support ticket
      without leaving the product.
- [ ] A customer can download their own invoice/receipt from the billing
      portal without waiting on an email.
- [ ] An org's own OWNER can configure their organization's SSO connection
      (post-decision, per C1) without filing a request to platform staff.
- [ ] Staff have a working admin UI for coupons and refunds.
- [ ] Every item above has a capability-registry entry with
      `verification.method: dynamic_browser` or `dynamic_api` and a real,
      live, post-merge production check recorded — not `static` alone.

---

## 6. Guardrails — do not

- Do not run the D1 schema migration workflow yourself. Prepare it; the
  repository owner applies it.
- Do not force-push over unmerged, non-superseded work. Confirm the diff is
  empty/expected before any `--force-with-lease`.
- Do not skip or bypass CI checks, and do not merge with fewer than all
  ~32 checks individually confirmed green.
- Do not build speculative infrastructure for a problem this backlog
  doesn't actually name — stay inside §3's scope; log genuinely new
  findings as their own disclosed follow-up rather than silently expanding
  the current wave.
- Do not claim a wave verified live until you have re-checked it against
  production, post-deploy, with zero mocking on anything that now exists
  there.
- Do not publish or commit anything containing secrets, tokens, or
  customer PII surfaced while tracing these flows.

---

## 7. How to start

Open with Wave A2 (test coverage) or A1 (pervasive RBAC) per §4's
reasoning, unless the user directs otherwise. Before writing any code:
read `docs/capability-registry/PROGRAM_BOARD.md`'s latest entries and the
specific domain JSON file(s) for the wave you're starting, to confirm
nothing has changed since this document was written and that you're
building on the real current state, not a stale summary.
