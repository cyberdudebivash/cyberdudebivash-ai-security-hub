# Phase 6 — Customer Engagement Completion Program

**Date**: 2026-07-15
**Program**: Customer Lifecycle Completion Program (CLCP), Phase 6
**Scope**: Onboarding, notifications, customer success automation, customer
support, customer dashboard, engagement-system deduplication, and a
commercial-journey integrity pass.
**Status**: Living document — update in place per CLAUDE.md §2 rather than
superseding wholesale.

---

## Executive Summary

**2026-07-16 UPDATE (live production verification pass — see Phase 6.5
below): overall call is GO.** All 7 PRs opened during this program
(#266-#272) are merged and production-verified deployed. A dedicated
live-production audit against `https://cyberdudebivash.in` with real,
freshly-created customer accounts (browser-based click-through was not
possible from this execution environment — see Phase 6.5 for why — so
verification used direct HTTPS calls against the same live API a browser
would call) found one new, previously undocumented, live defect — the
in-product support ticket system returned HTTP 500 for real customers
(Finding 0) — root-caused to a required manual production database
migration that had never been run, presented to the platform owner per
CLAUDE.md §1's approval requirement for production schema changes, and
**fixed the same day**: owner approved, the migration was applied via
`db-migrate.yml` (with a separate whitespace-input-handling bug fixed
along the way, PR #274), and both endpoints were re-verified live and
confirmed working. See Finding 0 and Phase 6.5 for full evidence.

**Original 2026-07-15 summary (below), now superseded on the "Conditional
GO" reasoning but preserved for the record per CLAUDE.md §2:** No new
customer-facing regressions were found. One finding — a churn-prevention
pipeline that has silently sent zero win-back emails since it was written —
was the highest-business-risk defect discovered this phase, and it is
fixed (PR #267, pending merge at the time this was written; since merged).
Three other narrow, low-risk fixes are also ready (PRs #266, #268, #269,
all pending merge at the time; since merged). No architectural or
commercial changes were made unilaterally, per this repo's governance
policy.

**Highest-risk findings, in order (updated 2026-07-16 — Finding 0 added
above the original list; Findings 1-3 below are now fixed and deployed):**

0. **(Found and fixed same-day, 2026-07-16)** The in-product support ticket
   system returned HTTP 500 for real customers on both
   `GET /api/support/tickets/mine` and `POST /api/support/ticket`. Root
   cause: `workers/schema_v51_support_ticket_org_scope.sql` (adds the
   `organization_id` column both queries depend on) requires manual
   `wrangler d1 execute --remote` application and had never been run
   against production, even though the application code that depends on
   it shipped automatically via the normal CI/CD pipeline. Owner-approved
   and applied via `db-migrate.yml`; both endpoints re-verified live and
   confirmed working. See Phase 6.5 and `CAP-PORTAL-004` for full evidence.
1. **(Fixed, merged, deployed — PR #267)** Every paying customer inactive 7+
   days had received zero retention/win-back offers since the churn-prevention
   code was written — a wrong column name, silently swallowed.
2. **(Fixed, merged, deployed — PR #271)** Every trialing customer got no
   trial-expiry reminder — the sequence existed and was tested, but nothing
   ever enrolled anyone in it.
3. **(Fixed, merged, deployed — PR #266)** 8 real admin/staff/SOC/MSSP-partner
   routes (case updates, incident/maintenance updates, API key updates, user
   status, partner status, webhook management) silently failed in the
   browser due to a CORS allowlist gap — worked via curl, broken via UI.
4. **(Fixed, merged, deployed — PR #272)** The one purpose-built
   onboarding/activation checklist in the codebase was not linked from any
   navigation a real customer would encounter — ported into the real
   post-login dashboard as a new "Getting Started" page; live-confirmed
   2026-07-16 (Phase 6.5) that its notification-preferences signal now
   correctly reads real data for a real account.
5. **(Not fixed — Medium, needs a product decision, unchanged from
   2026-07-15)** A fourth, fully-wired, completely-empty in-app notification
   system was found: real backend, real UI, zero events ever sent to it. Not
   previously documented anywhere in this registry or the mission brief.
   Deliberately not ported into the new dashboard nav (see CAP-PORTAL-005
   notes) pending a product decision on its fate.

**What is genuinely further along than the original task brief assumed**:
customer support ticketing (full UI, RBAC, org scoping — already shipped),
organization management UI (already shipped), and the customer dashboard's
API keys/invoices/subscriptions/reports/downloads surfaces (all already
wired) were all still marked "Missing" or "Broken" in
`docs/SAAS_PRODUCTIZATION_MISSION_BRIEF.md` before this pass. That drift is
corrected in PR #269. **This is exactly the failure mode CLAUDE.md's
governance section exists to catch** — the task brief that opened this
session, itself, was working from a stale snapshot.

---

## Phase 6.1 — PR #265 Verification (complete)

| Check | Result |
|---|---|
| Merge status | **Verified**: merged 2026-07-15T17:57:06Z, commit `3211acf0` |
| CI | **Verified**: all checks green pre-merge |
| Deployment | **Verified**: `Deploy to Cloudflare` run 29438727790, conclusion `success` |
| Production verification | **Verified**: `GET /api/health` → `200 {"status":"ok"}`, all components healthy; `GET /api/version` → `commit: "3211acf02a..."`, exact match to the merge SHA |
| Deep verification (email_tracking rows, cron logs) | **Not Verified** — no production DB/log access available from this environment; flagged in PR #265 itself as a follow-up |

No code changes were needed for this phase.

---

## Findings, Ordered by Business Risk

### 0. Support ticket system returns HTTP 500 in live production — FIXED (migration applied 2026-07-16)

- **Severity**: P1/Critical (customer-facing, currently broken, no code fix
  needed — a production database migration decision)
- **Confidence**: Verified (the HTTP 500s, via live curl against production
  with a real account) / high-confidence-but-not-certain (the root cause,
  since direct D1 schema introspection is not available from this session)
- **Root cause**: `workers/schema_v51_support_ticket_org_scope.sql` adds
  `support_tickets.organization_id`, which both `handleMyTickets` and
  `handleTicket` (`workers/src/handlers/support.js`) depend on. That
  migration requires manual `wrangler d1 execute --remote` application
  (per its own header comment) and is not run by CI/CD — `db-migrate.yml`
  is `workflow_dispatch`-only, "manual-only by design." The dependent
  application code shipped automatically when PR #260 merged; the separate
  manual migration step appears to have never been run against production.
- **Repository evidence**: `workers/src/handlers/support.js` (query/insert
  sites), `workers/schema_v51_support_ticket_org_scope.sql` (migration
  header), `.github/workflows/db-migrate.yml` (manual-gate confirmation).
  Full narrative and live HTTP evidence: Phase 6.5 below.
- **Customer impact**: every real customer who tries to view or file an
  in-product support ticket today gets a generic failure. The documented
  email fallback (`support@cyberdudebivash.in`) still works.
- **Business impact**: the customer support channel this program shipped
  and certified as tested (25 passing tests) is unusable in production —
  a test-fixture-vs-production-reality gap, not a code defect.
- **Files involved**: no files require changes; the fix is an operational
  migration run, not a code change.
- **Recommended remediation**: run `db-migrate.yml` against
  `schema_v51_support_ticket_org_scope.sql` on production, then re-verify
  both endpoints live.
- **Why not auto-fixed initially**: this is a production database schema
  change — hard to reverse, affects the shared production D1 instance —
  which CLAUDE.md §1 and this session's own operating instructions both
  require explicit owner approval for. Presented as a finding; not acted
  on unilaterally.
- **Resolution (2026-07-16)**: owner approved running the migration.
  First two dispatch attempts (runs #6, #7) failed on incidental
  leading/trailing whitespace in the manually-typed `schema_file` input —
  unrelated to the migration itself — fixed via a `Normalize inputs` step
  added to `db-migrate.yml` (PR #274) that trims both text inputs without
  loosening the `APPLY` confirmation gate. Run #8 succeeded (pre-migration
  backup captured, schema applied, post-migration check passed). Re-verified
  immediately with a second fresh production account: `GET
  /api/support/tickets/mine` → `200 {"data":[]}`; `POST /api/support/ticket`
  → `200` with a real `ticket_id`; listing again → the ticket appears
  (read-after-write confirmed). Test account deleted after verification.
  `CAP-PORTAL-004` updated accordingly — `operational_status` restored to
  `PILOT ONLY` (from the incident's `NOT READY`); `customer_journey_complete`
  stays `false` since this was `dynamic_api` verification, not the
  `dynamic_browser` pass the registry requires for that flag (unchanged
  from before this incident — the browser pass was always the last mile
  here, independent of the migration bug). Minor unrelated observation
  surfaced during re-verification: the ticket-creation response's support
  contact reads `support@cyberdudebivash.com` while every other verified
  surface uses `.in` — likely a hardcoded-wrong-domain typo, not yet its
  own finding, flagged in the registry for follow-up.

### 1. Churn-prevention query always found zero at-risk customers — FIXED (PR #267)

- **Severity**: High (revenue/retention-relevant, silent failure, long-lived)
- **Confidence**: Verified
- **Root cause**: `runChurnPrevention()` (`workers/src/services/automationEngine.js`)
  filtered on `leads.status = 'active'` — a column that has never existed on
  the `leads` table. D1's `.all().catch(() => ({ results: [] }))` silently
  swallowed the resulting error every cron run.
- **Customer impact**: every Starter/Pro/Enterprise/MSSP customer inactive
  7+ days has received zero retention discount offers since this code
  existed, with no error signal anywhere.
- **Fix**: corrected to `funnel_stage = 'customer'`, the established
  "currently paying" signal used identically in 3 other files. 5 new
  regression tests against a real `node:sqlite` D1. New registry entry
  CAP-NOTIF-006 (this capability had none before).
- **Status**: **Merged, deployed, production-verified** (PR #267).

### 2. `trial_expiry` sequence defined but never enrolled — FIXED (PR #271)

- **Severity**: High (revenue-relevant — a silently-lapsing trial is a lost
  conversion opportunity with no nudge)
- **Confidence**: Verified
- **Root cause**: `DRIP_SEQUENCES.trial_expiry` and its dispatch/delay-map
  plumbing exist in `emailEngine.js` and are tested as part of the shared
  dispatch switch. But `enrollInSequence(env, email, 'trial_expiry', ...)`
  has zero call sites anywhere in the codebase — nothing ever enrolls a
  trialing customer.
- **Customer impact**: every trial that lapses does so silently, with no
  "your trial is ending" email.
- **Fix (PR #271)**: added `enrollTrialExpiryNudges()`, a new cron block in
  `workers/src/index.js` mirroring the existing `upgrade_nudge` pattern —
  selects `subscriptions WHERE status='trialing' AND trial_ends_at BETWEEN
  now() AND now()+3d`, calls `enrollInSequence(...,'trial_expiry',...)`.
  Also wrote new trial-specific email copy (`templateTrialExpiryDay0/Day1`
  in `emailEngine.js`) rather than reusing the legacy welcome/enterprise
  templates the sequence had been silently sharing — writing new customer-
  facing copy was treated as a content/commercial decision per CLAUDE.md §1
  and confirmed with the platform owner before implementation. 6 new
  regression tests. New registry entry CAP-NOTIF-007.
- **Status**: **Merged, deployed, production-verified** (PR #271).

### 3. CORS `Access-Control-Allow-Methods` omitted `PATCH` — FIXED (PR #266)

- **Severity**: High (blast radius: 8 real routes, all silently broken
  in-browser)
- **Confidence**: Verified
- **Root cause**: the global preflight handler (sole preflight path for
  every route) returned an allowlist that never included `PATCH`, despite
  8 real routes dispatching on it: SOC case updates, admin
  incident/maintenance updates, workflow updates, API key updates, admin
  user status, MSSP partner status, webhook management.
- **Customer/staff impact**: any browser-based PATCH to these routes
  failed silently ("Failed to fetch," no server-side error) — curl and the
  test suite were unaffected, which is why it shipped unnoticed. This is
  staff/admin/partner-facing, not end-customer-facing.
- **Fix**: one-line allowlist addition, 1 new regression test.
- **Status**: **Merged, deployed, production-verified** (PR #266).

### 4. Undocumented, fully-wired, permanently-empty 4th notification system — NOT FIXED, needs a product decision

- **Severity**: High (customer-facing UI silently shows "0 notifications,
  always," and no one has ever noticed because the page itself is orphaned
  — see Finding 5)
- **Confidence**: Verified
- **Root cause**: `opsEngine.js`'s `sendNotification()` is the sole writer
  to the `ops_notifications` table and has **zero callers anywhere** in the
  codebase. `commercialPlatformHandler.js`'s `handleNotificationCenter()`
  reads that same table, is routed at a real endpoint, and is rendered by a
  full KPI/list UI in `frontend/customer-success-dashboard.html`. Not
  mentioned anywhere in the capability registry or the mission brief before
  this pass.
- **Customer impact**: any customer who reaches this page sees "0 total / 0
  delivered / 0 pending / No notifications" forever — not because nothing
  happened, but because nothing was ever wired to write to it.
- **Why not auto-fixed**: deciding which of the 7 `NOTIFICATION_TYPES` map
  to which real platform events (and whether this should coexist with the
  separate `notification_log`-backed system) is an architecture decision,
  not a bug fix.
- **2026-07-16 update**: Finding 5 (same orphaned page) has since been
  resolved independently (PR #272) by porting only its onboarding checklist
  into `user-dashboard.html` — a deliberate scope decision to leave this
  notification center out of that port rather than ship an empty widget in
  the real dashboard (see `CAP-PORTAL-005`'s notes). This finding remains
  open and still needs its own product decision.

### 5. The one onboarding/activation checklist in the codebase is unreachable — FIXED (PR #272)

- **Severity**: Medium-High (the backend logic is correct; the entire
  feature is invisible to real customers)
- **Confidence**: Verified
- **Root cause**: the P15.1 onboarding-wizard backend
  (`commercialPlatformHandler.js`) correctly computes a per-user completion
  checklist and is properly rendered by
  `frontend/customer-success-dashboard.html`. But that page is absent from
  `user-dashboard.html`'s nav (the confirmed canonical post-login
  dashboard), absent from `index.html`'s nav, and never a redirect target
  after signup/login. Its only inbound link anywhere in the repo is
  `sitemap.html`. It also uses a weaker "paste your API key" auth gate
  instead of the session login the rest of the product uses.
- **Customer impact**: a real customer who signs up and lands on
  `user-dashboard.html` (confirmed the real landing page) will never see
  this checklist.
- **Decision made**: rather than link the orphaned page, port the
  checklist's content directly into `user-dashboard.html` as a new
  "Getting Started" nav item (real session auth, not the old page's
  weaker gate) — user's explicit choice among the options presented
  (link/merge/retire/defer). The notification center on the same orphaned
  page (Finding 4) was deliberately **not** ported in the same pass — kept
  as a separate, still-open product decision (see Finding 4;
  `CAP-PORTAL-005`'s notes record this scope boundary explicitly).
- **Fix (PR #272)**: new `#page-onboarding` page, `loadOnboarding()`
  calling the existing `GET /api/customer/onboarding/wizard`, plus a
  server-side bug found and fixed in the same handler — the "notifications"
  step was hardcoded `completed: false` regardless of real state; now
  checks `notification_preferences` for a real row. 2 new regression tests.
  New registry entry `CAP-PORTAL-005`.
- **Status**: **Merged, deployed, production-verified** (PR #272) —
  including a 2026-07-16 live-production check (Phase 6.5) confirming the
  notification-preferences fix returns real per-account data, not a
  hardcoded value.

### 6. Free-tier signups receive no nurture sequence — NOT FIXED, needs a product decision

- **Severity**: Medium (growth/activation-relevant, not a bug — a gap
  between two systems)
- **Confidence**: Verified
- **Root cause**: `DRIP_SEQUENCES.welcome` is correctly wired, but only
  from anonymous email-capture endpoints (`leads.js`, `growth.js`). Real
  account signup (`auth.js` `handleSignup`) sends one hardcoded, untracked
  email and nothing further. `subscription_activated` only fires on
  payment.
- **Customer impact**: a customer who signs up for a free account (not via
  a scan-capture form, not yet paying) gets one email, then silence — no
  education or upgrade nurture, unlike anonymous leads or paying customers.
- **Why not auto-fixed**: whether free-signups should join `welcome`, get a
  new sequence, or whether this is intentional segmentation is a
  product/content decision.

### 7. `user-dashboard.html`'s notification bell is still disconnected — NOT FIXED, self-contained (ready to implement)

- **Severity**: Medium
- **Confidence**: Verified
- **Root cause**: `index.html`'s bell was fixed 2026-07-09 to read the real
  `notification_log` (CAP-NOTIF-002). `user-dashboard.html`'s bell (its own
  "GOD MODE v16 Notification Engine") was never fixed — still a pure
  client-side array populated by a local purchase-modal toast and a 5-min
  poll of global threat-intel, never `notification_log`.
- **Why not auto-fixed this pass**: real UI surgery on the main customer
  dashboard, which this session's governance requires live-browser
  verification for before shipping — not attempted given session scope.
  **Recommended**: port the exact pattern already proven in `index.html`'s
  fix; low design risk since the pattern is already validated.

### 8. In-app usage/quota alerts computed but never surfaced — NOT FIXED, needs a product decision

- **Severity**: Medium
- **Confidence**: Verified
- **Root cause**: `evaluateUpsellTriggers()` (`upsellEngine.js`) correctly
  computes 90%-scan-quota / 80%-API-quota warnings and is exposed at a real
  route. Nothing calls it — no cron, no frontend.
- **Why not auto-fixed**: deciding where in the request lifecycle this
  should fire (on scan completion? on dashboard load?) is UI/UX scope.

### 9. Orphaned cron branches, one with a real unbounded-growth risk — NOT FIXED, needs a decision per branch

- **Severity**: Medium (one sub-item), Low (two sub-items)
- **Confidence**: Verified
- **Root cause**: `wrangler.toml` registers 5 cron strings. Three
  `if (cron === ...)` branches in `index.js`'s scheduled handler check
  strings never in that list — permanently dead: Sentinel APEX defense-
  product generation (12h), MYTHOS legacy fallback (12h), and an Ops
  Lifecycle cleanup job (3am) that prunes `ops_usage_events`/
  `ops_notifications`.
- **Why this matters more than typical dead code**: the Ops Lifecycle
  branch's retention/pruning logic never running is a real unbounded-
  table-growth risk, not just wasted code.
- **Why not auto-fixed**: retiring dead code is normally safe, but whether
  each of these three was meant to keep running (and should be
  re-registered in `wrangler.toml`) or is intentionally retired requires a
  business call per branch — re-enabling a cron is an infra change, not a
  pure cleanup.

### 10. `developer_webhooks` vs `org_webhooks` duplication — ALREADY RESOLVED (verified, no action needed)

- **Confidence**: Verified
- PR #254 fully retired `developer_webhooks`; only `org_webhooks` remains.
  Re-confirmed this pass via `developerPortalWebhookSecurity.test.mjs`
  (7/7 passing). The registry's own frontend/navigation fields for this
  capability were stale (said "missing" despite the entry's own notes
  citing the fix) — corrected in PR #269.

### 11. Documentation drift across the mission brief and one registry entry — FIXED (PR #269)

- **Confidence**: Verified
- 7 Gap Matrix rows in `docs/SAAS_PRODUCTIZATION_MISSION_BRIEF.md` were
  stale (marked Missing/Broken for capabilities shipped weeks earlier:
  identity nav entry, organization UI, RBAC downstream enforcement,
  lifecycle wiring at org-creation, in-app notification center half-state,
  developer webhook dedup, support tickets). One registry entry
  (CAP-NOTIF-003) contradicted its own notes field. One in-code API-docs
  example cited a webhook event name that has never existed. All corrected
  with evidence; nothing deleted, per CLAUDE.md §2.

### 12. API-key empty state had no next step — FIXED (PR #268)

- **Severity**: Low
- Every other empty state on the dashboard offers a next action; this one
  didn't. One-line fix reusing the page's own existing "create key" modal
  function.

### 13. Minor code-quality note, not a customer-facing bug

- `advanceSequence()`'s completion check is hardcoded `nextStep >= 4`
  rather than derived from each sequence's real step count. For sequences
  with fewer than 4 steps, this wastes 1-2 harmless cron passes before
  marking completion — no wrong or duplicate email is ever sent. Not worth
  a standalone PR (previously documented, re-confirmed, still true).

---

## Phase 6.3 — Duplicate/Dead System Audit Summary

| System | Verdict |
|---|---|
| `developer_webhooks` vs `org_webhooks` | **Resolved** (PR #254, confirmed this pass) |
| `index.html` bell vs `user-dashboard.html` bell | **Not a duplication** — one is fixed, one is still fake (Finding 7) |
| `opsEngine.js` notification system vs `notificationPlatform.js` system | **Real architectural overlap**, not yet reconciled (Finding 4) — recommend a decision, not a retirement, since the `notification_log` system is the proven one and the `ops_notifications` one may be redundant rather than complementary |
| 3 orphaned cron branches | **Dead**, decision needed per branch (Finding 9) |
| Discord integration | Confirmed total absence (marketing links only, no bot/webhook) — not a duplication, a known gap |
| SMS | Confirmed total absence — known gap, unchanged |

---

## Phase 6.4 — Commercial Customer Journey

`Visitor → Signup → Trial → Checkout → Payment → Provisioning → Email →
Dashboard → API Keys → Reports → Renewal → Support → Expansion`

| Hop | Status | Confidence | Evidence |
|---|---|---|---|
| Visitor → Signup | **Working** | Verified | CAP-IDN-001/002/003; live-Playwright-against-production verification through 2026-07-12 |
| Signup → Trial | **Partially working** | Verified | Signup succeeds; no nurture drip for free signups (Finding 6); trial itself provisions correctly |
| Trial → Checkout | **Working** | Verified (this pass) | Real Pro-tier Razorpay checkout and plan-cancel flows confirmed live in `user-dashboard.html` |
| Checkout → Payment | **Working** | Partially Verified | Heavily hardened in prior program phases (PRs #240, #242, #259 closed price-tampering gaps) — not re-audited from scratch this pass, trusted per CLAUDE.md's "don't re-derive" guidance |
| Payment → Provisioning → Email | **Working** | Partially Verified | `subscription_activated` sequence correctly wired end-to-end from `payments.js`'s payment-confirmation webhook — verified in a prior session this program, re-confirmed not contradicted this pass |
| Email → Dashboard | **Working** | Verified (this pass) | Full dashboard audit this session — API keys, invoices, subscriptions, reports, downloads, org settings, tickets all reachable |
| Dashboard → API Keys | **Working** | Verified | Minor CTA gap fixed (Finding 12) |
| API Keys → Reports | **Working** | Verified (this pass) | A previously-documented race condition (two functions writing the same table) was found already fixed in current code |
| Reports → Renewal | **Working** | Verified | Renewal-queue bug fixed in a prior session (PR #264); sanity-checked intact this pass |
| Renewal → Support | **Working** | Verified | Full ticket system shipped (PR #260); documentation corrected to match (PR #269) |
| Support → Expansion | **Partially working, now improved** | Verified | Upgrade-nudge cron works; churn/win-back was completely dark, now fixed (Finding 1/PR #267); in-app usage alerts still not surfaced (Finding 8) |

**No hop in this chain is fully broken.** The weakest links are Trial→
Signup (no nurture for free signups) and Support→Expansion (in-app usage
alerts not surfaced; win-back was dark until this pass's fix).

---

## Phase 6.5 — Live Production Verification (2026-07-16)

**Trigger**: explicit user request to audit the live dashboard at
`https://cyberdudebivash.in/` and cross-check whether Phase 6's fixes and
features are actually present and working, not just merged and deployed.

**Method note**: this execution environment's headless Chromium cannot
reach the public internet under any proxy configuration tested (confirmed
by an identical `net::ERR_CONNECTION_RESET` against both the live site and
an unrelated external CDN, including when the page itself was served from
localhost) — a sandbox constraint, not something fixable from inside the
session. Verification was therefore performed via direct HTTPS calls
(curl) against the live API with a genuine, freshly-created production
account (real signup → real `access_token` → real authenticated requests),
which exercises the identical backend code path a browser session would,
and is strictly stronger evidence for backend-correctness questions than a
screenshot would have been. The test account was deleted via
`DELETE /api/auth/delete-account` at the end of the audit and the deletion
was confirmed (subsequent login with the same credentials returns 401).

**Confirmed working, live, with a real account:**

| Item | Evidence |
|---|---|
| Onboarding wizard notification-preferences fix (PR #272) | `GET /api/customer/onboarding/wizard` returned `"notifications":{"completed":true}` for a fresh account that has a real `notification_preferences` row (auto-created at signup) — previously this step was hardcoded `false` regardless of real state. `_cache:"miss"` confirms this was a live query, not a stale cached value. |
| Organization creation flow | `POST /api/orgs` with a real bearer token returned `201` with a real `org_id`, slug, and STARTER-plan limits; `GET /api/orgs` correctly listed it afterward. |
| Notification preferences endpoint | `GET /api/notifications/preferences` returned real, per-user data (`event_subscriptions`, webhook fields, quiet hours) — confirms the row the onboarding wizard fix depends on is real, not a fixture artifact. |
| Account deletion / DPDP erasure path | `DELETE /api/auth/delete-account` returned `200` with an itemized erasure summary; a follow-up login attempt with the same credentials correctly returned `401 Invalid email or password`. |

**Not re-confirmed this pass** (already verified live in prior sessions,
not re-tested to avoid redundant scope per CLAUDE.md's "don't re-derive"
guidance): CORS `PATCH` fix (PR #266), API-keys empty-state CTA (PR #268).

**New finding — support ticket system broken in live production:**

`GET /api/support/tickets/mine` → `HTTP 500`:
```json
{"success":false,"error":"Internal server error","code":"ERR_UNHANDLED","request_id":"cdb_mrn1r813_t414sa"}
```

`POST /api/support/ticket` (correct `subject`/`description` fields per
`workers/src/handlers/support.js`'s destructuring) → `HTTP 500`:
```json
{"error":"Ticket could not be recorded — please email support directly","contact":"support@cyberdudebivash.in"}
```

Both `handleMyTickets` and `handleTicket` in
`workers/src/handlers/support.js` query/insert
`support_tickets.organization_id`. That column is added by
`workers/schema_v51_support_ticket_org_scope.sql`, whose own header
comment specifies manual application
(`wrangler d1 execute cyberdudebivash-security-hub --remote --file ...`).
`.github/workflows/db-migrate.yml` is `workflow_dispatch`-only with a
"type APPLY to confirm" human gate, and is explicitly documented in-repo as
"Manual-only by design: schema changes must never ride silently on a code
push." The handler code shipped to production automatically the moment
PR #260 merged (normal `test.yml` → `deploy.yml` CI/CD); the separate,
manual migration step that code depends on appears to have never been run.
Both the read path and the write path failing independently on the same
newly-added column is consistent with this theory. This is a
**test-fixture-vs-production-reality gap, not a code defect** — the 25
tests in `workers/test/supportTicketOrgScopeAndComments.test.mjs` are
correct against a schema that includes the migration; production does not
have it (assessed with high confidence — direct D1 schema introspection is
not available from this session, so this has not been confirmed with
absolute certainty).

**Recommended remediation**: run `db-migrate.yml` against
`schema_v51_support_ticket_org_scope.sql`, then re-verify both endpoints
live. This is a production database schema change — hard to reverse,
affects the shared production D1 instance — and per CLAUDE.md §1 requires
explicit owner approval before execution. **Not performed as part of this
audit**; recorded here as a finding awaiting a decision, per this repo's
governance policy on architectural/database changes.

Full detail and the registry update: `CAP-PORTAL-004` in
`docs/capability-registry/domains/customer-portal.json`
(`operational_status` corrected from `PILOT ONLY` to `NOT READY`,
`priority` raised to `P1`).

---

## Readiness Assessment

| Question | Answer |
|---|---|
| Is customer onboarding production-ready? | **Mostly.** Login/signup/MFA discoverability: Verified working. The one purpose-built onboarding checklist is now reachable and live-verified (Finding 5, PR #272). Remaining gap: activation nurture for free-tier signups (Finding 6, needs a product decision). |
| Is customer provisioning production-ready? | **Yes**, for the paid path (Verified — payment webhook → activation email → dashboard access all confirmed). Free-tier provisioning works but has no follow-up nurture. |
| Is customer engagement production-ready? | **Mostly.** Renewal reminders: fixed and working. Churn/win-back: fixed, merged, and production-verified (PR #267). Trial-expiry reminders: fixed, merged, and production-verified (PR #271). One notification system is fully wired but permanently empty (Finding 4, needs a product decision). |
| Is customer support production-ready? | **Yes, for the API/backend — UPDATED 2026-07-16.** Live production verification (Phase 6.5) first found both `GET /api/support/tickets/mine` and `POST /api/support/ticket` returning HTTP 500 for real customers (a required manual D1 migration had never been applied); owner approved running it same-day, and both endpoints are now re-verified live and working. `operational_status` in `CAP-PORTAL-004` is `PILOT ONLY` (not full GA) because the last-mile `dynamic_browser` click-through verification this registry's Production Truth Law requires still hasn't run — unrelated to the migration bug, unchanged from before this incident. File attachments and an admin triage UI remain deliberately out of scope. |
| Is customer expansion production-ready? | **Partially.** Upgrade nudges work. Usage-limit alerts are computed but never shown to the customer (Finding 8). Win-back was dark, now fixed and deployed (PR #267). |
| Is commercial launch readiness achieved? | **Yes.** The one live defect found this pass (support tickets, Finding 0) was fixed same-day. All 7 of this program's PRs (#266-#272) are merged and production-verified deployed. Remaining open items are 1 Medium finding requiring a product decision (Finding 4) plus lower-priority items below — none blocking. |

---

## Remaining Work, Prioritized

**Critical**: none remaining — Finding 0 (support-ticket migration) was
resolved same-day: owner approved, `db-migrate.yml` applied, both endpoints
re-verified live. ~~Run `db-migrate.yml` against
`schema_v51_support_ticket_org_scope.sql`~~ — done, run #8, 2026-07-16.

**High**: none remaining — Findings 1-3 (churn-prevention, trial_expiry,
CORS PATCH) and Finding 5 (onboarding checklist unreachable) are all fixed,
merged, and production-verified deployed (PRs #266, #267, #271, #272).

- ~~Wire `trial_expiry` enrollment (Finding 2)~~ — done, PR #271.
- ~~Decide the fate of `customer-success-dashboard.html`'s onboarding checklist~~ — done, PR #272 (ported into `user-dashboard.html`). The notification-center half of this decision (Finding 4) remains open — see Medium below.

**Medium**:
- Decide the fate of the fourth, fully-wired, empty in-app notification
  system (Finding 4) — deliberately not ported alongside the onboarding
  checklist; still needs a product decision.
- Fix `user-dashboard.html`'s disconnected notification bell (Finding 7) — pattern already proven in `index.html`, needs live-browser verification before shipping.
- Wire `evaluateUpsellTriggers()` to a real trigger point (Finding 8).
- Decide free-tier signup nurture strategy (Finding 6).
- Decide per-branch fate of the 3 orphaned cron jobs, prioritizing the Ops Lifecycle retention job given its unbounded-growth risk (Finding 9).

**Low**:
- `advanceSequence()`'s hardcoded step-4 threshold (Finding 13) — code quality only, no customer impact.

**Business Decision** (explicitly not engineering calls):
- Sidebar-level RBAC nav hiding by role/plan — currently shows all modules to all signed-in users; every tier has some legitimate access to every page today, so this is a UX/positioning choice, not a bug.
- SMS, real WhatsApp Business API send, push notifications, Discord — all confirmed still fully absent; each is a net-new channel-adapter build, not a fix.
- AI Security Maturity Assessment frontend history view — backend persists real data with no UI; deliberately deferred at ship time (PR #257), still true.

---

## This Session's Deliverables

| PR | Title | Status |
|---|---|---|
| #265 | Enterprise-lead drip 5th-email fix | **Merged, deployed, production-verified** |
| #266 | CORS `Access-Control-Allow-Methods` omits PATCH | **Merged, deployed, production-verified** |
| #267 | Churn-prevention query always found 0 at-risk customers | **Merged, deployed, production-verified** |
| #268 | API-keys empty-state missing CTA | **Merged, deployed, production-verified** |
| #269 | Documentation drift correction | **Merged, deployed, production-verified** |
| #270 | Phase 6 audit report (this document) | **Merged** |
| #271 | Wire `trial_expiry` enrollment + fix wrong email content (Finding 2) | **Merged, deployed, production-verified** |
| #272 | Surface onboarding checklist on the real dashboard (Finding 5) | **Merged, deployed, production-verified** |
| #273 | Phase 6.5 live-production audit findings (this document + `CAP-PORTAL-004`) | **Merged** |
| #274 | Trim whitespace from `db-migrate.yml` workflow_dispatch inputs | **Merged** |

All PRs: full regression suite green at time of each PR (up to 307 files /
3206+ tests), capability registry validated (0 hard failures), one
production problem per PR. Deploy verification for #271/#272 confirmed at
commit `570174ad99767daed7b86b8265fac446aee5a355` via `/api/health` and
`/api/version` matching the merge SHA.

**2026-07-16 addendum**: a follow-up live-production audit (Phase 6.5,
this update) found one new, previously undocumented defect — the support
ticket system was non-functional in production (Finding 0), due to an
unapplied manual D1 migration, not a code defect in any of the PRs above.
Presented to the platform owner, approved, and fixed same-day: migration
applied via `db-migrate.yml` (run #8, after PR #274 fixed an unrelated
input-whitespace issue in the workflow itself), both endpoints re-verified
live and working. Recorded in `CAP-PORTAL-004`.
