# Capability Registry — Program Board

**Status:** Living doc, updated at the end of every execution wave (see
`EXECUTION_PROCEDURE.md`). Tracks *structural completion of the registry
population effort itself* — how much of the platform has been catalogued,
not how well the platform serves customers. It is not a customer-outcome
measure and does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only outcome
scoreboard. Read this + `EXECUTION_PROCEDURE.md` before starting any
registry-population session.

## Current status (2026-07-09, CAP-ADMIN-004 fix — Staff Admin Console: Users + Organizations oversight, 4th and last of the enterprise-readiness program)

| Metric | Value | Source |
|---|---|---|
| Domain files | 21 | `docs/capability-registry/domains/*.json` |
| Domains populated | 17 | see list below |
| Domains empty (stubs) | 4 | see Remaining Work Register |
| Capabilities registered | 56 | `node scripts/registry/validate.mjs` |
| Validator | 0 failures, 0 warnings | `node scripts/registry/validate.mjs`, run 2026-07-09 |
| Worker test suite | 187 files / 2002 tests passing | `npx vitest run`, run 2026-07-09 (includes 35 new tests for CAP-ADMIN-004: 20 backend RBAC/business-logic, 15 frontend route/permission/injection-safety contract) |
| Production readiness verdict | **NOT READY** (computed) | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-09 |
| Backend / Frontend / Parity | 75.9% / 47.3% / 41.1% | `PRODUCTION_READINESS_REPORT.md` (up from 75% / 46.4% / 41.1% before this fix — CAP-ADMIN-004 backend+frontend status: missing → partial) |
| Customer journeys browser-verified | 0% | `PRODUCTION_READINESS_REPORT.md` — no `dynamic_browser` verification has been performed yet on any entry (this pass used a local headless-Chromium session with mocked API responses against the changed file, not a `dynamic_browser` pass against production) |
| Gaps by severity | Critical 16 · High 16 · Medium 4 · Low 20 | `PRODUCTION_READINESS_REPORT.md` — unchanged this pass: CAP-ADMIN-004 stays P2 (still `PILOT ONLY`, not GA — Marketplace/Academy/Affiliate/CRM/Support admin surfaces, organization suspension (needs a schema migration), and a production `dynamic_browser` pass all remain); see remediation sections below |

Full structural breakdown (per-domain tables, gap definitions): regenerate
and read `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — never
hand-copy its numbers here beyond the summary above, to avoid two sources of
truth drifting apart.

**Domains populated (17):** academy, administration, affiliate-partner,
commercial-billing, customer-portal, dashboard-personalization,
developer-portal-apikeys, identity, masoc, mssp, navigation, notifications,
organizations, production-readiness, rbac, sales-crm,
sentinel-apex-marketplace.

## ✅ Critical finding remediated (was open, see history below)

**CAP-IDN-002 / CAP-IDN-003** (`docs/capability-registry/domains/identity.json`):
**FIXED 2026-07-09**. Live Microsoft customer escalation: a prospective
customer with no existing credentials clicking "No account? Get started
free" on the login overlay (`frontend/user-dashboard.html`) was sent to
`href="/"` — the homepage — with **no signup form anywhere on the site**.
`POST /api/auth/signup` (`handleSignup`) was already a complete,
production-grade implementation (password hashing, duplicate-email check,
rollback-on-partial-failure, welcome email, auto-provisioned first API
key); zero frontend code anywhere called it (exhaustive grep, 0 matches).
Fixed by adding a real `#signup-view` to the existing login overlay and a
`doSignup()` mirroring `doLogin()`'s exact pattern — no backend changes.
While tracing `doLogin()` to build this, also found and fixed **CAP-IDN-003**:
`doLogin()` never checked the backend's `mfa_required` response, so any
customer with 2FA enabled silently failed to complete login (fell through
to the success path with an `undefined` token, then got bounced back to
the login screen with no explanation) — `POST /api/auth/mfa/authenticate`
already existed and was already tested, nothing in the frontend ever called
it. Fixed with an `#mfa-view` + `doMfaVerify()`, same pattern. Both fixes
are purely additive — zero changes to any backend handler, zero changes to
the existing login/forgot/reset views. Live Playwright verification: full
signup happy-path and duplicate-email error-path, MFA-required login
routing to the code-entry view with no token stored mid-challenge, plain
non-MFA login proven unaffected, forgot-password view-switching proven
unaffected. axe-core scan found and fixed one real new WCAG issue
(`link-in-text-block` on the new "Sign in" link — added
`text-decoration:underline`, applied symmetrically to the pre-existing
"Get started free" link too); all other flagged violations are a
pre-existing, site-wide `--muted` color-contrast issue confirmed identical
on the untouched `login-view`/`forgot-view` baseline (out of scope for this
fix — flagged as a follow-up in the registry entry's `notes`). Regression
coverage: `workers/test/userDashboardSignupAndMfa.test.mjs` (13 tests).
Full suite green: 181 files / 1916 tests.

**CAP-IDN-001** (`docs/capability-registry/domains/identity.json`): **FIXED
2026-07-09**. The homepage's only "Sign In" surface was a dead-end modal
(button just closed itself, went nowhere); the real, working login form
existed but was reachable only via a small dim footer link, not primary
navigation — confirmed still true live immediately before the fix. Extended
the existing, already-proven `cdbApplyGates()` pattern (which already
injected a "Dashboard" link for authenticated visitors) with the symmetric
"not authenticated" branch: a real "Sign In" link now appears in both
desktop nav and the mobile drawer for logged-out visitors, pointing at
`frontend/user-dashboard.html`'s login overlay. The dead-end modal's button
now navigates there too, with a separate "Cancel" preserving the original
dismiss behavior. Purely additive — the existing authenticated-user
Dashboard link and in-page `#dashboard` section were left untouched, and a
Playwright session confirmed the Sign In link correctly disappears (no
stale UI) after a simulated login while the Dashboard link correctly
appears, so nothing already working regressed. Regression coverage:
`workers/test/homepageSignInPath.test.mjs` (3 tests). Full suite green: 180
files / 1902 tests.

**CAP-MASOC-001** (`docs/capability-registry/domains/masoc.json`): **FIXED
2026-07-08**, as its own dedicated change per this board's prior
recommendation (own commit, own regression test). `/api/agents/run`,
`/api/agents/stream`, and `/api/agents/dispatch/:id` now gate on
`isRealUser(authCtx)` before running — the same established pattern used at
30+ other routes in `workers/src/index.js` — closing the path that let
unauthenticated requests invoke compute-expensive parallel AI-agent
orchestration behind only a 5-req/min KV rate limit. `/api/agents/status`
was deliberately left open (read-only, no compute cost, embedded
unauthenticated in the public SOC dashboard widget). Regression coverage:
`workers/test/authGateRealUser.test.mjs`. Full suite green: 177 files / 1862
tests. See the registry entry's `verification.evidence` for full detail.

A second, lower-severity finding on the same capability is now **also
FIXED** (2026-07-08, separate commit): `handleAgentsStream`'s SSE response
hand-rolled its own CORS check narrower than the real 6-origin
`PROD_ORIGINS` allowlist, silently breaking SSE streaming for 3 of 6 real
production origins (`cyberdudebivash.pages.dev`, `tools.cyberdudebivash.com`,
`intel.cyberdudebivash.com`) while the JSON/status routes on the same
capability worked fine. Now uses the shared `corsHeaders()` from
`workers/src/middleware/cors.js`, same pattern as every other route.
Regression coverage: `workers/test/multiAgentSOC.test.mjs`'s new
`handleAgentsStream() — SSE CORS` block. Full suite green: 177 files / 1867
tests.

One low-severity finding remains unfixed on this capability (out of scope
for both fixes above): a frontend default-selection bug in
`frontend/soc-agents.html` that silently duplicates one agent's AI call
every run — detailed in the registry entry's `notes` field. Not a security
gate.

## ✅ Wave 2 critical findings remediated (2026-07-09)

**Developer Portal / API Keys domain** (`docs/capability-registry/domains/developer-portal-apikeys.json`):
all three findings surfaced by Wave 2 are **FIXED**, each as its own
dedicated change with real regression tests (`workers/test/devPortalApiKeyFixes.test.mjs`,
`workers/test/apiKeyHashing.test.mjs`), same treatment as CAP-MASOC-001 above:

- **CAP-DEVPORTAL-002** (Self-Service Automation API Keys,
  `workers/src/handlers/enterpriseAutomation.js`): the parameter-ordering
  bug is corrected (`createApiKey(D, userId(authCtx), userTier(authCtx), label)`),
  a per-tier key limit now matches the canonical route, list now returns
  `count`/`max_keys` (previously undefined), and a new `handleRotateSelfKey`
  closes the missing rotate route (previously a guaranteed 404).
- **CAP-DEVPORTAL-003** (Developer Portal key endpoints,
  `workers/src/handlers/developerPortal.js`): the four broken local
  reimplementations were deleted and the routes now delegate to the
  canonical `workers/src/handlers/apikeys.js` handlers, gated on
  `isRealUser(authCtx)` (previously no auth at all). Also fixed in the same
  pass: 18 occurrences of a literal unfilled placeholder domain
  (`your-worker.workers.dev`) across every SDK generator and the OpenAPI
  spec's own declared server URL.
- **CAP-DEVPORTAL-004** (Growth/Plan API Key Provisioning,
  `workers/src/services/apiRevenueEngine.js`, `workers/src/handlers/growth.js`):
  the INSERT now supplies every real, required column and replaces the
  invalid `ON CONFLICT(email)` with an explicit select-then-upsert; the
  companion identity-escalation gap (any caller could mint an
  arbitrary-tier key for any email) is closed — the tier is now taken only
  from a lead's own server-recorded, webhook-verified plan, never client
  input. **Residual gap, not fixed here:** `sap_`-prefixed keys still cannot
  authenticate anywhere on the platform — `workers/src/middleware/auth.js`'s
  request-time key resolver has no recognition path for this prefix at all,
  a deeper issue outside the original finding's scope and requiring changes
  to the platform's core auth resolver. See the registry entry's `notes`
  for the full writeup; `operational_status` for this one entry stays
  `BLOCKED` until that's addressed as its own reviewed follow-up.

CAP-DEVPORTAL-001 (the canonical, correctly-implemented API Key Management
system) was the consolidation target used for -002 and -003, per this
board's prior recommendation.

## Remaining Work Register

4 domains are still empty stubs (`[]`):

| Domain | File | Status |
|---|---|---|
| Threat Hunting / Intel | `threat-hunting-intel.json` | Not started |
| MYTHOS / God Mode | `mythos-godmode.json` | Not started |
| Security Scanners | `security-scanners.json` | Not started |
| Compliance Store | `compliance-store.json` | Not started |

## Proposed wave plan

- **Wave 2 — Developer Portal / API Keys.** ✅ DONE (2026-07-08) — see
  session log above; its 3 findings are now also fixed (see remediation
  section above).
- **Wave 3 — Threat Hunting/Intel + Security Scanners.** Two domains,
  grouped only if the next session has room to spare after one — otherwise
  run them as separate waves.
- **Wave 4 — MYTHOS/God Mode + Compliance Store.**
- **CAP-DEVPORTAL-002/003/004 fixes.** ✅ DONE (2026-07-09) — see remediation
  section above. Not registry waves; normal CAB-reviewed product fixes, same
  treatment as the MASOC auth-gate fix was. Can run before, after, or
  between the domain waves above — sequencing is a business call, not a
  registry-population
  dependency.

## Session log (most recent first)

### 2026-07-09 — Fix sprint: CAP-ADMIN-004 (Staff Admin Console: Users + Organizations oversight), 4th and last of the 4-initiative enterprise-readiness program

- **Trigger:** direct continuation of the 4-initiative program. This is the
  most security-sensitive of the four — a new backend surface granting staff
  destructive/PII-visible power over customer accounts — deliberately
  sequenced last, after re-confirming the codebase's RBAC/audit patterns
  across three lower-risk builds first (CAP-RBAC-002, CAP-ORG-001,
  CAP-MSSP-003).
- **Recovery note:** the prior session's implementation of this exact item
  was in progress (backend handler, RBAC keys, routes, and a partial
  `admin-portal.html` edit) when a usage-limit cutoff ended that session
  mid-work. None of it was ever committed — confirmed directly (`git log`,
  `grep` for the handler filename, and the capability registry, which still
  showed `CAP-ADMIN-004` as `"status": "missing"` with zero handlers). Per
  `EXECUTION_PROCEDURE.md`'s own rule ("if it isn't in git, it didn't
  happen, no matter how confidently it was described"), this was rebuilt
  from scratch against the current tree rather than assumed to exist.
- **Scope decision:** `CAP-ADMIN-004` as originally registered spans 7
  areas (Users, Organizations, Marketplace, Academy, Affiliate, CRM,
  Support). Only Users and Organizations map to the customer's actual
  "user lifecycle" ask; the other 5 remain explicitly out of scope and the
  registry entry still reflects them as missing.
- **Root cause / design basis, confirmed by direct code read:**
  `users.status` already exists in schema (`active|suspended|unverified`)
  **and** is already fully enforced end-to-end — `handlers/auth.js`'s
  `handleLogin` already rejects any non-`'active'` user with 403 "Account
  suspended" — so "disable a customer account" only needed a control plane
  wired onto enforcement that was already live, the same "backend built, no
  door" bug class as the rest of this program, just inverted. By contrast,
  `organizations` has no `status`/`suspended` column (confirmed against
  `workers/schema_master.sql`), so org suspension is genuinely not
  representable without a schema migration — not built, and disclosed
  rather than invented.
- **Fix (backend):** new `workers/src/handlers/staffUserOrgAdmin.js` —
  `handleListUsers`/`handleGetUserAdmin`/`handleUpdateUserStatus` (search,
  view, suspend/reactivate) and `handleListOrgsAdmin`/`handleGetOrgAdmin`
  (view-only org oversight, with member list). Two new `auth/rbac.js`
  permission keys, matching the file's existing least-privilege pattern:
  `admin:users:manage` (Super Admin only — PII + account mutation) and
  `admin:orgs:read` (Platform Admin — view-only, lower bar). Suspending a
  user both flips `users.status` and revokes every outstanding refresh
  token via the existing `auth/jwt.js` `revokeAllUserTokens` (the same
  helper "log out everywhere" and password-change already use) — otherwise
  a suspension would only take effect on the session's natural expiry, not
  immediately. Routes registered in `index.js` immediately after the
  existing `/api/admin/roles*` block, matching its exact dynamic-import
  style.
- **Fix (frontend):** two new sections in the existing staff console
  `frontend/admin-portal.html` (no new page) — "Customer Accounts" and
  "Organization Oversight" — plus two detail modals, introducing this
  file's first modal system (it had none; modelled on the sibling
  `partner-portal.html` convention). Both sections gracefully degrade to a
  restricted-access message on 403, mirroring the existing
  `loadRoles()`/`renderGrantForm()` pattern exactly. While in the file,
  fixed a real **pre-existing unescaped-innerHTML-injection** bug in
  `loadRoles()` (raw `${r.email}`/`${r.role}`/`${r.granted_by}`/
  `${r.granted_at}` spliced directly into table rows, plus an inline
  `onclick` built by partially-escaping a value into a single-quoted JS
  string embedded in an HTML attribute — safe from neither an HTML
  injection nor an attribute-breakout with a crafted role/email). Fixed by
  adding an `esc()` helper (matching `partner-portal.html`'s DOM-based
  pattern) and switching the revoke button to `data-*` attributes read via
  `this.dataset`, which need only ordinary HTML-attribute escaping instead
  of the harder double-context (JS-string-inside-HTML-attribute) escaping
  the original code never did correctly.
- **Verification:** full backend suite green before AND after the frontend
  work (zero regressions at each step). Live headless-Chromium Playwright
  session against a local static server with mocked `/api/admin/*`
  responses — a SUPERADMIN session (search, view, suspend, reactivate,
  org drill-down — 21/21 checks) and a plain ADMIN session (Users
  correctly shows the Super-Admin-only restricted state; Organizations
  still works at its lower permission bar) — zero uncaught JS exceptions
  in either. axe-core scan on both new sections and both new modals found
  one real new issue — `scrollable-region-focusable` on the two modal
  member/org tables, which genuinely overflow inside the narrower modal
  box unlike the full-width page tables — fixed with `tabindex="0"` +
  `aria-label`. Remaining violations (`color-contrast`,
  `landmark-one-main`, `region`, `select-name`) confirmed pre-existing on
  untouched parts of the same page (verified each traces to a class or
  structural pattern — `--text-dim`, `.data-table th`, missing `<main>` —
  that already existed before this change), not introduced by this fix.
- **Tests:** `workers/test/staffUserOrgAdmin.test.mjs` (20, backend — RBAC
  gating per permission tier including the ADMIN-vs-SUPERADMIN boundary,
  search, suspend/reactivate incl. refresh-token revocation and audit-log
  write, unchanged-status no-op, org member listing) and
  `workers/test/adminPortalStaffOversightContract.test.mjs` (15, frontend —
  route/permission contract against the real backend, plus a named
  regression guard locking in the `loadRoles()` injection fix and
  `esc()`-wrapping on every new render path so it can't silently regress).
  Full suite green: 187 files / 2002 tests.
- **Registry:** `administration.json`'s `CAP-ADMIN-004` updated in place
  (not a new ID, matching the CAP-ORG-001/CAP-MSSP-003 precedent) —
  backend/frontend `missing` → `partial`, `navigation.discoverable` →
  `true`, `rbac.enforced` → `true`, `operational_status` `NOT READY` →
  `PILOT ONLY`. `verification.method` recorded as `static` (not
  `dynamic_browser`) to match the CAP-ORG-001 precedent — that field is
  reserved for a live-production pass, not a local mocked-route Playwright
  session, even though a real browser was used. Validator: 56 IDs, 0
  failures, 0 warnings.
- **Also fixed this session, before this item:** CI on `main` was red
  after the CAP-ORG-001/CAP-MSSP-003 merge (PR #112) — Secret Scan,
  Test & Quality Gate, and CI — Lint & Validate all showed failures.
  Root-caused from GitHub Actions job timestamps (not assumed): 12 jobs
  across those 3 workflows never got a runner for ~28 minutes then were
  all cancelled within the same few seconds — a runner-concurrency-pool
  starvation event, not a code regression (every job that *did* get a
  runner passed cleanly). Fixed the one real, permanent gap it surfaced —
  `.github/workflows/gitleaks.yml` was the only CI-adjacent workflow with
  no `concurrency` group, unlike every sibling workflow — in PR #113.
  Could not trigger a re-run of the stuck runs directly (GitHub API
  returned 403, insufficient Actions-write permission on this session's
  GitHub App) — flagged for the repo owner to re-run manually.
- **Next:** none remaining in this 4-initiative program. Follow-on work
  disclosed but explicitly out of scope this pass: Marketplace/Academy/
  Affiliate/CRM/Support staff admin surfaces (the other 5 areas of
  `CAP-ADMIN-004`), organization suspension (needs an `organizations`
  schema migration), delegated/scoped MSSP staff admin, in-product support
  tickets, and a production `dynamic_browser` verification pass across
  every capability in the registry.

### 2026-07-09 — Fix sprint: CAP-MSSP-003 (MSSP per-client drill-down + partner-session auth-gate fix), 3rd of a 4-initiative enterprise-readiness program

- **Trigger:** continuation of the 4-initiative program. Research for this
  item had already been done in parallel during the CAP-RBAC-002 wave and
  surfaced a blocking finding that changed the shape of this fix before any
  code was written.
- **Root cause, confirmed by direct code read (not assumed from the research
  pass):** two layers. (1) `frontend/partner-portal.html`'s client list threw
  away `c.id`/`c.org_slug` after fetching them — no stable key to drill into
  even with a UI. (2) The real blocker: `workers/src/handlers/
  msspTenantPlatform.js`'s `requireMSSPAdmin()`/`partnerScope()` never
  recognized a real MSSP partner session. `resolvePartnerSession()`
  (`workers/src/auth/middleware.js`) resolves a magic-link partner login to
  `{ partnerId, userId: null, user_id: null, tier: 'RESELLER'|..., role:
  'partner' }` — `requireMSSPAdmin()` only checked `isAdmin` and
  `tier==='MSSP'` (a JWT/API-key user whose own subscription happens to be
  literally MSSP-tier, a *different* identity), so every one of the 18
  handlers in this file 403'd for every real partner. Confirmed the sibling
  `workers/src/handlers/msspWorkspace.js` (which backs the 2 already-wired
  handlers, `GET`/`POST /api/mssp/customers`) was already fixed for exactly
  this case, with its own explanatory comment dated 2026-07-06 — this file
  just never received the same fix. Building a frontend against the
  documented contract, as originally planned, would have shipped a feature
  that silently failed for every real customer in production.
- **Fix (backend, done first):** mirrored the identical, already-proven-safe
  pattern from `msspWorkspace.js` into `msspTenantPlatform.js`:
  `requireMSSPAdmin()` now also admits `authCtx?.role === 'partner'`;
  `partnerScope()` now checks `authCtx?.partnerId` first, falling back to
  `userId`/`user_id` for the legacy JWT-tier-MSSP identity. Zero handler
  bodies changed — both functions are called by all 18 handlers, so this one
  surgical, 2-function change fixes every one of them at once. Verified this
  doesn't weaken anything: anonymous and plain-authenticated-non-partner
  callers are still 403'd; a spoofed `userId` cannot override the
  server-derived `partnerId`; the legacy `tier:'MSSP'` path is unaffected.
- **Fix (frontend):** client rows in `frontend/partner-portal.html` are now
  clickable, opening a drill-down view with 4 tabs — Overview (dashboard
  stats + labels, read-only), Sub-Tenants (list + create), API Keys (list +
  generate with a one-time plaintext reveal + revoke), Billing & Usage
  (30-day usage stats + billing-period history) — wiring 8 of the remaining
  16 handlers. Introduced a lightweight tab-bar and modal system (this file
  had neither), reusing its existing card/stat-box/badge/table CSS exactly.
  **Deliberately NOT wired**, disclosed rather than hidden: Notification
  Preferences (a 5-channel × 12-event settings matrix) and Ticket Routing
  Rules (confirmed **partner-wide, not customer-scoped** — nesting it under
  one client's drill-down would mislead a partner into thinking a rule only
  applies there; needs a product decision on where it belongs before it's
  built at all), label add/remove, and the parent/child hierarchy tree view
  beyond the flat sub-tenant list already shown.
- **Verification:** inline `<script>` syntax check clean. Real
  headless-Chromium Playwright session, mocking the full backend contract —
  **17/17 checks**: dashboard → client list → drill-down → all 4 tabs →
  create a sub-tenant → generate an API key with the plaintext shown exactly
  once → revoke a key → back to dashboard. Zero uncaught JS exceptions.
  axe-core scan: zero new violations (the one flagged violation is on the
  pre-existing, unmodified dashboard shell, present before navigating to any
  new view — out of scope, same as the pattern documented on CAP-IDN-002/
  CAP-RBAC-002/CAP-ORG-001).
- **Tests:** `workers/test/msspPartnerSessionTenantPlatform.test.mjs` (new,
  12 tests, real in-memory SQLite, same convention as the existing
  `deadAdminChecksRestored.test.mjs`) — proves the real partner-session
  identity (shaped exactly like the real middleware's output, not a
  simplified stand-in) can now reach its own data, that cross-partner
  isolation still holds for it, and that the legacy identity is unaffected.
  `workers/test/partnerPortalClientDrilldown.test.mjs` (new, 11 tests,
  frontend, cross-checks against `index.js` and `msspTenantPlatform.js`
  directly). Full suite green: 185 files / 1967 tests (184/1956 after the
  backend-only fix, 185/1967 after the frontend — 183/1944 baseline + 12
  backend + 11 frontend).
- **Registry:** `mssp.json`'s `CAP-MSSP-003` updated — `frontend.status`
  `missing → partial`, `navigation.discoverable` `false → true`,
  `operational_status` `NOT READY → PILOT ONLY`, full fix evidence
  including the auth-gate root cause. Also **corrected a pre-existing
  inaccuracy** found while updating this entry: its `test_coverage` field
  previously claimed `msspTenantIsolation.test.mjs`/`msspIsolation.test.mjs`
  import from `msspTenantPlatform.js` — independently re-verified false,
  both import exclusively from the sibling `msspWorkspace.js`; corrected to
  cite the real pre-existing coverage (`deadAdminChecksRestored.test.mjs`,
  4 of 18 handlers, legacy identity only). `PRODUCTION_READINESS_REPORT.md`
  regenerated (frontend 45.5% → 46.4%). Validator: 56 IDs, 0 failures, 0
  warnings (same bare-filename-citation round-trip as CAP-ORG-001 — fixed).
- **Next:** Staff Admin Console for user/org lifecycle (4th and last of the
  program) — new backend surface, most security-sensitive, done last and
  most carefully per the original risk-ascending sequencing decision.

### 2026-07-09 — Fix sprint: CAP-ORG-001 (Organization Management UI), 2nd of a 4-initiative enterprise-readiness program

- **Trigger:** continuation of the 4-initiative program agreed after the
  CAP-RBAC-002 fix (below). This was the customer's and this board's
  independent top recommendation: registry's own prior wording called it
  "the highest-value single gap identified across the whole platform" — a
  complete, RBAC-enforced, tested backend with precisely zero customer-facing
  UI, and a brand-new signup account had no org and no way to create one.
- **Recovery/research done ahead of coding (previous session, reused here):**
  a dedicated research pass had already confirmed no near-miss page existed
  under `frontend/enterprise*.html` (checked all 4: threat-intel feed, SSO/SIEM
  docs, CDB's own internal revenue KPIs, marketing copy — none call
  `/api/orgs`) and had extracted the complete, exact request/response contract
  for all 10 backend handlers, including two easy-to-miss gotchas: the create
  response field is `org_id`, not `id`; `GET /api/orgs/:id/dashboard` requires
  the real UUID (unlike `GET /api/orgs/:id`, which resolves a slug), and its
  zero-member response is a differently-shaped payload with no `summary` key.
- **Fix:** added `#page-orgs` to `frontend/user-dashboard.html` — a list view
  (empty-state "Create Organization" CTA + org table) and a detail view
  (dashboard stat tiles, members table, settings form, danger zone), plus 4
  modals (create/invite/remove-confirm/delete-confirm), all reusing the
  page's existing form/card/table/modal CSS and JS conventions exactly. New
  "Team" sidebar section. Client-side RBAC was derived directly from
  `orgManagement.js`'s own enforcement code, not guessed: only OWNER/ADMIN
  see the Invite button and Settings card; only OWNER sees the Danger Zone
  or a per-member role dropdown; OWNER/ADMIN/the member themself can
  remove/leave; the OWNER's own row never offers a role-change or
  remove/leave control (matching the backend's `role != 'OWNER'` guards).
  Zero backend changes. Deliberately left `handleOrgScans` (org-wide scan
  history) unwired rather than rushed — disclosed as a known remaining gap.
- **Verification:** inline `<script>` syntax check clean (3/3 blocks).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green. Real headless-Chromium
  Playwright session, mocking the full backend contract per role — **27/27
  checks** across 3 scenarios: full OWNER lifecycle (empty state → create →
  detail view with live dashboard stats → invite → change a member's role →
  remove a member → save settings → back to list, with the newly-created org
  now appearing in the list), and a dedicated MEMBER-role boundary check
  (zero management controls visible, only "Leave" — never "Remove" — on
  their own row, no action at all available on the other OWNER's row). Zero
  uncaught JS exceptions.
- **axe-core scan found and fixed 2 real new issues** (both `critical`
  severity, not the usual pre-existing `color-contrast` noise): a `label`
  violation on the settings form's Name field (fixed with proper `for`/`id`
  pairing — root-caused precisely: the pre-existing login/signup fields
  pass this same axe rule only because they happen to have a `placeholder`
  attribute, which HTML-AAM's accessible-name fallback accepts as a weak
  substitute; this new field had neither a real label nor a placeholder, so
  it had zero accessible name at all — fixed with the *stronger* pattern
  rather than copying the weaker pre-existing one), and a `select-name`
  violation on the dynamically-generated per-member role `<select>` (fixed
  with `aria-label`). Remaining flagged violations are the same pre-existing,
  site-wide `--muted`/`.badge-gray`/`.btn-danger` color-contrast issue
  already documented as out-of-scope on CAP-IDN-002 and CAP-RBAC-002 — every
  class involved was reused, not newly introduced.
- **Tests:** `workers/test/userDashboardOrgManagement.test.mjs` (new, 17
  tests) — cross-checks the frontend against `workers/src/index.js` and
  `workers/src/handlers/orgManagement.js` directly (exact route/field names,
  the `org_id`-vs-`id` and slug-vs-UUID gotchas, and that the client RBAC
  literally matches the backend's role checks). Full suite green: 183 files
  / 1944 tests (182/1927 baseline + 1 new file/17 tests).
- **Registry:** `organizations.json`'s `CAP-ORG-001` updated — `frontend.status`
  `missing → partial`, `navigation.discoverable` `false → true`,
  `operational_status` `NOT READY → PILOT ONLY`, full fix evidence, and the
  `GENERAL_AVAILABILITY_REPORT.md` correction narrowed (scan-history UI and
  a production verification pass are the specifically-still-inaccurate
  parts, not the whole "GA APPROVED" claim). Stays P2 (not closed):
  `handleOrgScans` remains unwired, and `customer_journey_complete` stays
  `false` pending a real `dynamic_browser` pass. `PRODUCTION_READINESS_REPORT.md`
  regenerated (frontend 44.6% → 45.5%). Validator: 56 IDs, 0 failures, 0
  warnings (one round-trip needed: initial evidence text cited
  `enterprise-dashboard.html` etc. as bare filenames, which the validator
  correctly rejects — fixed to the required `frontend/enterprise-dashboard.html`
  full-path form).
- **Next:** MSSP per-client drill-down (3rd of 4). Research already done in
  the same prior session surfaced a **blocking backend finding** for that
  one — see the CAP-RBAC-002 entry below for detail — so that fix starts
  with a small backend auth-gate change, not frontend work.

### 2026-07-09 — Fix sprint: CAP-RBAC-002 (tier-gating case bugs + MSSP support), part of a 4-initiative enterprise-readiness program

- **Trigger:** after CAP-IDN-002/003 shipped, the customer widened scope to a
  full production-grade audit across every account type (admin, paid,
  enterprise, MSSP) with zero-trust framing. Rather than build blind against
  such a broad ask, ran an evidence-based audit of the RBAC/Administration/
  MSSP/Organizations/Customer-Portal domains first (reading the existing
  registry, not re-deriving it) and presented a prioritized, evidenced
  backlog of 7 real gaps for the customer to choose from. Sequencing chosen
  deliberately risk-ascending (smallest/safest first, newest backend surface
  last): (1) this fix, (2) Organization Management UI, (3) MSSP drill-down,
  (4) Staff Admin Console.
- **Root cause, confirmed live:** while designing the sidebar fix, found
  `GET /api/user/plan`'s real `plan` field is uppercase
  (`'FREE'|'STARTER'|'PRO'|'ENTERPRISE'|'MSSP'`, confirmed against
  `workers/src/auth/apiKeys.js`'s `TIER_LIMITS`/`PLAN_FEATURES` keys), but
  `exportCisoPDF()`, `syncPlanCards()`, and `selectPlan()` in
  `frontend/user-dashboard.html` compared it against lowercase literals —
  gates that silently never fired for any real account (a paying PRO
  customer's own billing card never showed as "current"; clicking "Upgrade
  to Pro" while already Pro re-initiated payment instead of short-circuiting).
  Also found `TOOL_CATALOG`/`PLAN_QUOTA` had zero `MSSP` entries despite MSSP
  being a real, top-tier plan — MSSP customers saw every tool locked and
  FREE-tier quota numbers. Also found `loadKeys()` reading
  `_plan?.plan?.key_limit` (always `undefined` — `_plan.plan` is a string,
  not an object) instead of `_plan?.key_limit`.
- **Important negative finding — did NOT do what it looked like it should:**
  `initAiPage()`/`submitAiAnalysis()` had the identical-looking case bug, but
  "fixing" it would have been wrong. `workers/test/aiBrainEntitlementGate.test.mjs`
  proves `POST /api/ai/analyze` is intentionally not plan-gated for *any*
  tier (unlike `/api/ai/simulate`/`/api/ai/forecast`, which really are PRO+).
  The case bug was accidentally masking an already-stale, already-incorrect
  restriction — correcting the case would have reintroduced a real
  regression, blocking FREE customers from a capability they're
  contractually, test-verified entitled to. Removed the dead block (and its
  adjacent fabricated "queries left" counter, which read a field
  `GET /api/user/plan` never returns) instead of case-correcting it.
- **Scope decision — did NOT hide sidebar nav-items by tier:** the original
  framing ("sidebar should vary by plan/role") turned out to have no safe,
  evidenced implementation. `PLAN_FEATURES`/`TIER_LIMITS` show every tier,
  including FREE, has some real, legitimate access to every one of the 17
  sidebar pages (e.g. FREE gets 1 real API key, not zero) — hiding a nav-item
  would have been an unauthorized product guess risking a real regression
  (a FREE customer's "API Keys" page disappearing despite them having a real
  key to manage). Fixed the concrete, evidenced breakage instead of guessing
  at new UI restrictions.
- **Fix:** all changes confined to `frontend/user-dashboard.html`, zero
  backend changes. Case-sensitivity fixes normalize the fetched tier value
  once per function (`.toLowerCase()`) rather than rewriting every
  comparison/DOM id. Added `'MSSP'` to every `TOOL_CATALOG` tier allow-list
  that already included `'ENTERPRISE'`, plus a `PLAN_QUOTA.MSSP` entry.
  Fixed `loadKeys()`'s field path. Removed the AI-analysis FREE-tier block
  and credits counter.
- **Verification:** inline `<script>` syntax check clean (3/3 blocks).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green. Real headless-Chromium
  Playwright session against the changed file, mocking `/api/user/plan` per
  tier — 8/8 checks: FREE tier confirmed unblocked on AI Analysis (0 JS
  errors); MSSP tier confirmed showing all 8 tools UNLOCKED and the real
  "9999/mo" quota (was: 0 tools, FREE quota); PRO tier confirmed showing
  their billing card marked "current" with a "✓ Current Plan" button (was:
  never, for any real account); a FREE-tier regression check confirmed
  exactly 1 tool (not all 8) shows unlocked, proving the fix isn't
  over-permissive. Zero uncaught JS exceptions across all scenarios.
- **Tests:** `workers/test/userDashboardTierGating.test.mjs` (new, 11 tests) —
  cross-checks the frontend against `workers/src/auth/apiKeys.js`'s
  `PLAN_FEATURES`/`TIER_LIMITS` as the source of truth, and against
  `workers/test/aiBrainEntitlementGate.test.mjs`'s proven contract before
  asserting the AI-analysis block should be absent. Full suite green: 182
  files / 1927 tests (181/1916 baseline + 1 new file/11 tests).
- **Registry:** `rbac.json`'s `CAP-RBAC-002` updated — `frontend.status`
  `broken → partial`, `operational_status` `NOT READY → PILOT ONLY`,
  `subscription_gated` `false → true`, full fix evidence and an explicit
  explanation of why nav-items were not hidden by tier. Stays P4 (not
  closed): org-role gating (`OWNER`/`ADMIN`/`ANALYST`/`MEMBER`/`VIEWER`, see
  `CAP-ORG-001`) remains entirely unwired into this page, correctly out of
  scope until organization membership has a customer-facing UI at all — the
  next item in this program. `PRODUCTION_READINESS_REPORT.md` regenerated
  (frontend 43.8% → 44.6%). Validator: 56 IDs, 0 failures, 0 warnings.
- **Research for the next two initiatives, done in parallel this session
  (read-only, no code changes yet):** deep audits of
  `workers/src/handlers/orgManagement.js` (full request/response contracts
  for all 10 handlers, confirmed zero duplicate/near-miss page exists under
  `frontend/enterprise*.html`, confirmed a brand-new signup account has zero
  orgs and there's no "create your first org" flow anywhere) and
  `workers/src/handlers/msspTenantPlatform.js` (full contract for all 18
  handlers). The MSSP audit surfaced a **blocking backend finding**: every
  one of the 16 not-yet-wired MSSP handlers would 403 for every real partner
  session, because `requireMSSPAdmin()`/`partnerScope()` in
  `msspTenantPlatform.js` were never updated to recognize the
  `role:'partner'`/`partnerId`-based identity `partner-portal.html` actually
  uses — unlike the sibling `msspWorkspace.js`, which was already fixed for
  exactly this. Building frontend against the 16 handlers as originally
  planned would have shipped a feature that silently fails for every real
  customer; the MSSP initiative now needs a small backend auth-gate fix
  first, before any frontend work.

### 2026-07-09 — Fix sprint: CAP-IDN-002 (signup entry point) + CAP-IDN-003 (MFA login completion)

- **Trigger:** live Microsoft customer escalation, reported the same day as
  the CAP-IDN-001 fixes below: "when a new user or customer trying to sign
  up when they dont have any existing login credentials available - this
  sign up functionalities does not work - this simply returns to the home
  page." Resumed a session that had hit a usage-limit interruption before
  this escalation could be investigated.
- **Recovery:** fetched `origin`, confirmed local branch already sat exactly
  on `origin/main` (`a2885bf`, includes the merged PR #108 and #109
  CAP-IDN-001 fixes) — no rebase needed before starting.
- **Root cause, confirmed live:** grepped `frontend/user-dashboard.html` and
  found `No account? <a href="/">Get started free</a>` — matches the
  screenshot in the escalation exactly (the link just returns to the
  homepage). Broader grep across all of `frontend/` for
  `api/auth/signup`/`doSignup`/`signup-view`/any signup modal id returned
  **zero matches anywhere on the site**. Read `workers/src/handlers/auth.js`
  and confirmed `POST /api/auth/signup` (`handleSignup`) was already a
  complete, tested, production-grade implementation, correctly routed in
  `workers/src/index.js` — the backend was never the problem; no frontend
  surface had ever been built to call it. Separately, while reading
  `doLogin()` to model the new `doSignup()` on it, noticed it never
  branches on `d.mfa_required` — traced `handleLogin()` and confirmed it
  really does return `{mfa_required:true, mfa_challenge_token}` with HTTP
  200 (no `access_token`) whenever MFA is enabled, which `doLogin()` was
  silently mistreating as a successful login. `POST /api/auth/mfa/authenticate`
  was already built and already covered by `workers/test/mfaAuthGate.test.mjs`
  — again, a missing frontend consumer of a working backend capability, not
  a backend gap.
- **Explicitly ruled out as in-scope:** the existing "forgot password" /
  "reset password" flow already works end-to-end via a secure, single-use,
  30-minute email link (`handleForgotPassword`/`handleResetPassword`) — a
  legitimate, common pattern, not a bug, so left untouched. No numeric-code
  email/SMS "OTP" delivery mechanism exists anywhere in the codebase beyond
  authenticator-app TOTP (a different concept); building one would be new
  infrastructure requiring a provider decision, not a bug fix, so it was not
  invented here — flagged instead of built blind, per this board's
  standing "never assume production infra" rule.
- **Fix:** additive only, both changes confined to
  `frontend/user-dashboard.html`'s existing `#login-overlay`:
  - Added `#signup-view` (name/email/company/password, same
    `.form-group`/`.form-label`/`.form-input` markup as the pre-existing
    views) and `doSignup()`, byte-for-byte mirroring `doLogin()`'s
    fetch/error/spinner structure, posting to the existing, unmodified
    `/api/auth/signup`. "Get started free" now calls
    `showAuthView('signup-view')` instead of navigating away; a symmetric
    "Already have an account? Sign in" link was added to return.
  - Added `#mfa-view` (6-digit code field) and `doMfaVerify()`, same
    pattern, posting to the existing, unmodified
    `/api/auth/mfa/authenticate`. `doLogin()` now checks `d.mfa_required`
    and routes there *before* trusting the response as a login success,
    storing no token until the second factor is verified.
  - Extended `showAuthView()`'s view list to include both new views.
  - Zero changes to any backend handler, zero changes to the existing
    login/forgot/reset views' markup or behavior.
- **Verification:**
  - `node --check`-equivalent syntax parse of all 3 inline `<script>`
    blocks: clean.
  - `scripts/seo-structure-lock.mjs`: 22/22 pages green (unaffected —
    change is entirely below `<body>`, outside `<head>`).
  - Real headless-Chromium Playwright session against the changed file
    (served locally via `python3 -m http.server`, mocking
    `/api/auth/signup`, `/api/auth/login`, `/api/auth/mfa/authenticate`,
    `/api/auth/me`): 18/18 checks passed — signup happy path (correct POST
    body, tokens stored, overlay hidden), signup duplicate-email error
    path (backend message surfaced, no false-positive login), MFA-required
    login correctly routes to the code view with **zero token stored
    mid-challenge** (previously: silently treated as logged in), MFA
    verify completes login with the real token, plain non-MFA login proven
    unaffected, forgot-password view-switching proven unaffected. Zero
    uncaught JS exceptions.
  - `axe-core` WCAG2A/AA scan (installed fresh this session; not a repo
    dependency) run against all five auth views: found and fixed one
    genuinely new issue — `link-in-text-block` on the new "Sign in" link,
    resolved with `text-decoration:underline`, applied symmetrically to
    the pre-existing "Get started free" link for visual consistency. All
    remaining flagged violations are the pre-existing, site-wide `--muted`
    color-contrast issue (#64748b on #111827, 3.72:1 vs the 4.5:1 AA
    minimum), confirmed identical on the untouched `login-view`/
    `forgot-view` baseline via isolated before/after axe runs — real, but
    out of scope for an auth-flow fix; noted as a follow-up in the registry
    entry rather than redesigned here.
- **Tests:** `workers/test/userDashboardSignupAndMfa.test.mjs` (new, 13
  tests, static-parse convention matching `userDashboardAuthContract.test.mjs`
  — cross-checks `frontend/user-dashboard.html` against
  `workers/src/index.js`, `workers/src/handlers/auth.js`, and
  `workers/src/handlers/mfa.js` so the frontend can never again silently
  drift from the routes the backend actually serves). Full suite green:
  181 files / 1916 tests (180/1903 baseline + 1 new file/13 tests) — run
  twice, once immediately after the axe-driven underline fix, to confirm
  zero regressions from either change.
- **Registry:** `identity.json` gained `CAP-IDN-002` (Sign-Up / Account
  Creation Entry Point, P1) and `CAP-IDN-003` (MFA Second-Factor Login
  Completion, P1); `PRODUCTION_READINESS_REPORT.md` regenerated (backend
  74.1%→75%, frontend 41.7%→43.8%, parity 38.9%→41.1%). Validator: 56
  capability IDs, 0 failures, 0 warnings.
- **Not done this pass:** the rest of the P1–P7 backlog was not
  re-audited; `customer_journey_complete` stays `false` on both new
  entries pending a real `dynamic_browser` pass against production (this
  fix used a local static-file-server Playwright session, not a production
  browser click-through). "Post-login features" (scans, reports, API keys,
  billing, MFA setup, etc.) were confirmed already built and already
  covered by prior audit waves per this board's history — not re-audited
  here since the customer escalation was specifically about signup, not
  the dashboard behind it.

### 2026-07-09 — CAP-IDN-001 follow-up: third dead end found and fixed

Same-day, before PR #108 (the fix below) had merged: user reported a live
production escalation — scanning a domain after a scan-token reuse showed
"Access denied: ... Please log in to continue," and clicking "log in" landed
back on the homepage with no login form, escalated as a possible missing
login feature entirely. Investigated before touching anything:
`frontend/index.html:9657`'s 403-error "log in" link called
`showModal('loginModal')` — an id that never existed anywhere in the file
(grep-confirmed 0 matches; `showModal()` itself is not broken, e.g.
`showModal('leadModal')` elsewhere correctly targets a real element). This
is a **third, independent instance of the same CAP-IDN-001 bug class**, not
evidence the login system itself is missing — the working login system was
already confirmed and tested in the fix below. Did not build a duplicate
login panel; replaced the dead `onclick` with a real
`href="/user-dashboard.html"` anchor, matching the same evidence-based,
minimally-disruptive pattern as the other two fixes. Re-verified live via
Playwright (isolated the correct anchor among now-multiple same-target
links on the page, confirmed no stray `onclick`). Added as a 4th test to
`workers/test/homepageSignInPath.test.mjs`; added as a second commit on the
same PR #108 branch (same root cause, same capability, still unmerged at
the time). Full suite green: 180 files / 1902 tests.

### 2026-07-09 — Fix sprint: CAP-IDN-001 (homepage Sign In dead end)

- **Trigger:** user adopted a standing "Global Production Release Governance"
  operating mode for the session. Per its own "verify first, don't guess"
  principle, checked the single most severe-looking open item in
  `PRODUCTION_READINESS_REPORT.md` (P1, no frontend) before proposing any
  backlog — re-verified live against current code rather than trusting the
  2026-07-08 registry timestamp.
- **Root cause, confirmed live:** `frontend/index.html`'s homepage "Sign In
  Required" modal (`createMonitorModal()`) had exactly one button, whose
  only behavior was to remove itself — no link anywhere. The real login
  form (`#login-overlay`) exists and works at `frontend/user-dashboard.html`,
  but nothing in primary navigation points to it (only a footer link styled
  `v14-footer-link-dim`). Traced the mechanism precisely: `cdbApplyGates()`
  already had a working, idempotent "inject Dashboard link for authenticated
  visitors" pattern — the symmetric "not authenticated → inject Sign In
  link" branch was simply never written.
- **Fix:** extended `cdbApplyGates()` with the missing else-branch (desktop
  `#cdb-nav-actions` + mobile `#nav-mobile-drawer`, both →
  `/user-dashboard.html`), with cleanup on the `cdb:login` event so the link
  never lingers post-login. Fixed the modal's dead-end button to navigate
  there too, adding a separate "Cancel" button so the original dismiss
  capability is preserved (backward compatible, not just replaced).
- **Verification:** real headless-Chromium Playwright session against the
  changed file (served locally via `python3 -m http.server`, since
  `frontend/` is a no-build-step static site) — confirmed the Sign In link
  renders correctly on both desktop and mobile, confirmed it disappears and
  the Dashboard link appears after a simulated `cdb:login` event (proving
  zero regression to the already-working authenticated path), confirmed the
  modal's new buttons render with correct text, zero uncaught JS errors.
  Also ran `scripts/seo-structure-lock.mjs` locally (22/22 pages green,
  unaffected) since `tests/e2e/smoke.spec.mjs` intentionally targets live
  production (no `SMOKE_BASE` override in CI) and would give a false signal
  against a not-yet-deployed fix.
- **Tests:** `workers/test/homepageSignInPath.test.mjs` (new, 3 tests,
  reads `frontend/index.html` directly — same convention as
  `workers/test/autoSocToggleGuard.test.mjs`). Full suite green: 180 files
  / 1902 tests.
- **Registry:** `identity.json`'s CAP-IDN-001 updated with fix evidence;
  `PRODUCTION_READINESS_REPORT.md` regenerated (frontend 39.8% → 41.7%,
  parity 37% → 38.9%). Validator: 0 failures, 0 warnings.
- **Not done this pass:** the other 13 P1 "Critical" items in the readiness
  report have not been individually live-reverified; `customer_journey_complete`
  stays `false` pending a real `dynamic_browser` pass against production
  (this fix used a local static-file-server Playwright session, not a
  production browser click-through).

### 2026-07-09 — Fix sprint: CAP-DEVPORTAL-002/003/004

- **Scope:** the three confirmed-broken findings documented by Wave 2
  (2026-07-08), fixed as their own dedicated change per that wave's own
  recommendation — same treatment as CAP-MASOC-001.
- **CAP-DEVPORTAL-002** (`workers/src/handlers/enterpriseAutomation.js`):
  fixed the `createApiKey` parameter-ordering bug, added the matching
  per-tier key-limit enforcement, fixed the list response (`count`/`max_keys`
  were previously undefined), and implemented the missing rotate route
  (mirrors the canonical `handleRotateKey`'s atomic revoke-then-recreate).
- **CAP-DEVPORTAL-003** (`workers/src/handlers/developerPortal.js`,
  `workers/src/index.js`): deleted the four broken local reimplementations
  and delegated to the canonical `handlers/apikeys.js`; threaded `authCtx`
  through the router and gated all four key routes on `isRealUser`. Found
  and fixed independently while in this file: 18 occurrences of a literal
  unfilled placeholder domain (`your-worker.workers.dev`) across every SDK
  generator and the OpenAPI spec's own declared server URL.
- **CAP-DEVPORTAL-004** (`workers/src/services/apiRevenueEngine.js`,
  `workers/src/handlers/growth.js`): fixed the INSERT's column list (real
  NOT NULL columns supplied, `tier` not `plan`) and replaced the invalid
  `ON CONFLICT(email)` with an explicit select-then-upsert (no schema
  migration needed). Found and fixed independently in the same file:
  `resolveApiKey`'s D1 fallback selected the same nonexistent `plan` column
  (previously dead code — nothing calls this function's D1 path in
  production, confirmed by a full grep); `recordApiUsage`'s usage-log
  INSERT referenced nonexistent `api_key`/`weight` columns (also dead code,
  never called); `getApiUsageSummary`'s three queries summed a `weight`
  column that was never persisted (corrected to `COUNT(*)`). Closed the
  actual identity-escalation gap in `handleProvisionApiKey`: the tier was
  previously trusted from client input whenever no lead record existed,
  letting any caller mint an arbitrary-tier key for any email; now taken
  only from a lead's own server-recorded, webhook-verified plan.
  **Residual, deliberately unfixed:** `sap_` keys still cannot authenticate
  anywhere — `workers/src/middleware/auth.js`'s request-time key resolver
  has no recognition path for this prefix, and a separate KV-naming
  mismatch (hash vs raw) would break even a fast-path lookup if one
  existed. Fixing this means touching the platform's core, every-request
  auth resolver — out of proportion for this bounded fix and outside the
  original finding's scope (which only examined the INSERT). Flagged as
  its own follow-up in the registry entry's `notes`; `operational_status`
  for this one entry honestly stays `BLOCKED`.
- **Tests:** `workers/test/devPortalApiKeyFixes.test.mjs` (new, 12 tests,
  real in-memory D1 via `node:sqlite` matching the live schema — not a
  hand-rolled regex mock, precisely to catch the bug class being fixed).
  `workers/test/apiKeyHashing.test.mjs` updated (its mock's SQL-matching
  regex still referenced the now-fixed `plan` column; corrected to `tier`).
  Full suite green: 179 files / 1899 tests.
- **Registry:** all three entries' `status`/`operational_status`/
  `test_coverage`/`verification`/`notes` updated with fix evidence;
  `PRODUCTION_READINESS_REPORT.md` regenerated (backend 69.4% → 74.1%).
  Validator: 0 failures, 0 warnings.

### 2026-07-08 — Wave 2: Developer Portal / API Keys

- **Recovery:** Followed `EXECUTION_PROCEDURE.md` §3 before starting. Fetched
  `main` fresh, confirmed `git ls-remote origin` for the two branches from
  the wave-1 recovery (`claude/capability-registry-recovery-elpx1n`,
  `claude/capability-registry-resume-ldqytt`) that looked "13 commits ahead"
  by `git log` — verified via `git diff <branch> main --stat` (not
  commit-count, per §3.4's explicit warning) that this was a squash-merge
  artifact with zero actual content difference; nothing to recover. Confirmed
  the domain was still a genuine empty stub (`[]`) on every branch.
- **Execute:** Dispatched a research pass across `workers/src/`,
  `frontend/*.html`, `workers/test/`, and the D1 schema to map every
  API-key-related code path. Independently re-verified (read the actual
  code and schema myself, not just trusted the research pass) both leads
  named in the prior session's note, plus discovered and independently
  verified a third, previously-unknown instance of the same bug class
  (`apiRevenueEngine.js`) and a sixth key-issuance path
  (`developerOnboardingHandler.js`'s trial-key funnel) that turned out to
  be a correct consumer of the canonical function, not another broken
  reimplementation.
- **Commits this session:** (registry entries + docs only — no product code
  changed in this wave)
  - Populated `docs/capability-registry/domains/developer-portal-apikeys.json`
    with 4 capability entries (CAP-DEVPORTAL-001 through -004).
- **Validator:** 54 capability IDs, 0 failures, 0 warnings.
- **Tests:** 177 files / 1867 tests passing (full suite, independently
  re-run; unchanged from before this wave since no product code changed).
- **Findings:** 3 confirmed, real, independently-verified bugs — see "Open
  critical findings" above for full detail (CAP-DEVPORTAL-002, -003, -004).
  All three are the same general bug class (parallel, untested
  reimplementations of API-key issuance drifting out of sync with the real
  schema or the real auth pattern) as the domain's own prior-session lead
  predicted, plus one additional independent instance found this wave.
- **Remaining in this wave:** none — the single domain named for Wave 2 is
  fully populated and validated.
- **Risks / follow-ups:** 3 open, unfixed, evidence-backed findings (above),
  each recommended as its own bounded fix sprint, same treatment as MASOC.
- **Next recommended wave:** Wave 3 (Threat Hunting/Intel + Security
  Scanners), or one of the CAP-DEVPORTAL-00{2,3,4} fixes first if
  prioritized higher — owner's call.

### 2026-07-08 — Wave: Recovery + Execution Procedure establishment

- **Recovery:** Verified real repo state via `git fetch` + `git ls-remote
  origin` (local `main` was stale/shallow, would have misjudged what was
  already merged if trusted directly — see `EXECUTION_PROCEDURE.md` §0).
  Confirmed PRs #98–#100 merged (Administration, Navigation, Production
  Readiness, plus everything from PR #99: RBAC, Commercial/Billing,
  Customer Portal, Sales/CRM, Affiliate/Partner, Sentinel APEX Marketplace,
  Notifications, Academy, Dashboard/Personalization). Found the MASOC commit
  (`977628f1`) pushed to `origin/claude/capability-registry-recovery-elpx1n`
  but never merged (PR #100 merged one commit earlier). Confirmed the
  Developer Portal/API Keys work described in the prior session's log was
  never committed anywhere — genuinely lost.
- **Commits this session:**
  - `c5ede40` — recovered MASOC domain (`git cherry-pick 977628f1`)
- **Validator:** 50 capability IDs, 0 failures, 0 warnings.
- **Tests:** 176 files / 1835 tests passing (full suite, independently
  re-run, not assumed from a prior session's report).
- **New docs this session:** `EXECUTION_PROCEDURE.md`, this file
  (`PROGRAM_BOARD.md`), both registered in `DOCUMENTATION_INDEX.md`.
- **Findings:** MASOC unauthenticated-access gap (see above) — confirmed
  real, still open, flagged for a dedicated fix rather than bundled here.
- **Remaining in this wave:** none — this wave was process establishment
  + recovery, not a domain, and is complete.
- **Risks / follow-ups:** MASOC auth gate (above). Developer Portal/API Keys
  leads need re-verification before trusting them (above).
- **Next recommended wave:** Wave 2 (Developer Portal / API Keys), or the
  MASOC auth-gate fix first if prioritized higher — owner's call.
