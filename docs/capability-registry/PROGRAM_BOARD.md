# Capability Registry — Program Board

**Status:** Living doc, updated at the end of every execution wave (see
`EXECUTION_PROCEDURE.md`). Tracks *structural completion of the registry
population effort itself* — how much of the platform has been catalogued,
not how well the platform serves customers. It is not a customer-outcome
measure and does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only outcome
scoreboard. Read this + `EXECUTION_PROCEDURE.md` before starting any
registry-population session.

## Current status (2026-07-12 — the prior 24-item Tier 1–3 follow-up backlog from the full 80-page frontend audit is **fully closed, merged, and live in production** (PR #185 squash-merged to `main` as commit `9819fed7`, `Deploy to Cloudflare` ran and passed its post-deploy smoke tests; see the entry twenty-eight below for the original 24-item list and the two entries above it for the closure + pre-merge security-fix account). **A new program has now started**, at the owner's explicit direction: bring all 22 `subscription_gated: true` (paid) capabilities in the registry to genuine, evidenced production grade — frontend, backend, RBAC, security, tests, docs, the works — not a subset. Every one of the 22 currently sits below GA; 5 have no working frontend at all. Tracked as tasks #25–#46. Item 1 (`CAP-RBAC-002`, chosen first since 8 other items share its "RBAC not enforced" gap) turned out to need **zero code changes** — the registry's own record was stale, predating the Organizations feature that had already closed the gap; corrected the record instead of inventing busywork. Item 2 (`CAP-MYTHOS-003`) was the opposite case: investigation found a live, unauthenticated production endpoint fabricating security-scan and compliance results under the platform's brand name, plus a dangerous, untested, live-reachable duplicate payment/tier-grant mechanism sitting behind it — both fixed (scan/compliance redirected to this platform's real engines; the duplicate payment path removed outright with the owner's explicit sign-off). Item 3 (`CAP-DEVPORTAL-002`) resolved its two open "unknown" registry fields by direct verification: `subscription_gated` was confirmed `false` (correctly tier-scaled, not a paid-only gate — matches its canonical sibling), and `navigation.discoverable` was confirmed **false** and fixed — the page had zero links anywhere outside the sitemap, now has a real nav-item. Item 4 (`CAP-DEVPORTAL-004`) surfaced a second live, unauthenticated vulnerability this program has found: a sibling route (`POST /api/growth/upgrade`, not previously catalogued under this capability) let anyone mint a real, free ENTERPRISE-tier API key for any email with zero payment — closed with the same RBAC gate already used for 3 sibling routes in the same file, proven at the database-mutation level, not just an HTTP status code. See the top session-log entry for the full account. 18 of 22 remain, continuing in chosen order.

**Housekeeping note:** this line had drifted 6 PRs stale (last updated as of the
CAP-CRM-007/CAP-COMP-005 wave, #172/#173) — PRs #174–#179 each correctly
appended their own session-log entry below but never rolled the header
summary forward, so it still named CAP-CRM-007 as the latest work and the
metrics table below still read 211 files/2188 tests after the suite had
already reached 217/2242. Corrected here; see session log for the full,
unedited history of every wave in between (URL-hardcoding fix #177, GDPR
claims reconciliation #176, dead catalog products #175, portal metrics
mislabeling #174, admin/revenue dashboard gating + CISO paywall bypass #178,
and the homepage `?owner=1` shell-reveal fix + 5-page self-correction #179).

As of today: all of the above are shipped and merged. This session's own
work (full account in the session log entry below) closed CAP-DEVPORTAL-004's
last open item — `sap_`-prefixed growth/plan API keys minted via `POST
/api/growth/api-key` could never authenticate anywhere on the platform
(confirmed by reading the actual resolver, not the registry's prior
description of it) — plus a second, independent stale-KV-on-rotation bug
found while regression-testing the fix. `operational_status` for that entry
moves from `BLOCKED` to `PILOT ONLY` (matching its CAP-DEVPORTAL-001/002/003
siblings); its `priority` field stays `P1` untouched, per this file's
established historical-severity convention. Metrics table below regenerated
fresh via `node scripts/registry/generate-report.mjs` (2026-07-11) rather
than hand-updated, per this file's own rule never to let the two drift.

Also corrected: the "Remaining Work Register" and "Proposed wave plan"
sections below were stale in the same way — both still described 3 domains
(`threat-hunting-intel`, `mythos-godmode`, `compliance-store`) as unpopulated
stubs and recommended them as the next wave, but the "Domains populated (21)"
list two paragraphs above already correctly listed all 21 as populated, and
the generated report confirms non-zero capability counts for all three
(17/6/5 respectively) — that population work is done and was simply never
removed from the register. See those two sections for the correction.

**Scope note (2026-07-10):** starting this date, sessions on this branch
follow the customer's "production readiness lifecycle" priority (visitor →
signup → … → retention) rather than continuing registry-population waves for
their own sake. The registry, its bounded-wave discipline, and
`docs/ENGINEERING_STANDARDS.md`'s CEAP/CIP/CORB/CAB architecture are still
authoritative and are being reused as-is, not replaced — this file remains
the single source of truth for what's catalogued and what's real, and every
fix below still updates its capability entry in place rather than spawning a
parallel tracking document.

| Metric | Value | Source |
|---|---|---|
| Domain files | 21 | `docs/capability-registry/domains/*.json` |
| Domains populated | 21 | see list below (all 3 former stubs now populated) |
| Domains empty (stubs) | 0 | none remain |
| Capabilities registered | 97 | `node scripts/registry/validate.mjs` (+2 this wave: CAP-MASOC-002, CAP-MSSP-005) |
| Validator | 0 failures, 0 warnings | `node scripts/registry/validate.mjs`, run 2026-07-12 (after CAP-DEVPORTAL-004's registry update) |
| Worker test suite | 247 files / 2516 tests passing | `npx vitest run`, run 2026-07-12 — +4 tests this wave, extended `anonymousExposureAudit.test.mjs` (CAP-DEVPORTAL-004: proves POST /api/growth/upgrade rejects anonymous callers and that the underlying leads.plan write never executes without authorization). Baseline going into this wave was 247 files / 2512 tests (CAP-DEVPORTAL-002). |
| Production readiness verdict | **NOT READY** (computed) | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-12 — still NOT READY: multiple other Critical (P1) items are untouched by this session, and fixed items still count toward the historical Critical total per this file's own historical-priority convention (see below) |
| Backend / Frontend / Parity | 89.7% / 66.5% / 60.8% | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-12 — **unchanged by this wave's CAP-MYTHOS-003 fix**: its backend went from fabricated to real and its `operational_status` improved (`NOT READY`→`PILOT ONLY`), but its frontend is still `missing`, so it stays in the same backend-only/no-frontend structural bucket this report measures — a quality improvement, not a structural one |
| Customer journeys browser-verified | 3/97 capabilities now carry both `verification.method: dynamic_browser` AND `customer_journey_complete: true` (CAP-IDN-001, CAP-IDN-002, CAP-IDN-003 — unchanged this wave, all static verification) | Full real chain against LIVE PRODUCTION (`cyberdudebivash.in`), zero mocking: signup → MFA setup/enable (real RFC 6238 TOTP, no authenticator app) → logout → password login → MFA challenge → authenticated dashboard link — see session log |
| Gaps by severity | Critical 9 · High 24 · Medium 13 · Low 51 | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-11 — Medium +1 (P4, CAP-MSSP-005's rbac.enforced:true but frontend partial nudges its own bucket) and Low +1 (P6, CAP-MASOC-002/CAP-MSSP-005 both carry real but incomplete test coverage) from the 2 new entries; Critical/High unchanged. Do not hand-diff against older rows in this table — each was already flagged non-comparable; treat this run as the current baseline |

Full structural breakdown (per-domain tables, gap definitions): regenerate
and read `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — never
hand-copy its numbers here beyond the summary above, to avoid two sources of
truth drifting apart.

**Domains populated (21):** academy, administration, affiliate-partner,
commercial-billing, compliance-store, customer-portal,
dashboard-personalization, developer-portal-apikeys, identity, masoc,
mssp, mythos-godmode, navigation, notifications, organizations,
production-readiness, rbac, sales-crm, sentinel-apex-marketplace,
security-scanners, threat-hunting-intel.

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

**Correction (2026-07-11):** this section said all 3 of the domains below
were still empty, unstarted stubs, and the wave plan below it recommended
populating them as the next two waves. Both were stale — all 3 were
populated back on 2026-07-09 ("Backlog sweep, wave 1: 3-domain audit", see
session log) with 5 (compliance-store), 6 (mythos-godmode), and 17
(threat-hunting-intel) capabilities respectively, and the "Domains populated
(21)" list above this section has correctly listed all 21 domains
(including these 3) for several waves now. Nobody had removed the
now-contradicting table below in the meantime. Registry population itself
(all 21 domains, 95 capabilities) is **complete** — confirmed by
`node scripts/registry/validate.mjs` (0 failures) and
`PRODUCTION_READINESS_REPORT.md`'s per-domain capability counts. There is no
remaining registry-population work; anything still open is a product/fix
backlog item (see `PRODUCTION_READINESS_REPORT.md`'s gap tables and the
session log below), not an unpopulated domain.

## Proposed wave plan

Registry population (Waves 1–4, the domain-by-domain cataloguing effort) is
**complete** — see the correction immediately above. Per the 2026-07-10
scope note near the top of this file, sessions on this branch have since
followed the customer's production-readiness-lifecycle priority instead of
further registry waves for their own sake; that shift is working as intended
and stays in effect. Recommended next steps, in the same spirit as the fixes
already shipped under it:

- Work the remaining real (non-historical, non-owner-blocked) gaps in
  `PRODUCTION_READINESS_REPORT.md` — regenerate it first
  (`node scripts/registry/generate-report.mjs`) rather than trusting any
  cached copy, then re-verify each candidate by reading its actual code
  before touching anything, per this file's own repeated lesson (5 false
  positives were caught and corrected this way in the #178/#179 wave alone).
- The one remaining owner-action item from an earlier wave: the Threat Graph
  findings-persistence fix still needs the owner to run the gated D1 Schema
  Migration workflow (`workers/schema_migration_scan_history_findings_2026_07.sql`)
  to activate — code-complete, shipped as a safe no-op until then.
- CAP-DEVPORTAL-002/003/004 fixes: ✅ DONE (2026-07-09, plus CAP-DEVPORTAL-004's
  own residual sap_-key auth-resolution gap closed 2026-07-11) — see the
  remediation section above and today's session log entry below.

## Session log (most recent first)

### 2026-07-12 — 22-paid-feature program, item 4 (of 22): CAP-DEVPORTAL-004 — a sibling route let anyone mint a free ENTERPRISE-tier API key with zero payment; closed

- **Started from CAP-DEVPORTAL-004's own open questions**, not a fresh
  grep sweep: this capability's frontend is intentionally `missing` (it
  provisions `sap_` API keys for "programmatic growth/API-economy
  customers" via a marketing-funnel path, not a customer-facing UI), and
  the registry's own notes already say the backend was fixed and tested
  in two prior waves (2026-07-09, 2026-07-11). Before accepting "nothing
  left to do here," traced whether the auto-provisioning loop is
  genuinely live: confirmed `workers/src/services/apiRevenueEngine.js`'s
  `handlePaymentSuccess` (called by the real, HMAC-verified Razorpay
  webhook) does call `provisionApiKey()` automatically on every real
  payment (line 299) — not dead/orphaned infrastructure, a real
  auto-provisioning loop.
- **While tracing that loop, found a second live vulnerability this
  program has now uncovered** (after CAP-MYTHOS-003's fabricated-scan
  finding): `POST /api/growth/upgrade` (`handleUpgradeLead`,
  `workers/src/handlers/growth.js:427`) was never previously catalogued
  as an entry point of this capability, registered fully public
  (`workers/src/index.js`'s own comment: "mark lead as upgraded
  (public)"), and took `{email, plan}` directly from an anonymous
  client's JSON body with zero verification. It called `upgradeLead()`
  (`workers/src/services/funnelEngine.js:146`), which writes `UPDATE
  leads SET plan = ? WHERE email = ?` — **the exact same column**
  `handleProvisionApiKey`'s 2026-07-09 fix relies on as its entire trust
  boundary ("plan comes only from the lead's own server-recorded value,
  set exclusively by the HMAC-verified Razorpay webhook — never client
  input"). `handleUpgradeLead` then immediately auto-provisioned a key
  itself for any non-free plan. **Net effect: any anonymous caller could
  mint a real, working ENTERPRISE-tier `sap_` API key for any email —
  full access to the premium `/api/v1` threat-intel monetized feed — with
  zero payment**, via two unauthenticated POST requests. This reopened,
  through a sibling code path the 2026-07-09 fix never touched, the exact
  vulnerability class that fix documented as closed.
- **Confirmed zero legitimate callers exist** before deciding how to fix
  it: grepped `frontend/*.html`, all of `workers/`, `docs/`, and
  `scripts/` for any reference to this route outside its own
  registration and handler — none found. The capability's real,
  legitimate payment path (the actual Razorpay webhook →
  `handlePaymentSuccess` → `provisionApiKey`) does not call or depend on
  this route at all.
- **The fix:** gated the route behind the identical `admin:business:read`
  RBAC check (`requireCan`) this exact file already uses for 3 sibling
  routes fixed in an earlier "anonymous-exposure audit" pass
  (`/api/growth/analytics`, `/api/growth/funnel`, `/api/growth/leads`) —
  chose to gate rather than remove outright (unlike CAP-MYTHOS-003's
  checkout) because a legitimate administrative use case plausibly exists
  here (support staff manually marking a lead upgraded for an
  out-of-band payment) and this matches the file's own established
  remediation pattern exactly.
- **Test plan:** extended `workers/test/anonymousExposureAudit.test.mjs`
  — added `['/api/growth/upgrade', 'POST']` to the existing
  table-driven route array (free anonymous-rejected + ADMIN_KEY-bypass
  coverage), plus a new dedicated describe block proving the fix closes
  the exploit at the database-mutation level, not just the HTTP-status
  level: a recording D1 mock asserts **zero** `UPDATE leads SET plan`
  writes occur for an anonymous caller and **exactly one** for an
  authorized one. Full suite green: 247 files / 2516 tests (`npx vitest
  run`, up from 247/2512). Registry validator: 0 failures, 0 warnings
  (after fixing one of my own bare-filename evidence citations the
  validator caught — `apiRevenueEngine.js` needed its
  `workers/src/services/` prefix).
- **Follow-up found, deliberately not fixed here (documented, not
  silently dropped):** a key provisioned through the real payment-webhook
  path has no delivery mechanism to the lead at all — no email, no UI.
  The platform already has a ready-built email template for exactly this
  (`emailEngine.js`'s `templateSubscriptionDay0` conditionally renders a
  raw API-key block when `meta.api_key` is supplied), but nothing in this
  growth-funnel path populates it. Not fixed because (a) it's genuinely
  ambiguous whether this endpoint is meant to be consumed by an external
  growth-automation tool that already handles delivery through its own
  channel — invisible to this session either way — and (b) reusing the
  established `triggerPostPurchase()` lifecycle helper wholesale would
  also re-log `revenue_events`/`funnel_events` for a payment this
  module's own `handlePaymentSuccess` already recorded once, risking
  double-counted revenue metrics without deeper reconciliation. Flagged
  for an explicit product decision rather than guessed at.

### 2026-07-12 — 22-paid-feature program, item 3 (of 22): CAP-DEVPORTAL-002 — Self-Service Automation API Keys had zero discoverable path to its page; both open "unknown" registry fields resolved

- **Chose the 2 remaining P1-priority items next**, per the registry's own
  priority field, now that the two higher-urgency findings (RBAC-002's
  leverage, MYTHOS-003's live fabrication/payment risk) were closed.
  `CAP-DEVPORTAL-002` (Self-Service Automation API Keys,
  `frontend/automation-dashboard.html`) first.
- **`navigation.discoverable` was recorded `"unknown"`** — a prior wave's
  own note said it "was not verified this pass." Resolved by direct
  check: grepped every file under `frontend/*.html` for any reference to
  "automation-dashboard" at all. Exactly one hit — `frontend/sitemap.html`
  (a machine-readable URL list, not a navigation surface). No nav bar, no
  dashboard menu, no button, no card anywhere links to this page. A
  paying customer with zero knowledge of the direct URL had no way to
  ever find self-service automation API keys, webhooks, scheduled
  reports, team management, or the usage/governance dashboards this page
  hosts (P7.0-001 through P7.0-009) — a real, actionable "hidden feature"
  gap, the same class already fixed for other capabilities in this
  program (e.g. PR #181's homepage section discoverability fix).
- **`subscription_gated` was also recorded `"unknown"`.** Resolved by
  reading `workers/src/auth/apiKeys.js`'s `TIER_LIMITS` directly rather
  than guessing from the capability's own description ("intended to let
  self-service (including ENTERPRISE-tier) customers…", which reads
  ambiguous out of context). Every tier — including `FREE` — has an
  explicit, non-`Infinity` `api_keys` cap (FREE:1, STARTER:2, PRO:5,
  ENTERPRISE:20, MSSP:unlimited); `maxSelfKeysForTier()`
  (`workers/src/handlers/enterpriseAutomation.js:124`) reads the exact
  same table the canonical `POST /api/keys` route enforces. This is
  **not a paid-only gate** — it is a tier-scaled key-count limit
  available to every authenticated tier, exactly mirroring its canonical
  sibling `CAP-DEVPORTAL-001` (also `subscription_gated: false`).
  Correcting an "unknown" to a verified `false` is itself real progress
  toward this program's "genuine, evidenced" bar — an unresolved unknown
  is not a passing grade for a paid feature either.
- **The fix:** `frontend/user-dashboard.html`'s "Developer" sidebar
  section gained a real nav-item linking to `automation-dashboard.html`,
  next to the existing "API Keys" link — following the exact
  dedicated-page-navigation pattern already established one section up
  for `threat-intel-workbench.html` (`location.href='...'`, not the
  in-page `showPage()` tab mechanism used for this file's own sections).
  No backend change; `CAP-DEVPORTAL-002`'s underlying key-management
  logic was already fixed and tested in a prior wave (2026-07-09) and
  was not touched again here.
- **Test plan:** new
  `workers/test/automationDashboardDiscoverability.test.mjs` (4 tests) —
  proves the real nav-item exists, sits inside a real sidebar section
  (not orphaned markup), follows the established
  `threat-intel-workbench.html` pattern, and leaves the existing API Keys
  tab untouched. Full suite green: 247 files / 2512 tests (`npx vitest
  run`, up from 246/2508). Registry validator: 0 failures, 0 warnings
  (after correcting two of my own bare-filename evidence citations the
  validator caught — `/automation-dashboard.html` and
  `threat-intel-workbench.html` needed their `frontend/` prefix, and a
  quoted JS literal in the evidence text itself false-matched the
  validator's citation regex, reworded to prose to avoid it).
  `PRODUCTION_READINESS_REPORT.md` regenerated — only the generation
  timestamp changed; this capability's `operational_status` stayed
  `PILOT ONLY` (unchanged) and the report's aggregate severity/parity
  numbers are unaffected.

### 2026-07-12 — 22-paid-feature program, item 2 (of 22): CAP-MYTHOS-003 — a live, unauthenticated endpoint fabricating security-scan/compliance results was redirected to real engines; a dangerous duplicate payment path was removed

- **Resumed after a usage-limit cutoff.** The prior session had reached
  item 2 of the 22-item paid-feature program, found the fabrication
  described below, gotten explicit owner direction to redirect it to real
  engines, and had just spawned 3 parallel research agents to design the
  fix when it hit the usage limit mid-investigation. This session verified
  ground truth first rather than trusting the cutoff transcript: `git
  ls-remote` confirmed `main` was still exactly at `9819fed` (PR #185) with
  `Test & Quality Gate` and `Deploy to Cloudflare` both green on that
  commit; the item-1 (`CAP-RBAC-002`) docs fix had been pushed to an
  abandoned branch (`claude/production-tasks-resume-akvl95`) right before
  the cutoff — cherry-picked onto the correct working branch (commit
  `b66f800`) rather than left orphaned, opened as PR #186.
- **The finding, re-verified directly against source, not just the prior
  session's notes:** `workers/src/handlers/mythosRevenueEngine.js`'s
  `handleMythosScan` (`POST /api/mythos/scan`) pulled a generic,
  not-target-specific intel list from KV and returned **100%-hardcoded**
  Sigma/KQL/Suricata/YARA/SOC-playbook string templates — identical for
  any target except the target name string-interpolated in — plus a fixed
  4-IP IOC list (`45.33.32.156` etc.), branded `CYBERDUDEBIVASH MYTHOS AI
  v30.0.2`, reachable with **zero authentication** (`isPremium(authCtx)`
  silently treats a missing/failed auth resolve as free-tier rather than
  rejecting the call). `handleMythosCompliance` (`POST
  /api/mythos/compliance`) returned a static per-framework lookup table
  with `verification_status` hardcoded `'ALIGNED'` for every organization,
  for any of 7 frameworks. Both were live in production right now, not a
  theoretical risk.
- **3 parallel Explore agents investigated the real-engine landscape**
  (domain-scan engine; rule/compliance-generation engines; the checkout
  path's safety) so the fix could be designed from facts, not
  assumptions:
  - **Real scan engine confirmed real, not another layer of mocking:**
    `workers/src/lib/dns.js`'s `resolveDomain()`/`inferTLSGrade()` make
    genuine Cloudflare DoH queries and a live HTTPS `HEAD` probe against
    the actual submitted target; `workers/src/lib/dnsbl.js`'s
    `fullBlacklistCheck()` queries 7 real threat feeds (Spamhaus DBL/ZEN,
    SURBL, URIBL, ABUSE.CH, Barracuda, SORBS) keyed on that same target.
    `workers/src/handlers/domain.js`'s `buildRealResult()` assembles
    these into the exact result already served to paying customers on
    `/api/scan/domain` — proof of honesty: when DNS doesn't resolve it
    returns `grade: null, risk_level: 'UNKNOWN'` rather than fabricate a
    verdict.
  - **Real rule-generation engine exists but doesn't fit this data
    shape:** `workers/src/services/mythosOrchestrator.js` +
    `workers/src/lib/solutionTemplates.js` genuinely branch on real
    vulnerability-class intel (RCE/SQLI/AUTH_BYPASS/SSRF/DESERIALIZATION)
    with real CVE/MITRE-technique interpolation — real, but built for a
    different taxonomy than domain-hygiene findings (DNS/TLS/email-auth).
    Forcing domain findings through it would itself be a subtle new
    fabrication (mislabeling a missing-DMARC finding as an "RCE Sigma
    rule"). Used the already-real, already-finding-driven
    `mythosEnrichmentEngine.js` instead (MITRE ATT&CK mapping, CyberBrain
    risk scoring, attack-path prediction, autonomous remediation plan, AI
    executive narrative gated on real CRITICAL/HIGH findings) — the same
    genuinely computed enrichment already relied on by `domain.js` and 8
    other handlers.
  - **Real compliance engine confirmed, and already honest:**
    `workers/src/engine.js`'s `complianceEngine()` (used by 6 live
    frontend pages via `compliance.js`) self-labels
    `assessment_mode:'STATIC'`, `live_verification:false` rather than
    claiming a false verified "ALIGNED" result — the right redirect
    target given `handleMythosCompliance`'s input shape (a framework name
    and an org name, no actual control-implementation data to assess
    against). A deeper, real input-driven scorer
    (`services/complianceEngine.js`'s `runComplianceAssessment`) also
    exists for a future "answer a real questionnaire" product, but has no
    frontend today and needs real input data this route doesn't collect —
    out of scope for this fix.
  - **Checkout/webhook path: not dead code, a live latent danger.**
    `handleMythosCheckout`/`handleMythosWebhook` had zero frontend
    callers — but investigation found the one page that looked like a
    match, `frontend/index.html`'s `#mythosOverlay` modal
    (`window.CDB_MYTHOS.open()`), is itself confirmed-unreachable dead
    code: nothing anywhere calls `.open()` on it (every real "Buy" button
    on the platform already goes through the separate, real
    `window.CDB_CHECKOUT_MODAL` system). More seriously: the webhook's
    real HMAC-SHA256-verified handler wrote `UPDATE users SET tier = ?
    WHERE id = ?` to the **exact same column** the platform's actual
    billing path (`payments.js` + `subscriptionPaywallEngine.js`, wired to
    `billing-portal.html`/`upgrade.html`) uses, verified by the same
    shared `RAZORPAY_WEBHOOK_SECRET` — a live, untested, duplicate
    tier-grant mechanism, not inert. It only appeared harmless because (a)
    Razorpay's dashboard likely isn't configured to call this second URL
    and (b) `handleMythosCheckout` never actually minted a real Razorpay
    order — neither of which is a code-enforced protection.
  - Also confirmed via `wrangler.toml`'s `main = "src/index.js"` and the
    single `npx wrangler deploy` step in `deploy.yml`: `workers/index.ts` +
    `workers/webhook.ts` + `workers/health.js` + `workers/trust-center.js`
    + `workers/cve-ingester.js` (a second, genuinely well-built HMAC +
    replay-protected Razorpay webhook with its own `SENTINEL_DB`/
    `SENTINEL_CACHE` bindings) are **orphaned — never bundled by the
    actual deploy**, so they were never a live competing implementation.
    Flagged as a follow-up decision (delete vs. wire up vs. document), not
    touched here.
- **Asked the owner explicitly before touching payment code** (a
  materially different action than "redirect fabricated data" — this was
  a live payment/tier-grant path, not just fake content): chose "remove
  both routes and handlers entirely" over disabling-in-place or
  documenting-only.
- **The fix:** `handleMythosScan` now calls the real
  `resolveDomain`/`inferTLSGrade`/`fullBlacklistCheck` chain, assembles
  via `domain.js`'s `buildRealResult()` (falling back to the honest
  heuristic `domainScanEngine()` only if live DNS itself throws — never to
  fabricated content), and enriches via `enrichAssessmentWithMYTHOS` for
  premium tiers. `handleMythosCompliance` now calls the real
  `complianceEngine()` and the same enrichment. Free/premium gating is
  preserved (findings capped at 2 for free tier; the deep
  `mythos_intelligence` block — real MITRE mapping, attack paths,
  remediation plan, AI narrative — locked behind PRO+, whole rather than
  partially scrubbed, since every field in it is now genuinely computed
  and none of it is safe to give away for free). `handleMythosCheckout`/
  `handleMythosWebhook` and their 2 routes are deleted outright, along
  with their now-dead constants/helpers (`getTxnId`, merchant/pricing/
  crypto-wallet constants, `_processRazorpayWebhook`).
- **Test plan:** new `workers/test/mythosRevenueEngineRealEngines.test.mjs`
  (13 tests) — proves `resolveDomain`/`inferTLSGrade`/`fullBlacklistCheck`
  are called with the real submitted target; proves two different targets
  (clean vs. blacklisted) produce genuinely different risk levels/threat
  intelligence, not a fixed template; proves none of the old fabricated
  IOC/rule-template strings are ever emitted; proves a live-DNS failure
  falls back honestly rather than crashing or fabricating; proves
  free/premium gating of findings and the `mythos_intelligence` block;
  proves `handleMythosCompliance` uses the real STATIC-labeled engine and
  rejects unsupported frameworks; statically proves
  `handleMythosCheckout`/`handleMythosWebhook` are gone from both the
  handler file and the route table. Full suite green: 246 files / 2508
  tests (`npx vitest run`, up from 245/2495). Registry validator: 0
  failures, 0 warnings. `PRODUCTION_READINESS_REPORT.md` regenerated —
  CAP-MYTHOS-003 moves `NOT READY`→`PILOT ONLY`; the report's aggregate
  backend/frontend/parity and severity-gap numbers are unchanged by this
  wave (frontend for this capability is still `missing`, so it stays in
  the same structural bucket — this was a quality fix, not a structural
  one).
- **Follow-ups found, deliberately not fixed here (documented, not
  silently dropped):** (1) `frontend/index.html`'s dead `#mythosOverlay`/
  `CDB_MYTHOS` block (~lines 23082-23353) is confirmed-unreachable and
  could be deleted in a future pass; (2) the orphaned
  `workers/index.ts`/`webhook.ts`/etc. files described above need an
  explicit decision, not silent removal, since they represent real
  engineering effort (a second Razorpay webhook with proper replay
  protection) that was never finished/wired up.

### 2026-07-12 — New program launched: bring all 22 paid/subscription-gated capabilities to genuine production grade — item 1 (of 22): CAP-RBAC-002 re-verified, registry corrected, zero code changes needed

- **Trigger:** with the 24-item Tier 1–3 backlog closed and merged to `main`,
  owner asked for every flagship *paid* feature on the platform to be
  brought to real, complete, customer-usable, production-grade status —
  explicitly not a subset, all 22, across every dimension (frontend,
  backend, APIs, AI workflows, auth, RBAC, security, validation, error
  handling, loading states, performance, testing at every level,
  monitoring, logging, analytics, docs, deployment automation,
  accessibility, responsive UI, onboarding).
- **Scoping:** queried the registry directly rather than guessing —
  `subscription_gated: true` across all 21 domain files returns exactly
  22 capabilities, and **every one** is currently below GA (9 `NOT
  READY`, 13 `PILOT ONLY`; 0 clean `GA APPROVED`), none with
  `customer_journey_complete: true`. 5 of the 6 P2-priority items have no
  working frontend at all. Logged all 22 as tracked tasks (#25–#46).
  Chose to start with `CAP-RBAC-002` (Role/Plan-Based Frontend Feature
  Gating) first, ahead of registry priority order: 8 of the other 21
  capabilities are independently flagged `rbac.enforced: false`, and
  fixing the shared gating mechanism once is better leverage than
  patching that gap ad-hoc in 8 different places later.
- **Investigation found the registry itself was stale, not the code:**
  this entry's own notes said org-role-based gating (OWNER/ADMIN/
  ANALYST/MEMBER/VIEWER) was "entirely unwired… correctly out of scope
  until organization membership itself has a customer-facing UI." That
  UI (CAP-ORG-001, `#page-orgs` in `frontend/user-dashboard.html`) has
  since shipped — confirmed directly in this pass, since this session's
  own earlier work (the onclick-escaping security fix) touched that
  exact code. Read `workers/src/handlers/orgManagement.js` end to end:
  `handleUpdateMemberRole`/`handleRemoveMember`/`handleInviteMember` all
  scope the caller's membership lookup to `WHERE org_id = ? AND user_id =
  <their own id>` — real, correct, per-org isolation with no BOLA/IDOR (a
  user who is OWNER of a *different* org gets no membership row here, not
  cross-org authority). `frontend/user-dashboard.html:2745-2751` computes
  `canManage`/`isOwner` from the real `org.your_role` and hides (not just
  disables) the Invite button, Settings/Audit/Danger-Zone cards, and
  per-member role-change/remove controls to match — line-for-line
  consistent with the server-side rule. `workers/test/orgRbacIsolation
  .test.mjs` (11 tests) already carries its own verdict: "org member
  management is production-grade." Ran it plus 4 sibling test files (69
  tests total) — all pass, unchanged.
- **Conclusion: no code fix needed.** The capability genuinely works,
  correctly and securely, today. The gap was the registry's own record
  never being updated after CAP-ORG-001 shipped. Updated
  `docs/capability-registry/domains/rbac.json`'s `CAP-RBAC-002`: `rbac.
  enforced` → `true` with real permission strings (`org:invite`,
  `org:member:role:change`, `org:member:remove`, `org:audit:read`,
  `org:settings:update`); `operational_status` → `GA APPROVED WITH
  DOCUMENTED LIMITATIONS`; `frontend`/`test_coverage`/`verification`
  evidence extended with the citations above; `last_verified` →
  2026-07-12. **`customer_journey_complete` deliberately left `false`**
  — the validator hard-fails `true` without `verification.method:
  "dynamic_browser"`, and this pass used static code-reading plus the
  existing automated test suite, not a fresh live-browser session against
  this specific UI. Documented that honestly in `notes` as the one real
  limitation, rather than overclaiming. `priority` (P4) left unchanged
  per this file's historical-severity convention.
- **Caught and fixed 2 of my own mistakes before finishing:** first pass
  cited 4 evidence filenames without their full relative path (the exact,
  previously-documented failure mode — `orgManagement.js` instead of
  `workers/src/handlers/orgManagement.js`, etc.) and set
  `customer_journey_complete: true` before checking the validator's
  dynamic_browser requirement. Both caught by `node
  scripts/registry/validate.mjs` (5 hard failures) before commit, not
  after.
- **Verification:** `node scripts/registry/validate.mjs`: 0 failures, 0
  warnings after fixes. Full suite re-run: 245 files / 2495 tests passing
  (unchanged — no source code was touched this item).
  `PRODUCTION_READINESS_REPORT.md` regenerated (operational_status/rbac
  changes affect the aggregate completion numbers, unlike a notes-only
  edit).
- **21 of 22 paid capabilities remain**, continuing in the chosen order
  (high-leverage/foundational items next, then the 5 P2 no-frontend items,
  then the rest).

### 2026-07-12 — Pre-merge security gate: CodeQL caught a real High-severity incomplete-escaping bug in this backlog's own PR before it reached `main`

- **Trigger:** owner asked to verify/validate/audit and merge PR #185 (the
  entire 24-item Tier 1–3 backlog) into `main`. Before merging, checked the
  PR's live CI status rather than assuming green — `total_count: 32` check
  runs, all green except one: a native GitHub code-scanning check named
  `CodeQL` (distinct from the `Analyze (javascript-typescript)`/`Analyze
  (python)` SARIF-generation jobs, both of which had already passed)
  reported `conclusion: failure`, 1 new High-severity alert, rule
  "Incomplete string escaping or encoding", `frontend/user-dashboard.html`
  line 2559.
- **Confirmed real, not a false gate:** line 2559 is this backlog's own
  Tier-3 item #4 code (the API Keys "Usage" button, task #22 earlier this
  session): `onclick="viewKeyUsage('${k.id}', '${label.replace(/'/g,
  "\\'")}')"`. This only escapes a literal `'`, never a literal `\` — a key
  name ending in a raw backslash (fully user-controlled: the key owner
  names their own key at creation) collapses the escaper's own inserted `\`
  together with the label's trailing `\`, which the browser's JS parser
  then reads as a single escaped quote — terminating the string one
  character early and letting the remainder of the label execute as
  trailing script inside the onclick handler. A real, if narrow (self-only
  — the caller can only inject into their own session), DOM XSS.
- **Found a worse sibling while fixing it:** grepped the same file for the
  identical `.replace(/'/g, "\\'")` pattern and found a second, pre-existing
  (not part of this PR's diff — confirmed via `git diff origin/main..HEAD
  -- frontend/user-dashboard.html`'s hunk list, nowhere near this line)
  instance in the Organization "Remove member" button: `onclick=
  "confirmRemoveMember('${org.id}','${m.user_id}','${orgEsc(m.full_name ||
  m.email || m.user_id).replace(/'/g, "\\'")}')"`. This one is strictly
  worse: `orgEsc()` (a `textContent`-round-trip HTML escaper meant for text
  *content*, safe everywhere else it's used in this file) never escapes a
  literal `"` either, so a member's `full_name`/`email` containing a `"`
  breaks straight out of the double-quoted `onclick="..."` attribute with
  no JS-string layer needed at all — and because organization member names
  are set by *other* members, not just the viewer, this is genuine stored
  XSS across users (e.g. any member could plant a payload that fires in the
  org owner's browser when they view the member list), not merely
  self-inflicted like the first one. A third, related instance: the same
  member-role `<select>`'s `aria-label="Change role for
  ${memberLabel}"` used the same under-escaping `orgEsc()` result in an
  attribute context.
- **Fix (`frontend/user-dashboard.html`):** added one new helper,
  `jsAttrEsc(s)`, immediately after the existing `mfaEsc()`: HTML-escapes
  `&<>"` first (delegating to `mfaEsc`, unchanged), then escapes `\` before
  `'` (order matters — escaping the quote first would double the
  backslash the quote-escape itself introduces on a second pass). Used at
  all 3 sites: the Usage button, the Remove-member button, and
  `memberLabel`'s definition (this last one only needed the `mfaEsc()` half
  — no JS-string layer, since `aria-label` isn't parsed as JS — so it was
  switched from `orgEsc()` straight to `mfaEsc()`, not `jsAttrEsc()`).
  `orgEsc()` itself is untouched and remains correct for its ~13 other,
  genuinely text-content-only call sites in this file.
- **Also found, deliberately left alone (out of scope for this PR):** the
  identical `.replace(/'/g, "\\'")` pattern also appears 5× in
  `frontend/index.html` (`dsPurchase`/`initiatePayment`/`CDB_PAYMENT.open`
  buttons, e.g. `:3210,3307,3520,10149,14413`) — confirmed via `git diff`
  that none of those lines are anywhere near this PR's actual `index.html`
  changes (Tier-2 item #3's fake-KPI/badge fix, entirely different section
  of the file). Those use catalog/product data the site owner controls
  (`s.title`/`course.label`), a materially different risk profile than
  free-text user/member names — flagged here as a follow-up worth its own
  dedicated pass, not fixed opportunistically inside an unrelated merge.
- **Verification:** `node --check` on the extracted inline `<script>`
  block. New `workers/test/userDashboardOnclickEscapingFix.test.mjs` (6
  tests): confirms `jsAttrEsc()`'s exact escape order, confirms all 3 call
  sites were updated, and — the real proof — 2 end-to-end tests that
  simulate the actual 2-stage browser parse (HTML-entity-decode the
  escaped output, then hand it to a real JS engine via `new Function` to
  parse as a single-quoted string literal) for a trailing-backslash label
  and a label containing embedded quotes plus an injection attempt,
  asserting both reconstruct to *exactly* the original label with no
  early termination or breakout — the precise mechanism CodeQL flagged.
  Re-ran the 2 pre-existing tests referencing the touched code
  (`userDashboardApiKeysUsageClickFix.test.mjs`,
  `orgAuditLog.test.mjs`) — both still pass unchanged. Full suite: 245
  files / 2495 tests passing (was 244/2489 before this fix — +1 file, +6
  tests). `node scripts/registry/validate.mjs`: 0 failures, 0 warnings.
- **No capability-registry domain JSON edited** — this is a security
  hardening fix to existing rendering code, not a capability-completeness
  change; no domain entry's `description`/`entry_points` scope covers
  "onclick-attribute escaping correctness" as a capability in its own
  right.
- Pushed as an additional commit on top of the 24-item backlog on
  `claude/production-tasks-resume-akvl95` (PR #185) before merging to
  `main`, per the owner's explicit instruction to verify/validate/audit
  first. This is exactly what that gate is for: caught before production,
  not after.

### 2026-07-12 — Tier-3 backlog item #6 (last of 6): threat-intel-workbench.html — APT actor cards rendered raw keyword text instead of an icon glyph — closes the entire 24-item backlog

- **Trigger:** continuing the Tier 1–3 backlog, final item after Tier-3
  item #5.
- **Root cause confirmed against actual code:** the APT Actor Profiles
  panel's `renderActorGrid()` and `showActorDetail()` both rendered
  `${a.icon || '🎭'}` into a small (36px grid / 40px modal) icon box.
  `workers/src/services/aptActorProfiles.js`'s `icon` field turned out to
  be a semantic keyword (`'bear'`, `'dragon'`, `'typhoon'`, `'skull'`,
  `'panda'`, `'worm'`, `'ghost'`, `'lock'`, `'cat'`, `'spider'`,
  `'snake'`), not a display-ready glyph — and every one of the 15 actors
  in `APT_ACTORS` has this field set to a non-empty string. That means
  the `|| '🎭'` fallback was dead code: it never triggered for any real
  actor. Every single APT actor card, for every actor, always rendered
  the literal keyword text crammed into a box sized for one emoji glyph
  — a real, if purely cosmetic, bug matching the audit's description
  once the actual mechanism was found.
- **Fix (`frontend/threat-intel-workbench.html`, frontend-only, no
  backend change needed):** added an `ACTOR_ICON_EMOJI` keyword→glyph
  map (covering all 11 keywords actually used across the dataset) and an
  `actorIconEmoji(a)` helper — falling back to the original 🎭 mask for
  any future unmapped keyword, preserving the original
  degrade-gracefully intent instead of ever printing raw text again.
  Wired into both the grid card and the detail modal, the only two
  actor-icon render sites on the page (a third `relevant_actors` render
  site in the sector-brief panel renders `a.id` text tags, not icons —
  confirmed out of scope).
- **Verification:** `node --check` on the extracted inline `<script>`
  block. New
  `workers/test/threatIntelWorkbenchActorIconFix.test.mjs` (5 tests):
  imports the real `APT_ACTORS` dataset directly and asserts every
  actor's real `icon` keyword is covered by the frontend's map — the
  general form of this bug (an unmapped keyword silently falling
  through to the mask), not just today's 11 instances — plus
  static-parse checks that both render sites use the new helper and
  that the graceful-degradation fallback still exists. Searched
  `workers/test/` for any pre-existing test referencing actor-icon
  rendering — none existed, so no bug-reinforcing assertion needed
  correcting. Full suite: 244 files / 2489 tests passing (was 243/2484
  before this item — +1 file, +5 tests). `node
  scripts/registry/validate.mjs`: 0 failures, 0 warnings.
- **Registry:** `CAP-TIH-003` (`threat-hunting-intel.json`, "Threat
  Intel Pro Workbench (MITRE ATT&CK, APT Actors, STIX/TAXII, AI
  Analyst)") directly covers this exact page and the APT Actor Profiles
  panel specifically (same entry Tier-2 item #1 fixed earlier this
  session). Appended a dated fix paragraph to its `notes` field;
  `test_coverage.has_tests` left unchanged since the new test is
  frontend-only static parse plus a data-shape assertion, not new
  import-based coverage of `handleThreatIntelPro` itself. `node
  scripts/registry/generate-report.mjs` regenerated (only the timestamp
  changed).
- **All 6 Tier-3 items are now fixed. All 24 items in the original
  24-item Tier 1–3 backlog (10 Tier-1 + 8 Tier-2 + 6 Tier-3) are now
  fixed.** The entire follow-up backlog from the full 80-page frontend
  audit — every item queued after the 2 Tier-0 exposures already fixed
  in PR #183 — is closed. Every fix in this backlog followed the same
  discipline: confirm the real root cause against actual code (not just
  the audit's one-line paraphrase), implement the minimal
  root-cause-complete fix, add a real regression test (importing real
  handlers/data directly wherever feasible, static-parse contract tests
  for frontend-only fixes), run the full suite, run the registry
  validator, update the capability-registry entry that already covers
  the fixed capability when one existed (never inventing a new entry for
  a bounded bug fix), and commit/push individually. PR #185 (open) now
  carries every Tier-3 item's commits on top of the earlier Tier-1/Tier-2
  work already merged via PR #184.

### 2026-07-12 — Tier-3 backlog item #5 (of 6): soc-agents.html — the per-agent token-count pill read a field that never existed

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-3
  item #4.
- **Root cause confirmed against actual code:** `updateAgentCard()`'s meta
  row (model · provider · latency · tokens) read
  `result.tokens?.total_tokens`. Traced every route that feeds it
  (`/api/agents/run`, `/api/agents/stream`, `/api/agents/dispatch/:id` —
  all three call the same `runAgent()`, `workers/src/handlers/multiAgentSOC.js`)
  and its underlying `routeAICall()`/`dispatchToProvider()`
  (`workers/src/core/aiProviderRouter.js`): the real, only-ever-produced
  shape is `tokens: { input, output }` — there is no `total_tokens` field
  anywhere in the real response, on any of the three routes. The token
  pill accordingly never rendered, for any agent, on any successful run,
  regardless of real usage — a pure field-path mismatch, not a missing
  backend capability (the backend already correctly tracks and returns
  real usage).
- **Also found while tracing this:** `workers/test/multiAgentSOC.test.mjs`'s
  own `routeAICall` mock used the identical wrong shape
  (`tokens: { total_tokens: 42 }`) — harmless to that file's own
  assertions (which only check property presence via `toHaveProperty
  ('tokens')`, never the inner shape), but a misleading model of the real
  contract sitting right next to the code this fix touches. Corrected to
  the real `{ input, output }` shape in the same change.
- **Fix (`frontend/soc-agents.html`):** `updateAgentCard()` now sums
  `(result.tokens?.input || 0) + (result.tokens?.output || 0)` and only
  renders the pill when that total is truthy — preserving the original
  no-pill-when-no-real-data behavior while actually letting a nonzero
  total render for the first time.
- **Verification:** `node --check` on the extracted inline `<script>`
  block. New `workers/test/socAgentsTokenCountFix.test.mjs` (3 tests,
  static parse): confirms the dead `tokens?.total_tokens` read is gone,
  confirms the real `tokens.input`/`tokens.output` fields are read
  instead, and confirms the pill still degrades cleanly to nothing when
  there's no real usage data. Re-ran the corrected
  `workers/test/multiAgentSOC.test.mjs` in full (42 tests, all still
  passing — the mock-shape correction changed no assertion's outcome).
  Full suite: 243 files / 2484 tests passing (was 242/2481 before this
  item — +1 file, +3 tests). `node scripts/registry/validate.mjs`: 0
  failures, 0 warnings.
- **Registry:** `CAP-MASOC-001` (`masoc.json`, "Multi-Agent SOC — 9
  Parallel AI Security Agents") directly covers this capability — exact
  page and exact entry_points match. Appended a dated fix paragraph to
  its `notes` field; `test_coverage.has_tests` left unchanged since the
  new test is frontend-only static parse, not new import-based coverage
  of any backend `entry_point`. `node
  scripts/registry/generate-report.mjs` regenerated (only the timestamp
  changed).
- **1 Tier-3 item remains** (of 6, the last one), queued next in the
  audit's stated priority order.

### 2026-07-12 — Tier-3 backlog item #4 (of 6): user-dashboard.html — API Keys "Usage" card had no way to ever select a key

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-3
  item #3.
- **Root cause confirmed against actual code:** the backend side of this
  feature was already correct and already tested — `GET
  /api/keys/{id}/usage` (`handleKeyUsage` /
  `getKeyUsageSummary`, `workers/src/handlers/apikeys.js`) works and is
  covered by the pre-existing `workers/test/keyUsageBola.test.mjs`
  (BOLA/IDOR ownership-scoping tests). The bug was entirely on the
  frontend: `renderKeys()` in `frontend/user-dashboard.html` gave every
  key row exactly one action, a "Revoke" button — no click handler, no
  link, nothing — so the adjacent "Usage" card's `#key-usage-table`
  permanently showed its static placeholder, "Select a key to view
  usage," with no way for a user to ever actually select one. Grepped the
  whole file for any dead/mis-wired handler that might already reference
  a usage-selection function — found none; the click interaction never
  existed at all.
- **Fix (`frontend/user-dashboard.html`, frontend-only, no backend
  change needed):** added a second, `btn-outline` "Usage" button to each
  key row (alongside the existing "Revoke" button, not replacing it),
  calling a new `viewKeyUsage(id, label)`. It fetches the existing
  endpoint via `apiFetch` and renders the real response shape into the
  table: one row per module from `today.by_module` (falling back to an
  explicit "No requests yet today" row when empty) plus a summary row
  for `month.total`, with its own loading and error states so the table
  never gets stuck on a spinner.
- **Verification:** `node --check` on the extracted inline `<script>`
  block. New
  `workers/test/userDashboardApiKeysUsageClickFix.test.mjs` (6 tests,
  static parse): `viewKeyUsage()` exists and calls the real endpoint,
  renders into the real `#key-usage-table` element, is actually wired
  onto each rendered row alongside (not instead of) the Revoke button,
  reads the backend's real `today.by_module`/`month.total` fields, and
  degrades gracefully on a failed fetch. Searched `workers/test/` for
  any pre-existing test referencing `viewKeyUsage`/`key-usage-table` —
  none existed, so no bug-reinforcing assertion needed correcting. Full
  suite: 242 files / 2481 tests passing (was 241/2475 before this item —
  +1 file, +6 tests). `node scripts/registry/validate.mjs`: 0 failures,
  0 warnings.
- **Registry:** `CAP-DEVPORTAL-001` (`developer-portal-apikeys.json`,
  "API Key Management (canonical)") directly covers this capability —
  its own description names "per-key usage stats" explicitly and its
  `entry_points` already list `getKeyUsageSummary`/`handleKeyUsage`.
  Appended a dated fix paragraph to its `notes` field documenting the
  gap and the fix; `test_coverage.has_tests` left unchanged since the
  new test is frontend-only static parse, not new import-based coverage
  of any backend `entry_point`. `node
  scripts/registry/generate-report.mjs` regenerated (only the timestamp
  changed).
- **2 Tier-3 items remain** (of 6), queued next in the audit's stated
  priority order.

### 2026-07-12 — Tier-3 backlog item #3 (of 6): user-dashboard.html — Settings' Alert Notifications form had no way to load previously-saved preferences

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-3
  item #2.
- **Root cause confirmed against actual code:** `saveAlerts()` in
  `frontend/user-dashboard.html` already correctly POSTs to
  `/api/auth/alerts` (backed by the real, working `handleAlertConfig`,
  which upserts into the `alert_configs` table). But no GET counterpart —
  neither a backend handler nor a frontend caller — ever existed. Every
  visit to the Settings page rendered the "Alert Notifications" card's
  `#alert-email` dropdown and `#alert-tg` input at their hardcoded HTML
  defaults, regardless of what a returning user had actually saved. A user
  had no way to confirm their alert preferences had taken effect short of
  re-submitting the form blind.
- **Fix:**
  - `workers/src/handlers/auth.js`: added `handleGetAlertConfig`,
    reading the same `alert_configs` row `handleAlertConfig` writes
    (`workers/schema_bootstrap.sql:384-396`). A user with no saved row
    yet gets the form's own blank-state defaults (`email_enabled: true,
    min_risk_score: 0, telegram_enabled: false`) rather than a 404 or
    `handleAlertConfig`'s INSERT-time fallback of `min_risk_score: 70`,
    which this frontend form never actually sends or represents.
  - `workers/src/index.js`: registered `GET /api/auth/alerts` alongside
    the existing `POST` route, both resolving auth via the same
    `resolveAuthV5()` call.
  - `frontend/user-dashboard.html`: added `loadAlerts()`, calling the new
    endpoint via the page's existing `apiFetch()` wrapper and
    reverse-mapping the saved config onto `#alert-email`/`#alert-tg` (the
    exact inverse of `saveAlerts()`'s own forward mapping); wired into
    `showPage()`'s `settings` branch alongside the two pre-existing
    analogous calls (`loadMFAStatus()`, `loadSessions()`).
- **Verification:** `node --check` on both backend files and the
  extracted inline `<script>` block. New
  `workers/test/userDashboardAlertPreferencesGetFix.test.mjs` (10 tests):
  real `node:sqlite`-backed `alert_configs` table (not mocks) proving a
  genuine `handleAlertConfig` POST → `handleGetAlertConfig` GET round
  trip, the no-saved-row default shape, 401/503 gates, boolean
  coercion (not raw SQLite 0/1), and upsert-not-duplicate on a second
  save — plus static-parse assertions that `loadAlerts()` exists, is
  wired into `showPage()`, and references only element ids that really
  exist in the markup. Searched `workers/test/` for any pre-existing test
  referencing `handleAlertConfig`/`alert_configs`/`saveAlerts` — none
  existed, so no bug-reinforcing assertion needed correcting. Full suite:
  241 files / 2475 tests passing (was 240/2465 before this item — +1
  file, +10 tests). `node scripts/registry/validate.mjs`: 0 failures, 0
  warnings.
- **Registry:** no domain JSON edited. Checked all three plausible
  entries first: `CAP-NOTIF-001` (`notifications.json`) covers a
  *different* system entirely — the still-frontend-less Slack/Teams
  webhook preferences backed by `notificationPlatform.js`, unrelated to
  the `alert_configs` table this fix touches; `CAP-PORTAL-001`
  (`customer-portal.json`, "Profile & Security Settings") covers the same
  page but explicitly scopes only profile/password/MFA, not alerts
  (`entry_points` lists only `handleUpdateProfile`/
  `handleChangePassword`); `CAP-IDN-001` (`identity.json`) lists
  `handleAlertConfig` only incidentally inside a broad sign-in-flow
  entry_points array, not as a described capability. None directly
  covers Alert Notifications, so per this file's established convention
  no entry was edited and none was created.
- **3 Tier-3 items remain** (of 6), queued next in the audit's stated
  priority order.

### 2026-07-12 — Tier-3 backlog item #2 (of 6): ops-dashboard.html — a nonexistent element id silently killed the Top Endpoints table 2 lines later

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-3
  item #1.
- **Investigation false starts, corrected before concluding anything:**
  traced both "Top Endpoints"-labeled tables on the page in full — the
  Overview tab's `#top-endpoints` (fed by `loadMetrics()`, reading
  `d.d1.top_endpoints`) and the Usage tab's `#usage-endpoints` (fed by
  `loadUsage()`, reading `d.top_endpoints`). Cross-checked both against
  their real backend response shapes (`handleOpsMetrics` and
  `handleAdminUsage`, `workers/src/handlers/opsEngine.js`) — both DOM ids
  and both field paths were already completely correct. Neither table had
  an obvious bug on direct inspection.
- **Found the real bug via a systematic, whole-file cross-reference instead
  of further inspection of the table code itself:** extracted every literal
  `getElementById('...')`/`querySelector('#...')` id reference in the
  page's inline script and every `id="..."` defined in its HTML, and
  diffed the two sets. Exactly one referenced id had no matching element:
  `wh-bar`. The real element (a KV cache-hit-ratio progress bar) is
  `id="wh-kv-bar"`. `document.getElementById('wh-bar')` always returned
  `null`; the very next statement, `.style.width = ratio + '%'`, threw a
  `TypeError` — silently caught by `loadMetrics()`'s own empty `catch {}`.
  Critically, that throw happens **immediately before, in the same `try`
  block as**, the Top Endpoints table population 2 lines later — so
  execution never reached it. The table itself (DOM id and field path both
  already correct, as established above) never had a chance to render, for
  any visitor, on any page load, ever — a wrong element ID silently
  breaking a *different*, unrelated-looking table via early termination of
  their shared try block, exactly matching the audit's description once
  the real mechanism was found.
- **Fix (`frontend/ops-dashboard.html`):** changed
  `document.getElementById('wh-bar')` to `document.getElementById
  ('wh-kv-bar')` — the one-line, root-cause-complete fix.
- **Verification:** `node --check` on the extracted inline `<script>`
  block; new `workers/test/opsDashboardElementIdFix.test.mjs` (7 tests,
  static parse) — rather than only asserting the one specific string fix,
  formalized the manual diffing process used to find the bug as a
  permanent, general contract test: every literal id reference anywhere in
  the page's script must resolve to a real `id="..."` element (0 orphans
  allowed), which would have caught this exact bug class immediately and
  now guards against any future regression of it anywhere on this page —
  plus specific assertions that `wh-bar` is gone, `wh-kv-bar` is used and
  really exists, and the Top Endpoints table's (already-correct) DOM id and
  field path are unchanged. Searched `workers/test/` for any pre-existing
  test referencing this page — none existed, so no bug-reinforcing
  assertion needed correcting. Full suite: 240 files / 2465 tests passing
  (was 239/2458 before this item — +1 file, +7 tests). `node
  scripts/registry/validate.mjs`: 0 failures, 0 warnings. Updated
  `CAP-ADMIN-001`'s `notes` in
  `docs/capability-registry/domains/administration.json` (it already
  covers `frontend/ops-dashboard.html` and `handleOpsMetrics` specifically)
  to record the fix — `test_coverage.has_tests` deliberately left
  unchanged since the new test is frontend-only static parse, not new
  import-based coverage of `handleOpsMetrics` or any other backend
  entry_point. `node scripts/registry/generate-report.mjs` regenerated
  (only the timestamp changed).
- **4 Tier-3 items remain** (of 6), queued next in the audit's stated
  priority order.

### 2026-07-12 — Tier-3 backlog item #1 (of 6): billing-portal.html — a real USD figure displayed with a ₹ symbol, plus a wrong-currency static placeholder

- **Trigger:** all 10 Tier-1 and all 8 Tier-2 items closed; starting Tier 3
  (minor/cosmetic class), first item.
- **Re-verified against actual code:** the overage-charges tile read
  `u.overage_charges_usd` and rendered it through `fmtINR(n)` (`'₹' +
  Number(n||0).toLocaleString('en-IN')`). Traced the field to its real
  source, `handleGetUsageStats`
  (`workers/src/handlers/enterpriseTransformHandler.js:441`):
  `overage_charges_usd: Math.round(overageUsd * 100) / 100`, where
  `overageUsd` comes from `SELECT SUM(amount_usd) as total FROM invoices
  WHERE ... description='API Overage Charge'` — a genuinely US-dollar
  figure, confirmed by both its own field name and the real DB column it's
  summed from. A customer with real overage charges of, say, $45.50 would
  have seen "₹45.50" on this page — the **wrong currency entirely** (not a
  formatting nit — roughly an 80x difference in real value), directly
  contradicting whatever their actual Razorpay/invoice charge shows.
- **Found a second, related instance while auditing every static currency
  placeholder on the page:** the plan-price tile's static HTML fallback
  read `"$0"`, but the real field that replaces it once data loads
  (`sub.price_inr`) is genuinely INR — every other `*_inr` field on this
  exact page (`monthly-spend`, the upgrade-plan list, invoice rows) is
  already correctly formatted with `fmtINR()`. Grepped the whole file for
  every static `$`-prefixed placeholder (`>\$[0-9]`) to confirm these were
  the only two — `overage-charges`'s own static placeholder ("$0.00") was
  already correct and needed no change, only its *dynamic* JS update was
  wrong.
- **Fix (`frontend/billing-portal.html`):**
  - Added a real `fmtUSD(n)` formatter (`'$' +
    Number(n||0).toLocaleString('en-US', {minimumFractionDigits:2,
    maximumFractionDigits:2})`), matching `fmtINR()`'s existing style.
  - `overage-charges`'s update now calls `fmtUSD(u.overage_charges_usd)`
    instead of `fmtINR(...)`.
  - `plan-price`'s static HTML placeholder corrected from `$0` to `₹0` to
    match the real currency of the data that replaces it.
- **Verification:** `node --check` on the extracted inline `<script>`
  block; new `workers/test/billingPortalCurrencySymbolFix.test.mjs`
  (6 tests, static parse) asserting: `fmtUSD()` is defined; the
  overage-charges assignment uses it (and no longer uses `fmtINR` for that
  field); the overage-charges *static* placeholder was confirmed
  already-correct and unchanged; the plan-price static placeholder now
  reads `₹0` (not `$0`) while its dynamic assignment (`fmtINR(sub.price_inr)`)
  is unchanged; every other real-INR field on the page (`monthly-spend`,
  the upgrade-plan list) still correctly uses `fmtINR()`, confirming the
  fix didn't overcorrect anything that was already right. Checked
  `workers/test/billingPortal.test.mjs` — it tests the *backend*
  `overage_charges_usd` value (confirms the handler computes `4.5`
  correctly) but never asserts anything about frontend currency-symbol
  formatting, so no conflict/reconciliation was needed. Full suite: 239
  files / 2458 tests passing (was 238/2452 before this item — +1 file,
  +6 tests). `node scripts/registry/validate.mjs`: 0 failures, 0 warnings.
  Updated `CAP-BILL-003`'s `notes` in
  `docs/capability-registry/domains/commercial-billing.json` (it already
  covers `frontend/billing-portal.html` as its dedicated page) to record
  the fix. `node scripts/registry/generate-report.mjs` regenerated (only
  the timestamp changed).
- **5 Tier-3 items remain** (of 6), queued next in the audit's stated
  priority order.

### 2026-07-12 — Tier-2 backlog item #8 (last of 8): academy.html — attention-strip CVE/scan counters read fields that never existed, one permanently invisible

- **Trigger:** continuing the Tier 1–3 backlog, final Tier-2 item, next after
  item #7. Closes out Tier 2 entirely.
- **Re-verified against actual code — two independent bugs:** `liveCounters()`
  fetched `GET /api/health` and read `d.cves_tracked`/`d.total_scans`
  directly off the top-level response. Traced the real handler
  (`healthResponseAsync`, `workers/src/index.js:996`): its response has
  **no `cves_tracked` field anywhere** (this endpoint reports D1/KV/cache
  health and scan counts, not CVE counts), and its real scan count is
  nested at `stats.total_scans` — never a top-level `total_scans`. Both
  reads always evaluated to `undefined`.
  1. `#acy-cve` has a static HTML fallback ("3") and no visibility toggle,
     so the failed read was invisible — the counter silently just never
     updated from launch-day placeholder, forever presented as if live.
  2. `#acy-scan` has **no static text of its own at all** and starts
     `style="display:none"` in the markup — clearly designed to be revealed
     by this same script once real data loads. Since the read always failed,
     this element was never populated AND never unhidden — the entire
     "scans completed" strip item has never appeared to any visitor, on any
     page load, since it was built.
- **Fix (`frontend/academy.html`):**
  - `liveCounters()` now fetches `/api/health` (for the real, correctly-
    nested `stats.total_scans`) and `/api/threat-intel/stats` (a second,
    already-public, already-used-elsewhere-this-session endpoint, for a
    real CVE-adjacent figure — `stats.critical`, the platform's real,
    currently-tracked critical-severity CVE count) in parallel.
  - `#acy-scan` now gets both real descriptive text (`"{N} scans
    completed"` — it has no surrounding label in the HTML, unlike `#acy-cve`,
    so the script must supply one) and has its `display:none` cleared once
    a real count arrives.
  - `#acy-cve`'s static fallback copy was corrected from "critical CVEs
    **today**" to "critical CVEs **tracked**": `stats.critical` is a real,
    live, currently-tracked total with no time-boxing, and continuing to
    label it "today" once real (much larger, cumulative) data replaced the
    small static "3" placeholder would have started making a *new* false
    claim — the same class of bug this whole backlog exists to remove, not
    a fix for one.
- **Verification:** `node --check` on the extracted inline `<script>`
  block; new `workers/test/academyLiveCountersFieldPathFix.test.mjs`
  (7 tests, static parse) asserting: the old top-level `d.cves_tracked`/
  `d.total_scans` reads are gone; the real nested `health.stats.
  total_scans` and `intel.stats.critical` paths are used; `#acy-scan`'s
  `display:none` is actually cleared and its text includes a real label
  (not a bare number); the markup itself still starts hidden/textless
  (confirming the JS is solely responsible for revealing it — this wasn't
  redundantly duplicated); the "today" claim is gone and "tracked" is used
  instead. One self-inflicted false failure caught and fixed while writing
  the test: an overly clever regex meant to catch any bare top-level
  `total_scans` read matched this fix's own explanatory code comment
  (which necessarily names the old buggy field); simplified to a precise
  `not.toContain('d.total_scans')` check instead. Searched `workers/test/`
  for any pre-existing test referencing this page — none existed, so no
  bug-reinforcing assertion needed correcting. Full suite: 238 files / 2452
  tests passing (was 237/2445 before this item — +1 file, +7 tests).
  `node scripts/registry/validate.mjs`: 0 failures, 0 warnings. Checked
  `docs/capability-registry/domains/academy.json`'s existing 2 entries
  (`CAP-ACAD-001` covers this exact page but scoped specifically to the
  purchase/verify flow; `CAP-ACAD-002` covers a different page's buy
  buttons) — neither covers the attention-strip counters specifically, so
  no existing entry needed correcting and no new one was added, consistent
  with this session's practice for bounded bug fixes.
  `PRODUCTION_READINESS_REPORT.md` was not regenerated this item since no
  registry domain JSON was touched.
- **All 8 Tier-2 items are now fixed.** All 6 Tier-3 items (minor/cosmetic
  class) remain, queued next in the audit's stated priority order:
  billing-portal.html USD/₹ symbol mismatch; ops-dashboard.html wrong
  element ID breaking the Top Endpoints table; user-dashboard.html
  Notification Preferences with no GET endpoint; user-dashboard.html API
  Keys Usage tab's dead click handler; soc-agents.html's dead token-count
  field; threat-intel-workbench.html's cosmetic APT icon issue.

### 2026-07-12 — Tier-2 backlog item #7 (of 8): agent-threats.html — "Scan My Agent" tool sent zero Authorization header, always 401'd invisibly behind a client-side fallback

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-2
  item #6.
- **Re-verified against actual code:** `runAgentScan()` (behind the "Scan
  My Agent →" button and its modal, "Scan Your AI Agent") POSTs to
  `/api/ai-security/agents/scan` with `{'Content-Type':'application/json'}`
  only — no `Authorization` header anywhere on this page (grep-confirmed
  zero occurrences of `cdb_access`/`cdb_token`/`Authorization` in the whole
  file before this fix). Traced the handler,
  `handleScanAgent` (`workers/src/handlers/aiThreatIntel.js:957`):
  `if (!authCtx?.userId) return err('Auth required', 401);` — a hard gate.
  With no token ever sent, every visitor — including a real, logged-in,
  paying customer — always got a 401 from the real backend.
- **Why this one was invisible in the UI (unlike the god-mode.html panels in
  item #5, which showed a visible error):** the frontend has a complete,
  parallel client-side fallback — "local OWASP LLM Top 10 assessment (no
  server)" — using the identical scoring rules as the backend. Because
  `runAgentScan()` checks `if(r.ok){backendResult=await r.json();}` and the
  401 makes `r.ok` false, it silently falls through to this client-only
  path and renders a complete-looking risk report regardless. The bug had
  zero visible symptom — every visitor always saw a full assessment — but
  the report was never the real one: no real `agent_id`
  (`backendResult.agent_id` never populated, `ai_agent_inventory` never
  written), so "Register & Save Report", advisory alerts for the agent's
  framework, and automated rescans (all explicitly promised right below the
  results) had nothing real to attach to, for anyone, ever.
- **Fix (`frontend/agent-threats.html`):** added a `getAuthToken()` helper
  (checks `sessionStorage['cdb_access']` first — the real key
  `user-dashboard.html`'s login/signup flow writes — falling back to the
  legacy `cdb_token` keys, the same convention already established
  elsewhere this session, e.g. Tier-2 item #5's god-mode.html fix) and
  attached it as `Authorization: Bearer <token>` on the scan request when
  present. The client-side fallback logic itself is unchanged — it's still
  the correct behavior for a genuinely anonymous visitor or a real backend
  outage, just no longer the silent default for every authenticated
  customer too.
- **Verification:** `node --check` on the extracted inline `<script>`
  block; new `workers/test/agentThreatsScanAuthFix.test.mjs` (5 tests) — 2
  real behavioral tests importing `handleScanAgent` directly (confirms a
  401 with no `userId` on `authCtx`, confirms 200 + a real `agt_`-prefixed
  `agent_id` with one) plus 3 static-parse tests confirming
  `getAuthToken()`'s key-priority order, that `runAgentScan()` calls it and
  conditionally sets the `Authorization` header, and that the existing
  `Content-Type`/body construction is unchanged. Searched `workers/test/`
  for any pre-existing test referencing `runAgentScan`/`getAuthToken` — none
  existed (the one hit for `handleScanAgent`'s sibling file,
  `agentThreatAdvisories.test.mjs`, tests a different, unrelated admin
  route) — no bug-reinforcing assertion needed correcting. Full suite: 237
  files / 2445 tests passing (was 236/2440 before this item — +1 file, +5
  tests). `node scripts/registry/validate.mjs`: 0 failures, 0 warnings.
  Updated `CAP-TIH-007`'s `frontend`/`notes` fields in
  `docs/capability-registry/domains/threat-hunting-intel.json` — it already
  listed `handleScanAgent` as an entry point but its `frontend.pages` was
  missing `frontend/agent-threats.html` entirely (only listed
  `frontend/index.html`), and its single `auth_enforced:false` field was
  accurate for the feed/report/radar entry points but not for
  `handleScanAgent`/`handleRegisterAgent`/`handleListAgents` (all 3 hard-
  require auth) — documented that nuance in `notes` rather than overstating
  or understating a single boolean field for a capability that bundles
  entry points with different real auth requirements.
  `node scripts/registry/generate-report.mjs` regenerated (only the
  timestamp changed).
- **1 Tier-2 item remains** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-2 backlog item #6 (of 8): ai-security-assessment.html — free "Live MITRE ATLAS Probe" demo called a POST-only route with GET, always failed

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-2 item #5.
- **Re-verified against actual code:** `openRedTeamDemo()` — the handler
  behind the page's "🔍 See a Live MITRE ATLAS Probe — Free, No Payment"
  button, whose own inline code comment says these probes are "genuinely
  backed by /api/ai-redteam/*, not fabricated demo data" — fetches two
  endpoints in parallel and does
  `if (!techRes.ok || !promptRes.ok) throw new Error('API unavailable')`.
  One of the two, `fetch(API_BASE + '/api/ai-redteam/probe/jailbreak', {
  signal: ... })`, sent no `method`, defaulting to GET. Traced the backend's
  internal router (`handleAIRedTeamPro`,
  `workers/src/handlers/aiRedTeamPro.js:146`): this exact path is registered
  **POST-only** (`path === '/api/ai-redteam/probe/jailbreak' && method ===
  'POST'`); every other method falls through to the router's final
  `404 {error:'Not found'}`. Because `Promise.all` always resolved
  `promptRes.ok` to `false`, the `throw` fired on **every single visit**,
  meaning this entire free demo modal — explicit bait to prove "this is the
  real engine, not a mockup" before asking for ₹99,999 — always showed the
  generic "⚠️ Live demo temporarily unavailable" fallback and never once
  rendered real MITRE ATLAS data to any visitor.
- **Confirmed a bare method fix alone would not be enough:** `probeJailbreak`
  (the real handler behind this route) does `const body = await
  request.json();` unconditionally — a POST with no body at all throws
  (invalid JSON), caught and turned into a 500. The frontend fix needed a
  real JSON body, not just the right verb.
- **Fix (`frontend/ai-security-assessment.html`):** the `/probe/jailbreak`
  fetch now sends `method: 'POST'`, `'Content-Type': 'application/json'`,
  and `body: JSON.stringify({})` — an empty object is sufficient since
  `probeJailbreak` treats both of its read fields
  (`body.technique`/`body.target_model`) as optional. The sibling
  `/api/ai-redteam/techniques` fetch (already correctly GET, matching its
  own GET-only registration) and the page's third `/api/ai-redteam/prompts`
  call (also already correctly GET) were both verified unaffected/correct
  and left untouched.
- **Verification:** `node --check` on the extracted inline `<script>` block;
  new `workers/test/aiRedTeamDemoPostFix.test.mjs` (6 tests) — 3 real
  behavioral tests importing `handleAIRedTeamPro` directly (GET really 404s,
  confirming the root cause; POST with a valid empty-object body really
  returns 200 with real `probeType`/`probes`/`probeCount`; POST with no body
  at all really 500s, confirming the body was a necessary part of the fix)
  plus 3 static-parse tests confirming the frontend's fetch call now
  specifies `method:'POST'`, the JSON headers/body, and that the sibling
  GET-only `/api/ai-redteam/techniques` call was left untouched. One
  self-inflicted false-anchor bug caught and fixed while writing the test:
  an initial `body.indexOf('/api/ai-redteam/probe/jailbreak')` matched this
  fix's own explanatory code comment (placed just above the real fetch
  call, and mentioning the same path) instead of the call site itself;
  corrected to anchor on the fuller `fetch(API_BASE + '/api/ai-redteam/
  probe/jailbreak'` substring, which only the real call contains. Searched
  `workers/test/` for any pre-existing test referencing `openRedTeamDemo`/
  `probe/jailbreak` — none existed, so no bug-reinforcing assertion needed
  correcting. Full suite: 236 files / 2440 tests passing (was 235/2434
  before this item — +1 file, +6 tests). `node scripts/registry/
  validate.mjs`: 0 failures, 0 warnings. No capability registry domain file
  covers `aiRedTeamPro.js`/`ai-security-assessment.html` at all (a
  pre-existing cataloguing gap) — consistent with this session's practice,
  no new capability entry was added for a bounded bug fix;
  `PRODUCTION_READINESS_REPORT.md` was not regenerated this item since no
  registry domain JSON was touched.
- **2 Tier-2 items remain** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-2 backlog item #5 (of 8): god-mode.html — Agentic AI Command Center panels always 401'd, no Authorization header ever sent

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-2 item #4.
- **Re-verified against actual code:** `god-mode.html`'s "Agentic AI Command
  Center" (`loadAnomaly()`/`loadPredict()`/`loadAgentBus()`, added in an
  earlier pass per this page's own code comment: "these three engines are
  real, D1-backed, cron-driven backends with no UI anywhere on the platform
  until now") all call the page's one shared `fetchJson(path)` helper, which
  sent only `{Accept: 'application/json'}` — no `Authorization` header of
  any kind, ever. Traced their backend routes in `workers/src/index.js`:
  `/api/anomaly/*`, `/api/predict/*`, and `/api/agent/*` each resolve
  `authCtx` via `resolveAuthV5` and then hard-gate with
  `if (!isRealUser(authCtx)) return unauthorized();` before dispatching.
  With no token ever sent, **every visitor to this page — including a real,
  logged-in ENTERPRISE customer — always got a 401** on all three panels,
  rendering "Anomaly/Predictive/Agent Bus endpoint error: HTTP 401"
  permanently, regardless of login state.
- **Found the identical root cause one function away, already broken for a
  second, adjacent feature:** `getUserToken()` (used by `buildTriggerHeaders()`
  for the ENTERPRISE "trigger a God Mode run" button) only read
  `localStorage.getItem('cdb_token')` — a legacy key. Cross-checked against
  `frontend/user-dashboard.html`'s real login/signup flow (`saveTokens()`):
  it writes the real, current session token to `sessionStorage['cdb_access']`
  only. This is the exact same bug class already found and fixed once before
  in `frontend/assets/copilot-widget.js` (see
  `workers/test/copilotWidgetDashboardFix.test.mjs`, whose own comment
  explicitly lists `god-mode.html` among the pages still on the old,
  narrower fallback) — confirming this is a real, recurring pattern across
  the codebase, not a one-off. The run-trigger has a partial mitigation
  (an `x-api-key` admin-key fallback), so it wasn't fully dead like the
  panels, but real ENTERPRISE customers' own JWTs were silently never used.
- **Fix (`frontend/god-mode.html`):**
  - `getUserToken()`: now checks `sessionStorage.getItem('cdb_access')`
    first, falling back to the legacy `localStorage`/`sessionStorage`
    `cdb_token` keys unchanged (preserves the admin/OAuth flows that still
    populate those).
  - `fetchJson()`: now calls `getUserToken()` and conditionally attaches
    `Authorization: Bearer <token>` when one is present, fixing all three
    Agentic AI panel loaders (and any other current/future caller of this
    shared helper) in one place.
  - **Deliberately not touched:** a third, separate occurrence of the same
    dead-key read pattern in this file's inline copilot-chat handler
    (`POST /api/copilot/chat`) — that endpoint doesn't hard-require auth
    (no `isRealUser` gate found), so it's a minor personalization/attribution
    gap rather than a fully-broken feature, and is a different widget from
    the named "Agentic AI panels" finding; left alone to keep this fix
    bounded to the two provably-broken (hard 401 / silently-never-used-JWT)
    call sites.
- **Verification:** `node --check` on the extracted inline `<script>` block;
  ran the pre-existing `workers/test/godModeDashboard.test.mjs` (11 tests —
  document hygiene, API contract, security/escaping, syntax) first to
  confirm no regression, then added new
  `workers/test/godModeAgenticPanelAuthFix.test.mjs` (5 tests, static parse)
  asserting: `getUserToken()` checks `cdb_access` before the legacy keys
  (and still falls back to them); `fetchJson()` calls `getUserToken()` and
  conditionally sets the `Authorization` header while preserving the
  `Accept` header; all 3 panel loaders (`loadAnomaly`/`loadPredict`/
  `loadAgentBus`) go through `fetchJson()` with their documented endpoint
  paths. Searched `workers/test/` for any test referencing
  `god-mode.html`/`fetchJson`/`getUserToken` — found 4 hits
  (`adminRevenueShellGating.test.mjs`, `copilotWidgetDashboardFix.test.mjs`,
  `godModeDashboard.test.mjs`, `phase6TruthLocks.test.mjs`); read each and
  confirmed none assert anything about `fetchJson`/`getUserToken`'s
  implementation (copilotWidgetDashboardFix.test.mjs only *mentions*
  god-mode.html in an explanatory comment about a different file) — no
  bug-reinforcing assertion needed correcting. Full suite: 235 files / 2434
  tests passing (was 234/2429 before this item — +1 file, +5 tests).
  `node scripts/registry/validate.mjs`: 0 failures, 0 warnings. No capability
  registry domain file covers the Anomaly/Predictive/Agent-Bus engines or
  their god-mode.html panels at all (a pre-existing cataloguing gap) —
  consistent with this session's practice, no new capability entry was
  added for a bounded bug fix; `PRODUCTION_READINESS_REPORT.md` was not
  regenerated this item since no registry domain JSON was touched.
- **3 Tier-2 items remain** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-2 backlog item #4 (of 8): cyber-defense.html — EPSS/KEV fields never populate on live-NVD lookups + IOC lookup nested-field mismatch

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-2 item #3.
- **Re-verified against actual code — two independent bugs, one backend, one
  frontend:**
  1. **EPSS/KEV never populate:** `cyber-defense.html`'s "Live CVE Threat
     Intelligence Lookup" (`cdLookup()`) calls `GET /api/vulns/cve/:cveId`
     (`handleCVELookup`, `workers/src/handlers/vulnManagement.js`) and reads
     `d.epss_score`/`d.in_kev`. Traced the handler: its primary path (live
     NVD API lookup, the common case for any real, well-known CVE) returned
     only `cvss_score/cvss_vector/cvss_version/severity/cwe/references/
     configurations` — **no `epss_score` or `in_kev` field at all**, because
     NVD's own API carries neither. Only the secondary fallback path (local
     seed data, used only when NVD is unreachable or the CVE isn't in NVD)
     included them. Net effect: the page's own default pre-filled example,
     `CVE-2024-3400` — a real, famous, actively-exploited CISA KEV entry —
     showed EPSS "N/A" and "⚪ Not in KEV" on every normal page load.
  2. **IOC lookup nested-field mismatch:** the same tool's IOC branch calls
     `POST /api/hunt/ioc` (`handleIOCLookup`,
     `workers/src/handlers/threatHunting.js`) and reads `d.virustotal`/
     `d.abuseipdb` directly off the top-level response. Traced the real
     response shape: this endpoint supports batch lookups
     (`{ioc}` or `{iocs:[]}`), so the real per-target result is nested at
     `d.results[0]`, and the real field names inside it
     (`services/iocEnrichmentEngine.js`'s `enrichIOC`) are `raw_data.
     virustotal` (not a top-level `virustotal`) and `abuse_score` (a plain
     0–100 number, not a nested `abuseipdb.abuse_confidence_score`).
     `d.virustotal`/`d.abuseipdb` never existed at any level of the real
     response — the tile always showed 0 malicious engines and "AbuseIPDB
     checked" (the generic fallback text), regardless of the real verdict.
- **Fix:**
  - `workers/src/handlers/vulnManagement.js`: imported the existing
    `fetchEPSS()` (`services/compositeRiskScoring.js`, already used
    elsewhere in this codebase, KV-cached against the real FIRST.org EPSS
    API) and added a small new `fetchKEVIds(env)` helper mirroring its exact
    KV-caching pattern (`kev:ids:cache`, 6h TTL) against the same live CISA
    KEV feed URL `handleKEVFeed` (right below, in the same file) already
    fetches uncached for its own full-catalog-browse use case. The NVD
    live-lookup success path now enriches its response with a real
    `epss_score` (from `fetchEPSS`) and real `in_kev` (CVE-ID membership
    check against `fetchKEVIds`'s cached list) — `in_kev` is `null` (not a
    false "not exploited" claim) if the KEV feed itself is unreachable.
  - `frontend/cyber-defense.html`: the IOC branch now unwraps
    `d.results[0]`, reads VirusTotal stats from `res.raw_data.virustotal`,
    and the abuse score from `res.abuse_score` directly (a number) instead
    of a non-existent nested `abuseipdb.abuse_confidence_score`.
- **Verification:** `node --check` on both modified files; new
  `workers/test/cveEpssKevEnrichmentFix.test.mjs` (7 tests) — 4 real
  behavioral tests importing `handleCVELookup` directly with mocked
  `fetch` (NVD + FIRST.org EPSS + CISA KEV, all three branched by URL) and
  a mock KV, asserting: a KEV-listed CVE gets `epss_score`+`in_kev:true`; a
  genuinely non-KEV CVE gets `in_kev:false`; an unreachable KEV feed yields
  `in_kev:null` (never a fabricated `false`); the new KEV-ids KV cache is
  actually used (a second lookup within the TTL doesn't re-fetch CISA) — plus
  3 static-parse tests confirming `cyber-defense.html`'s IOC branch unwraps
  `d.results[0]` and reads the real `raw_data.virustotal`/`abuse_score`
  paths, with the old buggy code patterns (`= d.virustotal`, `d.abuseipdb
  ?`, `abuse_confidence_score`) confirmed gone. One self-inflicted false
  failure caught and fixed immediately: an overly broad `not.toContain
  ('d.virustotal')` assertion matched this fix's own explanatory code
  comment (which necessarily names the old buggy pattern); narrowed to the
  actual executable-code substring. Searched `workers/test/` for any
  pre-existing test referencing `handleCVELookup`/`cyber-defense.html`/
  these field names — none existed, so no bug-reinforcing assertion needed
  correcting. Full suite: 234 files / 2429 tests passing (was 233/2422
  before this item — +1 file, +7 tests). `node scripts/registry/
  validate.mjs`: 0 failures, 0 warnings. Updated `CAP-TIH-001`'s `notes` in
  `docs/capability-registry/domains/threat-hunting-intel.json` (it already
  documented `handleIOCLookup` and explicitly cited
  `frontend/cyber-defense.html:156` as a caller) to record the frontend fix
  — `test_coverage.has_tests` deliberately left `false` since no new
  import-based test of `handleIOCLookup` itself was added (that handler
  was never the bug; only its frontend consumer's field-path assumptions
  were wrong). No existing registry entry covers `handleCVELookup`/
  `/api/vulns/cve` at all (a pre-existing cataloguing gap, not created by
  this fix) — consistent with this session's practice, no new capability
  entry was added for a bounded bug fix.
  `node scripts/registry/generate-report.mjs` regenerated (only the
  timestamp changed).
- **4 Tier-2 items remain** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-2 backlog item #3 (of 8): index.html — fabricated "PATCHED" KPI, hardcoded "Platform: Operational" badge, and 3 false "CyberBrain V2" claims

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-2 item #2.
- **Re-verified against actual code, found each of the 3 named sub-bugs had
  a distinct root cause requiring its own fix:**
  1. **Fake PATCHED counter:** the Vulnerability Management section's
     "PATCHED" KPI tile (`#vm-patched`) computed
     `Math.floor(s.confirmed_exploited/10)` from the real
     `/api/threat-intel/stats` response — an invented formula with *zero*
     factual relationship to remediation. Traced the full stack looking for
     a real "patched count" field: `handleThreatIntelStats`
     (`workers/src/handlers/threatIntel.js`) only returns
     `total_advisories/critical/high/medium/low/confirmed_exploited/
     ransomware_linked` — no patch-status field exists. A genuine vuln
     lifecycle *does* exist (`workers/src/handlers/vulnManagement.js`'s
     `open→in_progress→testing→patched→...` stage machine, real
     `POST /api/vulns/:id/remediate`), but `handleListVulns` hardcodes
     `stage:'open'` for every CVE sourced from the platform-wide
     `threat_intel` table (the vast majority) — only a small, per-org,
     authenticated-user-created KV subset can ever have a different stage.
     There is no real "how many CVEs has this platform patched" number
     anywhere. Fixed to `statOrDash('vm-patched', null)` (both the success
     and pre-existing catch paths) — the same honest "—" dash this exact
     file's `statOrDash()` helper already shows for every other KPI when
     real data isn't available, with a comment explaining why.
  2. **Hardcoded "Platform: Operational" live dot:** the Command Centers
     mega-widget's header badge (`#cdb-platform-status`, plus its
     `.cdb-live-dot` pulsing green dot) was static HTML — grep-confirmed
     `#cdb-platform-status` appears exactly once in the whole file, never
     assigned to by any script. It always read "Operational" in green
     regardless of real backend health. Found this page *already* runs a
     genuinely real, working health poller two sections earlier — a
     "V21.0 PRODUCTION ENGINE — Real API data only. Zero hardcoded/fake
     metrics" IIFE that fetches `/api/platform/health` every 90s and
     correctly branches on real `OK`/`DEGRADED`/`DOWN` status for a warning
     banner and the SOC live-log feed — it simply never updated this badge.
     Fixed by extending that existing poller (both its success and its
     `.catch` failure path) to also set the badge's text/CSS class and the
     dot's color from the same real `st` value, rather than adding a second,
     redundant poller. Added the one missing CSS variant needed
     (`.cdb-status-red`, for `DOWN` — only green/amber existed).
  3. **3 false "CyberBrain V2" claims:** the MYTHOS AI Analyst chat panel's
     header badge ("POWERED BY CYBERBRAIN V2") and status line ("ONLINE ·
     CyberBrain V2 active"), plus a third, separate "AUTONOMOUS SOC MODE ·
     CYBERBRAIN V2" badge — all claim a "CyberBrain V2" engine powers these
     features. Traced the real call chain: this chat panel's
     `cdbAnalystSend()` calls `POST /api/ai/chat` →
     `handleAIChat` (`workers/src/handlers/aiAnalysis.js`) → a
     template-based intent-detection/response-builder (grounded in real CVE
     data via `lookupCveIntel()`, but not an LLM call and not CyberBrain).
     The platform's *real* CyberBrain engine
     (`workers/src/core/cyberBrain.js` / `services/cyberBrainEngine.js`) is
     a completely separate, genuinely-versioned-v20.0 module used for
     scan-result enrichment (`enrichScanWithBrain`) — never imported by
     `handleAIChat` or anywhere near this UI. "V2" corresponds to no real
     version of anything; the domain's own `CAP-MYTHOS-001` registry entry
     already documented a closely-related naming collision ("'MYTHOS' is
     also the customer-facing AI-chat-widget brand name... UI branding
     only") without yet catching this third, CyberBrain-specific
     mislabeling. Fixed all 3 occurrences to plain, accurate "MYTHOS"
     branding — matching what the real backend actually is, and matching
     the correct "MYTHOS AI ENGINE"/"MYTHOS AI Analyst" labels already used
     one line above each fix site.
- **Verification:** `node --check` on both extracted inline `<script>`
  blocks containing the JS edits (the `vm-patched` fix and the extended
  health poller); new `workers/test/indexFabricatedStatsAndStatusFix.test.mjs`
  (9 tests, static parse) asserting: the fabricated `Math.floor(.../10)`
  formula is gone and both `vm-patched` call sites pass `null`; the platform
  dot has a targetable id and a red status class now exists; the real
  health poller's body now references both the badge and dot ids in both
  its success and failure paths, with each real status value driving a
  distinct real label (`OK`→"Operational", `DEGRADED`→"Degraded",
  `DOWN`→"Down"); zero case-insensitive occurrences of "CYBERBRAIN V2"
  remain anywhere in the file; all 3 corrected badges read the accurate
  MYTHOS branding. Searched `workers/test/` for any pre-existing test
  referencing these strings/ids — none existed, so no bug-reinforcing
  assertion needed correcting. Full suite: 233 files / 2422 tests passing
  (was 232/2413 before this item — +1 file, +9 tests).
  `node scripts/registry/validate.mjs`: 0 failures, 0 warnings (after fixing
  one JSON syntax error of my own making — a stray trailing period after a
  closing quote in `CAP-MYTHOS-001`'s `notes` field, caught immediately by
  `python3 -c "import json; json.load(...)"` before the validator run).
  Updated `CAP-MYTHOS-001`'s `notes` in
  `docs/capability-registry/domains/mythos-godmode.json` to record this
  third naming-collision fix alongside the two the entry already documented.
  `node scripts/registry/generate-report.mjs` regenerated (only the
  timestamp changed).
- **5 Tier-2 items remain** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.
- **Also fixed in this entry's commit:** my own `old_string`/`new_string`
  Edit for inserting this entry initially dropped the `## Session log (most
  recent first)` heading above it — the same mistake documented earlier in
  this session's item #5/#6 entries. Caught immediately via
  `grep -c "^## Session log"` returning 0 right after the edit; restored
  before this commit.

### 2026-07-11 — Tier-2 backlog item #2 (of 8): sentinel-apex-marketplace.html — Threat Actor and Malware intel cards were 100% fabricated static data

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-2 item #1.
- **Re-verified against actual code:** the page's Intelligence tabs
  (`loadIntelTab()`, line ~740) dispatch to 4 loader functions —
  `loadCVECards()`, `loadThreatActorCards()`, `loadMalwareCards()`,
  `loadReportCatalogGrid()`. `loadCVECards()` was already correctly fixed in
  an earlier pass (real fetch to `/api/v1/intel/latest.json`, honest
  "temporarily unavailable" fallback on failure — explicit code comments at
  lines 753-754/796-797 document this). `loadThreatActorCards()` (line 806)
  and `loadMalwareCards()` (line 840), by contrast, had **zero fetch calls of
  any kind** — a fixed JS array of 6 hardcoded objects each, unconditionally
  rendered every single page load, no live/fallback distinction at all. Two
  of the malware entries were entirely invented with no basis in this
  platform's own data (`'AI-Enhanced RAT'`, `'BianLian'` — neither appears in
  `workers/src/handlers/intelligencePreview.js`'s real `MALWARE_FAMILIES`
  dict), and every numeric "Risk Score" (9.8, 9.5, 8.9, …) and "Vector"
  string was fabricated prose with no backing field in any real API. This
  page's own meta description and hero copy advertise "Live CVE
  intelligence, threat actor dossiers, malware reports... powered by
  SENTINEL APEX™" — every visitor saw the identical static fiction
  presented as live, regardless of what the platform's real intelligence
  actually contains.
- **Found real, already-working backend sources for both, requiring no new
  capability:** `GET /api/intel/actors` (`workers/src/handlers/threatIntelPro.js`,
  confirmed public/no-auth-required in the Tier-2 item #1 investigation
  immediately prior) already serves the platform's real APT actor database
  (`workers/src/services/aptActorProfiles.js`'s `APT_ACTORS`, 60+ tracked
  groups with real `id`/`aliases`/`origin`/`target_sectors`/`known_tools`/
  `risk_score` fields) — the exact same backend `threat-intel-workbench.html`
  already uses. For malware, `GET /api/preview/malware/:familyId`
  (`workers/src/handlers/intelligencePreview.js`) serves a real, curated
  `MALWARE_FAMILIES` dict (8 families: lockbit, blackcat, cobeacon, qakbot,
  emotet, icedid, sliver, metasploit) with real `name`/`malware_type`/
  `severity`/`active_in_wild`/`summary` fields — confirmed public (only a
  FREE-tier + logged-in rate limit applies; anonymous calls are unmetered,
  a separate pre-existing characteristic of that router not touched here
  since these are cheap DB/dict lookups, not LLM calls — not the same
  cost-abuse class as Tier-2 item #1). No "list all malware families"
  endpoint exists yet, only this single-id preview; rather than add a new
  backend route (out of scope for a bug fix), the frontend now fetches a
  fixed set of 6 of the 8 known real family ids in parallel and renders
  only the real fields the API returns — the *content* is never invented
  client-side, only the *list of ids to ask about* is client-known, the
  same pattern `tools.html`'s marketplace already uses for its own catalog.
- **Fix (`frontend/sentinel-apex-marketplace.html`):**
  - `loadThreatActorCards()`: now fetches `/api/intel/actors`, maps up to 6
    real actors (severity bucketed from real `risk_score`: ≥90 CRITICAL,
    ≥75 HIGH, else MEDIUM; tactics from real `known_tools`/`motivation`;
    sectors from real `target_sectors`), and falls back to a new
    `renderFallbackThreatActors()` honest-unavailable state (mirroring
    `renderFallbackCVEs()`'s exact pattern) if the feed is empty or the
    fetch fails — never the old fabricated array.
  - `loadMalwareCards()`: now fetches `/api/preview/malware/:id` for 6 known
    real family ids in parallel, renders only real returned fields
    (`name`, `malware_type`, `severity`, `active_in_wild`, `summary`), and
    falls back to a new `renderFallbackMalware()` honest-unavailable state
    on total failure — never the old fabricated array.
  - All backend-sourced display text now passed through the page's existing
    `escHtml()` helper (already used by `loadCVECards()`) before injection.
  - The "Buy Dossier"/"Buy Report" purchase-modal buttons and
    `openModal(...)` wiring are unchanged — this fix only replaces the data
    source, not the purchase flow (already covered by CAP-MKT-003).
- **Verification:** `node --check` on the extracted inline `<script>` block;
  new `workers/test/sentinelApexMarketplaceRealIntel.test.mjs` (10 tests,
  static parse, same convention as this session's other frontend-fix tests)
  asserting: both loaders fetch the real endpoints and read the real
  response shapes; neither contains the old hardcoded array literal; the
  fabricated static roster (`AI-Enhanced RAT`, `BianLian`, the fake risk-
  score/vector literals, `SideCopy (Pakistan)`, `Scattered Spider`) is gone
  from the file entirely; both new fallback functions exist and are honest
  ("temporarily unavailable", not a re-hidden fabricated list); both loaders
  escape backend-sourced fields via `escHtml()`. Searched `workers/test/`
  for any pre-existing test referencing this file or these two function
  names — found 3 unrelated hits (`marketplaceDeadCodeRemoval.test.mjs`,
  `seoStructuredDataTruth.test.mjs`, `truthClaims.test.mjs`); read each
  reference and confirmed none assert anything about the Threat Actor/
  Malware cards specifically (`truthClaims.test.mjs`'s two
  `sentinel-apex-marketplace.html` describe blocks cover the CVE feed and
  report catalog only — both already-fixed, different functions) — no
  bug-reinforcing assertion needed correcting. Full suite: 232 files / 2413
  tests passing (was 231/2403 before this item — +1 file, +10 tests).
  `node scripts/registry/validate.mjs`: 0 failures, 0 warnings.
  `node scripts/registry/generate-report.mjs` regenerated (only the
  timestamp changed — no capability registry entry was touched: none of
  this domain's existing 6 `CAP-MKT-*` entries cover the intel-grid preview
  cards specifically, only the separate purchase/checkout flows, so there
  was no existing entry to correct; adding a brand-new capability entry for
  a previously-uncatalogued feature was judged out of scope for a bounded
  bug fix, consistent with how Tier-1 items #1–#10 and this same page's
  earlier CVE-feed fix were handled).
- **6 Tier-2 items remain** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-2 backlog item #1 (of 8): threat-intel-workbench.html — AI Analyst / CVE-brief / sector-brief routes had zero auth and zero rate limiting

- **Trigger:** all 10 Tier-1 items closed (see the entry immediately below);
  starting Tier 2, first item.
- **Re-verified against actual code, traced the full call chain from the
  frontend through to the LLM provider:** `threat-intel-workbench.html`'s
  AI Analyst chat (`sendChat()` → `POST /api/intel/analyst/query`, line 1405)
  is dispatched by `index.js:5251-5273` to `handleThreatIntelPro()`
  (`workers/src/handlers/threatIntelPro.js`) with `authCtx` best-effort —
  `resolveAuthV5(...).catch(() => null) || {}`, i.e. it never rejects the
  request even if auth resolution fails entirely. Inside that handler, the
  `analyst`/`analyst/query` route (line 513, pre-fix) called `analyzeQuery()`
  (`workers/src/services/aiThreatAnalyst.js`) — a **real LLM call** via
  `callLLM()` — with no auth check, no tier check, and no rate-limit check
  of any kind anywhere in the file. Two sibling routes in the same handler
  have the identical defect: `cve-brief/:id` (line 471, calls
  `generateCVEBrief()` → LLM) and `sector/:sector` (line 439, calls
  `generateSectorBrief()` → LLM). All three were reachable by any anonymous
  visitor, unlimited times — every request is billed as real third-party LLM
  API usage, a genuine open cost-abuse vector (this domain's own registry
  entry, CAP-TIH-003, already recorded `auth_enforced: false` and
  `test_coverage.has_tests: false` for this exact handler — corroborating,
  not new information invented for this fix).
- **Found the fix should reuse existing, tested infrastructure rather than
  invent new:** `workers/src/middleware/rateLimit.js` already exports
  `checkRateLimitCost(env, authCtx, endpoint)` + `rateLimitResponse(result,
  module)`, a KV-backed, tier-aware, cost-weighted quota system with an
  established `ENDPOINT_COST` registry — already used identically by
  `handlers/threatHunting.js` (`'hunt'`, `'hunt/ioc'`),
  `handlers/vulnManagement.js` and `handlers/auditLog.js` for their own
  costly operations. `authCtx.identity`/`authCtx.tier` are reliably
  populated even for anonymous callers: `resolveAuthV5()`'s IP-fallback
  branch (`auth/middleware.js:242-253`) sets `identity: `ip:${ip}``,
  `tier: 'FREE'` for any keyless/session-less request, so the quota keys
  correctly per-IP instead of collapsing to one shared anonymous bucket.
  Confirmed a **different**, unrelated `/api/intel/*` product
  (`handlers/intelAPIHandlers.js`'s `ioc`/`cve`/`actor`/`ttp`/`risk`
  developer-API-key economy, its own `checkIntelQuota()`) exists at
  overlapping-looking but distinct route paths — deliberately left
  untouched; conflating the two would entangle an unrelated monetized
  product's tier policy with this workbench's AI-chat feature.
- **Fix:**
  - `workers/src/middleware/rateLimit.js`: added 3 new `ENDPOINT_COST`
    entries — `'intel/analyst': 2, 'intel/cve-brief': 2, 'intel/sector': 2`
    (cost 2 mirrors the existing `'ai/chat': 2` entry — same class of
    operation).
  - `workers/src/handlers/threatIntelPro.js`: imported
    `checkRateLimitCost`/`rateLimitResponse`; added `const rl = await
    checkRateLimitCost(env, authCtx, '<endpoint>'); if (!rl.allowed) return
    rateLimitResponse(rl, '<module>');` as the first action inside each of
    the 3 LLM-calling route blocks, before any D1 query or LLM call.
  - **Deliberately not touched:** `auth_enforced` stays `false` — this fix
    closes the cost-abuse gap via a per-IP/per-tier daily quota (~5 calls/day
    for anonymous/FREE callers under `TIERS.FREE`'s 10-cost-unit budget,
    scaling up by tier), not by requiring login; the other ~12 non-LLM
    sub-routes in the same handler (actors, tactics, techniques, heatmap,
    STIX/TAXII, etc.) were not part of this finding and are untouched.
- **Verification:** `node --check` on both modified `.js` files; new
  `workers/test/threatIntelProAiRateLimit.test.mjs` (12 tests) — mocks
  `middleware/rateLimit.js` and the LLM-calling service functions
  (`analyzeQuery`/`generateCVEBrief`/`generateSectorBrief`) to assert: each
  of the 3 routes calls `checkRateLimitCost` with its distinct endpoint key
  before any LLM work; a denied quota returns 429 and never invokes the LLM
  function; an allowed quota proceeds normally (asserted via the mocked LLM
  functions actually being called); the GET `?q=` alias at `/api/intel/analyst`
  is gated identically to the POST path; an unrelated sibling route
  (`/api/intel/actors`) is confirmed NOT gated by the new check (guards
  against a future overly-broad refactor); a static source-check pins the 3
  new `ENDPOINT_COST` entries. Searched `workers/test/` for any pre-existing
  test referencing `threatIntelPro.js` or these route paths — none existed
  (matches the registry's own "zero test coverage" finding), so no
  bug-reinforcing assertion needed correcting. Full suite: 231 files / 2403
  tests passing (was 230/2391 before this item — +1 file, +12 tests).
  `node scripts/registry/validate.mjs`: 0 failures, 0 warnings.
  `node scripts/registry/generate-report.mjs` regenerated (only the
  timestamp changed). Also updated CAP-TIH-003's `test_coverage`,
  `verification.evidence` and `notes` fields in
  `docs/capability-registry/domains/threat-hunting-intel.json` to record
  the fix and the now-partial (3-of-~15-sub-routes) test coverage — first
  fixing a validator hard-failure of my own making (bare filenames like
  `mitreAttackService.js` in the new evidence text resolved against repo
  root and failed the "cited file must exist" check; corrected to the full
  `workers/src/services/...` paths the validator requires).
- **7 Tier-2 items remain** (of 8), plus all 6 Tier-3 items, queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-1 backlog item #10 (last of 10): tools.html — Tools/AI/Marketplace grids crashed empty + Marketplace wrong-catalog Buy Now 404s

- **Trigger:** continuing the Tier 1–3 backlog, final Tier-1 item, next after
  item #9.
- **Re-verified against actual code — found the real bug was worse than the
  audit's one-line paraphrase ("'Buy Now' 404s ... falls back to WhatsApp
  quoting the wrong price"), and traced it to three separate, compounding
  defects across `renderOfficialTools()`, `renderAITools()` and
  `renderMarketplace()`:**
  1. **All three render functions built their Buy button's price argument
     via `price.match(/\\d+/)[0]`** — a regex literal with a *doubled*
     backslash (confirmed byte-for-byte with `cat -A`/`od -c`, not a display
     artifact). `/\\d+/` matches a literal backslash character followed by
     digits, which never appears in a `'₹999'`-style string, so `.match()`
     always returned `null` and `null[0]` threw a `TypeError` — synchronously,
     during template-literal evaluation inside the `Array#map` callback.
     A throw inside a `.map()` callback aborts the *entire* `.map()` call, so
     `grid.innerHTML` was never assigned. Net effect: `officialToolsGrid`
     (for any premium item), `aiToolsGrid` (unconditionally — every AI tool
     has a Buy button) and `marketplaceGrid` (unconditionally, both live and
     fallback data) rendered **nothing at all**, for every visitor, not just
     a broken purchase button on an otherwise-visible catalog.
  2. **`renderOfficialTools()`'s live `/api/tools/catalog` path dropped
     `category`/`description`** when mapping API tools to render objects —
     even after fixing the regex, every API-sourced card would have shown
     the literal text "undefined" for its category badge and description
     (the fallback array already carried both fields; only the live-API
     mapping forgot them).
  3. **`renderMarketplace()` read `item.demand`/`item.cve`/`item.price`**,
     but the real `/api/defense/solutions` response (`enrichSolution()` in
     `workers/src/handlers/defenseMarketplace.js`) returns
     `demand_score`/`cve_id`/`price_inr` (a number, no `.price` string field
     at all) — so every live listing silently showed the hardcoded fallback
     demand (75%), CVE ('N/A') and price (₹999) instead of its real values.
  4. **Worse, "Buy Now" on a live (API-sourced) marketplace item was wired to
     `cdbToolBuy()` → `POST /api/tools/purchase`**, which looks up
     `TOOLS_CATALOG[product_id]` — a small static dict of ~28 fixed product
     IDs in `workers/src/handlers/toolsMarketplace.js` covering the Official
     Tools and AI Tools sections only. Every dynamic `defense_solutions` row
     ID (the Marketplace section's real, live inventory) is absent from that
     dict, so the purchase call always returned `404 {error:'Product not
     found'}`, tripping `cdbToolBuy`'s `manualFallback()` — which opens a
     WhatsApp deep link quoting the `priceNum` already computed wrong by
     defect #3 above (hardcoded ₹999 instead of the item's real `price_inr`).
     The correct backend endpoints for these dynamic solutions
     (`POST /api/defense/purchase/:id` + `POST /api/defense/verify/:id`,
     `handleInitiatePurchase`/`handleVerifyPurchase` in
     `defenseMarketplace.js`) already existed, fully implemented and
     correct — nothing in the frontend called them.
  Confirmed the Official Tools (`fallbackOfficialTools`), AI Tools
  (`aiTools`, no live fetch at all) and Marketplace-fallback
  (`fallbackMarketplace`) hardcoded arrays' product IDs *do* all exist in
  `TOOLS_CATALOG` — so `cdbToolBuy`/`CDB_PAY.open` remains correct for every
  item sourced from those three arrays; the wrong-catalog defect is scoped
  specifically to Marketplace items sourced from the live
  `/api/defense/solutions` fetch.
- **Fix (`frontend/tools.html`):**
  - Changed all three `match(/\\d+/)` occurrences to the correct single-
    backslash `match(/\d+/)` (lines in `renderOfficialTools`, `renderAITools`,
    `renderMarketplace`).
  - `renderOfficialTools()`: added `category: t.category || '', description:
    t.description || ''` to the live-API tool mapping.
  - `renderMarketplace()`: reads `item.demand_score ?? item.demand ?? 75` and
    `item.cve_id || item.cve || 'N/A'`; builds `priceNum`/`price` from
    `item.price_inr` (numeric) when present, falling back to parsing
    `item.price` (fallback-array string) otherwise; tracks a new
    `liveSource` flag (true only when the live fetch actually returned
    solutions) and branches the Buy button's `onclick` accordingly.
  - Added a new `cdbBuySolution(solutionId, priceInr, label)` function
    (in the same bottom-of-file Razorpay-checkout IIFE as `cdbToolBuy`,
    reusing its `loadRzp()` loader and manual/WhatsApp-fallback shape) that
    posts to `/api/defense/purchase/:id` and `/api/defense/verify/:id`
    instead, adapted to that endpoint's real response field names
    (`order.order_id`, not `order.razorpay_order_id`; `vData.solution_title`,
    not `vData.product_name`; no `product_id`/`email` in the verify body —
    the solution ID lives in the URL). Exposed as `window.cdbBuySolution`.
    Live-sourced Marketplace items now call this; fallback-array items keep
    calling `window.CDB_PAY.open()` (→ `cdbToolBuy`) exactly as before,
    since their IDs are genuinely in the static `TOOLS_CATALOG`.
- **Verification:** `node --check` on both extracted inline `<script>`
  blocks; new `workers/test/toolsMarketplaceFieldAndPurchaseFix.test.mjs`
  (14 tests, pure static parse of the raw HTML — same convention as this
  session's other frontend-fix tests) asserting: the doubled-backslash regex
  is gone from all three render functions; `renderOfficialTools` carries
  `category`/`description` through; `renderMarketplace` reads the real
  `demand_score`/`cve_id`/`price_inr` fields; `renderMarketplace` routes
  `liveSource` items to `window.cdbBuySolution` and fallback items to
  `window.CDB_PAY.open`; `cdbBuySolution` is defined, exported on `window`,
  calls the `/api/defense/purchase|verify/:id` endpoints (never the
  `/api/tools/*` ones), and correctly falls back to the manual/WhatsApp flow
  when no real Razorpay order is returned. Searched `workers/test/` for any
  pre-existing test referencing `tools.html`/these function names — none
  existed, so no bug-reinforcing assertion needed correcting. Full suite:
  230 files / 2391 tests passing (was 229/2377 before this item — +1 file,
  +14 tests). `node scripts/registry/validate.mjs`: 0 failures, 0 warnings
  (unchanged — no capability registry entries touched by this item).
  `node scripts/registry/generate-report.mjs` regenerated (only the
  timestamp changed — same 97 capabilities, same Backend/Frontend/Parity
  percentages, still **NOT READY**, as expected since this item fixed
  existing capabilities' bugs rather than adding new capabilities).
- **This closes all 10 Tier-1 items from the full-frontend audit.** 14 of
  the 24-item backlog remain: all 8 Tier-2 items (cost-abuse / misleading-
  data class) and all 6 Tier-3 items (minor/cosmetic class), queued next in
  the audit's stated priority order.

### 2026-07-11 — Tier-1 backlog item #9: developer-onboarding.html — trial-key tier normalization bug

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #8.
- **Re-verified against actual code, traced through 3 files to the real
  root cause:** `handleTrialKeyRequest`
  (`workers/src/handlers/developerOnboardingHandler.js`) computes
  `tier = normalizeTier(TRIAL_TIER)` where `TRIAL_TIER = 'COMMUNITY'`.
  `normalizeTier()` (`subscriptionPaywallEngine.js`) correctly returns the
  string `'COMMUNITY'` — the canonical modern tier vocabulary
  (`COMMUNITY/PROFESSIONAL/TEAM/BUSINESS/ENTERPRISE`) this codebase is
  migrating toward. That value is then passed straight into
  `createApiKey(env.DB, userId, tier, ...)` (`auth/apiKeys.js`), whose
  rate-limit lookup is `const limits = TIER_LIMITS[userTier] ||
  TIER_LIMITS.FREE` — but `TIER_LIMITS` only had entries for the *legacy*
  vocabulary (`FREE/STARTER/PRO/ENTERPRISE/MSSP`). `TIER_LIMITS['COMMUNITY']`
  is `undefined`, so every trial key silently fell back to
  `TIER_LIMITS.FREE` (5 req/day, 50/month) — baked into the key's
  `daily_limit`/`monthly_limit` columns at creation time — contradicting
  the 100 req/day this exact page advertises (meta description, pricing
  table) and `SUBSCRIPTION_TIERS.COMMUNITY`'s own real definition
  (100/day, 3,000/month, burst 5/min).
- **This is the identical bug class `TIER_LIMITS`'s own comment already
  documents being fixed once before:** "Missing entries here fall back to
  TIER_LIMITS.FREE ... MSSP customers were silently rate-limited as FREE."
  Same root cause, different missing tier.
- **Fix:** added a `COMMUNITY` entry to `TIER_LIMITS`
  (`daily_limit: 100, monthly_limit: 3000, burst_per_min: 5`, mirroring
  `SUBSCRIPTION_TIERS.COMMUNITY` exactly; other fields — `price_inr`,
  `scan_limit`, `api_keys`, `ai_access` — mirror `TIER_LIMITS.FREE`, since
  `subscriptionPaywallEngine.js`'s own comments establish COMMUNITY as
  the new name for the same free-tier concept:
  `FREE: null, // resolved to COMMUNITY at runtime`). Purely additive —
  no existing tier's values changed. `api_keys.tier` has no CHECK
  constraint (confirmed against `schema_bootstrap.sql`; unlike
  `users.tier`, which does and is why that INSERT correctly hardcodes the
  literal `'FREE'` already), so storing `'COMMUNITY'` there was always
  schema-safe — the bug was purely the missing rate-limit lookup entry.
- **Not touched:** `TIER_LIMITS.FREE` itself (used by real non-trial FREE
  signups elsewhere) — changing its value would be a much broader,
  unrelated change outside this bug's scope.
- **Tests:** extended the existing `test/developerOnboardingHandler.test.mjs`
  (already covers `handleTrialKeyRequest` with a real mock D1/KV env) — its
  `INSERT INTO api_keys` mock now also captures `daily_limit`/`monthly_limit`
  (previously ignored), and a new test asserts a fresh trial key gets
  `tier: 'COMMUNITY'`, `daily_limit: 100`, `monthly_limit: 3000` — not the
  old FREE-fallback 5/50. All 16 pre-existing tests in that file still
  pass unchanged. Full suite green: 229 files / 2377 tests (baseline
  229/2376 from Tier-1 item #8 — no new test *file*, extended an existing
  one).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#8). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (15 of 24):** next up: `tools.html`'s
  marketplace field mismatches + Buy Now 404s (Tier-1 #10, the last Tier-1
  item), then all of Tier 2/3 (full original list in the audit entry ten
  below).

### 2026-07-11 — Tier-1 backlog item #8: user-dashboard.html — My Trainings/My Purchases envelope-unwrap bug (plus a third, previously unnamed tab with the identical bug)

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #7.
- **Re-verified against actual code — found the real bug is one level
  deeper than the audit's paraphrase:** the finding said "both read
  data.deliveries; the real endpoint returns data.purchases." Reading
  `handleMyPurchases` (`workers/src/handlers/delivery.js`) directly:
  it returns `jsonOk({purchases, total})`, and `jsonOk()` wraps *every*
  response in this codebase's standard `{success, data, error, timestamp}`
  envelope. So the real path is `response.data.purchases` — fixing only
  the field name (`data.purchases` instead of `data.deliveries`, without
  also unwrapping the envelope) would have left the bug exactly as broken,
  just failing at a different property access. `loadMyTrainings()` and
  `loadMyDeliveries()` both had this exact double gap.
- **A third, unnamed tab found with the identical bug while fixing the
  named two:** `loadUserReports()` ("My Reports") calls
  `GET /api/user/reports` (`handleUserReports`, same file, same `jsonOk()`
  envelope, real field `reports`) as its primary source, falling back to
  `/api/delivery/my-purchases` on empty. Both its primary read (`d?.reports
  || d?.deliveries`) and its fallback read (`d2?.deliveries || d2?.purchases`)
  had the same missing-envelope-unwrap bug — the fallback's own
  `d2?.purchases` addition (from some earlier, partial fix attempt) was
  still wrong for the same reason, just one property deeper into the
  wrong object. This tab was not named in the original audit finding but
  shares the identical root cause and was fixed alongside it rather than
  left for a future pass to rediscover independently.
- **Fix:** all three call sites now unwrap `(raw && raw.success && raw.data)
  ? raw.data : raw` first — the same idiom already established elsewhere
  in this exact file (`loadCisoMetrics()`'s own comment: "Unwrap standard
  { success, data, error } response envelope") — then read the real field
  names (`purchases`, `reports`) instead of the nonexistent `deliveries`.
- **Tests:** new `test/userDashboardPurchasesEnvelopeFix.test.mjs` (6
  tests, static source-parse) — confirms all three call sites (2 named +
  1 discovered) unwrap the envelope and read the real field names, and
  that `.deliveries` no longer appears anywhere in the file (confirmed via
  full-file grep, 0 matches). Full suite green: 229 files / 2376 tests
  (baseline 228/2370 from Tier-1 item #7).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#7). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (16 of 24):** next up, in stated
  order: `developer-onboarding.html`'s trial-key tier normalization bug
  (Tier-1 #9), then `tools.html`'s marketplace field mismatches (Tier-1
  #10), then all of Tier 2/3 (full original list in the audit entry nine
  below).

### 2026-07-11 — Tier-1 backlog item #7: user-dashboard.html — post-upgrade billing token-storage + loadDashboard() bug

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #6.
- **Re-verified against actual code, two independent bugs in the same
  post-payment success handler (`handlePaymentSuccess`)**:
  1. `handleVerifyPayment`'s subscription branch (`workers/src/handlers/payments.js`)
     issues a real JWT with the new tier baked in, returned as
     `token`/`refresh_token` — confirmed by reading the actual return
     statement, not assuming the audit's paraphrase. The frontend read
     these correctly but stored them via
     `localStorage.setItem('cdb_token', d.token)` — a key and storage type
     this page's own `apiFetch()` (and 6 other read sites) never look at;
     the real, established pattern (already used by `doLogin()`'s own
     success path) is `_token = ...; saveTokens(_token, refresh)`, which
     writes to `sessionStorage['cdb_access']`. The customer's UI kept
     enforcing their pre-upgrade tier until the session token naturally
     expired and forced a fresh login.
  2. The same success path then called `await loadDashboard()` —
     confirmed via exhaustive grep that no such function exists anywhere
     in this file. This threw a `ReferenceError` immediately after the
     "Access Unlocked" success modal was already shown, caught by the
     surrounding `catch`, surfacing a confusing "Something went wrong"
     toast to a customer who had just successfully paid.
     `initDashboard()` — the same full-refresh function `doLogin()`'s own
     success path already calls — is the real, existing equivalent; it
     already calls `syncPlanCards()` internally once its data loads, so no
     separate call was needed.
- **Fix:** replaced both the `localStorage` writes with `_token = d.token;
  saveTokens(_token, d.refresh_token);`, and `await loadDashboard()` with
  `await initDashboard()`.
- **Pre-existing test corrected, not worked around:**
  `test/dashboardProUpgradeAuthPath.test.mjs` (written 2026-07-10 for a
  different, already-fixed bug in this same handler) had its own final
  assertion locking in `localStorage.setItem('cdb_token', d.token)` as
  correct behavior — the exact bug this wave fixed. Corrected to assert
  the real `_token`/`saveTokens()` path, preserving the test's original
  intent (confirm the JWT is actually captured) without re-encoding the
  storage bug as a requirement.
- **Also fixed in this entry's commit:** restored the `## Session log
  (most recent first)` heading, accidentally dropped 2 entries ago (item
  #5's own edit) — already corrected in the item #6 entry below; noted
  here for completeness of this session's housekeeping trail.
- **Tests:** new `test/userDashboardBillingTokenAndRefresh.test.mjs` (5
  tests, static source-parse) — confirms the success handler uses
  `_token`/`saveTokens()` (not `localStorage`), that `saveTokens()` itself
  writes to `sessionStorage`, that `initDashboard()` (not the nonexistent
  `loadDashboard()`) is called, and that `initDashboard` already syncs
  plan cards itself. Full suite green: 228 files / 2370 tests (baseline
  227/2365 from Tier-1 item #6).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#6). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (17 of 24):** next up, in stated
  order: `user-dashboard.html` My Trainings/My Purchases field mismatch
  (Tier-1 #8), then developer-onboarding.html and tools.html (Tier-1
  #9–#10) before Tier 2/3 (full original list in the audit entry eight
  below).

### 2026-07-11 — Tier-1 backlog item #6: soc-dashboard.html — AI Decision Engine field/scaling bugs

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #5.
- **Re-verified against actual code:** `loadDecisions()`'s real-data path
  read `d.action`/`d.reasoning`/`d.timestamp`. The real object shape
  (`services/decisionEngine.js`'s own header comment: `{decision, reason,
  confidence, priority, actions_recommended, risk_score}`, plus
  `decided_at` added at construction) never matched — every real decision
  rendered as a generic "ANALYZE" badge with "Processing threat data..."
  text, regardless of what the engine actually decided. Separately,
  `confidence` is already 0–100 (`computeConfidence()`'s own
  `Math.min(100, Math.round(...))`) — the frontend did `Math.round(d.confidence
  * 100)` for the percentage and `(d.confidence||.85)*80` for the bar
  width, both assuming a 0–1 scale, so a real confidence of 75 rendered as
  "7500%" with a confidence bar ~6000px wide.
- **Mock-data fallback, re-examined as two distinct call sites, not one bug:**
  `buildMockDecisions()` (fabricated CVE-2025-xxxx / 185.234.x.x IP data)
  is called from two places. (1) When `USER_PLAN !== 'ENTERPRISE'`
  (`USER_PLAN` is read from `localStorage.getItem('cdb_plan')` — the
  "client-controlled localStorage value" in the audit finding) — this path
  sits behind `#decision-gate`, an overlay that clearly reads "Autonomous
  threat triage and response requires ENTERPRISE plan" with an "Upgrade to
  Enterprise" button. Confirmed this is a legitimate, honestly-disclosed
  teaser pattern (matches this codebase's own established convention for
  gated preview content) — left unchanged. (2) The `catch` block of the
  *real* fetch, with no gate or disclosure of any kind — a genuine
  ENTERPRISE customer hitting a transient network error would silently see
  fabricated threat data presented as live. This is the actual bug: fixed
  to show an honest "Unable to load decisions — try refreshing" message
  instead, matching the disclosure standard this file already uses
  elsewhere (`loadIOCs()`'s own comment: "a clear upgrade prompt rather
  than a confusing empty state").
- **Fix:** `d.action`→`d.decision`, `d.reasoning`→`d.reason`,
  `d.timestamp`→`d.decided_at`; confidence display is now
  `Math.round(d.confidence)` (no `*100`) and the bar width scales by `*0.8`
  (not `*80`) to correctly map a 0–100 value onto the existing 0–80px bar.
  Also added the 5 missing `.dt-*` CSS classes for real decision values
  that had never had one (`auto_contain`, `fast_patch`, `monitor_closely`,
  `low_priority`, `false_positive` — only `escalate`/`block`/`alert`/`allow`
  existed), since real decisions will now actually reach this code path.
- **Tests:** new `test/socDashboardDecisionEngineFieldFix.test.mjs` (7
  tests, static source-parse) — confirms the real field names are read and
  the old ones are gone, confidence is not re-scaled, the catch block no
  longer calls `buildMockDecisions()` and shows the honest message instead,
  the legitimate non-ENTERPRISE teaser path is untouched and still clearly
  overlaid, and all 6 real `DECISIONS` values have a matching CSS class.
  Full suite green: 227 files / 2365 tests (baseline 226/2358 from Tier-1
  item #5).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#5). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Also fixed in this entry's commit:** restored the `## Session log (most
  recent first)` heading, accidentally dropped by the previous entry's own
  edit (item #5) — confirmed via `git show b8bca62 -- PROGRAM_BOARD.md`,
  the heading line was replaced instead of preserved. No content was lost,
  only the section heading itself; this fixes it in place per this file's
  own convention of correcting mistakes visibly rather than silently.
- **Remaining in the Tier 1–3 backlog (18 of 24):** next up, in stated
  order: `user-dashboard.html` billing token-storage + `loadDashboard()`
  bug (Tier-1 #7), then My Trainings/My Purchases field mismatch (Tier-1
  #8), then developer-onboarding.html and tools.html (Tier-1 #9–#10)
  before Tier 2/3 (full original list in the audit entry seven below).

### 2026-07-11 — Tier-1 backlog item #5: automation-dashboard.html — 5 dead/wrong endpoints

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #4.
- **Re-verified against actual code**, each of the 5 named issues independently:
  1. **Connector Health** (`loadConnectors`) called `/api/integrations/connectors`
     — the owner-only internal domain (`index.js:1550`'s
     `/^\/api\/(integrations|org-memory|...)/` prefix gate, `isOwner()`
     required). The real, customer-facing, API-key-authenticated route is
     `/api/auto/integrations/connectors` (`handleAutoRoute` →
     `handleIntegrationConnectors`, confirmed in the route's own
     `API_MANIFEST` entry). Once the path is fixed the field names already
     matched — this was a pure wrong-path bug, no shape mismatch.
  2. **SIEM Test** (`testConnector`) called `POST /api/integrations/test` —
     same wrong owner-only domain; the real route is
     `/api/auto/integrations/test` (`handleIntegrationTest`). Separately,
     that handler always returns HTTP 200 even for a failed connection test
     (`{success:false, message}` in the body, never a non-2xx status) —
     `testConnector`'s try/catch only had a failure branch for a thrown
     error, so it unconditionally rendered "Connection successful" as long
     as the request itself didn't throw. Fixed to branch on `d.success`.
  3. **Usage tab** (`loadUsage`) read `d.summary.{total_calls,cache_hit_ratio}`,
     `d.quota.{quota_pct,radar_limit,month_calls}`, and `d.by_endpoint` — the
     real handler (`handleUsageDashboard`) never computed a `summary` or
     `quota` object at all (only `hourly_trend`/`daily_trend`/
     `top_endpoints`/`breakdown_by_day` existed), and called the endpoint
     breakdown `top_endpoints`, not `by_endpoint`. `summary`/`quota` are a
     missing capability, not a rename (same class as the revenue-command-center.html
     KPI-tiles fix, item #3) — added real queries against the existing
     `ops_usage_events` table (already used by this same handler) plus
     `auth/apiKeys.js`'s `TIER_LIMITS` for the per-tier monthly quota.
     `radar_limit` sends `null` (not `TIER_LIMITS`'s internal `-1`) for
     unlimited tiers, matching the truthiness check `loadUsage` already
     uses. Frontend's `d.by_endpoint` corrected to `d.top_endpoints`
     (simpler than adding a backend alias, unlike the revenue fix's
     `pipeline`/`pipeline_value` case — no other consumer to preserve).
  4. **Governance tab** (`loadGovernance`) read `d.released`, `d.user_tier`,
     `d.quota_warning`, `d.throttle_limits` — `handleGovernance` just
     returned the static `API_MANIFEST` (version/endpoints/deprecations —
     platform-wide, not personalized) with none of those fields. Same
     missing-capability class as #3 above: added `user_tier` (from
     `authCtx`), `throttle_limits` (from `TIER_LIMITS[tier]`), `released`
     (aliases the manifest's existing `last_updated`), and a computed
     `quota_warning` (populated once calendar-month usage crosses 80% of
     the tier's monthly limit, `null` otherwise) — reusing the exact same
     `ops_usage_events`/`TIER_LIMITS` building blocks as the Usage tab fix.
  5. **Webhooks list** (`loadWebhooks`) called `JSON.parse(w.events||'[]')`
     on a field the real handler (`handleWebhookList`) already runs through
     `safeParseJSON()` server-side — `w.events` arrives as a real array, and
     `JSON.parse()` on a non-string argument coerces it via `.toString()`
     (producing a comma-joined, non-JSON string) and throws, silently
     caught by the surrounding try/catch, leaving the list permanently
     empty despite real webhooks existing. Fixed to use `w.events||[]`
     directly — no parsing needed, it's already the real array.
- **Tests:** new `test/automationDashboardDeadEndpoints.test.mjs` (11 tests)
  — backend: real in-memory SQLite (`node:sqlite`, same pattern as
  `enterpriseAutomationTeamManagement.test.mjs`) verifying `summary`/`quota`
  are computed correctly from real `ops_usage_events` rows (including that
  `radar_limit` is `null` not `-1` for unlimited tiers, and that
  `quota_warning` correctly appears only past the 80% threshold); frontend:
  static source-parse confirming the corrected paths, the `d.success`
  branch, the non-parsing webhook render, and the `top_endpoints` field
  name. Full suite green: 226 files / 2358 tests (baseline 225/2347 from
  Tier-1 item #4).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#4). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (19 of 24):** next up, in stated
  order: `soc-dashboard.html`'s AI Decision Engine field/scaling bugs, then
  `user-dashboard.html`'s billing token-storage bug, then the rest of Tier
  1 before Tier 2/3 (full original list in the audit entry six below).

### 2026-07-11 — Tier-1 backlog item #4: mssp-command-center.html — Add Partner always 400'd

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #3.
- **Re-verified against actual code:** `submitPartner()`
  (`frontend/mssp-command-center.html`) posted
  `{company, contact, tier, contract_value, email, notes}` to
  `POST /api/mssp/partners`. The real handler
  (`handleAddMsspPartner`, `workers/src/handlers/msspOps.js`) destructures
  `{company, contact_email, tier, plan, brand_name, custom_domain,
  primary_color, margin_pct}` and requires both `company` and
  `contact_email` — the frontend's `email` field was never read under that
  name, so `contact_email` was always empty and the `if (!company ||
  !contact_email)` check 400'd on literally every submission.
  `contact`/`contract_value`/`notes` were also silently dropped — no
  matching destructured field existed for any of them.
- **Fix:**
  - `submitPartner()` now sends `contact_email`/`contact_name` (the real
    field names), and its own client-side required-field check now
    includes email (previously the "Contact Email" label had no `*` and
    the form let you submit without it, guaranteeing a 400 even after the
    field-name fix if left blank) — label corrected to "Contact Email *"
    to match.
  - `handleAddMsspPartner` now also accepts `contact_name`/`contract_value`/
    `notes` and stores them in `mssp_partners.metadata` — a JSON column
    already in `schema_bootstrap.sql`, provisioned for exactly this kind of
    extensibility but never populated on insert. Confirmed this is real,
    retrievable data, not a write-only stub: `handleListMsspPartners`
    already `SELECT p.*`s every column including `metadata`. No schema
    migration needed or performed.
- **Deliberately not done in this pass:** surfacing `metadata`'s fields in
  the partner table or `viewPartner()`'s detail view — the audit finding
  was specifically about the 400 (a hard failure), not about the partner
  list's displayed columns; adding new visible UI is a separate, smaller
  follow-up now that the data is actually being captured.
- **Tests:** new `test/msspAddPartnerFieldMismatch.test.mjs` (5 tests) —
  backend: still 400s on missing `contact_email` (unchanged validation),
  succeeds and correctly stores `contact_name`/`contract_value`/`notes` in
  `metadata` on a valid submission; frontend: static source-parse
  confirming `submitPartner` sends the real field names, requires email
  client-side, and the label is marked required. Full suite green: 225
  files / 2347 tests (baseline 224/2342 from Tier-1 item #3).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#3). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (20 of 24):** next up, in stated
  order: `automation-dashboard.html`'s dead/wrong endpoints, then
  `soc-dashboard.html`'s AI Decision Engine field/scaling bugs, then the
  rest of Tier 1 before Tier 2/3 (full original list in the audit entry
  five below).

### 2026-07-11 — Tier-1 backlog item #3: revenue-command-center.html — 6 of 8 panels broken by response-shape mismatches

- **Trigger:** continuing the Tier 1–3 backlog, next item after Tier-1 item #2.
- **Re-verified against actual code**, endpoint by endpoint, rather than
  trusting the audit's category label ("object vs array, flat vs nested").
  Read every one of the 8 panels' frontend consumers
  (`frontend/revenue-command-center.html`) against their real backend
  handlers (`workers/src/handlers/revenueOps.js`,
  `workers/src/handlers/revenueMetrics.js`). 2 panels (Breakdown, MSSP
  Opportunities) were already correctly wired — confirmed, not touched. The
  other 6 each had a distinct, independently-verified mismatch:
  1. **KPI Metrics tiles** (`loadRevMetrics`) — MRR/ARR were correct, but
     `d.today`/`d.week`/`d.month` had **no corresponding backend field at
     all** (`handlers/revenueMetrics.js` only ever computed MRR/ARR from
     subscription-tier counts, never actual cash collected), and `d.pipeline`
     read a field the backend calls `pipeline_value`. This is a missing
     capability, not a rename — fixed by adding real `today`/`week`/`month`
     queries against the same `payments` table `revenueOps.js` already reads
     correctly (confirmed `env.DB` and `env.SECURITY_HUB_DB` are the same
     D1 database via `index.js`'s `if (env.SECURITY_HUB_DB && !env.DB) env.DB
     = env.SECURITY_HUB_DB` alias), plus a `pipeline` alias field.
  2. **Lead Sources** (`loadLeads`) — hardcoded a 6-item Title-Case taxonomy
     (`'Organic Search'`, `'Direct'`, …) that never matched any real
     `source` value; the real response is `{breakdown:[{source,count,pct}]}`.
     Fixed to render `d.breakdown` directly with a generic humanizer instead
     of a fixed, guessed taxonomy.
  3. **Conversion Funnel** (`loadFunnel`) — hardcoded 5 keys
     (`visitors`/`free_scan`/`lead_captured`/…) that matched none of the
     backend's real 7 stage ids (`visit`/`scan_start`/…/`purchase`); the
     real response is `{stages:[{stage,label,count,conversion_from_prev}]}`,
     already computed server-side. Fixed to render `d.stages` directly,
     with bar width now proportional to real counts instead of a fixed,
     fake sequence (100%/80%/60%/40%/25%).
  4. **Transactions** (`loadTransactions`) — checked `Array.isArray(data)`
     on a response that's actually `{transactions:[...], total}`, so the
     table was always empty; rows also read `tx.date`, a field that doesn't
     exist (`created_at`/`paid_at` do). Fixed to unwrap `data.transactions`
     and format `tx.paid_at || tx.created_at`.
  5. **Forecast** (`loadForecast`) — read flat
     `current_month_actual`/`next_month_projection`/`quarterly_forecast`;
     the real response nests these under `current_month.actual`,
     `next_month.projected`, `quarterly.projected`. Fixed to read the real
     nested paths.
  6. **Pipeline Kanban + Add Deal** (`loadPipeline`, `renderKanban`,
     `submitDeal`) — the deepest mismatch: `loadPipeline` expected the raw
     response to be an array of deals; it's actually
     `{stages:{lead:{count,value,deals},...}, total_deals, pipeline_value}`,
     already grouped server-side. The frontend's own stage taxonomy
     (`Lead`/`Qualified`/`Discovery`/`Proposal Sent`/`Negotiation`/`Won`)
     also didn't match any of the backend's real keys (`lead`/`qualified`/
     `demo`/`proposal`/`negotiation`/`closed_won`/`closed_lost`), so even a
     correctly-shaped deal could never land in the right column.
     Separately, `submitDeal` posted `{contact, value}`; the backend
     requires `contact_email` specifically (400s without it) and reads
     `deal_value_inr` — and the modal never had an email input at all
     (only a generic "Contact Person" name field), so this couldn't be
     fixed by renaming alone. Added a real Contact Email field to the
     modal, updated the stage `<select>` to the real backend values, and
     rewrote `loadPipeline`/`renderKanban` to consume the real grouped
     shape directly instead of re-grouping a (nonexistent) flat array
     client-side.
- **Deliberately not fixed in this pass:** `handleRevenueMetrics`'s own
  inner tier check (`isAdmin` or tier ENTERPRISE/MSSP) is redundant with
  — and stricter than — the route-level `isOwner()` gate `index.js` already
  applies before calling it; a real owner whose own account isn't tier
  ENTERPRISE/MSSP and isn't using the ADMIN_KEY bypass could theoretically
  still 403 here. Not touched: out of scope for a response-shape fix, not
  confirmed as an active problem (the owner's own account is ENTERPRISE in
  practice), and flagged here rather than silently left for a future pass
  to rediscover.
- **Tests:** new `test/revenueCommandCenterPanelFixes.test.mjs` (15 tests)
  — backend: real `payments`-table sums bucketed correctly into
  today/week/month with non-`success` and out-of-window rows excluded, and
  `pipeline` aliasing `pipeline_value`; frontend: static source-parse
  (same established pattern as `homepageSignInPath.test.mjs`) confirming
  each panel now reads the real field/shape and no longer references the
  old, never-matching one. Full suite green: 224 files / 2342 tests
  (baseline 223/2327 from Tier-1 item #2).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as items #1–#2). `PRODUCTION_READINESS_REPORT.md` regenerated
  (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (21 of 24):** next up, in stated
  order: `mssp-command-center.html` Add Partner field mismatch, then
  `automation-dashboard.html`'s dead/wrong endpoints, then the rest of Tier
  1 before Tier 2/3 (full original list in the audit entry four below).

### 2026-07-11 — Tier-1 backlog item #2: index.html Autonomous SOC / SIEM Integration Deploy / Org Memory auth gaps

- **Trigger:** continuing the Tier 1–3 backlog, next item in stated order
  after Tier-1 item #1 (enterprise-kpi-dashboard.html, PR #184, this same
  session).
- **Re-verified against actual code, and found the finding was actually two
  distinct bugs bundled together**, not one:
  1. **Autonomous SOC** (`workers/src/index.js:1516` — a customer-facing
     ENTERPRISE/MSSP/TEAM/PRO feature, explicitly carved out of the
     owner-only gate by an earlier session specifically to make it
     customer-usable) resolves auth from the request itself on *every*
     `/api/auto-soc/*` call, no exceptions. 6 of `index.html`'s fetch() calls
     to this prefix never attached the bearer token — `showGeneratedRules`
     (latest-rules), both fetches inside `cdbAutoSOCRun` (pipeline poll +
     the run POST itself), `cdbAutoSOCPollPipeline`, `cdbAutoSOCRefreshLog`,
     and `cdbAutoSOCSetSchedule` — so real paying customers clicking "Run
     Now," polling pipeline status, refreshing the log, viewing generated
     rules, or setting a schedule always got an anonymous 403 ("Enterprise
     plan required") regardless of their real tier. Only `cdbAutoSOCLoad`
     and `cdbAutoSOCToggle` already attached it correctly (the latter has
     its own explicit comment about why it must).
  2. **SIEM Integration Deploy and Org Memory** are genuinely different:
     their backend (`workers/src/index.js:1550`, the
     `/api/(integrations|org-memory|workflows|revenue|monetize)` prefix)
     requires `isOwner()` — the same strict, literal-owner-only check
     already used correctly by this page's `proposal-gen`/
     `growth-analytics`/`crm-ops-internal` sections. But both sections'
     `<section>` tags were marked `data-auth-gate="true"` (this file's own
     established convention for "reveals for any authenticated user" —
     see the comment at `index.html:413-414`) instead of
     `data-auth-gate="owner"` (reveals only for the server-verified owner)
     — shown to every logged-in customer, none of whom could ever pass the
     backend's real check. Separately, all 8 of their fetch() calls (6 in
     SIEM Deploy, 2 in Org Memory) attached no auth header at all, so even
     the real owner would have been rejected.
- **Fix:**
  - Auto-SOC: added the same `(window.SUBSCRIPTION && SUBSCRIPTION.getToken
    && SUBSCRIPTION.getToken()) || ''` token lookup already used correctly
    by `cdbAutoSOCLoad`/`cdbAutoSOCToggle` to all 6 broken call sites,
    attaching `Authorization: Bearer <token>` the same way.
  - SIEM Deploy / Org Memory: changed both sections'
    `data-auth-gate="true"` to `data-auth-gate="owner"` (2 sections have no
    nav link anywhere pointing at them — confirmed by grep — so this
    doesn't strand a dangling clickable link for non-owner visitors, unlike
    the 3-section nav-injection case fixed in an earlier session). Added
    the same `SUBSCRIPTION.getToken()`-based Authorization header to all 8
    of their fetch() calls, for consistency with the rest of the file and
    because `SUBSCRIPTION.getToken()` is a strict superset of the token
    lookup `p4Api()` (the proposal-gen/growth-analytics helper) already
    uses correctly for this exact same owner-only tier.
  - `autonomous-soc`'s own section tag is unchanged (`data-auth-gate="true"`
    stays correct — it's the customer-facing one).
- **Tests:** new `test/homepageOwnerAndTierGatedActionsAuthGaps.test.mjs`
  (17 tests, static source-parse — same established pattern as
  `homepageSignInPath.test.mjs`) — asserts every one of the 8 previously-broken
  functions now attaches the token, the 2 already-correct Auto-SOC functions
  still do (regression guard), both section tags carry the corrected
  `data-auth-gate` value, and `autonomous-soc`'s tag is untouched. Also
  corrected a pre-existing test (`executiveHubEnvelopeUnwrap.test.mjs`) whose
  `fnBody()` helper used a fixed 2500-char slice that this fix's added lines
  in `cdbMemoryRefresh` pushed just past (measured: 2609 chars to the
  now-truncated assertion target) — widened to find the real closing `};`
  instead of guessing a length, so it can't silently break the same way
  again. Full suite green: 223 files / 2327 tests (baseline 222/2310 from
  Tier-1 item #1).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — same
  reasoning as item #1: this bug was found by the general audit, not
  previously catalogued as its own registry capability).
  `PRODUCTION_READINESS_REPORT.md` regenerated (timestamp-only diff).
- **Remaining in the Tier 1–3 backlog (22 of 24):** next up, in stated
  order: `revenue-command-center.html` response-shape mismatches,
  `mssp-command-center.html` Add Partner field mismatch, then the rest of
  Tier 1 before Tier 2/3 (full original list in the audit entry three below).

### 2026-07-11 — Tier-1 backlog item #1: enterprise-kpi-dashboard.html tier-gate bug (P16 admin routes)

- **Trigger:** resumed this session after a prior one hit a hard usage-limit
  cutoff mid-task (see `EXECUTION_PROCEDURE.md` §3 — recovery checklist run
  first: `git ls-remote origin` confirmed PR #183 was already merged to
  `main` and CI/deploy were green, so that work was not redone). Continuing
  the 24-item Tier 1–3 backlog documented in the audit entry below, in the
  stated priority order, one bounded fix at a time per this file's own
  pacing discipline.
- **Re-verified against actual code before touching anything** (per this
  file's repeated lesson about false positives): the audit's claim held up.
  `workers/src/handlers/enterpriseTransformHandler.js`'s `adminGuard()`
  checked `authCtx.tier` against `{OWNER, ADMIN}` — values no auth path in
  the system ever produces. Real subscription tiers are
  FREE/STARTER/PRO/ENTERPRISE/MSSP (confirmed via `PLAN_ORDER` two lines
  above the bug itself); staff-console sessions
  (`handlers/staffAuth.js`'s `resolveStaffSession()`) hardcode
  `tier: 'ENTERPRISE'` regardless of role, and the real "is this an admin"
  signal lives in `platformRoles`/`isAdmin`. This 403'd every caller
  including the real platform owner and real platform admins, on all 5
  routes the shared `adminGuard()` protects: `GET /api/platform/kpi` (the
  one `enterprise-kpi-dashboard.html` actually calls, via
  `CDB_STAFF_AUTH.authFetch`), `GET /api/platform/overage/report`,
  `POST /api/platform/overage/charge`, `GET /api/platform/kpi/executive`,
  `GET /api/platform/transform/observability`.
- **Frontend needed no change:** `frontend/assets/staff-auth.js` already
  correctly sends the staff-session bearer token, and its own header comment
  already documented the intended design ("the actual data is still
  protected server-side by each API route's own authorization check
  (isOwner()/isPlatformAdmin() — see auth/rbac.js)"). The backend handler
  simply never got wired to that already-established RBAC helper — this was
  a backend-only fix.
- **Fix:** `adminGuard()` is now async, takes `env`, and delegates to
  `auth/rbac.js`'s `isPlatformAdmin(authCtx, env)` — the same predicate
  already used correctly elsewhere in the codebase (role inheritance:
  SUPERADMIN implies ADMIN; recognizes the ADMIN_KEY bypass, the legacy
  owner-email path, and real `user_roles` grants). Removed the now-dead
  `ADMIN_TIERS` constant (its sibling `PLAN_ORDER` is unrelated and still
  used elsewhere in the file for customer tier-upgrade logic — left
  untouched). All 5 call sites updated to `await adminGuard(authCtx, env)`.
- **Pre-existing test corrected, not worked around:** `test/phase2ContractDrift.test.mjs`
  (a response-field-name contract guard, unrelated in purpose to this bug)
  asserted `handlePlatformKPI`'s field names using an authCtx of
  `{ tier: 'OWNER' }` — the exact same impossible value the bug itself
  depended on to have ever been written without failing. Corrected to
  `{ isAdmin: true }` (the real ADMIN_KEY-bypass path) without touching what
  the test actually guards (KPI field-name drift).
- **Tests:** new `test/enterpriseTransformAdminGuard.test.mjs` (11 tests) —
  asserts anonymous callers get 401; an ordinary authenticated customer of
  *any* tier still gets 403 (confirming the fix doesn't overcorrect into an
  open door); and a real platform admin is admitted via each of: a
  `user_roles`-granted ADMIN, the ADMIN_KEY bypass (`isAdmin: true`), the
  legacy owner-email path, and — the exact real-world path — a
  `resolveStaffSession()`-shaped ADMIN and SUPERADMIN staff session
  (`tier: 'ENTERPRISE'`, real signal in `platformRoles`). Also covers the
  other 4 routes sharing the same gate (403 for an ordinary user, 200 for a
  platform admin, on each). Full suite green: 222 files / 2310 tests
  (baseline 221/2299 from PR #183; +1 file / +11 tests this wave).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged — this
  bug was found by the general frontend audit, not previously catalogued as
  its own registry capability; documented here rather than forced into a
  new registry entry, same handling as the audit's other non-catalogued
  findings). `PRODUCTION_READINESS_REPORT.md` regenerated (timestamp-only
  diff, no capability-count change).
- **Remaining in the Tier 1–3 backlog (23 of 24):** see the audit entry
  below for the complete original list. Next up, in stated order:
  `index.html` Autonomous SOC/SIEM Deploy/Org Memory auth gaps,
  `revenue-command-center.html` response-shape mismatches,
  `mssp-command-center.html` Add Partner field mismatch, and the rest of
  Tier 1 before Tier 2/3.

### 2026-07-11 — Full-frontend API-wiring audit (80 pages) + first 2 critical fixes (cross-tenant data exposure)

- **Trigger:** owner asked for a systematic audit of all 80 frontend pages —
  for each, is it genuinely wired to a live, correct backend, or does it show
  placeholder/hardcoded data — followed by production-grade fixes for
  whatever the audit found, same "report findings before touching anything"
  discipline as the homepage-anchor investigation two entries below.
- **Method:** re-derived the page categorization independently (11 pages are
  legitimately static — legal/marketing; ~23 are marketing pages with one
  legitimate embedded live-tool call; 46 are real dashboard/tool pages).
  Dispatched 8 parallel research passes covering all 46 dashboard/tool pages
  plus the two largest pages (`index.html`'s ~180 API call sites,
  `user-dashboard.html`'s ~70) — each cross-referenced every frontend
  fetch/authFetch call against its actual backend handler for: hardcoded/mock
  data dressed up as live, auth-gating mismatches, cross-tenant data leakage,
  field-name mismatches between frontend and backend, and dead/unregistered
  endpoints.
- **Overall verdict:** the platform is overwhelmingly real, not fake — most
  audited pages (autonomous-soc-dashboard, security-fabric-dashboard,
  cyber-signal-radar, admin-portal, admin-payments, revenue-intelligence-dashboard,
  customer-dashboard, customer-success-dashboard, partner-portal,
  enterprise-dashboard, decision-dashboard, mcp-security, attack-library,
  booking, enterprise-portal, marketplace-checkout, mssp-onboarding,
  vibe-code-scanner, copilot-admin, intel.html, intel-hub.html,
  ai-security-scorecard.html, ciso-hub.html, threat-hunting.html and more)
  verified genuinely live and correctly wired with no action needed. The
  audit surfaced 26 concrete, independently-verified bugs across the
  remaining pages, ranked by severity; this entry documents the first 2
  (active confidential-data exposure) fixed immediately. The remaining 24
  (broken-but-not-leaking features, cost-abuse gaps, and cosmetic issues) are
  queued as their own bounded follow-up fixes, same as this board's
  established practice for the Wave 2 Developer Portal findings.
- **Fix 1 — `docs/capability-registry/domains/*` gap, AI Governance domain
  (`workers/src/handlers/aiGovernancePro.js`,
  `workers/src/handlers/aiGovernancePdfHandler.js`, `frontend/ai-governance-pdf.html`):**
  every route in this domain (AI model registry CRUD, policies, shadow-AI
  detection, dashboard, report generation, and PDF export) had **zero
  authentication** and took `org_id` directly from client body/query
  params — any anonymous visitor could read, modify, or delete another
  organisation's confidential AI model registry (including `owner_email`),
  policies, and generated governance/compliance PDF reports just by
  supplying that org's id. `handleAIGovernancePro`/`handlePdfGenerate`/
  `handlePdfList` now require `isRealUser(authCtx)` and derive org scope
  exclusively from `authCtx.org_id` (the same per-user tenant id
  `withAuthAliases()` already establishes for every other scoped domain in
  this codebase), never from client input. Also closed, found while fixing
  the same bug class: `GET/PUT/DELETE /api/ai-governance/models/:id` and
  `POST /api/ai-governance/policies/:id/evaluate` had no ownership check at
  all (IDOR by guessable/known id) — now 404 for a non-owning caller.
  `frontend/ai-governance-pdf.html`'s "Organisation ID" free-text input
  (the actual attack surface — it let a visitor type any org's id) is
  removed; the page now requires sign-in and derives the report scope from
  the caller's own session token, matching the platform's existing
  `cdb_token` auth pattern (same as `billing-portal.html`).
- **Fix 2 — CISO Command Center cross-tenant leak (`workers/src/handlers/cisoMetrics.js`):**
  `frontend/user-dashboard.html`'s "CISO Executive Metrics" panel — explicitly
  subtitled "derived from your scan data" — actually showed the
  **platform-wide aggregate across every other customer's scans and
  incidents**, for three independent reasons: (1) `fetchRealMetricsFromD1()`
  queried `scan_history` (which does have a `user_id` column) with no `WHERE`
  clause at all; (2) `loadIncidents()`/`saveIncidents()` used one single
  shared KV key (`ciso:incidents`) for every caller — any customer's logged
  incident was visible, and mutable, by every other customer; (3)
  `handleGetCISOMetrics()` cached the entire computed response under one
  single shared KV key (`ciso:metrics_cache`), which would have leaked
  correctly-scoped data across users via the cache alone even after fixing
  (1) and (2) in isolation. `handleExportCisoPdf`'s board-report PDF export
  inherits (and is fixed by) the same change, since it calls
  `handleGetCISOReport` internally. All three are now namespaced by
  `authCtx.user_id`. `mythos_runs`/`threat_intel` are deliberately left
  unscoped — platform-level tool-generation stats and a shared CVE feed, not
  per-customer data. Also added, found while in this file: `isRealUser(authCtx)`
  gates on `GET /api/ciso/posture` and `GET /api/ciso/compliance-status`
  (previously had none — not an active leak today since both query tables
  that don't yet exist in the schema and always returned an empty/honest
  result, but needed for correct per-user scoping going forward); and fixed
  `handleGetComplianceStatus`'s pre-existing `buildComplianceStatus([])`
  call (wrong arg **and** missing `await`, meaning `.reduce` ran on an
  unresolved Promise and threw uncaught on every real call — a second,
  independent crash bug, of the exact same class `handleGetCISOReport`'s own
  inline comment already documents fixing elsewhere in this same file).
- **Tests:** `workers/test/aiGovernanceOrgScoping.test.mjs` (new, 8 tests,
  real in-memory D1 via `node:sqlite` matching the live schema — asserts
  anonymous 401s, that client-supplied `org_id` is ignored on both read and
  write paths, and that a second user cannot list/get/update/delete the
  first user's models, policies, shadow-AI scan, or generated reports).
  `workers/test/cisoMetricsTenantIsolation.test.mjs` (new, 6 tests — asserts
  two different authenticated users each see only their own scan stats,
  incidents, and risk-register entries, and that the response cache doesn't
  cross tenants). Full suite green: 221 files / 2299 tests (baseline 219/2285,
  +14 from these 2 new files).
- **Not done this pass:** the remaining 24 audit findings (10 "customer paid
  for a feature that silently 403s or shows wrong data" bugs, 8 cost-abuse/
  misleading-data bugs, 6 minor/cosmetic issues) — queued as follow-up
  bounded fixes, full list preserved in this session's conversation record
  for the next wave to work from.

### 2026-07-11 — Self-correction, same day: the immediately-prior entry's "no nav link existed anywhere" claim was wrong; fixed the real bug instead

- **What happened:** the customer reported "nothing changed" after the wave
  documented in the entry immediately below shipped, prompting a re-check
  rather than assuming the customer was simply looking in the wrong place.
  That re-check found the immediately-prior entry's central claim — "no nav
  link anywhere" pointed at `executive-hub`/`auto-defense`/`data-dominance` —
  was independently re-verified **false**. A pre-existing `p3InjectNav()`
  (`frontend/index.html`'s Phase 3 Engine block) already injected real nav
  links for exactly these 3 sections, labeled "CISO Hub" / "Defense" / "Data
  Intel". Neither this session's own grep-based investigation nor the
  10-minute agent pass it commissioned found it, because the links are built
  via `document.createElement()` + property assignment at runtime — never
  present as literal `href="..."` text for a static search to find.
- **What was actually wrong with `p3InjectNav()`** (now fixed): it ran
  **unconditionally for every visitor**, including logged-out ones who can
  never pass these sections' own `data-auth-gate="true"` — a nav item that
  always dead-ends for the one visitor who can see it, explaining exactly
  the "nothing changed, still not properly built" feeling reported — and it
  only ever targeted the desktop nav, leaving mobile with zero
  discoverability. Fixed: `p3InjectNav()` now gates on
  `window.CDB_AUTH.isAuthenticated` and injects into both desktop nav and
  the mobile drawer; re-runs on `cdb:login` (SPA-style, no reload) via a
  same-closure listener, matching `cdbApplyGates()`'s established pattern.
- **What was removed:** the prior entry's redundant, differently-labeled
  injection added directly to `cdbApplyGates()` ("Executive Hub" /
  "Auto-Defense" / "Threat Confidence") was deleted outright — it would have
  shown each of the 3 sections **twice**, under two different names, for any
  authenticated visitor (a real regression this correction catches before
  its first customer-facing exposure to a logged-in user, since the prior
  fix's own visible surface for logged-out visitors was unaffected — the
  duplication only manifests once authenticated, which the customer's
  logged-out screenshot could not have shown either way).
- **What was corrected to match reality:** `CDB_SECTIONS`' labels now use
  the real, already-shipped labels ("CISO Hub" / "Defense" / "Data Intel")
  instead of the invented ones from the prior entry, so `_showGateNotice()`'s
  message ("Sign in to view X.") now matches what the visitor actually
  clicked instead of a different, internally-invented name for the same
  section.
- **Registry entries corrected in place** (not silently edited — both
  `navigation.evidence` fields now say CORRECTED and explain what was wrong
  and why): CAP-MASOC-002 (auto-defense) and CAP-MSSP-005 (executive-hub's
  MSSP panel) had both cited the prior entry's false "zero nav path" claim.
- **What remains true and unaffected by this correction:** the auto-defense
  Engine's `isRealUser(authCtx)` auth-gate fix (a real, independently
  verified security finding — anyone unauthenticated could previously
  trigger a real automated defense action), the `#enterprise` button
  un-shadowing fix, and the 3 dead/wrong-domain link fixes are all
  completely unrelated to this correction and remain valid as shipped.
- **Commits:** `frontend/index.html` (p3InjectNav fix, CDB_SECTIONS label
  correction, redundant-injection removal), rewritten
  `workers/test/homepageMemberSectionDiscoverability.test.mjs`, 2 corrected
  registry entries, this PROGRAM_BOARD.md entry.
- **Tests:** full suite green, 219 files / 2285 tests (net +4 vs. the prior
  entry's 2281, from rewriting the one test file: 9 old tests replaced with
  13 new ones covering the actual fix).
- **Validator:** 0 failures, 0 warnings, 97 capabilities (unchanged —
  correcting evidence text on 2 existing entries, no new/removed
  capabilities).
- **Lesson for future waves, stated plainly:** a static grep for
  `href="#section-id"` cannot see nav links a script builds via
  `createElement()` + property assignment at runtime. Before concluding "no
  nav path exists anywhere" for anything, also grep for the section's raw id
  string across `<script>` blocks (not just `href="` patterns) to catch
  dynamically-constructed links — this exact gap is why the prior
  investigation's conclusion was wrong despite being a genuinely thorough
  pass by its own (insufficient) methodology.

### 2026-07-11 — Customer report "dashboard links aren't properly built" (11 homepage anchors) — investigated, premise mostly corrected, 5 real gaps fixed including one P0-class unauthenticated auto-defense control gap

- **Customer's framing vs. reality:** asked to rebuild 11 homepage sections
  (`#trust-center`, `#intel-api`, `#home`, `#scanner`, `#auto-defense`,
  `#data-dominance`, `#executive-hub`, `#enterprise`, `#affiliate-hub`,
  `#enterprise-sales`, `#pricing`) from scratch as "not properly built."
  A thorough investigation (full read of every named section, every
  `fetch()`/`onclick` traced to its live handler, cross-referenced against
  this registry) found **8 of 11 already have real, substantive content
  wired to real, live backend routes** — rebuilding them would have
  discarded working, tested code to fix a problem concentrated in a few
  specific bugs. Presented the corrected picture to the owner rather than
  executing the literal request; owner chose "fix the real bugs found,"
  not a rebuild. This section documents what was actually fixed.
- **1. Three sections invisible by default, indistinguishable from "not
  built":** `auto-defense`, `data-dominance`, `executive-hub` are
  `data-auth-gate="true"` + `display:none`. `cdbNavigate()`'s gate check
  (confirmed directly, `frontend/index.html` ~14735) silently scrolled an
  unqualified visitor back to hero with **zero explanation** — indistinguishable
  from a dead link. Also: `CDB_SECTIONS` had no entries for any of the 3
  (raw section-id fallback in breadcrumb/nav-state), and no nav link
  anywhere pointed at them even for a correctly-authenticated visitor.
  Fixed: `CDB_SECTIONS` now has real labels; a new `_showGateNotice()`
  tells a bounced visitor why ("Sign in to view X." / "X is staff-only.")
  instead of silently redirecting; `cdbApplyGates()` now injects nav links
  for all 3 (desktop nav + mobile drawer) for any authenticated user,
  mirroring the pre-existing Dashboard-link insertion pattern exactly.
  Regression: `workers/test/homepageMemberSectionDiscoverability.test.mjs`
  (9 new tests).
- **2. `#enterprise` section: two functions silently shadowed by a later,
  wrong redefinition.** `openMSSPApplication()` and `openEnterpriseBooking()`
  were each defined twice — once as real, dedicated modals (`#mssp-modal`
  with company/email capture → real `POST /api/global/mssp/apply`;
  `#enterprise-booking-modal` → real payment collection via `CDB_PAYMENT`),
  and again, much later, inside a "MANUAL PAYMENT SYSTEM" block whose own
  comment said it existed to intercept `startSubscription` calls — it
  named `openEnterpriseBooking` too, and (undocumented) also redefined
  `openMSSPApplication`, even though neither the button text ("Apply as
  MSSP Partner") nor the CAP-MSSP-001 registry entry's own history
  supported that. Confirmed via `enterprisePackageCheckout.test.mjs`
  (2026-07-10) that this was a real, independently-discovered bug pattern
  in this exact section before (a card's button pointed at the wrong
  priced package) — this was the same bug class, just in the two functions
  that test didn't touch. The two later redefinitions also had their own
  pricing map disagree with the first's for the same key (`starter_enterprise`
  → ₹9,999 in one, ₹49,900 in the other) — a real pricing-mismatch risk,
  simply never triggered because no current caller uses that key. Fixed:
  deleted the shadowing redefinitions; `startSubscription` (a genuinely
  separate, unrelated flow) untouched. Regression:
  `workers/test/enterpriseMSSPButtonShadowingFix.test.mjs` (8 new tests).
- **3. Three dead/wrong-domain links on OTHER dashboard-adjacent pages**
  (found while confirming the "dashboard links here" premise — which
  itself turned out to hold for only 1 of the 11 anchors from
  `user-dashboard.html` specifically; these three are from other pages):
  `ciso-hub.html`'s Enterprise Checkout fallback pointed at
  `/upgrade.html#enterprise` (upgrade.html has no such anchor — fixed to
  match its own sibling function's fallback, `/upgrade.html`, one function
  below in the same file); `decision-dashboard.html`'s upgrade link used
  `tools.cyberdudebivash.com` instead of `cyberdudebivash.in` (every other
  reference in that file uses `.in` — same bug class as PR #177's
  hardcoded-URL fix); `sitemap.html` linked the bare `/affiliate-hub`
  (confirmed 404 — this exact bug class was already fixed once, in
  `affiliateSystem.js`, and independently recurred here, uncaught by that
  fix's own test since it only checked the one file). Regression: extended
  the existing `workers/test/deadEndLinks.test.mjs` (3 new tests, same
  thematic file).
- **4. Two capability-registry gaps closed** — both found live-wired with
  real routes but zero registry entry anywhere:
  - **CAP-MASOC-002** (Auto-Defense Engine, `workers/src/handlers/autoDefenseEngine.js`,
    8 routes): while documenting this, found **none of its 8 routes checked
    `isRealUser(authCtx)`** — the identical vulnerability class already
    fixed once for this domain's sibling CAP-MASOC-001, except worse here:
    an unauthenticated caller could change the platform's live defense
    mode, fabricate a `threat` object to trigger a real AGGRESSIVE-mode
    auto-deploy to real target platforms (splunk/elastic/sentinel/webhook),
    or approve/rollback a real pending action — not merely a compute-abuse
    risk. Fixed in the same pass: all 8 routes (including the read-only
    GETs — unlike CAP-MASOC-001's status route, no route here has a
    legitimate anonymous caller, since the only frontend consumer is
    itself `data-auth-gate="true"`) now gate on `isRealUser(authCtx)`,
    the same established pattern used 30+ times elsewhere in
    `workers/src/index.js`. Also fixed a stale docblock (said
    `/api/defense/*`, actual live routes are `/api/defense-engine/*`).
    Regression: extended `workers/test/authGateRealUser.test.mjs` (13 new
    tests: 8 new "anonymous → 401" cases, 5 new "admin key passes" cases).
  - **CAP-MSSP-005** (MSSP Client Portfolio + White-Label panel embedded in
    `#executive-hub`, `workers/src/handlers/msspPanel.js`, 9 routes):
    confirmed genuinely distinct from CAP-MSSP-002 (different handler
    file, different KV namespace, different routes — `/api/mssp/clients`
    vs. `/api/mssp/customers`, `/api/mssp/whitelabel` vs.
    `/api/white-label/theme`) — two parallel, uncoordinated MSSP systems
    now both catalogued, a future consolidation candidate not attempted
    here. Confirmed properly tier-gated (`requireMSSP()`, MSSP/ENTERPRISE
    only) — no auth gap here, unlike its sibling finding above. Flagged,
    not fixed (out of scope for a cataloging pass): zero test coverage;
    a possible shared-KV-bucket tenant collision if `authCtx` ever lacks
    both `userId` and `orgId` for an MSSP-tier caller, not confirmed
    reachable in practice.
- **Commits:** homepage discoverability/enterprise-button fixes + tests;
  dead-link fixes; auto-defense auth-gate fix + tests; registry entries
  (CAP-MASOC-002, CAP-MSSP-005) + report regeneration; this PROGRAM_BOARD.md
  entry.
- **Validator:** 0 failures, 0 warnings, 97 capabilities (+2:
  CAP-MASOC-002, CAP-MSSP-005).
- **Tests:** full suite green, 219 files / 2281 tests (2247 + 34 new: 9 +
  8 + 13 + 3 + 1 pre-existing test's slice-window widened after a
  legitimate code-length increase broke its fixed-size assumption, not a
  logic regression).
- **Risks / follow-ups surfaced, not fixed in this pass:** CAP-MSSP-005's
  potential shared-bucket tenant collision (see above); zero test coverage
  for 6 of CAP-MASOC-002's 8 entry points beyond the auth gate itself;
  the two parallel uncoordinated MSSP systems (CAP-MSSP-002 vs. -005)
  warrant a consolidation decision; `#trust-center`'s in-page anchor
  duplicates a richer, separate standalone `trust-center.html` page — worth
  deciding whether the anchor should deep-link there instead.
- **Next recommended wave:** per the corrected wave-plan section above —
  same discipline, next candidate.

### 2026-07-11 — Recovery-and-continuation pass: PROGRAM_BOARD.md housekeeping (6-PR-stale header/register/wave-plan corrected) + CAP-DEVPORTAL-004's residual sap_-key auth gap closed

- **Recovery (§3):** fresh session picking up after the prior one hit a
  usage-limit cutoff. `git fetch origin main`, `git rev-parse HEAD` vs
  `origin/main` (identical — this branch already contained PR #179's merge,
  nothing to recover), `git ls-remote origin` (confirmed no stray unmerged
  branch for this work; the many other `claude/*` branches listed are
  unrelated prior efforts, out of scope, not touched). PR #179 itself
  confirmed merged via the GitHub API (not just trusted from narration).
- **Housekeeping found and fixed first:** `PROGRAM_BOARD.md`'s "Current
  status" header, metrics table, "Remaining Work Register", and "Proposed
  wave plan" had drifted 6 PRs stale (last rolled forward as of #172/#173) —
  each of #174–#179 correctly appended its own session-log entry but never
  updated the header, so it still named CAP-CRM-007 as the latest work, the
  test count still read 211/2188 against an actual 217/2242, and the
  register/wave-plan still described 3 already-populated domains
  (`threat-hunting-intel`, `mythos-godmode`, `compliance-store`) as
  unstarted stubs and recommended populating them as the next wave — they
  were populated back on 2026-07-09. Corrected in place; see those sections
  for the full explanation. This is a documentation-integrity fix only, zero
  code changes, called out separately from the real fix below.
- **Domains touched:** `developer-portal-apikeys` (code + registry entry).
- **Real fix — CAP-DEVPORTAL-004's residual gap, closed:** the entry's own
  `notes` field (written 2026-07-09) already documented that `sap_`-prefixed
  growth/plan API keys — minted successfully via `POST /api/growth/api-key`
  for a verified paid lead — could never authenticate anywhere on the
  platform, and flagged it `BLOCKED` pending a dedicated follow-up. Traced
  the actual call graph before touching anything (per this file's own
  repeated lesson about verifying claims against code, not descriptions):
  `workers/src/middleware/auth.js`'s `resolveApiKey()` had a KV fast-path
  keyed by the *raw* incoming key and a D1 branch matching only `cdb_` —
  neither recognized `sap_`, and separately `apiRevenueEngine.js`'s
  `provisionApiKey` cached its KV entry under a *hashed* name the resolver
  never looks up, so even the prefix-agnostic KV path would have missed.
  Fixed with a new, additive third branch in that resolver that delegates to
  `apiRevenueEngine.js`'s own `resolveApiKey(env, apiKey)` (hash-then-match
  against its D1 rows) instead of duplicating the lookup, so key
  rotation/revocation there is honored automatically — zero changes to the
  existing KV/`cdb_`/IP-fallback branches.
  - **Correcting the prior note's own severity claim:** it described
    `workers/src/middleware/auth.js` as "the platform's core, request-path
    authentication resolver used by every authenticated route." Grepping
    every importer of that file shows exactly one consumer:
    `workers/src/handlers/intelMonetization.js` (the premium `/api/v1`
    threat-intel feed). The platform-wide session/user resolver every other
    handler actually uses is the separate `workers/src/auth/middleware.js`
    (`resolveAuthV5`) — untouched by this change. The fix's real blast
    radius was the intel-monetization API surface only, not "every
    authenticated route"; still verified with the full suite regardless.
  - **Second, independent bug found while writing the rotation regression
    test (not in the original finding):** `provisionApiKey`'s rotation path
    (re-provisioning an email that already has an active key) updated the
    D1 row's hash but never invalidated the *old* hash's KV cache entry —
    once the new resolver branch above made that KV entry reachable for the
    first time, a rotated-away key would have kept authenticating for up to
    its 1-year TTL despite the D1 row now pointing at a different key. Fixed
    in the same change: the old KV entry is now explicitly deleted on
    rotation, wrapped in its own `try/catch` (not chained `.catch()`, which
    doesn't help when `.delete` isn't a function at all rather than a
    rejecting promise — caught this the hard way when it broke an
    *existing* test via the outer function's catch-and-return-null) so a KV
    binding lacking `.delete()` can't break provisioning itself.
  - `operational_status` moves `BLOCKED` → `PILOT ONLY` (matching its
    CAP-DEVPORTAL-001/002/003 siblings — no frontend surface by design,
    unverified live external callers, but the backend now genuinely works
    end-to-end). `priority` stays `P1`, untouched, per this file's
    historical-severity convention. `customer_journey_complete` stays
    `false` — proven correct against a real in-memory D1, not against live
    production (no deploy access from this session, and no confirmed
    external caller to verify against).
- **Commits:** code fix (`workers/src/middleware/auth.js`,
  `workers/src/services/apiRevenueEngine.js`) + new regression tests
  (`workers/test/intelKeyResolution.test.mjs`) in one commit; registry entry
  update (`docs/capability-registry/domains/developer-portal-apikeys.json`)
  and this PROGRAM_BOARD.md correction in a second commit.
- **Validator:** 0 failures, 0 warnings, 95 capabilities (unchanged count —
  no new/removed capabilities, only CAP-DEVPORTAL-004's own fields updated).
- **Tests:** full suite green, 217 files / 2247 tests (2242 + 5 new:
  `intelKeyResolution.test.mjs`'s new sap_-key describe block — a freshly
  provisioned key authenticates end-to-end at the correct tier via the same
  `resolveAuth()` → `entitlementsFor()` chain the real intel API uses; a
  STARTER-tier key resolves to STARTER rather than a silent FREE downgrade;
  rotation invalidates the old key; an unprovisioned sap_-shaped key is
  correctly rejected; the pre-existing cdb_/KV/IP-fallback branches in the
  same file are unaffected). Also re-ran every directly-related existing
  test file (`devPortalApiKeyFixes`, `apiKeyHashing`, `apiKeysActiveFilterFix`,
  `apiKeyLiveTier`, `intelMonetization`, `intelRateLimitEnforcement`,
  `phase2ContractDrift`) individually before the full run — all green.
- **Risks / follow-ups surfaced:** none new. The Threat Graph
  findings-persistence owner-action item from an earlier wave is still
  outstanding (see Proposed wave plan above) — unrelated to this fix, not
  touched.
- **Next recommended wave:** per the corrected wave-plan section above —
  work the next real, non-owner-blocked gap in a freshly regenerated
  `PRODUCTION_READINESS_REPORT.md`, re-verifying each candidate against
  actual code before treating any registry claim (including this file's own)
  as true.

### 2026-07-11 — Access-control gap wave 2: index.html's `?owner=1` shell-reveal fixed (server-verified); self-correction on 5 pages the previous entry incorrectly flagged as needing the same fix

- **Continuation of the wave-1 entry directly below** — same customer
  complaint, same investigation. Two things happened this wave: (1) the one
  item from wave 1's own follow-up list that was a genuine, confirmed gap is
  now fixed; (2) five other items on that same follow-up list were
  independently re-verified and turned out to be **wrong** — those pages
  were already correctly gated. Recorded here rather than silently editing
  the wave-1 entry, so the record stays honest about what was actually
  checked and when.
- **Self-correction (read this before trusting any "needs a fix" claim in
  the wave-1 entry's Risks/follow-ups list below):** re-verified all 5
  flagged pages by reading their actual auth code, not just their names/
  route comments:
  - `admin-payments.html` — claimed to have "an orphaned, non-functional
    auth mechanism" (`x-admin-secret` header supposedly never checked).
    **Wrong.** `resolveAuthV5`'s step 0 (`workers/src/auth/middleware.js`)
    checks `x-admin-secret` against `env.ADMIN_KEY` — a real secret
    (`workers/wrangler.toml`: "rotate via: wrangler secret put ADMIN_KEY").
    The dashboard (`#dashboard`) is `display:none` by default and the page's
    own login flow works correctly against this real check.
  - `ops-dashboard.html` / `copilot-admin.html` — claimed to use "an older
    `window.prompt()`-for-admin-key pattern (weaker than the proven
    session-based system)". **Wrong** — neither uses `window.prompt()`.
    Both hide their main content by default (`#app{display:none}` /
    `#dashboard{display:none}`) and `ops-dashboard.html`'s `doAuth()` makes a
    real test call to `/api/admin/customers?limit=1` with the entered key,
    checking for 401/403 before revealing anything or persisting the key.
  - `decision-dashboard.html` / `security-fabric-dashboard.html` — claimed
    to "need a different fix shape than `staff-auth.js` ... to stop
    rendering their shell before a paying customer's own login completes."
    **Wrong** — both already do exactly that: content is `display:none` by
    default, and `doAuth()`/`authenticate()` call a real backend endpoint
    (`/decision/summary` and `/api/auth/status` respectively) with the
    entered key and only reveal the dashboard after a 2xx + a real
    tier/authenticated check passes. These are correctly-implemented PAID-
    CUSTOMER (PRO+) gates, not owner-only — correctly NOT using
    `staff-auth.js`, which is platform-staff-only.
  - Net effect: none of these 5 pages were touched this wave. No regression
    risk introduced by leaving them alone — they were never broken.
- **The one confirmed-real item, fixed:** `frontend/index.html` still had
  the exact vulnerable pattern `staff-auth.js`'s own header comment
  describes ("bypassable outright with
  `localStorage.setItem('cdb_owner','true')` in devtools") — `?owner=1` in
  the URL wrote `localStorage.cdb_owner='1'` directly, and `initAuthGate()`'s
  `readAuth()` read that value straight back with zero server round-trip,
  revealing 3 owner-only sections (`crm-ops-internal` CRM pipeline,
  `proposal-gen`, `growth-analytics`). A second, fully redundant copy of the
  same insecure check lived inline inside the `crm-ops-internal` div itself
  (a leftover from before the head-IIFE timing bug was fixed), bypassing
  even a same-file fix if not also removed.
  - **Fixed:** `index.html` now loads `staff-auth.js` and gates all 3
    sections behind a real, async `verifyOwner()` — `ownerVerified` starts
    `false` (safe default) and flips `true` only after
    `CDB_STAFF_AUTH.authFetch('/api/staff/me')` returns `res.ok` (the same
    KV-backed, real-session check gating `revenue-intelligence-dashboard.html`
    and `enterprise-kpi-dashboard.html` from wave 1). `cdbApplyGates()` then
    re-runs to reveal the sections — every existing consumer of
    `window.CDB_AUTH.isOwner` (the gate function itself, `cdbNavigate()`'s
    direct-hash-navigation guard, and the floating nav-tab injector)
    inherits the fix automatically since they all read the same flag. The
    redundant inline duplicate-check script inside `crm-ops-internal` was
    removed outright (dead weight even before this fix — the outer gate
    already covered the same element via `data-auth-gate="owner"`).
    `?owner=1` alone now does nothing; a real staff session (created once by
    logging in on any staff-gated page, e.g. `/admin-portal.html` — shared
    via `localStorage` across `cyberdudebivash.in`) is picked up
    automatically on any subsequent homepage visit. `?owner=0` still clears
    the session on demand.
  - **Known minor limitation, not a security issue:** `p4InjectNav()` (a
    second, separate floating-nav-pill injector, distinct from the
    `data-owner-tab="1"` tabs the main gate already handles correctly) runs
    once at `DOMContentLoaded` and isn't re-triggered when `verifyOwner()`
    resolves afterward — a freshly-verified owner may need one page refresh
    before its pills show the Proposals/Growth links. The actual gated
    sections and their primary nav tabs reveal correctly without a refresh.
    Pre-existing limitation (this nav injector was never wired to the
    `cdb:login` re-apply event either); left as-is rather than refactoring
    an unrelated, working nav mechanism to fix a cosmetic edge case.
- **Verified:** new `workers/test/homepageOwnerGateVerification.test.mjs`
  (10 tests) — confirms `staff-auth.js` loads before the gate controller;
  confirms the `?owner=1` → `localStorage.setItem` bootstrap is gone;
  confirms `isOwner` reads the verified closure variable, not localStorage;
  confirms `verifyOwner()` only sets it true after a real `res.ok` from
  `/api/staff/me` and always re-applies gates afterward; confirms `?owner=0`
  still clears the session; confirms the redundant inline duplicate-check
  script is gone while the section itself is untouched; confirms the other
  owner-gated sections/nav tabs and the rest of `cdbApplyGates()`'s
  responsibilities (member gate, plan badge, nav injection) are unaffected;
  a regression guard re-reads `workers/src/handlers/staffAuth.js` and
  `workers/src/index.js` to confirm `GET /api/staff/me` and
  `resolveStaffSession()` are real, KV-backed, role-checked — not just
  asserted. `node --check` on all 37 real (non-JSON-LD) inline `<script>`
  blocks extracted from `index.html`: syntax valid. Full backend suite: 217
  files / 2242 tests passing (up from 216/2232). `node
  scripts/registry/validate.mjs`: 0 failures, 0 warnings.
  `scripts/seo-structure-lock.mjs`: 22/22 pages green (index.html's `<head>`
  untouched by this fix).
- **Commits this wave:** `frontend/index.html`, new test
  `workers/test/homepageOwnerGateVerification.test.mjs`,
  `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Wave 1's last open item, resolved — no fix needed:** `soc-dashboard.html`
  and `enterprise-portal.html`, the two lower-confidence candidates flagged
  but never deep-dived, were investigated by reading the full files and
  cross-checking the backend routes they call:
  - `enterprise-portal.html` — legitimately public marketing/integration-docs
    content for prospective enterprise customers (SSO/SIEM/TAXII setup
    steps, roadmap, "Book Integration Session" CTA). No `display:none`, no
    auth code anywhere in the file. Its one API call
    (`/api/enterprise/capability`) is intentionally public server-side
    (`workers/src/index.js` ~line 2853: defaults to `{tier:'FREE'}` on auth
    failure rather than blocking — a status/capability endpoint for
    evaluators). Same category as `ciso-hub.html`; correctly left alone.
  - `soc-dashboard.html` — this one is a real, customer-facing PAID product
    surface (not admin/internal — has an "Upgrade Plan" link and a
    plan-tier chip, i.e. freemium SaaS UX), and it does render its main
    shell (sidebar, KPI cards, alert feed, posture ring, IOC table, attack
    graph) unconditionally with no login wall. Its one internal
    Enterprise-tier gate (`decision-gate` overlay) reads
    `localStorage.getItem('cdb_plan')` client-side — spoofable, same
    anti-pattern class as everything else this investigation has been
    checking for. **But** the underlying data calls
    (`workers/src/handlers/soc.js`: `handleGetAlerts` requires STARTER+,
    `handleGetDecisions` requires `authCtx.tier === 'ENTERPRISE'`) derive
    `authCtx.tier` exclusively from `resolveAuthV5()` — real credentials
    only, never from anything client-supplied — so spoofing the localStorage
    flag bypasses only the cosmetic overlay; the subsequent fetch still gets
    a real server-side 403 and the visitor sees an empty/mock state, not
    real data. No admin or customer data actually exposed. Correctly left
    alone — this is a subscription paywall UX question (worth a future
    product-polish pass: `loadAlerts()`/`loadDecisions()` could check
    `r.ok` like `loadIOCs()` already does, to show "upgrade required"
    instead of a misleading empty state), not the admin-access-control gap
    the customer reported.
  - Neither file has a `<meta name="robots">` tag. Correct/expected for
    `enterprise-portal.html` (should be indexed, same as `ciso-hub.html`).
    Absent on `soc-dashboard.html` too — low-severity since real data is
    already server-gated regardless, but flagged for a future pass.
  - **This closes out every item on wave 1's follow-up list** — 6 candidates
    total, 1 genuine gap found and fixed (`index.html`), 5 false positives
    corrected above, 0 new gaps found on the final 2.

### 2026-07-11 — Customer-reported access-control gap: admin/revenue dashboard shells rendered for any visitor; one real paid-feature bypass in the customer dashboard — wave 1 of the fix (highest-severity cases)

- **Trigger:** a real customer complaint — admin-only sections (specifically
  called out: revenue-related ones) visible to the public in the platform's
  dashboard; paid-customer sections must be paid-customer-only; free
  sections should stay public. Directive: match how Mandiant/CrowdStrike/
  Recorded Future/ThreatConnect/IBM X-Force/Microsoft Sentinel handle this.
- **Investigation, not assumption, before any fix — full account since the
  eventual finding was more nuanced than the complaint's own framing:**
  systematically checked (a) `frontend/user-dashboard.html` (the actual
  day-to-day customer SPA — via a dedicated background investigation, since
  it's the largest single surface) for any revenue/admin content or
  role-detection mechanism, and (b) every standalone `admin`/`revenue`/
  `executive`/`ops`/`kpi`/`decision`-named page (12 files) for its real
  shell-gating and backend-authorization posture, reading actual handler
  code rather than trusting route comments.
- **Finding 1 — backend data authorization is sound.** Checked 6+ endpoint
  families end-to-end by reading the real enforcement code, not just route
  comments: `/api/platform/revenue-intelligence*` (`isOwner()`),
  `/api/platform/kpi*` (`adminGuard()` + `ADMIN_TIERS={OWNER,ADMIN}` — real
  special values, not purchasable plan tiers, confirmed by cross-reading
  `PLAN_ORDER`), `/api/decision/*` (`checkTier()` +
  `ALLOWED_TIERS={PRO,ENTERPRISE,MSSP,OWNER,ADMIN}` — a real paid-tier gate,
  correctly rejecting FREE/anonymous), `/api/admin/customers`
  (`assertAdmin()`), `/api/payment/admin/*` (`isOwner()`),
  `/api/conversion/funnel` (`isOwner()` — the exact endpoint
  `growth-analytics`'s `p4LoadFunnel()` calls, which this session's own
  earlier CAP-CRM-007 fix touched for field names only; confirmed its
  authorization was never weakened). Every one of these fails closed for
  unauthorized/anonymous callers (`resolveAuthV5`'s own IP-fallback path
  returns `tier:'FREE', email:null`, which every one of these gates
  correctly rejects) — no active data breach found in the sample checked.
- **Finding 2 — the real, confirmed gap is frontend shell exposure,
  inconsistently fixed.** The platform already has a proven, secure pattern
  for exactly this problem: `frontend/assets/staff-auth.js` — a real
  magic-link, server-verified-session gate (`GET /api/staff/me` re-verified
  before ever revealing the dashboard; never trusts a stored token alone).
  Its own header comment documents that it replaced a real, previously-
  shipped vulnerability class on 3 pages: a hardcoded shared password,
  "readable via view-source, or bypassable outright with
  `localStorage.setItem('cdb_owner','true')` in devtools." Confirmed 5
  pages correctly use it (`admin-portal.html`, `god-mode.html`,
  `mssp-command-center.html`, `revenue-command-center.html`,
  `proposal-generator.html`) — but the fix was never extended platform-wide.
  `revenue-intelligence-dashboard.html` and `enterprise-kpi-dashboard.html`
  (the two clearest, most severe matches to the complaint — real
  MRR/ARR/churn/NRR business metrics, backend-protected but zero frontend
  gate) rendered their full shell — nav, section headers ("Churn Alerts",
  "NRR Forecast", "Enterprise KPI") — to any visitor. **Also found, not
  just inferred:** both used `credentials:'include'` (cookies) for their API
  calls, but `resolveAuthV5` never checks cookies at all (only
  `Authorization: Bearer`, API keys, or an anonymous IP-fallback) — meaning
  these two pages were simultaneously publicly shell-visible **and**
  completely non-functional for their real, legitimate owner user. Fixing
  onto `staff-auth.js`'s real Bearer-token `authFetch()` fixes both problems
  in the same change.
- **Fixed (this wave — highest severity; more candidates queued, see
  follow-ups):**
  - `frontend/revenue-intelligence-dashboard.html`: added the proven
    gate-overlay pattern (`staff-auth.js` include, `#gateOverlay`/`#gateBox`
    markup, `CDB_STAFF_AUTH.guard()` wrapping all 4 data-load functions +
    the 5-minute auto-refresh interval), replaced all 5
    `credentials:'include'` calls with `CDB_STAFF_AUTH.authFetch()`.
  - `frontend/enterprise-kpi-dashboard.html`: same treatment (1 data-load
    function + auto-refresh interval); also added the `noindex,nofollow`
    meta tag every other staff-gated page already carries (this one had
    none at all — indexable by search engines until now).
  - `frontend/user-dashboard.html`'s `loadCisoMetrics()` (CISO Executive
    Metrics — a real PRO/ENTERPRISE/MSSP paid feature, confirmed backend-
    gated): the free-tier branch showed an upsell banner but never
    `return`ed early, so execution still reached the real API call (which
    the backend correctly 403s) **and then** a client-side fallback that
    recomputed an equivalent risk score / critical count / compliance % /
    30-day trend chart directly from the customer's own already-loaded scan
    history — completely bypassing the backend tier gate. A free-tier
    customer got the full paid feature, just computed in the browser
    instead of the backend, with only a cosmetic nag banner alongside it.
    Fixed: free tier now shows the honest locked/empty state (reusing the
    existing `data._empty` rendering path already used for "no scans yet")
    and never fetches or approximates real metrics. PRO+ behavior
    completely unchanged.
- **Verified:** new `workers/test/adminRevenueShellGating.test.mjs` (11
  tests): confirms both dashboards load `staff-auth.js` and gate all data
  loading behind `CDB_STAFF_AUTH.guard()`; confirms zero remaining
  `credentials:'include'` usage on either page; confirms the free-tier CISO
  branch sets `_empty:true` and never reaches `apiFetch` or `_allScans`;
  confirms the PRO+ path (real API call + scan-history fallback) is
  unchanged; a regression guard directly re-reads `workers/src/index.js` to
  confirm `/api/ciso/metrics`'s tier gate this whole fix depends on is real,
  not just asserted. `node --check` on all 3 modified files' extracted
  script blocks: syntax valid. Full backend suite: 216 files / 2232 tests
  passing (up from 215/2221). `node scripts/registry/validate.mjs`: 0
  failures, 0 warnings. `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Commits this session:** `frontend/revenue-intelligence-dashboard.html`,
  `frontend/enterprise-kpi-dashboard.html`, `frontend/user-dashboard.html`
  (CISO fix only), new test
  `workers/test/adminRevenueShellGating.test.mjs`,
  `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups — deliberately not all done in this same wave, to
  keep this change bounded and reviewable; continuing immediately after:**
  (1) `admin-payments.html` has its own login form but sends an
  `x-admin-secret` header that `resolveAuthV5` never checks at all (the
  real gate is `isOwner()`, Bearer-token-based) — an orphaned, non-
  functional auth mechanism; the backend data is safe (fails closed) but
  the page's own login flow doesn't actually work for its intended owner
  user either. (2) `ops-dashboard.html` and `copilot-admin.html` use an
  older `window.prompt()`-for-admin-key pattern (weaker than the proven
  session-based system, though its target endpoints are backend-gated).
  (3) `decision-dashboard.html` and `security-fabric-dashboard.html` are
  real PAID-customer (not platform-owner) features with backend tier gates
  already confirmed real — need a different fix shape than `staff-auth.js`
  (which is platform-staff-only) to stop rendering their shell before a
  paying customer's own login completes. (4) `index.html` itself still has
  the exact `?owner=1` → `localStorage.cdb_owner` → UI-only-gate pattern
  `staff-auth.js`'s own comment describes as the fixed vulnerability class
  on 3 other pages — 3 sections (`crm-ops-internal`, `proposal-gen`,
  `growth-analytics`) are revealable this way; their underlying data calls
  were checked and are backend-protected, but the shell-exposure problem is
  the same category as everything fixed in this wave. (5) Two lower-
  confidence candidate pages flagged during investigation but not deep-
  dived — `soc-dashboard.html`, `enterprise-portal.html` — need a quick
  content check before deciding whether they need the same fix or are
  already fine (unlike `ciso-hub.html`, confirmed to be a legitimately
  public, search-indexed marketing/lead-gen page and correctly left alone).

### 2026-07-11 — Platform-wide API-wiring audit: confirmed correctly wired to cyberdudebivash.in end-to-end; fixed 2 real outliers

- **Trigger:** the owner asked for a full check — is the entire platform,
  backend to frontend, consistently wired to the platform's own API
  (`https://cyberdudebivash.in/api/`), or are there stray places calling
  somewhere else — before continuing to the next task.
- **Method:** enumerated every distinct external domain referenced anywhere
  in `frontend/` (repo-wide grep for `https?://` targets), then every
  distinct API-base variable declaration (`const/let/var API`/`API_BASE`)
  across all ~40 frontend pages/scripts that define one, then checked the
  entire backend (`workers/src`) for any outbound `fetch()` to a sibling
  cyberdudebivash domain.
- **Finding: the platform is correctly wired end-to-end**, with 2 small,
  real exceptions (below). Of ~40 API-base declarations checked: the large
  majority use a same-origin relative path (`''`) or the explicit
  `https://cyberdudebivash.in`, several with a deliberate, well-engineered
  primary-domain-first-with-resilience-fallback pattern (`frontend/
  index.html`'s `API_ENDPOINTS` array: `CONFIG.API_BASE` primary, raw
  Workers URL fallback, with retry/timeout — a feature, not a bug). The
  backend never calls out to any sibling domain — fully self-contained;
  every `cyberdudebivash.in` URL found in `workers/src` is a developer-
  facing curl/JS/Python code example (`developerOnboardingHandler.js`),
  correctly absolute since those are for external use. One historical bug of
  exactly this class (a non-resolving bare `workers.dev` fallback that made
  a whole dashboard 100% dead) was already found and fixed in an earlier
  pass — `soc-dashboard.html`'s own in-code comment documents it in detail.
- **Ecosystem cross-links are correct as-is, not a gap — owner-confirmed:**
  `tools.cyberdudebivash.com`, `blog.cyberdudebivash.in`,
  `www.cyberdudebivash.com`, and `intel.cyberdudebivash.com` are deliberate
  links to sibling CYBERDUDEBIVASH-vendor properties (a Tools Suite, a blog,
  the core corporate site, and the separate Threat Intel product this
  platform's own API-subscription tiers are sold through — see CAP-MKT-005's
  session entry below). Nothing on `cyberdudebivash.in` fetches data from
  them for core platform functionality; they're navigational cross-
  promotion and, for the API-subscription line, an intentional external
  storefront — not a wiring defect. Explicitly confirmed with the owner
  before treating this as settled.
- **2 real, fixed exceptions — same-platform backend, wrong hostname (not
  an ecosystem-link question at all):** `frontend/index.html`'s
  "CDB_HARDENED_STATS" widget and the entirety of `frontend/gadgets.html`'s
  dashboard engine both hardcoded the raw Cloudflare Workers URL
  (`cyberdudebivash-security-hub.iambivash-bn.workers.dev`) unconditionally
  — this platform's own backend, just not through its own custom domain.
  Both still worked (the raw Workers URL stays live alongside the custom
  domain) but were needlessly fragile and the only 2 places in the whole
  codebase not following the established convention. Fixed:
  `index.html`'s widget now goes through `CONFIG.API_BASE` first (this
  file's own documented primary source) with the same
  `https://cyberdudebivash.in` fallback default; `gadgets.html` now uses a
  same-origin relative base (`''`), matching its own canonical URL
  (`https://cyberdudebivash.in/gadgets`) and the majority-pattern used by
  `billing-portal.html`, `ai-security-scorecard.html`, and others.
- **Verified:** new `workers/test/frontendApiBaseConsistency.test.mjs` (6
  tests): confirms neither file hardcodes the raw Workers URL anymore;
  confirms the new patterns are present; confirms `index.html`'s separate,
  deliberate multi-endpoint resilience fallback (a different, correct
  pattern) is untouched; confirms `gadgets.html`'s API calls (template-
  literal `${API}/api/...` usage) still resolve correctly with an empty-
  string relative base; confirms the ecosystem cross-links weren't
  accidentally removed. `node --check` on both extracted script blocks:
  syntax valid. Full backend suite: 215 files / 2221 tests passing (up from
  214/2215 — the 1 new file). `node scripts/registry/validate.mjs`: 0
  failures, 0 warnings (no domain JSON touched — this is cross-cutting
  frontend infrastructure, not itself a customer-facing capability in this
  registry's schema sense, matching the WAF false-positive fix's precedent
  of not minting a `CAP-*` id for infra-level findings).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Commits this session:** `frontend/index.html` (1 API-base fix),
  `frontend/gadgets.html` (1 API-base fix), new test
  `workers/test/frontendApiBaseConsistency.test.mjs`,
  `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups:** none identified — this was a clean, bounded,
  low-risk consistency fix with no functional behavior change (both pages
  still resolve to the exact same backend, just via the platform's own
  domain instead of bypassing it).

### 2026-07-11 — GDPR/compliance-framework-claims contradiction reconciled (owner: "make the tough decision correctly & perfectly")

- **Trigger:** the owner explicitly delegated the CAP-COMP-005 follow-on
  finding flagged at the end of the prior entry — two files independently
  maintaining compliance-framework claims that disagree on GDPR — with the
  instruction to resolve it correctly, in service of a global production
  customer release and closing competitive gaps (Mandiant/CrowdStrike/
  Recorded Future/ThreatConnect/IBM X-Force/Microsoft Sentinel all publish
  real, audited trust/compliance postures — getting this platform's own
  claims right and internally consistent is table stakes before any of that
  comparison is even fair).
- **Treated as a real evidence question, not a coin flip.** Before picking a
  side, read: DATA_PROCESSING_AGREEMENT_TEMPLATE.md (a real, substantive DPA
  template — 72-hour breach notification matching GDPR Art. 33's own
  timeline, SCC/IDTA-covered international transfers, a named Data
  Protection Officer, sub-processor 30-day notice); `DELETE /api/auth/
  delete-account` (workers/src/handlers/auth.js) — a real, working
  right-to-erasure mechanism, not just documented intent, that anonymizes
  the account row and purges personal data across every table keyed by
  user_id; SUB_PROCESSOR_LIST.md; frontend/privacy-policy.html in full.
  Conclusion: real mechanisms exist (enough to justify "aligned" in
  trustCenter.js's own defined sense — built with real regard for the
  framework, no certification claimed) but nothing formal/audited exists
  (not enough to justify enterprisePortalHandlers.js's stronger, unqualified
  "Aligned — implemented" claim). Landed on "aligned" with an accurate,
  evidence-backed scope_note rather than either original claim verbatim.
- **A narrower worry didn't hold up on a fuller read — noted rather than
  acted on, to avoid manufacturing a problem that isn't there:** an early
  grep hit on frontend/privacy-policy.html's "We process data with your
  explicit consent" looked like a possible mismatch (no consent checkbox
  found in the primary signup flow, frontend/user-dashboard.html). Reading
  the full §3 showed the policy already cites 4 distinct GDPR legal bases
  (Consent, Contract Performance, Legal Obligation, Legitimate Interest) —
  standard, sound multi-basis structure, not a blanket "everything is
  consent-based" claim; "Consent" most plausibly covers §4's separately-
  listed "promotional emails" specifically. One small adjacent finding did
  survive the fuller check: no dedicated marketing-email opt-out/preference
  mechanism exists anywhere in workers/src/handlers/ (confirmed
  notificationPlatform.js / CAP-NOTIF-001 handles a different, unrelated
  channel — Slack/Teams ops-alert webhooks, not email marketing
  preferences) — flagged in the registry as its own small, standalone,
  not-yet-built item, not conflated with CAP-NOTIF-001.
- **Fixed — real single-source-of-truth consolidation, not just a value
  change:** `trustCenter.js`'s `COMPLIANCE_FRAMEWORKS` (previously a local,
  unexported const) is now `export`ed and is the one canonical list, expanded
  from 9 to 12 frameworks (added `ccpa`, `owasp_top10`, `nist_csf2` — real
  claims `enterprisePortalHandlers.js`'s list was already making that
  `trustCenter.js`'s didn't cover at all). `enterprisePortalHandlers.js` no
  longer hand-writes its own `compliance_status.frameworks` array; it now
  imports `COMPLIANCE_FRAMEWORKS` and derives its response via a small
  display-layer transform (`complianceFrameworksForDisplay()`) that
  preserves the existing response shape (`{framework, status, evidence}`,
  Title-Case status strings) for zero frontend changes — this makes the
  specific class of bug that caused the GDPR contradiction (two independent
  hand-maintained copies silently drifting apart) structurally impossible to
  reintroduce by accident, not just fixed for today.
- **Verified:** new `workers/test/complianceFrameworksReconciliation.test.mjs`
  (4 tests): confirms `GET /api/trust/compliance` and `GET /api/trust-center`
  now report the identical GDPR status; confirms every framework the second
  route displays traces back to a real `COMPLIANCE_FRAMEWORKS` entry (byte-
  identical `scope_note`/`evidence`, no orphaned data); confirms the
  reconciled list covers the full 12-framework union; confirms no framework
  claims formal certification or a fabricated audit date. Pre-existing
  `workers/test/truthClaims.test.mjs` (which locks in the *absence* of
  fabricated SOC 2/ISO 27001 claims on this exact route) and
  `workers/test/trustMetricsContract.test.mjs` both still pass unmodified
  against the reconciled data. Full backend suite: 214 files / 2215 tests
  passing (up from 213/2211 — the 1 new file). `node
  scripts/registry/validate.mjs`: 0 failures, 0 warnings (2 more bare-
  filename evidence citations caught and fixed — same recurring class of
  mistake as this session's other 2 registry updates). `scripts/seo-
  structure-lock.mjs`: 22/22 pages green (unaffected — no frontend HTML
  changed).
- **Commits this session:** `workers/src/handlers/trustCenter.js`
  (`COMPLIANCE_FRAMEWORKS` exported + expanded to 12 frameworks, GDPR
  reconciled), `workers/src/handlers/enterprisePortalHandlers.js`
  (`compliance_status.frameworks` now derived from the shared list), new
  test `workers/test/complianceFrameworksReconciliation.test.mjs`,
  `docs/capability-registry/domains/compliance-store.json` (CAP-COMP-005
  entry: reconciliation documented, prior duplicate-list finding closed
  out), `docs/capability-registry/PRODUCTION_READINESS_REPORT.md`
  (regenerated), `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups:** the two dead, byte-identical
  `frontend/assets/(js/)sentinel-apex-live-metrics.js` files (the only prior
  callers of `/api/trust/compliance`, loaded by zero `<script>` tags
  anywhere) are unaffected by this fix — still real, still small, still not
  fixed; either wire one up or delete both, whenever prioritized. The
  marketing-email-preference gap noted above is new-to-the-registry this
  session and not yet a capability with its own ID — worth one if the
  platform starts real promotional email campaigns.

### 2026-07-11 — CAP-MKT-005 catalog question resolved with the owner; corrected diagnosis: the "broken browse-to-purchase journey" premise was wrong; real fix: removed 14 genuinely dead PRODUCT_CATALOG products

- **Trigger:** the owner responded to this session's carried-over CAP-MKT-005
  question (open since the prior session) with real product data from both
  catalogs presented alongside the question: reconcile PRODUCT_CATALOG's
  non-API-subscription products against MARKETPLACE_CATALOG's real,
  browsable ones. Also confirmed the auto-merge-once-green cadence for the
  rest of this session (see the CAP-COMP-005 entry below for that question).
- **The premise turned out to be wrong, caught before writing a reconciling
  data-merge — full account, same discipline as the CAP-COMP-005 catch
  earlier this session:** before touching PRODUCT_CATALOG, read
  `handleRecordPurchase`/`handleCreateSubscription`/`handleUpgradeSubscription`/
  `handleStartTrial`/`handleComparePlans`/`handleROICalculator` in full for
  the first time (the original 2026-07-11 finding had asserted these 5
  sub-actions do a `PRODUCT_CATALOG[product_id]` lookup that would fail for
  any browsed id, without having read what each one actually requires).
  Found: `subscribe`/`upgrade` hard-reject any `product.type !==
  'subscription'` (400); `trial` requires `product.trial_days`, set only on
  2 of 18 products; `compare`/`roi-calculator` never look up a product by id
  at all — both are hardcoded FREE/PRO/TEAM/ENTERPRISE tier tools. Then
  checked whether `marketplaceCheckoutHandler.js` already provides a
  complete, separate purchase path for `MARKETPLACE_CATALOG`'s real
  products: `frontend/sentinel-apex-marketplace.html` (the real browse page)
  fetches the live `GET /api/marketplace/catalog` and links every product to
  `frontend/marketplace-checkout.html?product=<id>`, which reads that param
  and calls the real `POST /api/marketplace/checkout` (a complete Razorpay
  order-creation flow, confirmed by direct read) followed by `/verify`. This
  chain is complete, live, and has never touched `PRODUCT_CATALOG`. The
  "customer can browse a product but can never buy it" framing was
  therefore wrong — that journey already works, on a different code path
  than the one the original finding was looking at.
- **The real, narrower fix:** `PRODUCT_CATALOG`'s 14 non-API-subscription
  products (detection packs, intel reports, defense kits, AI-security packs,
  a bundle) had no coherent purchase path of their own under any
  interpretation — no working self-serve checkout, most `cta_url` fields
  were `mailto:` manual-inquiry links rather than any endpoint in this file,
  and the one structurally-compatible endpoint (`subscribe`, for the 2 of
  the 14 that happened to have `type:'subscription'`) would have returned
  hardcoded `intel.cyberdudebivash.com` API-key/dashboard access info
  regardless of which product was "subscribed" to — nonsensical for e.g. a
  monthly PDF report. Removed as genuinely dead, superseded inventory.
  `PRODUCT_CATALOG` now contains exactly the 4 API-subscription tiers
  (`api-free`/`api-pro`/`api-team`/`api-enterprise`) these 5 sub-actions
  were actually built for; none of their own logic changed.
- **Confirmed safe to remove:** repo-wide grep for each of the 14 ids found
  zero references outside `sentinelApexMarketplace.js` itself and the
  registry entry being corrected, except one already-broken, pre-existing,
  unrelated reference: `workers/src/handlers/intelligencePreview.js`'s
  `yara_signatures.download_url` hardcodes `apt-yara-pack` as a
  `/api/marketplace/download/:accessToken` path parameter —
  `handleMarketplaceDownload` has always rejected this outright (real access
  tokens are 16+ hex characters; `"apt-yara-pack"` never was one). Not fixed
  here — flagged in the registry as its own small, separate finding,
  unaffected by and not affecting this change either way.
- **What remains a real, accurately-scoped gap (not fixed, correctly a
  different kind of task):** none of `purchase`/`subscribe`/`subscriptions-
  upgrade`/`trial`/`roi-calculator`/`compare` has a frontend caller — every
  one of the 4 API-subscription products' own `cta_url` sends customers to
  the external `intel.cyberdudebivash.com` instead. Building a self-serve,
  on-platform signup UI for that line is a real, separate, unscoped
  greenfield feature (the owner explicitly deferred this option this
  session, choosing the smaller cleanup instead) — not a bug fix, a
  different category of work from everything else in this session.
- **Verified:** new `workers/test/marketplaceCatalogCleanup.test.mjs` (20
  tests): confirms all 14 removed ids now 404 on `/api/marketplace/purchase`
  (`it.each`); confirms all 4 real API-subscription products are completely
  unaffected — `purchase`/`subscribe`/`trial` still work end-to-end for
  them; confirms `compare`/`roi-calculator` are untouched; confirms
  `MARKETPLACE_CATALOG` (a different module, `marketplaceCheckoutHandler.js`)
  still has all 12 real products and never contained any of the 14 removed
  ids in the first place (nothing to reconcile there). Full backend suite:
  216 files / 2223 tests passing (up from 213/2203 — CAP-COMP-005's session
  entry below plus this one's 1 new file). `node scripts/registry/validate.mjs`:
  0 failures, 0 warnings (after fixing 2 more bare-path evidence citations —
  the same class of mistake as CAP-COMP-005's, and the original 2026-07-11
  wave-1 lesson — caught a third time this session). `scripts/seo-structure-
  lock.mjs`: 22/22 pages green (unaffected — no frontend HTML changed).
- **Commits this session:** `workers/src/handlers/sentinelApexMarketplace.js`
  (PRODUCT_CATALOG cleanup + corrected comments), new test
  `workers/test/marketplaceCatalogCleanup.test.mjs`,
  `docs/capability-registry/domains/sentinel-apex-marketplace.json`
  (CAP-MKT-005 entry corrected: priority P1→P2, operational_status NOT
  READY→PILOT ONLY, reflecting that there is no broken customer journey
  here), `docs/capability-registry/PRODUCTION_READINESS_REPORT.md`
  (regenerated), `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups:** the self-serve API-subscription signup UI
  opportunity above, if ever prioritized, is real greenfield work — should
  be scoped and estimated as its own initiative, not assumed to be a small
  follow-on to this cleanup. `customer_journey_complete` stays `false` and
  `verification.method` is `dynamic_api` — this pass verified real handler
  behavior with real stubs, not a live production browser pass.

### 2026-07-11 — Second recovery; PR #173 deploy verified live; CAP-COMP-005 misdiagnosis caught before shipping; real fix: platform-metrics mislabeling on 2 customer/prospect-facing surfaces

- **Trigger:** the prior session hit a second hard usage-limit cutoff — this
  time not mid-edit, but mid-way through a scheduled post-merge check for
  PR #173 (CAP-ORG-001), immediately after scheduling a `send_later` wakeup
  to re-check in ~6 minutes. Resumed per a customer request to review the
  attached task-progress transcript and continue with production-grade
  precision.
- **Recovery (EXECUTION_PROCEDURE.md §3):** fresh container. `git status`
  clean; `git log` HEAD matched `origin/main` exactly (`git fetch origin
  main` + bidirectional `git log A..B --oneline` both empty) — PR #173 was
  already merged and no work was lost or stranded, unlike the prior
  cutoff. `mcp__github__list_pull_requests` confirmed zero open PRs (#168-173
  all merged) and PR #173's own body/timestamps directly, rather than
  trusting the transcript's narration alone.
- **Verified PR #173's deploy (the exact check the prior session was
  mid-way through when it was cut off):** fetched
  `https://cyberdudebivash.in/user-dashboard` directly — `loadOrgScans`,
  `orgScansPage`, and the "Scan History" card markup are all present (7
  occurrences each). Deploy landed cleanly; the prior session's scheduled
  check-in is no longer needed.
- **Gap-report triage:** regenerated context confirmed exactly **one**
  genuinely open Critical (P1 + operational_status NOT READY) item across
  the entire registry — CAP-MKT-005, the marketplace catalog mismatch —
  and 20 genuinely open High (P2 + NOT READY) items, the large majority of
  which are full greenfield UI builds or flagged duplicate-system/owner-
  decision situations (CAP-MYTHOS-003, CAP-TIH-014, CAP-CRM-004/006), not
  bounded wiring gaps. Selected **CAP-COMP-005** (Trust Center Compliance
  Framework Alignment) as the best-scoped candidate — its own `notes` field
  said "the only defect is wiring."
- **That diagnosis was wrong, and an initial fix attempt was caught and
  reverted before shipping — full account, since this is exactly the
  failure class this registry's own discipline (EXECUTION_PROCEDURE.md §0:
  "never trust a prior session's narrated summary as evidence by itself")
  exists to catch:** the prior wave-1 domain audit found
  `frontend/trust-center.html` calling
  `https://cyberdudebivash.in/api/trust-center` and, finding no matching
  route in its own read of `trustCenter.js`, concluded the route didn't
  exist and should have been `/api/trust/compliance`. A first fix pass
  rewired the frontend to call `/api/trust/center` +
  `/api/trust/compliance` instead, built a shape-translation layer, and
  wrote passing tests against it — before a router-level test exposed the
  real behavior: `/api/trust-center` **does** exist
  (`workers/src/index.js:5304-5306`) and returns rich, non-empty,
  correctly-shaped data. The route resolves to `handleEnterpriseTrustCenter`
  — an import alias (`workers/src/index.js:527`) that was assumed, without
  checking the `from` clause, to point at `trustCenter.js`'s
  `handleTrustCenter`. It actually imports a **second, different function
  with the same name** from `workers/src/handlers/enterprisePortalHandlers.js`
  — and that function's real response shape (`platform_stats`,
  `compliance_status.frameworks[].{framework,status,evidence}`,
  `vulnerability_disclosure`) matches the frontend's script field-for-field.
  The page was never broken. The in-progress fix and its test file were
  reverted (`git checkout --`, file deletion) before any of it was
  committed.
- **The real bug, found while re-diagnosing:**
  `enterprisePortalHandlers.js`'s `getLivePlatformMetrics()` computed
  `platform_stats.security_scans` (Trust Center) as `COUNT(*) FROM
  service_orders` — paid orders, not scans, a materially smaller number
  under the wrong label — and `cves_in_database` from an always-cold,
  unblended `COUNT(*) FROM threat_intel`, instead of the canonical hydrated
  blend `GET /api/trust/metrics` already uses
  (`handleTrustMetrics`, `workers/src/handlers/trustCenter.js` — already
  imported in this same file, but only ever read for uptime). Grepping for
  other callers of the same function surfaced a **second real caller**,
  `handleEnterpriseSalesKit` (`GET /api/enterprise/sales-kit` — the kit sent
  to prospects evaluating this platform against Mandiant/CrowdStrike/Recorded
  Future/etc.), displaying the identical wrong numbers as `scans_run` /
  `cves_tracked`. This is the same "enterprise-visible contradiction" bug
  class `trustCenter.js`'s own `handleTrustMetrics` doc comment describes
  fixing on its sibling route — unfixed here on a second, independent code
  path until now.
- **Fixed:** `getLivePlatformMetrics()` now calls `handleTrustMetrics()`
  itself and folds `total_scans`/`cves_tracked`/`uptime_pct` into its
  returned object from that one canonical source; both callers inherit the
  corrected values with zero changes to either call site's own body. The
  now-redundant direct `service_orders`/`threat_intel` queries were removed
  entirely (their only two consumers now come from the canonical blend).
- **Also flagged, NOT fixed (a real product/business decision, matching this
  registry's established convention for duplicate-system findings — CAP-CRM-
  004/006, CAP-MKT-005):** `enterprisePortalHandlers.js` maintains its own,
  independent, hand-written 7-framework/3-state compliance list that
  overlaps with but does not match `trustCenter.js`'s 9-framework/2-state
  `COMPLIANCE_FRAMEWORKS`, and on GDPR specifically the two **disagree**
  (`trustCenter.js`: "partial — not yet formally assessed";
  `enterprisePortalHandlers.js`: "Aligned — data minimization, consent,
  deletion rights implemented"). Not currently live-customer-visible — the
  only frontend code that ever called `trustCenter.js`'s
  `/api/trust/compliance` (`frontend/assets/sentinel-apex-live-metrics.js`,
  duplicated byte-for-byte at `frontend/assets/js/sentinel-apex-live-
  metrics.js`) is loaded by zero `<script>` tags anywhere in `frontend/` —
  fully dead code today, confirmed by repo-wide grep. Would become a live
  contradiction the instant either dead copy is ever wired up without first
  reconciling the two lists.
- **Verified:** new `workers/test/enterprisePortalMetricsSourcing.test.mjs`
  (3 tests) — direct handler tests (not router-level; no routing/shadowing
  risk here, unlike CAP-MKT-005) confirming both `handleTrustCenter` and
  `handleEnterpriseSalesKit` return the canonical seeded metrics rather than
  a deliberately-different, deliberately-small `service_orders`-sourced
  number, with a DB stub that **throws** if `service_orders` is ever queried
  again (regression guard, same style as `trustMetricsContract.test.mjs`'s
  own unwritten-key guard); confirms the real uptime-label formatting.
  `node scripts/registry/validate.mjs`: 0 hard failures, 0 warnings (after
  fixing several bare-filename evidence citations the validator correctly
  rejected — the same class of mistake flagged as a lesson in the 2026-07-11
  wave-1 session-log entry below, repeated and caught again here). Full
  backend suite: 213 files / 2203 tests passing (up from 211/2188 — the 1
  new file's 3 tests plus 2 test-runner-only smoke spec files that fail to
  *load* in this environment for an unrelated, pre-existing reason —
  `@playwright/test` is installed by a dedicated CI step
  (`.github/workflows/test.yml:193-195`) this container's plain `npm
  install` doesn't run; confirmed via `git status` that neither smoke spec
  is part of this change). `scripts/seo-structure-lock.mjs`: 22/22 pages
  green (unaffected — no frontend HTML changed in the final fix).
- **Commits this session:**
  `workers/src/handlers/enterprisePortalHandlers.js` (metrics-sourcing fix),
  new test `workers/test/enterprisePortalMetricsSourcing.test.mjs`,
  `docs/capability-registry/domains/compliance-store.json` (CAP-COMP-005
  entry corrected and updated), `docs/capability-registry/
  PRODUCTION_READINESS_REPORT.md` (regenerated), `docs/capability-registry/
  PROGRAM_BOARD.md` (this entry). `frontend/trust-center.html` is
  **unchanged** — the reverted fix attempt never reached a commit.
- **Risks / follow-ups:** (1) the GDPR compliance-claim contradiction and
  dead duplicate `sentinel-apex-live-metrics.js` files above, flagged for an
  owner decision; (2) `customer_journey_complete` stays `false` and
  `verification.method` is `dynamic_api` not `dynamic_browser` — this wave
  verified the real handlers with real stubs, not a live production browser
  pass; a live `dynamic_browser` check of the corrected numbers against
  `cyberdudebivash.in` is the natural next increment; (3) two decisions are
  now with the customer and this session is not proceeding past them
  unilaterally: CAP-MKT-005's catalog-mismatch question (open since the
  prior session), and — new this session, since no durable authorization
  for it was found anywhere in the repo (checked for a `CLAUDE.md`; none
  exists) — explicit confirmation of the auto-merge-once-green cadence
  narrated in the prior session's transcript before continuing to use it,
  given merges here trigger an immediate, ungated live production deploy.

### 2026-07-11 — Recovery + CAP-CRM-007 fix: Conversion Trigger & Funnel Tracking, all 6 call sites

- **Trigger:** the prior session hit a hard usage-limit cutoff mid-edit
  (mid-way through fixing `p4LoadFunnel`, immediately after fixing
  `p4LoadTriggers`/removing `p4ShowTriggers` and fixing `p4CheckPaywall`, per
  its own narrated transcript). Resumed per a customer request to review the
  attached task-progress transcript, audit real state, and continue with
  production-grade precision.
- **Recovery (EXECUTION_PROCEDURE.md §3):** fresh container, so no local
  state survived. `git status` on `claude/production-task-progress-q8el5e`
  was clean; `git log` showed HEAD at `2128b58` (PR #167, `main`) with zero
  divergence — confirmed via `git log origin/main -1` and
  `git diff main origin/<branch> --stat` (empty). Per EXECUTION_PROCEDURE.md
  §0's own stated lesson ("uncommitted work is not real"): the in-flight
  `p4LoadFunnel` edit, and the already-narrated-as-done `p4LoadTriggers`/
  `p4ShowTriggers`/`p4CheckPaywall` fixes, did not exist anywhere in git, on
  any branch, local or remote — none of it was recoverable. All of it was
  independently re-derived from the registry's own CAP-CRM-007 entry and a
  fresh read of `workers/src/handlers/conversionTriggers.js`, then redone
  from scratch and verified before trusting any of it, exactly as this
  document's own discipline prescribes.
- **Fixed — CAP-CRM-007** (`docs/capability-registry/domains/sales-crm.json`):
  all 5 broken frontend call sites into `conversionTriggers.js` (the 6th,
  CTA, was already correct) now match the real backend contract:
  `p4RecordBehaviorEvent()` sends `{session_id,event}` (was
  `{user_id,event_type}` — every call 400'd MISSING_EVENT, including the one
  real production caller, the homepage Enterprise Inquiry form's post-submit
  tracking beacon); `p4LoadTriggers()` queries `?session_id=` and reads
  `d.active_triggers[].{id,cta,title}` (was `?user_id=` /
  `d.triggers[].{trigger_id,cta_text}`, neither ever returned by the
  backend — the trigger list showed "No active triggers." unconditionally);
  `p4ShowTriggers()` deleted as unreachable dead code with its own
  additional internal field-shape bugs; `p4DismissTrigger()` sends
  `session_id` (was `user_id` — every signed-out visitor's dismissal was
  recorded under the single shared key `'anonymous'`); `p4CheckPaywall()`
  queries `?feature=` (was `?feature_id=` — handleGetPaywall 400s
  MISSING_FEATURE without it), which is the highest-severity finding in this
  fix: since a 400 response has no `gated` field, the old code read that as
  falsy and called `onAllowed()` unconditionally — **the paywall gate failed
  OPEN for every feature, on every plan, always.** Confirmed zero current
  blast radius (repo-wide search: `p4CheckPaywall()` itself has zero callers
  anywhere yet), but the fix is required-correct infrastructure before it
  safely can be wired to one. `p4LoadFunnel()` now reads the real
  `d.funnel_stages` (6 stages: Visitors/Ran a scan/Used AI/Viewed
  pricing/Clicked upgrade/Converted, each `{stage,count,pct_of_prev}`) in
  place of a `d.funnel` object shape that never existed
  (`total_sessions`/`signups`/`scans`/`upgrades`/`enterprise`/`revenue_inr`/
  `cta_impressions`/`cta_clicks` — none of these fields exist anywhere in
  `handleGetFunnel`'s response). `#p4-f-visitors` is deliberately left alone
  by the fix (already correctly kept live by the independent
  `loadVisitorStats()` / `GET /api/visitor/stats` — the funnel's own
  `session_start`-derived count would show a near-permanent 0 since
  production code doesn't fire that event today). `#p4-f-upgrades` now maps
  to the real "Converted" stage. `#p4-f-signups`/`#p4-f-revenue`/CTA-impression
  cards are left at their honest static "—" placeholder — no backend concept
  for any of them exists — rather than showing a fabricated number, matching
  this registry's established precedent (CAP-CRM-005's ROI-figure removal).
- **Verified:** `workers/test/conversionTriggersFieldNameFix.test.mjs` (new,
  20 tests) — backend contract-lock tests against a real in-memory-KV-backed
  exercise of all 5 fixed handlers (required-field 400s, real response
  shapes, a dismissed trigger correctly disappearing from a subsequent
  `active_triggers` read, ENTERPRISE-vs-FREE gating), plus frontend
  static body-assertion tests on the corrected field names and
  `p4ShowTriggers`'s removal. Additionally — beyond this registry's usual
  frontend-only-fix precedent of an uncommitted ad-hoc check — a real
  headless-Chromium (Playwright) session drove the actual, unmodified
  extracted script against a minimal DOM harness with all 6 endpoints
  mocked to their exact real shapes: confirmed correct outgoing field names
  on every request, correct rendering of triggers/paywall/funnel from real
  response shapes, and — the critical check — that `onAllowed()` is
  correctly **not** called for a `gated:true` paywall response, proving the
  fail-open bug is closed rather than relocated. Zero console/page errors.
  `node scripts/registry/validate.mjs`: 0 failures, 0 warnings, 95
  capability ids. Full backend suite: 208 files / 2169 tests (up from
  207/2149 — the 1 new file). `scripts/seo-structure-lock.mjs`: 22/22 pages
  green (change is inside `<body>`, outside `<head>`).
  `node --check` on the extracted script block: syntax valid.
- **Commits this session:** `frontend/index.html` (6 function fixes +
  1 grid-column adjustment), new test
  `workers/test/conversionTriggersFieldNameFix.test.mjs`,
  `docs/capability-registry/domains/sales-crm.json` (CAP-CRM-007 entry),
  `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` (regenerated),
  `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups:** (1) `funnel_stages`' 6 stage-defining event names
  are essentially never fired by real production traffic today (only 3 real
  `p4RecordBehaviorEvent()` call sites exist codebase-wide, none using those
  names) — the funnel is now correctly wired but will show sparse data until
  upstream code actually fires them; a real, separate follow-up. (2)
  Signups/revenue/CTA-impression tracking has no backend concept at all —
  would need new backend work, out of scope for this fix. (3) Not yet
  live-verified against production — `customer_journey_complete` stays
  `false` pending a post-merge deploy check, matching established
  convention. **Merge/deploy gate:** per this session's own explicit check
  with the customer, merging to `main` on this repo triggers a live
  Cloudflare production deploy with no separate approval step — PR opened
  and CI watched, but not auto-merged without an explicit go-ahead this
  session (see PR for current status).
- **Production verification (post-merge addendum):** customer authorized
  auto-merge + continued autonomous backlog work for this session. PR #168
  merged (squash `f8bfdb47`), all 32 checks individually green pre-merge, no
  review comments. Deploy confirmed live via content match (corrected field
  names present, old buggy ones absent). Direct live calls against the real
  production backend (`https://cyberdudebivash-security-hub.iambivash-bn.
  workers.dev`, zero mocking, synthetic self-expiring KV data only — no
  permanent CRM/D1 rows created, matching this registry's established
  discipline of not leaving untracked fake records in production) confirmed
  `POST /api/conversion/event`, `GET /api/conversion/paywall`, and
  `POST /api/conversion/dismiss` all now work end-to-end with the corrected
  field names. **`GET /api/conversion/triggers?session_id=...` — this fix's
  own corrected query param — instead returned a raw `{"error":"Bad
  request"}` 400**, not the field-name bug just fixed but a *second, separate,
  pre-existing* WAF false-positive (see the new session-log entry directly
  below this one for the full finding and fix). `customer_journey_complete`
  correctly stays `false` for CAP-CRM-007 pending a follow-up live check
  once that second fix is also deployed.

### 2026-07-11 — CAP-ORG-001: wired the last deferred handler (org-wide scan history); fixed a real pagination-total bug found alongside it

- **Trigger:** continuing the backlog per the customer's "auto-merge +
  continue" authorization, after CAP-MKT-005's catalog-mismatch finding was
  surfaced for a separate decision (still pending). Picked CAP-ORG-001
  specifically because it was "mostly fixed" already (9 of 10 backend
  handlers had real UI as of 2026-07-09) with one small, precisely-scoped,
  deliberately-deferred increment left — not a business decision, not a
  greenfield build, the same shape of task as CAP-CRM-007/CAP-MKT-005.
- **What shipped:** a new "Scan History" card in the organization detail
  view (`frontend/user-dashboard.html`'s `#page-orgs`), module filter +
  Prev/Next pager, calling `GET /api/orgs/:id/scans` — the one backend
  handler (`handleOrgScans`) left unwired in the 2026-07-09 build. Follows
  the existing page's established conventions exactly (card/table markup,
  `apiFetch`/`orgEsc`/`riskColor`/`fmtDate` helpers already used elsewhere
  on the same page) rather than introducing new patterns.
- **Backend bug found and fixed in the same pass:** `handleOrgScans`'
  `total` field was `results?.length` — i.e. always capped at whatever
  `limit` was requested (default 20), never the real row count across the
  org. A pager built directly on it would work fine on page 1 and then have
  no way to tell "more pages exist" from "this is everything" the moment an
  org had more scans than one page — shipping the new UI against the
  as-documented contract without checking would have reproduced the exact
  "looks right until it doesn't" bug class this whole registry exists to
  catch. Fixed with a real `COUNT(*)` over the identical WHERE clause
  (member ids + optional module filter); the `SELECT ... LIMIT ... OFFSET`
  query itself is byte-for-byte unchanged.
- **Verified:** new `workers/test/orgScansPagination.test.mjs` (8 tests) —
  backend tests seed 28 `scan_history` rows (deliberately more than the
  20-row default page size, since the pre-existing 2-row fixture in
  `phase9OrgDashboardSchema.test.mjs` can't distinguish the bug from the fix
  — both return 2 either way) to prove `total` is the real 28, not 20;
  confirm page-2 math (offset=20 → 8 remaining rows, `total` unchanged);
  confirm the module filter narrows `scans` and `total` consistently;
  confirm a non-member and a real member of a *different* org both
  correctly 403 (no cross-org leak). Frontend static tests confirm
  `loadOrgScans()`/`orgScansPage()` use the real field names
  (`target_summary`/`scanned_by`/`risk_score`/`scanned_at`) and the pager's
  disabled-state logic. Additionally, a real headless-Chromium session drove
  the actual, unmodified extracted `loadOrgScans()`/`orgScansPage()`
  functions against a minimal DOM harness seeded with the same 28-row
  fixture: confirmed page 1 shows 20 rows with a correct "1–20 of 28" range
  and Next enabled/Prev disabled; clicking Next shows the remaining 8 with
  "21–28 of 28" and the buttons correctly flipped; clicking Prev returns to
  page 1; the module filter narrows to 3 rows with Next correctly disabled;
  an empty-org response renders "No scans yet." Zero page errors across the
  whole sequence. `node --check` on the extracted script: syntax valid.
  Full backend suite: 211 files / 2188 tests (up from 210/2180 — the 1 new
  file). `node scripts/registry/validate.mjs`: 0 failures, 0 warnings.
  `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Commits this session:** `workers/src/handlers/orgManagement.js`
  (`total` fix), `frontend/user-dashboard.html` (Scan History card +
  `loadOrgScans`/`orgScansPage` + 2 call-site hooks), new test
  `workers/test/orgScansPagination.test.mjs`,
  `docs/capability-registry/domains/organizations.json` (CAP-ORG-001
  entry), `docs/capability-registry/PRODUCTION_READINESS_REPORT.md`
  (regenerated), `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups:** `operational_status` stays `PILOT ONLY` — this
  pass verified against a local harness with a mocked backend, not a real
  `dynamic_browser` pass against live production (true of the entire
  org-management capability since its 2026-07-09 build, not new to this
  increment). A production pass covering the full flow (create → invite →
  scan-history pagination → settings → delete) is the natural next
  increment to flip this to GA, whenever prioritized.

### 2026-07-11 — CAP-MKT-005: removed dead shadowed marketplace routes; discovered and flagged (not fixed) a deeper catalog product-id mismatch

- **Trigger:** continuing the backlog per the customer's "auto-merge +
  continue" authorization, after closing out CAP-CRM-007 and the WAF fix it
  surfaced. Picked CAP-MKT-005 as the most substantial genuinely-unaddressed
  Critical (P1) item — `PRODUCTION_GAP_CLOSURE_MASTER_PROMPT.md` §3.1 lists
  it among the original 9; unlike most of the others (already fixed,
  carrying `PILOT ONLY` as a historical label, not an active defect), this
  one's `NOT READY` reflected a real, still-open issue.
- **Re-confirmed the 2026-07-08 diagnosis still held** (line numbers had
  shifted, substance hadn't): `workers/src/index.js` registers exact-match
  routes for `GET /api/marketplace/catalog`, `GET /api/marketplace/catalog/
  :productId`, and `POST /api/marketplace/checkout` earlier in its if-chain
  (`workers/src/handlers/marketplaceCheckoutHandler.js`, CAP-MKT-002, the
  real live implementation — confirmed via `frontend/marketplace-checkout.
  html`) than the generic `/api/marketplace/*` prefix dispatch that reaches
  `handleMarketplace()`. Since the router returns on first match,
  `handleMarketplace()`'s own internal `handleGetCatalog`/`handleGetProduct`/
  `handleCheckout` were dead code — reachable only via a direct unit-test
  import bypassing the router, never by a real request.
- **Fixed:** deleted the 3 dead functions, their 3 dispatch-table entries,
  and their 2 now-inaccurate mentions in the dispatcher's own 404 hint list
  (`workers/src/handlers/sentinelApexMarketplace.js`). `PRODUCT_CATALOG`
  (shared by this file's other, live sub-actions) was confirmed still used
  elsewhere in the file before touching anything near it, so it was left
  alone. The other 12 sub-actions in the same dispatcher (purchase, webhook,
  subscribe, subscriptions list/cancel/upgrade, orders, entitlements, trial,
  roi-calculator, compare) were never shadowed and are unchanged.
- **Discovered while verifying the fix — NOT fixed, flagged for an owner/
  product decision:** `PRODUCT_CATALOG` (18 products — API subscriptions,
  kits, bundles — used by this file's live purchase/subscribe/subscriptions-
  upgrade/compare/trial actions) and `MARKETPLACE_CATALOG` (12 products —
  detection packs, playbooks, intel reports — `marketplaceCheckoutHandler.js`,
  what a customer actually sees via the real, live `GET /api/marketplace/
  catalog`) share **zero product ids**, confirmed by diffing both sets
  programmatically. A product a customer discovers by browsing the real
  catalog can never successfully resolve on subscribe/purchase/upgrade/
  compare/trial — each does a `PRODUCT_CATALOG[product_id]` lookup that's
  `undefined` for every id the customer could actually have. This is likely
  *why* the 2026-07-08 finding could never find a frontend caller for those
  5 sub-actions (plus roi-calculator) in the first place — wiring a UI to
  them from the browsable catalog would not have worked. Whether these are
  two genuinely different product lines that were never meant to share an
  id space, or a real reconciliation is overdue, is a product decision this
  pass deliberately did not make unilaterally — matching this registry's
  established convention for duplicate-system findings (CAP-CRM-004,
  CAP-CRM-006): flag for an explicit decision, don't guess which side is
  canonical or merge them without one.
- **Verified:** new `workers/test/marketplaceDeadCodeRemoval.test.mjs` (4
  tests) — critically, run against the **real router** (`worker.fetch()`),
  not `handleMarketplace()` in isolation, since the registry's own prior
  note flagged that a direct-import test would not have caught the original
  shadowing bug: confirms `GET /api/marketplace/catalog` and `/catalog/
  :productId` now return `marketplaceCheckoutHandler.js`'s real response
  shape (INR pricing, `total_products` — the removed dead code answered in
  USD with a `total` field, so this also positively distinguishes which
  implementation is answering, not just that *a* 200 came back); confirms a
  direct call to `handleMarketplace()` for the 3 removed paths now falls
  through to its own 404 instead of a shadowed handler, with the 404 hint
  list no longer claiming to serve them; spot-checks 3 of the 12 untouched
  live sub-actions still work. Full backend suite: 210 files / 2180 tests
  (up from 209/2176 — the 1 new file). `node scripts/registry/validate.mjs`:
  0 failures, 0 warnings. `scripts/seo-structure-lock.mjs`: 22/22 pages
  green (unaffected — no frontend HTML touched). `operational_status` stays
  `NOT READY` — the dead-code risk is closed, but the catalog-mismatch
  finding is arguably an equally real "broken customer journey" the moment
  anyone wires a UI to it naively, so this capability is not being marked
  done.
- **Commits this session:** `workers/src/handlers/sentinelApexMarketplace.js`
  (dead-code removal), new test
  `workers/test/marketplaceDeadCodeRemoval.test.mjs`,
  `docs/capability-registry/domains/sentinel-apex-marketplace.json`
  (CAP-MKT-005 entry), `docs/capability-registry/PRODUCTION_READINESS_REPORT.md`
  (regenerated), `docs/capability-registry/PROGRAM_BOARD.md` (this entry).
- **Risks / follow-ups:** the catalog-mismatch finding above is the clear
  next decision point for this capability — surfaced to the customer
  directly (not just logged here) per this session's practice of not
  unilaterally deciding real product/architecture questions.
- **Production verification (post-merge addendum):** PR #171 merged (squash
  `453b8cd`), all 32 checks green pre-merge, no review comments. Deploy
  confirmed live within minutes: `GET /api/marketplace/catalog` against
  `https://cyberdudebivash-security-hub.iambivash-bn.workers.dev` returns
  `currency: "INR"` and a real `total_products` count, with none of the
  removed dead code's shape (`currency: "USD"`, a `total` field) present —
  confirming the live handler is genuinely the one answering, not just that
  *a* 200 came back.

### 2026-07-11 — WAF false positive: `/on\w{2,20}\s*=/i` blocked real query params (session_id, context, component, min_confidence, month) sitewide, discovered during PR #168's post-merge production verification

- **Trigger:** live-verifying CAP-CRM-007's just-merged fix against real
  production (not local mocks, per this session's "production grade
  precision" mandate) surfaced `GET /api/conversion/triggers?session_id=...`
  — the exact corrected call CAP-CRM-007 now makes — returning a raw
  `{"error":"Bad request"}` 400, 0ms response time (rejected before routing).
  Confirmed not a regression from PR #168 by testing `GET
  /api/conversion/cta?context=general`, a route/param this session never
  touched, which 400'd identically.
- **Root cause:** `workers/src/middleware/security.js`'s `BLOCKED_PATTERNS`
  (checked against `url.pathname + url.search` on every request, before
  routing) included the bare regex `/on\w{2,20}\s*=/i`, intended to catch
  inline HTML event-handler XSS (`onerror=`, `onload=`, `onclick=`). With no
  word-boundary anchor, it also matches "on" appearing *inside* any
  legitimate identifier followed by 2-20 word characters and "=" —
  `"sessi`**`on`**`_id="` and `"c`**`on`**`text="` both satisfy it. A
  repo-wide scan of every `searchParams.get(...)` call across `workers/src`
  (130 distinct param names) found exactly 5 real, live, currently-used
  params that false-positive trip it: `session_id`, `context`, `component`,
  `min_confidence`, `month` — read by `conversionTriggers.js` (both
  `handleGetTriggers` and `handleGetUrgency`), `revenue.js`,
  `aiSecurityCopilot.js` (session continuity), `eop/uptime.js`, and
  `threatFusionEngine.js`/`enterpriseTransformHandler.js`. Any real request
  to any of those routes with that query param has been silently 400ing,
  for every caller, sitewide, since this pattern shipped — a second,
  previously-undiscovered production defect, unrelated to and not
  introduced by PR #168, but directly blocking that fix from working
  end-to-end in production.
- **Fix:** anchored the pattern to a real word boundary:
  `/\bon\w{2,20}\s*=/i`. A genuine inline-event-handler injection is always
  preceded by whitespace, a quote, or a tag boundary — never by a word
  character (`"xonerror="` is not a browser-recognized attribute name
  regardless) — so this loses no real attack coverage while eliminating the
  false positive. One-character change (`\b` added); no other
  `BLOCKED_PATTERNS` entries touched.
- **Verified:** new `workers/test/wafOnAttributeFalsePositive.test.mjs` (7
  tests, zero prior test coverage existed for `inspectForAttacks()` at all):
  direct unit tests confirming all 5 real param names no longer trip it
  while real `onerror=`/`onload=`/`onclick=` payloads (in the realistic
  contexts an attacker actually uses — preceded by a quote, tag, or
  whitespace) still do; full-pipeline integration tests through the real
  router (`worker.fetch()`) confirming `GET /api/conversion/triggers?
  session_id=...` and `GET /api/conversion/cta?context=...` now return real
  200s instead of the raw WAF 400, while a genuine attack query string
  through the same pipeline is still correctly rejected with the WAF 400.
  Full backend suite: 209 files / 2176 tests passing (up from 208/2169 — the
  1 new file). `node scripts/registry/validate.mjs`: 0 failures, 0 warnings
  (unaffected — no registry JSON touched; this is cross-cutting
  infrastructure, not itself a customer-facing capability in this
  registry's schema sense, so no new `CAP-*` id was minted for it).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green (unaffected — no
  frontend HTML touched).
- **Commits this session:** `workers/src/middleware/security.js` (1-line
  regex fix + explanatory comment), new test
  `workers/test/wafOnAttributeFalsePositive.test.mjs`.
- **Scope decision, stated explicitly:** fixed within the same session as
  CAP-CRM-007 (rather than deferred) because it was found live-verifying
  that exact fix and directly blocks it from working end-to-end in
  production; shipped as its own separate PR, not bundled into #168 (already
  merged) — matching this repo's "one wave, one PR" discipline. Not
  pre-cleared with the customer before implementing (unlike CAP-DEVPORTAL-004's
  `sap_`-key question, this had one objectively correct, low-risk,
  fully-tested fix with no product/business judgment call involved) — flagged
  here in full for visibility, per "state scope decisions out loud."
- **Risks / follow-ups:** worth a dedicated pass confirming no *other*
  `BLOCKED_PATTERNS` entry has the same unanchored-substring problem against
  the real 130-param surface (this pass only investigated the one pattern
  that live-blocked an actual request) — flagged, not done here, to keep
  this fix bounded and reviewable. Separately, and pre-existing (not
  introduced or worsened by this fix): `inspectForAttacks()` matches against
  the *raw, undecoded* `url.search` — a fully percent-encoded payload (e.g.
  `%3D` instead of a literal `=`) never contains the literal characters any
  pattern in this list looks for, so it passes through unblocked regardless
  of anchoring. Confirmed live post-deploy (see addendum below) with a
  fully-encoded vs. partially-encoded version of the same payload: only the
  latter (literal `=`/`(`/`)`, the form the existing test suite already
  covers) is blocked. A real, separate, structural WAF finding — worth its
  own dedicated review (decode before inspecting, or match both forms), not
  folded into this already-narrowly-scoped fix.
- **Production verification (post-merge addendum):** PR #169 merged (squash
  `73d5b91`) after resolving a real merge conflict correctly: `main` had
  already advanced past this branch's base via #168's own squash-merge (the
  pre-squash commit `a140098` was confirmed byte-for-byte tree-identical to
  the resulting `main` tip `f8bfdb47`, then just the genuinely-new WAF commit
  was rebased `--onto origin/main`, re-verified in full — 209 files/2176
  tests, validator, SEO lock all green again — and force-pushed with
  `--lease`, per this repo's own branch-discipline rule for exactly this
  situation). All 32 checks green on the rebased commit, no review comments.
  Deploy confirmed live: `GET /api/conversion/triggers?session_id=...` and
  `GET /api/conversion/cta?context=...` both now return real 200s against
  `https://cyberdudebivash-security-hub.iambivash-bn.workers.dev` (zero
  mocking); a literal (non-fully-encoded) `<svg onload=alert(1)>` payload in
  the same query string is still correctly rejected with the WAF 400,
  confirming no real detection coverage was lost.

### 2026-07-11 — Backlog sweep, wave 2 addendum: CAP-COMP-001 post-deploy live verification + CI axe catch

- PR #166 (wave 2) merged (squash 6ca6fb7). CI's Accessibility (axe) check
  — a required job — immediately caught a real, pre-existing WCAG
  color-contrast violation on 3 of the 7 compliance-pack badges (soc2,
  gdpr, nist_csf) the moment the section became visible; it was never
  auditable before since axe-core does not evaluate display:none content.
  Verified the exact failing ratios by reproducing axe-core's own
  relative-luminance/contrast algorithm in a Node script (2.64:1, 3.21:1,
  4.41:1 — all below the 4.5:1 AA minimum), fixed with a lighter same-hue
  `badgeColor` for just those 3 packs' badge text (now 5.5:1+), pushed a
  second commit to the same PR, all 32 checks green including axe, merged.
- Polled live production until the deploy landed, then ran a real
  headless-Chromium session against `https://cyberdudebivash.in` with no
  login: `#compliance-global` renders (`display:block`, real height), all
  7 badges present, and the 3 fixed badges' live computed colors match the
  shipped fix exactly (`rgb(129,140,248)` / `rgb(96,165,250)` /
  `rgb(248,113,113)`). Zero JS errors. `verification.method` upgraded to
  `dynamic_browser`; `customer_journey_complete` stays `false` — this
  verifies discoverability/visibility, not a completed Razorpay purchase.
- No GitHub Actions workflow in this repo runs a Cloudflare deploy step
  directly (confirmed by listing every job on the merge commit's 4
  triggered workflows: gitleaks, CodeQL, `CI — Lint & Validate`, `Test &
  Quality Gate` — none contain a deploy job) — deployment is handled by
  Cloudflare's own git integration outside of Actions. Noted here since it
  changes how "deploy landed" should be verified going forward: poll the
  live site directly rather than looking for an Actions-visible deploy job.

### 2026-07-11 — Backlog sweep, wave 2: CAP-MSSP-001 live re-verification + CAP-COMP-001 fix (nav/auth-gate mismatch)

- **CAP-MSSP-001** (`docs/capability-registry/domains/mssp.json`): the
  dead-end-link fix from 2026-07-08 had never been re-verified against live
  production. Ran a real headless-Chromium session directly against
  `https://cyberdudebivash.in`, zero mocking: confirmed both the
  post-checkout and post-free-trial success cards on the live
  `frontend/mssp-onboarding.html` link to `frontend/partner-portal.html`
  ("Go to MSSP Dashboard"), with no link anywhere to the staff-only command
  center; confirmed `frontend/partner-portal.html` renders a real login-link
  request form; submitted a guaranteed-non-existent test email through that
  real form and confirmed `POST /api/partners/login` returns the correct
  generic, non-account-enumerating 200 response. **Deliberately did not**
  exercise the real paid-checkout or free-trial signup, or consume a real
  magic-link token: `workers/src/handlers/msspOnboardingHandler.js` and
  `workers/src/services/msspOps.js` were checked directly and neither
  exposes any partner-deletion capability, so completing that chain would
  leave a permanent, untracktable `mssp_partners` row in production with no
  self-service cleanup (unlike the disposable test accounts used for the
  identity-domain work, cleaned up via `DELETE /api/auth/delete-account`).
  `verification.method` upgraded to `dynamic_browser`; `customer_journey_
  complete` stays `false` with the reasoning recorded directly in the
  registry entry rather than silently overclaimed.
- **CAP-COMP-001** (`docs/capability-registry/domains/compliance-store.json`,
  found during the prior wave's 3-domain audit): fixed. The `#compliance-
  global` section (`frontend/index.html`) carried `data-auth-gate="true"`
  and a `display:none` default, hiding it from logged-out visitors even
  though the backend it calls (`workers/src/services/globalScale.js`)
  requires no auth at all and the nav link stays visible to everyone
  regardless. Fixed by removing both the gate attribute and the default
  hidden style — confirmed via a direct re-read of `cdbNavigate()`'s own
  gate-check logic (`frontend/index.html:14714-14722`) that a section with
  no `data-auth-gate` attribute is no longer redirected away for logged-out
  visitors. Zero backend changes; zero changes to any other gated section.
  New test: `workers/test/complianceGlobalPublicAccess.test.mjs` (5 tests) —
  confirms the gate/hidden-default are gone, the nav link and purchase flow
  are unchanged, and sibling gated sections (`executive-hub`,
  `growth-analytics`) are untouched.
- **Verified:** `node scripts/registry/validate.mjs` → 0 hard failures, 0
  warnings. Full backend suite: 207 files / 2149 tests passing (up from
  206/2144 — the 1 new test file). `scripts/seo-structure-lock.mjs`: all 22
  pages green (change is inside `<body>`, outside `<head>`).
- **Follow-up:** a live production `dynamic_browser` re-check of
  CAP-COMP-001 after deploy is the natural next step before flipping its
  `customer_journey_complete` to `true`, matching the pattern already used
  for CAP-IDN-001/002/003 and CAP-MSSP-001 in this and the prior wave.

### 2026-07-11 — Backlog sweep, wave 1: 3-domain audit (compliance-store, mythos-godmode, threat-hunting-intel) + identity Critical-3 live re-verification

- **Trigger:** customer instruction — proceed one by one through the full
  backlog precisely as counted in `PRODUCTION_GAP_CLOSURE_MASTER_PROMPT.md`
  (9 Critical, 15 High), starting with the 3 domains flagged as never
  audited at all, then sweeping the Critical items, implementing every gap
  found "with 100% complete production grade level" — interpreted per this
  repo's own fixed vocabulary (`docs/ENGINEERING_STANDARDS.md` §9): zero
  Critical, zero High, every capability GA-approved and live-verified, never
  the literal banned phrase.
- **Method:** three background Explore agents, one per domain, each briefed
  with the known adjacent files/schemas and told explicitly to report
  "domain doesn't exist" rather than stretch if nothing real was found.
  Every finding below was independently cross-checked by direct file read
  and/or grep before being written into the registry — agent output was
  treated as a lead, not as ground truth on its own.
- **compliance-store** (`docs/capability-registry/domains/compliance-store.json`,
  was `[]`): 5 real, shipped, revenue-integrated capabilities found, none of
  them the already-catalogued CAP-SCAN-005 free scanner. **CAP-COMP-001**
  (Global Compliance Packs Store, `workers/src/services/globalScale.js`,
  3 live Razorpay routes) — **new Critical (P1)**: the nav link is visible
  to every visitor, but its target section is `data-auth-gate="true"` and
  hidden until login, even though the backend enforces no auth at all and
  the purchase flow needs only an email address. The one visitor most likely
  to buy (a prospect with no account) cannot reach the section. **CAP-COMP-002**
  (Compliance Assessment Engine, `workers/src/services/complianceEngine.js`'s
  `runComplianceAssessment`, a ₹24,999 tier-gated engine reachable via
  `POST /api/scan/compliance` and the service-order pipeline) — new High:
  zero frontend caller, zero tests, invisible to every paying customer today.
  **CAP-COMP-003** (Tools Marketplace toolkits) — backend+frontend+nav all
  genuinely wired, only test coverage missing (Low). **CAP-COMP-004** (DPDP
  Act 2023 Compliance Engine, `workers/src/handlers/dpdpCompliance.js`, 6
  real PRO+/ENTERPRISE-gated routes) — new High: fully backend-only, and
  `frontend/compliance-management.html`'s marketing copy ("automated evidence
  collection", "continuous compliance monitoring") overstates what this or
  any other engine in the domain actually does (a one-off gap assessment,
  not continuous monitoring) — a real content-vs-reality gap in the same
  family `workers/test/proposalGeneratorHonestClaims.test.mjs` was written to
  catch elsewhere. **CAP-COMP-005** (Trust Center Compliance Alignment,
  `workers/src/handlers/trustCenter.js`) — new High, but also a **positive
  finding**: the framework list is deliberately honest ("no formal
  certification held" for ISO 27001), a good reference tone for future
  compliance copy; its only defect is wiring — `frontend/trust-center.html`
  calls an unrelated external URL instead of the real endpoint.
  **Cross-cutting finding:** the same conceptual ISO 27001 pack is sold at
  three different prices (₹4,999 / ₹3,499 / ₹999) through three
  non-cross-referencing backend code paths — recorded, not silently merged.
- **mythos-godmode** (`docs/capability-registry/domains/mythos-godmode.json`,
  was `[]`): 6 real capabilities found, all already customer-facing to some
  degree. **CAP-MYTHOS-001** (the flagship 16-phase GOD MODE orchestrator) —
  backend/frontend/nav/auth/tests all genuinely exist; real gap is a
  declared-but-never-wired RBAC permission (`admin:infra:operate` in
  `workers/src/auth/rbac.js:103`, commented "god-mode / autonomous
  orchestration" but never referenced anywhere), scored Medium (P4), not
  Critical. **CAP-MYTHOS-002** (legacy v1 orchestrator) — a real auth
  inconsistency: `workers/src/index.js` runs its own narrower inline
  `x-admin-key`-only gate before ever reaching the handler's own broader
  `isValidAdminKey()` check, making the broader helper unreachable on this
  route. **CAP-MYTHOS-003** (Revenue Engine: multi-rail checkout, real
  HMAC-SHA256 Razorpay webhook verification) — new High: zero frontend
  caller, zero tests; flagged that a UI should not be built here without
  first confirming it isn't superseded by the platform's existing billing
  flow. **CAP-MYTHOS-004** (Platform Governor, autonomous health monitor) —
  correctly no frontend (internal ops tool), strongest RBAC in the domain.
  **CAP-MYTHOS-005** (AI Provider library) — the best-tested capability
  found this wave, two real regression suites tied to actual past production
  incidents (timeout overrun, prompt-injection defense). **CAP-MYTHOS-006**
  (AI Enrichment Engine) — correctly no dedicated UI, called from 9 other
  handlers. **Dead-schema finding:** `schema_v33_mythos_god_mode.sql`'s
  `mythos_god_mode_runs` table is never referenced anywhere under
  `workers/src` — the real pipeline uses the earlier, plainer `mythos_runs`
  table instead. **Disambiguation recorded to prevent future confusion:**
  "GOD MODE vNN" is also a generic internal release-wave codename used
  ~14 times for unrelated features; "MYTHOS" is also the customer-facing
  AI-chat-widget brand name — neither collides with the real `mythos*.js`
  code.
- **threat-hunting-intel** (`docs/capability-registry/domains/threat-hunting-intel.json`,
  was `[]`): the largest and most fragmented domain audited this session —
  17 distinct capabilities, condensed to 17 registry entries (CAP-TIH-001
  through 017) rather than merged, because the fragmentation itself is the
  headline finding: **three parallel hunting implementations, four parallel
  graph implementations, three parallel correlation implementations, two
  parallel APT-actor systems, and four parallel IOC-enrichment code paths**,
  none sharing an implementation. New Critical/High items: **CAP-TIH-002**
  (v1 API surface: correlations/graph/hunting sub-routes have zero frontend
  callers) and **CAP-TIH-004** (a backend Threat Intelligence Graph,
  `workers/src/handlers/threatGraph.js`, with live CISA-KEV enrichment and
  zero frontend callers anywhere — confirmed **completely independent** of
  the dashboard's own client-side Threat Graph already tracked from an
  earlier wave, sharing only a name) both new High. **CAP-TIH-009** (Threat
  Intel API Economy) and **CAP-TIH-014** (Intelligence Preview freemium
  teasers, whose upgrade URLs point at an *external* storefront,
  `intel.cyberdudebivash.com`, not this platform's own `/pricing` — flagged
  for an owner decision before any UI is built, not assumed to be in scope)
  also new High. Positive findings: **CAP-TIH-006** (Agent Threat
  Advisories) is the most prominently-linked page in the whole domain with
  clean backend+frontend+nav+tests; **CAP-TIH-015** (Public Threat-Intel
  Feeds) is the best-tested capability in the domain. **CAP-TIH-017**
  (legacy scan-to-CVE correlation) is self-declared legacy in its own code
  comment — flagged for a deprecation decision, not built on top of.
- **Identity Critical-3 live re-verification** (`docs/capability-registry/domains/identity.json`):
  CAP-IDN-001/002/003 were fixed in an earlier wave (2026-07-09/10) but
  CAP-IDN-002/003's `verification.method` was still `static` (Playwright
  against a locally-served copy, not live production). Ran a single
  real headless-Chromium session directly against **live production**
  (`https://cyberdudebivash.in`), zero mocking: real signup (`POST
  /api/auth/signup` → 201, real token), real MFA setup (`POST
  /api/auth/mfa/setup`) and enable (`POST /api/auth/mfa/enable` with a
  **real RFC 6238 TOTP code computed locally** — no authenticator app),
  logout, real password login, real MFA challenge view auto-appearing with
  zero token stored mid-challenge, a fresh real TOTP code submitted via the
  actual `#mfa-code` field, `POST /api/auth/mfa/authenticate` completing the
  login with a real token, and the homepage correctly showing a Dashboard
  link instead of Sign In afterward. Test account cleaned up via `DELETE
  /api/auth/delete-account` (200) at the end. **Bug found and fixed in the
  test script itself, not the platform:** the first attempt sent `{ token:
  code }` to `/api/auth/mfa/enable` and got `"totp_code must be 6 digits"`
  back — re-read `workers/src/handlers/mfa.js`'s `handleMFAEnable` directly
  and confirmed the real field name is `totp_code`; corrected the script and
  re-ran clean. All three capabilities' `verification.method` set to
  `dynamic_browser` and `customer_journey_complete` flipped to `true` — the
  exact condition each entry's `contradicts_doc` correction had been waiting
  on since 2026-07-09.
- **Honest backlog accounting:** the 3-domain audit is why Critical went
  9→10 and High went 15→23 this wave (see header table) — this is real,
  previously-invisible backlog becoming visible and counted for the first
  time, not new breakage. All 9 new items (1 Critical: CAP-COMP-001; 8
  High: CAP-COMP-002/004/005, CAP-MYTHOS-003, CAP-TIH-002/004/009/014) were
  added to the working task list alongside the original 24-item backlog.
- **Verified:** `node scripts/registry/validate.mjs` → 0 hard failures, 0
  warnings, 95 unique capability ids across 21 domain files (up from 66/18
  populated + 3 stubs). Every evidence `file:line` citation in all 3 new
  domain files and the identity.json edits resolves to a real file —
  including fixing ~62 bare-filename citations the validator's own
  `file:line` regex correctly rejected on the first pass (e.g. `index.js`
  written standalone instead of `workers/src/index.js` — the validator
  resolves every citation relative to repo root, with no memory of a fuller
  path given earlier in the same string). `node
  scripts/registry/generate-report.mjs` regenerated
  `PRODUCTION_READINESS_REPORT.md` cleanly. Full backend suite:
  206 files / 2144 tests passing (no backend code changed this wave —
  registry JSON + docs only — re-run as a discipline check).
- **Commits/PR:** registry population (3 domain files), `identity.json`
  evidence updates, `PROGRAM_BOARD.md` (this entry),
  `PRODUCTION_READINESS_REPORT.md` regeneration. See PR link in the commit
  that introduces this entry.
- **Follow-ups queued, not yet built:** all 9 newly-discovered items above,
  plus the pre-existing duplication findings (3 parallel hunting engines,
  4 parallel graph engines, 3 parallel correlation engines, 2 parallel
  APT-actor systems, 4 parallel IOC-enrichment paths) — each needs a
  reconciliation decision before more code is added on top, per this
  session's standing discipline of resolving duplicates before building.

### 2026-07-11 — Competitor gap analysis (CrowdStrike, SentinelOne, Palo Alto Cortex, Recorded Future, Google Mandiant, ThreatConnect) — wave 1 fix shipped (org Activity Log), 4 larger gaps scoped for follow-on waves

- **Trigger:** customer asked to research how six named world-class threat-intel/
  security platforms manage production customers, users, paid accounts, admin
  accounts, and CRM, compare strictly against this platform, and fix the gaps
  found — "complete with them at the highest max level globally."
- **Method:** a background research agent gathered publicly-documented
  (vendor docs/help centers/trust pages only, no invented architecture)
  practices across 8 dimensions per vendor: org/tenant model, RBAC/named
  roles, SSO/SAML/SCIM/MFA, admin console capabilities, billing self-service,
  API key management, customer-success/account-management touch, and audit
  logging. In parallel, re-read this session's own capability-registry
  domain files (organizations, rbac, sales-crm, developer-portal-apikeys,
  identity, administration, commercial-billing, customer-portal, mssp) —
  already-verified, evidence-backed ground truth for this platform's actual
  current state, not re-derived from scratch.
- **Cross-vendor patterns found** (full per-vendor detail was in the research
  agent's report; this is the actionable synthesis):
  1. Predefined roles (Admin/Analyst/Viewer-equivalent) enforced **pervasively**
     across the whole product, with growing (if inconsistent) custom-role support.
  2. SAML SSO is table stakes; SCIM is the universal weak point (gated/tied to
     specific IdPs or missing entirely even at these vendors).
  3. MFA is real but usually delegated to the connected IdP.
  4. MSSP/parent-child multi-tenancy is heavily marketed by the three
     endpoint/XDR-rooted platforms, but weak-to-absent at the three "pure"
     threat-intel platforms — not a universal baseline for this sub-category.
  5. **No vendor publishes self-service enterprise billing** above entry tier
     — all quote/sales-mediated.
  6. API keys ride on top of RBAC (permissions inherited from the creating
     user's role) rather than having independent fine-grained scoping; no
     vendor publishes numeric rate limits.
  7. A named Customer Success Manager + onboarding specialist + support-portal
     ticketing is the near-universal public proxy for "how CRM/account
     management works," since real internal tooling is never public.
  8. Audit logging exists in some documented form for 4 of 6 vendors
     (absent for Recorded Future and Mandiant Advantage); ThreatConnect's is
     the most granular (actor/action/timestamp/source IP/session ID).
- **Mapped against this platform's actual, already-verified state — 5
  concrete gaps identified, ranked by how universal the violated pattern is
  and how customer/trust-visible it is:**
  1. **Org RBAC (OWNER/ADMIN/ANALYST/MEMBER/VIEWER) is real and enforced
     within org management itself, but is entirely unwired everywhere else**
     (CAP-RBAC-002's own prior finding) — a VIEWER has identical scan/API-key/
     billing access to an OWNER outside the one org-settings page. Violates
     pattern #1 (pervasive enforcement is the norm, not enforcement scoped to
     one settings page). **Largest, most cross-cutting gap — not attempted
     this wave, needs its own dedicated multi-file effort.**
  2. **API keys: 5 parallel/duplicated systems**, one (`sap_`-prefixed
     growth/plan keys, CAP-DEVPORTAL-004) still cannot authenticate any live
     request at all despite being provisionable. Violates pattern #6 (every
     vendor has exactly one key system tied to RBAC). Prior waves already
     consolidated 2 of the 4 duplicates onto the canonical system
     (CAP-DEVPORTAL-002, -003); the registry's own existing recommendation
     for the last orphan is to confirm with the business owner whether it's
     still a live requirement before investing further — **not re-litigated
     this wave, already correctly scoped as a product decision, not a bug.**
  3. **In-product support ticketing does not exist at all** (CAP-PORTAL-004
     — mailto: links only). Violates pattern #7 (universal vendor baseline).
     **Real, substantial, greenfield feature — scoped out this wave, flagged
     as the clear next-wave candidate** (needs a new schema migration for a
     tickets table, so also needs the same safe-no-op-until-migration
     treatment as the Threat Graph fix).
  4. **Enterprise SSO configuration has a backend (ssoAuth.js) but zero UI
     anywhere, and today only the platform OWNER — not even an org's own
     admin — can configure it** (CAP-ADMIN-002). Violates pattern #2 (every
     vendor has at minimum admin-configurable SAML). **Scoped out this wave
     deliberately** — loosening an owner-only gate to per-org self-service
     has real security-design implications worth its own deliberate review,
     not a quick add.
  5. **No customer-facing audit log** — only a staff-only one
     (CAP-ADMIN-001). Violates pattern #8 (4 of 6 vendors document this).
     **Fixed this wave** — see below; the only one of the five gaps that was
     both fully within a single bounded PR's scope and required zero new
     schema/migration dependency.
- **Fix shipped this wave — CAP-ORG-002, Organization Activity Log:** reuses
  the existing, already-migrated D1 `audit_log` table (same table
  `aiSecurityCopilot.js`'s `writeCopilotAuditLog()` and the SSO handler
  already write to, and the staff console's `handleAdminAudit` already
  merges into its own view) — zero new schema, zero migration dependency,
  unlike the Threat Graph fix. `orgManagement.js` gained `writeOrgAuditLog()`
  (best-effort, never blocks the action it logs) called from all 5 real
  mutating actions (invite/role-change/remove-or-leave/update/delete), plus
  `handleGetOrgAuditLog()` (`GET /api/orgs/:id/audit`, OWNER/ADMIN-only,
  matching every researched vendor's admin-only audit-view bar). Frontend:
  a new "Activity Log" card in the existing org detail view, visible only to
  OWNER/ADMIN (same gate as the existing Settings card), rendering actor
  name, a human-readable action label, and a per-action detail string, all
  HTML-escaped.
- **Verified:** backend — `workers/test/orgAuditLog.test.mjs` (17 tests, real
  in-memory SQLite executing the real handler code): audit rows written
  correctly for every mutating action with correct actor+metadata; audit
  writing degrades gracefully if `audit_log` is unavailable (never blocks
  the org action); the read endpoint correctly 403s a plain MEMBER, a
  non-member outsider, and a real OWNER of a *different* org (no cross-org
  leak); route-registration contract locked in. Frontend — real
  headless-Chromium Playwright session: signup and org-create hit the REAL
  live backend (those routes already exist in production); the one new
  route (`/api/orgs/:id/audit`, which cannot exist on production until this
  merges) was verified via a locally-mocked response shaped field-for-field
  to match the handler's real, already-tested output — confirmed the
  Activity Log card renders correctly with human-readable labels and
  per-action detail, zero JS errors.
- **Commits this session:** `workers/src/handlers/orgManagement.js`
  (`writeOrgAuditLog`, `handleGetOrgAuditLog`, 5 call sites),
  `workers/src/index.js` (route registration), `frontend/user-dashboard.html`
  (Activity Log card + `loadOrgAudit`/`orgAuditDetail`/`ORG_AUDIT_LABELS`),
  new test `workers/test/orgAuditLog.test.mjs` (17 tests).
- **Validator:** 21 domain files, 67 capability ids (up from 66 — new
  CAP-ORG-002), 0 failures, 0 warnings.
- **Tests:** 206 files / 2144 tests passing (full suite, up from
  205/2127). `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** the 4 larger gaps above (pervasive org-RBAC
  enforcement, API-key consolidation of the one remaining orphan, in-product
  support ticketing, enterprise SSO self-service config) are explicitly
  scoped out of this wave, not silently dropped — each has enough detail
  above (and in its own registry entry) to start directly whenever
  prioritized. Support ticketing is the most likely next candidate: it's the
  most universally-expected-by-competitors capability this platform is
  missing entirely, and — like the Threat Graph fix — would need a new
  schema migration prepared but left for the owner to apply via the gated
  workflow.
- **Production verification (post-merge addendum):** PR #161 merged
  (squash `c2cdd6a`). All 32 checks individually inspected green pre-merge.
  Deploy confirmed live. Re-ran the full flow directly against
  `https://cyberdudebivash.in` with zero mocking this time (the new
  `/api/orgs/:id/audit` route now genuinely exists in production): created a
  real org, updated its settings, called the live `/audit` endpoint directly
  (200, 1 real entry, correct action/actor) and confirmed the real UI's
  Activity Log card renders it correctly. Zero JS errors. Test account and
  org cleaned up. Closes the loop for this wave's fix on live production.

### 2026-07-11 — P1: Threat Graph findings-persistence fix — code shipped as a safe no-op, ACTION NEEDED from the owner to activate

- **Trigger:** direct follow-up to the entry below, which diagnosed this gap
  and explicitly stopped short of fixing it pending an owner decision (it
  requires a production D1 schema change). Given the go-ahead to prepare
  the full fix, with the explicit constraint that actually applying the
  migration to production stays a manual, human-confirmed step — not
  something taken unilaterally.
- **What shipped:**
  - `workers/schema_migration_scan_history_findings_2026_07.sql` — adds a
    nullable `scan_history.findings` column. **Not yet applied to
    production.** `schema_master.sql`'s canonical `scan_history` definition
    updated to match (so a brand-new environment gets it automatically).
  - `workers/src/lib/findingsSummary.js` (new) — `distillFindingsForHistory()`
    compacts a scan's real findings (id/title/severity/cvss/cwe_ids, plus
    cve_id/ip/actor when a module's findings carry them) to keep
    `scan_history` rows lean, capped at 20 findings/scan;
    `parsePersistedFindings()` reverses it.
  - `workers/src/lib/queue.js` `insertD1History()` and
    `workers/src/handlers/domain.js` `trackDomainScan()` — both now issue a
    **separate** best-effort `UPDATE scan_history SET findings = ...` after
    their existing, unchanged `INSERT`, each in its own `try/catch`. Built
    this way on purpose: with the migration not yet applied, the column
    doesn't exist yet, so this UPDATE simply fails silently — the original
    INSERT (and the scan response itself) is never at risk. The moment the
    migration runs, this starts working with no further deploy.
  - `workers/src/handlers/history.js` `handleScanHistory()` — tries the
    richer `SELECT ... , findings` first; if that throws (column doesn't
    exist), falls back to the original column list instead of losing D1
    history entirely to the KV shadow copy for the whole pre-migration
    window.
  - `frontend/user-dashboard.html` `initThreatGraph()` — findings with none
    of `cve_id`/`ip`/`actor` (the domain scanner's real shape: `id`,
    `title`, `severity`, `cwe_ids`, no CVE attribution) now get a generic
    `finding` node + edge back to the domain, instead of being silently
    skipped. `tgNodeColor()`/`tgNodeRadius()` extended to style the new type
    (same severity-based treatment as `cve`). Filter dropdown gained a
    "Findings" option. Tooltip now shows CWE ids when present.
  - **Bonus bug caught before it could ever fire:** the existing
    finding-processing loop declared `const cveId` inside the `if
    (f.cve_id)` block, then referenced that identifier from the sibling `if
    (f.actor)` block — out of scope, a guaranteed `ReferenceError` for any
    finding with an `actor` but no `cve_id`. Never triggered before because
    `s.findings` was always empty in production; would have started
    crashing `initThreatGraph()` the moment this fix made findings flow.
    Fixed by hoisting `let cveId = null` above the if-blocks.
- **Verified live** (Playwright, against real `cyberdudebivash.in`, before
  the migration has run): seeded a real scan with real findings (2 findings
  from `scanme.nmap.org`), confirmed `/api/history` and the Threat Graph
  behave exactly as before this change — a safe no-op, zero JS errors,
  zero regression — proving this is safe to merge and deploy now, ahead of
  the schema change.
- **ACTION NEEDED (owner, not automatable from here):** run the "D1 Schema
  Migration (gated)" GitHub Action
  (`.github/workflows/db-migrate.yml`) with `schema_file:
  workers/schema_migration_scan_history_findings_2026_07.sql` and `confirm:
  APPLY`. The workflow takes its own pre-migration backup automatically.
  Once applied, no further deploy is needed — the code already in
  production starts persisting and serving findings on the next scan. I
  can live-verify the Threat Graph showing real relationship edges as soon
  as that's done.
- **Commits this session:** `workers/schema_migration_scan_history_findings_2026_07.sql`
  (new), `workers/schema_master.sql` (scan_history definition updated),
  `workers/src/lib/findingsSummary.js` (new),
  `workers/src/lib/queue.js`, `workers/src/handlers/domain.js`,
  `workers/src/handlers/history.js`, `frontend/user-dashboard.html`, new
  test `workers/test/scanHistoryFindingsPersistence.test.mjs` (16 tests).
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings.
- **Tests:** 205 files / 2127 tests passing (full suite, up from
  204/2111). `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** none from this change itself (it's inert until
  the migration runs). Once active, worth spot-checking a couple of other
  scan modules (redteam, identity) whose finding shapes weren't traced in
  as much detail as the domain scanner's, to confirm they distill sensibly
  too — `distillFindingsForHistory()` degrades gracefully either way
  (missing fields just come through as `null`/absent).
- **Production verification (post-merge addendum):** PR #159 merged
  (squash `2d8dc96`). All 32 checks individually inspected green pre-merge.
  Deploy confirmed live. Re-ran the full flow directly against
  `https://cyberdudebivash.in` with zero local-file substitution: seeded a
  real scan with real findings, confirmed PR #157's Download button still
  works (no regression), the new "Findings" Threat Graph filter option is
  live, the Threat Graph still correctly shows domain-only/zero-edges
  (expected — the migration hasn't been applied yet, exactly the safe
  no-op this was designed for), and zero JS errors across the whole flow.
  **Still waiting on the owner to run the gated D1 migration** — see
  "ACTION NEEDED" above — before the Threat Graph will show real edges.

### 2026-07-11 — P1: Scans page "Download" report link dead for every customer; Threat Graph relationship edges diagnosed as structurally impossible (fix not yet applied — needs owner decision)

- **Trigger:** continuing the same audit directive as the entry below
  ("check everything... the way customers use it"), traced what happens
  *after* a scan completes — does it actually show up correctly across the
  dashboard (Overview, Scans, Threat Graph, CISO Metrics) — since the prior
  wave only fixed getting a real customer's token onto the scan request
  itself, not what the dashboard does with the result afterward.
- **Method:** signed up a fresh account via `user-dashboard.html`, ran a
  real scan of a live target (`scanme.nmap.org` / `example.com`) through
  the now-fixed homepage flow, waited for actual backend completion (not
  simulated), then inspected `/api/history`, the Scans page, Threat Graph,
  and CISO Metrics for that account with real data behind them — the exact
  gap flagged as a follow-up in the previous wave's entry ("Threat
  Graph/CISO Metrics population from a real scan's data... previously only
  tested against empty-state").
- **Finding 1 (FIXED) — Download report link always "—":**
  `renderAllScans()` gated the Download cell on `s.report_url` from `GET
  /api/history`. Grepped every write path to `scan_history`
  (`workers/src/lib/queue.js` `insertD1History()`, the schema itself, and
  the sync path `workers/src/handlers/domain.js` `trackDomainScan()`) —
  none of them, nor the D1 schema, has ever had a `report_url` column or
  concept. This field was permanently `undefined` for every scan of every
  customer since this table shipped; the button never worked, for anyone.
  The backend capability to build a real report already existed, fully
  built and already unit-tested (`workers/test/reportGeneration.test.mjs`):
  `POST /api/report/generate` resolves a report from just a `scan_id` via
  the identity-scoped cache `cacheScanResultForReport()` already writes on
  every scan (confirmed `domain.js` calls it on both the fresh-scan and
  cache-hit paths) — it simply had no caller anywhere on the Scans page.
  Same recurring pattern this whole session: a complete, tested backend
  feature with zero frontend wiring.
  - **Fix:** Download cell now renders a button
    (`onclick="downloadScanReport('${s.scan_id}', this)"`, shown whenever
    the row has a `scan_id` — effectively always) that POSTs
    `/api/report/generate` through the page's own authenticated
    `apiFetch()` and opens the real returned `download_url`. A 422 (scan
    older than the 7-day cache window) shows a friendly toast instead of
    silently doing nothing. Purely additive/frontend-only — zero backend
    changes, zero schema changes.
  - **Verified live** (Playwright, local file relayed against the real
    backend): signed up, ran a real scan of `example.com`, clicked
    Download on the Scans page — it opened a genuine generated report
    (`/api/report/<uuid>`, titled "Domain Security Assessment —
    example.com") in a new tab, not a dead link.
  - **Regression coverage:** `workers/test/scanHistoryReportDownloadFix.test.mjs`
    (5 tests).
- **Finding 2 (DIAGNOSED, NOT FIXED) — Threat Graph can never show
  relationship edges, for any customer, regardless of scan volume:**
  `initThreatGraph()` builds nodes/edges from `s.findings` on each history
  entry — but `scan_history` (both the D1 write path and its KV
  predecessor) has never persisted a `findings` column at all, only
  summary fields (`risk_score`, `grade`, etc.). Confirmed via a direct
  backend call: a real scan of `scanme.nmap.org` returns 7 rich, genuinely
  good findings (MITRE ATT&CK technique mappings, CVSS, CWE, EPSS) in the
  live HTTP response, all of which are discarded the moment that response
  is sent — never written anywhere retrievable. Live-verified end state:
  every real scan produces exactly one isolated "domain" node on the
  Threat Graph and zero edges, forever — the feature is structurally
  incapable of showing a graph, not just occasionally sparse. Even if
  `findings` were persisted, `initThreatGraph()`'s edge-building only
  recognizes `f.cve_id`/`f.ip`/`f.actor` fields — the domain scanner's real
  finding shape (`id`, `title`, `severity`, `cwe_ids`, `mitre_techniques`)
  has none of those, so edges would still not appear for this module
  without also correcting that field mapping.
  - **Why not fixed this wave:** closing this properly needs a new nullable
    column on the live `scan_history` D1 table. Schema changes in this repo
    are deliberately gated behind a manual, human-confirmed GitHub Action
    (`.github/workflows/db-migrate.yml` — requires typing `APPLY`,
    explicitly "manual-only by design: schema changes must never ride
    silently on a code push"). That gate exists on purpose and isn't mine
    to bypass by shipping code that silently depends on a migration no one
    has run yet — doing so risks the D1 history read falling back to its
    (undated) KV shadow copy the moment the richer query is attempted
    against a column that doesn't exist yet in production. Flagged for the
    owner rather than unilaterally scheduling a production schema change.
  - **Recommended next step (owner decision needed):** add a nullable
    `findings` column to `scan_history`, persist a compact
    (id/title/severity/cvss/cwe) summary per scan, extend
    `handleScanHistory`'s SELECT to return it (with a safe fallback query
    if the column isn't there yet), and remap `initThreatGraph()`'s node
    types to the real finding shape instead of the CVE/IP/actor fields
    only some modules populate.
- **Commits this session:** `frontend/user-dashboard.html`
  (`downloadScanReport()` + Download-cell wiring), new test
  `workers/test/scanHistoryReportDownloadFix.test.mjs`.
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings.
- **Tests:** 204 files / 2111 tests passing (full suite).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** Threat Graph fix above is pending an owner
  go-ahead on the schema migration. CISO Metrics' honest-fallback
  arithmetic (derives risk/critical/assets from `_allScans` when the CISO
  API has no data) was exercised live and is already correct given what
  `scan_history` currently stores — it will automatically pick up richer
  CVE-level detail too once/if the findings column lands.
- **Production verification (post-merge addendum):** PR #157 merged
  (squash `8f8698d`). All 32 checks individually inspected green pre-merge.
  `Deploy to Cloudflare` run `29143807090` succeeded. Re-ran the full flow
  directly against `https://cyberdudebivash.in` with zero local-file
  substitution: signed up, ran a real live scan of `example.com`, opened
  the Scans page, clicked Download — it opened a genuine generated report
  (`/api/report/<uuid>`, titled "Domain Security Assessment —
  example.com") in a new tab. Test account cleaned up (200). Closes the
  loop for this finding on the live production site.

### 2026-07-11 — P0: dashboard-authenticated customers silently ran homepage scans as anonymous visitors

- **Trigger:** customer asked for an end-to-end audit of the dashboard from
  the perspective of a real threat-intel/SOC/cybersecurity customer —
  "the way customers want, the way customers use" — covering every button,
  form, and functionality, not just visuals.
- **Method:** since the dashboard's own scan-triggering surface just
  displays scan history/reports (the actual scan execution UI lives on the
  homepage — `runScan()`/`executeScan()`), traced the real, most core
  paid-product action a threat-intel customer takes: running a domain scan.
  Verified the real backend directly first (plain Node `fetch`, no browser)
  to rule out latency as a factor — a live scan of a real domain completed
  in ~4s, well under the client's 8s timeout, confirming the backend itself
  is healthy. Then drove the actual cross-page flow live: signed up via
  `user-dashboard.html` (the platform's primary customer-facing auth
  surface), then navigated to the homepage in the same browser and
  inspected the real outgoing scan request's headers.
- **Root cause:** the homepage's `SUBSCRIPTION` object (backing
  `executeScan()`'s Authorization header, the plan badge, and every
  `data-requires-plan` feature-gate check on the page) reads its session
  token from `localStorage`/`sessionStorage` key `cdb_token` only — correct
  for the homepage's own login/signup/OAuth-callback flows, which do write
  that key. `user-dashboard.html`'s login/signup overlay writes the real
  session token to `sessionStorage['cdb_access']` only. A customer who
  authenticated through the dashboard and then used the homepage's scanner
  had `SUBSCRIPTION.getToken()` return `null` — the exact same key-mismatch
  bug already found and fixed twice this session (the copilot widget, the
  org-invite email lookup), this time in the single shared function a prior
  wave's `scanRequestAuthHeader.test.mjs` fix depends on (that fix correctly
  attached `SUBSCRIPTION.getToken()` to the scan requests, but assumed the
  function itself always resolves a real customer's token).
- **Confirmed live, precisely:** `SUBSCRIPTION.getToken()` returned `null`
  on the homepage for a dashboard-only-authenticated account; the real
  outgoing `POST /api/scan/domain` request fired with no `Authorization`
  header at all.
- **Fix:** `SUBSCRIPTION`'s internal `_loadToken()` now checks
  `sessionStorage.getItem('cdb_access')` first, falling back to its
  existing `cdb_token` checks unchanged — purely additive, zero risk to the
  homepage's own login/OAuth paths. Because every `SUBSCRIPTION.getToken()`
  call site shares this one function, the fix simultaneously corrects scan
  execution, the plan badge, and every feature-gate check on the page for
  any customer whose only login was through the dashboard.
- **Verified live** (Playwright, route-intercepted to serve the locally
  fixed `index.html` against the real backend): `SUBSCRIPTION.getToken()`
  now returns the customer's real `cdb_access` token; the real outgoing
  `POST /api/scan/domain` request now carries `Authorization: Bearer
  <that token>`.
- **Test-methodology note:** two of my own test scripts produced false
  leads before landing on this — `window.SUBSCRIPTION.getToken` (a
  top-level `const` in a classic script never becomes a `window` property,
  even though the bare identifier is globally reachable within the same
  document — this only broke the test's check, not the app) and calling
  `runScan()` without accounting for `leadCaptured` being a plain JS
  variable read from `sessionStorage` once at page load, not re-read live —
  setting the storage key after load did nothing; the fix was to set the
  in-memory variable directly. Both are recorded here so they aren't
  mistaken for app bugs if this area is revisited.
- **Commits this session:** `frontend/index.html` (`_loadToken()` fix),
  2 new tests added to `workers/test/scanRequestAuthHeader.test.mjs`.
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings
  (no registry entry cleanly matched this fix — same precedent as recent
  waves — logged here instead).
- **Tests:** 206 files / 2118 tests passing (full suite, up from
  206/2116). `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** this was a deep, targeted trace of one
  high-leverage flow (scan execution) rather than the literal
  "every button/field/link/form/panel" sweep requested — that scope is not
  achievable with real rigor in a single pass. The same `cdb_token` vs
  `cdb_access` split likely affects other homepage features gated on
  `SUBSCRIPTION` that weren't individually exercised this session (AI
  Analysis, Red Team, Compliance, Cloud Security, Dark Web, AppSec, MCP
  Security, Vibe Code scan modules all route through the same
  `executeScan()`, so they inherit this fix automatically — not
  independently verified one-by-one). Recommend continuing with a similar
  deep-trace approach on other core flows (report generation/download,
  the actual Threat Graph/CISO Metrics population from a real scan's
  data) rather than attempting a shallow full-surface pass.
- **Production verification (post-merge addendum):** PR #155 merged (squash
  `a91449a`). All 32 checks individually inspected green pre-merge (CodeQL,
  both CI Gate jobs, Lighthouse CI mobile, Analyze javascript-typescript/
  python, Unit Tests/Vitest, E2E Smoke, Accessibility axe, SEO Structure
  lock, gitleaks, GitGuardian, Dependency Audit, all lint/folder-structure/
  registry-validation jobs — the two `Live Production Health Gate [main
  only]` runs `skipped` as expected on a PR). Confirmed the deployed
  `index.html` serves the fixed `_loadToken()` ordering via live `curl`.
  Then re-ran the full cross-page flow directly against
  `https://cyberdudebivash.in` with zero local-file substitution (a fresh
  signup through `user-dashboard.html`, no route interception on the
  homepage): `SUBSCRIPTION.getToken()` on the live homepage returned the
  real `cdb_access` token issued at signup, and the live outgoing `POST
  /api/scan/domain` request carried `Authorization: Bearer <that exact
  token>`. Test account cleaned up via `DELETE /api/auth/delete-account`
  (200). This closes the loop the customer's audit requested for this
  specific finding — a dashboard-authenticated customer's login now
  actually counts on the homepage, on the live production site, not just
  in a pre-merge test.

### 2026-07-11 — Enhancement: homepage header/nav visual polish (premium glow treatment)

- **Trigger:** customer, continuing directly from the "Sign In crowded
  off-screen" fix in the same session, asked to enhance the header
  section's links/buttons/page-links to "premium commercial production
  grade quality" — clearly visible, colourful, with an "impactful LED
  glowing indicator, SOC-II style" look, to make the best first impression
  on prospective customers.
- **Scope decision:** interpreted "header section" as the homepage
  (`frontend/index.html`) nav bar and its adjacent compliance-badge ticker
  — the same area just fixed — not a sitewide redesign across every page;
  stated this scoping explicitly rather than guessing silently. Confirmed
  `frontend/assets/main.v10.css` (the stylesheet touched) is used
  exclusively by `index.html`, so the change cannot ripple to other pages.
- **What was genuinely under-styled (verified by reading the actual CSS,
  not assumed):**
  - `.nav-links a` (Free Scan, Pricing, API, AI Security, AI Threat Intel,
    Threat Intel, Trust, Defense, Data Intel, CISO Hub) rendered at
    `color:var(--text-muted)` with a flat color swap on hover — no glow,
    no visual weight.
  - The desktop "Sign In" CTA (injected by `cdbApplyGates()`) was styled
    far more plainly than its own mobile-drawer counterpart: flat gray
    text (`var(--text-muted)`) and a near-invisible `rgba(0,212,255,.2)`
    border, vs. the mobile version's bright gradient + bold cyan text —
    despite being the primary return-customer entry point.
  - `.ticker-item` (the "SOC 2 Type II Ready / GDPR / PCI-DSS / DPDP Act /
    HIPAA…" compliance row) was plain uppercase scrolling text in a single
    flat color (`var(--accent3)`) with no badge/pill treatment at all —
    the literal element the customer meant by "SOC-II style indicators".
- **Fix (CSS-only, zero JS behavior changes):**
  - Brightened nav links to `var(--text)` at .82 opacity, with a glowing
    cyan `text-shadow` on hover instead of a flat color swap.
  - New `.nav-signin-cta` class (gradient background, bold cyan text,
    glowing border, hover lift+glow) applied via `signInLink.className`,
    giving the desktop Sign In CTA the same polish as its mobile
    counterpart.
  - Turned each `.ticker-item` into a glowing pill badge (colored border +
    soft background + box-shadow glow, hover intensifies), with a 4-color
    rotation via `:nth-child` — pure CSS, no HTML edits, so both halves of
    the duplicated seamless-loop marquee track get identical colors
    automatically.
- **Verified live** (Playwright, route-intercepted to serve the locally
  enhanced `index.html` + `main.v10.css` against the real backend):
  screenshotted the actual rendered nav bar and ticker at 1280/1440px
  desktop and 390px mobile. Confirmed: Sign In renders with the new glow
  and remains **fully inside the viewport** at both desktop widths (the
  prior wave's overflow fix still holds); ticker badges render as distinct
  colored glowing pills; the marquee scroll animation (`getComputedStyle
  (track).animationName === 'tick'`) is untouched; the mobile drawer's
  already-good Sign In styling is unaffected; zero new console errors.
- **Commits this session:** `frontend/assets/main.v10.css`,
  `frontend/index.html` (one-line `className` addition),
  `workers/test/homepageHeaderPremiumEnhancement.test.mjs` (new, 6 tests).
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings
  (no registry entry cleanly matched this fix — same precedent as recent
  waves — logged here instead).
- **Tests:** 206 files / 2116 tests passing (full suite, up from
  205/2110). `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** "premium," "colourful," and "impactful" are
  inherently subjective — this wave made a concrete, tasteful,
  live-verified improvement consistent with the site's existing dark/glow
  aesthetic, but is not a claim that every visual preference is now
  satisfied. MASOC/GOD MODE nav pills and the Book Demo CTA were already
  well-styled and were left untouched to keep this wave bounded. If the
  customer wants the same treatment extended to other pages' headers, that
  would need its own explicitly-scoped follow-up (`main.v10.css` is
  homepage-only; other pages use different stylesheets).

### 2026-07-11 — P1: homepage "Sign In" crowded off-screen on desktop by the inert FREEMIUM nav badge

- **Trigger:** customer report: the homepage's "Sign In" entry point lists
  clearly on mobile but not on desktop, and asked specifically whether the
  "FREEMIUM" badge (correctly identified as "not a button, it's just a text
  field") could be removed from the header to fix it.
- **Method:** live Playwright against production at real desktop widths
  (1280px, 1440px, 1920px) before touching anything, screenshotting the
  actual `#main-nav` bar (not just reading the CSS) to see what the customer
  was describing.
- **Root cause:** `frontend/index.html`'s `#nav-links-desktop` is a
  non-wrapping flex row: logo, Free Scan, Pricing, API, AI Security, AI
  Threat Intel, Threat Intel, Trust, MASOC, GOD MODE, the FREEMIUM plan
  badge (`#nav-plan-badge`), Book Demo — followed by `#cdb-nav-actions`
  (API Keys, Defense, Data Intel, CISO Hub, Sign In, search, notifications).
  Confirmed live: at 1280px "Sign In" was pushed fully off-screen (not
  visible at all without horizontal scroll); at 1440px it was clipped right
  at the edge of the viewport. Mobile hides this entire row for a hamburger
  drawer, which is why the customer saw no problem there. The FREEMIUM badge
  — inert branding text with no click target — was one of the widest single
  items in the row, and three separate scripts (`renderPlanBadge`,
  `fixFreeBadge`, `patchBranding`) kept re-showing/re-populating it.
- **Complication found while fixing:** a separate script injects the
  dashboard's "API Keys" quick-access nav button by anchoring off this exact
  element (`insertBefore(keyBtn, navBadge.nextSibling)`). Deleting
  `#nav-plan-badge` from the DOM outright — the obvious first approach —
  would have silently broken that button for logged-in users, a regression
  with no visible symptom in a quick before/after screenshot.
- **Fix:** a CSS override (`#nav-plan-badge { display: none !important; }`)
  forces the badge to permanently render nothing and take zero layout
  space, while leaving the DOM node in place as the anchor. Zero JS changed
  — the various scripts can still set the badge's own inline
  `style.display`/text (used elsewhere as a "does this session have plan
  info" signal) without it ever visually appearing, since the stylesheet
  `!important` wins over inline styles for rendering.
- **Verified live** (Playwright, route-intercepted to serve the locally
  fixed `index.html` against the real backend): badge computed
  `display: none` and still present in the DOM at both 1280px and 1440px;
  "Sign In" now fully inside the viewport at both widths (previously
  off-screen / clipped); manually reproduced the anchor-based "API Keys"
  button injection against the hidden badge and confirmed it still creates
  a visible button in the right place.
- **Commits this session:** `frontend/index.html` (CSS-only),
  `workers/test/homepageNavPlanBadgeOverflow.test.mjs` (new, 3 tests).
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings
  (no registry entry cleanly matched this fix — same precedent as recent
  waves — logged here instead).
- **Tests:** 205 files / 2110 tests passing (full suite, up from 204/2107).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** the desktop nav row is still visually dense (MASOC
  and GOD MODE remain as decorative pills alongside real functional links)
  — removing the one item the customer specifically flagged as non-functional
  resolved the reported symptom at the widths tested, but a narrower desktop
  window (below ~1280px, still above the mobile breakpoint) could still be
  tight. Worth a follow-up pass if a customer reports the same symptom on a
  smaller laptop screen.

### 2026-07-11 — P0: 2FA enrollment permanently broken for every customer; org-invite email case-sensitivity; revoked API keys never left the list; Threat Graph export mislabeled

- **Trigger:** customer asked to continue the audit into the specific
  next-wave targets flagged at the end of the prior session — Organizations
  (create/invite/remove/delete), API Keys (create/revoke), MFA setup, and the
  CISO export buttons — since those involve real state mutation, not just
  page loads, framed as an enterprise-buyer ("Cisco Samsung Intel AMD Dell
  Google customer") acceptance pass.
- **Method:** read every mutation function end-to-end first (Organizations,
  API Keys, MFA setup, CISO/Threat-Graph exports), then drove every flow for
  real against live production with two/three real accounts as needed
  (signup, cross-account org invite, MFA enrollment with a genuine RFC 6238
  TOTP code computed locally from the real returned secret, key create/revoke,
  CSV/PDF/graph export, org delete) — not just reading code, per this
  program's standing methodology. Every surprising result was re-verified
  independently (direct `apiFetch()` calls bypassing the UI, a second signup
  to rule out eventual-consistency, wider network-response capture) before
  being treated as a real finding, which caught and discarded one of my own
  test-script bugs (reading `window._mfaSecret`, a module-scope variable
  never attached to `window`) before it could be mis-reported as an app bug.
- **Finding 1 (P0, most severe — a core security feature was unusable):**
  `frontend/user-dashboard.html` has two elements with `id="mfa-code"`: the
  login overlay's `#mfa-view` (pre-auth 2FA challenge, `doMfaVerify()`, a
  working feature from a prior wave) is static HTML that stays in the DOM
  forever after login (only `display:none`'d, never removed); the Settings
  page's 2FA-**setup** flow (`mfaBeginSetup()`) dynamically injects its own
  `#mfa-code` input into `#mfa-body`. Once both exist, `mfaConfirmEnable()`'s
  `document.getElementById('mfa-code')` always resolves to the FIRST one in
  document order — the hidden, permanently-empty login-overlay input, never
  the visible Settings-page one. Live-confirmed: typed a correctly-computed
  TOTP code into the visible field, clicked the real "Verify & Enable"
  button, still got "Enter the 6-digit code from your app" — **no real
  customer could ever enable 2FA on this platform.** Fixed by renaming the
  Settings-page instance to `mfa-setup-code`; the login-flow instance and its
  `doMfaVerify()`/keydown listener are untouched. Re-verified live end-to-end:
  enable → `ENABLED` badge → disable → `DISABLED` badge, full cycle working.
- **Finding 2 (P1):** `handleInviteMember` (`workers/src/handlers/
  orgManagement.js`) looked up the invitee with a raw, case-sensitive
  `WHERE email = ?`. `handleSignup`/`validateEmail` store every email as
  `trim().toLowerCase()` (and `auth/rbac.js` already normalizes the same way
  for its own user lookups), but the invite endpoint didn't — inviting a
  genuinely-existing teammate by an email copied with different casing (a
  directory export, an email client, a business card) always 404'd with "No
  account found", confirmed against a real account: fresh signup (201),
  independently re-confirmed via a full re-login (200), then still 404'd on
  invite from a different account. Fixed with the same `.trim().toLowerCase()`
  normalization already used identically elsewhere in the codebase for this
  exact purpose.
- **Finding 3 (P1):** `GET /api/keys` (`handleListKeys`,
  `workers/src/handlers/apikeys.js`) returned every key regardless of
  `active` status, so a revoked key stayed permanently visible (with a live
  "Revoke" button) and permanently counted in the dashboard's key list and
  stat badge — even though `handleCreateKey`'s own per-tier limit check
  already correctly filtered to active keys, so the two endpoints disagreed.
  Confirmed live: real `DELETE /api/keys/:id` → 200, "Key revoked", key
  correctly set `active=0` in D1 — the very next `GET /api/keys` still
  listed it and reported `count:1`. Fixed by filtering to `active` keys in
  `handleListKeys` only (the shared `listUserApiKeys()` helper stays
  unfiltered — `handleRotateKey`/`handleKeyUsage` need to see inactive keys
  too, to give correct "already revoked" vs "not found" responses).
- **Finding 4 (cosmetic/trust):** the Threat Graph's "⬇ Export SVG" button
  called `canvas.toDataURL('image/png')` and downloaded a `.png` — it has
  never produced SVG (the graph is a live force-directed canvas simulation,
  no retained vector scene graph). Confirmed live: real PNG magic bytes,
  never XML. Renamed the button and function (`exportGraphPNG`) to match
  what it actually delivers rather than promise a format it can't produce —
  same "don't let a button claim a format it doesn't produce" principle
  already established in this file's `exportCisoPDF()`.
- **Also ruled out as NOT a defect:** creating a 2nd API key on FREE tier
  (1-key limit) while the auto-provisioned first key is still active
  correctly 409s — expected, not a bug. `POST /api/copilot/chat`-adjacent
  403s observed during the sweep trace to normal FREE-tier feature gating,
  consistent with prior waves' findings — not re-litigated in depth here
  since nothing new pointed at a defect.
- **Commits this session:**
  - `frontend/user-dashboard.html` — MFA duplicate-id fix, Threat Graph
    export rename.
  - `workers/src/handlers/orgManagement.js` — email normalization in
    `handleInviteMember`.
  - `workers/src/handlers/apikeys.js` — active-only filter in
    `handleListKeys`.
  - `workers/test/dashboardMfaAndGraphExportFix.test.mjs` (new, 7 tests),
    `workers/test/apiKeysActiveFilterFix.test.mjs` (new, 3 tests), +1 case
    added to `workers/test/orgRbacIsolation.test.mjs`.
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings
  (no registry entry cleanly matched these fixes — same precedent as the
  prior two waves — logged here instead).
- **Tests:** 204 files / 2107 tests passing (full suite, up from 202/2096).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** the org-invite and API-key fixes are backend-only
  (Cloudflare Worker) — this sandbox can't run the Workers runtime locally,
  so unlike the frontend-only fixes (verified pre-merge via the
  route-intercepted-Playwright-against-live-backend technique), these two
  were verified pre-merge via a real in-memory-SQLite test harness
  (`node:sqlite`, mirroring `orgRbacIsolation.test.mjs`'s existing pattern)
  driving the actual handler functions, plus precise code-reading against
  the exact live repro. **Post-merge update (same session):** re-ran the
  exact repro scenarios live against `cyberdudebivash.in` after deploy —
  inviting an existing user by a deliberately mismatched-case + whitespace
  email (`  P0-LIVEB-…@EXAMPLE.COM  `) now returns 201 "added to the
  organization" (was 404); revoking a customer's only API key now correctly
  drops `GET /api/keys` to `{keys:[], count:0}` (was still listing it at
  `count:1`). The MFA fix was also re-confirmed live end-to-end: a real TOTP
  code typed into the visible Settings input now shows "✅ 2FA is now
  enabled" (was "Enter the 6-digit code from your app" on every attempt).
  All four fixes in this wave are now live-verified, not just merged.
- **Next recommended wave:** Organizations (create/invite/role-change/
  remove/delete) and CSV/PDF/PNG exports all worked correctly end-to-end in
  this pass once account-existence was confirmed properly — no further
  findings there. Remaining unexercised mutation surfaces from the original
  ~100-onclick-handler inventory: notification panel actions, session revoke
  (Settings → Active Sessions), and the booking/checkout flows reachable
  from upsell prompts.

### 2026-07-10 — P1: APEX Copilot widget unauthenticated on the dashboard; FAB overlapped sidebar nav; dead AI-analysis badge removed

- **Trigger:** customer asked for a fresh enterprise-buyer-lens audit of the
  live dashboard ("review... as the Cisco Samsung Intel AMD Dell Google
  customer... find out all existing gaps issues... 100% production stable
  fix"), continuing the systematic feature sweep from the prior wave.
- **Method:** re-examined the screenshots and captured console/network
  errors from the prior wave's full 16-section sweep (still on disk) with
  fresh eyes for anything beyond the auth-token bug already fixed, then read
  every file referenced by what the screenshots showed, and re-verified live
  against production with a targeted Playwright run (route-intercepted to
  serve the locally fixed files against the real backend).
- **Finding 1 (P1, sitewide reach):** `frontend/assets/copilot-widget.js` —
  loaded on 250+ pages including `frontend/user-dashboard.html` — is the
  platform's "APEX Security Copilot" chat. Its `authHeaders()` only checked
  `localStorage`/`sessionStorage` key `cdb_token` (correct for
  `index.html`/`god-mode.html`/`intel-hub.html`, which genuinely use that
  key). But the dashboard's own login/signup overlay (`saveTokens()`) writes
  the real session token to `sessionStorage['cdb_access']` only — the same
  key class as the prior wave's fix, this time in a different file. Every
  dashboard customer's copilot conversation silently went out with no
  Authorization header, so the backend treated a paying customer identically
  to an anonymous FREE-tier visitor. Live-verified before/after: the
  `/api/copilot/capabilities` request carried no `Authorization` header
  before the fix; after, it carries `Bearer <the real per-user JWT>` for a
  freshly signed-up, still-in-session user.
- **Finding 2 (P1, visual + likely click-stealing):** `#cdb-copilot-fab` is
  fixed at `left:24/bottom:150` (deliberately chosen, per its own comment, to
  clear the marketing homepage's bottom-right clutter). Nobody accounted for
  `frontend/user-dashboard.html`'s own fixed-height `.sidebar`, whose last
  nav items (API Usage, Settings) render in that exact band — confirmed via
  8+ production screenshots across every dashboard section that the FAB's
  `z-index:99980` sits visually on top of those nav links on every page,
  every time.
- **Finding 3 (cleanup, cosmetic):** the AI Analysis page's
  `#ai-credits-badge` permanently read "— queries left" — dead markup left
  behind after a prior wave removed the JS that used to populate it (per
  that wave's own code comment: the backing field
  `_plan.ai_queries_remaining` doesn't exist in `GET /api/user/plan`'s
  response, so it always showed 0/blank regardless of real tier). The HTML
  span was never removed, so every customer saw a permanent, meaningless
  placeholder on a customer-facing panel.
- **Fix:**
  - `authHeaders()` now checks `sessionStorage.getItem('cdb_access')` first,
    falling back to the existing `cdb_token` checks unchanged — purely
    additive, zero risk to the homepage/god-mode/intel-hub paths that
    genuinely rely on `cdb_token`.
  - `injectStyles()` now detects `document.querySelector('.sidebar')`
    (unique to `user-dashboard.html`) and injects a scoped override moving
    the FAB/panel to `right:24px` at `min-width:769px` — matching the
    sidebar's own `display:none` breakpoint exactly, so it only fires where
    the collision is real. Bottom-right is clear there (the only other fixed
    element, `#toast`, is a transient pill well below `bottom:100px`).
  - Removed the dead `#ai-credits-badge` span outright.
- **Verified live** (Playwright, route-intercepted to serve the fixed files
  against the real backend, fresh signup): FAB renders at `right:24px`,
  bounding-rect confirms it starts entirely clear of the sidebar's right
  edge; opening the copilot panel sends `/api/copilot/capabilities` with a
  real `Authorization: Bearer` header; `#ai-credits-badge` is gone from the
  DOM. No new console errors (the 2 `ERR_BLOCKED_BY_CLIENT.Inspector` lines
  are pre-existing sandbox noise, also present in the prior wave's baseline).
- **Commits this session:**
  - `frontend/assets/copilot-widget.js` — auth-key fix + dashboard FAB
    override.
  - `frontend/user-dashboard.html` — removed dead `#ai-credits-badge`.
  - `workers/test/copilotWidgetDashboardFix.test.mjs` (new, 7 tests).
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings
  (no registry entry cleanly matched this fix — same precedent as the prior
  wave — logged here instead).
- **Tests:** 202 files / 2096 tests passing (full suite, up from 198/2077).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green. Note: 2 E2E spec files
  (`tests/e2e/smoke.spec.mjs`, `hardening/smoke.spec.mjs`) fail to import in
  this local sandbox (`@playwright/test` not installed here) — pre-existing,
  unrelated to this change; CI's dedicated E2E job runs these separately.
- **Risks / follow-ups:** the copilot widget's `cdb_token`/`cdb_access` split
  is a symptom of the platform running two parallel, independently-issued
  session systems (the homepage's own login/purchase flow vs. the
  dashboard's). Every other page that embeds this widget was re-checked only
  for the specific collision found here, not exhaustively re-audited — worth
  a follow-up grep for any other page-specific fixed-position elements that
  might collide with the FAB the same way the dashboard sidebar did.
- **Next recommended wave:** continue the dashboard feature audit —
  Organizations (create/invite/remove/delete), API Keys (create/revoke), MFA
  setup, and the CISO export buttons (PDF/CSV/SVG) are still the highest-value
  next targets since they involve real state mutation, not just data display
  (carried over from the prior wave, not yet started).

### 2026-07-10 — P0: 7 dashboard sections silently unauthenticated for every real customer

- **Trigger:** customer asked for a systematic feature-by-feature audit of
  `frontend/user-dashboard.html` ("test each and every button, field, form,
  feature... find out all the gaps"), driven in a real Chromium browser.
- **Method:** inventoried all 16 sidebar sections + ~100 onclick handlers by
  reading the file, then drove a real headless-Chromium session (signup →
  every section → cleanup) against live production. A broad sweep flagged
  401s on My Tools/Subscriptions/API Usage that a normal 403 (paid-tier gate)
  wouldn't produce — traced to the actual code rather than assumed.
- **Root cause:** the real session token is written exclusively to
  `sessionStorage['cdb_access']` (`saveTokens()`, called by
  doLogin/doSignup/doMfaVerify). Six call sites across five functions
  (`loadMyTrainings`, `loadMyDeliveries`, `loadMyTools`, `loadUserReports`,
  `apexFetch` + `loadIntelReports`'s own guard) instead read
  `localStorage.getItem('cdb_token')` — a key the dashboard's own login flow
  never writes; it belongs to an unrelated flow (the homepage's anonymous
  scan/lead-capture code + an OAuth callback page). Always null for a
  customer who logged in normally, so My Trainings/My Purchases/My
  Tools/My Reports/Intel Reports/Subscriptions/API Usage — 7 sections —
  either showed "Sign in to view…" or 401'd, even while genuinely
  authenticated.
- **Second, independent bug found in the same pass:** `loadMyTools()`'s
  "Scans Today" stat read `usage.today_count`, a field that has never
  existed in `GET /api/user/plan`'s response (live-verified: the real field
  is `usage.scans_used`, a **monthly** counter — the same field
  `loadPlan()` already reads correctly for the Overview tab). Relabeled to
  "Scans This Month" to match the data instead of inventing a fake daily
  counter.
- **Fix:** all 6 call sites now read `sessionStorage.getItem('cdb_access')`.
  Verified live end-to-end (Playwright, route-intercepted to serve the fixed
  file against the real backend): all 7 sections now render the correct
  authenticated (empty-for-a-new-account) state and every affected endpoint
  (`/api/user/plan`, `/api/keys`, `/api/user/reports`,
  `/api/delivery/my-purchases`, `/api/marketplace/{orders,entitlements,
  subscriptions}`) returns 200, not 401.
- **Also ruled out as NOT a defect (worth recording so it isn't re-flagged):**
  `/api/intel/actors`, `/api/intel/techniques`, `/api/intel/stix`,
  `/api/taxii/collections` answer anonymous requests with real data —
  initially looked like a broken-auth gap, but tracing the code
  (`threatIntelPro.js`) shows this is a deliberate freemium tier: base
  reference data (MITRE ATT&CK is public domain anyway) is open, while
  `/api/taxii/collections/{ioc,actor}-feed/objects` and the bundled
  actor/IOC content in `/api/intel/stix` correctly gate on
  `tierAtLeast(authCtx, 'PRO'|'ENTERPRISE')` with clean 403+upgrade
  responses. `/api/ioc/enrich` (the one hitting paid third-party APIs) is
  properly rate-limited per user/IP (10/day FREE) via `checkAndTrackUsage()`.
- **Commits this session:**
  - `frontend/user-dashboard.html` — 6-site token-source fix + the
    scans_used/label fix.
  - `workers/test/dashboardPurchasePortalAuthFix.test.mjs` (new, 6 tests).
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings
  (no registry entry cleanly matched this fix — same precedent as the
  funnel-tracking/logout fix in the prior UAT wave — logged here instead).
- **Tests:** 198 files / 2077 tests passing (full suite, up from 197/2071).
  `scripts/seo-structure-lock.mjs`: 22/22 pages green.
- **Risks / follow-ups:** the rest of the ~100 onclick handlers in this file
  (Organizations, API Keys create/revoke, MFA setup, CISO exports, AI
  Analysis submit, notification panel, session revoke, org invite/remove)
  were inventoried (button/input counts captured per section) but not yet
  individually exercised — recommend continuing the same systematic
  button-by-button pass as the next wave.
- **Next recommended wave:** continue the dashboard feature audit —
  Organizations (create/invite/remove/delete), API Keys (create/revoke), MFA
  setup, and the CISO export buttons (PDF/CSV/SVG) are the highest-value
  next targets since they involve real state mutation, not just data
  display.

### 2026-07-10 — P0 release blocker: Authentication Entry-Point Restoration (mobile nav overflow regression)

- **Trigger:** customer supplied a "P0 Release Blocker — Authentication
  Entrypoint Restoration" master prompt reporting that Login/Sign In was "no
  longer consistently visible," treating it as a regression until proven
  otherwise and demanding real-browser (not API/unit-test-only) verification
  before any fix, plus a release gate that a brand-new user and an existing
  customer must both complete the full auth journey on live production
  without developer intervention.
- **Audit first:** read `frontend/index.html`'s nav markup and the
  `cdbApplyGates()` auth-gate IIFE (CAP-IDN-001) in full before writing any
  code. Confirmed via a byte-level diff against a live fetch of
  `https://cyberdudebivash.in/` that production already runs the exact code
  at `main`'s tip (only difference: Cloudflare's automatic email-address
  obfuscation) — ruled out stale-deployment and CDN/service-worker caching
  as causes (`frontend/sw.js` already uses network-first for HTML, confirmed
  correct). Ruled out CSP (script-src allows 'unsafe-inline') and the
  orphaned, unreferenced `frontend/enterprise-ux.js` (zero `<script src>`
  citations anywhere — dead code, left untouched, out of scope).
- **Real browser evidence (root cause):** since this sandbox's Chromium
  cannot reach the network directly (`net::ERR_CONNECTION_RESET` on every
  external host — confirmed with a direct-nav test — while Node's own
  `fetch()` can), built a `page.route()` relay so Chromium could drive the
  REAL `https://cyberdudebivash.in/` with real cookies/CSP/origin intact.
  Measured `#cdb-nav-actions` (search trigger + notification bell +
  hamburger toggle, plus the CAP-IDN-001-injected Sign In pill) at
  320/360/375/390/414/428px: its total content width was a **constant
  424px regardless of viewport**, overflowing every one of those widths.
  `frontend/assets/cdb-mobile-responsive.css` (authored 2026-06-13) never
  constrained that row — it only held 3 fixed-size icon buttons at the time
  and fit fine. CAP-IDN-001 (commit `f3c38d0`, 2026-07-09) later added a 4th,
  ~90px child (the Sign In pill) to the same never-constrained row, 26 days
  after this stylesheet was authored — tipping it into overflow. With
  `overflow-x: clip` on `html`/`body` (added in the same file, for an
  unrelated reason), the excess is silently clipped, not scrollable:
  `#nav-hamburger` (and on narrower phones, part of the notification bell)
  rendered completely outside the reachable viewport, making the mobile nav
  drawer unreachable. Sign In itself stayed visible only incidentally,
  because it's inserted as the row's first child — not by design, and not
  guaranteed to survive any future addition to that row.
- **Secondary hardening (found while reading the same function):**
  `readAuth()` called `localStorage.getItem()` with no try/catch. Any
  browser context where storage access throws (privacy-restricted in-app
  webviews, storage disabled by device policy) aborted the entire
  `initAuthGate()` IIFE before `window.cdbApplyGates` was even assigned —
  silently deleting the Sign In injection, the Dashboard link, and owner
  gates for that visitor, with no visible error. Verified live (Playwright,
  `localStorage` getter forced to throw on every access, matching this
  repo's real-browser-evidence convention) that both before and after: before
  the fix `window.cdbApplyGates` never gets defined; after it, both
  `window.cdbApplyGates` and the Sign In link still exist.
- **Fix:** reclaimed width in `#cdb-nav-actions` itself — hid the
  keyboard-only search trigger on touch (no keyboard to invoke Cmd/Ctrl+K on
  a phone), tightened gaps, shrank the icon buttons and the injected Sign In
  pill, lightly compacted the wordmark below 340px (both text lines kept,
  just smaller — no branding removed). All rules scoped inside existing
  `@media (max-width: 768px)` / `(max-width: 340px)` blocks in
  `frontend/assets/cdb-mobile-responsive.css`, matching that file's own
  documented zero-regression convention (desktop ≥769px untouched; the
  targeted ids/classes only exist on `frontend/index.html`, so the other 85
  pages loading this stylesheet are unaffected). Prototyped the exact CSS
  live via `page.addStyleTag()` against the real production page (iterating
  on measured bounding rects) before writing anything to the repo, then
  re-verified the committed fix end-to-end by serving the modified files
  locally against the real backend: hamburger click opens the drawer, Sign
  In click navigates to `frontend/user-dashboard.html`, `#login-overlay`
  renders visible and functional.
- **Commits this session:**
  - `frontend/assets/cdb-mobile-responsive.css` — mobile nav-actions overflow
    fix (see above).
  - `frontend/index.html` — `readAuth()` guarded with try/catch + safe
    logged-out fallback.
  - `workers/test/homepageMobileNavOverflow.test.mjs` (new, 6 tests) —
    static-parse regression coverage for both fixes.
  - `docs/capability-registry/domains/identity.json` — CAP-IDN-001's
    `frontend`/`navigation`/`test_coverage`/`verification` evidence updated
    in place with this regression + fix (no new capability ID minted — this
    is a regression fix to an existing, already-registered capability, same
    precedent as the funnel-tracking/logout-view-reset fixes in the prior
    UAT wave).
  - `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — regenerated.
- **Validator:** 21 domain files, 66 capability ids, 0 failures, 0 warnings.
- **Tests:** 197 files / 2071 tests passing (full suite, up from 196/2065 —
  exactly +1 file/+6 tests, reconciled). `scripts/seo-structure-lock.mjs`:
  22/22 pages green (unaffected).
- **Findings:** 2 confirmed, independently re-verified regressions — see
  above. Both are narrow, dateable side effects of CAP-IDN-001 (the mobile
  overflow) or a latent gap in the same function CAP-IDN-001 touched (the
  unguarded storage read) — not a new architectural issue.
- **Risks / follow-ups:** the other 85 pages that load
  `cdb-mobile-responsive.css` have their own, structurally different nav
  markup (grep-confirmed: `#cdb-nav-actions` / `#nav-hamburger` exist only in
  `frontend/index.html`) and were NOT audited for their own mobile-nav
  overflow risk in this bounded wave — recommend a dedicated pass if the
  customer wants that guarantee site-wide rather than just on the homepage.
  Six other `localStorage` call sites on the homepage (funnel/analytics
  tracking, non-auth) remain unguarded — deliberately out of scope for an
  auth-entrypoint-visibility fix; flagging rather than silently leaving out.
- **Next recommended wave:** a dedicated mobile-nav-overflow sweep across the
  other 85 pages sharing `cdb-mobile-responsive.css`, or continuing the
  customer's own UAT wave plan (Wave 2: Free/Starter/Pro/Enterprise customer
  dashboards) — owner's call.
- **Production verification (post-merge addendum):** PR #147 merged
  (squash `b5ca4073`). Confirmed all 32 checks green pre-merge (individually
  inspected, not just combined status) and, on the merge commit: `Test &
  Quality Gate`, `CI — Lint & Validate`, `Secret Scan (gitleaks)`, and
  `CodeQL` all `success`; `Deploy to Cloudflare` run `29092316500` `success`
  (2026-07-10T12:21:53Z). Live curl spot-check confirmed the deployed Worker
  serves the new code, not the old broken path (`cdb-mobile-responsive.css`
  contains the new "HOMEPAGE TOP-NAV OVERFLOW" rules; `frontend/index.html`
  contains the guarded `readAuth()` catch block). Then re-ran the real
  headless-Chromium check directly against `https://cyberdudebivash.in/` at
  360px and 390px: hamburger, Sign In, and the notification bell all sit
  fully inside the viewport, the hamburger click opens
  `#nav-mobile-drawer` (`drawerOpen: true`), zero JS errors. This closes the
  loop the customer's added release gate required — a brand-new/anonymous
  visitor can find and use Sign In, on the live production site, in a real
  browser, without developer intervention.

### 2026-07-10 — Production-readiness lifecycle, Wave 3: Production Dashboard UAT (Wave 1 of the customer's own recommended UAT split — public site, signup, login, dashboard nav)

- **Trigger:** customer supplied a "Production Dashboard End-to-End
  Validation" master prompt (P0 release blocker) demanding real-browser UAT
  — not unit/API tests alone — across every dashboard/role, with a
  find-root-cause-and-fix policy for any confirmed defect, and recommended
  splitting the work into bounded dashboard waves (Wave 1: public site,
  signup, login, pricing, payment). Executed Wave 1 of that split.
- **Environment constraint discovered and solved:** headless Chromium in
  this session's sandbox cannot open its own sockets to the public internet
  at all (verified: fails even for `https://example.com`, `net::ERR_CONNECTION_RESET`,
  independent of proxy config, `--no-sandbox`, `--single-process`) — but
  Node's own `fetch()` from the same sandbox reaches the internet fine, and
  Chromium reaches `localhost` fine. Solved by routing every browser request
  through Playwright's `page.route()`/`context.route()` interception layer
  to a handler that performs the actual fetch via Node (permitted), then
  `route.fulfill()`s the browser's request with the real response — the
  browser navigates to the *real* `https://cyberdudebivash.in` URLs directly
  (correct origin, cookies, CSP, relative and absolute URLs all behave
  normally) while every socket is actually opened by Node. Not a proxy or
  TLS-verification bypass — it reuses the same already-permitted egress path
  (Node `fetch()`) that `curl`/`WebFetch` already use in this session, wired
  through Playwright so a full real-browser session becomes possible at all
  in this sandbox. One real gotcha hit and fixed in the harness itself:
  `redirect: 'manual'` combined with `route.fulfill()` mishandled the site's
  `/page.html → /page` clean-URL 308 redirects (`ERR_CONNECTION_RESET` even
  though `curl` proved the real redirect works fine) — switched to
  `redirect: 'follow'` to resolve redirects server-side. Also had to
  short-circuit `Accept: text/event-stream` requests (the homepage opens an
  SSE connection) since a full-buffer-then-fulfill relay hangs forever
  waiting for a stream that never closes.
- **Real defects found and fixed (2):**
  1. **`POST /api/funnel/event` was 403ing for every anonymous visitor**
     (P0, revenue-analytics-breaking). Found live: the homepage's own
     'visit' and 'exit_intent' tracking beacons (`frontend/index.html`)
     both call this endpoint on every page load, and every single call was
     rejected with `{"error":"Forbidden","message":"This resource is
     restricted to the platform owner."}` — confirmed directly via curl
     against production. Root cause: `workers/src/index.js`'s "internal
     back-office owner-only gate" (guarding genuinely-internal routes like
     `/api/revenue/*`, `/api/integrations/*`, and the separate READ-side
     `/api/funnel/metrics` aggregate) had `/api/funnel/event` in its path
     list too — but that route's own registration is explicitly commented
     "public, fire-and-forget" and its handler
     (`handlers/revenue.js` `handleFunnelEvent`) is written to accept a
     null `authCtx` by design (falls back to `userId: null`,
     `email: 'anonymous'`). This is the same bug class this exact gate
     already caused once before (`white-label` was removed from the same
     list for the identical reason, per the gate's own comment) — this
     time nobody had caught that `funnel/event` had the same problem. Net
     effect: the entire visitor funnel-tracking pipeline (visit → scan →
     signup → purchase) has had zero anonymous-visitor data flowing into
     it since whichever change added this path to the list — plausibly why
     the "Revenue Funnel — Live" dashboard widget shows all dashes/zero
     despite real scan activity elsewhere. **Fix:** removed
     `/api/funnel/event` from the gate's path list (one line); the
     sibling READ-side `/api/funnel/metrics` correctly remains owner-only.
  2. **Sign Out left the login overlay on the wrong view** (P2, real UX
     bug, not security). Found live via a full signup→dashboard→sign-out→
     re-login browser session: `doLogout()`
     (`frontend/user-dashboard.html`) clears tokens and shows the overlay,
     but never resets which internal auth view (`login-view`/
     `signup-view`/etc.) is active — so a customer who originally arrived
     via signup (auto-logged-in, never manually switched views) sees the
     **signup form** again after signing out, not the login form. Confirmed
     the re-login flow actually breaks on this: `#login-email` exists in
     the DOM but isn't visible (wrong view active), so a naive "just type
     your email" attempt fails silently. **Fix:** `doLogout()` now calls
     `showAuthView('login-view')` before showing the overlay.
- **Confirmed non-issues (investigated, not fixed):** `/src/mcpControl.js`
  404s in production, but this is a deliberately optional, gracefully-
  degrading module load (`import('/src/mcpControl.js').catch(...)`,
  explicitly commented "Resilient load... any failure degrades silently to
  the no-op fallback") — the file genuinely doesn't exist yet (a scaffolded
  future feature, "GOD MODE v16: MCP Control Client"), and its absence is
  by design, not a regression. `GET /api/dashboard/stream` briefly showed
  503 in one browser-harness run but returned 200 via direct curl
  immediately after — treated as a test-harness artifact, not a confirmed
  production defect. `GET /api/visitor/stats` is also called
  unconditionally from the public homepage (`loadVisitorStats()`) despite
  being correctly owner-gated (its own comment: "Was fully unauthenticated
  — closed as part of the anonymous-exposure audit") — a real but
  low-severity issue (silent 403, `.catch()`-swallowed, no visible
  breakage, `p4-f-visitors` keeps its default) — disclosed as a deferred
  P3 rather than fixed this wave, since the correct fix (gate the frontend
  call behind an owner-session check, not loosen the backend) needs a
  reliable client-side owner-detection signal this pass didn't verify.
- **Verification:** full signup → dashboard → nav (Organizations, API Keys,
  Billing & Plan, Settings — zero page errors on any) → sign-out → re-login
  round trip driven in a real headless-Chromium session against live
  production for both fixes, not just against the local test suite. The
  sign-out fix was specifically verified against the *modified* local
  `frontend/user-dashboard.html` served locally while every `/api/*` call
  was proxied to the real production backend (same interception technique,
  applied to a hybrid local-static + API-proxy server) — confirmed the
  broken repro (stuck on signup-view, re-login times out) before the fix and
  the correct behavior (login-view shown, re-login 200s, dashboard renders)
  after. 8 real test accounts were created on production during this session
  (`uat.wave1*@cyberdudebivash.in`) to exercise the real signup/login/logout
  flows end-to-end — all 8 were cleanly self-service-deleted via
  `DELETE /api/auth/delete-account` afterward (which itself is additional
  confirmation that flow works correctly for every one of them).
- **Tests:** `workers/test/funnelEventPublicAccess.test.mjs` (new, 7 tests,
  real router dispatch via `worker.fetch()`) — anonymous visit/exit-intent
  events now succeed, invalid stages still 400, and every genuinely-internal
  sibling route in the same former gate list (`/api/funnel/metrics`,
  `/api/affiliate/stats`, `/api/revenue/*`) is proven still owner-gated, so
  the fix doesn't over-loosen anything. `workers/test/userDashboardLogoutViewReset.test.mjs`
  (new, 3 tests, static-parse convention matching
  `workers/test/homepageSignInPath.test.mjs`) — locks `doLogout()` calling
  `showAuthView('login-view')` before the overlay is shown. Full backend
  suite green: 196 files / 2065 tests (194/2055 baseline + 2 new files / 10
  new tests, zero regressions).
- **Registry:** no capability-registry domain file touched this wave — both
  fixes are incident-style bug fixes (matching the PR #138–142 precedent)
  without a clean 1:1 capability match (`/api/funnel/event` is
  `handlers/revenue.js handleFunnelEvent`, a different route/handler from
  `CAP-CRM-007`'s `/api/conversion/event` `handlers/conversionTriggers.js
  handleRecordEvent` — confirmed distinct before deciding not to force a
  match). This session log entry is the authoritative record.
- **Remaining in this wave:** pricing-page and payment-CTA browser
  verification (the rest of the customer's own Wave 1 scope) not yet done
  this pass — real payment completion is intentionally out of scope for
  browser UAT (no real Razorpay charge), but order-creation-only
  verification (open checkout, confirm `POST /api/payments/create-order`
  fires correctly, stop before payment) was not reached this session.
- **Risks / follow-ups surfaced:** `GET /api/visitor/stats` frontend/backend
  mismatch (disclosed above, deferred). The browser-sandbox network
  constraint and its route-interception workaround are specific to this
  session's environment, not the product — worth capturing as a reusable
  project skill (`/run-skill-generator`) if browser UAT continues to be a
  recurring need in this environment.
- **Next recommended wave:** finish Wave 1 (pricing page, payment CTA/order
  creation verification), then Wave 2 (Free/Starter/Pro/Enterprise customer
  dashboards) per the customer's own recommended split — or the Wave 2
  payment-platform follow-ups (refund admin UI, webhook-events viewer,
  invoice download) if prioritized higher.

### 2026-07-10 — Production-readiness lifecycle, Wave 2: Payment & Subscription Platform — order-integrity + legacy-route consolidation

- **Trigger:** customer supplied a detailed "P0 Wave 2 — Enterprise Payment,
  Subscription & Billing Platform" master prompt asking for a Phase 1 audit
  of the complete payment/subscription lifecycle (buttons, APIs, webhooks,
  Razorpay integration, manual-payment fallback) followed by implementation
  of only the real gaps found, in one bounded wave — explicitly not a
  rebuild, reusing existing architecture.
- **Recovery:** `git status`/`git log` confirmed PR #143 (this branch's own
  prior wave) had merged (squash) into `main`, and a sibling session's PR
  #142 had also merged. Per the "already-merged PR" rule, restarted this
  branch from `origin/main` (`git checkout -B <branch> origin/main`) rather
  than stacking on stale history.
- **Phase 1 audit (read-only, before any code changed):** read
  `workers/src/handlers/payments.js` (1308 lines, the canonical path — order
  creation, verify, webhook, manual-confirmation, report download, refund
  reference), `workers/src/handlers/subscription.js` (473 lines), and
  `workers/src/lib/razorpay.js` (165 lines) in full, plus targeted greps
  across `workers/src/index.js`, `frontend/user-dashboard.html`, and every
  other file referencing `handleCreateSubscription`/`handleActivateSubscription`.
  Findings, classified per the master prompt's own taxonomy:
  - **Implemented and production-ready:** order creation with coupon support
    and duplicate-order prevention; signature verification (HMAC,
    constant-time compare); webhook idempotency (D1 `INSERT OR IGNORE` on a
    dedup ledger — atomic, not KV); webhook fallback tier-grant (the
    2026-07-10 ₹499-incident fix from PR #140); `payment.failed` → recovery
    pipeline + customer email; manual UPI/Bank/PayPal/Crypto confirmation
    flow (admin + customer emails, plausible-looking-txn-ref validation);
    refunds (`workers/src/handlers/v24Handler.js`, owner-gated, real
    Razorpay refund API call); admin payment views (`GET
    /api/payment(s)/admin/*` — list/stats/approve/reject, owner-gated,
    covered by `workers/test/paymentAdminPanel.test.mjs`).
  - **Implemented but broken (the two findings fixed this wave):** see
    below.
  - **Implemented but with no admin UI (real gap, not fixed this wave):**
    refunds are API-only — no admin-portal page calls
    `POST /api/admin/refunds`; `webhook_events` (the idempotency ledger) has
    no admin-facing viewer.
  - **Missing (real gap, not fixed this wave):** no customer-facing GET/
    download endpoint for invoices/receipts (`createInvoice` in
    `workers/src/services/v24/billingEngine.js` generates them, but delivery
    is email-attachment-only — no billing-portal "download invoice" link
    found).
- **Finding 1 (P0, security/revenue-integrity) — payment/plan tampering in
  `handleVerifyPayment`:** confirmed by direct code read, not assumed.
  `POST /api/payments/verify` (the canonical, most-used verify endpoint)
  determined WHAT to grant/deliver (subscription tier, package product,
  scan-report module) from the client-resent `module`/`target`/`plan`/
  `product_id` fields in the verify request body — never cross-checked
  against the `payments` row's own server-set values from order-creation
  time. The Razorpay signature only proves `razorpay_order_id` +
  `razorpay_payment_id` are a genuine, linked pair; it says nothing about
  which module/plan/product that order was actually priced for. Concretely:
  a customer could create+pay for a ₹499 STARTER subscription order, then
  call `/api/payments/verify` a second time with `plan:'MSSP'` (₹9,999/mo)
  reusing the same genuinely-signed order — the signature check alone would
  still pass, granting the top tier for the bottom price. The identical
  pattern applied to `package`/`product_id` (cheap report → expensive
  assessment) and to scan-report `module` (cheap module → expensive one).
- **Fix 1:** `handleVerifyPayment` now does an authoritative D1 lookup
  (`SELECT module, target, plan FROM payments WHERE razorpay_order_id = ?`)
  immediately after signature-format validation and before any branch logic
  runs; when a matching row exists, its `module`/`target`/`plan` override
  the client-supplied values for the rest of the function (a single ~20-line
  insertion, `module`/`target`/`product_id` changed from `const` to `let` in
  the destructure). Client-supplied values remain the fallback only when no
  D1 record exists (e.g. a DB outage) — harmless, since nothing this handler
  does persists without D1 anyway, matching its existing fail-open posture
  elsewhere. Zero behavior change for any legitimate caller (their own
  resent values already match what's on file).
- **Finding 2 (P0, reliability/data-integrity) — duplicate broken
  subscription system still live:** `POST /api/subscription/create` /
  `POST /api/subscription/activate` (`workers/src/handlers/subscription.js`
  `handleCreateSubscription`/`handleActivateSubscription`) ran their own
  parallel order-creation/verification logic, independent of the canonical
  `payments.js` path. `handleActivateSubscription`'s D1 writes used column
  names that don't exist in the live schema (`order_id`/`payment_id` vs. the
  real `razorpay_order_id`/`razorpay_payment_id`; `processor`/`external_id`/
  `activated_at` vs. the real `subscriptions` schema) — silently swallowed
  by `.catch()`, so every activation attempt charged the customer and never
  activated anything; `users.tier` was never touched at all. This is the
  exact incident PR #142 (a sibling session, same day) found and fixed —
  but PR #142 only repointed the one known frontend caller (the dashboard's
  "Upgrade to Pro" button) at the canonical path; it explicitly disclosed
  in its own PR description that the routes themselves were "left in place
  (not deleted)... would still fail the same way if called directly." Those
  routes were still live, still broken, and still publicly advertised in the
  `/api` index (`GET /api` → `endpoints['POST /api/subscription/create']`)
  for any other caller — an external integration, a future frontend
  regression pointing back at this URL, or direct API use.
- **Fix 2:** rather than delete the routes (backward compatibility is a
  hard requirement per the master prompt's Implementation Rules), both
  functions' internals were replaced with thin delegating wrappers over the
  canonical, now-hardened `handleCreateOrder`/`handleVerifyPayment`
  (`payments.js`), using an internal synthetic-`Request` delegation pattern
  already established elsewhere in this exact file (`payments.js`'s own
  scan-report branch calls `SCAN_HANDLERS[module](synReq, env, paidCtx)` the
  same way) — not a new pattern invented for this fix. Old response shapes
  (`plan`/`plan_name`/`session_token`/`features`/`message`) are preserved
  alongside the new, previously-entirely-missing fields (`token`/
  `refresh_token`/`user_id` — the actual JWT tier grant). The now-unused
  `generateSubscriptionToken()` helper and the `razorpay.js` imports it
  needed were removed as dead code. `index.js`'s route for
  `/api/subscription/activate` now also resolves and passes `authCtx`
  (previously omitted), matching the `/create` route and the canonical
  `handleVerifyPayment(request, env, authCtx)` signature. This also means
  these legacy routes automatically inherit Fix 1's tamper-resistance for
  free, since they now funnel through the same hardened function — exactly
  the "single reusable payment orchestration service" the master prompt's
  Phase 3 asked for.
- **Verification:** `node --check` clean on all 3 modified backend files.
  Ran the 13 pre-existing payment/subscription-adjacent test files first
  (109 tests) to confirm zero regressions before writing new tests — all
  passed unchanged, including `paymentEntitlementE2E.test.mjs`'s existing
  "STARTER purchase does NOT unlock the PRO-gated endpoint (no over-grant)"
  test and `paymentAdminPanel.test.mjs`'s "the former duplicate: POSTing the
  old manual-verify body shape to /api/payments/verify no longer verifies
  anything." Confirmed `workers/test/subscriptionVerifyTierGrant.test.mjs`'s
  mock D1 doesn't match the new authoritative-lookup query shape (its
  `first()` mock only handles two specific SQL patterns), so it exercises
  exactly the documented no-D1-record fallback path — explains why it still
  passes unchanged and is not a false negative.
- **Tests:** `workers/test/paymentVerifyOrderIntegrity.test.mjs` (new, 5
  tests, real in-memory `node:sqlite` with the live `payments`/
  `subscriptions`/`users`/`refresh_tokens` schema incl. the `partner_id`
  column added by `schema_v47_mssp_revenue_share.sql`) — proves a
  genuinely-paid STARTER order cannot be verified as MSSP, a cheap package
  cannot be verified as an expensive one, a cheap scan module cannot be
  verified as an expensive one, the legitimate matching-values flow is
  unaffected, and the no-D1-record fallback preserves pre-fix behavior.
  `workers/test/subscriptionLegacyRouteDelegation.test.mjs` (new, 7 tests) —
  a full create→pay→activate round trip through the legacy routes now
  proves a real `users.tier` grant + usable JWT (the exact thing PR #142
  found completely missing), a tampered-plan activate attempt is neutralized
  via the inherited order-integrity fix, invalid-plan/missing-email
  rejections, and a route-wiring contract check against `index.js`. Full
  backend suite green: 194 files / 2055 tests (192/2043 baseline —
  independently re-verified via `git stash -u` + re-run before trusting the
  number, rather than assumed from Wave 1's own log entry — + 2 new
  files / 12 new tests, zero regressions).
- **Registry:** `commercial-billing.json`'s `CAP-BILL-003` (Subscription
  Plans & Billing Portal) updated in place with full fix evidence — stays
  `GA APPROVED WITH DOCUMENTED LIMITATIONS`/P7 (the fix is a security/
  integrity hardening + code consolidation, not a structural backend/
  frontend-existence change, so its registry classification doesn't move),
  `test_coverage` and `verification` extended, `notes` records both findings
  and fixes plus the honestly-disclosed remaining gaps (refund admin UI,
  webhook-events viewer, invoice/receipt download endpoint).
  `PRODUCTION_READINESS_REPORT.md` regenerated (66 capabilities / 18
  domains; percentages and gap counts unchanged this wave, as expected).
  Validator: 66 IDs, 0 failures, 0 warnings, no round-trips needed this
  time.
- **Remaining in this domain:** refund admin UI, webhook-events admin
  viewer, invoice/receipt customer-facing download endpoint — each
  independently bounded, none fixed this pass (disclosed above, not silently
  skipped).
- **Risks / follow-ups surfaced:** none new beyond the disclosed gaps above.
  The same synthetic-`Request` delegation pattern used here is now used in
  three places in `payments.js`/`subscription.js` (scan-report branch,
  `handleCreateSubscription`, `handleActivateSubscription`) — if a fourth
  legacy/duplicate payment entry point is ever found, this is the
  established, proven pattern to reuse rather than inventing another one.
- **Next recommended wave:** owner's call between (a) the disclosed
  commercial-billing gaps above (refund admin UI, webhook-events viewer,
  invoice download), (b) continuing the Customer Management System P0 list
  from Wave 1 (`CAP-PORTAL-004` Support Ticket System, change-email flow,
  avatar upload), or (c) a live-production `dynamic_browser` verification
  pass across everything fixed so far this lifecycle (Waves 1 and 2 both
  still show `customer_journey_complete: false` pending this).

**Post-merge addendum (2026-07-10, same day):** PR #144 merge and production
rollout independently verified end-to-end before reporting this wave done:

- All 32 check runs on the PR (required + advisory: CI Gate, Test & Quality
  Gate/Unit Tests, CodeQL, gitleaks, GitGuardian, Lighthouse, axe, E2E Smoke,
  Worker Bundle Size Gate, SEO lock, Security Header Assertions, Dependency
  Audit, etc.) individually inspected via the Checks API, not assumed green
  from a single combined status. One real finding: CodeQL flagged a new
  high-severity "incomplete URL substring sanitization" alert
  (`workers/test/subscriptionLegacyRouteDelegation.test.mjs:40` —
  `url.includes('api.razorpay.com')` instead of a real hostname check, in
  the new fetch-stub). Test-only code with no real attacker surface, but
  fixed properly (parse the URL, compare `hostname` exactly) rather than
  waved off, re-pushed, and re-verified clean (CodeQL conclusion
  `success`) before merge — nothing was bypassed or force-merged.
- Merged via squash (`2286b998`, matching this repo's established merge
  convention). `Test & Quality Gate` on the merge commit: success.
  `Deploy to Cloudflare` (run `29072659970`) on the merge commit: success,
  completed 06:00:41 UTC.
- Live production spot-check (direct `curl` against `cyberdudebivash.in`,
  not assumed from CI alone): `POST /api/subscription/create` with no email
  returns the new "A valid email is required..." 400 (didn't exist pre-fix);
  with an invalid plan returns "...STARTER, PRO, ENTERPRISE, or MSSP." (the
  pre-fix message omitted MSSP, so this exact wording is new-code-only
  evidence); `POST /api/subscription/activate` and `POST /api/payments/verify`
  both still reject malformed input correctly. This confirms the deployed
  Worker is actually running the new code, not just that CI passed.
- `commercial-billing.json`'s `CAP-BILL-003` `verification.method` upgraded
  `static → dynamic_api` with this evidence; `customer_journey_complete`
  correctly stays `false` (a `dynamic_api` spot-check is not a
  `dynamic_browser` full purchase click-through — no real Razorpay payment
  was made). Also corrected a stale figure caught while re-reading this
  entry: its own notes cited "191/2038 baseline + 17 tests," which was
  wrong arithmetic carried over from an earlier draft of the same session
  log entry above (already fixed there) but not previously propagated to
  this file — corrected to the same independently-verified 192/2043 + 12
  new tests = 194/2055.

### 2026-07-10 — Production-readiness lifecycle, Wave 1: Customer Portal — Active Sessions (CAP-PORTAL-003)

- **Trigger:** explicit priority change from the customer — stop
  registry-population-for-its-own-sake and instead audit/harden the complete
  paying-customer lifecycle (signup → payment → subscription → dashboard →
  billing → renewal → cancellation → support), using the existing registry as
  the evidence base rather than re-auditing from scratch, and fixing real P0
  gaps in small, tested, one-feature-area-per-session waves — the same
  bounded-wave discipline this file already enforces, just re-pointed at
  customer-facing fixes instead of documentation.
- **Recovery:** `git status`/`git log` confirmed the branch was already
  clean and current — PR #140 (payment-incident fixes) and PR #141 (Security
  Scanners registry wave) were both merged and deployed in the prior session,
  nothing left uncommitted to recover.
- **Plan:** Read `PROGRAM_BOARD.md`, `customer-portal.json`, and
  `identity.json` (already-catalogued evidence, not re-derived) to find a
  real, well-scoped, still-open gap in Customer Management — the customer's
  stated Wave 1 priority. `CAP-PORTAL-003` (Session Management) was the
  clearest fit: NOT READY/P2, backend `partial`, frontend `missing`, and
  matches the customer's explicit ask for "Sessions"/"Devices" in a
  Stripe/GitHub/Notion/Cloudflare-style account security page — small enough
  to fully finish, verify, and ship in one session (this file's own bounded-
  wave rule), unlike the other 3 remaining stub domains or a Support Ticket
  System (CAP-PORTAL-004, real but much larger net-new surface).
- **Root cause, confirmed by direct code read:** `refresh_tokens` (schema:
  `id, user_id, token_hash, expires_at, created_at, revoked, ip_address,
  user_agent`) already tracked everything a session list needs, but no GET
  endpoint ever exposed it and no per-row revoke existed — the only
  self-service control was `POST /api/auth/logout {all:true}`
  (`revokeAllUserTokens`), a blanket sign-out-everywhere with no way to see or
  kick out one specific device.
- **Fix (backend, `workers/src/handlers/auth.js` + `workers/src/index.js`):**
  `handleListSessions` (GET `/api/user/sessions`) returns the caller's own
  active (non-revoked, non-expired) sessions; an optional `X-Session-Hint`
  header — the browser's own already-held refresh token, not a new privilege
  — lets it flag which row is "this device" without ever returning
  `token_hash` to the client. `handleRevokeSession` (DELETE
  `/api/user/sessions/:id`) is ownership-scoped (`WHERE id=? AND user_id=?`)
  so another user's session id 404s exactly like a nonexistent one — no
  IDOR/enumeration oracle. Both routes gated on `isRealUser(authCtx)`,
  registered in the existing auth-routes block immediately after
  `/api/auth/delete-account`, same pattern as every neighboring route; revoke
  is audit-logged via the existing `auditLog()` helper.
- **Fix (frontend, `frontend/user-dashboard.html`):** new "Active Sessions"
  card in the existing `#page-settings` (between Change Password and 2FA) —
  a table (device parsed from `user_agent` via a small `sessDeviceLabel()`
  heuristic, IP, signed-in date, "This device" badge, per-row "Sign out"
  button hidden for the current session). Lazy-loaded the first time Settings
  opens (`loadSessions()`), same pattern as the existing `loadMFAStatus()`
  call. The revoke button uses a `data-session-id` attribute read via
  `this.dataset` rather than a string-interpolated `onclick` — deliberately
  matching the safer pattern this board's own CAP-ADMIN-004 fix established,
  even though session ids here are server-generated hex (no actual injection
  vector) rather than the riskier convention some older code in the repo
  still uses.
- **Deliberately not built this pass (disclosed, not silently skipped):** a
  "sign out all other sessions" bulk action (needs a new backend function
  that excludes the caller's own current token — `revokeAllUserTokens`
  revokes literally everything including the caller, so reusing it here would
  log the customer themselves out); a "last active" timestamp
  (`refresh_tokens` has no such column — `created_at` is the closest existing
  proxy and is what's shown); IP geolocation display (would add a new
  dependency, out of scope for this fix).
- **Verification:** all 3 inline `<script>` blocks in
  `frontend/user-dashboard.html` re-parsed clean (`new Function(src)`) before
  and after the change. `node --check` clean on both modified backend files.
  Full backend suite green: 191 files / 2038 tests (190/2025 baseline + 1 new
  file/13 tests, zero regressions).
- **Tests:** `workers/test/userSessionManagement.test.mjs` (new, 13 tests,
  real in-memory `node:sqlite` matching the production schema, same
  convention as `workers/test/phase10PasswordReset.test.mjs`) — list scoping
  (own sessions only, excludes revoked/expired/other-users'), the
  `X-Session-Hint` current-session flag with no `token_hash` leak, the
  device/IP/date fields the UI renders, auth-required on both routes, owned-
  session revoke, ownership-scoped 404 on another user's session (IDOR
  check), 404 on nonexistent/already-revoked ids, plus a route+frontend
  contract check (routes really registered and wired; the frontend calls the
  real endpoints, not a placeholder; the revoke button really uses the
  data-attribute pattern, not a reintroduced string-interpolated `onclick`).
- **Registry:** `customer-portal.json`'s `CAP-PORTAL-003` updated in place
  (not a new ID) — `backend.status`/`frontend.status` `partial`/`missing` →
  `exists`/`exists`, `navigation.discoverable` `false → true`,
  `operational_status` `NOT READY → PILOT ONLY`, `priority` `P2 → P6` (fixed,
  tested; only remaining gap is a live-production verification pass, same
  P6/P7 convention as this file's other recent fixes).
  `PRODUCTION_READINESS_REPORT.md` regenerated (66 capabilities / 18 domains;
  backend 83.3%, frontend 67.4%, parity 62.1%; gaps Critical 9 · High 15 ·
  Medium 4 · Low 38). Validator: 66 IDs, 0 failures, 0 warnings (one
  round-trip needed: `test_coverage.evidence` prose cited bare `index.js`/
  `user-dashboard.html` filenames without their repo-root directory prefix,
  which the validator correctly rejects — fixed to the full
  `workers/src/index.js`/`frontend/user-dashboard.html` form, same class of
  fix as prior waves' round-trips). Also corrected this file's own "Current
  status" header block, which had gone stale after Wave 3a (Security
  Scanners) landed — it still showed 17/56 instead of 18/66 domains/
  capabilities; the session log entry for that wave existed but the summary
  header above it was never refreshed. Fixed as a 1-line-scope honest
  correction while already touching this file, not a separate wave.
- **Remaining in this domain:** none for CAP-PORTAL-003 itself. Sibling gap
  `CAP-PORTAL-004` (Support Ticket System, still `NOT READY`/P2, only static
  `mailto:` links) remains open — larger net-new surface, correctly out of
  scope for this bounded wave.
- **Risks / follow-ups surfaced:** none new. The "sign out all other
  sessions" bulk action and IP-geolocation display noted above as
  deliberately deferred, not forgotten.
- **Next recommended wave:** continue the Customer Management System P0 list
  — real remaining gaps identified this session but not yet fixed:
  `CAP-PORTAL-004` (Support Ticket System — currently just `mailto:` links,
  no in-product ticketing/history), a customer-facing "change email" flow
  (no `handleChangeEmail`/`/api/auth/change-email` exists anywhere — email
  changes are currently support-assisted only, per the Settings page's own
  disclosed copy), and an avatar-upload capability (none exists outside the
  Google-OAuth-provided avatar URL). Each is independently small enough to be
  its own bounded wave.

### 2026-07-09 — Wave 3a: Security Scanners

- **Trigger:** user requested continuation of the capability-registry
  process (offered as the recommended alternative to a sprawling, unbounded
  "audit + rebuild everything" mega-prompt that would have duplicated this
  existing registry and violated `docs/ENGINEERING_STANDARDS.md` §13's
  no-new-frameworks rule).
- **Recovery (mandatory, per `EXECUTION_PROCEDURE.md` §3, done before any
  new work):** `git fetch` + `git rev-parse` confirmed local `main` was
  behind `origin/main` (PR #140 had just merged as squash commit `c33bdf2`).
  `git rebase origin/main` hit conflicts replaying the pre-squash commits —
  diagnosed as the multi-commit squash-merge edge case (git's patch-id
  equivalence check can't match N individual commits against one combined
  squash commit), confirmed via `git diff <old-tip> origin/main --stat`
  returning empty (byte-identical trees), resolved with
  `git reset --hard origin/main` on the own feature branch (zero data loss,
  verified before acting). `git ls-remote origin` checked for stray
  in-flight registry work: `claude/capability-registry-recovery-elpx1n` and
  `claude/capability-registry-resume-ldqytt` (both dated 2026-07-08) exist
  but their commit content (MASOC, Production Readiness, Navigation,
  Administration, Academy, Dashboard/Personalization, Notifications,
  Sentinel APEX/Marketplace, Affiliate/Partner, Sales/CRM domain
  population) is already reflected in the current `PROGRAM_BOARD.md`
  Remaining Work Register (which listed only 4 stub domains) — nothing to
  recover from them. Two other stray branches
  (`claude/subscription-tier-webhook-fix`, `fix/instant-checkout-revenue`)
  are weeks-stale (last touched 2026-06-17/24) and unrelated.
- **Plan:** Wave 3 was originally proposed as "Threat Hunting/Intel +
  Security Scanners" together. Split per this file's own rule ("grouped
  only if room to spare... otherwise separate waves") given this was
  already a long session with substantial prior context. Chose Security
  Scanners over Threat Hunting/Intel: it's the core product surface (the
  10 scan modules customers actually pay for) and this session had just
  independently fixed and deeply verified the exact auth-header bug
  affecting all 10 of them, giving high-confidence, low-rediscovery-cost
  ground truth to work from.
- **Execute:** `node scripts/registry/extract-handlers.mjs --json` for
  ground truth, cross-referenced against `workers/src/index.js` routing
  and direct handler reads. Populated `domains/security-scanners.json`
  with 10 entries (CAP-SCAN-001..010: Domain, AI Security, Red Team,
  Identity, Compliance, Cloud Security, Dark Web, AppSec, MCP Security,
  Vibe Code).
- **Findings (real, independently verified against current code):**
  - All 10 modules funnel through 3 frontend call sites
    (`executeScan()`/`runMCPScan()`/`runVibeCodeScan()`) — the exact 3
    sites this session's earlier fix (PR #140) added JWT-forwarding to.
  - Tier-gating strategy differs by module, previously undocumented in one
    place: domain/AI are free-accessible (soft, IP-rate-limited resp.
    preview-truncated); redteam/identity/compliance are STARTER+ hard-gated
    via a shared quota check in `runSyncPipeline`
    (`workers/src/index.js:946`); cloud-security/dark-web/appsec are PRO+
    hard-gated via an in-handler tier check
    (`workers/src/handlers/serviceHandlers.js`); MCP Security and Vibe Code
    are deliberately free/unrestricted (MCP) or soft-gated via
    `applyTierGate()` (Vibe Code) — confirmed intentional (marketing
    positioning), not gaps.
  - **Severity distinction for the already-shipped auth-header fix**: for
    the PRO+ hard-gated modules (cloud-security/dark-web/appsec), the
    pre-fix impact was a complete 403 lockout of every paying PRO+
    customer (not degradation to free-tier limits like the other 7) —
    `authCtx?.tier` could never resolve above `FREE` with no Authorization
    header sent, and these three handlers hard-reject anything below PRO.
  - **New, previously-uncatalogued gap**: 3 of the 10 modules have zero
    test coverage — `handleCloudSecurityScan`, `handleMCPSecurityScan`,
    `handleVibeCodeScan` (confirmed via grep across
    `workers/test/**/*.mjs`, 0 matches each). Vibe Code is the largest
    untested surface (4 dedicated source files: scanner/engine/rules/util).
- **Fix:** None required this wave — the underlying auth-header bug these
  findings mostly document was already fixed and merged (PR #140) earlier
  in this same session. This wave is pure registry population +
  documentation of the differential severity/gating findings above, plus
  identification of the 3-module test-coverage gap as a real, separate,
  not-yet-fixed follow-up.
- **Verification:**
  - `node scripts/registry/validate.mjs` — 21 domain files, 66 unique
    capability IDs (56 + 10 new), zero hard failures, zero warnings.
  - `node scripts/registry/generate-report.mjs` — regenerated
    `PRODUCTION_READINESS_REPORT.md` (66 capabilities / 18 domains),
    spot-checked the new `security-scanners` section renders correctly.
  - Full backend suite: 190 files / 2025 tests pass (unchanged from
    pre-wave baseline — expected, this wave is documentation-only, no
    handler/frontend code touched).
  - `customer_journey_complete` left `false` on all 10 entries per
    `docs/ENGINEERING_STANDARDS.md` §11 (Production Truth Law) — 3 entries
    use `verification.method: "dynamic_browser"` (real headless-Chromium
    Playwright sessions run earlier this session against a locally-served
    build with mocked backend responses, confirming the JWT-forwarding fix
    specifically) but per the same convention already established at
    CAP-IDN-001, a mocked-response local Playwright run is not equivalent
    to live production and does not by itself justify
    `customer_journey_complete: true` or `operational_status: GA APPROVED`.
- **Tests:** No new test files this wave (registry population only). The
  3-module test-coverage gap identified above (CAP-SCAN-006/009/010) is
  flagged as a recommended follow-up, not fixed in this pass.
- **Remaining in this domain:** None — all 10 capabilities in Security
  Scanners are now registered. Wave complete.
- **Risks / follow-ups surfaced:**
  - 3 scan modules (Cloud Security, MCP Security, Vibe Code) have zero
    regression tests — recommend a follow-up pass adding tier-gate tests
    matching the `cisoExecutiveDashboardTierGate.test.mjs` pattern.
  - `runSyncPipeline`'s STARTER-only quota check
    (`workers/src/index.js:946`) is a single point of failure for 3 of the
    10 modules' tier gating (redteam/identity/compliance) — worth a
    dedicated regression test locking that specific gate, distinct from
    the auth-header fix's own tests.
- **Next recommended wave:** Wave 3b (Threat Hunting/Intel).

### 2026-07-09 — Fix sprint: 7 capabilities (CAP-DASH-001/002, CAP-NOTIF-002, CAP-ACAD-002, CAP-CRM-001/005, CAP-AFF-001), recovered from an uncommitted prior session

- **Trigger:** the user supplied a transcript of a prior session that had
  performed an RC-readiness synthesis (using this same registry as its
  evidence base, correctly declining to build a new audit-framework per
  `docs/ENGINEERING_STANDARDS.md` §13), identified these same 7 broken P1
  customer journeys, and had begun fixing them — then hit a hard usage-limit
  cutoff mid-fix, with a screenshot showing a PR #114 as "Merged."
- **Recovery (mandatory, per `EXECUTION_PROCEDURE.md` §3, done before any
  new work):** `git log` showed PR #114's actual content was CAP-ADMIN-004
  (Staff Admin Console — a *different*, already-completed initiative; the
  transcript's own text confirms this, referencing it only as "the same
  discipline as the Staff Admin Console work," i.e. prior, unrelated
  context). No commit after `d6396b1` (#114) existed on `main` or any
  branch. Direct grep of the current tree confirmed the specific fixes
  narrated in the transcript were **not present** — `frontend/index.html`'s
  buy buttons still called the never-defined `CDB_PAY`, and the capability
  registry (generated earlier the same day the transcript describes,
  2026-07-09T13:28Z) still showed all 7 capabilities as `NOT READY`/P1 with
  `frontend.status: broken`. Per `EXECUTION_PROCEDURE.md`'s own rule ("if it
  isn't in git, it didn't happen, no matter how confidently it was
  described"), all 7 fixes were redone from scratch against the current
  tree — the transcript was treated as a high-quality *investigation lead*
  (which capability, which file, which root-cause hypothesis), not as
  evidence that any code change existed.
- **Root causes, independently re-verified against current code (not
  assumed from the transcript) via the registry's own existing evidence in
  `dashboard-personalization.json`, `notifications.json`, `academy.json`,
  `sales-crm.json`, `affiliate-partner.json` — all dated 2026-07-08, one day
  stale but line-number-accurate enough to locate the real, current code
  precisely:**
  - **CAP-DASH-001 / CAP-DASH-002:** `GET /api/ciso/metrics` and the
    exact-match `GET /api/executive/dashboard` were both gated
    `requireCan(authCtx, env, 'admin:business:read')` — SUPERADMIN-only
    (`workers/src/auth/rbac.js:101`) — excluding every paying customer.
    Their own sibling `/api/executive/` prefix-dispatched block
    (`workers/src/index.js` ~7766) already used a proven, tier-inclusive
    pattern in production. A shared root cause, one fix pattern, two routes.
  - **CAP-NOTIF-002:** the homepage notification bell's `_fetch()` called
    `GET /api/v1/alerts` + `GET /api/realtime/stats` (global CVE/threat
    intel, plus a `_synthesizeAlerts()` fallback fabricating fake "personal"
    alerts from platform-wide counts) — never `GET /api/notifications/log`,
    the customer's own notification history.
  - **CAP-ACAD-002:** both homepage buy buttons called
    `if(window.CDB_PAY)CDB_PAY.open(id,price,label)` — `CDB_PAY` is never
    defined anywhere reachable from `frontend/index.html`.
  - **CAP-CRM-001 / CAP-CRM-005 / CAP-AFF-001:** a shared root cause — the
    Phase 4 Revenue Engine's `p4Api()` helper never unwrapped the
    `{success,data,error,timestamp}` envelope every backend route returns
    (`workers/src/lib/response.js`'s `ok()`/`fail()`) — plus per-capability
    field-name mismatches on top (lead/demo-booking field names; proposal
    generation never sending the required `lead_id`; affiliate status/payout
    calling a `?user_id=`/body `user_id` the backend never reads).
- **Fix:**
  - **RBAC (backend, `workers/src/index.js`):** both routes re-gated to the
    same tier-inclusive bar as their proven sibling:
    `['PRO','ENTERPRISE','MSSP'].includes(tier)` OR
    `requireCan(..., 'admin:analytics:read')`. Zero changes to any other
    CISO/executive route (not reported broken, left untouched).
  - **Notification bell (`frontend/index.html`):** `_fetch()` rewired to
    `GET /api/notifications/log`, mapped to the render item (`subject`→
    title, `channel`→description); the dead `_synthesizeAlerts()` fallback
    deleted entirely (a personal-notification bell should never fabricate
    global-stat-derived content). Gated on the page's own existing JWT
    presence check so a signed-out visitor sees an honest "sign in" message
    instead of a crash, an error, or someone else's-looking data.
  - **Buy buttons:** repointed to the page's own real, already-working
    `CDB_PAYMENT` object (options-object signature, matching the file's
    other ~15 working call sites). **Self-caught defect:** the first attempt
    copied the original code's `if(window.X)` guard style verbatim
    (`if(window.CDB_PAYMENT)`) — also always false, since `CDB_PAYMENT` is a
    bare top-level `const`, never assigned to `window`, same underlying
    class of bug as the original defect. Caught by the Playwright
    verification run itself (not by static review) and corrected to the
    `typeof CDB_PAYMENT!=='undefined'` guard the file's other working call
    sites already use.
  - **`p4Api()` envelope fix (shared):** flattens `data`'s fields onto the
    top level while preserving `success`/`error`/`code`, so existing
    failure-path checks (which read the top-level `error` field, already
    correct even before this fix) keep working while success-path field
    access now resolves. Fixes CAP-CRM-001/005/AFF-001 in one change, plus
    incidentally CAP-CRM-007 (Conversion Triggers, not in scope this pass —
    see its `notes` for an honest partial-credit update) and
    CAP-CRM-005/`p4LoadPackages()`'s silent fallback-to-static-data bug.
  - **Lead/demo booking:** field names corrected to the real backend
    contract; a second, previously-uncatalogued bug found in the same flow
    (`p4LoadDemoSlots()` read `s.slot_id`/`s.display`, but
    `GET /api/sales/demo/slots` returns `{slot,label}` — meaning even a
    field-name-correct booking submission would have sent a permanently
    blank `preferred_slot`) was also fixed.
  - **Proposal generation:** since `handleGenerateProposal` requires an
    existing `lead_id` (builds the document from a stored lead record, not
    freeform fields) and the form collects no lead selector, `p4GenerateProposal()`
    now chains two already-fixed real endpoints — `POST /api/sales/leads`
    first, then `POST /api/proposals/generate` with the returned `lead_id`
    — rather than inventing a new backend contract. A second,
    previously-uncatalogued bug: the "↻ Refresh" button's
    `onclick="p4LoadProposals()"` called a function with no `window.`
    prefix (IIFE-private) — a real click would have thrown `ReferenceError`
    — found via a systematic cross-reference of every `onclick="p4*("`
    call site in the file against every window-exposed vs. IIFE-private
    `p4*` function definition (one genuine hit; all other `p4*` onclick
    targets confirmed correctly exposed).
  - **Affiliate join/status/payout/leaderboard:** join fixed to the real
    field names (`{name,email}` — `handleJoin` never reads a client-supplied
    `user_id`/`company`/`affiliate_type`). Status/payout: the old
    `?user_id=`/body `user_id` was dead code — `handleGetStatus`/
    `handleRequestPayout` only ever resolve identity from a real
    `authCtx.userId`, by design (a prior anonymous-exposure/IDOR fix closed
    the old `?email=` lookup precisely because it let anyone who
    knew/guessed an affiliate's email pull their stats — correctly **not
    reverted** here). Rewired to gate on a real client-side session-token
    check before calling, so a signed-out visitor fails fast with an honest
    message instead of a doomed network call. `p4RenderAffStatus()` itself
    had further uncatalogued field-mapping bugs against the real
    `handleGetStatus` shape (`aff.commission_rate`/`aff.total_referrals`/
    `aff.total_earned_inr`/`aff.pending_payout_inr` never existed at any
    level of a real response) — fixed to `tier_details.commission_pct` and
    `stats.{total_referrals,conversions,total_commission_earned_inr,pending_payout_inr}`.
    Leaderboard: `handleGetLeaderboard` deliberately never returns a
    per-affiliate earnings figure (privacy) — the fabricated always-₹0
    "earnings" line was removed and replaced with the real, previously
    unused `badge` field. A stale HTML comment describing the old,
    non-functional `p4_aff_user_id` localStorage identity scheme was
    corrected to describe the real, current design (join is public by
    design; status/payout correctly require a real session; a non-customer
    external affiliate currently has no in-page self-serve status check —
    disclosed as a genuine follow-up, not silently worked around by
    reopening the closed IDOR).
  - **Accessibility (found and fixed while touching the bell/toast code,
    not part of the original 7 but directly adjacent):** the severity-badge
    palette's LOW tier fell through to MEDIUM's cyan background tint while
    keeping distinct gray text — computed contrast 3.44:1, failing WCAG AA
    (needs ≥4.5:1 for small text); fixed with its own tint plus the page's
    existing `--text-muted` token (7.08:1, verified by direct WCAG relative-
    luminance calculation, not eyeballed). The shared `p4Toast()` helper
    appended plain `<div>`s with no ARIA live region — silent to screen
    readers; added `role="status" aria-live="polite"`.
- **Verification:**
  - All 38 real inline `<script>` blocks in `frontend/index.html`
    (excluding JSON-LD) syntax-checked clean (`node --check`) before and
    after every round of edits.
  - Full backend suite green throughout: 188 files / 2012 tests (187/2002
    baseline + 1 new file/10 tests).
  - Real headless-Chromium Playwright session against the actual page
    (served locally; cookie-consent banner suppressed via `addInitScript`
    to avoid blocking actionability checks, matching a returning-visitor
    scenario) with network responses mocked to match each real handler's
    verified source-code response shape exactly (not guessed) — **20/21
    checks pass**. The one non-pass is `console.error` noise from an
    unrelated, unmodified file (`dashboard-live.js`, dated before this
    session) whose `EventSource` call can't be satisfied by the test's
    simple JSON catch-all mock — confirmed unrelated to any of the 7 fixes
    by direct source grep before accepting it as a known mock-environment
    limitation rather than chasing it further.
  - axe-core WCAG2A/AA scan of the populated notification panel: zero
    violations post-fix.
  - **`customer_journey_complete` intentionally left `false` on all 7
    registry entries** despite the `dynamic_browser` verification method —
    per `docs/ENGINEERING_STANDARDS.md` §11 (Production Truth Law, "only
    observed production behaviour establishes reality"), a Playwright
    click-through against contract-accurate *mocks* is not the same as
    live deployed production, and this session has no deploy access. Each
    entry's `verification.evidence` states this distinction explicitly
    rather than overclaiming.
- **Tests:** `workers/test/cisoExecutiveDashboardTierGate.test.mjs` (new,
  10 tests — real PRO/ENTERPRISE-tier admission via an `api_keys`-row DB
  mock matching the established `whiteLabelThemeGate.test.mjs` pattern,
  FREE-tier and anonymous still rejected, ADMIN_KEY bypass still admitted,
  for both routes). The 5 frontend-only fixes have **no committed,
  permanent regression test** — the Playwright verification used this pass
  was an ad-hoc scratch script, not added to the repository (would require
  a real infrastructure decision: adding `playwright`/`axe-core` as
  devDependencies and wiring browser-based tests into CI, which is bigger
  than this bug-fix task's scope) — flagged as a real, honest gap in each
  entry's `test_coverage.evidence` rather than silently claimed as covered.
- **Registry:** all 7 entries updated in place (not new IDs) — `frontend.status`
  `broken → exists`, `operational_status` `NOT READY → GA APPROVED WITH
  DOCUMENTED LIMITATIONS`, `priority` `P1 → P6` (5 entries, no committed
  test) or `P7` (CAP-DASH-001/002, which do have a committed test — no
  test-coverage gap, residual gap is documentation/live-verification only).
  `customer_journey_complete` stays `false` on all 7 (see above).
  CAP-CRM-007 (Conversion Triggers, sharing the `p4Api()` envelope root
  cause but with its own separate, unaddressed field-name bugs) got an
  honest `notes` update only — envelope portion now fixed as a side effect,
  status/priority intentionally unchanged since it wasn't in scope this
  pass. `PRODUCTION_READINESS_REPORT.md` regenerated (backend 75.9%→79.5%,
  frontend 47.3%→59.8%, parity 41.1%→53.6%, Critical/P1 16→9). Validator:
  56 IDs, 0 failures, 0 warnings (one round-trip needed: an evidence string
  cited `proposalGenerator.js:326` without its directory prefix, which the
  validator correctly rejects as a nonexistent repo-root file — fixed to
  the full `workers/src/handlers/proposalGenerator.js:326` path).
- **Next:** a committed, CI-wired Playwright/axe-core regression suite for
  the Phase 4 Revenue Engine (lead/demo/proposal/affiliate/notification
  flows) would close the `test_coverage` gap disclosed above — an
  infrastructure decision for the owner, not assumed here. A post-merge
  production smoke test (real PRO-tier account sees non-zero CISO data;
  real lead/demo/proposal/affiliate submissions succeed against the live
  deployed backend) would close `customer_journey_complete` on all 7
  entries. CAP-CRM-007's own field-name bugs (event_type/user_id/feature_id
  mismatches, separate from the envelope bug fixed here) remain open. The
  4 domains not yet in this program are unchanged from before this session
  (see Remaining Work Register).

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
