# Capability Registry — Program Board

**Status:** Living doc, updated at the end of every execution wave (see
`EXECUTION_PROCEDURE.md`). Tracks *structural completion of the registry
population effort itself* — how much of the platform has been catalogued,
not how well the platform serves customers. It is not a customer-outcome
measure and does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only outcome
scoreboard. Read this + `EXECUTION_PROCEDURE.md` before starting any
registry-population session.

## Current status (2026-07-11, Backlog-sweep wave 2: CAP-MSSP-001 live-reverified against production (dead-end fix confirmed deployed, real non-mutating login-endpoint check); CAP-COMP-001 (found in wave 1's 3-domain audit) fixed — a compliance-pack nav link no longer leads to a hidden, auth-gated section for logged-out visitors. **Session resumed after a usage-limit cutoff mid-edit** (see EXECUTION_PROCEDURE.md §0 — the in-flight p4LoadFunnel edit was never committed and was not recoverable from git, so it was redone from scratch rather than resumed): CAP-CRM-007 (Conversion Trigger & Funnel Tracking) fixed — all 6 frontend call sites into conversionTriggers.js now match the real backend contract, including closing a paywall gate that failed OPEN for every feature/plan (zero live callers today, so zero current blast radius, but now correct before anything gets wired to it). Metrics table below updated for the CAP-CRM-007 fix only (frontend/parity % + test count) — priority fields are historical-severity records, not auto-derived from the now-fixed booleans, matching this session's established convention. Also still open: Threat Graph findings-persistence fix from an earlier wave still needs the owner to run the gated D1 Schema Migration workflow with `workers/schema_migration_scan_history_findings_2026_07.sql` to activate)

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
| Capabilities registered | 95 | `node scripts/registry/validate.mjs` |
| Validator | 0 failures, 0 warnings | `node scripts/registry/validate.mjs`, run 2026-07-11 |
| Worker test suite | 208 files / 2169 tests passing | `npx vitest run`, run 2026-07-11 (+1 file / +20 tests this wave: `workers/test/conversionTriggersFieldNameFix.test.mjs`, CAP-CRM-007's fix) |
| Production readiness verdict | **NOT READY** (computed) | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-11 — still NOT READY: 9 other Critical (P1) items are untouched by this wave, and CAP-CRM-007 itself still counts toward the 10 per this file's own historical-priority convention (see below) |
| Backend / Frontend / Parity | 88.4% / 64.7% / 58.9% | `PRODUCTION_READINESS_REPORT.md` — up from 64.2%/57.9%; CAP-CRM-007's frontend.status flipped partial→exists this wave, the only change |
| Customer journeys browser-verified | 3/95 capabilities now carry both `verification.method: dynamic_browser` AND `customer_journey_complete: true` (CAP-IDN-001, CAP-IDN-002, CAP-IDN-003 — all three flipped to `true` this wave) | Full real chain against LIVE PRODUCTION (`cyberdudebivash.in`), zero mocking: signup → MFA setup/enable (real RFC 6238 TOTP, no authenticator app) → logout → password login → MFA challenge → authenticated dashboard link — see session log |
| Gaps by severity | Critical 10 · High 23 · Medium 12 · Low 50 | `PRODUCTION_READINESS_REPORT.md` — up from Critical 9 · High 15 · Medium 4 · Low 38 before this wave. The increase is the 3-domain audit doing its job: CAP-COMP-001 is 1 new Critical; CAP-COMP-002/004/005, CAP-MYTHOS-003, CAP-TIH-002/004/009/014 are 8 new High. None of the original 9 Critical/15 High items got worse — see session log |

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

3 domains are still empty stubs (`[]`):

| Domain | File | Status |
|---|---|---|
| Threat Hunting / Intel | `threat-hunting-intel.json` | Not started |
| MYTHOS / God Mode | `mythos-godmode.json` | Not started |
| Compliance Store | `compliance-store.json` | Not started |

Security Scanners populated 2026-07-09 (10 capabilities, CAP-SCAN-001..010) —
see session log below.

## Proposed wave plan

- **Wave 2 — Developer Portal / API Keys.** ✅ DONE (2026-07-08) — see
  session log above; its 3 findings are now also fixed (see remediation
  section above).
- **Wave 3a — Security Scanners.** ✅ DONE (2026-07-09) — see session log
  below. Threat Hunting/Intel (originally grouped with it as Wave 3) split
  out as its own wave per this file's own splitting rule.
- **Wave 3b — Threat Hunting/Intel.** Next recommended wave.
- **Wave 4 — MYTHOS/God Mode + Compliance Store.**
- **CAP-DEVPORTAL-002/003/004 fixes.** ✅ DONE (2026-07-09) — see remediation
  section above. Not registry waves; normal CAB-reviewed product fixes, same
  treatment as the MASOC auth-gate fix was. Can run before, after, or
  between the domain waves above — sequencing is a business call, not a
  registry-population
  dependency.

## Session log (most recent first)

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
  this fix bounded and reviewable.

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
