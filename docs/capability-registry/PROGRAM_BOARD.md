# Capability Registry — Program Board

**Status:** Living doc, updated at the end of every execution wave (see
`EXECUTION_PROCEDURE.md`). Tracks *structural completion of the registry
population effort itself* — how much of the platform has been catalogued,
not how well the platform serves customers. It is not a customer-outcome
measure and does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only outcome
scoreboard. Read this + `EXECUTION_PROCEDURE.md` before starting any
registry-population session.

## Current status (2026-07-09, 7-capability fix sprint — CAP-DASH-001/002, CAP-NOTIF-002, CAP-ACAD-002, CAP-CRM-001/005, CAP-AFF-001, recovered from an uncommitted prior session)

| Metric | Value | Source |
|---|---|---|
| Domain files | 21 | `docs/capability-registry/domains/*.json` |
| Domains populated | 17 | see list below |
| Domains empty (stubs) | 4 | see Remaining Work Register |
| Capabilities registered | 56 | `node scripts/registry/validate.mjs` |
| Validator | 0 failures, 0 warnings | `node scripts/registry/validate.mjs`, run 2026-07-09 |
| Worker test suite | 188 files / 2012 tests passing | `npx vitest run`, run 2026-07-09 (includes 10 new tests: `cisoExecutiveDashboardTierGate.test.mjs`) |
| Production readiness verdict | **NOT READY** (computed) | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-09 |
| Backend / Frontend / Parity | 79.5% / 59.8% / 53.6% | `PRODUCTION_READINESS_REPORT.md` (up from 75.9% / 47.3% / 41.1% before this fix) |
| Customer journeys browser-verified | 0% | `PRODUCTION_READINESS_REPORT.md` — this pass used real Playwright click-throughs of the actual pages (not `dynamic_api`), but against contract-accurate mocked network responses, not a live deployed backend — `customer_journey_complete` intentionally left `false` on all 7 entries pending a post-merge production smoke test |
| Gaps by severity | Critical 9 · High 16 · Medium 4 · Low 27 | `PRODUCTION_READINESS_REPORT.md` — Critical (P1) dropped 16 → 9, exactly the 7 capabilities fixed this session; see remediation section below |

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
