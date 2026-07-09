# Capability Registry — Program Board

**Status:** Living doc, updated at the end of every execution wave (see
`EXECUTION_PROCEDURE.md`). Tracks *structural completion of the registry
population effort itself* — how much of the platform has been catalogued,
not how well the platform serves customers. It is not a customer-outcome
measure and does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only outcome
scoreboard. Read this + `EXECUTION_PROCEDURE.md` before starting any
registry-population session.

## Current status (2026-07-09, CAP-DEVPORTAL-002/003/004 fix sprint)

| Metric | Value | Source |
|---|---|---|
| Domain files | 21 | `docs/capability-registry/domains/*.json` |
| Domains populated | 17 | see list below |
| Domains empty (stubs) | 4 | see Remaining Work Register |
| Capabilities registered | 54 | `node scripts/registry/validate.mjs` |
| Validator | 0 failures, 0 warnings | `node scripts/registry/validate.mjs`, run 2026-07-09 |
| Worker test suite | 179 files / 1899 tests passing | `npx vitest run`, run 2026-07-09 (includes 12 new tests for this sprint + apiKeyHashing.test.mjs corrections) |
| Production readiness verdict | **NOT READY** (computed) | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-09 |
| Backend / Frontend / Parity | 74.1% / 39.8% / 37% | `PRODUCTION_READINESS_REPORT.md` (up from 69.4% / 38% / 35.2% — CAP-DEVPORTAL-002/003/004 backend now correct, -002's rotate button now functional) |
| Customer journeys browser-verified | 0% | `PRODUCTION_READINESS_REPORT.md` — no `dynamic_browser` verification has been performed yet on any entry |
| Gaps by severity | Critical 14 · High 16 · Medium 4 · Low 20 | `PRODUCTION_READINESS_REPORT.md` — unchanged: priority reflects `customer_journey_complete`/`dynamic_browser` status, not fixed this pass; see remediation section below |

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
