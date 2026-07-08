# Capability Registry — Program Board

**Status:** Living doc, updated at the end of every execution wave (see
`EXECUTION_PROCEDURE.md`). Tracks *structural completion of the registry
population effort itself* — how much of the platform has been catalogued,
not how well the platform serves customers. It is not a customer-outcome
measure and does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only outcome
scoreboard. Read this + `EXECUTION_PROCEDURE.md` before starting any
registry-population session.

## Current status (2026-07-08, end of Recovery + Execution Procedure wave)

| Metric | Value | Source |
|---|---|---|
| Domain files | 21 | `docs/capability-registry/domains/*.json` |
| Domains populated | 16 | see list below |
| Domains empty (stubs) | 5 | see Remaining Work Register |
| Capabilities registered | 50 | `node scripts/registry/validate.mjs` |
| Validator | 0 failures, 0 warnings | `node scripts/registry/validate.mjs`, run 2026-07-08 |
| Worker test suite | 176 files / 1835 tests passing | `npx vitest run`, run 2026-07-08 (independently re-run this session, not carried over from a prior session's claim) |
| Production readiness verdict | **NOT READY** (computed) | `PRODUCTION_READINESS_REPORT.md`, regenerated 2026-07-08 |
| Backend / Frontend / Parity | 72% / 38% / 36% | `PRODUCTION_READINESS_REPORT.md` |
| Customer journeys browser-verified | 0% | `PRODUCTION_READINESS_REPORT.md` — no `dynamic_browser` verification has been performed yet on any entry |
| Gaps by severity | Critical 11 · High 16 · Medium 4 · Low 19 | `PRODUCTION_READINESS_REPORT.md` |

Full structural breakdown (per-domain tables, gap definitions): regenerate
and read `docs/capability-registry/PRODUCTION_READINESS_REPORT.md` — never
hand-copy its numbers here beyond the summary above, to avoid two sources of
truth drifting apart.

**Domains populated (16):** academy, administration, affiliate-partner,
commercial-billing, customer-portal, dashboard-personalization, identity,
masoc, mssp, navigation, notifications, organizations, production-readiness,
rbac, sales-crm, sentinel-apex-marketplace.

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

## Remaining Work Register

5 domains are still empty stubs (`[]`):

| Domain | File | Status |
|---|---|---|
| Developer Portal / API Keys | `developer-portal-apikeys.json` | **Not started** — see note below |
| Threat Hunting / Intel | `threat-hunting-intel.json` | Not started |
| MYTHOS / God Mode | `mythos-godmode.json` | Not started |
| Security Scanners | `security-scanners.json` | Not started |
| Compliance Store | `compliance-store.json` | Not started |

**Developer Portal / API Keys — important note:** a prior session (2026-07-08)
investigated this domain and reported finding 4-5 parallel API-key systems,
including two real bugs (one unauthenticated endpoint referencing
non-existent DB columns, always 500s, yet linked from the platform's own
OpenAPI spec; a parameter-ordering bug forcing every ENTERPRISE self-service
key onto FREE-tier limits), plus a regression test. It hit a hard usage-limit
cutoff before committing any of it. This session's recovery pass confirmed
via `git log`/`git ls-remote` that **none of that work exists anywhere in
git** — `developer-portal-apikeys.json` is still an empty stub on every
branch, local and remote, and no orphaned commit exists for it (unlike
MASOC, which was recoverable). Treat this domain as **not started**. The
prior session's findings are leads worth re-checking first (they may well be
real — re-verify quickly against the code before disbelieving them), not
verified facts to register directly — per this registry's own evidence rule
(`SCHEMA.md` — never mark verified without evidence).

## Proposed wave plan

- **Wave 2 — Developer Portal / API Keys.** Redo from scratch per the note
  above. Single domain, already has a specific lead to start from.
- **Wave 3 — Threat Hunting/Intel + Security Scanners.** Two domains,
  grouped only if Wave 2 finishes with room to spare in the *next* session —
  otherwise run them as separate waves.
- **Wave 4 — MYTHOS/God Mode + Compliance Store.**
- Unscheduled — **MASOC auth-gate fix** (see finding above). Not a registry
  wave; a normal CAB-reviewed product fix. Can run before, after, or between
  the waves above — sequencing is a business call, not a registry-population
  dependency.

## Session log (most recent first)

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
