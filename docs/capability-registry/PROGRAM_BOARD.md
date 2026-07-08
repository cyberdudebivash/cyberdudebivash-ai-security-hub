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

## ⚠ Open critical finding surfaced by this effort, not yet remediated

**CAP-MASOC-001** (`docs/capability-registry/domains/masoc.json`): none of
the 4 Multi-Agent SOC routes (`/api/agents/run`, `/api/agents/stream`,
`/api/agents/status`, `/api/agents/dispatch/:id`) gate on `isRealUser()` —
`resolveAuthV5`'s IP-fallback sets `authenticated: true` for anonymous
callers, so **unauthenticated requests can invoke compute-expensive
parallel AI-agent orchestration**, with only a 5-req/min KV rate limit as a
control. This is a live production gap, independently re-verified this
session (not just carried over from the registry entry), not a documentation
gap — it should not wait behind further registry-population waves. It was
deliberately **not fixed in this session**: the fix belongs in its own
CAB-reviewed change (own commit, own regression test, own review of
interaction with the existing rate limiter and the separately-gated
Copilot-mediated path to the same capability — see the entry's `notes` field
for the full analysis), not bundled into a process/documentation PR.
Recommend this be picked up as a dedicated fix before or alongside Wave 2.

Two lower-severity, also-unfixed findings on the same capability (SSE CORS
narrower than the real production origin allowlist; a frontend
default-selection bug that silently duplicates one agent's AI call every
run) are detailed in the same registry entry's `notes` field.

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
