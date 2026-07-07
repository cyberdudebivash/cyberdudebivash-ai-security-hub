# Enterprise RBAC — Phase 0 Report: Central Authorization Foundation + Live-Exposure Closure

**Date:** 2026-07-07 · **Authority:** Owner-directed (Enterprise RBAC mandate — 9 roles: Public, Free, Paid, Enterprise, MSSP, Sales, Affiliate, Platform Admin, Super Admin)
**Objective:** the full mandate spans ~30+ dashboard pages and a complete backend authorization rewrite — genuinely multi-week work. Before writing code, three parallel research passes mapped the *current* auth/dashboard state. This phase covers what that research surfaced as the highest-leverage, concretely-verified slice: a central RBAC foundation (wiring the schema's dormant `user_roles` table into real, multi-user Platform Admin/Super Admin roles) and closing every live exposure the research found — not a full implementation of all 9 roles.
**Honesty boundary:** this is **Phase 0 of N**, not "RBAC complete." Every item below is either fixed-and-tested or explicitly listed as outstanding in §5 — nothing is claimed done without a test or a live verification step backing it.

## 1. What the research found (evidence, not assumption)

Three Explore agents mapped the auth layer, the frontend dashboard inventory, and the backend admin/ops surfaces before any code was written. Findings, each independently verified against the source file before being "fixed":

| # | Finding | Evidence |
|---|---|---|
| 1 | A hardcoded shared password was the entire access gate on 3 "admin" pages | `mssp-command-center.html:655`, `revenue-command-center.html:597`, `proposal-generator.html:302` — readable via view-source, or bypassable with `localStorage.setItem('cdb_owner','true')` |
| 2 | `god-mode.html` had zero page-load gating, was linked from the public homepage nav, and was search-engine indexable | `<meta name="robots" content="index,follow">` (only internal tool with this), no `#auth-gate` element anywhere in the file |
| 3 | `handlers/executiveCommandCenter.js`'s `/api/executive/*` catch-all had no auth check at all | `index.js:7587-7589` (pre-fix) called the handler with no `resolveAuthV5`, no `withSecurityHeaders`/`withCors` wrapper either |
| 4 | `handlers/productAnalytics.js`'s growth/funnel/adoption/prune routes claimed "(admin)" in a doc comment but enforced nothing | `index.js:3081-3105` (pre-fix) — every route only resolved `authCtx`, never checked it |
| 5 | Authorization logic that *does* exist is fragmented across 4 independent per-file `requireRole()`/`enterpriseOnly()` implementations | `customerSuccess.js`, `reliabilityEngineering.js`, `whiteLabelMSSP.js`, `executiveRiskHandlers.js` |
| 6 | "Admin" access had exactly one path: the shared `ADMIN_KEY` secret, or a single hardcoded owner email (`isOwner()`) — no way to have a second real admin user | `auth/middleware.js` `isOwner()`/`ownerEmails()`; confirmed no `users.role`/`is_admin` column exists |
| 7 | An unused, never-wired `user_roles` table already exists in the schema with exactly the right role vocabulary | `schema_master.sql:3256-3262` — `SUPERADMIN\|ADMIN\|SOC_ANALYST\|THREAT_HUNTER\|VIEWER\|API_USER`, zero references anywhere in `workers/src` before this phase |

**One research finding was corrected before it was acted on**: `GET /api/proposals/:id` was reported as missing an ownership check at the `index.js` route-dispatch site. Direct verification of `handlers/proposalGenerator.js:437-438` showed `isOwner()` is already enforced *inside* the handler — the same pattern several other "admin" handlers in this codebase already use. No fix was needed there; it is not listed as fixed below because it was never actually broken.

**A second finding required a design correction mid-implementation**: `god-mode.html` was initially assumed to be Super-Admin-only. Reading `triggerRun()`/`buildTriggerHeaders()` in that file (lines 662-699) showed it is genuinely a **paying ENTERPRISE/MSSP customer feature** (the footer says so: *"ENTERPRISE subscribers can trigger autonomous runs"*), not an internal-only tool — gating the whole page behind a staff-only login would have regressed a feature real customers pay for. The fix below reflects the corrected design: full content for ENTERPRISE/MSSP tier *or* staff, an upgrade/login prompt for everyone else, nav links preserved (legitimate upsell surface).

## 2. Fixed this phase (permanent, test-locked)

| # | Gap | Fix | Lock |
|---|---|---|---|
| 1 | No multi-user admin role model | `auth/rbac.js` (new): wires the dormant `user_roles` table into `isPlatformAdmin()`/`isSuperAdmin()`, KV-cached (~120s TTL) so it never adds a D1 round-trip to ordinary requests. `isOwner()`/`ownerEmails()`/`authCtx.role` in `middleware.js` are **untouched** — a SUPERADMIN-role session sets `isAdmin:true` (same field the `ADMIN_KEY` bypass already sets), making it `isOwner()`-equivalent everywhere for free. A plain `ADMIN` (Platform Administrator) session does **not** get `isAdmin:true` — least privilege, scoped only to `isPlatformAdmin()`-gated resources. | `rbac.test.mjs` (20 tests) |
| 2 | No way to create a second admin user, ever | `POST /api/admin/roles/grant`, `DELETE /api/admin/roles/revoke`, `GET /api/admin/roles` — Super-Admin-only; the existing owner (`ADMIN_KEY`/owner-email) bootstraps the first real grants | `rbac.test.mjs` |
| 3 | Hardcoded shared password on 3 admin pages | Real passwordless magic-link staff login (`handlers/staffAuth.js`, mirrors the already-tested `handlers/partnerAuth.js` pattern) + `frontend/assets/staff-auth.js` shared gate, replacing the password check in all 3 pages. Their `X-Owner-Key` header (never validated by any backend route — confirmed by grep) is also replaced with real `Authorization: Bearer <session>` on every API call those pages make. | `staffAuth.test.mjs` (13 tests); headless Playwright: gate renders for anonymous, hides for a valid session, zero JS errors either state |
| 4 | `god-mode.html` zero gating + public indexing | Real gate added (page previously had none) admitting ENTERPRISE/MSSP tier *or* a verified staff session; `robots` meta fixed to `noindex,nofollow` | Headless Playwright: anonymous → upgrade/login prompt; `cdb_tier=ENTERPRISE` → dashboard renders unblocked, zero JS errors |
| 5 | `executiveCommandCenter.js` open API | Gated to PRO/ENTERPRISE/MSSP tier or `isPlatformAdmin()`, matching the sibling `executiveRiskHandlers.js` bar on the same `/api/executive/*` prefix; also now wrapped in `withSecurityHeaders`/`withCors` like every other route (previously wasn't) | `executiveCommandCenterGate.test.mjs` (3 tests) |
| 6 | `productAnalytics.js` unenforced admin routes | `growth`/`funnel`/`adoption`/`prune` now require `isPlatformAdmin()`; `event` (client-side tracking ingest) intentionally left public | `productAnalyticsAdminGate.test.mjs` (6 tests) |
| 7 | 4 duplicated per-file role-check helpers | Internals of `customerSuccess.js`/`reliabilityEngineering.js`'s `requireRole()`, `executiveRiskHandlers.js`'s `enterpriseOnly()`, `whiteLabelMSSP.js`'s `requireRole()`/`requireRoleOrPartner()` now delegate `'admin'` to `rbac.js`'s `isPlatformAdmin()` — purely additive, every existing pass condition (ADMIN_KEY, `role==='mssp_admin'`, tier checks) is unchanged. Exported function names/signatures unchanged, zero call-site churn beyond adding `await`. | Existing test suites for all 4 files re-run green (no new tests needed — behavior is additive) |

## 3. Verification

- Full suite: **157 files / 1631 tests passing** (1589 baseline + 42 new across `rbac.test.mjs`, `staffAuth.test.mjs`, `executiveCommandCenterGate.test.mjs`, `productAnalyticsAdminGate.test.mjs`). Zero regressions in the 4 consolidated files' existing test coverage.
- Headless Chromium (Playwright) sanity checks: all 3 retrofitted admin pages + `god-mode.html`, both unauthenticated and authenticated states, zero JS console errors in either state.
- Live production verification: pending PR merge + deploy (this report is written pre-merge; the PR description/CI status is the record of that step).

## 4. Role/permission matrix — as of this phase

| Role (mandate) | Backing mechanism | Status |
|---|---|---|
| Public Visitor | No auth (`ip_fallback`) | Pre-existing, unchanged |
| Registered Free User | JWT, `tier='FREE'` | Pre-existing, unchanged |
| Paid Customer (Starter/Pro) | JWT/API key, `tier` | Pre-existing, unchanged |
| Enterprise Customer | `tier IN ('PRO','ENTERPRISE')`, `org_members` (SSO-federated) | Pre-existing; **not** newly built this phase |
| MSSP / Partner | `tier='MSSP'`, `partnerId` (magic-link session) | Built in the prior Partner/White-label infra phase (this session); untouched here |
| Sales Team | `isOwner()`-gated CRM/pipeline routes | Pre-existing; **no dedicated Sales role/login built this phase** |
| Affiliate Partner | Self-service routes, no owner/admin gate by design | Pre-existing, unchanged |
| Platform Administrator | **New**: `user_roles.role='ADMIN'` via `auth/rbac.js` `isPlatformAdmin()` | Built this phase — permission model + login exist; no dedicated dashboard page built yet |
| Super Administrator | **New**: `user_roles.role='SUPERADMIN'` (equivalent to `ADMIN_KEY`/`isOwner()`) | Built this phase — real multi-user path now exists alongside the legacy single-owner-email path |

## 5. Outstanding — explicitly not done this phase

1. **Enterprise, Sales, and Affiliate dashboards** are not rebuilt/segmented this phase — they continue to work exactly as before (tier/owner-gated), just not restructured into the modular, per-widget `requiredRole`/`requiredPermission`/`featureFlag` architecture the full mandate describes.
2. **No dedicated Platform Administrator dashboard page exists yet** — the role, permission checks, and grant/revoke API are real and tested, but there is no UI surface for an `ADMIN` (non-super) staff member beyond what `isPlatformAdmin()` already unlocks on `executiveCommandCenter`/`productAnalytics`.
3. **`org_members` vs. `org_team_members`** — two structurally similar but separate per-org membership tables exist (`orgManagement.js` vs. `enterpriseAutomation.js`); not consolidated this phase.
4. **`aiSecurityCopilot.js`'s independent `resolveOrgRole()`/`ROLE_RANK`** — a third, separate org-role resolution system; not touched.
5. **The dead `'TEAM'` tier reference** (`index.js:1516`) and the **`authCtx.orgId` vs. `org_id` field-name mismatch** in `auditLog.js` — both pre-existing, both noted, neither fixed this phase.
6. **`god-mode.html`'s own read-only status API calls remain unauthenticated at the backend** (`/api/mythos/god-mode/status`) — the page-load gate now controls who *sees* the dashboard shell, but the underlying read-only status fetch itself was not re-audited for whether that data should also require server-side auth; flagged for a follow-up decision, not assumed either way.
7. **Live production verification** of every fix (§3) is a PR-merge-and-deploy step that happens after this report is written, following the same branch → PR → CI → merge → deploy → live-curl-verify protocol already used for the Partner/White-label infra phase in this session.

This phase is a foundation, not a finish line — do not read §2 as "RBAC is done." The next phase, per the mandate's own priority order, should extend Platform Admin/Super Admin into an actual dashboard page (parity with the now-real permission model), before moving on to Enterprise/Sales/Affiliate dashboard segmentation.
