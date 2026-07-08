# ==============================================================================
# CYBERDUDEBIVASH® ENTERPRISE PLATFORM
# SAAS PRODUCTIZATION MISSION BRIEF
# "From Feature-Rich Backend to Coherent Multi-Tenant SaaS"
# VERSION: v1.0 — 2026-07-08
# ==============================================================================

## 0. HOW TO USE THIS DOCUMENT

Paste this entire document as the opening message of a new Claude Code session
scoped to `cyberdudebivash/cyberdudebivash-ai-security-hub`. Do not let the
session write implementation code until Section 3 (Phase 0 — Mandatory Audit)
is complete and its Gap Matrix has been reviewed by a human.

This is a **multi-week, multi-PR program**, not a single implementation pass.
Each domain in Section 5 should become its own sequence of small, reviewable
PRs, following the branch-per-PR-off-latest-main workflow already proven in
this repository (90+ PRs merged this way before this document was written).

---

## 1. ROLE

You are acting simultaneously as:
- Principal Software Architect
- Principal Security Architect
- Principal IAM Architect
- Enterprise SaaS Architect
- Principal Platform Engineer
- Principal DevSecOps Engineer
- Enterprise Product Architect

---

## 2. PRIME DIRECTIVE

> Perform a production-readiness audit of the CYBERDUDEBIVASH Enterprise
> Platform's identity, organization, RBAC, commercial, and dashboard-
> personalization layers, and implement **only the verified missing
> capabilities** required to deliver it as a coherent, secure, multi-tenant
> SaaS product — without breaking, duplicating, or rewriting the
> substantial working architecture that already exists.

Non-negotiable constraints, in order of priority:
1. **Never break a currently-working authenticated flow.** This platform has
   real paying customers and a real admin/RBAC audit trail already in
   production. A regression here is worse than a missing feature.
2. **Audit before you build.** For every capability in Section 5, determine
   whether it already exists (fully, partially, or as dead/unwired code)
   before writing a single line of new code. Grep the actual handlers,
   read the actual schema, do not assume from folder names or comments.
3. **Never duplicate.** If a capability exists but is incomplete or
   unwired, extend or wire it. Do not build a parallel system next to it.
4. **Every change ships with**: tests (unit + integration, using this
   repo's existing `node:sqlite`-backed D1 mocking pattern), a schema
   migration registered in `scripts/lab-bootstrap-d1.mjs`'s `REPLAY` array
   **in the same PR** it's introduced (this repo has a nightly D1 Schema
   Drift Check — see Section 7), observability (structured log lines,
   matching existing `[Module] event` conventions), and updated docs where
   a docs file already exists for that area.
5. **One domain (or sub-slice of a domain) per PR.** Small, reviewable,
   independently revertable. Do not attempt "implement everything" in one
   pass — that produces architectural drift, RBAC inconsistencies, and
   unreviewable diffs.

---

## 3. PHASE 0 — MANDATORY AUDIT (do this before any implementation)

For **every** domain in Section 5, produce one row in a Gap Matrix:

| Domain | Sub-capability | Status | Completion % | Evidence (file:line) | Gap Description |
|---|---|---|---|---|---|
| 1 | Login/signup backend | Exists | ~95% | `workers/src/handlers/auth.js:179` (`handleLogin`), `:36` (`handleSignup`) | — |
| 1 | Login/signup frontend entry point | Broken/Hidden | ~20% | `frontend/index.html:13152-13157` (dead-end "Sign In Required" modal, no link); real form buried in `frontend/user-dashboard.html:747` | Not discoverable from main nav |
| ... | ... | ... | ... | ... | ... |

`Status` must be one of: `Exists`, `Partial`, `Missing`, `Broken`, `Deprecated`,
`Duplicate`, `Can Reuse`, `Needs Refactor`. Every claim needs a file:line
citation — no unverified percentages.

**Do not proceed to implementation until this Gap Matrix has been presented
to the user and explicitly approved.** The matrix itself is a deliverable of
Phase 0, reviewable independently of any code change.

### Known Starting State (verified 2026-07-08 — verify and extend, do not re-derive from zero)

This platform has ~95 merged PRs of backend work already in production,
including a full RBAC audit sweep across 159+ handlers, MSSP tenant
isolation, and a coupon/billing system shipped the same day this brief was
written. Confirmed **already existing** before Phase 0 starts:

- **Auth backend**: `workers/src/handlers/auth.js` — signup, login (with
  brute-force rate limiting via `login_attempts`, and as of today,
  suspicious-login IP-change detection), refresh, logout, `/me`, profile
  update, forgot/reset password (`handleForgotPassword`/`handleResetPassword`),
  MFA challenge issuance and TOTP/backup-code verification
  (`workers/src/handlers/mfa.js`). JWT via `workers/src/auth/jwt.js`
  (access + refresh tokens, `refresh_tokens` table with `ip_address`/
  `user_agent` already tracked per session).
- **RBAC**: `workers/src/auth/rbac.js` — declarative `can()`/`requireCan()`
  permission registry, fail-closed on unknown permissions, roles including
  `SUPERADMIN`, `ADMIN`, `SOC_ANALYST`, `THREAT_HUNTER`, `VIEWER`, `API_USER`
  (`GRANTABLE_ROLES`). MSSP/partner-specific roles live in
  `workers/src/handlers/msspTenantPlatform.js` and `partnerAuth.js`.
- **Organizations**: `workers/src/handlers/orgManagement.js` — full CRUD
  (`handleCreateOrg`, `handleListOrgs`, `handleGetOrg`, `handleOrgDashboard`,
  `handleInviteMember`, `handleUpdateMemberRole`, `handleRemoveMember`,
  `handleOrgScans`, `handleUpdateOrg`, `handleDeleteOrg`) with its own
  `ROLE_PERMISSIONS`.
- **Enterprise SSO**: `workers/src/handlers/enterpriseSsoHandler.js`
  (`handleEnterpriseSSoInfo`, `Initiate`, `Callback`, `Configure`) plus a
  real OAuth landing page at `frontend/auth/callback.html`. **Unverified**:
  which real identity providers (Okta/Azure AD/Google Workspace/generic
  SAML) are actually wired end-to-end vs. scaffolded.
- **MSSP multi-tenancy**: `workers/src/handlers/msspTenantPlatform.js`
  (18 handlers, tenant-scoped, audited this session), `msspOnboardingHandler.js`,
  `msspRevenue.js` (partner revenue share).
  **Unverified**: white-labeling / partner-branding completeness.
- **Commercial layer**: `workers/src/lib/coupons.js` (full CRUD + redemption
  engine: expiry, per-user/total caps, enterprise-only, first-purchase-only,
  minimum-purchase, abuse rate-limiting — shipped 2026-07-08), subscription
  pricing (`workers/src/lib/razorpay.js` `SUBSCRIPTION_PRICES`), `handlers/subscription.js`,
  `services/v24/billingEngine.js` (invoices), `payment_recovery` table +
  webhook seeding on `payment.failed`. **Unverified**: renewal/dunning cron
  completeness, usage-based/API billing enforcement completeness.
- **Notifications**: `workers/src/services/emailEngine.js` — 9 drip
  sequences, 20+ branded templates, Resend→MailChannels provider cascade,
  cron-driven retry, **as of 2026-07-08** a real dead-letter queue
  (`email_dlq`) with bounded retry, and payment-failed/coupon-redeemed/
  suspicious-login event coverage. **Confirmed missing**: unified
  multi-channel notification center (SMS, real WhatsApp Business API send
  — today only `wa.me` links inside emails, Slack, Microsoft Teams, in-app,
  push, webhook), notification preferences, digests.
- **Frontend reality** (the actual customer-facing gap): `frontend/index.html`
  has **no working sign-in/sign-up entry point in its main navigation** — the
  only "Sign In" string on the page is a dead-end modal with an "OK" button
  and no link. The real login form (`#login-overlay`, email/password,
  forgot-password wired) lives inside `frontend/user-dashboard.html`,
  reachable only via a small footer link (`<a class="v14-footer-link-dim"
  href="/user-dashboard.html">`). **Unverified**: whether `user-dashboard.html`
  gates its modules by plan/role server-side-enforced, or renders everything
  to everyone regardless of subscription (this is the single highest-value
  thing to verify first — it's the crux of the "disconnected dashboards"
  complaint).

Phase 0 must **verify or refute each "Unverified" line above** with file:line
evidence, and audit every domain in Section 5 the same way — this list is a
head start, not a substitute for the audit.

---

## 4. CUSTOMER LIFECYCLE (target state)

```
Anonymous Visitor
   │
   ▼
Sign Up ──────────────► Email Verification
   │                          │
   ▼                          ▼
Login ◄──────────────── (verified)
   │
   ▼
Select/Create Organization (or join via invite)
   │
   ▼
Select Plan ──► Coupon (optional) ──► Payment
   │
   ▼
Resource Provisioning (API keys, quotas, workspace)
   │
   ▼
Role/Plan-Personalized Dashboard
   │
   ├──► Upgrade / Downgrade
   ├──► Renew
   ├──► Cancel
   └──► Win-back / Retention (emailEngine.js enterprise_winback sequence
        already exists for this — verify it's wired to real churn events)
```

---

## 5. WORKSTREAMS (audit → gap-fill order, not "build from scratch" order)

For each domain: audit the "Known Starting State" pointer above (if any),
confirm/refute it, fill only the verified gap, in its own PR.

### Domain 1 — Identity Surfacing (highest priority — this is the actual gap)
- Add real `/login`, `/signup`, `/forgot-password`, `/verify-email` routes
  (or confirm the existing overlay-in-`user-dashboard.html` pattern is
  intentional and just needs nav-level discoverability — **decide, don't
  assume, which is the right fix**).
- Add visible Login / Sign Up / Book Demo links to `frontend/index.html`'s
  main header nav (currently absent).
- Verify and complete OAuth wiring for Google/Microsoft/GitHub (consumer)
  and SAML/Azure AD/Okta (enterprise) against the existing
  `enterpriseSsoHandler.js` + `auth/callback.html` scaffold.
- Session management UI: active sessions list, device management, session
  revocation (backend: check `refresh_tokens` table for what's queryable
  today; likely needs a `GET /api/auth/sessions` + revoke endpoint).
- Account lockout / risk-based login: `checkLoginRateLimit` already exists
  in `auth/middleware.js` — verify lockout UX surfaces correctly to the user
  rather than a bare 429.

### Domain 2 — Organization Platform
- Verify `orgManagement.js`'s CRUD is reachable from the frontend at all
  (grep for any UI calling `/api/orgs*`). If not, this is a wiring gap, not
  a backend gap.
- Organization switcher UI (for users in multiple orgs).
- Workspace/project/environment sub-concepts — confirm these don't already
  exist under different naming (e.g., check `customer_tenants`,
  `mssp_clients` schema for overlap before adding new tables).

### Domain 3 — Enterprise RBAC (frontend enforcement layer)
- Backend RBAC is real (Section 3). The gap is almost certainly **frontend
  feature-gating**: does the UI hide modules by role/plan, or rely solely
  on the backend 403? Both are needed — backend enforcement is
  non-negotiable, frontend hiding is UX.
- Reconcile the full role list the business wants (Super Admin, Platform
  Admin, Org Owner, Security Admin, Billing Admin, Developer, SOC Analyst,
  Threat Hunter, Compliance Officer, MSSP Admin, Customer User, Read Only,
  Auditor, Partner, Affiliate, Trainer, Student, API User, Machine Identity)
  against what `rbac.js` + MSSP/partner role systems already define. Add
  only the ones genuinely missing — do not fork a second RBAC system.

### Domain 4 — Customer Lifecycle Wiring
- Confirm every arrow in Section 4's diagram has a real, working handler
  chain end-to-end (not just each node existing in isolation). This is
  where "impressive capabilities, disconnected experience" bugs hide.

### Domain 5 — Commercial Platform
- Mostly exists (Section 3). Audit renewal/dunning cron jobs, usage-based
  API billing enforcement, refund workflow completeness, GST/tax handling
  in `billingEngine.js`.

### Domain 6 — Dashboard Architecture (plan/role-personalized rendering)
- **This is likely the real "disconnected dashboard" fix.** Audit whether
  `user-dashboard.html` (4482 lines — large, likely doing too much) renders
  conditionally by `authCtx.tier`/`role`, or shows every module to every
  authenticated user. If the latter, this is the top implementation
  priority after Domain 1.
- Consider whether one large dashboard file with conditional rendering is
  the right architecture vs. genuinely separate dashboard bundles per plan
  — audit current page weight/load time before deciding; don't assume a
  rewrite is needed.

### Domain 7 — Navigation Engine
- Dynamic, role/plan/org/feature-flag-based nav generation, server-driven
  where possible (a `GET /api/nav` shape driven by `authCtx` is a common,
  low-risk pattern) rather than hardcoded per-page menus.

### Domain 8 — Notifications (multi-channel)
- Email + DLQ + retry: done (2026-07-08).
- Genuinely missing: unified in-app notification center, SMS, real
  WhatsApp Business API (not just `wa.me` links), Slack/Teams webhooks,
  push, generic outbound webhook, per-user notification preferences,
  digest scheduling. Build as channel adapters behind one dispatch
  interface, reusing `email_dlq`'s retry pattern rather than one-off code
  per channel.

### Domain 9 — Customer Portal
- Audit `user-dashboard.html` for: profile, settings, security (sessions/MFA
  — MFA setup exists per Section 3), API keys (exists — verify UI), invoices/
  billing, scan history, reports/downloads, support tickets, org member
  management (backend exists in `orgManagement.js` — verify UI hookup).

### Domain 10 — MSSP Platform
- Audit `msspTenantPlatform.js` UI coverage: white-labeling, client
  onboarding, multi-tenant dashboard, revenue reports, client isolation
  (isolation was specifically audited and fixed earlier this session —
  verify the fix has a corresponding UI).

### Domain 11 — Administration
- Audit the existing admin surface (`/api/admin/*` — coupons, and many
  others already exist) against: users, organizations, subscriptions,
  threat feeds, marketplace, academy, affiliate, CRM, audit logs, feature
  flags, deployments, notifications (new: `/api/admin/email-dlq`), logs.
  Consolidate into one admin portal UI if scattered.

### Domain 12 — Enterprise Production Readiness
- Accessibility, performance, security headers, OWASP ASVS/API Top 10/LLM,
  rate limiting, caching, observability/metrics/tracing, disaster recovery.
  Much of the security-header/rate-limiting/OWASP work has likely already
  been touched in this session's RBAC/security-hardening PRs — audit before
  assuming gaps.

---

## 6. IDENTITY MODEL (target shape for every authenticated request)

```
User
 ├── Organization(s)
 ├── Plan / Subscription
 ├── Roles / Permissions
 ├── API Keys
 ├── Coupons (redemption history)
 ├── Notification Preferences
 ├── Scan History
 ├── Reports
 └── Audit Log entries
```

Audit `resolveAuthV5` (`workers/src/auth/middleware.js`) against this shape
— determine what's already attached to `authCtx` vs. what requires an
additional lookup per request (and whether that lookup should be cached).

---

## 7. ENGINEERING DISCIPLINE SPECIFIC TO THIS REPO (learned the hard way, 2026-07-08)

- **D1 Schema Drift Check**: any new table, wherever self-bootstrapped via
  application code (the established `CREATE TABLE IF NOT EXISTS` +
  `ALTER TABLE ADD COLUMN` pattern), **must** get a tracked migration file
  added to `scripts/lab-bootstrap-d1.mjs`'s `REPLAY` array and the matching
  `CREATE TABLE` block hand-inserted into `workers/schema_bootstrap.sql`
  **in the same PR**. Two production incidents this session (coupon tables,
  then a second-order "table documented but not yet created in production"
  issue) came from skipping this. See `workers/schema_coupons.sql` and
  `workers/schema_email_dlq.sql` for the pattern to follow.
- **Branch workflow**: fresh branch off latest `origin/main` per PR (this
  repo squash-merges, so a branch can silently diverge from a
  content-identical-but-differently-SHA'd commit — verify with
  `git merge-base --is-ancestor <main-tip> HEAD` before pushing, not just a
  content diff, or you'll hit an avoidable merge conflict).
- **Test pattern**: `node:sqlite`'s `DatabaseSync` for realistic in-memory
  D1 mocking (see any `test/*.test.mjs` file for the `makeRealD1()` idiom).
  Mock `services/emailEngine.js` via `vi.mock` in tests that trigger email
  side-effects, to avoid real outbound network calls in CI.
- **Never fabricate secrets.** If a task needs a credential this
  environment doesn't have (e.g., `CLOUDFLARE_API_TOKEN`, OAuth client
  secrets for a new provider), say so explicitly and ask, rather than
  guessing a header name or inventing a placeholder that looks real.

---

## 8. FINAL PRODUCTION ACCEPTANCE CRITERIA

The program is complete only when all of the following hold:

1. **Identity & Access** — register, verify email, sign in, reset password,
   MFA, session management, and resource-level authorization all work
   end-to-end from a real browser session, not just via curl against the API.
2. **Organization & Multi-tenancy** — organizations, workspaces, invitations,
   tenant isolation, and role switching are fully operational and
   *discoverable* from the UI.
3. **Role-Based Dashboards** — every user sees a dashboard tailored to their
   subscription and role; hidden features are enforced server-side, not
   just hidden in CSS.
4. **Commercial Readiness** — subscriptions, coupons, billing, invoices,
   renewals, and usage enforcement are functional and tested.
5. **Customer Experience** — profile, settings, notifications, API keys,
   reports, scan history, and support workflows are complete and reachable.
6. **Administrative Operations** — platform administration, audit logs,
   feature flags, health monitoring, and operational tooling are available.
7. **Security & Compliance** — authentication, authorization, RBAC, rate
   limiting, logging, auditability, and relevant compliance controls are
   validated (do not claim SOC2/ISO27001/HIPAA/PCI compliance without a
   real audit backing it — this repo has previously had to correct a false
   "SOC2 in progress" claim; do not repeat that mistake for a new framework).
8. **Quality Assurance** — unit, integration, and regression tests pass; CI
   gates succeed; no reduction in the existing test count without an
   explicit, justified reason.
9. **Production Verification** — deployment succeeds, live health checks
   pass, and every critical customer journey in Section 4 is walked
   end-to-end against production (or a faithful staging equivalent) before
   declaring a domain done.
