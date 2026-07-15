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
- **Enterprise SSO**: **UPDATED 2026-07-15** — `workers/src/handlers/ssoAuth.js`
  is now the canonical implementation (`handleSSOLogin`/`Callback`/
  `ConfigUpsert`/`Get`/`Delete`), real PKCE + signature-verified OIDC via
  `lib/oidc.js`, plus a real OAuth landing page at `frontend/auth/callback.html`.
  `enterpriseSsoHandler.js`'s login/callback routes are retired (see Domain 1
  gap-matrix row below for the full reconciliation record); its `Info`/
  `Configure` handlers remain as the config-guide content endpoint. **Still
  unverified**: a live-IdP round-trip against a real Okta/Azure AD/Google
  Workspace tenant (only realistic-but-simulated RSA-signed IdP responses have
  been tested) — no real customer has completed SSO yet.
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
  push, webhook), notification preferences, digests. **FIXED 2026-07-15**
  (Customer Lifecycle Completion Program, Phase 6): the `enterprise` legacy
  drip sequence (auto-enrolled on every scan-detected enterprise domain,
  `growth.js:86`) declared a 5-touch cadence (`DRIP_SEQUENCES.enterprise.steps:
  [0,1,3,5,7]`, `DELAY_MAP.enterprise` already 5 entries long) but the shared
  legacy dispatch switch only ever implemented 4 templates — step index 4
  silently fell through to the no-op default and marked the sequence
  `completed` without sending. Added `templateEnterpriseLeadDay7` and wired
  it to that step; see `workers/test/enterpriseLeadDripStep4.test.mjs`.
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

## 3B. PHASE 0 AUDIT RESULTS (completed 2026-07-08)

The audit below was performed against this repository as it stood on
2026-07-08 (commit `0d07c6b7`). **This section is now the authoritative gap
matrix — Section 5's per-domain notes should be read as superseded by the
specific findings here where they overlap.**

### Quick wins — fix independently of the wider program

These are small, isolated, high-value fixes that don't require the identity/
org/dashboard rearchitecture below. Recommend doing these first, each as its
own tiny PR:

1. **Broken MSSP partner onboarding link (customer-facing dead end).**
   `workers/src/services/emailEngine.js:747,761` sends every newly onboarded
   MSSP partner a welcome email linking to `${BASE_URL}/mssp-command-center`.
   That page (`frontend/mssp-command-center.html:652`) is gated by
   `CDB_STAFF_AUTH.guard()`, which per `workers/src/handlers/staffAuth.js:13-19`
   only accepts the platform-owner email or internal `user_roles` rows —
   **an external MSSP partner can never log into the page their welcome
   email sends them to.** The correct destination,
   `frontend/partner-portal.html` (magic-link partner auth, real branding/
   domain/revenue/client features), is never linked from onboarding at all.
   Fix: point the onboarding email at `partner-portal.html`.
2. **Client-spoofable feature lock.** `frontend/user-dashboard.html:3564`
   reads the user's plan tier from `localStorage.getItem('cdb_tier')` to
   decide which "My Tools" cards are unlocked (`:3598`), instead of the
   authenticated `_plan` state fetched from the backend. Trivially bypassed
   in devtools. (Real scan execution presumably still enforces server-side —
   verify this before treating it as cosmetic-only.)
3. **Race condition on the Reports page.** Two independent functions
   (`loadPayments()` and `loadUserReports()`, `frontend/user-dashboard.html:2220`
   and `:3633`) both write into the same `#reports-table` element on page
   load — whichever resolves last silently wins.
4. **Audit-log blind spot.** The "Audit Log" tab admins actually see
   (`GET /api/admin/audit` → `frontend/ops-dashboard.html:503`) reads a KV
   trail (`writeOpsAudit()`, `opsEngine.js:124-137`) that is entirely
   separate from the real D1 `audit_log` table SSO config changes
   (`enterpriseSsoHandler.js:314`) and AI-copilot actions
   (`aiSecurityCopilot.js:1203`) actually write to. An admin reviewing "the
   audit log" today would never see an SSO reconfiguration. Fix: either
   point `handleAdminAudit()` at the real `audit_log` table, or merge both
   trails into one read path.

### Gap Matrix

| # | Domain | Sub-capability | Status | Evidence | Gap |
|---|---|---|---|---|---|
| 1 | Identity | Login/signup/MFA/password-reset backend | **Exists** | `handlers/auth.js`, `handlers/mfa.js` | — |
| 1 | Identity | Login/signup frontend entry point on main site | **SUPERSEDED — FIXED 2026-07-09** | Real "Sign In" nav link now injected on both desktop/mobile (`cdbApplyGates()`), dead-end modal now has a working button; live-Playwright-verified against production 2026-07-10/11/12, full real signup→MFA→logout→login→MFA-challenge chain confirmed. See `docs/capability-registry/domains/identity.json` CAP-IDN-001 (`customer_journey_complete: true`) | Resolved — retained here for history per this repo's Documentation Drift policy (CLAUDE.md §2) |
| 1 | Identity | Google OAuth (consumer) | **Exists, unlinked** | `handlers/googleAuth.js`, real callback at `frontend/auth/callback.html` | Zero frontend pages link to it — fully built, invisible |
| 1 | Identity | Enterprise SSO (Azure AD / Okta / generic OIDC) | **RECONCILED 2026-07-15** (Customer Lifecycle Completion Program, Phase 5) | `handlers/ssoAuth.js` is now the sole customer-facing implementation (`/api/auth/sso/login`, `/api/auth/sso/callback`, `POST /api/admin/sso/config`) — chosen because it already did a real, cryptographically-verified OIDC round-trip (PKCE + nonce + RS256 `id_token` signature check via `lib/oidc.js`, tested with real RSA keypairs in `ssoOidcVerify.test.mjs`/`oidcSSO.test.mjs`) and real `org_members` JIT provisioning, while `enterpriseSsoHandler.js` trusted the IdP's `userinfo` response with zero verification and never provisioned org membership. `ssoAuth.js` gained the two things it was missing: a real `audit_log` write (mirroring `enterpriseSsoHandler.js`'s own, per `ssoAuditLogWrite.test.mjs`'s lesson about silent-catch audit failures) and the friendly named-`idp_type` (`azure_ad`/`okta`) discovery-URL convenience `enterpriseSsoHandler.js` had. `enterpriseSsoHandler.js`'s login/callback routes now redirect/410 to the canonical ones (`workers/src/index.js`'s `/api/auth/enterprise/*` block); its `config` info endpoint stays alive at the same URL (linked from `frontend/enterprise-portal.html`) but now documents the canonical contract. Verified safe to do now, not just easy: `KPI_DASHBOARD.md` and both `SUPPORT_PLAYBOOK.md`/`IMPLEMENTATION_PLAYBOOK.md` confirm zero real customers have ever completed SSO on either system, and the internal ops docs already treated `/api/auth/sso/*` as the real production surface before this change — only `enterprise-portal.html`'s marketing copy pointed at the other one, and that's been corrected. | SAML remains genuinely missing (both systems are OIDC-only) — unaffected by this reconciliation, tracked separately below. |
| 1 | Identity | SAML | **Missing** | The canonical SSO path (`ssoAuth.js`, see reconciled row above) is OIDC-only by design (`lib/oidc.js`'s own header comment: a hand-rolled SAML signature verifier is a security liability, not a feature) | Real gap if a customer specifically requires SAML |
| 1 | Identity | Session list / per-session revoke | **Missing** | Only blanket "revoke all sessions" exists (`auth.js:508-512,605-610`) | No enumerable session list in UI or API |
| 2 | Organization | Backend CRUD (create/list/get/dashboard/invite/roles/remove/scans/update/delete) | **Exists** | `handlers/orgManagement.js` (10 handlers), routed `index.js:3543-3597` | — |
| 2 | Organization | Any frontend UI | **SUPERSEDED — SHIPPED 2026-07-09→11 (CAP-ORG-001)** | Real UI in `user-dashboard.html`: sidebar "Team" section, `#page-orgs` list+detail, Create Organization, Members table + Invite, org-scoped scan history, Settings/Danger Zone with real `canManage`/`isOwner` gating matching backend RBAC. See `docs/capability-registry/domains/organizations.json` | Resolved — retained here for history per CLAUDE.md §2 |
| 3 | RBAC | Backend enforcement | **Exists** | `auth/rbac.js` `can()`/`requireCan()`, fail-closed, audited across 159+ handlers this session | — |
| 3 | RBAC | Frontend feature-gating by role/plan | **PARTIALLY SUPERSEDED (2026-07-15 re-audit)** | `user-dashboard.html:837-902`-equivalent sidebar still shows all 17+ modules to every signed-in user regardless of role/plan (unchanged). But the *downstream* gating this row originally flagged as "not real" is now largely real: the case-sensitivity bug that silently defeated tier checks in `exportCisoPDF()`/`syncPlanCards()`/`selectPlan()`/`loadKeys()`/MSSP tool catalog is fixed (now keys off authenticated `_plan.plan`, not localStorage), and the client-spoofable `localStorage.getItem('cdb_tier')` read is gone from the unlock-decision path | Sidebar-level nav hiding is a product decision (every tier has *some* legitimate access to every page per this registry's own reasoning), not a bug fix — left open, Low severity |
| 4 | Lifecycle | End-to-end wiring signup→org→plan→payment→dashboard | **SUPERSEDED at the org-creation step (2026-07-09→11)** | The specific break this row identified — no UI at organization creation/selection — is resolved (Domain 2 above). Not re-verified end-to-end as a single chained flow in this pass; full-chain re-assessment is Customer Lifecycle Completion Program Phase 6.4 scope (Not Verified as of this update) | Resolved at this hop — retained here for history per CLAUDE.md §2 |
| 5 | Commercial | Coupons | **Exists** | Full CRUD + redemption engine, shipped 2026-07-08 | — |
| 5 | Commercial | Subscriptions/billing/invoices | **Exists** | `handlers/subscription.js`, `services/v24/billingEngine.js`, `billing-portal.html` (real UI: cancel/upgrade/usage/invoices) | — |
| 5 | Commercial | Payment-failed customer notification | **Exists** | Shipped 2026-07-08 (`sendPaymentFailedEmail`) | — |
| 6 | Dashboard architecture | Plan/role-personalized rendering | **Missing (see Domain 3)** | Same finding as Domain 3 — no real personalization, only upsell overlays | Highest-value fix in the whole program |
| 7 | Navigation | Server-driven, role/plan/feature-flag-based nav | **Missing** | No `/api/nav` endpoint anywhere; nav is static HTML (`index.html:1123-1195`, `user-dashboard.html:805-901`) plus hardcoded client-side JS arrays for owner-only items (`index.html:20196-20307`) | Feature flags exist server-side (`opsEngine.js`) but nothing consumes them for nav |
| 8 | Notifications | Email + DLQ + retry | **Exists** | Shipped 2026-07-08 | — |
| 8 | Notifications | Generic multi-channel dispatcher (Slack/Teams/webhook/in-app) | **Exists, undersold** | `handlers/notificationPlatform.js` — real Slack/Teams webhook delivery, wired to real events (`CHURN_RISK_ALERT`, MSSP/developer onboarding) | No frontend UI lets a user configure their Slack/Teams webhook (`PUT /api/notifications/preferences` unused by any page) |
| 8 | Notifications | SMS | **Missing** | No provider integration anywhere | — |
| 8 | Notifications | Real WhatsApp (Business/Cloud API) | **Missing** | Every WhatsApp reference is a `wa.me` click-to-chat link, not a send API | — |
| 8 | Notifications | Push notifications | **Missing** | No web-push/FCM/APNs anywhere | — |
| 8 | Notifications | In-app notification center | **PARTIALLY SUPERSEDED (2026-07-09 fix, 2026-07-15 re-audit)** | `index.html`'s bell now reads the real `GET /api/notifications/log` (CAP-NOTIF-002 — `customer_journey_complete: false` pending one post-merge production smoke test, not yet performed). `user-dashboard.html`'s bell (its own "GOD MODE v16 Notification Engine") is still a pure client-side in-memory array — never reads `notification_log`, populated only by a local purchase-modal toast and a 5-min poll of global `/api/threat-intel/live` | Half-fixed: `index.html` connected (pending final smoke test), `user-dashboard.html` still disconnected — self-contained fix, reuse the exact pattern already shipped for `index.html` |
| 8 | Notifications | Developer webhooks | **SUPERSEDED — RESOLVED (PR #254, 2026-07-xx)** | `developer_webhooks` was fully retired from `developerPortal.js`; only `org_webhooks`/`webhook_delivery_log` (`enterpriseAutomation.js`) remains. Confirmed via 2026-07-15 re-audit: `developerPortalWebhookSecurity.test.mjs` (7/7 passing) | Resolved — retained here for history per CLAUDE.md §2. Note: the one remaining webhook dispatcher (`dispatchWebhookEvent`) still has zero real production callers (pre-existing, already-tracked CAP-NOTIF-003 gap, not a duplication issue) |
| 9 | Customer Portal | Profile/password/MFA | **Exists** | `user-dashboard.html:2778-2945` | — |
| 9 | Customer Portal | API key management | **Exists** | `user-dashboard.html:1258-1300,2173,2201` | — |
| 9 | Customer Portal | Billing/invoices/subscription mgmt | **Exists** | `user-dashboard.html:2708-2775`, `billing-portal.html` | — |
| 9 | Customer Portal | Scan history / reports | **Exists, buggy** | See Quick Win #3 (race condition) | — |
| 9 | Customer Portal | Session management UI | **Missing** | See Domain 1 | — |
| 9 | Customer Portal | Support ticket system | **SUPERSEDED — SHIPPED (PR #260, Customer Lifecycle Completion Program Phase 3)** | Full in-product ticket creation, org scoping (incl. cross-org 403/404 isolation), status, comments, history, in-app notifications, RBAC — `user-dashboard.html:974` (nav), `#page-support` (dedicated page), `workers/src/handlers/support.js`. 25 passing tests. See `docs/capability-registry/domains/customer-portal.json` CAP-PORTAL-004. Deliberately deferred: file attachments (no upload infra in repo), admin ticket-triage UI (admin API untouched) | Resolved for the customer-facing ask — retained here for history per CLAUDE.md §2. `operational_status: PILOT ONLY` pending a live dynamic-browser click-through (not yet performed) |
| 10 | MSSP Platform | Tenant isolation backend | **Exists** | `handlers/msspTenantPlatform.js` (18 handlers), audited/fixed earlier this session | — |
| 10 | MSSP Platform | Partner self-service portal | **Exists, orphaned** | `frontend/partner-portal.html` — real branding/domain/revenue/client features | Never linked from onboarding (Quick Win #1) |
| 10 | MSSP Platform | Multi-tenant sub-account dashboards (per-client drill-down) | **Partial** | Backend fully built (`msspTenantPlatform.js` dashboard/hierarchy/sub-tenants/billing/usage endpoints); zero frontend calls any of them | Only the coarse client list/create is wired |
| 10 | MSSP Platform | Delegated admin permissions (MSSP staff sub-accounts) | **Missing** | No route, handler, or UI reference found | — |
| 11 | Administration | Coupons admin | **Exists** | Full CRUD, no UI (API-only) | — |
| 11 | Administration | Users/Organizations/Marketplace/Academy/Affiliate/CRM/Support admin routes | **Missing** | Zero `/api/admin/*` routes for any of these areas | Real gap — these areas have no admin surface at all, not even API-only |
| 11 | Administration | Feature flags | **Exists, inconsistent naming** | `GET/PUT /api/ops/flags` (`opsEngine.js`) — works, but breaks the `/api/admin/*` naming convention used everywhere else | — |
| 11 | Administration | Audit logs | **Broken** | See Quick Win #4 | — |
| 11 | Administration | Admin frontend coverage | **Partial** | `ops-dashboard.html` + `admin-portal.html` (roles) cover ~7 of ~35 admin routes; the rest (including all of coupons admin) are API-only | — |
| 12 | Production Readiness | Security headers / accessibility / Lighthouse / dependency scanning / secret scanning | **Exists** | Enforced as required CI gates (`Security Header Assertions`, `Accessibility (axe)`, `Lighthouse CI`, `Dependency Vulnerability Audit`, `gitleaks`, `GitGuardian`) | — |
| 12 | Production Readiness | Rate limiting / structured request-ID logging | **Exists** | `middleware/rateLimit.js`; global error boundary + request-ID correlation | — |
| 12 | Production Readiness | Distributed tracing / APM | **Missing** | No Sentry/Datadog/OpenTelemetry anywhere | — |
| 12 | Production Readiness | Formal OWASP ASVS/API-Top-10 checklist audit | **Not verified** | Individual controls exist (headers, rate limiting, RBAC) but no consolidated checklist artifact found | Worth producing one, not necessarily worth new controls |

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
