# Phase 6 — Customer Engagement Completion Program

**Date**: 2026-07-15
**Program**: Customer Lifecycle Completion Program (CLCP), Phase 6
**Scope**: Onboarding, notifications, customer success automation, customer
support, customer dashboard, engagement-system deduplication, and a
commercial-journey integrity pass.
**Status**: Living document — update in place per CLAUDE.md §2 rather than
superseding wholesale.

---

## Executive Summary

**Overall call: Conditional GO for continued commercial operation, NOT
"100% complete."** No new customer-facing regressions were found. One
finding — a churn-prevention pipeline that has silently sent zero win-back
emails since it was written — was the highest-business-risk defect
discovered this phase, and it is fixed (PR #267, pending merge). Three
other narrow, low-risk fixes are also ready (PRs #266, #268, #269, all
pending merge). No architectural or commercial changes were made
unilaterally, per this repo's governance policy.

**Highest-risk findings, in order:**

1. **(Fixed, pending merge)** Every paying customer inactive 7+ days has
   received zero retention/win-back offers since the churn-prevention code
   was written — a wrong column name, silently swallowed. PR #267.
2. **(Not fixed — High, ready to implement)** Every trialing customer gets
   no trial-expiry reminder — the sequence exists and is tested, but
   nothing ever enrolls anyone in it. Clear one-PR fix, described below.
3. **(Fixed, pending merge)** 8 real admin/staff/SOC/MSSP-partner routes
   (case updates, incident/maintenance updates, API key updates, user
   status, partner status, webhook management) silently failed in the
   browser due to a CORS allowlist gap — worked via curl, broken via UI.
   PR #266.
4. **(Not fixed — High, needs a product decision)** A fourth, fully-wired,
   completely-empty in-app notification system was found: real backend,
   real UI, zero events ever sent to it. Not previously documented
   anywhere in this registry or the mission brief.
5. **(Not fixed — Medium, needs a product decision)** The one purpose-built
   onboarding/activation checklist in the codebase is not linked from any
   navigation a real customer would encounter.

**What is genuinely further along than the original task brief assumed**:
customer support ticketing (full UI, RBAC, org scoping — already shipped),
organization management UI (already shipped), and the customer dashboard's
API keys/invoices/subscriptions/reports/downloads surfaces (all already
wired) were all still marked "Missing" or "Broken" in
`docs/SAAS_PRODUCTIZATION_MISSION_BRIEF.md` before this pass. That drift is
corrected in PR #269. **This is exactly the failure mode CLAUDE.md's
governance section exists to catch** — the task brief that opened this
session, itself, was working from a stale snapshot.

---

## Phase 6.1 — PR #265 Verification (complete)

| Check | Result |
|---|---|
| Merge status | **Verified**: merged 2026-07-15T17:57:06Z, commit `3211acf0` |
| CI | **Verified**: all checks green pre-merge |
| Deployment | **Verified**: `Deploy to Cloudflare` run 29438727790, conclusion `success` |
| Production verification | **Verified**: `GET /api/health` → `200 {"status":"ok"}`, all components healthy; `GET /api/version` → `commit: "3211acf02a..."`, exact match to the merge SHA |
| Deep verification (email_tracking rows, cron logs) | **Not Verified** — no production DB/log access available from this environment; flagged in PR #265 itself as a follow-up |

No code changes were needed for this phase.

---

## Findings, Ordered by Business Risk

### 1. Churn-prevention query always found zero at-risk customers — FIXED (PR #267)

- **Severity**: High (revenue/retention-relevant, silent failure, long-lived)
- **Confidence**: Verified
- **Root cause**: `runChurnPrevention()` (`workers/src/services/automationEngine.js`)
  filtered on `leads.status = 'active'` — a column that has never existed on
  the `leads` table. D1's `.all().catch(() => ({ results: [] }))` silently
  swallowed the resulting error every cron run.
- **Customer impact**: every Starter/Pro/Enterprise/MSSP customer inactive
  7+ days has received zero retention discount offers since this code
  existed, with no error signal anywhere.
- **Fix**: corrected to `funnel_stage = 'customer'`, the established
  "currently paying" signal used identically in 3 other files. 5 new
  regression tests against a real `node:sqlite` D1. New registry entry
  CAP-NOTIF-006 (this capability had none before).
- **Status**: PR #267 open, tests green, awaiting merge approval.

### 2. `trial_expiry` sequence defined but never enrolled — NOT FIXED, ready to implement

- **Severity**: High (revenue-relevant — a silently-lapsing trial is a lost
  conversion opportunity with no nudge)
- **Confidence**: Verified
- **Root cause**: `DRIP_SEQUENCES.trial_expiry` and its dispatch/delay-map
  plumbing exist in `emailEngine.js` and are tested as part of the shared
  dispatch switch. But `enrollInSequence(env, email, 'trial_expiry', ...)`
  has zero call sites anywhere in the codebase — nothing ever enrolls a
  trialing customer.
- **Customer impact**: every trial that lapses does so silently, with no
  "your trial is ending" email.
- **Recommended fix** (not implemented this pass — new invocation, not a
  broken-reference fix, so held for a dedicated PR rather than bundled):
  mirror the existing `upgrade_nudge` cron block already in
  `workers/src/index.js` — select `subscriptions WHERE status='trialing'
  AND trial_ends_at BETWEEN now() AND now()+3d`, call
  `enrollInSequence(...,'trial_expiry',...)`. All downstream machinery
  (template, dispatch, delivery) already exists and is tested.
- **Status**: Not started. Recommended as the next Phase 6 PR.

### 3. CORS `Access-Control-Allow-Methods` omitted `PATCH` — FIXED (PR #266)

- **Severity**: High (blast radius: 8 real routes, all silently broken
  in-browser)
- **Confidence**: Verified
- **Root cause**: the global preflight handler (sole preflight path for
  every route) returned an allowlist that never included `PATCH`, despite
  8 real routes dispatching on it: SOC case updates, admin
  incident/maintenance updates, workflow updates, API key updates, admin
  user status, MSSP partner status, webhook management.
- **Customer/staff impact**: any browser-based PATCH to these routes
  failed silently ("Failed to fetch," no server-side error) — curl and the
  test suite were unaffected, which is why it shipped unnoticed. This is
  staff/admin/partner-facing, not end-customer-facing.
- **Fix**: one-line allowlist addition, 1 new regression test.
- **Status**: PR #266 open, tests green, awaiting merge approval.

### 4. Undocumented, fully-wired, permanently-empty 4th notification system — NOT FIXED, needs a product decision

- **Severity**: High (customer-facing UI silently shows "0 notifications,
  always," and no one has ever noticed because the page itself is orphaned
  — see Finding 5)
- **Confidence**: Verified
- **Root cause**: `opsEngine.js`'s `sendNotification()` is the sole writer
  to the `ops_notifications` table and has **zero callers anywhere** in the
  codebase. `commercialPlatformHandler.js`'s `handleNotificationCenter()`
  reads that same table, is routed at a real endpoint, and is rendered by a
  full KPI/list UI in `frontend/customer-success-dashboard.html`. Not
  mentioned anywhere in the capability registry or the mission brief before
  this pass.
- **Customer impact**: any customer who reaches this page sees "0 total / 0
  delivered / 0 pending / No notifications" forever — not because nothing
  happened, but because nothing was ever wired to write to it.
- **Why not auto-fixed**: deciding which of the 7 `NOTIFICATION_TYPES` map
  to which real platform events (and whether this should coexist with the
  separate `notification_log`-backed system) is an architecture decision,
  not a bug fix. **Recommend**: resolve together with Finding 5, since both
  point at the same orphaned page.

### 5. The one onboarding/activation checklist in the codebase is unreachable — NOT FIXED, needs a product decision

- **Severity**: Medium-High (the backend logic is correct; the entire
  feature is invisible to real customers)
- **Confidence**: Verified
- **Root cause**: the P15.1 onboarding-wizard backend
  (`commercialPlatformHandler.js`) correctly computes a per-user completion
  checklist and is properly rendered by
  `frontend/customer-success-dashboard.html`. But that page is absent from
  `user-dashboard.html`'s nav (the confirmed canonical post-login
  dashboard), absent from `index.html`'s nav, and never a redirect target
  after signup/login. Its only inbound link anywhere in the repo is
  `sitemap.html`. It also uses a weaker "paste your API key" auth gate
  instead of the session login the rest of the product uses.
- **Customer impact**: a real customer who signs up and lands on
  `user-dashboard.html` (confirmed the real landing page) will never see
  this checklist.
- **Why not auto-fixed**: three overlapping dashboard-like pages exist
  (`user-dashboard.html`, `customer-dashboard.html`,
  `customer-success-dashboard.html`) — deciding where onboarding content
  and the notification center (Finding 4) belong is an information-
  architecture call, not a one-line patch. **This is the single highest-
  value open decision from this audit**: resolving it closes both Finding
  4 and Finding 5 at once.

### 6. Free-tier signups receive no nurture sequence — NOT FIXED, needs a product decision

- **Severity**: Medium (growth/activation-relevant, not a bug — a gap
  between two systems)
- **Confidence**: Verified
- **Root cause**: `DRIP_SEQUENCES.welcome` is correctly wired, but only
  from anonymous email-capture endpoints (`leads.js`, `growth.js`). Real
  account signup (`auth.js` `handleSignup`) sends one hardcoded, untracked
  email and nothing further. `subscription_activated` only fires on
  payment.
- **Customer impact**: a customer who signs up for a free account (not via
  a scan-capture form, not yet paying) gets one email, then silence — no
  education or upgrade nurture, unlike anonymous leads or paying customers.
- **Why not auto-fixed**: whether free-signups should join `welcome`, get a
  new sequence, or whether this is intentional segmentation is a
  product/content decision.

### 7. `user-dashboard.html`'s notification bell is still disconnected — NOT FIXED, self-contained (ready to implement)

- **Severity**: Medium
- **Confidence**: Verified
- **Root cause**: `index.html`'s bell was fixed 2026-07-09 to read the real
  `notification_log` (CAP-NOTIF-002). `user-dashboard.html`'s bell (its own
  "GOD MODE v16 Notification Engine") was never fixed — still a pure
  client-side array populated by a local purchase-modal toast and a 5-min
  poll of global threat-intel, never `notification_log`.
- **Why not auto-fixed this pass**: real UI surgery on the main customer
  dashboard, which this session's governance requires live-browser
  verification for before shipping — not attempted given session scope.
  **Recommended**: port the exact pattern already proven in `index.html`'s
  fix; low design risk since the pattern is already validated.

### 8. In-app usage/quota alerts computed but never surfaced — NOT FIXED, needs a product decision

- **Severity**: Medium
- **Confidence**: Verified
- **Root cause**: `evaluateUpsellTriggers()` (`upsellEngine.js`) correctly
  computes 90%-scan-quota / 80%-API-quota warnings and is exposed at a real
  route. Nothing calls it — no cron, no frontend.
- **Why not auto-fixed**: deciding where in the request lifecycle this
  should fire (on scan completion? on dashboard load?) is UI/UX scope.

### 9. Orphaned cron branches, one with a real unbounded-growth risk — NOT FIXED, needs a decision per branch

- **Severity**: Medium (one sub-item), Low (two sub-items)
- **Confidence**: Verified
- **Root cause**: `wrangler.toml` registers 5 cron strings. Three
  `if (cron === ...)` branches in `index.js`'s scheduled handler check
  strings never in that list — permanently dead: Sentinel APEX defense-
  product generation (12h), MYTHOS legacy fallback (12h), and an Ops
  Lifecycle cleanup job (3am) that prunes `ops_usage_events`/
  `ops_notifications`.
- **Why this matters more than typical dead code**: the Ops Lifecycle
  branch's retention/pruning logic never running is a real unbounded-
  table-growth risk, not just wasted code.
- **Why not auto-fixed**: retiring dead code is normally safe, but whether
  each of these three was meant to keep running (and should be
  re-registered in `wrangler.toml`) or is intentionally retired requires a
  business call per branch — re-enabling a cron is an infra change, not a
  pure cleanup.

### 10. `developer_webhooks` vs `org_webhooks` duplication — ALREADY RESOLVED (verified, no action needed)

- **Confidence**: Verified
- PR #254 fully retired `developer_webhooks`; only `org_webhooks` remains.
  Re-confirmed this pass via `developerPortalWebhookSecurity.test.mjs`
  (7/7 passing). The registry's own frontend/navigation fields for this
  capability were stale (said "missing" despite the entry's own notes
  citing the fix) — corrected in PR #269.

### 11. Documentation drift across the mission brief and one registry entry — FIXED (PR #269)

- **Confidence**: Verified
- 7 Gap Matrix rows in `docs/SAAS_PRODUCTIZATION_MISSION_BRIEF.md` were
  stale (marked Missing/Broken for capabilities shipped weeks earlier:
  identity nav entry, organization UI, RBAC downstream enforcement,
  lifecycle wiring at org-creation, in-app notification center half-state,
  developer webhook dedup, support tickets). One registry entry
  (CAP-NOTIF-003) contradicted its own notes field. One in-code API-docs
  example cited a webhook event name that has never existed. All corrected
  with evidence; nothing deleted, per CLAUDE.md §2.

### 12. API-key empty state had no next step — FIXED (PR #268)

- **Severity**: Low
- Every other empty state on the dashboard offers a next action; this one
  didn't. One-line fix reusing the page's own existing "create key" modal
  function.

### 13. Minor code-quality note, not a customer-facing bug

- `advanceSequence()`'s completion check is hardcoded `nextStep >= 4`
  rather than derived from each sequence's real step count. For sequences
  with fewer than 4 steps, this wastes 1-2 harmless cron passes before
  marking completion — no wrong or duplicate email is ever sent. Not worth
  a standalone PR (previously documented, re-confirmed, still true).

---

## Phase 6.3 — Duplicate/Dead System Audit Summary

| System | Verdict |
|---|---|
| `developer_webhooks` vs `org_webhooks` | **Resolved** (PR #254, confirmed this pass) |
| `index.html` bell vs `user-dashboard.html` bell | **Not a duplication** — one is fixed, one is still fake (Finding 7) |
| `opsEngine.js` notification system vs `notificationPlatform.js` system | **Real architectural overlap**, not yet reconciled (Finding 4) — recommend a decision, not a retirement, since the `notification_log` system is the proven one and the `ops_notifications` one may be redundant rather than complementary |
| 3 orphaned cron branches | **Dead**, decision needed per branch (Finding 9) |
| Discord integration | Confirmed total absence (marketing links only, no bot/webhook) — not a duplication, a known gap |
| SMS | Confirmed total absence — known gap, unchanged |

---

## Phase 6.4 — Commercial Customer Journey

`Visitor → Signup → Trial → Checkout → Payment → Provisioning → Email →
Dashboard → API Keys → Reports → Renewal → Support → Expansion`

| Hop | Status | Confidence | Evidence |
|---|---|---|---|
| Visitor → Signup | **Working** | Verified | CAP-IDN-001/002/003; live-Playwright-against-production verification through 2026-07-12 |
| Signup → Trial | **Partially working** | Verified | Signup succeeds; no nurture drip for free signups (Finding 6); trial itself provisions correctly |
| Trial → Checkout | **Working** | Verified (this pass) | Real Pro-tier Razorpay checkout and plan-cancel flows confirmed live in `user-dashboard.html` |
| Checkout → Payment | **Working** | Partially Verified | Heavily hardened in prior program phases (PRs #240, #242, #259 closed price-tampering gaps) — not re-audited from scratch this pass, trusted per CLAUDE.md's "don't re-derive" guidance |
| Payment → Provisioning → Email | **Working** | Partially Verified | `subscription_activated` sequence correctly wired end-to-end from `payments.js`'s payment-confirmation webhook — verified in a prior session this program, re-confirmed not contradicted this pass |
| Email → Dashboard | **Working** | Verified (this pass) | Full dashboard audit this session — API keys, invoices, subscriptions, reports, downloads, org settings, tickets all reachable |
| Dashboard → API Keys | **Working** | Verified | Minor CTA gap fixed (Finding 12) |
| API Keys → Reports | **Working** | Verified (this pass) | A previously-documented race condition (two functions writing the same table) was found already fixed in current code |
| Reports → Renewal | **Working** | Verified | Renewal-queue bug fixed in a prior session (PR #264); sanity-checked intact this pass |
| Renewal → Support | **Working** | Verified | Full ticket system shipped (PR #260); documentation corrected to match (PR #269) |
| Support → Expansion | **Partially working, now improved** | Verified | Upgrade-nudge cron works; churn/win-back was completely dark, now fixed (Finding 1/PR #267); in-app usage alerts still not surfaced (Finding 8) |

**No hop in this chain is fully broken.** The weakest links are Trial→
Signup (no nurture for free signups) and Support→Expansion (in-app usage
alerts not surfaced; win-back was dark until this pass's fix).

---

## Readiness Assessment

| Question | Answer |
|---|---|
| Is customer onboarding production-ready? | **Partially.** Login/signup/MFA discoverability: Verified working. Activation nurture: real gap for free-tier signups (Finding 6); the one purpose-built onboarding checklist is unreachable (Finding 5). |
| Is customer provisioning production-ready? | **Yes**, for the paid path (Verified — payment webhook → activation email → dashboard access all confirmed). Free-tier provisioning works but has no follow-up nurture. |
| Is customer engagement production-ready? | **Partially.** Renewal reminders: fixed and working. Churn/win-back: fixed this pass, not yet deployed. Trial-expiry reminders: still completely unwired (Finding 2). One notification system is fully wired but permanently empty (Finding 4). |
| Is customer support production-ready? | **Yes, for the customer-facing ask** (Verified — full ticket UI, org scoping, RBAC, notifications, 25 tests). Still `operational_status: PILOT ONLY` in the registry pending one live dynamic-browser click-through, which this session did not perform. File attachments and an admin triage UI remain deliberately out of scope. |
| Is customer expansion production-ready? | **Partially.** Upgrade nudges work. Usage-limit alerts are computed but never shown to the customer (Finding 8). Win-back was dark, now fixed pending merge. |
| Is commercial launch readiness achieved? | **No single blocking defect**, but not "100% complete": 2 High findings remain open by design (Findings 2 and 4, both requiring a product decision or a follow-up PR), plus 4 PRs from this session awaiting merge. |

---

## Remaining Work, Prioritized

**Critical**: none found this pass.

**High**:
- Wire `trial_expiry` enrollment (Finding 2) — clear, scoped, one-PR fix, all downstream machinery already exists and is tested.
- Decide the fate of `customer-success-dashboard.html` (onboarding checklist + notification center, Findings 4 & 5) — an IA decision that unblocks two real features at once.

**Medium**:
- Fix `user-dashboard.html`'s disconnected notification bell (Finding 7) — pattern already proven in `index.html`, needs live-browser verification before shipping.
- Wire `evaluateUpsellTriggers()` to a real trigger point (Finding 8).
- Decide free-tier signup nurture strategy (Finding 6).
- Decide per-branch fate of the 3 orphaned cron jobs, prioritizing the Ops Lifecycle retention job given its unbounded-growth risk (Finding 9).

**Low**:
- `advanceSequence()`'s hardcoded step-4 threshold (Finding 13) — code quality only, no customer impact.

**Business Decision** (explicitly not engineering calls):
- Sidebar-level RBAC nav hiding by role/plan — currently shows all modules to all signed-in users; every tier has some legitimate access to every page today, so this is a UX/positioning choice, not a bug.
- SMS, real WhatsApp Business API send, push notifications, Discord — all confirmed still fully absent; each is a net-new channel-adapter build, not a fix.
- AI Security Maturity Assessment frontend history view — backend persists real data with no UI; deliberately deferred at ship time (PR #257), still true.

---

## This Session's Deliverables

| PR | Title | Status |
|---|---|---|
| #265 | Enterprise-lead drip 5th-email fix | **Merged, deployed, production-verified** |
| #266 | CORS `Access-Control-Allow-Methods` omits PATCH | Open, tests green, awaiting merge |
| #267 | Churn-prevention query always found 0 at-risk customers | Open, tests green, awaiting merge |
| #268 | API-keys empty-state missing CTA | Open, tests green, awaiting merge |
| #269 | Documentation drift correction | Open, tests green, awaiting merge |

All four open PRs: full regression suite green at time of each PR (up to
307 files / 3206 tests), capability registry validated (0 hard failures),
one production problem per PR, held for explicit merge approval per this
session's established convention for every prior fix.
