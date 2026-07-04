# Phase IX — Customer Playbooks (Implementation · Success · Support)

> Operational playbooks for the Release Candidate, grounded in the customer
> journeys verified against **live production** in Phase IX. These complement,
> and do not duplicate, the existing `PRODUCTION_OPERATIONS_MANUAL.md` and the
> incident/DR/deploy runbooks (see `DOCUMENTATION_INDEX.md`).
>
> **Date:** 2026-07-04 · **Build:** `b81bce0` + org-dashboard RC fix.

---

## A. Implementation Playbook (new enterprise customer, self-serve)

Every step below was executed as a paying customer over HTTP against production;
none required engineering intervention. Times are observed live.

| Step | Action | Endpoint | Expected result |
|------|--------|----------|-----------------|
| 1 | Create account | `POST /api/auth/signup` | 201; access+refresh tokens; **API key returned once** (`api_key`), save it; `next_steps` guidance |
| 2 | Sign in | `POST /api/auth/login` | 200; access token |
| 3 | Confirm identity | `GET /api/auth/me` | 200; profile + tier (FREE until upgrade) |
| 4 | Create organization (tenant) | `POST /api/orgs` | 201; `org_id`; you are OWNER; STARTER org defaults |
| 5 | View org posture dashboard | `GET /api/orgs/:id/dashboard` | 200; empty-state zeros for a new org, aggregates as scans accrue |
| 6 | Issue / manage API keys | `GET/POST /api/keys` | list 200; FREE = 1 key (auto-issued at signup) |
| 7 | Enable MFA | `POST /api/auth/mfa/setup` → `GET /api/auth/mfa/status` | secret issued; status reflects enrollment |
| 8 | (Enterprise) Configure SSO | `GET /api/auth/enterprise/sso?org=<slug>` | needs a live IdP (Okta/Entra); **pilot-only** until the round-trip is proven |
| 9 | First scan | `POST /api/scan/domain` | 200; grade/risk; unresolvable domains return `unmeasurable` (no false verdict) |
| 10 | First report | `POST /api/report/generate` → `GET /api/report/:token` | 201 + shareable link; HTML downloads (7-day FREE retention) |
| 11 | First AI insight | `POST /api/ai/analyze` | 200; severity + confidence; paid AI (simulate/forecast) is PRO+ |

**Provisioning note:** no manual provisioning step exists or is needed — tenancy,
keys, and entitlements are created by the customer's own actions.

---

## B. Customer Success Playbook

**Time-to-value targets (measured live):**

| Milestone | Target | Observed |
|-----------|--------|----------|
| First value (signup→first scan) | < 5 min | ~2.6 s |
| First report | < 5 min | < 1 s after scan |
| First AI insight | < 5 min | < 0.1 s |
| Time to production | < 1 day | minutes (self-serve) |

**Adoption milestones → health signals:**

1. **Activated** — first scan + first report generated. (Healthy: within day 1.)
2. **Integrated** — API key in use from the customer's tooling; monitors created.
3. **Team-adopted** — organization created, multiple members, dashboard in use.
4. **Expanded** — approaching FREE limits (5/day), upgrade prompt surfaced.
5. **Renewed** — sustained weekly/monthly reporting cadence.

**Expansion path (verified mechanics; monetary step needs GA gate 1):** additional
users → additional organizations → additional API keys → tier upgrade (FREE →
STARTER → PRO → ENTERPRISE/MSSP) via `POST /api/subscription/create`.

**Renewal risk signals:** no scans in 30 days; repeated 402s without upgrade
(evaluate pricing fit); support tickets unresolved > SLA. **Renewal drivers:**
weekly executive reports, AI correlation used in real investigations, org
dashboard adopted by the SOC manager.

---

## C. Support Playbook

Common tickets and first-line resolutions, keyed to the actual error responses the
platform returns (all verified in production).

| Ticket | Customer sees | First-line resolution |
|--------|---------------|-----------------------|
| "Cannot log in" | 401 `Invalid email or password` | Confirm email/password; check account not deleted; offer password path |
| "My API call is rejected" | 401 (names required plan) | Key belongs to a plan without `/api/v1` access — the message states the required PRO/ENTERPRISE plan |
| "A feature says payment required" | 402 `ERR_PLAN_REQUIRED` (+ `required_plan`, `upgrade_url`) | Expected gate for simulate/forecast/v1 — direct to the upgrade URL in the response |
| "Scans stopped working" | 429 (+ `retry_after`, upgrade benefits) | Rate/quota boundary; the response states retry timing and the upgrade that lifts it |
| "My scan looks wrong" | grade for a domain | If `scan_status=unmeasurable` (`grade=null`), the domain didn't resolve — this is correct, not a bug |
| "Report says my scan doesn't exist" | (was 422) | Fixed in Phase VIII (cache-hit scan_id) — if seen, escalate with the `scan_id` |
| "Org dashboard errors" | (was 500) | Fixed in Phase IX (BLK-01) — if seen post-deploy, escalate with the `request_id` from the response |
| "Billing question" | — | Order creation works; live billing is in pilot — route to the owner |
| "SSO won't connect" | 400 asks for `?org=` | SSO needs a configured IdP per org — pilot engagement; collect IdP metadata |

**Escalation path:** self-service docs (`/api` self-description, `next_steps`) →
support engineer (this playbook) → engineering (with `request_id`/`scan_id`).
**Known escalation risk:** single-operator coverage (R-10) — no SLA-grade on-call
until a support deputy is in place.

**Troubleshooting principle:** every error response is designed to be
self-explaining (status + reason + next action). A ticket that a customer could
have resolved from the response body is a documentation signal, logged to the
Objection Register.
