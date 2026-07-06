# Implementation Playbook — Enterprise Onboarding

> Phase IX deliverable. Every step below was executed against live production
> (`https://cyberdudebivash.in`) as a customer during the RC program; steps
> that require third-party evidence are marked **[owner evidence pending]**.
> Canonical operations docs: `PRODUCTION_OPERATIONS_MANUAL.md`; deploy:
> `DEPLOY.md`.

## 1. Standard SaaS onboarding (verified path)

| Step | Action | Verified behavior |
|------|--------|-------------------|
| 1 | `POST /api/auth/signup` (email, password, full_name) | 201; returns session token **and** an auto-issued API key (`api_key` + `api_key_note` + `next_steps`) — save the key now, it is shown once |
| 2 | Review plan + entitlements: `GET /api/user/plan` | Advertised features equal enforcement (regression-locked) |
| 3 | First scan — dashboard UI (handles the anti-abuse handshake automatically), or programmatically: with your API key `POST /api/scan/domain` + `x-api-key` header (**exempt** from the scan token); with a session JWT you must first `POST /api/scan/token` and send the result as `X-Scan-Token` (single-use, 5-min TTL, IP-bound) | Result includes `scan_id` == `X-Scan-ID` header; unmeasurable targets return `grade: null`, `risk: UNKNOWN` — the platform does not fabricate |
| 4 | First report: `POST /api/report/generate` with that `scan_id` | 201 + download URL; works for cached (repeat) domains too |
| 5 | AI insight: `POST /api/ai/analyze` | Available on FREE; `simulate`/`forecast` require PRO (402 names the plan) |
| 6 | Create the organization: `POST /api/orgs` | 201 with org id, slug, plan limits |
| 7 | Invite team: `POST /api/orgs/{id}/members` | OWNER/ADMIN only; roles: ADMIN, ANALYST, MEMBER, VIEWER |
| 8 | Org posture: `GET /api/orgs/{id}/dashboard`, `GET /api/orgs/{id}/scans` | 200 with per-org aggregates (RC-B1 fixed + locked this phase) |

Time budget: the whole sequence completes in seconds (Phase VIII: TTFV p50
406 ms across 100 organizations).

## 2. Tier planning

Limits are enforced from a single source of truth (`TIER_LIMITS`) and the
docs derive from it. FREE: 5 scans/day, 2/min burst, 1 API key, 7-day report
retention, no `/api/v1` premium surface. Size production SOC workloads on
paid tiers; FREE throttling is an intended boundary with graceful 429s
(reason, `retry_after`, upgrade path).

## 3. Enterprise SSO (OIDC)

Endpoints verified responding in production: `/api/auth/sso/login` (expects
org slug), `/api/auth/sso/callback`, `/api/auth/enterprise/sso` (setup
guidance). Configure per the enterprise/sso guidance, then run one live IdP
round-trip before cutover. **[owner evidence pending — no live-IdP round-trip
has been executed yet]**

## 4. Integrations

Integration is API/webhook-level (REST + API keys + webhooks + SIEM export
endpoints). There are no packaged vendor connectors; plan custom effort for
SIEM/SOAR/ticketing wiring and validate in the customer's environment.
Enterprise proxies/Zero-Trust egress must allow `https://cyberdudebivash.in`.

## 5. Self-hosted / staging / DR environments

Bootstrap an empty D1 database with `workers/schema_bootstrap.sql` (verified:
228 tables, 0 errors from empty). Required secrets and failure modes are in
`DEPLOY.md`. Post-deploy, confirm `GET /api/version` commit matches what you
deployed and `GET /api/health` is 200 — the same signals the pipeline's smoke
test uses.

## 6. Production cutover checklist

- [ ] Signup → scan → report → AI verified by the customer's own admin
- [ ] Org created; members invited with least-privilege roles
- [ ] Org dashboard + org scan history load (RC-B1 journey)
- [ ] Quota plan matches expected scan volume (429 behavior reviewed)
- [ ] Offboarding tested: account deletion returns erasure receipt
- [ ] Escalation contacts exchanged (see `SUPPORT_PLAYBOOK.md`)
