# Support Playbook

> Phase IX deliverable. Diagnostic steps below reflect **verified production
> behavior** (RC program, build `b81bce0`+): every status code and response
> shape cited here was observed on the live platform. Escalation and incident
> handling: `INCIDENT_RESPONSE_RUNBOOK.md`. Recovery:
> `DISASTER_RECOVERY_RUNBOOK.md`.

## Triage fundamentals

- Every error body carries a `request_id` — always collect it; it is the
  correlation key for worker logs.
- Confirm the serving build first: `GET /api/version` (commit) and
  `GET /api/health` (200). Frontend/backend sync: compare with
  `/version.json`.
- The platform's error contract is honest: expected failures return 4xx with
  a reason; any 500 is a defect — file it, don't work around it.

## Ticket taxonomy (verified diagnostics)

### "I can't log in"
Wrong password returns **401** (verified). Check: correct email; account not
deleted (deleted accounts also 401 by design — verified). Password change:
`POST /api/auth/change-password`.

### "I forgot my password"
Self-service since Phase X: "Forgot password?" on the login page →
`POST /api/auth/forgot-password` (always answers generically — never confirms
whether an email has an account) → emailed single-use link (30-min expiry) →
`POST /api/auth/reset-password`. Resetting revokes all previous sessions.
Rate limit: 3 requests/hour per email. If the customer reports no email
arriving, verify `RESEND_API_KEY` is configured in production
(lock: `phase10PasswordReset.test.mjs`).

### "My API key doesn't work"
Invalid key → **401** (verified). FREE keys are valid on the standard `/api`
surface but get **403 on `/api/v1`** (premium) — that is entitlement, not a
defect. Key was auto-issued at signup and shown once; if lost, revoke and
re-issue (FREE limit: 1 key).

### "I'm being rate limited / scans rejected"
Expected shape (verified live): **429** whose **body** always carries
`reason` (`daily_limit_reached` / `burst_exceeded`), `retry_after`, and
`upgrade_url` with per-tier `upgrade_benefits`. `Retry-After` /
`X-RateLimit-*` **headers** appear on the daily-quota path but not on burst
429s — read the body, not the headers (parity is backlog CI-4). FREE =
5/day, 2/min. This is the tier boundary working; guide sizing or upgrade.

### "My API key usage shows zero but I've been scanning"
Per-key usage (`GET /api/keys/{id}/usage`) counts **key-authenticated**
requests only (verified live: a key-authed scan increments `today.total`; a
session-token scan does not). Dashboard/session activity appears in
`GET /api/history` instead. Both views are correct — they answer different
questions.

### "My report says the scan doesn't exist" (422)
Historic S1 (Phase VIII, fixed): body `scan_id` must equal the `X-Scan-ID`
header. If a 422 recurs with matching ids inside the retention window
(FREE: 7 days), treat as regression — escalate with `request_id`
(lock: `phase8CachedScanReportId.test.mjs`).

### "The org dashboard is broken"
Historic RC-B1 (Phase IX, fixed): dashboard/org-scans 500. Now 200 with
per-panel degradation (a failing aggregate empties that panel, never 500s).
Any recurrence → escalate as critical with `request_id`
(lock: `phase9OrgDashboardSchema.test.mjs`).

### "The scan gave no grade"
Correct honesty behavior (verified): unmeasurable targets return
`grade: null`, `risk: UNKNOWN`. Explain rather than "fix" — the platform
does not fabricate verdicts. Same for AI: unknown CVEs are refused, not
invented.

### "SSO isn't working"
Endpoints: `/api/auth/sso/login` (needs org slug), `/api/auth/sso/callback`,
`/api/auth/enterprise/sso` (setup guidance). Verify the org slug and IdP
config first. Note: no live-IdP deployment exists yet — first SSO customer
is a pilot; involve engineering.

### "Billing question"
Pricing truth: `GET /api/subscription/plans` (derived from enforcement —
cannot drift). No live payment has ever been processed; the first real
transaction must be shepherded end-to-end and its evidence recorded.

### "Delete my account / my data"
`DELETE /api/auth/delete-account` → 200 with per-category erasure receipt;
credentials die immediately (verified). GDPR/DPDP language in
`DATA_PROCESSING_AGREEMENT_TEMPLATE.md`.

## Escalation

| Severity | Example | Path |
|----------|---------|------|
| SEV-1 | 5xx on a customer-critical surface, data exposure suspicion | `INCIDENT_RESPONSE_RUNBOOK.md` immediately; rollback via `DEPLOY_RECOVERY_RUNBOOK.md` |
| SEV-2 | Feature broken with workaround | File defect with `request_id` + repro; regression-lock required with the fix |
| SEV-3 | Docs/clarity/how-to | Answer + record in `CUSTOMER_OBJECTION_REGISTER.md` if the confusion is product-caused |

**Known organizational limit (disclosed):** support is single-operator today
(risk R-3/R-10). A deputy + coverage calendar is an owner-level GA gate.
