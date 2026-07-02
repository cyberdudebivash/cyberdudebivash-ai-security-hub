# CYBERDUDEBIVASH® — Incident Response Runbook
**Version:** 1.0 | **Effective:** 2026-07-01 | **Owner:** bivash@cyberdudebivash.com

---

## Severity Classification

| Level | Definition | Response SLA | Example |
|---|---|---|---|
| **SEV-1 (Critical)** | Platform fully unavailable OR active security breach OR payment data at risk | Acknowledge ≤15 min, resolution ≤4 h | Worker returning 500 to all requests; unauthorized access to production D1; Razorpay webhook HMAC bypass |
| **SEV-2 (Major)** | Core feature unavailable; significant data integrity issue; authentication broken | Acknowledge ≤30 min, resolution ≤8 h | All logins failing; scan results not persisting; MFA bypassed |
| **SEV-3 (Minor)** | Degraded performance, single-feature outage, non-critical bug in production | Acknowledge ≤2 h, resolution ≤48 h | A single endpoint returning wrong data; UI rendering error |
| **SEV-4 (Low)** | Cosmetic issues, documentation errors, non-urgent hygiene | Next business day | Broken link, wrong placeholder text |

---

## Detection Sources

1. **Telegram admin alert channel** — `logSystemError()` fires for payment, refund, and ticket failures. Check the Telegram bot linked in `ADMIN_TELEGRAM_BOT_TOKEN`.
2. **`/api/platform/health`** — structured JSON with DB/KV/R2/intel latency. Any field returning `degraded` or `error` is an anomaly.
3. **Cloudflare Dashboard → Workers → Analytics** — error rate spike, CPU time spike, invocation failures.
4. **Cloudflare Dashboard → D1 → Metrics** — query latency, error rate.
5. **Customer contact** — `support@cyberdudebivash.in` or in-app support ticket.
6. **`GET /api/support/errors`** (admin-only) — last 100 `system_errors` entries from D1.

---

## Runbook

### SEV-1: Platform Down (all routes 500)

```
1. Check Cloudflare Status: https://www.cloudflarestatus.com
   → If CF incident: wait + communicate ETA from CF.

2. Check Worker logs: Cloudflare Dashboard → Workers → Logs → Last 30 min
   → Look for uncaught exception, runtime panic, env binding missing.

3. If last deploy is the cause:
   cd workers/
   npx wrangler rollback   # reverts to previous deployed version
   → Verify with: curl https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/platform/health

4. If D1 is the cause (DB queries failing):
   → Cloudflare Dashboard → D1 → SECURITY_HUB_DB → check status
   → If migration failure: restore per DISASTER_RECOVERY_RUNBOOK.md —
     D1 Time Travel for point-in-time, or the latest "Nightly D1 Backup"
     artifact from GitHub Actions for full restore

5. Communicate on status page (if configured) within 15 min of acknowledgment.
```

### SEV-1: Security Breach (unauthorized access / data exfiltration suspected)

```
1. IMMEDIATELY rotate all Wrangler secrets:
   cd workers/
   echo "<new-value>" | npx wrangler secret put ADMIN_TOKEN
   echo "<new-value>" | npx wrangler secret put JWT_SECRET
   echo "<new-value>" | npx wrangler secret put RAZORPAY_KEY_SECRET
   # (full list: see wrangler.toml [vars] section for names)
   → This forces a redeploy with new credentials, invalidating all active JWTs.

2. Revoke all refresh tokens in D1:
   npx wrangler d1 execute SECURITY_HUB_DB --remote \
     --command "UPDATE refresh_tokens SET revoked = 1 WHERE revoked = 0"
   → All users are forced to re-authenticate.

3. Review audit log in KV:
   → Cloudflare Dashboard → KV → SECURITY_HUB_KV → search "audit:"

4. Review system_errors for unusual patterns:
   curl -H "Authorization: Bearer <admin-token>" \
     https://cyberdudebivash-security-hub.iambivash-bn.workers.dev/api/support/errors

5. Preserve evidence: export D1 snapshot before any cleanup.

6. Notify affected users via email if PII exposure is confirmed.
   → Under DPDP Act 2023, notify the Data Protection Board of India if breach
     affects personal data of Indian residents.
```

### SEV-2: Authentication Broken

```
1. Verify JWT_SECRET is set:
   cd workers/
   npx wrangler secret list   # should show JWT_SECRET without its value

2. Check refresh_tokens table is accessible:
   npx wrangler d1 execute SECURITY_HUB_DB --remote \
     --command "SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0"

3. Check KV rate-limit keys (brute-force lock may have mis-fired):
   Cloudflare Dashboard → KV → SECURITY_HUB_KV → filter "login_attempts:"

4. If MFA KV keys are stuck blocking users:
   npx wrangler d1 execute SECURITY_HUB_DB --remote \
     --command "UPDATE mfa_secrets SET enabled = 0 WHERE user_id = '<affected_user_id>'"
   → Only as last resort; notify user to re-enroll MFA.
```

### SEV-2: Payment Processing Broken

```
1. Verify Razorpay credentials:
   cd workers/
   npx wrangler secret list   # confirm RAZORPAY_KEY_ID + RAZORPAY_KEY_SECRET

2. Test Razorpay API directly:
   curl -u <KEY_ID>:<KEY_SECRET> https://api.razorpay.com/v1/orders \
     -d '{"amount":99900,"currency":"INR","receipt":"test-001"}'
   → If this fails, the issue is Razorpay-side, not our code.

3. Check orders table:
   npx wrangler d1 execute SECURITY_HUB_DB --remote \
     --command "SELECT * FROM orders ORDER BY created_at DESC LIMIT 10"

4. Check for R2 fulfillment failures in system_errors:
   GET /api/support/errors (admin auth)
   → Filter for area = 'payments.r2_store'
```

### SEV-3: Single Endpoint Returning Wrong Data

```
1. Check git log for recent changes to the relevant handler:
   git log --oneline workers/src/handlers/<handler>.js

2. Reproduce locally:
   cd workers/
   npx wrangler dev --local

3. If data issue: run targeted D1 query to verify source data.
4. Fix → test locally → push to main → CI deploys.
```

---

## Communication Templates

### Customer-facing (status page / email)
```
Subject: [Service Update] CYBERDUDEBIVASH Security Hub — <brief description>

We are currently investigating an issue affecting <feature>.
Impact: <what users cannot do>
Status: <Investigating | Identified | Mitigating | Resolved>
Next update: <time>
```

### Resolution notice
```
Subject: [Resolved] CYBERDUDEBIVASH Security Hub — <brief description>

The issue has been resolved as of <time UTC+5:30>.
Root cause: <1-2 sentences>
Duration: <X hours Y minutes>
Actions taken: <brief list>
Prevention: <what we're changing>
```

---

## Post-Incident Review (required for all SEV-1 and SEV-2)

Complete within 48 hours of resolution:

1. **Timeline** — minute-by-minute from detection to resolution.
2. **Root cause** — what broke and why.
3. **Impact** — how many users affected, for how long, any data at risk.
4. **Detection gap** — why didn't we catch it before users did?
5. **Prevention** — concrete code or infrastructure change to prevent recurrence.
6. **Action items** — owner + deadline for each.

Store in `docs/post-incident/YYYY-MM-DD-<slug>.md` (create the dir on first use).

---

## Key Contacts & Links

| Resource | Value |
|---|---|
| Cloudflare Dashboard | https://dash.cloudflare.com |
| Cloudflare Status | https://www.cloudflarestatus.com |
| Razorpay Dashboard | https://dashboard.razorpay.com |
| Production Worker URL | https://cyberdudebivash-security-hub.iambivash-bn.workers.dev |
| Health endpoint | `/api/platform/health` |
| Admin support errors | `/api/support/errors` (admin JWT) |
| Primary operator | bivash@cyberdudebivash.com |
| Support inbox | support@cyberdudebivash.in |
| Enterprise contact | enterprise@cyberdudebivash.in |

> **Single-operator note:** This runbook assumes a single operator. Until a secondary on-call is established, all SEV-1 response depends on the primary operator being reachable. This is a known gap documented in `FORTUNE500_SECURITY_TRUST_OVERVIEW.md`.
