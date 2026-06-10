# CYBERDUDEBIVASH AI Security Hub — Deploy Runbook v22.0
**PRODUCTION STABLE FIX — Deploy immediately**

## What changed in v22.0

| # | Fix | Impact |
|---|-----|--------|
| 1 | `apt_groups` JSON parse bug | Defense marketplace shows corrupt arrays |
| 2 | Scan tracking D1 write | `scans_today` counter was always 0 |
| 3 | Missing route aliases | `/api/defense-marketplace`, `/api/gtm/funnel-dashboard` returned 404 |
| 4 | `solution_generated` schema mismatch | `intel_feed.total` always 0 in MYTHOS metrics |
| 5 | Realtime stats D1 query | Used wrong table/column for scan count |
| 6 | Threat level fallback | Used KV sentinel when D1 empty |
| 7 | `version.json` build inject | Now has real commit SHA |
| 8 | Schema migration v22 | Adds 12 missing columns to deployed D1 |

---

## Step 1 — Apply D1 schema migration (REQUIRED FIRST)

```powershell
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers

# Apply production schema migration
npx wrangler d1 execute cyberdudebivash-security-hub `
  --file=./schema_v22_production_fix.sql `
  --remote
```

Expected output: `Successfully applied migration`

---

## Step 2 — Deploy Worker

```powershell
cd C:\Users\Administrator\Desktop\cyberdudebivash-ai-security-hub\workers

npx wrangler deploy
```

Expected: `Deployed cyberdudebivash-security-hub (version 22.0.0)`

---

## Step 3 — Bootstrap D1 data (re-run after schema migration)

```powershell
curl -X POST `
  -H "Authorization: Bearer bootstrap-cyberdude-2026" `
  https://cyberdudebivash.in/api/admin/bootstrap
```

---

## Step 4 — Switch Razorpay to LIVE mode (REVENUE CRITICAL)

**This is currently in TEST mode — NO real payments are processed.**

```powershell
# Set live Razorpay key
npx wrangler secret put RAZORPAY_KEY_ID
# Enter: rzp_live_XXXXXXXX (from Razorpay dashboard)

npx wrangler secret put RAZORPAY_KEY_SECRET
# Enter: your live secret key

npx wrangler secret put RAZORPAY_WEBHOOK_SECRET
# Enter: from Razorpay dashboard → Webhooks → signing secret
```

After setting secrets, redeploy: `npx wrangler deploy`

---

## Step 5 — Smoke test

```powershell
# Health check
curl https://cyberdudebivash.in/api/health

# Scan tracking test
curl -X POST -H "Content-Type: application/json" `
  -d '{"domain":"example.com"}' `
  https://cyberdudebivash.in/api/scan/domain

# Wait 2s then check counters
curl https://cyberdudebivash.in/api/realtime/stats

# Defense marketplace (was 404)
curl https://cyberdudebivash.in/api/defense-marketplace

# MYTHOS intel feed (was 0)
curl https://cyberdudebivash.in/api/mythos/metrics
```

---

## Verification checklist

- [ ] `scans_today` increments after scan
- [ ] `apt_groups` in `/api/defense/solutions` shows clean arrays (no `["APT41"`)
- [ ] `/api/defense-marketplace` returns 200
- [ ] `/api/gtm/funnel-dashboard` returns 200
- [ ] `intel_feed.total > 0` in mythos/metrics
- [ ] Razorpay mode = `live` in `/api/config`
- [ ] `version.json` shows `22.0.0`

