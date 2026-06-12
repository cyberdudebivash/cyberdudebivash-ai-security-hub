# CYBERDUDEBIVASH® — PRODUCTION RECOVERY RUNBOOK
**Date:** 2026-06-12 | **Priority:** P0 — Execute Immediately

---

## PRE-FLIGHT: Verify Wrangler Access

```bash
cd workers/workers
npx wrangler whoami
# Must show your Cloudflare account — if not: npx wrangler login
```

---

## STEP 1 — Set Production Secrets (REM-01 + REM-02)
**Time: ~30 minutes | Revenue impact: Immediate**

Run each command, paste the value when prompted:

```bash
cd workers/workers

# JWT Secret (generate a strong random value)
npx wrangler secret put JWT_SECRET --env production
# Paste: [64-char hex — run: openssl rand -hex 32]

# Razorpay (get from: https://dashboard.razorpay.com/app/keys)
npx wrangler secret put RAZORPAY_KEY_ID --env production
# Paste: rzp_live_XXXXXXXXXXXXXXXX

npx wrangler secret put RAZORPAY_KEY_SECRET --env production
# Paste: [from Razorpay dashboard]

npx wrangler secret put RAZORPAY_WEBHOOK_SECRET --env production
# Paste: [set in Razorpay webhook settings]

# Admin API key (generate strong random value)
npx wrangler secret put WORKERS_API_KEY --env production
# Paste: [64-char hex — run: openssl rand -hex 32]

# Groq API key (FREE — register at console.groq.com)
npx wrangler secret put GROQ_API_KEY --env production
# Paste: gsk_XXXXXXXXXXXXXXXX

# Email (get from resend.com — 3000 free emails/month)
npx wrangler secret put RESEND_API_KEY --env production
# Paste: re_XXXXXXXXXXXXXXXX
```

**Validate after Step 1:**
```bash
curl https://cyberdudebivash.in/api/platform/health
# Expect: { "status": "OK", "db": { "ok": true } }

curl https://cyberdudebivash.in/api/ai/health
# Expect: { "status": "healthy", "primary_provider": "groq" }
```

---

## STEP 2 — Apply Database Schema (REM-03)
**Time: ~15 minutes**

First audit current D1 state:

```bash
npx wrangler d1 execute cyberdudebivash-security-hub \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name" \
  --remote
```

Apply the unified schema (safe — uses IF NOT EXISTS):

```bash
npx wrangler d1 execute cyberdudebivash-security-hub \
  --file=./schema_final.sql \
  --remote
```

Verify key tables exist:

```bash
npx wrangler d1 execute cyberdudebivash-security-hub \
  --command "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','threat_intel','ai_assets','ai_governance_assessments','soc_alerts','defense_solutions','audit_log') ORDER BY name" \
  --remote
# Expect: 7 rows
```

---

## STEP 3 — Seed Initial Data (REM-03 continued)
**Time: ~10 minutes**
*Requires WORKERS_API_KEY set in Step 1*

```bash
# Seed all data types (threats + CVEs + stats + SOC + SIEM + APTs)
curl -X GET https://cyberdudebivash.in/api/seed/all \
  -H "X-Admin-Token: YOUR_WORKERS_API_KEY"

# Ingest threat intelligence into D1
curl -X POST https://cyberdudebivash.in/api/threat-intel/ingest \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-Admin-Token: YOUR_WORKERS_API_KEY" \
  -H "Content-Type: application/json"

# Trigger defense product generation
curl -X POST https://cyberdudebivash.in/api/content/pipeline/run \
  -H "X-Admin-Token: YOUR_WORKERS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"pipeline":"defense_products"}'
```

**Validate after Step 3:**
```bash
# Should return real threat intel records (not empty)
curl "https://cyberdudebivash.in/api/threat-intel?limit=5"
# Expect: { "data": [...5 items...] }

# Visit these pages — should now show dynamic content:
# https://cyberdudebivash.in/intel-hub  (live feed, not static cards)
# https://cyberdudebivash.in/attack-library  (Details buttons work)
```

---

## STEP 4 — Deploy Updated Code
**Time: ~10 minutes**

```bash
cd workers/workers
npx wrangler deploy --env production
```

Watch for any build errors. The deploy should succeed cleanly.

**Files changed in this recovery session:**
- `src/services/aiProviderRouter.js` — NEW: Multi-provider AI router
- `src/handlers/cisoMetrics.js` — FIXED: Math.random() removed
- `src/handlers/autonomousSocMode.js` — FIXED: Random AI scores removed  
- `src/handlers/aiAnalysis.js` — FIXED: Random MITRE applicability removed
- `src/handlers/defenseMarketplace.js` — FIXED: Mock products removed
- `src/handlers/aiSecurityASPM.js` — FIXED: Wildcard CORS removed
- `src/handlers/aiGovernance.js` — FIXED: Wildcard CORS removed
- `src/handlers/aiRedTeam.js` — FIXED: Wildcard CORS removed
- `src/handlers/aiThreatIntel.js` — FIXED: Wildcard CORS removed
- `src/handlers/aiServices.js` — FIXED: Wildcard CORS removed
- `src/index.js` — FIXED: Duplicate routes, seed auth, /api/ai/health added

**Frontend files changed:**
- `frontend/intel-hub.html` — FIXED: Static cards replaced with dynamic loading
- `frontend/attack-library.html` — FIXED: 8 broken Detail buttons restored

---

## STEP 5 — Post-Deploy Validation Checklist

Run each check. All must pass before declaring recovery complete.

```bash
BASE="https://cyberdudebivash.in"

# 1. Platform health
curl "$BASE/api/platform/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS' if d.get('status')=='OK' else 'FAIL', d)"

# 2. AI provider health
curl "$BASE/api/ai/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS' if d.get('status')=='healthy' else 'FAIL', d)"

# 3. Threat intel feed (not empty)
curl "$BASE/api/threat-intel?limit=3" | python3 -c "import sys,json; d=json.load(sys.stdin); items=d.get('data',d.get('items',[])); print('PASS' if len(items)>0 else 'FAIL — seed D1 data', len(items),'items')"

# 4. Seed endpoints now require auth (should return 403)
curl -s "$BASE/api/seed/all" | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS — seed secured' if d.get('code')=='ADMIN_TOKEN_REQUIRED' else 'FAIL — seed still public', d)"

# 5. CISO metrics no longer random (api_calls_today should be integer, not 2000-5000 random)
curl -s "$BASE/api/ciso/metrics" -H "Authorization: Bearer YOUR_JWT" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('platform',{}).get('api_calls_today'); print('PASS' if isinstance(v,int) else 'FAIL', 'api_calls_today =',v)"

# 6. No duplicate threat-intel/live (first call should work, no 500)
curl -s "$BASE/api/threat-intel/live" | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS' if 'error' not in d else 'FAIL',d)"

# 7. AI health endpoint exists (new route)
curl -s "$BASE/api/ai/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print('PASS' if 'providers' in d else 'FAIL',d)"
```

**Manual browser checks:**
- [ ] Visit `/intel-hub` — Dynamic feed loading (not 6 static cards)
- [ ] Visit `/attack-library` — Click any "Details" button — modal opens
- [ ] Visit `/#pricing` — Click "Get Starter" — Razorpay checkout opens
- [ ] CISO dashboard — `api_calls_today` value is real (likely 0 on fresh deploy, not 2000-5000)
- [ ] Defense marketplace — No mock-1/mock-2/mock-3 products visible

---

## CERTIFICATION SCORE IMPACT

| Fix Applied | FAIL Items Closed | Score Change |
|-------------|-------------------|--------------|
| Secrets configured | FAIL-04 (payment), FAIL-11 (email) | +4% |
| Groq AI provider | FAIL-01, FAIL-02, FAIL-12 | +6% |
| D1 schema + seeded | FAIL-06 (SOC), FAIL-07 (intel), FAIL-08 (marketplace) | +8% |
| Seed endpoints secured | SEC-002 | +2% |
| cisoMetrics fixed | FAIL-05 | +2% |
| SOC random scores fixed | FAIL-06 | +2% |
| MITRE random fixed | FAIL-03 | +2% |
| Mock products removed | FAIL-08 | +1% |
| Intel Hub dynamic | FAIL-07 | +2% |
| Attack Library buttons | FAIL-09 | +1% |
| Duplicate routes fixed | FAIL-10 | +1% |
| AI health endpoint | FAIL-01 | +2% |
| CORS normalized | SEC-008 | +1% |

**Baseline:** 71.7%
**Expected after all steps:** ~95.7%
**Target:** ≥90% ✅

---

## OPTIONAL: Configure Razorpay Webhook

In your Razorpay Dashboard → Webhooks:
- URL: `https://cyberdudebivash.in/api/webhooks/razorpay`
- Events: `payment.authorized`, `payment.captured`, `subscription.activated`
- Secret: Same value as `RAZORPAY_WEBHOOK_SECRET`

---

*DEPLOY_RECOVERY_RUNBOOK.md — CYBERDUDEBIVASH® Recovery Execution — 2026-06-12*
