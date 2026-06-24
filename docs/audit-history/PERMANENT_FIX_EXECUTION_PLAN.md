# PERMANENT FIX EXECUTION PLAN
## CYBERDUDEBIVASH AI SECURITY HUB™
**Date:** 2026-06-11  
**Priority:** Certification recovery to ≥90%  
**Method:** Evidence-based remediation — each fix validated against live API

---

## EXECUTION RULES
1. Fix ONE gap at a time. Test immediately after. Confirm PASS before moving to next.
2. No new features until all P0 and P1 fixes are CONFIRMED PASS.
3. Each fix must include a validation command to confirm resolution.
4. Deploy after every P0 fix — do not batch P0 fixes.

---

## PHASE 1 — P0 CRITICAL FIXES (Target: +8% certification)

### FIX-001: Stop CVE Hallucination (2 hours)

**File:** `workers/src/handlers/intelHandler.js` (or equivalent CVE handler)  
**Change:** When `found_in_db: false`, do NOT call AI enrichment. Return structured "not found" with NVD link.

**Implementation:**
```javascript
// In CVE lookup handler, after D1 query returns no results:
if (!cveRecord) {
  return Response.json({
    success: true,
    cve_id: cveId,
    found_in_db: false,
    cvss_score: null,
    description: null,
    ai_enrichment: null,
    note: `CVE not in local database. Reference: https://nvd.nist.gov/vuln/detail/${cveId}`,
    recommendation: 'Ingest this CVE via POST /api/threat-intel/ingest (PRO+)'
  });
}
// ONLY run AI enrichment when found_in_db: true
```

**Alternative (better, ~4 hours):** Add NVD API call for cache miss:
```javascript
const nvdRes = await fetch(
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
  { headers: { 'apiKey': env.NVD_API_KEY || '' } }
);
if (nvdRes.ok) {
  const nvd = await nvdRes.json();
  const vuln = nvd.vulnerabilities?.[0]?.cve;
  // Map to response format
}
```

**Validation:**
```bash
curl "$BASE/api/intel/cve?id=CVE-2024-3094" -H "x-api-key: $KEY"
# Must return found_in_db: false WITH NO AI ENRICHMENT
# OR accurate XZ Utils description if NVD integration implemented
```

---

### FIX-002: Fix Scan Counter Tracking (2 hours)

**File:** `workers/src/handlers/` — domain scanner, redteam scanner, AI scanner handlers  
**Investigation first:** Find which file handles `POST /api/scan/domain`.

```bash
grep -r "scan/domain\|scan/redteam\|scan/ai" workers/src/index.js | head -20
```

**Change:** Ensure `trackScan()` is called at handler completion with correct parameters.

```javascript
// At end of each scan handler (domain, redteam, ai):
try {
  await trackScan(env, {
    module: 'domain_scanner',  // or 'redteam', 'ai_scanner'
    target,
    risk_score: result.risk_score || 0,
    findings_count: (result.findings || []).length,
    user_id: authResult?.userId || null,
    tier: authResult?.tier || 'FREE',
  });
} catch (e) {
  console.error('[scan-track] failed:', e.message);
  // Non-fatal — do not break scan response
}
```

Also confirm `trackScan()` writes to KV key: `scan_count:total:${day}` where `day = new Date().toISOString().slice(0,10)`.

**Validation:**
```bash
curl -X POST "$BASE/api/scan/domain" -H "x-api-key: $KEY" -d '{"target":"example.com"}'
sleep 2
curl "$BASE/api/realtime/stats"
# total_scans_today must be > 0
```

---

### FIX-003: Fix Scan History Persistence (3 hours)

**File:** Domain/redteam/AI scan handlers  
**Change:** INSERT scan result to D1 `scan_history` table after each scan.

```javascript
// After scan completes, persist to D1:
if (env?.DB) {
  try {
    await env.DB.prepare(`
      INSERT INTO scan_history 
        (id, user_id, target, module, risk_score, findings_count, grade, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      crypto.randomUUID(),
      authResult?.userId || null,
      target,
      'domain_scanner',
      result.risk_score || 0,
      (result.findings || []).length,
      result.grade || null
    ).run();
  } catch (e) {
    console.error('[scan-history] persist failed:', e.message);
  }
}
```

Also add `scan_id` to `scan_metadata`:
```javascript
result.scan_metadata = {
  ...result.scan_metadata,
  scan_id: crypto.randomUUID(),
  tracked: true,
  persisted_at: new Date().toISOString(),
};
```

**Validation:**
```bash
curl -X POST "$BASE/api/scan/domain" -H "x-api-key: $KEY" -d '{"target":"example.com"}'
curl "$BASE/api/history" -H "x-api-key: $KEY"
# scans array must contain the scan just performed
```

---

## PHASE 2 — P1 REVENUE FIXES (Target: +12% certification)

### FIX-004: Register AISPM Handler (4 hours)

The existing AI scanner at `/api/scan/ai` can be the base. Register an alias with AISPM-specific framing.

**In `workers/src/index.js`:**
```javascript
if (path === '/api/aispm/scan' && method === 'POST') {
  // Route to AI scanner handler with AISPM mode flag
  return handleAIScan(request, env, { mode: 'aispm' });
}
```

Ensure the handler returns an AISPM-specific response structure:
```json
{
  "success": true,
  "models_scanned": 1,
  "total_findings": 9,
  "owasp_llm_coverage": {...},
  "powered_by_mythos": true
}
```

---

### FIX-005: Register ASM Handler (6 hours)

**In `workers/src/index.js`:**
```javascript
if (path === '/api/asm/scan' && method === 'POST') {
  return handleASMScan(request, env);
}
```

Minimal ASM implementation using existing domain scanner as core:
```javascript
async function handleASMScan(request, env) {
  const { domain, tier } = await request.json();
  // Run domain scan as core
  const domainResult = await runDomainScan(domain, env);
  // Generate subdomains list (pattern-based or via DNS enumeration)
  const subdomains = generateSubdomainSurface(domain);
  return Response.json({
    success: true,
    domain,
    total_assets: subdomains.length + 1,
    assets: subdomains,
    primary_domain: domainResult,
    powered_by_mythos: true,
  });
}
```

---

### FIX-006: Register Executive Reports Handler (4 hours)

**In `workers/src/index.js`:**
```javascript
if (path === '/api/reports/executive' && method === 'POST') {
  return handleExecutiveReport(request, env);
}
```

Implementation: Query `scan_history` D1 for recent scans of requested target, aggregate findings, call `routeAICall()` for executive narrative.

---

### FIX-007: Register IOC Enrichment Handler (3 hours)

**In `workers/src/index.js`:**
```javascript
if (path.startsWith('/api/intel/ioc') && method === 'POST') {
  return handleIOCEnrich(request, env);
}
```

Minimal implementation: check D1 IOC table, return classification + threat score. For IPs, can use basic abuse score heuristics.

---

### FIX-008: Fix Threat Actor by Sector (2 hours)

**In `workers/src/index.js`:**
```javascript
if (path === '/api/intel/threat-actors' && method === 'GET') {
  const sector = url.searchParams.get('sector') || '';
  const rows = await env.DB.prepare(
    `SELECT * FROM threat_intel WHERE type='threat_actor' AND active=1 
     AND (target_sectors LIKE ? OR target_sectors IS NULL) LIMIT 10`
  ).bind(`%${sector}%`).all();
  return Response.json({ success: true, sector, threat_actors: rows.results || [] });
}
```

---

### FIX-009: Fix Compliance Scan (2 hours)

Diagnose why `POST /api/generate/compliance` returns error. Likely an auth middleware rejection.

```bash
grep -n "generate/compliance\|generateCompliance" workers/src/index.js
```

Ensure the route is registered AND the handler correctly handles both `x-api-key` and `Authorization: Bearer` auth.

---

## PHASE 3 — P2 QUALITY FIXES (Target: +5% certification)

### FIX-010: Apply MYTHOS Enrichment to All Scan Types (3 hours)

**Files:** Domain scanner handler, redteam scanner handler, AI scanner handler  
**Change:** Add `enrichAssessmentWithMYTHOS()` call before returning response.

```javascript
import { enrichAssessmentWithMYTHOS } from '../services/mythosEnrichmentEngine.js';

// At end of each scan handler:
const enriched = await enrichAssessmentWithMYTHOS(env, {
  report: result,
  findings: result.findings || [],
  service_name: 'Domain Security Scanner',
  service_ref: 'CDB-DOM-001',
  target,
  sector: body.sector || 'Technology',
  tier: authResult?.tier || 'FREE',
});
return Response.json(enriched);
```

---

### FIX-011: Make Threat Actor Overlay Contextual (2 hours)

**File:** `workers/src/handlers/domainScanHandler.js` (or equivalent)  
**Change:** Remove hardcoded threat actor list from `enterprise_intelligence` block. Query D1 or remove entirely.

---

### FIX-012: Fix Risk Score Consistency in AI Analyze (1 hour)

**File:** AI analyze handler  
**Change:** Use the provided `scan_result.risk_score` as the base, not override it.

---

### FIX-013: Fix Realtime Stats to Use Real Counts (2 hours)

**File:** Realtime stats handler  
**Change:**
```javascript
// Replace hardcoded values with D1 queries:
const scanCount = await env.DB.prepare(
  `SELECT COUNT(*) as count FROM scan_history WHERE date(created_at) = date('now')`
).first();
const cveCount = await env.DB.prepare(
  `SELECT COUNT(*) as count FROM threat_intel WHERE type='cve'`
).first();

return Response.json({
  total_scans_today: scanCount?.count || 0,
  active_threats: cveCount?.count || 0,
  // ...
});
```

---

### FIX-014: Fix Signup Name Persistence (30 min)

**File:** Auth signup handler  
**Change:** One-line fix in user INSERT:
```javascript
// Before: INSERT ignores name field
// After: 
await env.DB.prepare(
  `INSERT INTO users (id, email, full_name, tier, created_at) VALUES (?, ?, ?, 'FREE', datetime('now'))`
).bind(userId, email, body.name || body.full_name || null).run();
```

---

## DEPLOYMENT SEQUENCE

```
FIX-014 (30min) → deploy → validate
FIX-001 (2hr)   → deploy → validate CVE accuracy
FIX-002 (2hr)   → deploy → validate scan counter
FIX-003 (3hr)   → deploy → validate scan history
FIX-009 (2hr)   → deploy → validate compliance
FIX-010 (3hr)   → deploy → validate MYTHOS coverage
FIX-012 (1hr)   → deploy → validate risk score
FIX-013 (2hr)   → deploy → validate stats
FIX-011 (2hr)   → deploy → validate threat actors
FIX-004 (4hr)   → deploy → validate AISPM
FIX-007 (3hr)   → deploy → validate IOC
FIX-008 (2hr)   → deploy → validate threat actors endpoint
FIX-006 (4hr)   → deploy → validate executive reports
FIX-005 (6hr)   → deploy → validate ASM
```

---

## VALIDATION MASTER SCRIPT

After all fixes are deployed, run this full validation:

```bash
BASE="https://cyberdudebivash-security-hub.iambivash-bn.workers.dev"
KEY="REDACTED_ROTATED_KEY"

# P0 validations
echo "=== CVE ACCURACY ===" 
curl -s "$BASE/api/intel/cve?id=CVE-2024-3094" -H "x-api-key: $KEY" | python3 -c "
import sys,json; d=json.load(sys.stdin)
ai=d.get('ai_enrichment','')
print('PASS' if 'xz' in ai.lower() or not ai else 'FAIL — still hallucinating')
"

echo "=== SCAN COUNTER ==="
curl -s -X POST "$BASE/api/scan/domain" -H "x-api-key: $KEY" -d '{"target":"example.com"}' > /dev/null
sleep 1
curl -s "$BASE/api/realtime/stats" | python3 -c "
import sys,json; d=json.load(sys.stdin)
count=d.get('total_scans_today',0)
print('PASS' if count > 0 else 'FAIL — still zero')
"

echo "=== SCAN HISTORY ==="
curl -s "$BASE/api/history" -H "x-api-key: $KEY" | python3 -c "
import sys,json; d=json.load(sys.stdin)
scans=d.get('scans',[])
print('PASS' if len(scans) > 0 else 'FAIL — empty')
"

echo "=== AISPM ==="
curl -s -X POST "$BASE/api/aispm/scan" -H "x-api-key: $KEY" \
  -d '{"models":[{"id":"gpt-4","vendor":"openai"}]}' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('PASS' if d.get('success') else 'FAIL')
"

echo "=== MYTHOS ENRICHMENT ==="
curl -s -X POST "$BASE/api/scan/domain" -H "x-api-key: $KEY" \
  -d '{"target":"example.com"}' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('PASS' if d.get('powered_by_mythos') else 'FAIL — missing')
"
```

---

*Permanent Fix Execution Plan v1.0 | CYBERDUDEBIVASH AI Security Hub | 2026-06-11*
