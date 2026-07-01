/**
 * CYBERDUDEBIVASH AI Security Hub — Identity Security Scanner v41.0
 * POST /api/identity   — Zero Trust identity posture assessment
 *
 * v41.0 changes:
 *  - Correct D1 schema: identity NOT NULL, no updated_at column
 *  - Synchronous D1 tracking (pre-build response, then await DB writes)
 *  - MYTHOS enrichment inline on every scan
 *  - KV scan counter (same key pattern as all other handlers)
 *  - scan_history row for authenticated users
 */

import { identityScanEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { sanitizeString } from '../middleware/security.js';
import { enrichAssessmentWithMYTHOS } from '../services/mythosEnrichmentEngine.js';
import { cacheScanResultForReport } from '../lib/scanResultCache.js';

const VALID_IDPS = ['azure-ad','okta','google-workspace','auth0','onelogin','ping','keycloak','jumpcloud','duo','other'];
function genScanId() { return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8); }

// ─── KV scan counter ──────────────────────────────────────────────────────────
async function incrementScanCounter(env) {
  try {
    const kv = env.SECURITY_HUB_KV;
    if (!kv) return;
    const day = new Date().toISOString().slice(0, 10);
    const key = `scan_count:total:${day}`;
    const cur = parseInt((await kv.get(key).catch(() => '0')) || '0', 10);
    await kv.put(key, String(cur + 1), { expirationTtl: 90 * 86400 }).catch(() => {});
  } catch {}
}

export async function handleIdentityScan(request, env, authCtx = {}) {
  const body   = await parseBody(request);
  const orgVal = validateString(
    sanitizeString(body?.org_name || body?.org || body?.organization || body?.domain || body?.target || ''),
    'org_name', 2, 120
  );
  if (!orgVal.valid) return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });

  const idpVal = validateEnum(body?.identity_provider || body?.idp || 'other', 'identity_provider', VALID_IDPS, 'other');
  const scanId = genScanId();
  let result   = identityScanEngine(orgVal.value, idpVal.value);

  // v41.0: MYTHOS enrichment on all identity scans
  try {
    result = await enrichAssessmentWithMYTHOS(env, {
      report:       result,
      findings:     result.findings || [],
      service_name: 'Identity & Zero Trust Assessment',
      service_ref:  'CDB-IDN-001',
      target:       orgVal.value,
      sector:       authCtx?.sector || 'Technology',
      tier:         authCtx?.tier   || 'FREE',
    });
  } catch { /* non-blocking — never break scan response */ }

  // v41.0: Pre-build response so it is ready regardless of DB outcome
  const responsePayload = addMonetizationFlags(result, 'identity', authCtx, scanId);
  const finalResponse = Response.json(
    responsePayload,
    { status: 200, headers: { 'X-Scan-ID': scanId, 'X-Module': 'identity' } }
  );

  // v41.0: Synchronous D1 tracking with correct schema
  try {
    void incrementScanCounter(env);
    void cacheScanResultForReport(env, authCtx, scanId, responsePayload);
    if (env?.DB) {
      const jobId    = `sync_${crypto.randomUUID().slice(0,8)}_${scanId}`;
      const identity = authCtx?.user_id || authCtx?.keyId || 'api_anon';
      await env.DB.prepare(
        `INSERT OR IGNORE INTO scan_jobs
         (id, user_id, identity, module, target, status, risk_level, risk_score, completed_at)
         VALUES (?, ?, ?, 'identity', ?, 'completed', ?, ?, datetime('now'))`
      ).bind(
        jobId,
        authCtx?.user_id || null,
        identity,
        orgVal.value,
        result?.risk_level || 'LOW',
        result?.risk_score || 0
      ).run();

      if (authCtx?.user_id) {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO scan_history
           (user_id, job_id, scan_id, target, module, risk_score, risk_level, grade, data_source, status)
           VALUES (?, ?, ?, ?, 'identity', ?, ?, 'N/A', 'identity_engine', 'completed')`
        ).bind(
          authCtx.user_id,
          jobId,
          scanId,
          orgVal.value,
          result?.risk_score || 0,
          result?.risk_level || 'LOW'
        ).run();
      }
    }
  } catch { /* tracking must never break scan response */ }

  return finalResponse;
}
