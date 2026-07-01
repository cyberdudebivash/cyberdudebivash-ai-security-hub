/**
 * CYBERDUDEBIVASH AI Security Hub — Compliance Scanner v41.0
 * POST /api/compliance   — Multi-framework compliance gap assessment
 *
 * v41.0 changes:
 *  - Correct D1 schema: identity NOT NULL, no updated_at column
 *  - Synchronous D1 tracking (pre-build response, then await DB writes)
 *  - MYTHOS enrichment inline on every scan
 *  - KV scan counter (same key pattern as all other handlers)
 *  - scan_history row for authenticated users
 */

import { complianceEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { sanitizeString } from '../middleware/security.js';
import { enrichAssessmentWithMYTHOS } from '../services/mythosEnrichmentEngine.js';
import { cacheScanResultForReport } from '../lib/scanResultCache.js';

const VALID_FRAMEWORKS = ['iso27001','soc2','gdpr','pcidss','dpdp','hipaa'];
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

export async function handleCompliance(request, env, authCtx = {}) {
  const body   = await parseBody(request);
  const orgVal = validateString(
    sanitizeString(body?.org_name || body?.org || body?.organization || body?.domain || body?.target || ''),
    'org_name', 2, 120
  );
  if (!orgVal.valid) return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });

  const fwVal  = validateEnum((body?.framework || 'iso27001').toLowerCase(), 'framework', VALID_FRAMEWORKS, 'iso27001');
  const scanId = genScanId();
  let result   = complianceEngine(orgVal.value, fwVal.value);

  // v41.0: MYTHOS enrichment on all compliance scans
  try {
    result = await enrichAssessmentWithMYTHOS(env, {
      report:       result,
      findings:     result.domain_assessments || [],
      service_name: 'Compliance Gap Assessment',
      service_ref:  'CDB-CMP-001',
      target:       orgVal.value,
      sector:       authCtx?.sector || 'Technology',
      tier:         authCtx?.tier   || 'FREE',
    });
  } catch { /* non-blocking — never break scan response */ }

  // v41.0: Pre-build response so it is ready regardless of DB outcome
  const responsePayload = addMonetizationFlags(result, 'compliance', authCtx, scanId);
  const finalResponse = Response.json(
    responsePayload,
    { status: 200, headers: { 'X-Scan-ID': scanId, 'X-Module': 'compliance' } }
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
         VALUES (?, ?, ?, 'compliance', ?, 'completed', ?, ?, datetime('now'))`
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
           VALUES (?, ?, ?, ?, 'compliance', ?, ?, 'N/A', 'compliance_engine', 'completed')`
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
