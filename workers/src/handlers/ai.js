import { aiScanEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { inspectForAttacks, sanitizeString } from '../middleware/security.js';
import { enrichAssessmentWithMYTHOS } from '../services/mythosEnrichmentEngine.js';

const VALID_USE_CASES = ['chatbot','code-generation','rag','agent','recommendation','classification','image','vision','voice','other'];
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

export async function handleAIScan(request, env, authCtx = {}) {
  const body      = await parseBody(request);
  const rawModel  = body?.model_name || body?.model || body?.target || '';
  const rawUC     = body?.use_case || body?.usecase || 'other';

  if (inspectForAttacks(rawModel) || inspectForAttacks(rawUC)) {
    return Response.json({ error: 'Invalid input detected' }, { status: 400 });
  }

  const nameVal = validateString(sanitizeString(rawModel), 'model_name', 2, 100);
  if (!nameVal.valid) {
    return Response.json({ error: 'Validation failed', message: nameVal.message }, { status: 400 });
  }
  const ucVal = validateEnum(rawUC, 'use_case', VALID_USE_CASES, 'other');

  const scanId = genScanId();
  let result   = aiScanEngine(nameVal.value, ucVal.value);

  // v40.0: MYTHOS enrichment on all AI scans
  try {
    result = await enrichAssessmentWithMYTHOS(env, {
      report:       result,
      findings:     result.findings || [],
      service_name: 'AI Model Security Assessment',
      service_ref:  'CDB-AI-001',
      target:       nameVal.value,
      sector:       authCtx?.sector || 'Technology',
      tier:         authCtx?.tier   || 'FREE',
    });
  } catch { /* non-blocking */ }

  // v40.1+: Guaranteed D1 tracking — awaited before response
  const finalResponse = Response.json(addMonetizationFlags(result, 'ai', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'ai' } });
  try {
    void incrementScanCounter(env);
    if (env?.DB) {
      const jobId    = `sync_${crypto.randomUUID().slice(0,8)}_${scanId}`;
      const identity = authCtx?.user_id || authCtx?.keyId || 'api_anon';
      await env.DB.prepare(
        `INSERT OR IGNORE INTO scan_jobs
         (id, user_id, identity, module, target, status, risk_level, risk_score, completed_at)
         VALUES (?, ?, ?, 'ai', ?, 'completed', ?, ?, datetime('now'))`
      ).bind(jobId, authCtx?.user_id || null, identity, nameVal.value, result?.risk_level || 'LOW', result?.risk_score || 0).run();
      if (authCtx?.user_id) {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO scan_history (user_id, job_id, scan_id, target, module, risk_score, risk_level, grade, data_source, status)
           VALUES (?, ?, ?, ?, 'ai', ?, ?, 'N/A', 'ai_engine', 'completed')`
        ).bind(authCtx.user_id, jobId, scanId, nameVal.value, result?.risk_score || 0, result?.risk_level || 'LOW').run();
      }
    }
  } catch { /* tracking must never break scan response */ }
  return finalResponse;
}
