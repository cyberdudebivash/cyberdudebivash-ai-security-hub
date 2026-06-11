import { redteamEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { sanitizeString } from '../middleware/security.js';
import { enrichAssessmentWithMYTHOS } from '../services/mythosEnrichmentEngine.js';

const VALID_SCOPES = ['external','internal','full','web','cloud','hybrid','api'];
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

export async function handleRedteamScan(request, env, authCtx = {}) {
  const body      = await parseBody(request);
  const orgVal    = validateString(sanitizeString(body?.target_org || body?.org || body?.target || ''), 'target_org', 2, 120);
  if (!orgVal.valid) return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });

  const scopeVal = validateEnum(body?.scope || 'external', 'scope', VALID_SCOPES, 'external');
  const scanId   = genScanId();
  let result     = redteamEngine(orgVal.value, scopeVal.value);

  // v40.0: MYTHOS enrichment on all redteam scans
  try {
    result = await enrichAssessmentWithMYTHOS(env, {
      report:       result,
      findings:     result.findings || [],
      service_name: 'Red Team Attack Simulation',
      service_ref:  'CDB-RT-001',
      target:       orgVal.value,
      sector:       authCtx?.sector || 'Technology',
      tier:         authCtx?.tier   || 'FREE',
    });
  } catch { /* non-blocking */ }

  // v40.1+: Guaranteed D1 tracking — awaited before response
  const finalResponse = Response.json(addMonetizationFlags(result, 'redteam', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'redteam' } });
  try {
    void incrementScanCounter(env);
    if (env?.DB) {
      const jobId    = `sync_${crypto.randomUUID().slice(0,8)}_${scanId}`;
      const identity = authCtx?.user_id || authCtx?.keyId || 'api_anon';
      await env.DB.prepare(
        `INSERT OR IGNORE INTO scan_jobs
         (id, user_id, identity, module, target, status, risk_level, risk_score, completed_at)
         VALUES (?, ?, ?, 'redteam', ?, 'completed', ?, ?, datetime('now'))`
      ).bind(jobId, authCtx?.user_id || null, identity, orgVal.value, result?.risk_level || 'LOW', result?.risk_score || 0).run();
      if (authCtx?.user_id) {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO scan_history (user_id, job_id, scan_id, target, module, risk_score, risk_level, grade, data_source, status)
           VALUES (?, ?, ?, ?, 'redteam', ?, ?, 'N/A', 'redteam_engine', 'completed')`
        ).bind(authCtx.user_id, jobId, scanId, orgVal.value, result?.risk_score || 0, result?.risk_level || 'LOW').run();
      }
    }
  } catch { /* tracking must never break scan response */ }
  return finalResponse;
}
