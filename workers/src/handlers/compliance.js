import { complianceEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { sanitizeString } from '../middleware/security.js';

const VALID_FRAMEWORKS = ['iso27001','soc2','gdpr','pcidss','dpdp','hipaa'];
function genScanId() { return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8); }

export async function handleCompliance(request, env, authCtx = {}) {
  const body    = await parseBody(request);
  const orgVal  = validateString(sanitizeString(body?.org_name || body?.org || body?.organization || ''), 'org_name', 2, 120);
  if (!orgVal.valid) return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });

  const fwVal   = validateEnum((body?.framework || 'iso27001').toLowerCase(), 'framework', VALID_FRAMEWORKS, 'iso27001');
  const scanId  = genScanId();
  const result  = complianceEngine(orgVal.value, fwVal.value);
  // v22.0: Non-blocking D1 scan tracking (fire-and-forget)
  void (async () => {
    try {
      if (env?.DB) {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO scan_jobs
           (id, module, target, status, risk_level, risk_score, created_at, updated_at)
           VALUES (?, ?, ?, 'completed', ?, ?, datetime('now'), datetime('now'))`
        ).bind(
          'sync_' + Date.now().toString(36),
          'compliance',
          body?.org || body?.domain || body?.target || 'unknown',
          result?.risk_level || result?.overall_risk || 'LOW',
          result?.risk_score  || result?.overall_score || 0
        ).run();
      }
    } catch { /* non-blocking */ }
  })();

  return Response.json(addMonetizationFlags(result, 'compliance', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'compliance' } });
}
