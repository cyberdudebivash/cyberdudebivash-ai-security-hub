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
  return Response.json(addMonetizationFlags(result, 'compliance', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'compliance' } });
}
