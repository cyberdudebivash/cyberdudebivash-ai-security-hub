import { domainScanEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateDomain, parseBody } from '../middleware/validation.js';
import { inspectForAttacks, sanitizeString } from '../middleware/security.js';

function genScanId() { return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8); }

export async function handleDomainScan(request, env, authCtx = {}) {
  const body   = await parseBody(request);
  const raw    = body?.domain || body?.target || '';

  if (inspectForAttacks(raw)) {
    return Response.json({ error: 'Invalid input detected', field: 'domain' }, { status: 400 });
  }

  const validation = validateDomain(sanitizeString(raw));
  if (!validation.valid) {
    return Response.json({ error: 'Validation failed', message: validation.message, field: 'domain' }, { status: 400 });
  }

  const scanId = genScanId();
  const result = domainScanEngine(validation.value);
  return Response.json(addMonetizationFlags(result, 'domain', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'domain' } });
}
