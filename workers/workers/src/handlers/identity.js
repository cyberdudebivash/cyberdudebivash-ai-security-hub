import { identityScanEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { sanitizeString } from '../middleware/security.js';

const VALID_IDPS = ['azure-ad','okta','google-workspace','auth0','onelogin','ping','keycloak','jumpcloud','duo','other'];
function genScanId() { return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8); }

export async function handleIdentityScan(request, env, authCtx = {}) {
  const body    = await parseBody(request);
  const orgVal  = validateString(sanitizeString(body?.org_name || body?.org || body?.organization || ''), 'org_name', 2, 120);
  if (!orgVal.valid) return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });

  const idpVal  = validateEnum(body?.identity_provider || body?.idp || 'other', 'identity_provider', VALID_IDPS, 'other');
  const scanId  = genScanId();
  const result  = identityScanEngine(orgVal.value, idpVal.value);
  return Response.json(addMonetizationFlags(result, 'identity', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'identity' } });
}
