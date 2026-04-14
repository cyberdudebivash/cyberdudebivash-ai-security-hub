import { redteamEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { sanitizeString } from '../middleware/security.js';

const VALID_SCOPES = ['external','internal','full','web','cloud','hybrid','api'];
function genScanId() { return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8); }

export async function handleRedteamScan(request, env, authCtx = {}) {
  const body      = await parseBody(request);
  const orgVal    = validateString(sanitizeString(body?.target_org || body?.org || body?.target || ''), 'target_org', 2, 120);
  if (!orgVal.valid) return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });

  const scopeVal  = validateEnum(body?.scope || 'external', 'scope', VALID_SCOPES, 'external');
  const scanId    = genScanId();
  const result    = redteamEngine(orgVal.value, scopeVal.value);
  return Response.json(addMonetizationFlags(result, 'redteam', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'redteam' } });
}
