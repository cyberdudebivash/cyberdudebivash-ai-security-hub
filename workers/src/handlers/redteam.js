import { redteamEngine } from '../engine.js';
import { checkRateLimit, addMonetizationFlags, trackUsage } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';

const VALID_SCOPES = ['external','internal','full','web','cloud','hybrid'];

export async function handleRedteamScan(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const rateOk = await checkRateLimit(env, ip, 'redteam');
  if (!rateOk) {
    return Response.json({
      error: 'Rate limit exceeded',
      message: 'Free tier: 10 scans/hour. Upgrade at ₹999/report.',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const body      = await parseBody(request);
  const targetOrg = body?.target_org || body?.org || body?.target || '';
  const scope     = body?.scope || 'external';

  const orgVal   = validateString(targetOrg, 'target_org', 2, 120);
  if (!orgVal.valid) {
    return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });
  }
  const scopeVal = validateEnum(scope, 'scope', VALID_SCOPES, 'external');

  const result    = redteamEngine(orgVal.value, scopeVal.value);
  const monetized = addMonetizationFlags(result, 'redteam');

  if (env?.SECURITY_HUB_KV) await trackUsage(env, ip, 'redteam');

  return Response.json(monetized, { status: 200 });
}
