import { identityScanEngine } from '../engine.js';
import { checkRateLimit, addMonetizationFlags, trackUsage } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';

const VALID_IDPS = ['azure-ad','okta','google-workspace','auth0','onelogin','ping','keycloak','other'];

export async function handleIdentityScan(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const rateOk = await checkRateLimit(env, ip, 'identity');
  if (!rateOk) {
    return Response.json({
      error: 'Rate limit exceeded',
      message: 'Free tier: 10 scans/hour. Upgrade at ₹799/report.',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const body             = await parseBody(request);
  const orgName          = body?.org_name || body?.org || body?.organization || '';
  const identityProvider = body?.identity_provider || body?.idp || 'other';

  const orgVal = validateString(orgName, 'org_name', 2, 120);
  if (!orgVal.valid) {
    return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });
  }
  const idpVal = validateEnum(identityProvider, 'identity_provider', VALID_IDPS, 'other');

  const result    = identityScanEngine(orgVal.value, idpVal.value);
  const monetized = addMonetizationFlags(result, 'identity');

  if (env?.SECURITY_HUB_KV) await trackUsage(env, ip, 'identity');

  return Response.json(monetized, { status: 200 });
}
