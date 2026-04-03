import { domainScanEngine } from '../engine.js';
import { checkRateLimit, addMonetizationFlags, trackUsage } from '../middleware/monetization.js';
import { validateDomain, parseBody } from '../middleware/validation.js';

export async function handleDomainScan(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const rateOk = await checkRateLimit(env, ip, 'domain');
  if (!rateOk) {
    return Response.json({
      error: 'Rate limit exceeded',
      message: 'Free tier: 10 scans/hour. Upgrade for unlimited access.',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const body = await parseBody(request);
  const domain = body?.domain || body?.target || '';

  const validation = validateDomain(domain);
  if (!validation.valid) {
    return Response.json({ error: 'Validation failed', message: validation.message }, { status: 400 });
  }

  const result = domainScanEngine(validation.value);
  const monetized = addMonetizationFlags(result, 'domain');

  if (env?.SECURITY_HUB_KV) {
    await trackUsage(env, ip, 'domain');
  }

  return Response.json(monetized, { status: 200 });
}
