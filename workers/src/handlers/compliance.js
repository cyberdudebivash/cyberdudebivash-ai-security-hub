import { complianceEngine } from '../engine.js';
import { checkRateLimit, addMonetizationFlags, trackUsage } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';

const VALID_FRAMEWORKS = ['iso27001','soc2','gdpr','pcidss','dpdp','hipaa'];

export async function handleCompliance(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const rateOk = await checkRateLimit(env, ip, 'compliance');
  if (!rateOk) {
    return Response.json({
      error: 'Rate limit exceeded',
      message: 'Free tier: 10 scans/hour. Full reports from ₹499.',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const body      = await parseBody(request);
  const orgName   = body?.org_name || body?.org || body?.organization || '';
  const framework = (body?.framework || 'iso27001').toLowerCase();

  const orgVal = validateString(orgName, 'org_name', 2, 120);
  if (!orgVal.valid) {
    return Response.json({ error: 'Validation failed', message: orgVal.message }, { status: 400 });
  }
  const fwVal = validateEnum(framework, 'framework', VALID_FRAMEWORKS, 'iso27001');

  const result    = complianceEngine(orgVal.value, fwVal.value);
  const monetized = addMonetizationFlags(result, 'compliance');

  if (env?.SECURITY_HUB_KV) await trackUsage(env, ip, 'compliance');

  return Response.json(monetized, { status: 200 });
}
