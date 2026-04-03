import { aiScanEngine } from '../engine.js';
import { checkRateLimit, addMonetizationFlags, trackUsage } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';

const VALID_USE_CASES = ['chatbot','code-generation','rag','agent','recommendation','classification','other'];

export async function handleAIScan(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const rateOk = await checkRateLimit(env, ip, 'ai');
  if (!rateOk) {
    return Response.json({
      error: 'Rate limit exceeded',
      message: 'Free tier: 10 scans/hour. Upgrade for unlimited access.',
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const body = await parseBody(request);
  const modelName = body?.model_name || body?.model || '';
  const useCase   = body?.use_case   || body?.usecase || 'other';

  const nameVal = validateString(modelName, 'model_name', 2, 100);
  if (!nameVal.valid) {
    return Response.json({ error: 'Validation failed', message: nameVal.message }, { status: 400 });
  }
  const usecaseVal = validateEnum(useCase, 'use_case', VALID_USE_CASES, 'other');

  const result    = aiScanEngine(nameVal.value, usecaseVal.value);
  const monetized = addMonetizationFlags(result, 'ai');

  if (env?.SECURITY_HUB_KV) await trackUsage(env, ip, 'ai');

  return Response.json(monetized, { status: 200 });
}
