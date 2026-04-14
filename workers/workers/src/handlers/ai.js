import { aiScanEngine } from '../engine.js';
import { addMonetizationFlags } from '../middleware/monetization.js';
import { validateString, validateEnum, parseBody } from '../middleware/validation.js';
import { inspectForAttacks, sanitizeString } from '../middleware/security.js';

const VALID_USE_CASES = ['chatbot','code-generation','rag','agent','recommendation','classification','image','vision','voice','other'];
function genScanId() { return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8); }

export async function handleAIScan(request, env, authCtx = {}) {
  const body      = await parseBody(request);
  const rawModel  = body?.model_name || body?.model || '';
  const rawUC     = body?.use_case || body?.usecase || 'other';

  if (inspectForAttacks(rawModel) || inspectForAttacks(rawUC)) {
    return Response.json({ error: 'Invalid input detected' }, { status: 400 });
  }

  const nameVal = validateString(sanitizeString(rawModel), 'model_name', 2, 100);
  if (!nameVal.valid) {
    return Response.json({ error: 'Validation failed', message: nameVal.message }, { status: 400 });
  }
  const ucVal   = validateEnum(rawUC, 'use_case', VALID_USE_CASES, 'other');

  const scanId  = genScanId();
  const result  = aiScanEngine(nameVal.value, ucVal.value);
  return Response.json(addMonetizationFlags(result, 'ai', authCtx, scanId), { status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'ai' } });
}
