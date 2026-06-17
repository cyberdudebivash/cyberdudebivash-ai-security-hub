/**
 * Lead Capture Handler — /api/leads/capture
 * Captures email before showing full results.
 * Associates leads with scan IDs in KV.
 * POST /api/leads/capture  → { email, scan_id?, module? }
 */
import { parseBody, validateString } from '../middleware/validation.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function genLeadId() {
  return 'ld_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

export async function handleLeadCapture(request, env) {
  const body   = await parseBody(request);
  const email  = (body?.email || '').trim().toLowerCase();
  const scanId = (body?.scan_id || '').trim();
  const module = (body?.module  || 'general').trim();
  const source = (body?.source  || 'platform').trim();

  if (!email || !EMAIL_RE.test(email)) {
    return Response.json({
      error: 'Validation failed',
      message: 'A valid email address is required',
    }, { status: 400 });
  }

  const leadId  = genLeadId();
  const leadObj = {
    lead_id:    leadId,
    email,
    scan_id:    scanId || null,
    module,
    source,
    ip:         request.headers.get('CF-Connecting-IP') || 'unknown',
    country:    request.headers.get('CF-IPCountry') || 'unknown',
    captured_at: new Date().toISOString(),
    converted:  false,
  };

  // Persist to D1 for durable storage (KV is cache only, 90-day TTL causes data loss)
  if (env?.DB) {
    try {
      await env.DB.prepare(`
        INSERT OR IGNORE INTO leads
          (id, email, name, domain, source, module, scan_id,
           ip_country, funnel_stage, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'lead', datetime('now'), datetime('now'))
      `).bind(
        leadId, email, '',
        email.includes('@') ? email.split('@')[1] : '',
        source, module, scanId || null,
        request.headers.get('CF-IPCountry') || 'unknown',
      ).run();
    } catch { /* non-blocking — table may not have all columns on older schema */ }
  }

  // Store in KV: lead:{leadId} and index by email (cache layer)
  if (env?.SECURITY_HUB_KV) {
    try {
      await Promise.all([
        env.SECURITY_HUB_KV.put(`lead:${leadId}`, JSON.stringify(leadObj), { expirationTtl: 7776000 }), // 90 days
        env.SECURITY_HUB_KV.put(`lead:email:${email}`, leadId),
        env.SECURITY_HUB_KV.put(`stats:leads:${new Date().toISOString().slice(0,10)}`,
          String((parseInt(await env.SECURITY_HUB_KV.get(`stats:leads:${new Date().toISOString().slice(0,10)}`) || '0')) + 1),
          { expirationTtl: 90000 }),
      ]);
    } catch { /* non-blocking */ }
  }

  // Auto-enroll in welcome email drip (fire-and-forget)
  if (env?.SECURITY_HUB_KV || env?.DB) {
    (async () => {
      try {
        const { enrollInSequence } = await import('../services/emailEngine.js');
        await enrollInSequence(env, email, 'welcome', { scan_id: scanId || null, module, source });
      } catch (e) { console.warn('[leads] drip enroll error:', e.message); }
    })();
  }

  return Response.json({
    status: 'ok',
    lead_id: leadId,
    message: 'Email captured successfully. Your full scan results are being prepared.',
    next_step: 'Your scan report is ready. Check the results panel.',
    scan_id: scanId || null,
  }, { status: 201 });
}
