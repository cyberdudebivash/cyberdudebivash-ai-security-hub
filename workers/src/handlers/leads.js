/**
 * Lead Capture Handler — /api/leads/capture
 * Captures email before showing full results.
 * Associates leads with scan IDs in KV.
 * POST /api/leads/capture  → { email, scan_id?, module? }
 */
import { parseBody, validateString } from '../middleware/validation.js';
import { attributeReferral } from './affiliateSystem.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function genLeadId() {
  return 'ld_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

export async function handleLeadCapture(request, env) {
  const body   = await parseBody(request);
  const email  = (body?.email || '').trim().toLowerCase();
  const scanId = (body?.scan_id || '').trim();
  const module = (body?.module  || 'general').trim();
  const source      = (body?.source       || 'platform').trim();
  const utmSource   = (body?.utm_source   || '').trim();
  const utmMedium   = (body?.utm_medium   || '').trim();
  const utmCampaign = (body?.utm_campaign || '').trim();
  const refCode     = (body?.ref_code     || '').trim();

  // Optional enrichment fields sent by lead-capture forms (services.html's
  // enterprise form, tools.html's custom-tool request) — were accepted by
  // this endpoint's JSON body but never read, so the caller saw a success
  // response while the backend silently discarded everything except email.
  const name        = (body?.name        || '').trim().slice(0, 200);
  const company     = (body?.company     || '').trim().slice(0, 200);
  const companySize = (body?.size        || body?.company_size || '').trim().slice(0, 50);
  const freeText    = (body?.challenge   || body?.description  || '').trim().slice(0, 2000);
  const toolType    = (body?.toolType    || '').trim().slice(0, 100);
  const notesParts = [];
  if (companySize) notesParts.push(`Company size: ${companySize}`);
  if (toolType)    notesParts.push(`Requested tool: ${toolType}`);
  if (freeText)     notesParts.push(freeText);
  const notes = notesParts.join(' | ') || null;

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
      // Upsert rather than INSERT OR IGNORE: an email already captured once
      // (e.g. from an earlier scan) would otherwise silently no-op on a
      // later, richer submission (enterprise form's name/company/notes),
      // discarding exactly the data this fix exists to stop losing.
      // COALESCE keeps existing values when this submission didn't supply one.
      await env.DB.prepare(`
        INSERT INTO leads
          (id, email, name, company, notes, domain, source, module, scan_id,
           ip_country, funnel_stage, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'lead', datetime('now'), datetime('now'))
        ON CONFLICT(email) DO UPDATE SET
          name       = COALESCE(excluded.name, leads.name),
          company    = COALESCE(excluded.company, leads.company),
          notes      = COALESCE(excluded.notes, leads.notes),
          updated_at = datetime('now')
      `).bind(
        leadId, email, name || null, company || null, notes,
        email.includes('@') ? email.split('@')[1] : '',
        source, module, scanId || null,
        request.headers.get('CF-IPCountry') || 'unknown',
      ).run();
    } catch { /* non-blocking — table may not have all columns on older schema */ }

    // Write funnel_events entry with full UTM attribution — enables channel-level conversion analysis
    const now = new Date().toISOString();
    const effectiveSource = utmSource || source;
    await env.DB.prepare(`
      INSERT INTO funnel_events (id, email, stage, meta, created_at)
      VALUES (?, ?, 'email_capture', ?, ?)
    `).bind(
      'fe_' + leadId, email,
      JSON.stringify({ source: effectiveSource, utm_source: utmSource, utm_medium: utmMedium, utm_campaign: utmCampaign }),
      now,
    ).run().catch(() => {});

    // Write cac_events lead entry for channel attribution — cost_inr=0 at capture, converted=0 until payment
    const CAC_CHANNEL_MAP = {
      google: 'paid_search', bing: 'paid_search', adwords: 'paid_search', ppc: 'paid_search',
      facebook: 'social', instagram: 'social', linkedin: 'social', twitter: 'social', youtube: 'social',
      telegram: 'telegram', affiliate: 'affiliate', partner: 'partner',
      referral: 'referral', ref: 'referral', organic: 'organic', cold_outreach: 'cold_outreach',
    };
    const channel = CAC_CHANNEL_MAP[effectiveSource.toLowerCase()] || 'direct';
    await env.DB.prepare(`
      INSERT OR IGNORE INTO cac_events
        (id, channel, campaign, email, cost_inr, converted, plan_converted, mrr_generated, event_date)
      VALUES (?, ?, ?, ?, 0, 0, 'free', 0, date('now'))
    `).bind('cac_lead_' + leadId, channel, utmCampaign || '', email).run().catch(() => {});

    // Attribute to a referring affiliate (first-touch wins) — credited on conversion via triggerPostPurchase
    if (refCode) {
      await attributeReferral(env, { email, ref_code: refCode, source: effectiveSource }).catch(() => {});
    }
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

  // Auto-enroll in welcome email drip and compute initial lead score (fire-and-forget)
  if (env?.SECURITY_HUB_KV || env?.DB) {
    (async () => {
      try {
        const { enrollInSequence } = await import('../services/emailEngine.js');
        await enrollInSequence(env, email, 'welcome', { scan_id: scanId || null, module, source });
      } catch (e) { console.warn('[leads] drip enroll error:', e.message); }
      try {
        await computeAndUpdateLeadScore(env, email);
      } catch { /* non-blocking */ }
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

// ─── Lead Qualification Scoring ───────────────────────────────────────────────
// Computes a 0–100 score from domain quality, scan activity, funnel depth,
// API usage, and acquisition source. Writes lead_score + qualified funnel_stage.
// Call fire-and-forget; safe to re-run — uses non-downgrading UPDATE guard.
const FREE_EMAIL_DOMAINS = new Set([
  'gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com',
  'protonmail.com','yopmail.com','temp-mail.org','guerrillamail.com','mailinator.com',
]);

export async function computeAndUpdateLeadScore(env, email) {
  if (!env?.DB || !email) return;
  const db = env.DB;

  const [leadRow, funnelRow, apiRow] = await Promise.all([
    db.prepare(`SELECT source, domain, scan_count, funnel_stage, lead_score
                FROM leads WHERE email = ? LIMIT 1`)
      .bind(email).first().catch(() => null),
    db.prepare(`SELECT MAX(CASE WHEN stage='purchase' THEN 4
                               WHEN stage='sql'      THEN 3
                               WHEN stage='lead'     THEN 2
                               WHEN stage='email_capture' THEN 1 ELSE 0 END) as depth
                FROM funnel_events WHERE email = ?`)
      .bind(email).first().catch(() => null),
    db.prepare(`SELECT COALESCE(SUM(request_count), 0) as api_calls
                FROM api_key_usage
                WHERE key_id IN (SELECT id FROM api_keys WHERE email = ? LIMIT 5)
                  AND date_bucket >= date('now','-30 days')`)
      .bind(email).first().catch(() => null),
  ]);

  if (!leadRow) return;
  // Never downgrade a converted or churned lead
  if (['customer', 'churned'].includes(leadRow.funnel_stage)) return;

  const domain = (leadRow.domain || email.split('@')[1] || '').toLowerCase();
  const domainScore  = FREE_EMAIL_DOMAINS.has(domain) ? 0 : 25;
  const scanScore    = Math.min(25, (leadRow.scan_count || 0) * 5);
  const apiScore     = Math.min(20, Math.floor((apiRow?.api_calls || 0) / 10) * 2);
  const funnelScore  = Math.min(20, (funnelRow?.depth || 0) * 5);
  const SOURCE_MAP   = {
    enterprise_inquiry: 10, mssp_inquiry: 10, assessment: 8,
    api: 7, referral: 6, platform: 5, organic: 4, social: 3,
  };
  const sourceScore  = SOURCE_MAP[leadRow.source] || 3;

  const score = Math.min(100, domainScore + scanScore + apiScore + funnelScore + sourceScore);

  let qualStage;
  if (score >= 75)      qualStage = 'sql';
  else if (score >= 55) qualStage = 'hot_lead';
  else if (score >= 35) qualStage = 'warm_lead';
  else                  qualStage = 'lead';

  const wasAlreadySql = leadRow.funnel_stage === 'sql';
  await db.prepare(`
    UPDATE leads SET lead_score = ?, funnel_stage = ?, updated_at = datetime('now')
    WHERE email = ? AND funnel_stage NOT IN ('customer','churned')
  `).bind(score, qualStage, email).run().catch(() => {});

  // Smart routing: newly SQL-qualified leads auto-enroll in enterprise_nurture.
  // The atomic enrollInSequence insert ensures this fires exactly once per lead.
  if (qualStage === 'sql' && !wasAlreadySql) {
    const { enrollInSequence } = await import('../services/emailEngine.js');
    enrollInSequence(env, email, 'enterprise_nurture', {
      lead_score: score,
      source:     leadRow.source,
      domain,
      qualified_at: new Date().toISOString(),
    }).catch(() => {});
  }
}
