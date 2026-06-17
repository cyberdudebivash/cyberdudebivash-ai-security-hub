// =============================================================================
// GTM TELEMETRY HANDLERS  (/api/gtm/*  +  /api/csp-report)
// -----------------------------------------------------------------------------
// Wires the frontend acquisition-analytics beacons that were previously 404ing:
//   POST /api/gtm/funnel-event   — single conversion-funnel event (CDB_FUNNEL)
//   POST /api/gtm/events/batch   — batched product events       (CDB_TRACK)
//   POST /api/gtm/email-capture  — scan-gate email capture → lead
//   POST /api/csp-report         — browser CSP violation reports
//
// All handlers are STRICTLY fire-and-forget: they never throw and always return
// a 2xx, so a client beacon can never surface an error to a visitor. DB writes
// target ONLY columns verified to exist on the live D1 schema:
//   funnel_events(id, email, event_type, stage, metadata, created_at)
//   leads(id, email, domain, plan, created_at, lead_score, is_enterprise,
//         stage, last_activity, company, ip, country, metadata, updated_at)
// =============================================================================

import { recordFunnelEvent } from '../services/funnelEngine.js';

// Free / consumer mailbox providers — anything else is treated as a business
// (enterprise) email and scored higher.
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
  'aol.com', 'protonmail.com', 'proton.me', 'mail.com', 'gmx.com',
  'yandex.com', 'zoho.com', 'live.com', 'msn.com', 'rediffmail.com',
]);

// Map granular client event names → canonical funnel stages the dashboards
// aggregate on. Unknown events fall through and are stored under their own name.
const EVENT_STAGE_MAP = {
  page_land:                  'visit',
  page_view:                  'visit',
  scan_start:                 'scan_start',
  scan_complete:              'scan_done',
  scan_done:                  'scan_done',
  pricing_viewed:             'product_view',
  product_view:               'product_view',
  enterprise_section_viewed:  'product_view',
  upgrade_prompt:             'upsell_view',
  upsell_view:                'upsell_view',
  pay_click:                  'checkout_start',
  pay_attempt:                'checkout_start',
  checkout_start:             'checkout_start',
  sub_click:                  'upgrade_click',
  upgrade_click:              'upgrade_click',
  pay_success:                'purchase',
  sub_success:                'purchase',
  purchase:                   'purchase',
  email_capture:              'email_capture',
  enterprise_submit:          'enterprise_submit',
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isEmailish = (v) => typeof v === 'string' && v.length <= 254 && EMAIL_RE.test(v);

function ok(extra = {}) {
  return Response.json({ success: true, ...extra });
}

function stageFor(event) {
  const e = String(event || '').trim().toLowerCase().slice(0, 64);
  return { event: e, stage: EVENT_STAGE_MAP[e] || e || 'unknown' };
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/gtm/funnel-event — single event from CDB_FUNNEL.track()
// Body: { event, email?, plan?, session_id?, page_url?, ts?, ...meta }
// ─────────────────────────────────────────────────────────────────────────────
export async function handleGtmFunnelEvent(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const { event: evt, stage } = stageFor(body.event || body.stage);
    if (!evt) return ok({ skipped: 'no_event' });

    const { event: _e, stage: _s, email: _em, ...meta } = body;
    const email = isEmailish(body.email) ? body.email : 'anonymous';

    await recordFunnelEvent(
      env,
      email,
      stage,
      { ...meta, user_id: authCtx?.userId || null },
      evt,
    );
    return ok();
  } catch {
    return ok(); // telemetry must never break the client
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/gtm/events/batch — batched events from CDB_TRACK._send()
// Body: { events: [{ event, props, session, referrer }, ...] }
// ─────────────────────────────────────────────────────────────────────────────
export async function handleGtmEventsBatch(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const events = Array.isArray(body.events) ? body.events.slice(0, 50) : [];
    if (!events.length) return ok({ recorded: 0 });

    const userId = authCtx?.userId || null;
    const stmt = env.DB.prepare(`
      INSERT INTO funnel_events (id, email, event_type, stage, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `);

    const rows = events.map((ev) => {
      const { event: evt, stage } = stageFor(ev.event);
      const props = (ev.props && typeof ev.props === 'object') ? ev.props : {};
      const email = isEmailish(props.email) ? props.email : 'anonymous';
      const meta = {
        ...props,
        session: ev.session || null,
        referrer: ev.referrer || null,
        user_id: userId,
      };
      return stmt.bind(crypto.randomUUID(), email, evt || 'unknown', stage, JSON.stringify(meta));
    });

    await env.DB.batch(rows).catch(() => {});
    return ok({ recorded: rows.length });
  } catch {
    return ok({ recorded: 0 });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/gtm/email-capture — scan-gate email capture → persist as a lead
// Body: { email, source?, module?, domain?, risk_level?, finding_count? }
// ─────────────────────────────────────────────────────────────────────────────
export async function handleGtmEmailCapture(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    if (!isEmailish(email)) return ok({ skipped: 'invalid_email' });

    const emailDomain = email.split('@')[1] || '';
    const isEnterprise = emailDomain && !FREE_EMAIL_PROVIDERS.has(emailDomain) ? 1 : 0;
    const leadDomain = String(body.domain || '').trim() || emailDomain;
    const ip = request.headers.get('CF-Connecting-IP') || null;
    const country = request.headers.get('CF-IPCountry') || null;
    const now = new Date().toISOString();
    const meta = JSON.stringify({
      source: body.source || 'scan_gate',
      module: body.module || null,
      risk_level: body.risk_level || null,
      finding_count: body.finding_count ?? null,
    });

    // No UNIQUE constraint on leads.email on the live schema → manual upsert.
    const existing = await env.DB
      .prepare(`SELECT id FROM leads WHERE email = ? LIMIT 1`)
      .bind(email).first().catch(() => null);

    if (existing?.id) {
      await env.DB.prepare(`
        UPDATE leads
        SET domain        = COALESCE(?, domain),
            is_enterprise = ?,
            last_activity = ?,
            updated_at    = ?,
            metadata      = ?
        WHERE id = ?
      `).bind(leadDomain || null, isEnterprise, now, now, meta, existing.id)
        .run().catch(() => {});
    } else {
      await env.DB.prepare(`
        INSERT INTO leads
          (id, email, domain, plan, created_at, lead_score, is_enterprise,
           stage, last_activity, ip, country, metadata, updated_at)
        VALUES (?, ?, ?, 'free', ?, ?, ?, 'email_captured', ?, ?, ?, ?, ?)
      `).bind(
        crypto.randomUUID(), email, leadDomain || null, now,
        isEnterprise ? 15 : 5, isEnterprise, now, ip, country, meta, now,
      ).run().catch(() => {});
    }

    await recordFunnelEvent(env, email, 'email_capture', {
      source: body.source || 'scan_gate',
      module: body.module || null,
      is_enterprise: !!isEnterprise,
    }, 'email_capture');

    return ok({ captured: true, is_enterprise: !!isEnterprise });
  } catch {
    return ok({ captured: false });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/csp-report — browser Content-Security-Policy violation reports.
// Stops the report-uri 404s; logs a concise line for visibility (no DB write).
// ─────────────────────────────────────────────────────────────────────────────
export async function handleCspReport(request, env) {
  try {
    const raw = await request.text().catch(() => '');
    if (raw) {
      let report = null;
      try { report = JSON.parse(raw); } catch { /* malformed — ignore body */ }
      // Legacy format: { "csp-report": {...} }. Reporting API: [{ body: {...} }].
      const r = report?.['csp-report']
        || (Array.isArray(report) ? report[0]?.body : null)
        || report;
      if (r && (r['violated-directive'] || r.effectiveDirective)) {
        const directive = r['violated-directive'] || r.effectiveDirective || 'unknown';
        const blocked = r['blocked-uri'] || r.blockedURL || '';
        console.warn(`[csp-report] ${directive} blocked=${blocked}`);
      }
    }
  } catch {
    // never throw on a report beacon
  }
  // 204: standard, body-less acknowledgement for report endpoints.
  return new Response(null, { status: 204 });
}
