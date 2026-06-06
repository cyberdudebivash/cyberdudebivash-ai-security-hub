/**
 * CYBERDUDEBIVASH AI Security Hub — v24 Revenue Dominance Handler
 * Routes: /api/v24/*
 *
 * PHASE 1  — Billing:     /api/v24/billing/*
 * PHASE 2  — Sales OS:    /api/v24/sales/*
 * PHASE 3  — Proposals:   /api/v24/proposals/*
 * PHASE 4  — Scanner:     /api/v24/scanner/*
 * PHASE 5  — API Economy: /api/v24/api-economy/* (v23 revosHandler extended)
 * PHASE 6  — Defense:     /api/v24/defense/*
 * PHASE 7  — MSSP:        /api/v24/mssp/* (v23 extended)
 * PHASE 8  — CS AI:       /api/v24/cs/* (v23 extended)
 * PHASE 9  — Trust:       /api/v24/trust/*
 * PHASE 10 — CEO:         /api/v24/ceo/*
 */

import { createInvoice, issueLicense, verifyLicense, createPayPalOrder, capturePayPalOrder, runPaymentRecovery, buildRenewalQueue } from '../services/v24/billingEngine.js';
import { scoreEnterpriseOpportunity, generateProposal } from '../services/v24/salesOS.js';
import { SCAN_TIERS, createScanOrder, fulfillScanOrder, getScanOrderByToken, getScannerRevenue, getTrustCenterData, logUptimeCheck, seedReleaseNotes, getCEODashboard } from '../services/v24/platformEngine.js';

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}
function err(msg, status = 400, code = 'ERR') {
  return json({ success: false, error: msg, code }, status);
}
async function parseBody(req) {
  try { return await req.json(); } catch { return {}; }
}
function isAdmin(authCtx) {
  return authCtx?.role === 'admin' || authCtx?.plan === 'ENTERPRISE';
}

export async function handleV24(request, env, authCtx, path, method) {
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const db = env?.DB;
  const kv = env?.SECURITY_HUB_KV;

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 1 — BILLING ENGINE
  // ══════════════════════════════════════════════════════════════════════

  // POST /api/v24/billing/invoice/create
  if (path === '/api/v24/billing/invoice/create' && method === 'POST') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const body = await parseBody(request);
    if (!body.line_items?.length) return err('line_items required');
    const result = await createInvoice(db, {
      userId:         authCtx.userId,
      email:          body.email || authCtx.email,
      company:        body.company,
      gstin:          body.gstin,
      billingAddress: body.billing_address,
      lineItems:      body.line_items,
      subscriptionId: body.subscription_id,
      paymentId:      body.payment_id,
      paymentMethod:  body.payment_method || 'razorpay',
      periodStart:    body.period_start,
      periodEnd:      body.period_end,
    });
    return json(result);
  }

  // GET /api/v24/billing/invoices
  if (path === '/api/v24/billing/invoices' && method === 'GET') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const rows = db ? await db.prepare(
      `SELECT id, invoice_number, total_inr, status, created_at, pdf_key FROM invoices
       WHERE user_id=? ORDER BY created_at DESC LIMIT 50`
    ).bind(authCtx.userId).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, invoices: rows.results || [] });
  }

  // GET /api/v24/billing/invoice/:id
  if (path.startsWith('/api/v24/billing/invoice/') && !path.includes('create') && method === 'GET') {
    const invId = path.replace('/api/v24/billing/invoice/', '').split('/')[0];
    const inv = db ? await db.prepare(`SELECT * FROM invoices WHERE id=?`).bind(invId).first().catch(() => null) : null;
    if (!inv) return err('Invoice not found', 404);
    return json({ success: true, invoice: inv });
  }

  // POST /api/v24/billing/license/issue
  if (path === '/api/v24/billing/license/issue' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const body = await parseBody(request);
    if (!body.user_id || !body.email || !body.plan) return err('user_id, email, plan required');
    const result = await issueLicense(db, body);
    return json(result);
  }

  // POST /api/v24/billing/license/activate
  if (path === '/api/v24/billing/license/activate' && method === 'POST') {
    const body = await parseBody(request);
    const result = await verifyLicense(db, body.license_key);
    if (!result.valid) return err(result.error || 'Invalid license', 400, 'LICENSE_INVALID');
    return json({ success: true, ...result });
  }

  // GET /api/v24/billing/license/verify?key=CBD-XXXX-XXXX
  if (path === '/api/v24/billing/license/verify' && method === 'GET') {
    const key = new URL(request.url).searchParams.get('key');
    if (!key) return err('key parameter required');
    const result = await verifyLicense(db, key);
    return json({ success: result.valid, ...result });
  }

  // POST /api/v24/billing/paypal/create
  if (path === '/api/v24/billing/paypal/create' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.amount_usd || !body.plan_id) return err('amount_usd and plan_id required');
    const result = await createPayPalOrder(env, {
      amountUSD:   body.amount_usd,
      planId:      body.plan_id,
      description: body.description,
      userId:      authCtx?.userId,
      email:       body.email || authCtx?.email,
    });
    return json(result);
  }

  // POST /api/v24/billing/paypal/capture
  if (path === '/api/v24/billing/paypal/capture' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.order_id) return err('order_id required');
    const result = await capturePayPalOrder(db, env, body.order_id);
    if (!result.ok) return err(result.error || 'Capture failed', 400);
    return json({ success: true, ...result });
  }

  // POST /api/v24/billing/refund/request
  if (path === '/api/v24/billing/refund/request' && method === 'POST') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const body = await parseBody(request);
    if (!body.payment_id || !body.reason) return err('payment_id and reason required');
    if (db) {
      const refId = `ref-${Date.now().toString(36)}`;
      await db.prepare(`
        INSERT INTO refunds (id, payment_id, invoice_id, user_id, email, reason, reason_detail, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
      `).bind(refId, body.payment_id, body.invoice_id || null, authCtx.userId,
               body.email || authCtx.email, body.reason, body.detail || '').run().catch(() => {});
    }
    return json({ success: true, message: 'Refund request submitted. Review within 2 business days.' });
  }

  // POST /api/v24/billing/recovery/run (admin/cron)
  if (path === '/api/v24/billing/recovery/run' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const result = await runPaymentRecovery(db, env);
    return json({ success: true, ...result });
  }

  // POST /api/v24/billing/renewals/build (admin/cron)
  if (path === '/api/v24/billing/renewals/build' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const result = await buildRenewalQueue(db);
    return json({ success: true, ...result });
  }

  // GET /api/v24/billing/renewals
  if (path === '/api/v24/billing/renewals' && method === 'GET') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const rows = db ? await db.prepare(
      `SELECT * FROM renewal_queue WHERE status='upcoming' ORDER BY renewal_date LIMIT 50`
    ).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, renewals: rows.results || [] });
  }

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 2 — ENTERPRISE SALES OS
  // ══════════════════════════════════════════════════════════════════════

  // POST /api/v24/sales/score
  if (path === '/api/v24/sales/score' && method === 'POST') {
    const body = await parseBody(request);
    const score = scoreEnterpriseOpportunity(body);

    // Update deal if deal_id provided
    if (body.deal_id && db) {
      await db.prepare(`
        UPDATE deal_pipeline SET
          opportunity_score    = ?,
          security_budget_inr  = COALESCE(?, security_budget_inr),
          ai_adoption_level    = COALESCE(?, ai_adoption_level),
          compliance_needs     = COALESCE(?, compliance_needs),
          risk_exposure        = COALESCE(?, risk_exposure),
          mssp_potential       = ?,
          updated_at           = datetime('now')
        WHERE id = ?
      `).bind(
        score.opportunity_score,
        body.security_budget_inr || null,
        body.ai_adoption_level   || null,
        body.compliance_needs ? JSON.stringify(body.compliance_needs) : null,
        body.risk_exposure        || null,
        score.mssp_candidate ? 1 : 0,
        body.deal_id,
      ).run().catch(() => {});
    }

    return json({ success: true, scoring: score });
  }

  // GET /api/v24/sales/pipeline
  if (path === '/api/v24/sales/pipeline' && method === 'GET') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const rows = db ? await db.prepare(
      `SELECT *, opportunity_score, security_budget_inr, ai_adoption_level
       FROM deal_pipeline ORDER BY opportunity_score DESC, updated_at DESC LIMIT 100`
    ).all().catch(() => ({ results: [] })) : { results: [] };

    const stages = {};
    for (const deal of (rows.results || [])) {
      if (!stages[deal.stage]) stages[deal.stage] = { deals: [], count: 0, value: 0 };
      stages[deal.stage].deals.push(deal);
      stages[deal.stage].count++;
      stages[deal.stage].value += deal.deal_value_inr || 0;
    }
    return json({ success: true, pipeline: stages, total_deals: rows.results?.length || 0 });
  }

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 3 — PROPOSAL FACTORY
  // ══════════════════════════════════════════════════════════════════════

  // POST /api/v24/proposals/generate
  if (path === '/api/v24/proposals/generate' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.company || !body.contact_email) return err('company and contact_email required');

    const proposal = generateProposal(body, body.type || 'enterprise', {
      custom_price_inr: body.custom_price_inr,
      billing:          body.billing,
    });

    // Save to D1
    if (db) {
      await db.prepare(`
        INSERT INTO proposals
          (id, deal_id, type, company, contact_email, contact_name, value_inr, plan,
           status, content_json, valid_until, html_content, roi_data, exec_summary, revision)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, 1)
      `).bind(
        proposal.proposal_id,
        body.deal_id || null,
        body.type || 'enterprise',
        body.company,
        body.contact_email,
        body.contact_name || '',
        proposal.total_inr,
        'ENTERPRISE',
        JSON.stringify(proposal.sections).slice(0, 20000),
        proposal.valid_until,
        proposal.html.slice(0, 65000),
        JSON.stringify(proposal.sections.roi),
        proposal.sections.executive_summary,
      ).run().catch(() => {});
    }

    return json({
      success:     true,
      proposal_id: proposal.proposal_id,
      type:        proposal.type,
      total_inr:   proposal.total_inr,
      valid_until: proposal.valid_until,
      html_length: proposal.html.length,
      proposal:    { ...proposal, html: undefined }, // Don't send HTML in JSON (send separately)
    });
  }

  // GET /api/v24/proposals/:id/html — serve the HTML proposal
  if (path.match(/^\/api\/v24\/proposals\/[^/]+\/html$/) && method === 'GET') {
    const propId = path.split('/')[4];
    const prop = db ? await db.prepare(`SELECT html_content, company, type FROM proposals WHERE id=?`)
      .bind(propId).first().catch(() => null) : null;
    if (!prop?.html_content) return err('Proposal not found', 404);
    return new Response(prop.html_content, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS } });
  }

  // GET /api/v24/proposals
  if (path === '/api/v24/proposals' && method === 'GET') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const rows = db ? await db.prepare(
      `SELECT id, proposal_id, type, company, contact_email, value_inr, status, created_at, valid_until
       FROM proposals ORDER BY created_at DESC LIMIT 50`
    ).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, proposals: rows.results || [] });
  }

  // POST /api/v24/proposals/:id/send
  if (path.match(/^\/api\/v24\/proposals\/[^/]+\/send$/) && method === 'POST') {
    const propId = path.split('/')[4];
    if (db) {
      await db.prepare(`UPDATE proposals SET status='sent', sent_at=datetime('now'), updated_at=datetime('now') WHERE id=?`)
        .bind(propId).run().catch(() => {});
    }
    return json({ success: true, proposal_id: propId, status: 'sent' });
  }

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 4 — SCANNER REVENUE ENGINE
  // ══════════════════════════════════════════════════════════════════════

  // GET /api/v24/scanner/tiers
  if (path === '/api/v24/scanner/tiers' && method === 'GET') {
    return json({ success: true, tiers: SCAN_TIERS });
  }

  // POST /api/v24/scanner/order
  if (path === '/api/v24/scanner/order' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.target || !body.tier) return err('target and tier required');
    const result = await createScanOrder(db, {
      userId: authCtx?.userId,
      email:  body.email || authCtx?.email,
      target: body.target,
      module: body.module || 'domain',
      tier:   body.tier,
    });
    return json(result);
  }

  // POST /api/v24/scanner/fulfill
  if (path === '/api/v24/scanner/fulfill' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.order_id || !body.payment_id) return err('order_id and payment_id required');
    const result = await fulfillScanOrder(db, body.order_id, body.payment_id);
    return json(result);
  }

  // GET /api/v24/scanner/report?token=xxx — gated report download
  if (path === '/api/v24/scanner/report' && method === 'GET') {
    const token = new URL(request.url).searchParams.get('token');
    if (!token) return err('token required');
    const order = await getScanOrderByToken(db, token);
    if (!order) return err('Invalid or expired token', 403);
    return json({ success: true, order, scan_result: order.scan_result ? JSON.parse(order.scan_result) : null });
  }

  // GET /api/v24/scanner/revenue
  if (path === '/api/v24/scanner/revenue' && method === 'GET') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const period = new URL(request.url).searchParams.get('period');
    const data = await getScannerRevenue(db, period);
    return json({ success: true, ...data });
  }

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 9 — TRUST CENTER (PUBLIC)
  // ══════════════════════════════════════════════════════════════════════

  // GET /api/v24/trust — full trust center data (public)
  if (path === '/api/v24/trust' && method === 'GET') {
    const data = await getTrustCenterData(db, kv);
    return json({ success: true, ...data });
  }

  // POST /api/v24/trust/uptime — log uptime check (internal cron)
  if (path === '/api/v24/trust/uptime' && method === 'POST') {
    const body = await parseBody(request);
    await logUptimeCheck(db, body.service || 'api', body.status_code || 200, body.latency_ms || 0);
    return json({ success: true });
  }

  // POST /api/v24/trust/incident — report incident (admin)
  if (path === '/api/v24/trust/incident' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const body = await parseBody(request);
    if (!body.title || !body.severity) return err('title and severity required');
    const incId = `inc-${Date.now().toString(36)}`;
    if (db) {
      await db.prepare(`
        INSERT INTO trust_incidents (id, title, severity, status, affected_systems, description)
        VALUES (?, ?, ?, 'investigating', ?, ?)
      `).bind(incId, body.title, body.severity, JSON.stringify(body.affected_systems || []), body.description || '').run().catch(() => {});
    }
    kv?.delete('trust:center:v1').catch(() => {});
    return json({ success: true, incident_id: incId });
  }

  // POST /api/v24/trust/seed — seed release notes + testimonials (admin)
  if (path === '/api/v24/trust/seed' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    await seedReleaseNotes(db);
    return json({ success: true, message: 'Release notes seeded' });
  }

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 10 — CEO REVENUE COMMAND CENTER
  // ══════════════════════════════════════════════════════════════════════

  // GET /api/v24/ceo/dashboard
  if (path === '/api/v24/ceo/dashboard' && method === 'GET') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const data = await getCEODashboard(db, kv);
    return json(data);
  }

  // GET /api/v24/ceo/revenue-streams
  if (path === '/api/v24/ceo/revenue-streams' && method === 'GET') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const period = new URL(request.url).searchParams.get('period') || new Date().toISOString().slice(0, 7);
    const rows = db ? await db.prepare(
      `SELECT * FROM revenue_streams WHERE period=? ORDER BY revenue_inr DESC`
    ).bind(period).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, period, streams: rows.results || [] });
  }

  // ══════════════════════════════════════════════════════════════════════
  // v24 Health
  // ══════════════════════════════════════════════════════════════════════
  if (path === '/api/v24/health' && method === 'GET') {
    return json({
      success: true,
      version: '24.0.0',
      phases:  ['billing','sales_os','proposals','scanner_revenue','api_economy','defense_pipeline','mssp','cs_ai','trust_center','ceo_dashboard'],
      db:      !!db,
      kv:      !!kv,
      generated_at: new Date().toISOString(),
    });
  }

  return err('v24 route not found', 404, 'NOT_FOUND');
}
