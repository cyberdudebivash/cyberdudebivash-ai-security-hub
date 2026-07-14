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
import { normalizeTier, getTierDef } from './subscriptionPaywallEngine.js';
import { scoreEnterpriseOpportunity, generateProposal } from '../services/v24/salesOS.js';
import { SCAN_TIERS, createScanOrder, fulfillScanOrder, getScanOrderByToken, getScannerRevenue, getTrustCenterData, logUptimeCheck, seedReleaseNotes, getCEODashboard } from '../services/v24/platformEngine.js';
import { createRazorpayRefund, verifyPaymentSignature } from '../lib/razorpay.js';
import { isOwner } from '../auth/middleware.js';
import { logSystemError } from '../lib/errorLog.js';

const REFUND_REASONS = new Set(['customer_request', 'duplicate', 'fraud', 'service_failure', 'other']);

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
// Neither `authCtx.role` nor `authCtx.plan` is ever actually set anywhere in
// the auth layer — this gate was unreachable by anyone, including the
// platform owner via ADMIN_KEY (which sets `isAdmin: true`, not `role` or
// `plan`). Every route gated by this is a staff-only operational task
// (license issuance, payment-recovery job trigger, renewal queue, aggregate
// revenue reporting, incident posting, release-notes seeding) — genuinely
// admin-only, not something a paying customer should trigger, so no tier
// bypass is added here (contrast msspTenantPlatform.js's requireMSSPAdmin()).
function isAdmin(authCtx) {
  return authCtx?.isAdmin === true;
}

export async function handleV24(request, env, authCtx, path, method) {
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const db = env?.DB;
  const kv = env?.SECURITY_HUB_KV;

  // ══════════════════════════════════════════════════════════════════════
  // PHASE 1 — BILLING ENGINE
  // ══════════════════════════════════════════════════════════════════════

  // POST /api/v24/billing/invoice/create — manual/back-office invoice issuance
  // (e.g. for a payment received by bank transfer). Previously gated only to
  // "any logged-in user," with payment_id optional and never verified —
  // any authenticated customer, any tier, could self-mint a real,
  // sequentially-numbered "paid" GST invoice for an arbitrary amount with no
  // payment at all, and it fed the fabricated amount into revenue_streams
  // (2026-07-14 commercial-integrity audit). No confirmed caller anywhere
  // used self-service invoice creation via this route; every real payment
  // flow in this codebase creates invoices from its OWN verify handler after
  // its OWN payment verification, not through this generic HTTP route.
  if (path === '/api/v24/billing/invoice/create' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
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
    }, env);
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

  // GET /api/v24/billing/invoice/:id — previously had no ownership check at
  // all (any authenticated, or even unauthenticated, caller who knew/guessed
  // an invoice id could fetch it, including GSTIN/billing address/line
  // items). Flagged as a known follow-up in PR #230's own notes and never
  // fixed until now (2026-07-14 commercial-integrity audit). Scoped the same
  // way GET /api/v24/billing/invoices (list) already correctly scopes: the
  // owning customer, or staff.
  if (path.startsWith('/api/v24/billing/invoice/') && !path.includes('create') && method === 'GET') {
    if (!authCtx?.userId) return err('Authentication required', 401);
    const invId = path.replace('/api/v24/billing/invoice/', '').split('/')[0];
    const inv = db ? await db.prepare(`SELECT * FROM invoices WHERE id=?`).bind(invId).first().catch(() => null) : null;
    if (!inv) return err('Invoice not found', 404);
    if (inv.user_id !== authCtx.userId && !isAdmin(authCtx)) return err('Forbidden', 403);
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
  // SECURITY: amountUSD is derived from the server-side SUBSCRIPTION_TIERS
  // catalog by plan_id only — body.amount_usd was previously trusted
  // verbatim into a real PayPal order (2026-07-14 commercial-integrity
  // audit, Priority 4). Never accept a client-supplied amount here.
  if (path === '/api/v24/billing/paypal/create' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.plan_id) return err('plan_id required');
    const tierKey = normalizeTier(body.plan_id);
    const tierDef = getTierDef(tierKey);
    if (!tierDef || !(tierDef.price_usd > 0)) {
      return err('Invalid or free plan_id — PayPal checkout requires a paid plan', 400, 'INVALID_PLAN');
    }
    const result = await createPayPalOrder(env, {
      amountUSD:   tierDef.price_usd,
      planId:      tierKey,
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
    if (!db) return err('Service temporarily unavailable', 503);
    const reason = REFUND_REASONS.has(body.reason) ? body.reason : 'other';
    const refId = `ref-${Date.now().toString(36)}`;
    const result = await db.prepare(`
      INSERT INTO refunds (id, payment_id, invoice_id, user_id, email, amount_inr, reason, reason_detail, status, initiated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'customer')
    `).bind(refId, body.payment_id, body.invoice_id || null, authCtx.userId,
             body.email || authCtx.email, body.amount_inr || 0, reason, body.detail || body.reason).run()
      .catch(async e => {
        await logSystemError(env, { area: 'refund.request_insert', message: e.message, context: { payment_id: body.payment_id, user_id: authCtx.userId } });
        return null;
      });
    if (!result) return err('Refund request could not be recorded — please email support directly', 500);
    return json({ success: true, refund_id: refId, message: 'Refund request submitted. Review within 2 business days.' });
  }

  // POST /api/v24/billing/refund/process (owner-only) — issues an instant Razorpay refund
  if (path === '/api/v24/billing/refund/process' && method === 'POST') {
    if (!isOwner(authCtx, env)) return err('Owner authorization required', 403);
    const body = await parseBody(request);
    if (!body.refund_id) return err('refund_id required');
    if (!db) return err('Service temporarily unavailable', 503);
    const refund = await db.prepare(`SELECT * FROM refunds WHERE id = ?`).bind(body.refund_id).first().catch(() => null);
    if (!refund) return err('Refund record not found', 404);
    if (refund.status !== 'pending') return err(`Refund already ${refund.status}`, 409);

    await db.prepare(`UPDATE refunds SET status = 'processing' WHERE id = ?`).bind(body.refund_id).run().catch(() => {});

    let rzpRefund;
    try {
      rzpRefund = await createRazorpayRefund(env, refund.payment_id,
        refund.amount_inr > 0 ? Math.round(refund.amount_inr * 100) : undefined,
        { refund_record_id: refund.id, reason: refund.reason });
    } catch (e) {
      await db.prepare(`UPDATE refunds SET status = 'failed' WHERE id = ?`).bind(body.refund_id).run().catch(() => {});
      await logSystemError(env, { area: 'refund.razorpay_api', message: e.message, context: { refund_id: body.refund_id, payment_id: refund.payment_id } });
      return err(`Razorpay refund failed: ${e.message}`, 502);
    }

    await db.prepare(`
      UPDATE refunds SET status = 'completed', razorpay_refund_id = ?, processed_at = datetime('now')
      WHERE id = ?
    `).bind(rzpRefund.id, body.refund_id).run()
      .catch(e => logSystemError(env, { area: 'refund.status_update', message: e.message, context: { refund_id: body.refund_id }, notify: false }));

    return json({ success: true, refund_id: body.refund_id, razorpay_refund_id: rzpRefund.id, status: 'completed' });
  }

  // GET /api/v24/billing/refunds (owner-only) — list refund queue
  if (path === '/api/v24/billing/refunds' && method === 'GET') {
    if (!isOwner(authCtx, env)) return err('Owner authorization required', 403);
    const status = new URL(request.url).searchParams.get('status') || 'pending';
    const rows = db ? await db.prepare(
      `SELECT * FROM refunds WHERE status = ? ORDER BY created_at DESC LIMIT 100`
    ).bind(status).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, refunds: rows.results || [] });
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

  // POST /api/v24/sales/score — the scoring computation itself has no side
  // effects and stays open, but the deal_id branch below writes to a real
  // internal deal_pipeline record and previously had no auth check at all
  // (2026-07-14 commercial-integrity audit) — any caller who knew/guessed a
  // deal_id could overwrite its budget/compliance/risk fields.
  if (path === '/api/v24/sales/score' && method === 'POST') {
    const body = await parseBody(request);
    const score = scoreEnterpriseOpportunity(body);

    // Update deal if deal_id provided
    if (body.deal_id && db) {
      if (!isAdmin(authCtx)) return err('Admin required', 403);
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

  // GET /api/v24/sales/pipeline — internal deal data across every prospect,
  // not scoped to the caller; previously any logged-in customer (any tier)
  // could see the whole company's enterprise sales pipeline, budgets, and
  // risk data (2026-07-14 commercial-integrity audit — same class as the
  // already-fixed C1 finding for /api/revenue/dashboard).
  if (path === '/api/v24/sales/pipeline' && method === 'GET') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
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

  // POST /api/v24/proposals/generate — had no auth check at all: anyone
  // (including anonymous callers — /api/v24/* doesn't require auth) could
  // generate and persist an enterprise sales proposal with a client-chosen
  // custom_price_inr. Gated the same isAdmin-only way as the sibling
  // /api/v24/proposals (list) and /api/v24/proposals/:id/send routes, and
  // matching the established convention for this whole proposal subsystem —
  // proposalGenerator.js's /api/proposals/* equivalents are all isOwner-gated,
  // by design: proposals are generated by internal sales staff and sent to
  // prospects externally (email/DocuSign), never viewed via an in-app
  // customer-facing link (2026-07-14 commercial-integrity audit, Priority 3).
  if (path === '/api/v24/proposals/generate' && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
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

  // GET /api/v24/proposals/:id/html — serve the HTML proposal. Previously had
  // no auth check at all, and the id it's keyed on (PROP-YYYY-MM-XXXX, where
  // XXXX is only the last 4 base36 digits of Date.now()) is trivially
  // enumerable — any caller could brute-force another prospect's full
  // proposal (company, contact email, pricing, ROI figures). Same isAdmin
  // gate as the sibling routes above/below (2026-07-14 commercial-integrity
  // audit, Priority 3).
  if (path.match(/^\/api\/v24\/proposals\/[^/]+\/html$/) && method === 'GET') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const propId = path.split('/')[4];
    const prop = db ? await db.prepare(`SELECT html_content, company, type FROM proposals WHERE id=?`)
      .bind(propId).first().catch(() => null) : null;
    if (!prop?.html_content) return err('Proposal not found', 404);
    return new Response(prop.html_content, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS } });
  }

  // GET /api/v24/proposals — lists every enterprise proposal across every
  // prospect company; previously any logged-in customer could see this
  // (2026-07-14 commercial-integrity audit).
  if (path === '/api/v24/proposals' && method === 'GET') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
    const rows = db ? await db.prepare(
      `SELECT id, proposal_id, type, company, contact_email, value_inr, status, created_at, valid_until
       FROM proposals ORDER BY created_at DESC LIMIT 50`
    ).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, proposals: rows.results || [] });
  }

  // POST /api/v24/proposals/:id/send — previously had no auth check at all;
  // any caller could flip any proposal's status by guessing/knowing its id
  // (2026-07-14 commercial-integrity audit).
  if (path.match(/^\/api\/v24\/proposals\/[^/]+\/send$/) && method === 'POST') {
    if (!isAdmin(authCtx)) return err('Admin required', 403);
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

  // POST /api/v24/scanner/fulfill — previously had NO payment verification of
  // any kind: it marked any caller-supplied order_id "paid" with an
  // arbitrary payment_id string, no signature check at all (2026-07-14
  // commercial-integrity audit) — a direct caller could self-issue an order
  // via /scanner/order, mark it paid here, and pull the report for free via
  // /scanner/report. Now requires and verifies a real Razorpay signature,
  // matching the canonical pattern every other checkout handler in this
  // codebase uses.
  if (path === '/api/v24/scanner/fulfill' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.order_id || !body.payment_id || !body.razorpay_order_id || !body.razorpay_signature) {
      return err('order_id, payment_id, razorpay_order_id, and razorpay_signature are required');
    }
    const sigValid = await verifyPaymentSignature(env, body.razorpay_order_id, body.payment_id, body.razorpay_signature);
    if (!sigValid) return err('Payment signature verification failed', 400, 'INVALID_SIGNATURE');
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

  // GET /api/v24/ceo/dashboard — real platform-wide MRR/ARR/revenue data;
  // previously any logged-in customer (any tier) could read this. Same
  // vulnerability class as the already-fixed C1 finding
  // (GET /api/revenue/dashboard, PR #233) — that fix's exact gate is reused
  // here (2026-07-14 commercial-integrity audit).
  if (path === '/api/v24/ceo/dashboard' && method === 'GET') {
    if (!isOwner(authCtx, env)) return err('Owner authorization required', 403);
    const data = await getCEODashboard(db, kv);
    return json(data);
  }

  // GET /api/v24/ceo/revenue-streams — same issue as /ceo/dashboard above.
  if (path === '/api/v24/ceo/revenue-streams' && method === 'GET') {
    if (!isOwner(authCtx, env)) return err('Owner authorization required', 403);
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
