/**
 * CYBERDUDEBIVASH AI Security Hub — Payments Handler v1.0
 * Razorpay integration: order creation, payment verification, report unlock
 * Full monetization flow: scan → payment → HTML report → R2 storage → download
 *
 * Routes:
 *   POST   /api/payments/create-order   → create Razorpay order
 *   POST   /api/payments/verify         → verify + generate HTML report
 *   GET    /api/payments/status/:orderId → check payment status
 *   GET    /api/reports/download/:token → token-gated R2 HTML report download
 *   POST   /api/webhooks/razorpay       → Razorpay async webhook
 */

import {
  MODULE_PRICES,
  SUBSCRIPTION_PRICES,
  createRazorpayOrder,
  verifyPaymentSignature,
  verifyWebhookSignature,
  generateReceiptId,
  generateAccessToken,
} from '../lib/razorpay.js';
import { generateHTMLReport } from '../lib/htmlReport.js';
import { buildReport }        from '../lib/reportEngine.js';
import { trackEvent }         from './analytics.js';
import { sendPurchaseConfirmation } from '../services/emailEngine.js';
import { createInvoice }            from '../services/v24/billingEngine.js';

// ─── Handlers for each scan module (run at ENTERPRISE tier for full data) ────
import { handleDomainScan }    from './domain.js';
import { handleAIScan }        from './ai.js';
import { handleRedteamScan }   from './redteam.js';
import { handleIdentityScan }  from './identity.js';
import { handleCompliance }    from './compliance.js';

const SCAN_HANDLERS = {
  domain:     handleDomainScan,
  ai:         handleAIScan,
  redteam:    handleRedteamScan,
  identity:   handleIdentityScan,
  compliance: handleCompliance,
};

// ─── Dynamic paid-scan auth context (scoped to a verified payment order) ─────
// SECURITY: Never use a static hardcoded ENTERPRISE context.
// This function creates a single-use, order-scoped context only after
// Razorpay HMAC signature validation has passed. The context is not
// exported and cannot be constructed from outside this module.
function buildPaidAuthCtx(orderId, userId, email) {
  if (!orderId || typeof orderId !== 'string' || orderId.length < 4) {
    throw new Error('[Payments] buildPaidAuthCtx: invalid orderId — refusing to issue context');
  }
  return {
    authenticated:       true,
    method:              'payment_verified',
    identity:            `paid:${orderId.slice(0, 12)}`,
    user_id:             userId || null,
    email:               email  || null,
    tier:                'ENTERPRISE',
    limits:              { daily_limit: -1, burst_per_min: 60 },
    isTemporary:         true,
    issuedFor:           orderId,
    payment_verified_at: Date.now(),
    // Explicit deny-list: these elevated privileges must never bleed into
    // persistent storage or session tokens
    noSession:           true,
    noPersist:           true,
  };
}

// Report access TTL: 30 days
const ACCESS_TTL_DAYS = 30;

// ─── POST /api/payments/create-order ─────────────────────────────────────────
export async function handleCreateOrder(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { module, target, scan_id, email } = body;

  // Validate module
  if (!module || !MODULE_PRICES[module]) {
    return Response.json({
      error:   'Invalid module',
      valid:   Object.keys(MODULE_PRICES),
      pricing: MODULE_PRICES,
    }, { status: 400 });
  }

  // Subscription: resolve plan-specific pricing
  if (module === 'subscription') {
    const planKey = (body.plan || target || 'STARTER').toUpperCase();
    const subPlan = SUBSCRIPTION_PRICES?.[planKey] || { amount: 49900, label: '₹499', name: planKey + ' Plan' };
    // Override price for this request
    Object.assign(MODULE_PRICES['subscription'], subPlan);
  }

  // Assessment/threat-intel/red-team: one-time products with fixed pricing
  if (['assessment', 'threat_intel', 'red_team'].includes(module)) {
    // Pricing already set in MODULE_PRICES — no override needed
    if (body.price_inr) {
      MODULE_PRICES[module].amount = Math.round(Number(body.price_inr) * 100);
    }
  }

  // Defense: use price_inr from request body
  if (module === 'defense' && body.price_inr) {
    MODULE_PRICES['defense'].amount = Math.round(Number(body.price_inr) * 100);
    MODULE_PRICES['defense'].label  = '₹' + Number(body.price_inr).toLocaleString('en-IN');
    MODULE_PRICES['defense'].name   = body.solution_title || 'Defense Solution';
  }
  if (!target || typeof target !== 'string' || target.length < 2 || target.length > 253) {
    return Response.json({ error: 'target is required (domain name or org name)' }, { status: 400 });
  }

  const price   = MODULE_PRICES[module];
  const receipt = generateReceiptId();
  const ip      = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Check for existing unpaid order for same target+module (prevent double charges)
  if (env.DB) {
    const existingOrder = await env.DB.prepare(
      `SELECT id, razorpay_order_id, status FROM payments
       WHERE module = ? AND target = ? AND status = 'pending'
       AND created_at > datetime('now', '-30 minutes')
       LIMIT 1`
    ).bind(module, target.toLowerCase()).first().catch(() => null);

    if (existingOrder?.razorpay_order_id) {
      // Return existing order instead of creating a new one
      return Response.json({
        order_id:  existingOrder.razorpay_order_id,
        key_id:    env.RAZORPAY_KEY_ID || '',
        amount:    price.amount,
        currency:  'INR',
        module,
        target,
        price_label: price.label,
        report_name: price.name,
        existing:  true,
      });
    }
  }

  // Create Razorpay order
  let razorOrder;
  try {
    razorOrder = await createRazorpayOrder(env, {
      amount:  price.amount,
      receipt,
      notes:   { module, target, scan_id: scan_id || '', platform: 'cyberdudebivash' },
    });
  } catch (err) {
    console.error('[Payments] Order creation failed:', err.message, 'module:', module, 'target:', target);
    // Non-blocking: log failure event to analytics
    trackEvent(env, 'payment_order_failed', module, authCtx?.user_id || null,
      request.headers?.get?.('CF-Connecting-IP'), { error: err.message, target }).catch(() => {});
    return Response.json({
      error:   'Payment gateway error. Please try again.',
      details: err.message,
      fallback: `Contact bivash@cyberdudebivash.com to complete purchase.`,
    }, { status: 502 });
  }

  // Store pending payment record in D1
  if (env.DB) {
    const paymentId = crypto.randomUUID?.() || Date.now().toString(36);
    await env.DB.prepare(
      `INSERT INTO payments (id, user_id, scan_id, module, target, amount, currency, razorpay_order_id, status, ip, email, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'INR', ?, 'pending', ?, ?, datetime('now'))`
    ).bind(
      paymentId,
      authCtx.user_id || null,
      scan_id || null,
      module,
      target.toLowerCase(),
      price.amount,
      razorOrder.id,
      ip,
      email || authCtx.email || null,
    ).run().catch(e => console.error('[Payments] D1 insert failed:', e.message));

    await trackEvent(env, 'payment_initiated', module, authCtx.user_id, ip, {
      razorpay_order_id: razorOrder.id,
      amount: price.amount,
      target,
    });
  }

  return Response.json({
    order_id:    razorOrder.id,
    key_id:      env.RAZORPAY_KEY_ID || '',
    amount:      price.amount,
    currency:    'INR',
    module,
    target,
    price_label: price.label,
    report_name: price.name,
    receipt,
  });
}

// ─── POST /api/payments/verify ────────────────────────────────────────────────
export async function handleVerifyPayment(request, env, authCtx = {}) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    module,
    target,
    scan_id,
    email,
  } = body;

  // Validate required fields
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return Response.json({
      error: 'razorpay_order_id, razorpay_payment_id, and razorpay_signature are required',
    }, { status: 400 });
  }
  // ── Subscription plan activation ─────────────────────────────────────────────
  if (module === 'subscription') {
    const sigValid = await verifyPaymentSignature(env, razorpay_order_id, razorpay_payment_id, razorpay_signature);
    if (!sigValid) {
      return Response.json({ error: 'Payment signature invalid. Contact support.' }, { status: 400 });
    }

    const planKey = ((body.plan || target || 'STARTER')).toUpperCase();
    const validPlans = ['STARTER', 'PRO', 'ENTERPRISE', 'MSSP'];
    if (!validPlans.includes(planKey)) {
      return Response.json({ error: 'Invalid plan. Valid: STARTER, PRO, ENTERPRISE, MSSP' }, { status: 400 });
    }

    const confirmedEmail = email || authCtx.email || null;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Idempotency: return existing activation if already processed
    if (env.DB) {
      const existing = await env.DB.prepare(
        `SELECT id FROM payments WHERE razorpay_order_id = ? AND status = 'paid' LIMIT 1`
      ).bind(razorpay_order_id).first().catch(() => null);

      if (existing) {
        const kvToken = confirmedEmail
          ? await env.SECURITY_HUB_KV?.get(`sub:token:${confirmedEmail}`).catch(() => null)
          : null;
        return Response.json({
          success:   true,
          token:     kvToken || existing.id,
          tier:      planKey,
          duplicate: true,
          message:   `${planKey} plan already activated.`,
        });
      }
    }

    // Find or create user record
    const userId = `user_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,7)}`;
    if (env.DB && confirmedEmail) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO users (id, email, tier, created_at) VALUES (?, ?, ?, datetime('now'))`
      ).bind(userId, confirmedEmail, planKey).run().catch(() => {});
      await env.DB.prepare(
        `UPDATE users SET tier = ?, updated_at = datetime('now') WHERE email = ?`
      ).bind(planKey, confirmedEmail).run().catch(() => {});
    }

    // Record payment in D1
    const subPaymentId = `sub_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,7)}`;
    const planPrice    = SUBSCRIPTION_PRICES[planKey]?.amount || 49900;
    if (env.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO payments
         (id, user_id, module, target, amount, currency, razorpay_order_id,
          razorpay_payment_id, razorpay_signature, status, email, ip, paid_at, created_at)
         VALUES (?, ?, ?, ?, ?, 'INR', ?, ?, ?, 'paid', ?, ?, datetime('now'), datetime('now'))`
      ).bind(
        subPaymentId, userId, 'subscription', planKey, planPrice,
        razorpay_order_id, razorpay_payment_id, razorpay_signature,
        confirmedEmail || null, ip,
      ).run().catch(e => console.warn('[Payments] sub D1 insert:', e.message));
    }

    // Grant KV access token — 365-day TTL
    const accessToken = generateAccessToken();
    const expiresAt   = new Date(Date.now() + 365 * 86400000).toISOString();
    if (env.SECURITY_HUB_KV && confirmedEmail) {
      await Promise.all([
        env.SECURITY_HUB_KV.put(`sub:token:${confirmedEmail}`, accessToken,  { expirationTtl: 365 * 86400 }),
        env.SECURITY_HUB_KV.put(`sub:tier:${confirmedEmail}`,  planKey,      { expirationTtl: 365 * 86400 }),
        env.SECURITY_HUB_KV.put(`sub:active:${accessToken}`,   JSON.stringify({
          email: confirmedEmail, tier: planKey, activated_at: new Date().toISOString(),
        }),                                                                     { expirationTtl: 365 * 86400 }),
      ]).catch(() => {});
    }

    // Fire-and-forget: purchase email + GST invoice
    const subPriceInr = Math.round(planPrice / 100);
    Promise.all([
      confirmedEmail
        ? sendPurchaseConfirmation(env, {
            to:            confirmedEmail,
            productName:   SUBSCRIPTION_PRICES[planKey]?.name || `${planKey} Plan`,
            amountInr:     subPriceInr,
            paymentId:     razorpay_payment_id,
            downloadUrl:   '/dashboard',
            accessExpires: expiresAt,
          }).catch(() => {})
        : Promise.resolve(),
      (env.DB && subPriceInr)
        ? createInvoice(env.DB, {
            userId:        userId,
            email:         confirmedEmail || 'noreply@buyer',
            lineItems:     [{ description: SUBSCRIPTION_PRICES[planKey]?.name || `${planKey} Plan`, amount_inr: subPriceInr, quantity: 1 }],
            paymentId:     razorpay_payment_id,
            paymentMethod: 'razorpay',
          }).catch(() => {})
        : Promise.resolve(),
    ]).catch(() => {});

    await trackEvent(env, 'subscription_activated', 'subscription', userId, ip, {
      plan: planKey, razorpay_order_id, razorpay_payment_id, email: confirmedEmail,
    });

    return Response.json({
      success:    true,
      token:      accessToken,
      tier:       planKey,
      expires_at: expiresAt,
      message:    `${planKey} plan activated. Welcome to CYBERDUDEBIVASH AI Security Hub.`,
    });
  }

  if (!module || !SCAN_HANDLERS[module]) {
    return Response.json({ error: 'Invalid scan module', valid: Object.keys(SCAN_HANDLERS) }, { status: 400 });
  }
  if (!target || typeof target !== 'string') {
    return Response.json({ error: 'target is required' }, { status: 400 });
  }

  // Verify Razorpay HMAC signature
  const sigValid = await verifyPaymentSignature(env, razorpay_order_id, razorpay_payment_id, razorpay_signature);
  if (!sigValid) {
    console.error('[Payments] Signature verification FAILED for order', razorpay_order_id);
    await trackEvent(env, 'payment_signature_invalid', module, authCtx.user_id,
      request.headers.get('CF-Connecting-IP'), { razorpay_order_id });
    return Response.json({ error: 'Payment signature invalid. Contact support.' }, { status: 400 });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Check for duplicate verification (idempotency)
  let existingToken = null;
  if (env.DB) {
    const existing = await env.DB.prepare(
      `SELECT report_token FROM payments
       WHERE razorpay_order_id = ? AND status = 'paid' LIMIT 1`
    ).bind(razorpay_order_id).first().catch(() => null);

    if (existing?.report_token) {
      existingToken = existing.report_token;
    }
  }

  if (existingToken) {
    return Response.json({
      success:      true,
      token:        existingToken,
      download_url: `/api/reports/download/${existingToken}`,
      message:      'Payment already verified — report available for download',
      duplicate:    true,
    });
  }

  // ── Run FULL scan for paid report (ENTERPRISE tier = no monetization gates) ─
  let scanResult;
  try {
    const payload = buildPayload(module, target, scan_id);
    const synReq  = new Request(`https://worker/api/scan/${module}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    // Build single-use, order-scoped ENTERPRISE context for this paid scan
    const paidCtx = buildPaidAuthCtx(
      razorpay_order_id,
      authCtx.user_id || null,
      email || authCtx.email || null,
    );
    const scanResp = await SCAN_HANDLERS[module](synReq, env, paidCtx);
    scanResult = await scanResp.json();

    // Merge locked findings into main findings for the full report
    if (scanResult.locked_findings?.length) {
      scanResult.findings = [
        ...(scanResult.findings || []),
        ...scanResult.locked_findings,
      ];
      delete scanResult.locked_findings;
    }
  } catch (err) {
    console.error('[Payments] Full scan failed for', target, err.message);
    return Response.json({
      error:   'Report generation failed — payment recorded. Contact support.',
      support: 'bivash@cyberdudebivash.com',
      order_id: razorpay_order_id,
    }, { status: 500 });
  }

  // ── Build structured report + HTML ───────────────────────────────────────────
  const reportId     = crypto.randomUUID?.() || Date.now().toString(36);
  const accessToken  = generateAccessToken();
  const expiresAt    = new Date(Date.now() + ACCESS_TTL_DAYS * 86400000).toISOString();
  const structReport = buildReport(scanResult, {
    email:     email || authCtx.email,
    tier:      'PRO',
    report_id: reportId,
  });
  const htmlContent  = generateHTMLReport(scanResult, { report_id: reportId });

  // ── Store HTML report in R2 ───────────────────────────────────────────────────
  const r2Key = `reports/${new Date().toISOString().slice(0,7)}/${accessToken}.html`;
  let r2Stored = false;
  if (env.SCAN_RESULTS) {
    try {
      await env.SCAN_RESULTS.put(r2Key, htmlContent, {
        httpMetadata: {
          contentType:        'text/html; charset=utf-8',
          contentDisposition: `attachment; filename="cyberdudebivash-${module}-report-${target.replace(/[^a-z0-9]/gi,'_')}.html"`,
        },
        customMetadata: {
          report_id:   reportId,
          module,
          target,
          risk_score:  String(scanResult.risk_score ?? 0),
          generated_at: new Date().toISOString(),
        },
      });
      r2Stored = true;
    } catch (e) {
      console.error('[Payments] R2 store failed:', e.message);
    }
  }

  // ── Store access token in KV for fast lookup ──────────────────────────────────
  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `report_access:${accessToken}`,
      JSON.stringify({ r2_key: r2Key, module, target, report_id: reportId, expires_at: expiresAt }),
      { expirationTtl: ACCESS_TTL_DAYS * 86400 }
    ).catch(() => {});
  }

  // ── Update D1 payment record + create report_access row ───────────────────────
  if (env.DB) {
    const accessId = crypto.randomUUID?.() || Date.now().toString(36) + '_acc';
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE payments SET
           status = 'paid',
           razorpay_payment_id = ?,
           razorpay_signature = ?,
           report_token = ?,
           paid_at = datetime('now')
         WHERE razorpay_order_id = ?`
      ).bind(razorpay_payment_id, razorpay_signature, accessToken, razorpay_order_id),
      env.DB.prepare(
        `INSERT INTO report_access (id, scan_id, user_id, token, module, r2_key, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      ).bind(
        accessId,
        scan_id || scanResult.scan_metadata?.scan_id || null,
        authCtx.user_id || null,
        accessToken,
        module,
        r2Stored ? r2Key : null,
        expiresAt,
      ),
    ]).catch(e => console.error('[Payments] D1 update failed:', e.message));

    await trackEvent(env, 'payment_completed', module, authCtx.user_id, ip, {
      razorpay_order_id,
      razorpay_payment_id,
      amount:   MODULE_PRICES[module]?.amount,
      target,
      report_id: reportId,
    });
  }

  // Fire-and-forget: GST invoice + purchase confirmation email
  const confirmedEmail = email || authCtx.email || null;
  const priceInr       = Math.round((MODULE_PRICES[module]?.amount || 0) / 100);
  Promise.all([
    (env.DB && priceInr)
      ? createInvoice(env.DB, {
          userId:      authCtx.user_id || razorpay_payment_id,
          email:       confirmedEmail || 'noreply@buyer',
          lineItems:   [{ description: MODULE_PRICES[module]?.name || module, amount_inr: priceInr, quantity: 1 }],
          paymentId:   razorpay_payment_id,
          paymentMethod: 'razorpay',
        }).catch(e => console.warn('[Payments] invoice error:', e.message))
      : Promise.resolve(),
    confirmedEmail
      ? sendPurchaseConfirmation(env, {
          to:          confirmedEmail,
          productName: MODULE_PRICES[module]?.name || `${module} Report`,
          amountInr:   priceInr,
          paymentId:   razorpay_payment_id,
          downloadUrl: `/api/reports/download/${accessToken}`,
          accessExpires: expiresAt,
        }).catch(e => console.warn('[Payments] email error:', e.message))
      : Promise.resolve(),
  ]).catch(() => {});

  return Response.json({
    success:      true,
    token:        accessToken,
    download_url: `/api/reports/download/${accessToken}`,
    report_id:    reportId,
    expires_at:   expiresAt,
    risk_score:   scanResult.risk_score,
    risk_level:   scanResult.risk_level,
    findings_count: (scanResult.findings || []).length,
    message:      `✅ Payment verified. Full ${MODULE_PRICES[module]?.name} ready for download.`,
  });
}

// ─── GET /api/reports/download/:token ────────────────────────────────────────
export async function handleReportDownload(request, env, authCtx = {}) {
  const url   = new URL(request.url);
  const token = url.pathname.split('/').pop();

  if (!token || token.length < 16) {
    return Response.json({ error: 'Invalid report token' }, { status: 400 });
  }

  // Fast KV lookup first
  let meta = null;
  if (env.SECURITY_HUB_KV) {
    const raw = await env.SECURITY_HUB_KV.get(`report_access:${token}`).catch(() => null);
    if (raw) meta = JSON.parse(raw);
  }

  // Fallback to D1
  if (!meta && env.DB) {
    const row = await env.DB.prepare(
      `SELECT token, module, r2_key, expires_at, downloaded_count
       FROM report_access WHERE token = ? LIMIT 1`
    ).bind(token).first().catch(() => null);
    if (row) meta = row;
  }

  if (!meta) {
    return Response.json({
      error:   'Report not found or expired.',
      message: 'Token may have expired (30 days) or is invalid. Contact bivash@cyberdudebivash.com',
    }, { status: 404 });
  }

  // Check expiry
  if (meta.expires_at && new Date(meta.expires_at) < new Date()) {
    return Response.json({ error: 'Report access token has expired.' }, { status: 410 });
  }

  // Retrieve HTML from R2
  if (env.SCAN_RESULTS && meta.r2_key) {
    const obj = await env.SCAN_RESULTS.get(meta.r2_key).catch(() => null);
    if (obj) {
      // Increment download counter (non-blocking)
      if (env.DB) {
        env.DB.prepare(
          `UPDATE report_access SET downloaded_count = downloaded_count + 1,
           last_downloaded_at = datetime('now') WHERE token = ?`
        ).bind(token).run().catch(() => {});
        trackEvent(env, 'report_downloaded', meta.module, authCtx.user_id,
          request.headers.get('CF-Connecting-IP'), { token });
      }

      const filename = `cbd-${meta.module ?? 'security'}-report.html`;
      return new Response(obj.body, {
        headers: {
          'Content-Type':        'text/html; charset=utf-8',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Cache-Control':       'private, no-store',
          'X-Report-Module':     meta.module || '',
          'X-Report-Expires':    meta.expires_at || '',
        },
      });
    }
  }

  return Response.json({
    error:   'Report file not found in storage.',
    support: 'bivash@cyberdudebivash.com',
    token,
  }, { status: 404 });
}

// ─── GET /api/payments/status/:orderId ───────────────────────────────────────
export async function handlePaymentStatus(request, env, authCtx = {}) {
  const orderId = new URL(request.url).pathname.split('/').pop();
  if (!orderId) return Response.json({ error: 'orderId required' }, { status: 400 });

  if (env.DB) {
    const row = await env.DB.prepare(
      `SELECT id, module, target, amount, status, report_token, paid_at, created_at
       FROM payments WHERE razorpay_order_id = ? LIMIT 1`
    ).bind(orderId).first().catch(() => null);

    if (!row) return Response.json({ error: 'Order not found' }, { status: 404 });

    return Response.json({
      order_id:    orderId,
      status:      row.status,
      module:      row.module,
      target:      row.target,
      amount_paise: row.amount,
      paid_at:     row.paid_at,
      created_at:  row.created_at,
      ...(row.status === 'paid' && row.report_token ? {
        download_url: `/api/reports/download/${row.report_token}`,
      } : {}),
    });
  }

  return Response.json({ error: 'Database not available' }, { status: 503 });
}

// ─── POST /api/webhooks/razorpay ──────────────────────────────────────────────
// Razorpay sends async confirmations — used as backup to frontend verification
export async function handleRazorpayWebhook(request, env) {
  const rawBody = await request.text();
  const sig     = request.headers.get('x-razorpay-signature') || '';

  const valid = await verifyWebhookSignature(env, rawBody, sig);
  if (!valid) {
    console.warn('[Webhook] Invalid Razorpay webhook signature');
    return Response.json({ error: 'Invalid signature' }, { status: 401 });
  }

  let event;
  try { event = JSON.parse(rawBody); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const type    = event.event;
  const payload = event.payload?.payment?.entity || {};

  console.log('[Webhook] Razorpay event:', type, 'order_id:', payload.order_id);

  if (type === 'payment.captured' || type === 'order.paid') {
    const orderId   = payload.order_id;
    const paymentId = payload.id;

    if (env.DB && orderId) {
      // Check if already verified via frontend
      const existing = await env.DB.prepare(
        `SELECT status FROM payments WHERE razorpay_order_id = ? LIMIT 1`
      ).bind(orderId).first().catch(() => null);

      if (existing?.status !== 'paid') {
        // Mark as paid — report generation will happen when user accesses download
        await env.DB.prepare(
          `UPDATE payments SET
             status = 'paid',
             razorpay_payment_id = ?,
             paid_at = datetime('now')
           WHERE razorpay_order_id = ? AND status = 'pending'`
        ).bind(paymentId, orderId).run().catch(e =>
          console.error('[Webhook] D1 update failed:', e.message)
        );
      }
    }
  }

  if (type === 'payment.failed') {
    const orderId = payload.order_id;
    if (env.DB && orderId) {
      await env.DB.prepare(
        `UPDATE payments SET status = 'failed' WHERE razorpay_order_id = ? AND status = 'pending'`
      ).bind(orderId).run().catch(() => {});
    }
  }

  return Response.json({ received: true });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function buildPayload(module, target, scan_id) {
  switch (module) {
    case 'domain':     return { domain: target };
    case 'ai':         return { model_name: target, use_case: 'chatbot' };
    case 'redteam':    return { target_org: target, scope: 'full' };
    case 'identity':   return { org_name: target, identity_provider: 'azure-ad' };
    case 'compliance': return { org_name: target, framework: 'iso27001' };
    default:           return { domain: target };
  }
}

// ─── POST /api/payment/confirm ────────────────────────────────────────────────
// Manual payment confirmation — customer submits txn ID after paying via UPI/Bank/Crypto/PayPal
// Sends admin notification email + customer confirmation email
// Reject obviously-fake / malformed transaction references while staying lenient
// enough never to block a genuine UPI UTR, bank ref, PayPal txn id, Razorpay
// payment id, or crypto tx hash. Returns an error string, or null if plausible.
// (A human still verifies the real transfer — this only stops junk like
// "0xw7rwerrwer" being recorded as a confirmed payment.)
export function validateManualTxnRef(raw, method) {
  const txn = String(raw || '').trim();
  if (txn.length < 6 || txn.length > 80) {
    return 'Enter the exact transaction reference from your payment app (6–80 characters).';
  }
  if (!/^[A-Za-z0-9._:\-]+$/.test(txn)) {
    return 'Transaction reference contains invalid characters — paste the exact ID from your receipt.';
  }
  // Anything that looks like a crypto hash (starts 0x) must be a full 0x + 64-hex
  // tx hash. Catches the classic "0x…junk" fake.
  if (/^0x/i.test(txn) && !/^0x[0-9a-fA-F]{64}$/.test(txn)) {
    return 'That is not a valid crypto transaction hash (expected 0x followed by 64 hex characters).';
  }
  if ((method || '').toLowerCase() === 'crypto' && !/^0x[0-9a-fA-F]{64}$/.test(txn)) {
    return 'Enter your on-chain transaction hash (0x followed by 64 hex characters).';
  }
  // Reject low-entropy junk (e.g. "aaaaaa", "121212") — real refs have ≥4 distinct chars.
  if (new Set(txn.toLowerCase().replace(/[^a-z0-9]/g, '')).size < 4) {
    return 'Transaction reference looks invalid — please paste the exact ID from your payment app.';
  }
  return null;
}

export async function handlePaymentConfirm(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { txnId, method, product, user: customerEmail, amount, notes, currency = 'INR' } = body;

  const txnRefErr = validateManualTxnRef(txnId, method);
  if (txnRefErr) {
    return Response.json({ error: txnRefErr, code: 'INVALID_TXN_REF' }, { status: 422 });
  }
  if (!customerEmail || !customerEmail.includes('@')) {
    return Response.json({ error: 'Valid customer email required' }, { status: 422 });
  }

  const confirmId = 'CDB-' + Date.now().toString(36).toUpperCase();
  const ts        = new Date().toUTCString();

  // ── Persist to D1 if available ──────────────────────────────────────────────
  try {
    if (env.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO payment_confirmations
         (id, txn_id, method, product, customer_email, amount, currency, notes, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_verification', ?)`
      ).bind(confirmId, txnId.trim(), method || 'UNKNOWN', product || 'unknown',
             customerEmail, amount || '', currency, notes || '', ts).run();
    }
  } catch (dbErr) {
    console.warn('[PaymentConfirm] DB write skipped:', dbErr.message);
  }

  // ── Send admin notification email ───────────────────────────────────────────
  try {
    const { sendEmail } = await import('../services/emailEngine.js');
    const adminHtml = `
<div style="font-family:monospace;background:#0a0e1a;color:#e2e8f0;padding:24px;border-radius:10px;border:2px solid #f59e0b">
  <h2 style="color:#f59e0b;margin:0 0 16px">💰 NEW PAYMENT CONFIRMATION</h2>
  <table style="width:100%;border-collapse:collapse">
    <tr><td style="padding:6px 0;color:#94a3b8;width:140px">Confirm ID</td><td style="color:#00d4ff;font-weight:700">${confirmId}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Transaction ID</td><td style="color:#22c55e;font-weight:900;font-size:16px">${txnId}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Method</td><td>${method || 'Not specified'}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Product</td><td style="color:#a78bfa">${product || 'Unknown'}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Amount</td><td style="color:#f59e0b;font-weight:700">${amount ? (currency + ' ' + amount) : 'See txn'}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Customer</td><td><a href="mailto:${customerEmail}" style="color:#00d4ff">${customerEmail}</a></td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Notes</td><td style="color:rgba(255,255,255,.6)">${notes || '—'}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Received At</td><td>${ts}</td></tr>
  </table>
  <div style="margin-top:20px;padding:14px;background:rgba(245,158,11,.1);border-radius:8px;border:1px solid rgba(245,158,11,.3)">
    ⚡ <strong>ACTION REQUIRED:</strong> Verify transaction on UPI/Bank/Crypto and activate customer access within 2–4 hours.
  </div>
</div>`;

    await sendEmail(env, {
      to:      'bivash@cyberdudebivash.com',
      subject: `[CDB PAYMENT] New confirmation — ${txnId} — ${product || 'unknown product'}`,
      html:    adminHtml,
      text:    `New payment confirmation:\nID: ${confirmId}\nTxn: ${txnId}\nMethod: ${method}\nProduct: ${product}\nAmount: ${amount} ${currency}\nCustomer: ${customerEmail}\nTime: ${ts}`,
    });
  } catch (emailErr) {
    console.error('[PaymentConfirm] Admin email failed:', emailErr.message);
    // Don't fail the request — log and continue
  }

  // ── Send customer confirmation email ────────────────────────────────────────
  try {
    const { sendEmail } = await import('../services/emailEngine.js');
    const custHtml = `
<div style="font-family:'Segoe UI',Arial,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:32px;border-radius:12px;max-width:560px;margin:0 auto">
  <div style="text-align:center;margin-bottom:24px">
    <div style="font-size:48px">✅</div>
    <h1 style="color:#22c55e;font-size:22px;margin:8px 0">Payment Received!</h1>
    <p style="color:#94a3b8;margin:0">Your confirmation has been logged successfully.</p>
  </div>
  <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:20px;margin-bottom:20px">
    <div style="font-size:12px;color:#6b7280;margin-bottom:4px">TRANSACTION ID</div>
    <div style="font-size:18px;font-weight:700;color:#00d4ff;font-family:monospace">${txnId}</div>
  </div>
  <p style="color:#94a3b8;line-height:1.7">Our team will verify your payment and <strong style="color:#e2e8f0">activate your access within 2–4 hours</strong>. You'll receive an access confirmation at this email once verified.</p>
  <p style="color:#94a3b8">Questions? Contact us at <a href="mailto:bivash@cyberdudebivash.com" style="color:#00d4ff">bivash@cyberdudebivash.com</a> or WhatsApp <a href="tel:+918179881447" style="color:#00d4ff">+91 8179881447</a></p>
  <div style="text-align:center;margin-top:24px;font-size:11px;color:#374151">CYBERDUDEBIVASH PRIVATE LIMITED · Odisha, India</div>
</div>`;

    await sendEmail(env, {
      to:      customerEmail,
      subject: `✅ Payment Confirmed — ${product || 'Your Purchase'} | Ref: ${confirmId}`,
      html:    custHtml,
      text:    `Payment confirmed! Transaction ID: ${txnId}\nRef: ${confirmId}\nProduct: ${product}\nOur team will activate access within 2-4 hours.\nContact: bivash@cyberdudebivash.com`,
    });
  } catch (emailErr) {
    console.error('[PaymentConfirm] Customer email failed:', emailErr.message);
  }

  return Response.json({
    success:    true,
    confirm_id: confirmId,
    message:    'Payment confirmation received. Access will be activated within 2–4 hours.',
    txn_id:     txnId,
  });
}
