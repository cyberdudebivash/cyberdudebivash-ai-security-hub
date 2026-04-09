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
  createRazorpayOrder,
  verifyPaymentSignature,
  verifyWebhookSignature,
  generateReceiptId,
  generateAccessToken,
} from '../lib/razorpay.js';
import { generateHTMLReport } from '../lib/htmlReport.js';
import { buildReport }        from '../lib/reportEngine.js';
import { trackEvent }         from './analytics.js';

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

// Auth context used for full (paid) scans — bypasses all monetization gates
const PAID_AUTH_CTX = {
  authenticated: true,
  method:        'payment_verified',
  identity:      'paid_report',
  user_id:       null,
  tier:          'ENTERPRISE',
  limits:        { daily_limit: -1, burst_per_min: 60 },
};

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
    const scanResp = await SCAN_HANDLERS[module](synReq, env, {
      ...PAID_AUTH_CTX,
      user_id: authCtx.user_id || null,
      email:   email || authCtx.email || null,
    });
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
