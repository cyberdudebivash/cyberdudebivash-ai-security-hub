/**
 * CYBERDUDEBIVASH v27 — Assessment Booking Handler
 * Primary revenue product: Security Assessment (Rs9,999+)
 *
 * POST /api/assessments/book         -> book + create Razorpay order
 * POST /api/assessments/confirm      -> confirm payment + activate
 * GET  /api/assessments/:id          -> get assessment status (auth)
 * GET  /api/assessments              -> list (admin)
 * PUT  /api/assessments/:id/status   -> update status (admin)
 */

import { createRazorpayOrder, verifyPaymentSignature, generateReceiptId } from '../lib/razorpay.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}
function err(msg, status = 400) { return json({ success: false, error: msg }, status); }

const ASSESSMENT_PLANS = {
  standard:   { price_inr: 9999,  label: 'Standard Assessment',   delivery_h: 72  },
  premium:    { price_inr: 19999, label: 'Premium Assessment',    delivery_h: 48  },
  enterprise: { price_inr: 49999, label: 'Enterprise Assessment', delivery_h: 24  },
};

// ── POST /api/assessments/book ────────────────────────────────────────────────
export async function handleBookAssessment(request, env) {
  let body;
  try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const email   = (body.email || '').trim().toLowerCase();
  const company = (body.company || '').trim();
  const domain  = (body.domain  || '').trim();
  const phone   = (body.phone   || '').trim();
  const plan    = (body.plan    || 'standard').toLowerCase();

  if (!email || !email.includes('@')) return err('Valid email required');
  if (!domain) return err('Domain required');

  const planInfo = ASSESSMENT_PLANS[plan];
  if (!planInfo) return err('Invalid plan. Valid: standard, premium, enterprise');

  const assessId  = 'asmnt_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7);
  const receiptId = generateReceiptId('assessment');

  // Create Razorpay order
  let rzpOrder = null;
  let keyId = null;
  try {
    const rzpRes = await createRazorpayOrder(env, {
      amount:          planInfo.price_inr * 100,
      currency:        'INR',
      receipt:         receiptId,
      notes:           { assessment_id: assessId, email, domain, plan },
    });
    rzpOrder = rzpRes.order;
    keyId    = rzpRes.key_id;
  } catch(e) {
    console.error('[Assessment] Razorpay order failed:', e.message);
    // Still create the booking record — allow manual payment fallback
  }

  // Write assessment record to D1
  try {
    await env.DB.prepare(
      "INSERT INTO assessments (id,email,company,domain,phone,plan,price_inr,status,razorpay_order,delivery_sla_h) VALUES (?,?,?,?,?,?,?,?,?,?)"
    ).bind(
      assessId, email, company || null, domain, phone || null,
      plan, planInfo.price_inr,
      rzpOrder ? 'booked' : 'booked_manual',
      rzpOrder?.id || null,
      planInfo.delivery_h
    ).run();
  } catch(dbErr) {
    console.error('[Assessment] D1 insert failed:', dbErr.message);
    return err('Booking record failed. Contact support.', 500);
  }

  // Track funnel event
  try {
    const fevId = 'fev_' + Date.now().toString(36);
    await env.DB.prepare(
      "INSERT INTO funnel_events (id, email, stage, meta) VALUES (?,?,?,?)"
    ).bind(fevId, email, 'assessment_booked',
      JSON.stringify({ plan, price_inr: planInfo.price_inr, domain })
    ).run();
  } catch { /* non-blocking */ }

  // Send confirmation email (non-blocking)
  try {
    await env.SECURITY_HUB_KV?.put(
      'pending_email:assessment_booked:' + assessId,
      JSON.stringify({ to: email, assessment_id: assessId, plan, domain, price: planInfo.price_inr }),
      { expirationTtl: 86400 }
    );
  } catch { /* non-blocking */ }

  return json({
    success: true,
    assessment_id: assessId,
    plan,
    price_inr: planInfo.price_inr,
    delivery_sla_hours: planInfo.delivery_h,
    razorpay: rzpOrder ? {
      order_id: rzpOrder.id,
      amount:   rzpOrder.amount,
      currency: rzpOrder.currency,
      key_id:   keyId,
    } : null,
    next: rzpOrder
      ? 'Complete payment to confirm your assessment booking.'
      : 'Manual payment required. Contact bivash@cyberdudebivash.com',
  }, 201);
}

// ── POST /api/assessments/confirm ────────────────────────────────────────────
export async function handleConfirmAssessment(request, env) {
  let body;
  try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, assessment_id } = body;
  if (!razorpay_payment_id || !razorpay_signature) return err('Payment details required');

  // Verify Razorpay signature
  const valid = await verifyPaymentSignature(env, {
    order_id: razorpay_order_id, payment_id: razorpay_payment_id, signature: razorpay_signature,
  });
  if (!valid) return err('Payment verification failed', 400);

  // Update assessment status in D1
  try {
    await env.DB.prepare(
      "UPDATE assessments SET status='paid', payment_ref=?, paid_at=unixepoch() WHERE id=? OR razorpay_order=?"
    ).bind(razorpay_payment_id, assessment_id || '', razorpay_order_id || '').run();
  } catch(e) {
    return err('Status update failed: ' + e.message, 500);
  }

  // Update platform metrics
  try {
    await env.DB.prepare(
      "UPDATE platform_metrics SET value_int=value_int+1, updated_at=unixepoch() WHERE key='total_assessments'"
    ).run();
  } catch { /* non-blocking */ }

  return json({
    success: true,
    status: 'paid',
    message: 'Assessment confirmed. Your analyst will contact you within 4 hours.',
    assessment_id: assessment_id || razorpay_order_id,
    payment_id: razorpay_payment_id,
  });
}

// ── GET /api/assessments/:id ─────────────────────────────────────────────────
export async function handleGetAssessment(request, env, authCtx) {
  const url = new URL(request.url);
  const id  = url.pathname.split('/').pop();
  if (!id || id === 'assessments') return err('Assessment ID required');

  const row = await env.DB.prepare(
    "SELECT id,email,company,domain,plan,price_inr,status,report_url,delivery_sla_h,booked_at,paid_at,delivered_at FROM assessments WHERE id=?"
  ).bind(id).first();

  if (!row) return err('Assessment not found', 404);

  // Non-admin: only own assessments
  if (authCtx?.role !== 'admin' && authCtx?.email !== row.email) {
    return err('Access denied', 403);
  }

  return json({ success: true, assessment: row });
}

// ── GET /api/assessments (admin list) ────────────────────────────────────────
export async function handleListAssessments(request, env, authCtx) {
  if (authCtx?.role !== 'admin') return err('Admin only', 403);
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const status = url.searchParams.get('status') || null;

  const rows = status
    ? await env.DB.prepare(
        "SELECT * FROM assessments WHERE status=? ORDER BY booked_at DESC LIMIT ?"
      ).bind(status, limit).all()
    : await env.DB.prepare(
        "SELECT * FROM assessments ORDER BY booked_at DESC LIMIT ?"
      ).bind(limit).all();

  return json({ success: true, assessments: rows.results || [], total: rows.results?.length || 0 });
}

// ── PUT /api/assessments/:id/status (admin) ─────────────────────────────────
export async function handleUpdateAssessmentStatus(request, env, authCtx) {
  if (authCtx?.role !== 'admin') return err('Admin only', 403);
  const url = new URL(request.url);
  const id  = url.pathname.split('/').slice(-2)[0];

  let body;
  try { body = await request.json(); } catch { return err('Invalid JSON'); }

  const newStatus  = body.status;
  const reportUrl  = body.report_url;
  const notes      = body.analyst_notes;
  const validStatuses = ['booked','paid','in_progress','delivered','completed','cancelled'];

  if (!validStatuses.includes(newStatus)) return err('Invalid status');

  const deliveredAt = newStatus === 'delivered' ? ', delivered_at=unixepoch()' : '';
  const completedAt = newStatus === 'completed'  ? ', completed_at=unixepoch()' : '';
  const startedAt   = newStatus === 'in_progress'? ', started_at=unixepoch()' : '';

  await env.DB.prepare(
    `UPDATE assessments SET status=?${deliveredAt}${completedAt}${startedAt}
     ${reportUrl ? ', report_url=?' : ''}
     ${notes     ? ', analyst_notes=?' : ''}
     WHERE id=?`
  ).bind(...[newStatus, reportUrl, notes, id].filter(x => x !== undefined && x !== null)).run();

  return json({ success: true, id, status: newStatus });
}
