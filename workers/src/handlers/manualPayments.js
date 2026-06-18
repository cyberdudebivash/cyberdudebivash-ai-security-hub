/**
 * CYBERDUDEBIVASH AI Security Hub
 * Manual Payment System — Primary Revenue Engine
 * Handles UPI / Bank / PayPal / Crypto payment records + admin verification
 */

// Local response helpers — standalone, no request object required
function jsonOk(data, status = 200) {
  return new Response(JSON.stringify({ success: true, data, error: null, timestamp: new Date().toISOString() }), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Platform': 'CYBERDUDEBIVASH-AI-HUB' },
  });
}
function jsonErr(message, status = 500) {
  return new Response(JSON.stringify({ success: false, data: null, error: message, timestamp: new Date().toISOString() }), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Platform': 'CYBERDUDEBIVASH-AI-HUB' },
  });
}

// ── Payment method config — LIVE production details ──────────────────────────
export const PAYMENT_CONFIG = {
  company_name:    'CYBERDUDEBIVASH AI Security Hub',
  owner_name:      'Bivash Kumar Nayak',
  support_email:   'bivash@cyberdudebivash.com',
  billing_email:   'bivash@cyberdudebivash.com',
  whatsapp:        '+918179881447',
  verification_sla: '2–4 hours',

  // Primary UPI — works with PhonePe, GPay, Paytm, BHIM, any UPI app
  upi: [
    { label: 'Axis (Primary)',  id: 'iambivash.bn-5@okaxis',  type: 'upi' },
    { label: 'Axis Bank',       id: '6302177246@axisbank',    type: 'upi' },
  ],
  upi_deep_link: 'upi://pay?pa=iambivash.bn-5@okaxis&pn=CYBERDUDEBIVASH&cu=INR',
  upi_qr_url:    '/assets/payment/upi-qr.png',

  // Bank transfer — NEFT / IMPS / RTGS (24x7 via IMPS)
  bank: {
    account_name:   'Bivash Kumar Nayak',
    account_number: '915010024617260',
    ifsc:           'UTIB0000052',
    bank_name:      'Axis Bank',
    account_type:   'Savings Account',
    swift:          'AXISINBB',   // for international wire
  },

  // PayPal — for international customers
  paypal: {
    email:   'iambivash.bn@gmail.com',
    paypalme: 'https://www.paypal.com/paypalme/iambivash',
    note:    'Use "Friends & Family" to avoid fees. Add product name + email in the note.',
  },

  // Crypto — BNB Smart Chain + Ethereum (same address, BEP20/ERC20)
  crypto: [
    {
      coin:    'USDT / BNB / ETH (BEP20)',
      address: '0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796',
      network: 'BNB Smart Chain (BEP20)',
      note:    'Send ONLY on BNB Smart Chain or Ethereum. Wrong network = lost funds.',
    },
    {
      coin:    'USDT / ETH (ERC20)',
      address: '0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796',
      network: 'Ethereum Mainnet (ERC20)',
      note:    'TX Hash is your Transaction ID after sending.',
    },
  ],
};

// ── Product catalog ──────────────────────────────────────────────────────────
export const PRODUCT_CATALOG = {
  FREE:                 { name: 'Free Plan',              price_inr: 0,        plan_key: 'FREE' },
  STARTER:              { name: 'Starter Plan',           price_inr: 499,      plan_key: 'STARTER' },
  PRO:                  { name: 'Pro Plan',               price_inr: 1499,     plan_key: 'PRO' },
  ENTERPRISE:           { name: 'Enterprise Plan',        price_inr: 4999,     plan_key: 'ENTERPRISE' },
  MSSP:                 { name: 'MSSP Command',           price_inr: 9999,     plan_key: 'MSSP' },
  STARTER_PLUS_ANNUAL:  { name: 'Starter Plus (Annual)',  price_inr: 49900,    plan_key: 'STARTER_PLUS' },
  PROFESSIONAL_ANNUAL:  { name: 'Professional (Annual)',  price_inr: 149900,   plan_key: 'PROFESSIONAL' },
  ENTERPRISE_SHIELD:    { name: 'Enterprise Shield',      price_inr: 499900,   plan_key: 'ENTERPRISE_SHIELD' },
  MSSP_COMMAND:         { name: 'MSSP Command Suite',     price_inr: 1499900,  plan_key: 'MSSP_COMMAND' },
  THREAT_INTEL_REPORT:  { name: 'Threat Intelligence Report', price_inr: 14999, plan_key: 'REPORT' },
  API_PROFESSIONAL:     { name: 'API Access — Professional',  price_inr: 9999,  plan_key: 'API_PRO' },
};

// Reject obviously-fake / malformed transaction references while staying lenient
// enough never to block a genuine UPI UTR, bank ref, PayPal txn id, or crypto
// hash. Returns an error string, or null if plausible. A human still verifies the
// real transfer — this only stops junk like "0xw7rwerrwer" being recorded as paid.
function validateManualTxnRef(raw, method) {
  const txn = String(raw || '').trim();
  if (txn.length < 6 || txn.length > 80) {
    return 'Enter the exact transaction reference from your payment app (6–80 characters).';
  }
  if (!/^[A-Za-z0-9._:\-]+$/.test(txn)) {
    return 'Transaction reference contains invalid characters — paste the exact ID from your receipt.';
  }
  if (/^0x/i.test(txn) && !/^0x[0-9a-fA-F]{64}$/.test(txn)) {
    return 'That is not a valid crypto transaction hash (expected 0x followed by 64 hex characters).';
  }
  if ((method || '').toLowerCase() === 'crypto' && !/^0x[0-9a-fA-F]{64}$/.test(txn)) {
    return 'Enter your on-chain transaction hash (0x followed by 64 hex characters).';
  }
  if (new Set(txn.toLowerCase().replace(/[^a-z0-9]/g, '')).size < 4) {
    return 'Transaction reference looks invalid — please paste the exact ID from your payment app.';
  }
  return null;
}

// ── Submit payment ────────────────────────────────────────────────────────── */
export async function handleSubmitPayment(request, env) {
  try {
    const body = await request.json();
    const {
      user_id, product_id, amount_inr, payment_method,
      transaction_id, payer_name, payer_email,
      screenshot_url, notes
    } = body;

    if (!transaction_id || !payer_email || !product_id || !amount_inr) {
      return jsonErr('Missing required fields: transaction_id, payer_email, product_id, amount_inr', 400);
    }
    if (!['upi','bank','paypal','crypto'].includes(payment_method)) {
      return jsonErr('Invalid payment_method. Must be: upi | bank | paypal | crypto', 400);
    }
    const txnRefErr = validateManualTxnRef(transaction_id, payment_method);
    if (txnRefErr) {
      return jsonErr(txnRefErr, 422);
    }

    const payment_id = 'pay_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8).toUpperCase();
    const record = {
      payment_id,
      user_id:        user_id || 'anonymous',
      product_id,
      amount_inr:     parseFloat(amount_inr),
      payment_method,
      transaction_id: transaction_id.trim(),
      payer_name:     payer_name || '',
      payer_email:    payer_email.trim().toLowerCase(),
      screenshot_url: screenshot_url || null,
      notes:          notes || '',
      status:         'pending',           // pending → verified | rejected
      created_at:     new Date().toISOString(),
      verified_at:    null,
      verified_by:    null,
    };

    const KV = env.SECURITY_HUB_KV;
    await KV.put(`payment:record:${payment_id}`, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 180 }); // 180d

    // Append to index
    let index = [];
    try { index = JSON.parse(await KV.get('payment:index') || '[]'); } catch (_) {}
    index.unshift({ payment_id, status: 'pending', amount_inr: record.amount_inr, payer_email: record.payer_email, created_at: record.created_at, product_id });
    if (index.length > 500) index = index.slice(0, 500);
    await KV.put('payment:index', JSON.stringify(index));

    // User-level index
    let userIndex = [];
    try { userIndex = JSON.parse(await KV.get(`payment:user:${record.payer_email}`) || '[]'); } catch (_) {}
    userIndex.unshift({ payment_id, status: 'pending', amount_inr: record.amount_inr, product_id, created_at: record.created_at });
    await KV.put(`payment:user:${record.payer_email}`, JSON.stringify(userIndex), { expirationTtl: 60 * 60 * 24 * 365 });

    return jsonOk({
      payment_id,
      status: 'pending',
      message: `Payment recorded. Access will be activated within ${PAYMENT_CONFIG.verification_sla} after verification.`,
      support_email: PAYMENT_CONFIG.support_email,
    });
  } catch (e) {
    return jsonErr('Failed to submit payment: ' + e.message, 500);
  }
}

// ── Get payment status ────────────────────────────────────────────────────── */
export async function handleGetPaymentStatus(request, env) {
  try {
    const url = new URL(request.url);
    const payment_id = url.searchParams.get('payment_id');
    const email      = url.searchParams.get('email');

    const KV = env.SECURITY_HUB_KV;
    if (payment_id) {
      const record = JSON.parse(await KV.get(`payment:record:${payment_id}`) || 'null');
      if (!record) return jsonErr('Payment not found', 404);
      return jsonOk({ payment: record });
    }

    if (email) {
      const userIndex = JSON.parse(await KV.get(`payment:user:${email.toLowerCase()}`) || '[]');
      return jsonOk({ payments: userIndex });
    }

    return jsonErr('Provide payment_id or email', 400);
  } catch (e) {
    return jsonErr('Failed to get payment status: ' + e.message, 500);
  }
}

// ── Admin: List all payments ──────────────────────────────────────────────── */
export async function handleListPayments(request, env) {
  try {
    const url = new URL(request.url);
    const status = url.searchParams.get('status') || 'all';
    const limit  = parseInt(url.searchParams.get('limit') || '50');

    const KV = env.SECURITY_HUB_KV;
    let index = JSON.parse(await KV.get('payment:index') || '[]');
    if (status !== 'all') index = index.filter(p => p.status === status);

    // Enrich with full records for first N
    const enriched = [];
    for (const entry of index.slice(0, Math.min(limit, 100))) {
      try {
        const record = JSON.parse(await KV.get(`payment:record:${entry.payment_id}`) || 'null');
        if (record) enriched.push(record);
      } catch (_) { enriched.push(entry); }
    }

    const stats = {
      total: index.length,
      pending:  index.filter(p => p.status === 'pending').length,
      verified: index.filter(p => p.status === 'verified').length,
      rejected: index.filter(p => p.status === 'rejected').length,
      total_revenue_inr: index.filter(p => p.status === 'verified').reduce((s, p) => s + (p.amount_inr || 0), 0),
    };

    return jsonOk({ payments: enriched, stats });
  } catch (e) {
    return jsonErr('Failed to list payments: ' + e.message, 500);
  }
}

// ── Admin: Approve / Reject payment — shared core (KV mutation + plan activation) ──
async function verifyManualPaymentCore(env, payment_id, action, admin_note) {
  const KV = env.SECURITY_HUB_KV;
  const record = JSON.parse(await KV.get(`payment:record:${payment_id}`) || 'null');
  if (!record) return { error: 'Payment not found', status: 404 };

  record.status      = action === 'approve' ? 'verified' : 'rejected';
  record.verified_at = new Date().toISOString();
  record.admin_note  = admin_note || '';

  await KV.put(`payment:record:${payment_id}`, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 180 });

  // Update index entry status
  let index = JSON.parse(await KV.get('payment:index') || '[]');
  index = index.map(p => p.payment_id === payment_id ? { ...p, status: record.status } : p);
  await KV.put('payment:index', JSON.stringify(index));

  // Update user index status
  let userIndex = JSON.parse(await KV.get(`payment:user:${record.payer_email}`) || '[]');
  userIndex = userIndex.map(p => p.payment_id === payment_id ? { ...p, status: record.status } : p);
  await KV.put(`payment:user:${record.payer_email}`, JSON.stringify(userIndex), { expirationTtl: 60 * 60 * 24 * 365 });

  // If approved — activate plan for user
  if (action === 'approve' && record.user_id && record.user_id !== 'anonymous') {
    const product = PRODUCT_CATALOG[record.product_id];
    if (product && product.plan_key) {
      await KV.put(
        `user:plan:${record.user_id}`,
        JSON.stringify({ plan: product.plan_key, activated_at: new Date().toISOString(), payment_id }),
        { expirationTtl: 60 * 60 * 24 * 400 }
      );
    }
  }

  return { record };
}

export async function handleVerifyPayment(request, env) {
  try {
    const body = await request.json();
    const { payment_id, action, admin_note } = body; // action: 'approve' | 'reject'

    if (!payment_id || !['approve', 'reject'].includes(action)) {
      return jsonErr('Provide payment_id and action (approve|reject)', 400);
    }

    const result = await verifyManualPaymentCore(env, payment_id, action, admin_note);
    if (result.error) return jsonErr(result.error, result.status);

    return jsonOk({ payment_id, status: result.record.status, message: `Payment ${result.record.status}.` });
  } catch (e) {
    return jsonErr('Failed to verify payment: ' + e.message, 500);
  }
}

// ── Admin Payments Dashboard (admin-payments.html) ─────────────────────────
// This UI was built against a flat `{ payments: [...] }` / `{ total, pending, ... }`
// contract (record_id/user/txnId/method/product field names, 'approved' not
// 'verified') rather than the jsonOk-wrapped shape above. These adapters
// translate the same underlying KV data into that contract instead of
// duplicating the read/enrich logic.
const STATUS_TO_PANEL = { pending: 'pending', verified: 'approved', rejected: 'rejected' };
const ADMIN_LIST_ENRICH_CAP = 200;

function toAdminPanelShape(record) {
  return {
    record_id:   record.payment_id,
    status:      STATUS_TO_PANEL[record.status] || record.status,
    method:      String(record.payment_method || '').toUpperCase(),
    product:     PRODUCT_CATALOG[record.product_id]?.name || record.product_id,
    user:        record.payer_email,
    txnId:       record.transaction_id,
    amount:      record.amount_inr,
    currency:    'INR',
    created_at:  record.created_at,
    admin_notes: record.admin_note || '',
  };
}

// GET /api/payment/admin/list
export async function handleAdminPaymentList(request, env) {
  try {
    const url    = new URL(request.url);
    const status = url.searchParams.get('status') || 'all';
    const limit  = parseInt(url.searchParams.get('limit') || String(ADMIN_LIST_ENRICH_CAP));

    const KV = env.SECURITY_HUB_KV;
    let index = JSON.parse(await KV.get('payment:index') || '[]');
    if (status !== 'all') index = index.filter(p => p.status === status);

    const payments = [];
    for (const entry of index.slice(0, Math.min(limit, ADMIN_LIST_ENRICH_CAP))) {
      try {
        const record = JSON.parse(await KV.get(`payment:record:${entry.payment_id}`) || 'null');
        payments.push(toAdminPanelShape(record || entry));
      } catch (_) { payments.push(toAdminPanelShape(entry)); }
    }

    return Response.json({ payments });
  } catch (e) {
    return Response.json({ payments: [], detail: 'Failed to list payments: ' + e.message }, { status: 500 });
  }
}

// GET /api/payment/admin/stats
export async function handleAdminPaymentStats(request, env) {
  try {
    const KV    = env.SECURITY_HUB_KV;
    const index = JSON.parse(await KV.get('payment:index') || '[]');

    const stats = {
      total:    index.length,
      pending:  index.filter(p => p.status === 'pending').length,
      approved: index.filter(p => p.status === 'verified').length,
      rejected: index.filter(p => p.status === 'rejected').length,
      by_method: { UPI: 0, BANK: 0, PAYPAL: 0, CRYPTO: 0 },
    };

    // by_method needs payment_method, which isn't in the lightweight index entry —
    // enrich the most recent records only (matches the list endpoint's cap).
    for (const entry of index.slice(0, ADMIN_LIST_ENRICH_CAP)) {
      try {
        const record = JSON.parse(await KV.get(`payment:record:${entry.payment_id}`) || 'null');
        const m = String(record?.payment_method || '').toUpperCase();
        if (m && stats.by_method[m] !== undefined) stats.by_method[m]++;
      } catch (_) {}
    }

    return Response.json(stats);
  } catch (e) {
    return Response.json({
      total: 0, pending: 0, approved: 0, rejected: 0, by_method: {},
      detail: 'Failed to load stats: ' + e.message,
    }, { status: 500 });
  }
}

// POST /api/payment/admin/approve/:record_id or /api/payment/admin/reject/:record_id
export async function handleAdminPaymentAction(request, env, recordId, action) {
  try {
    if (!recordId) return Response.json({ detail: 'record_id required' }, { status: 400 });
    if (!['approve', 'reject'].includes(action)) {
      return Response.json({ detail: 'Invalid action' }, { status: 400 });
    }

    let notes = null;
    try { ({ notes } = await request.json()); } catch (_) {}

    const result = await verifyManualPaymentCore(env, recordId, action, notes);
    if (result.error) return Response.json({ detail: result.error }, { status: result.status });

    return Response.json({
      success: true,
      record_id: recordId,
      status: STATUS_TO_PANEL[result.record.status] || result.record.status,
    });
  } catch (e) {
    return Response.json({ detail: `Failed to ${action} payment: ` + e.message }, { status: 500 });
  }
}

// ── Get payment config (for frontend modal) ───────────────────────────────── */
export async function handleGetPaymentConfig(request, env) {
  try {
    // Return config without sensitive details
    return jsonOk({
      config: {
        company_name:    PAYMENT_CONFIG.company_name,
        gst_number:      PAYMENT_CONFIG.gst_number,
        support_email:   PAYMENT_CONFIG.support_email,
        verification_sla: PAYMENT_CONFIG.verification_sla,
        upi:    PAYMENT_CONFIG.upi,
        bank:   PAYMENT_CONFIG.bank,
        paypal: PAYMENT_CONFIG.paypal,
        crypto: PAYMENT_CONFIG.crypto,
      },
      products: PRODUCT_CATALOG,
    });
  } catch (e) {
    return jsonErr('Failed to get payment config: ' + e.message, 500);
  }
}
