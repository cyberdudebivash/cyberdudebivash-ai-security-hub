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

// ── Payment method config (update these before go-live) ─────────────────────
export const PAYMENT_CONFIG = {
  company_name:    'CyberDudeBivash Pvt. Ltd.',
  gst_number:      'GSTIN: 23XXXXX1234X1Z5',   // Update with real GSTIN
  support_email:   'iambivash.bn@gmail.com',
  verification_sla: '2–4 hours',

  upi: [
    { label: 'Primary UPI',   id: 'cyberdudebivash@upi',     type: 'upi' },
    { label: 'PhonePe / GPay', id: 'bivash@ibl',              type: 'upi' },
  ],

  bank: {
    account_name:   'CyberDudeBivash Pvt. Ltd.',
    account_number: 'XXXX XXXX XXXX 4321',   // Update before go-live
    ifsc:           'SBIN0001234',
    bank_name:      'State Bank of India',
    account_type:   'Current Account',
  },

  paypal: {
    email: 'iambivash.bn@gmail.com',
    note:  'Use "Goods & Services" for international payments',
  },

  crypto: [
    { coin: 'USDT (TRC-20)', address: 'TYour_USDT_TRC20_Address_Here', network: 'TRON' },
    { coin: 'BTC',           address: 'bc1q_Your_BTC_Address_Here',    network: 'Bitcoin' },
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

    await env.CDB_KV.put(`payment:record:${payment_id}`, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 180 }); // 180d

    // Append to index
    let index = [];
    try { index = JSON.parse(await env.CDB_KV.get('payment:index') || '[]'); } catch (_) {}
    index.unshift({ payment_id, status: 'pending', amount_inr: record.amount_inr, payer_email: record.payer_email, created_at: record.created_at, product_id });
    if (index.length > 500) index = index.slice(0, 500);
    await env.CDB_KV.put('payment:index', JSON.stringify(index));

    // User-level index
    let userIndex = [];
    try { userIndex = JSON.parse(await env.CDB_KV.get(`payment:user:${record.payer_email}`) || '[]'); } catch (_) {}
    userIndex.unshift({ payment_id, status: 'pending', amount_inr: record.amount_inr, product_id, created_at: record.created_at });
    await env.CDB_KV.put(`payment:user:${record.payer_email}`, JSON.stringify(userIndex), { expirationTtl: 60 * 60 * 24 * 365 });

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

    if (payment_id) {
      const record = JSON.parse(await env.CDB_KV.get(`payment:record:${payment_id}`) || 'null');
      if (!record) return jsonErr('Payment not found', 404);
      return jsonOk({ payment: record });
    }

    if (email) {
      const userIndex = JSON.parse(await env.CDB_KV.get(`payment:user:${email.toLowerCase()}`) || '[]');
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

    let index = JSON.parse(await env.CDB_KV.get('payment:index') || '[]');
    if (status !== 'all') index = index.filter(p => p.status === status);

    // Enrich with full records for first N
    const enriched = [];
    for (const entry of index.slice(0, Math.min(limit, 100))) {
      try {
        const record = JSON.parse(await env.CDB_KV.get(`payment:record:${entry.payment_id}`) || 'null');
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

// ── Admin: Approve / Reject payment ──────────────────────────────────────── */
export async function handleVerifyPayment(request, env) {
  try {
    const body = await request.json();
    const { payment_id, action, admin_note } = body; // action: 'approve' | 'reject'

    if (!payment_id || !['approve', 'reject'].includes(action)) {
      return jsonErr('Provide payment_id and action (approve|reject)', 400);
    }

    const record = JSON.parse(await env.CDB_KV.get(`payment:record:${payment_id}`) || 'null');
    if (!record) return jsonErr('Payment not found', 404);

    record.status      = action === 'approve' ? 'verified' : 'rejected';
    record.verified_at = new Date().toISOString();
    record.admin_note  = admin_note || '';

    await env.CDB_KV.put(`payment:record:${payment_id}`, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 180 });

    // Update index entry status
    let index = JSON.parse(await env.CDB_KV.get('payment:index') || '[]');
    index = index.map(p => p.payment_id === payment_id ? { ...p, status: record.status } : p);
    await env.CDB_KV.put('payment:index', JSON.stringify(index));

    // Update user index status
    let userIndex = JSON.parse(await env.CDB_KV.get(`payment:user:${record.payer_email}`) || '[]');
    userIndex = userIndex.map(p => p.payment_id === payment_id ? { ...p, status: record.status } : p);
    await env.CDB_KV.put(`payment:user:${record.payer_email}`, JSON.stringify(userIndex), { expirationTtl: 60 * 60 * 24 * 365 });

    // If approved — activate plan for user
    if (action === 'approve' && record.user_id && record.user_id !== 'anonymous') {
      const product = PRODUCT_CATALOG[record.product_id];
      if (product && product.plan_key) {
        await env.CDB_KV.put(
          `user:plan:${record.user_id}`,
          JSON.stringify({ plan: product.plan_key, activated_at: new Date().toISOString(), payment_id }),
          { expirationTtl: 60 * 60 * 24 * 400 }
        );
      }
    }

    return jsonOk({ payment_id, status: record.status, message: `Payment ${record.status}.` });
  } catch (e) {
    return jsonErr('Failed to verify payment: ' + e.message, 500);
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
