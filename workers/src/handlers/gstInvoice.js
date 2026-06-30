/**
 * CYBERDUDEBIVASH AI Security Hub — GST Invoice Engine
 * India GST-compliant invoice generation for B2B procurement
 *
 * GET  /api/billing/invoices            → list user's invoices
 * GET  /api/billing/invoice/:id         → get specific invoice JSON
 * POST /api/billing/invoice/generate    → generate GST invoice for a payment
 *
 * GST Details:
 *   - SAC Code: 998313 (Information technology (IT) consulting and support services)
 *   - Tax: 18% GST (IGST for interstate / CGST+SGST 9%+9% for intrastate Karnataka)
 *   - Platform GSTIN: must be set in env as PLATFORM_GSTIN
 */

import { corsHeaders } from '../middleware/cors.js';

// ─── Platform identity ────────────────────────────────────────────────────────
const PLATFORM = {
  name:     'CYBERDUDEBIVASH Technology Solutions',
  address:  'Bengaluru, Karnataka — 560001',
  state:    'Karnataka',
  state_code: '29',
  email:    'billing@cyberdudebivash.in',
  website:  'https://cyberdudebivash.in',
  sac_code: '998313',
  hsn_desc: 'Information Technology (IT) Consulting and Support Services',
};

const GST_RATE = 0.18;

function generateInvoiceNumber(seq) {
  const now   = new Date();
  const fy    = now.getMonth() >= 3 ? now.getFullYear() : now.getFullYear() - 1;
  const fyStr = `${fy.toString().slice(2)}${(fy + 1).toString().slice(2)}`;
  return `CBD/${fyStr}/${String(seq).padStart(5, '0')}`;
}

function formatINR(paise) {
  const inr = (paise || 0) / 100;
  return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(inr);
}

function numberToWords(num) {
  if (num === 0) return 'Zero';
  const ones = ['', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine',
                 'Ten', 'Eleven', 'Twelve', 'Thirteen', 'Fourteen', 'Fifteen', 'Sixteen',
                 'Seventeen', 'Eighteen', 'Nineteen'];
  const tens = ['', '', 'Twenty', 'Thirty', 'Forty', 'Fifty', 'Sixty', 'Seventy', 'Eighty', 'Ninety'];

  function helper(n) {
    if (n < 20) return ones[n];
    if (n < 100) return tens[Math.floor(n / 10)] + (n % 10 ? ' ' + ones[n % 10] : '');
    if (n < 1000) return ones[Math.floor(n / 100)] + ' Hundred' + (n % 100 ? ' ' + helper(n % 100) : '');
    if (n < 100000) return helper(Math.floor(n / 1000)) + ' Thousand' + (n % 1000 ? ' ' + helper(n % 1000) : '');
    if (n < 10000000) return helper(Math.floor(n / 100000)) + ' Lakh' + (n % 100000 ? ' ' + helper(n % 100000) : '');
    return helper(Math.floor(n / 10000000)) + ' Crore' + (n % 10000000 ? ' ' + helper(n % 10000000) : '');
  }
  return helper(Math.round(num));
}

function buildInvoiceObject({ invoiceNo, payment, customer, platformGstin, seq }) {
  const amountPaise    = payment.amount || 0;
  const baseAmount     = Math.round(amountPaise / (1 + GST_RATE));
  const gstAmount      = amountPaise - baseAmount;
  const customerState  = customer.state || '';
  const isInterstate   = customerState.toLowerCase() !== 'karnataka' && customerState !== '';

  const taxLines = isInterstate
    ? [{ type: 'IGST', rate: 18, amount_paise: gstAmount }]
    : [
        { type: 'CGST', rate: 9, amount_paise: Math.round(gstAmount / 2) },
        { type: 'SGST', rate: 9, amount_paise: gstAmount - Math.round(gstAmount / 2) },
      ];

  return {
    invoice_number:   invoiceNo,
    invoice_date:     new Date().toISOString().slice(0, 10),
    due_date:         new Date().toISOString().slice(0, 10), // on receipt
    invoice_type:     'TAX INVOICE',
    currency:         'INR',
    payment_id:       payment.payment_id || payment.order_id,
    razorpay_order:   payment.order_id,
    status:           'PAID',

    supplier: {
      name:       PLATFORM.name,
      address:    PLATFORM.address,
      gstin:      platformGstin || env?.BUSINESS_GST || 'PENDING_REGISTRATION',
      state:      PLATFORM.state,
      state_code: PLATFORM.state_code,
      email:      PLATFORM.email,
      website:    PLATFORM.website,
    },

    customer: {
      name:         customer.name || customer.email,
      email:        customer.email,
      company:      customer.company || '',
      gstin:        customer.gstin || '',
      address:      customer.billing_address || '',
      state:        customer.state || '',
      state_code:   customer.state_code || '',
    },

    line_items: [
      {
        sr:          1,
        description: payment.module
          ? `${payment.module.replace('subscription:', '').toUpperCase()} Plan — CYBERDUDEBIVASH AI Security Platform`
          : 'CYBERDUDEBIVASH AI Security Hub — Subscription / Service',
        sac_code:    PLATFORM.sac_code,
        hsn_desc:    PLATFORM.hsn_desc,
        quantity:    1,
        unit:        'Month',
        rate_paise:  baseAmount,
        taxable_value_paise: baseAmount,
      },
    ],

    totals: {
      subtotal_paise:    baseAmount,
      tax_lines:         taxLines,
      total_tax_paise:   gstAmount,
      grand_total_paise: amountPaise,
      subtotal_inr:      formatINR(baseAmount),
      total_tax_inr:     formatINR(gstAmount),
      grand_total_inr:   formatINR(amountPaise),
      amount_in_words:   numberToWords(Math.round(amountPaise / 100)) + ' Rupees Only',
    },

    notes: [
      'This is a computer-generated invoice. No signature required.',
      'Payment received via Razorpay — HTTPS secure gateway.',
      `GST SAC Code: ${PLATFORM.sac_code} — ${PLATFORM.hsn_desc}`,
      'For support: billing@cyberdudebivash.in',
    ],

    generated_at:  new Date().toISOString(),
    generated_by:  'CYBERDUDEBIVASH GST Invoice Engine v1.0',
    itc_eligible:  !!customer.gstin,
    itc_note:      customer.gstin
      ? `Input Tax Credit eligible. GSTIN: ${customer.gstin}`
      : 'Provide your GSTIN to claim Input Tax Credit (ITC).',
  };
}

// ─── GET /api/billing/invoices — list user invoices ──────────────────────────
export async function handleListInvoices(request, env, authCtx) {
  const headers = corsHeaders(request);
  const userId = authCtx?.user_id || authCtx?.userId;
  const email  = authCtx?.email;

  if (!userId && !email) {
    return Response.json({ error: 'Authentication required.' }, { status: 401 });
  }

  const url   = new URL(request.url);
  const page  = parseInt(url.searchParams.get('page') || '1');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
  const offset = (page - 1) * limit;

  let payments = [];
  try {
    const query = userId
      ? `SELECT razorpay_order_id, razorpay_payment_id, module, amount, currency, status, email, created_at
         FROM payments WHERE email = (SELECT email FROM users WHERE id = ?) OR email = ?
         ORDER BY created_at DESC LIMIT ? OFFSET ?`
      : `SELECT razorpay_order_id, razorpay_payment_id, module, amount, currency, status, email, created_at
         FROM payments WHERE email = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;

    const rows = userId
      ? await env.DB.prepare(query).bind(userId, email || '', limit, offset).all()
      : await env.DB.prepare(query).bind(email, limit, offset).all();

    payments = rows?.results || [];
  } catch (_) {}

  const invoices = payments.map((p, i) => ({
    invoice_number: generateInvoiceNumber(offset + i + 1),
    payment_id:     p.razorpay_payment_id || p.razorpay_order_id,
    order_id:       p.razorpay_order_id,
    module:         p.module,
    amount_inr:     formatINR(p.amount),
    amount_paise:   p.amount,
    status:         p.status === 'captured' ? 'PAID' : p.status || 'PENDING',
    date:           p.created_at?.slice(0, 10),
    download_url:   `/api/billing/invoice/${p.razorpay_order_id || p.razorpay_payment_id}`,
  }));

  return Response.json({
    success: true,
    data: {
      invoices,
      total: invoices.length,
      page,
      limit,
      gstin_note: 'Provide your GSTIN via POST /api/billing/invoice/generate to get ITC-eligible invoices.',
    },
  }, { headers: { ...headers, 'Content-Type': 'application/json' } });
}

// ─── GET /api/billing/invoice/:id — get single invoice ───────────────────────
export async function handleGetInvoice(request, env, authCtx, invoiceId) {
  const headers = corsHeaders(request);
  const email   = authCtx?.email;
  const userId  = authCtx?.user_id || authCtx?.userId;

  if (!userId && !email) {
    return Response.json({ error: 'Authentication required.' }, { status: 401 });
  }

  let payment = null;
  try {
    const q = userId
      ? `SELECT p.* FROM payments p
         LEFT JOIN users u ON u.email = p.email
         WHERE (p.razorpay_order_id = ? OR p.razorpay_payment_id = ?) AND (u.id = ? OR p.email = ?)`
      : `SELECT * FROM payments WHERE (razorpay_order_id = ? OR razorpay_payment_id = ?) AND email = ?`;

    payment = userId
      ? await env.DB.prepare(q).bind(invoiceId, invoiceId, userId, email || '').first()
      : await env.DB.prepare(q).bind(invoiceId, invoiceId, email).first();
  } catch (_) {}

  if (!payment) {
    return Response.json({ error: 'Invoice not found or access denied.' }, { status: 404 });
  }

  const seq = 1;
  const invoiceNo = generateInvoiceNumber(seq);
  const platformGstin = env.PLATFORM_GSTIN || env.BUSINESS_GST || '';

  const customer = {
    email:   payment.email,
    name:    payment.email?.split('@')[0],
    company: '',
    gstin:   '',
    state:   '',
  };

  // Normalize payment fields to expected shape
  payment.order_id   = payment.razorpay_order_id;
  payment.payment_id = payment.razorpay_payment_id;

  const invoice = buildInvoiceObject({ invoiceNo, payment, customer, platformGstin, seq });

  return Response.json({ success: true, data: invoice }, {
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}

// ─── POST /api/billing/invoice/generate — generate full GST invoice ───────────
export async function handleGenerateInvoice(request, env, authCtx) {
  const headers = corsHeaders(request);
  const userId = authCtx?.user_id || authCtx?.userId;
  const email  = authCtx?.email;

  if (!userId && !email) {
    return Response.json({ error: 'Authentication required.' }, { status: 401 });
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}

  const {
    order_id,
    customer_name    = '',
    customer_company = '',
    customer_gstin   = '',
    customer_address = '',
    customer_state   = '',
    customer_state_code = '',
  } = body;

  if (!order_id) {
    return Response.json({ error: 'order_id is required.' }, { status: 400 });
  }

  let payment = null;
  try {
    payment = await env.DB.prepare(
      `SELECT * FROM payments WHERE razorpay_order_id = ? AND email IN (
         SELECT email FROM users WHERE id = ?
         UNION SELECT ?
       )`
    ).bind(order_id, userId || '', email || '').first();
    if (payment) {
      payment.order_id   = payment.razorpay_order_id;
      payment.payment_id = payment.razorpay_payment_id;
    }
  } catch (_) {}

  if (!payment) {
    return Response.json({ error: 'Payment not found or access denied.' }, { status: 404 });
  }

  // Get invoice sequence number
  let seq = 1;
  try {
    const countRow = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM report_jobs WHERE type = 'gst_invoice'`
    ).first();
    seq = (countRow?.cnt || 0) + 1;
  } catch (_) {}

  const invoiceNo     = generateInvoiceNumber(seq);
  const platformGstin = env.PLATFORM_GSTIN || env.BUSINESS_GST || '';

  const customer = {
    email:           payment.email,
    name:            customer_name || payment.email,
    company:         customer_company,
    gstin:           customer_gstin,
    billing_address: customer_address,
    state:           customer_state,
    state_code:      customer_state_code,
  };

  const invoice = buildInvoiceObject({ invoiceNo, payment, customer, platformGstin, seq });
  const invoiceId = 'inv_' + Date.now().toString(36);

  // Store in D1
  if (env.DB && userId) {
    await env.DB.prepare(
      `INSERT INTO report_jobs (id, type, user_id, status, result_score, result_json, created_at, completed_at)
       VALUES (?, 'gst_invoice', ?, 'completed', 100, ?, datetime('now'), datetime('now'))`
    ).bind(invoiceId, userId, JSON.stringify(invoice)).run().catch(() => {});
  }

  return Response.json({
    success: true,
    data:    invoice,
    message: 'GST invoice generated. Share invoice_number with your finance team for ITC claim.',
  }, { headers: { ...headers, 'Content-Type': 'application/json' } });
}
