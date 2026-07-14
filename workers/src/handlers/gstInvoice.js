/**
 * CYBERDUDEBIVASH AI Security Hub — GST Invoice Engine
 * India GST-compliant invoice generation for B2B procurement
 *
 * GET  /api/billing/invoices            → list user's invoices
 * GET  /api/billing/invoice/:id         → get specific invoice JSON
 * POST /api/billing/invoice/generate    → generate GST invoice for a payment
 *
 * This handler is a read/write façade over the single invoice authority:
 * the `invoices` table + createInvoice() (workers/src/services/v24/billingEngine.js),
 * the same engine the core Razorpay payment-success path and every
 * marketplace purchase flow already write to. It never mints its own
 * invoice numbers — every number in the system comes from that one place.
 *
 * GST Details:
 *   - SAC Code: 998313 (Information technology (IT) consulting and support services)
 *   - Tax: 18% GST (IGST for interstate / CGST+SGST 9%+9% for intrastate Karnataka)
 *   - Platform GSTIN: must be set in env as PLATFORM_GSTIN
 */

import { corsHeaders } from '../middleware/cors.js';
import { createInvoice } from '../services/v24/billingEngine.js';

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

function safeParseJSON(text, fallback) {
  try {
    const v = JSON.parse(text);
    return v == null ? fallback : v;
  } catch (_) { return fallback; }
}

// Builds the rich GST invoice envelope from a persisted `invoices` row.
// Never computes or reassigns invoice_number — it only ever displays the
// stable value already stored on the row.
function buildInvoiceObject(invoiceRow, platformGstin) {
  const lineItemsRaw = safeParseJSON(invoiceRow.line_items, []);
  const billingAddr  = safeParseJSON(invoiceRow.billing_address, {});
  const customerState = billingAddr.state || '';
  const isInterstate   = customerState.toLowerCase() !== 'karnataka' && customerState !== '';

  const subtotalPaise = Math.round((invoiceRow.subtotal_inr || 0) * 100);
  const gstPaise      = Math.round((invoiceRow.gst_amount_inr || 0) * 100);
  const totalPaise    = Math.round((invoiceRow.total_inr || 0) * 100);

  const taxLines = isInterstate
    ? [{ type: 'IGST', rate: 18, amount_paise: gstPaise }]
    : [
        { type: 'CGST', rate: 9, amount_paise: Math.round(gstPaise / 2) },
        { type: 'SGST', rate: 9, amount_paise: gstPaise - Math.round(gstPaise / 2) },
      ];

  const items = lineItemsRaw.length ? lineItemsRaw : [{
    description: 'CYBERDUDEBIVASH AI Security Hub — Subscription / Service',
    amount_inr:  invoiceRow.subtotal_inr || 0,
    quantity:    1,
  }];

  const line_items = items.map((item, i) => ({
    sr:          i + 1,
    description: item.description || 'CYBERDUDEBIVASH AI Security Hub — Subscription / Service',
    sac_code:    PLATFORM.sac_code,
    hsn_desc:    PLATFORM.hsn_desc,
    quantity:    item.quantity || 1,
    unit:        item.unit || 'Unit',
    rate_paise:  Math.round((item.amount_inr || 0) * 100),
    taxable_value_paise: Math.round((item.amount_inr || 0) * 100),
  }));

  return {
    invoice_number:   invoiceRow.invoice_number,
    invoice_date:     (invoiceRow.created_at || '').slice(0, 10),
    due_date:         (invoiceRow.due_date || invoiceRow.created_at || '').slice(0, 10),
    invoice_type:     'TAX INVOICE',
    currency:         invoiceRow.currency || 'INR',
    payment_id:       invoiceRow.payment_id || '',
    status:           invoiceRow.status === 'paid' ? 'PAID' : String(invoiceRow.status || 'PENDING').toUpperCase(),

    supplier: {
      name:       PLATFORM.name,
      address:    PLATFORM.address,
      gstin:      platformGstin || 'PENDING_REGISTRATION',
      state:      PLATFORM.state,
      state_code: PLATFORM.state_code,
      email:      PLATFORM.email,
      website:    PLATFORM.website,
    },

    customer: {
      name:         invoiceRow.company || invoiceRow.email,
      email:        invoiceRow.email,
      company:      invoiceRow.company || '',
      gstin:        invoiceRow.gstin || '',
      address:      billingAddr.address || '',
      state:        billingAddr.state || '',
      state_code:   billingAddr.state_code || '',
    },

    line_items,

    totals: {
      subtotal_paise:    subtotalPaise,
      tax_lines:         taxLines,
      total_tax_paise:   gstPaise,
      grand_total_paise: totalPaise,
      subtotal_inr:      formatINR(subtotalPaise),
      total_tax_inr:     formatINR(gstPaise),
      grand_total_inr:   formatINR(totalPaise),
      amount_in_words:   numberToWords(Math.round(totalPaise / 100)) + ' Rupees Only',
    },

    notes: [
      'This is a computer-generated invoice. No signature required.',
      'Payment received via Razorpay — HTTPS secure gateway.',
      `GST SAC Code: ${PLATFORM.sac_code} — ${PLATFORM.hsn_desc}`,
      'For support: billing@cyberdudebivash.in',
    ],

    generated_at:  invoiceRow.created_at || new Date().toISOString(),
    generated_by:  'CYBERDUDEBIVASH GST Invoice Engine v2.0',
    itc_eligible:  !!invoiceRow.gstin,
    itc_note:      invoiceRow.gstin
      ? `Input Tax Credit eligible. GSTIN: ${invoiceRow.gstin}`
      : 'Provide your GSTIN to claim Input Tax Credit (ITC).',
  };
}

// ─── Ownership-scoped lookups ─────────────────────────────────────────────────

async function resolveEmail(env, userId, email) {
  if (email) return email;
  if (!userId || !env.DB) return '';
  const row = await env.DB.prepare(`SELECT email FROM users WHERE id = ?`).bind(userId).first().catch(() => null);
  return row?.email || '';
}

// A persisted invoice, matched by its own id or by the payment it was billed
// against, scoped to the caller who owns it.
async function lookupOwnedInvoice(env, id, userId, email) {
  if (!env.DB || !id) return null;
  return env.DB.prepare(
    `SELECT * FROM invoices WHERE (id = ? OR payment_id = ?) AND (user_id = ? OR email = ?) LIMIT 1`
  ).bind(id, id, userId || '', email || '').first().catch(() => null);
}

// Matches the legacy contract: `id` may be a Razorpay order_id or payment_id.
async function lookupOwnedPayment(env, orderOrPaymentId, userId, email) {
  if (!env.DB || !orderOrPaymentId) return null;
  const q = userId
    ? `SELECT p.* FROM payments p
       LEFT JOIN users u ON u.email = p.email
       WHERE (p.razorpay_order_id = ? OR p.razorpay_payment_id = ?) AND (u.id = ? OR p.email = ?)`
    : `SELECT * FROM payments WHERE (razorpay_order_id = ? OR razorpay_payment_id = ?) AND email = ?`;

  return userId
    ? env.DB.prepare(q).bind(orderOrPaymentId, orderOrPaymentId, userId, email || '').first().catch(() => null)
    : env.DB.prepare(q).bind(orderOrPaymentId, orderOrPaymentId, email || '').first().catch(() => null);
}

// Creates (or enriches) the one persisted invoice for a payment via the
// shared invoice authority. Idempotent by payment — safe to call from a
// list/get/generate path without ever producing a second invoice number for
// the same payment. Only ever fills in GSTIN/company/address that the
// existing row is missing; invoice_number and financial fields are never
// touched once written.
async function materializeInvoiceForPayment(env, payment, customerDetails = {}) {
  if (!env.DB || !payment) return null;
  const paymentKey = payment.razorpay_payment_id || payment.razorpay_order_id;
  if (!paymentKey) return null;

  const priceInr = Math.round((payment.amount || 0) / 100);
  const description = payment.module
    ? `${String(payment.module).replace('subscription:', '').toUpperCase()} Plan — CYBERDUDEBIVASH AI Security Platform`
    : 'CYBERDUDEBIVASH AI Security Hub — Subscription / Service';

  const result = await createInvoice(env.DB, {
    userId:         payment.user_id || payment.email,
    email:          payment.email,
    company:        customerDetails.company || '',
    gstin:          customerDetails.gstin || '',
    billingAddress: {
      address:    customerDetails.address || '',
      state:      customerDetails.state || '',
      state_code: customerDetails.state_code || '',
    },
    lineItems:      [{ description, amount_inr: priceInr, quantity: 1 }],
    paymentId:      paymentKey,
    paymentMethod:  'razorpay',
  }, env);

  if (!result?.ok) return null;

  let invoiceRow = await env.DB.prepare(`SELECT * FROM invoices WHERE id = ?`).bind(result.invoice_id).first().catch(() => null);
  if (!invoiceRow) return null;

  if (result.already_existed && customerDetails.gstin && !invoiceRow.gstin) {
    await env.DB.prepare(
      `UPDATE invoices SET gstin = ?, company = ?, billing_address = ?
       WHERE id = ? AND (gstin IS NULL OR gstin = '')`
    ).bind(
      customerDetails.gstin,
      customerDetails.company || invoiceRow.company || '',
      JSON.stringify({
        address:    customerDetails.address || '',
        state:      customerDetails.state || '',
        state_code: customerDetails.state_code || '',
      }),
      invoiceRow.id,
    ).run().catch(() => {});
    invoiceRow = await env.DB.prepare(`SELECT * FROM invoices WHERE id = ?`).bind(invoiceRow.id).first().catch(() => invoiceRow);
  }

  return invoiceRow;
}

// ─── GET /api/billing/invoices — list user invoices ──────────────────────────
export async function handleListInvoices(request, env, authCtx) {
  const headers = corsHeaders(request);
  const userId = authCtx?.user_id || authCtx?.userId;
  const email  = authCtx?.email;

  if (!userId && !email) {
    return Response.json({ error: 'Authentication required.' }, { status: 401 });
  }

  const url    = new URL(request.url);
  const page   = Math.max(parseInt(url.searchParams.get('page') || '1') || 1, 1);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20') || 20, 50);
  const offset = (page - 1) * limit;

  const resolvedEmail = await resolveEmail(env, userId, email);

  let rows = [];
  try {
    const result = await env.DB.prepare(
      `SELECT id, invoice_number, payment_id, total_inr, currency, status, created_at, line_items
       FROM invoices WHERE user_id = ? OR email = ?
       ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(userId || '', resolvedEmail || '', limit, offset).all();
    rows = result?.results || [];
  } catch (_) {}

  const invoices = rows.map((row) => {
    const items = safeParseJSON(row.line_items, []);
    const amountPaise = Math.round((row.total_inr || 0) * 100);
    return {
      invoice_number: row.invoice_number,
      payment_id:     row.payment_id,
      order_id:       row.payment_id,
      module:         items[0]?.description || null,
      amount_inr:     formatINR(amountPaise),
      amount_paise:   amountPaise,
      status:         row.status === 'paid' ? 'PAID' : String(row.status || 'PENDING').toUpperCase(),
      date:           row.created_at?.slice(0, 10),
      download_url:   `/api/billing/invoice/${row.id}`,
    };
  });

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

  const resolvedEmail = await resolveEmail(env, userId, email);
  const platformGstin = env.PLATFORM_GSTIN || env.BUSINESS_GST || '';

  let invoiceRow = await lookupOwnedInvoice(env, invoiceId, userId, resolvedEmail);

  if (!invoiceRow) {
    // Legacy download_url links were minted from the payments table's
    // Razorpay order/payment id, from before invoices were persisted rows.
    // Resolve the same way, materializing the (still-missing) invoice once.
    const payment = await lookupOwnedPayment(env, invoiceId, userId, resolvedEmail);
    if (payment && payment.status === 'paid') {
      invoiceRow = await materializeInvoiceForPayment(env, payment, {});
    }
  }

  if (!invoiceRow) {
    return Response.json({ error: 'Invoice not found or access denied.' }, { status: 404 });
  }

  const invoice = buildInvoiceObject(invoiceRow, platformGstin);

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

  const resolvedEmail = await resolveEmail(env, userId, email);
  const payment = await lookupOwnedPayment(env, order_id, userId, resolvedEmail);

  if (!payment) {
    return Response.json({ error: 'Payment not found or access denied.' }, { status: 404 });
  }
  if (payment.status !== 'paid') {
    return Response.json({ error: 'Payment has not completed yet; cannot issue a tax invoice.' }, { status: 409 });
  }

  const platformGstin = env.PLATFORM_GSTIN || env.BUSINESS_GST || '';
  const invoiceRow = await materializeInvoiceForPayment(env, payment, {
    name:       customer_name,
    company:    customer_company,
    gstin:      customer_gstin,
    address:    customer_address,
    state:      customer_state,
    state_code: customer_state_code,
  });

  if (!invoiceRow) {
    return Response.json({ error: 'Invoice generation failed.' }, { status: 500 });
  }

  const invoice = buildInvoiceObject(invoiceRow, platformGstin);

  return Response.json({
    success: true,
    data:    invoice,
    message: 'GST invoice generated. Share invoice_number with your finance team for ITC claim.',
  }, { headers: { ...headers, 'Content-Type': 'application/json' } });
}
