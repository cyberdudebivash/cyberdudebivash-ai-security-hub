/**
 * CYBERDUDEBIVASH AI Security Hub — v24 Billing Engine
 * Production billing: invoices + GST + licenses + PayPal + failed payment recovery
 *
 * Routes under /api/v24/billing/*:
 *   POST /api/v24/billing/invoice/create    — generate GST invoice
 *   GET  /api/v24/billing/invoice/:id       — get invoice
 *   GET  /api/v24/billing/invoices          — list user invoices
 *   POST /api/v24/billing/license/issue     — issue license key
 *   POST /api/v24/billing/license/activate  — activate license
 *   GET  /api/v24/billing/license/verify    — verify license key
 *   POST /api/v24/billing/paypal/create     — create PayPal order
 *   POST /api/v24/billing/paypal/capture    — capture PayPal payment
 *   POST /api/v24/billing/refund/request    — request refund
 *   GET  /api/v24/billing/recovery/pending  — list failed payments (admin)
 *   POST /api/v24/billing/recovery/retry    — retry failed payment (cron)
 */

const GST_RATE = 0.18; // 18% GST
const INVOICE_PREFIX = 'CBD';

// ─── Invoice number generator ─────────────────────────────────────────────────
function generateInvoiceNumber(seq) {
  const y = new Date().getFullYear();
  const m = String(new Date().getMonth() + 1).padStart(2, '0');
  return `${INVOICE_PREFIX}-${y}${m}-${String(seq).padStart(4, '0')}`;
}

// ─── Generate GST invoice ─────────────────────────────────────────────────────
export async function createInvoice(db, params) {
  if (!db) return { ok: false, error: 'No DB' };
  const {
    userId, email, company, gstin, billingAddress,
    lineItems, subscriptionId, paymentId, paymentMethod, periodStart, periodEnd,
  } = params;

  try {
    // Get next invoice sequence
    const lastInv = await db.prepare(
      `SELECT invoice_number FROM invoices ORDER BY created_at DESC LIMIT 1`
    ).first().catch(() => null);

    let seq = 1;
    if (lastInv?.invoice_number) {
      const parts = lastInv.invoice_number.split('-');
      seq = (parseInt(parts[parts.length - 1]) || 0) + 1;
    }

    const invoiceNumber = generateInvoiceNumber(seq);
    const subtotal = lineItems.reduce((s, i) => s + (i.amount_inr || 0), 0);
    const gstAmount = Math.round(subtotal * GST_RATE);
    const total = subtotal + gstAmount;
    const dueDate = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);
    const invId = `inv-${Date.now().toString(36)}`;

    await db.prepare(`
      INSERT INTO invoices
        (id, invoice_number, customer_id, user_id, email, company, gstin,
         billing_address, line_items, subtotal_inr, gst_rate, gst_amount_inr,
         total_inr, status, payment_id, payment_method, due_date,
         subscription_id, period_start, period_end)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'paid', ?, ?, ?, ?, ?, ?)
    `).bind(
      invId, invoiceNumber,
      userId || email, userId, email,
      company || '', gstin || '',
      JSON.stringify(billingAddress || {}),
      JSON.stringify(lineItems),
      subtotal, GST_RATE * 100, gstAmount, total,
      paymentId || '', paymentMethod || 'razorpay',
      dueDate, subscriptionId || '',
      periodStart || new Date().toISOString().slice(0, 7) + '-01',
      periodEnd || new Date().toISOString().slice(0, 10),
    ).run();

    // Store in revenue_streams
    const period = new Date().toISOString().slice(0, 7);
    await db.prepare(`
      INSERT INTO revenue_streams (period, stream, revenue_inr, transaction_count, customer_count)
      VALUES (?, 'subscriptions', ?, 1, 1)
      ON CONFLICT(period, stream) DO UPDATE SET
        revenue_inr       = revenue_inr + ?,
        transaction_count = transaction_count + 1,
        updated_at        = datetime('now')
    `).bind(period, total, total).run().catch(() => {});

    return {
      ok: true,
      invoice_id:     invId,
      invoice_number: invoiceNumber,
      total_inr:      total,
      gst_amount_inr: gstAmount,
      subtotal_inr:   subtotal,
      html:           generateInvoiceHTML({ invId, invoiceNumber, email, company, gstin, lineItems, subtotal, gstAmount, total, periodStart, periodEnd }),
    };
  } catch (e) { return { ok: false, error: e.message }; }
}

// ─── Generate invoice HTML (printable / PDF-ready) ────────────────────────────
function generateInvoiceHTML(inv) {
  const { invoiceNumber, email, company, gstin, lineItems, subtotal, gstAmount, total, periodStart, periodEnd } = inv;
  const now = new Date().toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric' });

  const rows = lineItems.map(item => `
    <tr>
      <td>${item.description || item.name}</td>
      <td style="text-align:right">₹${(item.amount_inr || 0).toLocaleString('en-IN')}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Invoice ${invoiceNumber}</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; max-width: 800px; margin: 0 auto; padding: 40px; color: #1a1a2e; }
  .header { display: flex; justify-content: space-between; margin-bottom: 40px; }
  .brand { font-size: 22px; font-weight: 900; color: #7c3aed; }
  .brand-sub { font-size: 11px; color: #666; }
  .invoice-meta { text-align: right; }
  .invoice-number { font-size: 20px; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; margin: 24px 0; }
  th { background: #7c3aed; color: white; padding: 10px; text-align: left; }
  td { padding: 10px; border-bottom: 1px solid #eee; }
  .totals td { font-weight: 600; }
  .total-row td { background: #f5f3ff; font-size: 16px; color: #7c3aed; }
  .footer { margin-top: 40px; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 20px; }
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="brand">CYBERDUDEBIVASH®</div>
    <div class="brand-sub">CYBERDUDEBIVASH PRIVATE LIMITED</div>
    <div class="brand-sub">GST: 21ARKPN8270G1ZP | CIN: U74999OR2024PTC049281</div>
    <div class="brand-sub">Ragadi, Odisha 755019, India</div>
  </div>
  <div class="invoice-meta">
    <div class="invoice-number">TAX INVOICE</div>
    <div style="color:#7c3aed;font-weight:700">${invoiceNumber}</div>
    <div>Date: ${now}</div>
    ${periodStart ? `<div>Period: ${periodStart} to ${periodEnd}</div>` : ''}
  </div>
</div>

<div style="margin-bottom:24px">
  <strong>Bill To:</strong><br>
  ${company || ''}<br>
  ${email}<br>
  ${gstin ? `GSTIN: ${gstin}` : ''}
</div>

<table>
  <thead><tr><th>Description</th><th style="text-align:right">Amount</th></tr></thead>
  <tbody>${rows}</tbody>
  <tbody class="totals">
    <tr><td>Subtotal</td><td style="text-align:right">₹${subtotal.toLocaleString('en-IN')}</td></tr>
    <tr><td>GST @ 18% (IGST)</td><td style="text-align:right">₹${gstAmount.toLocaleString('en-IN')}</td></tr>
    <tr class="total-row"><td><strong>TOTAL</strong></td><td style="text-align:right"><strong>₹${total.toLocaleString('en-IN')}</strong></td></tr>
  </tbody>
</table>

<div class="footer">
  <p>Payment terms: Due on receipt | Bank: Axis Bank | A/C: 915010024617260 | IFSC: UTIB0000052</p>
  <p>UPI: iambivash.bn-5@okaxis | Email: bivash@cyberdudebivash.com | +91 8179881447</p>
  <p>This is a computer-generated invoice and does not require a physical signature.</p>
</div>
</body></html>`;
}

// ─── License key operations ───────────────────────────────────────────────────
export async function issueLicense(db, params) {
  if (!db) return { ok: false };
  const { userId, email, plan, product, seats = 1, paymentId, expiresInDays = 365 } = params;
  try {
    // Generate cryptographically safe license key
    const raw = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const licKey = `CBD-${raw.slice(0,4).toUpperCase()}-${raw.slice(4,8).toUpperCase()}-${raw.slice(8,12).toUpperCase()}-${raw.slice(12,16).toUpperCase()}`;

    const expiresAt = new Date(Date.now() + expiresInDays * 86400000).toISOString();
    const licId = `lic-${Date.now().toString(36)}`;

    await db.prepare(`
      INSERT INTO licenses (id, license_key, user_id, email, plan, product, seats, payment_id, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(licId, licKey, userId, email, plan, product || plan, seats, paymentId || '', expiresAt).run();

    return { ok: true, license_id: licId, license_key: licKey, expires_at: expiresAt };
  } catch (e) { return { ok: false, error: e.message }; }
}

export async function verifyLicense(db, licenseKey) {
  if (!db || !licenseKey) return { valid: false };
  try {
    const lic = await db.prepare(`SELECT * FROM licenses WHERE license_key=?`).bind(licenseKey).first();
    if (!lic) return { valid: false, error: 'License not found' };
    if (lic.status !== 'active') return { valid: false, error: `License ${lic.status}` };
    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      await db.prepare(`UPDATE licenses SET status='expired' WHERE id=?`).bind(lic.id).run().catch(() => {});
      return { valid: false, error: 'License expired' };
    }
    return { valid: true, plan: lic.plan, email: lic.email, seats: lic.seats, expires_at: lic.expires_at };
  } catch (e) { return { valid: false, error: e.message }; }
}

// ─── PayPal integration ───────────────────────────────────────────────────────
const PAYPAL_API = 'https://api-m.paypal.com'; // production

export async function createPayPalOrder(env, params) {
  const { amountUSD, description, planId, userId, email } = params;
  if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) {
    return { ok: false, error: 'PayPal credentials not configured' };
  }
  try {
    // Get access token
    const auth = btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`);
    const tokenResp = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    });
    const { access_token } = await tokenResp.json();

    // Create order
    const orderResp = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: { currency_code: 'USD', value: amountUSD.toFixed(2) },
          description: description || `CYBERDUDEBIVASH ${planId}`,
          custom_id: `${userId || email}_${planId}`,
        }],
        application_context: {
          brand_name:          'CYBERDUDEBIVASH',
          return_url:          'https://cyberdudebivash.in/payment/success',
          cancel_url:          'https://cyberdudebivash.in/payment/cancel',
          user_action:         'PAY_NOW',
          shipping_preference: 'NO_SHIPPING',
        },
      }),
    });
    const order = await orderResp.json();
    const approveUrl = order.links?.find(l => l.rel === 'approve')?.href;
    return { ok: true, order_id: order.id, approve_url: approveUrl };
  } catch (e) { return { ok: false, error: e.message }; }
}

export async function capturePayPalOrder(db, env, orderId) {
  if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) return { ok: false };
  try {
    const auth = btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`);
    const tokenResp = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    });
    const { access_token } = await tokenResp.json();

    const captureResp = await fetch(`${PAYPAL_API}/v2/checkout/orders/${orderId}/capture`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json' },
    });
    const result = await captureResp.json();
    const capture = result.purchase_units?.[0]?.payments?.captures?.[0];
    const amountUSD = parseFloat(capture?.amount?.value || '0');

    if (result.status === 'COMPLETED' && db) {
      await db.prepare(`
        INSERT OR IGNORE INTO paypal_transactions
          (paypal_order_id, paypal_payer_id, amount_usd, amount_inr, currency, status, completed_at)
        VALUES (?, ?, ?, ?, 'USD', 'completed', datetime('now'))
      `).bind(orderId, result.payer?.payer_id || '', amountUSD, Math.round(amountUSD * 83)).run();
    }
    return { ok: result.status === 'COMPLETED', status: result.status, capture_id: capture?.id, amount_usd: amountUSD };
  } catch (e) { return { ok: false, error: e.message }; }
}

// ─── Failed payment recovery ──────────────────────────────────────────────────
export async function runPaymentRecovery(db, env) {
  if (!db) return { processed: 0 };
  try {
    // Find recoverable failed payments due for retry
    const due = await db.prepare(`
      SELECT * FROM payment_recovery
      WHERE status IN ('pending','retrying')
        AND resolved = 0
        AND attempt_count < max_attempts
        AND (next_retry_at IS NULL OR next_retry_at <= datetime('now'))
      ORDER BY created_at ASC LIMIT 20
    `).all();

    let processed = 0;
    for (const rec of (due.results || [])) {
      try {
        // Increment attempt count and schedule next retry (exponential backoff)
        const backoffHours = Math.pow(2, rec.attempt_count); // 1h, 2h, 4h
        const nextRetry = new Date(Date.now() + backoffHours * 3600000).toISOString();

        await db.prepare(`
          UPDATE payment_recovery SET
            attempt_count  = attempt_count + 1,
            last_attempt_at = datetime('now'),
            next_retry_at  = ?,
            status         = CASE WHEN attempt_count + 1 >= max_attempts THEN 'abandoned' ELSE 'retrying' END
          WHERE id = ?
        `).bind(nextRetry, rec.id).run();

        // TODO: Integrate with Razorpay subscription retry API
        // For now: send recovery email via Resend
        if (env.RESEND_API_KEY && rec.email) {
          await sendRecoveryEmail(env, rec).catch(() => {});
        }
        processed++;
      } catch {}
    }
    return { processed, total_pending: due.results?.length || 0 };
  } catch (e) { return { processed: 0, error: e.message }; }
}

async function sendRecoveryEmail(env, rec) {
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from:    'billing@cyberdudebivash.in',
      to:      [rec.email],
      subject: 'Action Required: Payment Failed — CYBERDUDEBIVASH',
      html: `<p>Hi,</p>
<p>Your recent payment of ₹${(rec.amount_inr || 0).toLocaleString('en-IN')} failed.</p>
<p>Please update your payment method to continue your subscription.</p>
<p><a href="https://cyberdudebivash.in/billing" style="background:#7c3aed;color:white;padding:10px 20px;border-radius:6px;text-decoration:none">Update Payment Method</a></p>
<p>If you need help, reply to this email or contact bivash@cyberdudebivash.com</p>
<p>— CYBERDUDEBIVASH Team</p>`,
    }),
  });
}

// ─── Renewal queue management ─────────────────────────────────────────────────
export async function buildRenewalQueue(db) {
  if (!db) return { queued: 0 };
  try {
    // Find subscriptions renewing in next 7 days
    const renewing = await db.prepare(`
      SELECT s.*, u.email
      FROM subscriptions s
      LEFT JOIN users u ON u.id = s.user_id
      WHERE s.status = 'active'
        AND s.current_period_end BETWEEN datetime('now') AND datetime('now','+7 days')
        AND s.cancel_at_period_end = 0
        AND s.id NOT IN (SELECT subscription_id FROM renewal_queue WHERE status IN ('upcoming','processing'))
    `).all().catch(() => ({ results: [] }));

    let queued = 0;
    for (const sub of (renewing.results || [])) {
      await db.prepare(`
        INSERT OR IGNORE INTO renewal_queue
          (subscription_id, user_id, email, plan, amount_inr, renewal_date, status)
        VALUES (?, ?, ?, ?, ?, ?, 'upcoming')
      `).bind(
        sub.id, sub.user_id, sub.email || '',
        sub.plan, sub.price_inr || 0,
        sub.current_period_end,
      ).run().catch(() => {});
      queued++;
    }
    return { queued };
  } catch (e) { return { queued: 0, error: e.message }; }
}
