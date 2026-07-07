/**
 * Sentinel APEX Marketplace Handler — dynamic intel product purchases
 * POST /api/sentinel/purchase  — create Razorpay order for any intel product
 * POST /api/sentinel/verify    — verify payment + grant access + invoice + founder alert
 *
 * Products are dynamic (CVE reports, threat actor dossiers, malware intel).
 * Prices are validated server-side against the allowed price list.
 */

const FOUNDER_EMAIL = 'bivash@cyberdudebivash.com';

// Server-side price whitelist — frontend cannot override these
const SENTINEL_PRICE_MAP = {
  cve_report:           { price_inr: 3999, label: 'CVE Intelligence Report' },
  threat_actor_dossier: { price_inr: 6499, label: 'Threat Actor Dossier' },
  malware_intel:        { price_inr: 6499, label: 'Malware Intelligence Report' },
  generic_report:       { price_inr: 3999, label: 'Security Intelligence Report' },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

// POST /api/sentinel/purchase
export async function handleSentinelPurchase(request, env) {
  try {
    const body = await request.json();
    const { product_type, product_title, email } = body;

    const priceEntry = SENTINEL_PRICE_MAP[product_type] || SENTINEL_PRICE_MAP.generic_report;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return json({ success: false, error: 'Valid email required' }, 400);
    }

    const title  = (product_title || priceEntry.label).substring(0, 200);
    const amount = priceEntry.price_inr * 100; // paise

    let razorpayOrderId = null;
    const rzKey    = env.RAZORPAY_KEY_ID;
    const rzSecret = env.RAZORPAY_KEY_SECRET;
    if (rzKey && rzSecret) {
      const r = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${btoa(`${rzKey}:${rzSecret}`)}` },
        body: JSON.stringify({
          amount,
          currency: 'INR',
          receipt: `sa_${(product_type || 'report').slice(0, 10)}_${Date.now()}`,
          notes: { product_type, product_title: title, email },
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (r.ok) razorpayOrderId = (await r.json()).id;
    }

    return json({
      success: true,
      order: {
        razorpay_order_id: razorpayOrderId,
        product_type,
        product_title: title,
        price_inr: priceEntry.price_inr,
        amount,
        currency: 'INR',
        razorpay_key: rzKey,
        prefill: { email },
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// POST /api/sentinel/verify
export async function handleSentinelVerify(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature,
            product_type, product_title, email } = body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return json({ success: false, error: 'Missing verification fields' }, 400);
    }

    const priceEntry = SENTINEL_PRICE_MAP[product_type] || SENTINEL_PRICE_MAP.generic_report;
    const title = (product_title || priceEntry.label).substring(0, 200);

    // HMAC-SHA256 verify
    const secret  = env.RAZORPAY_KEY_SECRET || '';
    const payload = `${razorpay_order_id}|${razorpay_payment_id}`;
    const key     = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBuf  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const expected = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (!secret || expected !== razorpay_signature) {
      return json({ success: false, error: 'Payment signature verification failed' }, 400);
    }

    // Idempotency check
    if (env.DB) {
      const existing = await env.DB.prepare(
        `SELECT id FROM payments WHERE razorpay_order_id = ? AND status = 'paid' LIMIT 1`
      ).bind(razorpay_order_id).first().catch(() => null);
      if (existing) {
        return json({ success: true, access_granted: true, product_title: title,
          delivery_note: 'Your report will be delivered to your email within 4 hours.', duplicate: true });
      }
    }

    // Record in D1
    const purchaseId = `sa_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
    if (env.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO payments (id, user_id, module, target, amount, currency, razorpay_order_id, razorpay_payment_id, status, email, created_at)
         VALUES (?,?,?,?,?,?,?,?,'paid',?,datetime('now'))`
      ).bind(purchaseId, email || null, 'sentinel_intel', product_type || 'report',
             priceEntry.price_inr * 100, 'INR', razorpay_order_id, razorpay_payment_id, email || null)
       .run().catch(e => console.warn('[Sentinel] D1 error:', e.message));
    }

    // KV access grant (365 days)
    const accessKey = `access:sentinel:${product_type}:${email || razorpay_payment_id}`;
    await env.SECURITY_HUB_KV?.put(accessKey, JSON.stringify({
      granted_at: new Date().toISOString(),
      payment_id: razorpay_payment_id,
      product_title: title,
    }), { expirationTtl: 365 * 86400 }).catch(() => {});

    // Fire-and-forget: GST invoice + customer confirmation + founder delivery alert
    Promise.all([
      (async () => {
        try {
          const { createInvoice } = await import('../services/v24/billingEngine.js');
          if (env.DB) {
            await createInvoice(env.DB, {
              userId: email || purchaseId, email: email || 'noreply@buyer',
              lineItems: [{ description: title, amount_inr: priceEntry.price_inr, quantity: 1 }],
              paymentId: razorpay_payment_id, paymentMethod: 'razorpay',
            });
          }
        } catch (e) { console.warn('[Sentinel] invoice error:', e.message); }
      })(),
      (async () => {
        try {
          const { sendPurchaseConfirmation } = await import('../services/emailEngine.js');
          if (email) {
            await sendPurchaseConfirmation(env, {
              to: email, productName: title, amountInr: priceEntry.price_inr,
              paymentId: razorpay_payment_id,
            });
          }
        } catch (e) { console.warn('[Sentinel] confirmation email error:', e.message); }
      })(),
      (async () => {
        try {
          const { sendEmail } = await import('../services/emailEngine.js');
          await sendEmail(env, {
            to: FOUNDER_EMAIL,
            subject: `🛰 SENTINEL SALE: ${title} [₹${priceEntry.price_inr.toLocaleString('en-IN')}] — ${email || 'unknown'}`,
            html: `<h2 style="color:#7c3aed">Sentinel APEX Marketplace Sale</h2>
<table style="border-collapse:collapse;font-family:sans-serif">
<tr><td style="padding:6px 12px;color:#6b7280">Product</td><td style="padding:6px 12px;font-weight:700">${title}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Type</td><td style="padding:6px 12px">${product_type || 'report'}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Price</td><td style="padding:6px 12px;font-weight:700;color:#7c3aed">₹${priceEntry.price_inr.toLocaleString('en-IN')}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Buyer Email</td><td style="padding:6px 12px"><a href="mailto:${email}">${email || 'N/A'}</a></td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Payment ID</td><td style="padding:6px 12px;font-family:monospace">${razorpay_payment_id}</td></tr>
<tr><td style="padding:6px 12px;color:#6b7280">Order ID</td><td style="padding:6px 12px;font-family:monospace">${razorpay_order_id}</td></tr>
</table>
<p style="margin-top:20px;padding:12px 16px;background:#f3e8ff;border-radius:8px;color:#6d28d9;font-weight:600">⚡ ACTION REQUIRED: Deliver "${title}" to ${email} within 4 hours.</p>
<p><a href="mailto:${email}?subject=Your ${encodeURIComponent(title)} — Sentinel APEX" style="background:#7c3aed;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700">Send Report Now →</a></p>`,
            text: `SENTINEL SALE: ${title} ₹${priceEntry.price_inr} to ${email}. Payment: ${razorpay_payment_id}. DELIVER WITHIN 4H.`,
          });
        } catch (e) { console.warn('[Sentinel] founder alert error:', e.message); }
      })(),
    ]).catch(() => {});

    return json({
      success: true,
      access_granted: true,
      product_title: title,
      payment_id: razorpay_payment_id,
      delivery_note: `${title} will be delivered to ${email} within 4 hours. Check your inbox.`,
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
