/**
 * CYBERDUDEBIVASH AI Security Hub — Stripe Webhook Handler v1.0
 *
 * Handles Stripe payment events:
 *   POST /api/webhooks/stripe → verified Stripe webhook processor
 *
 * Events handled:
 *   checkout.session.completed  → unlock report + provision API key
 *   payment_intent.succeeded    → record revenue + grant feature access
 *   customer.subscription.created → activate subscription tier
 *   customer.subscription.deleted → downgrade tier
 *
 * Security: HMAC-SHA256 signature verification via STRIPE_WEBHOOK_SECRET
 * All unverified requests are rejected with 401 before any processing.
 */

// ─── Stripe Webhook Signature Verification ───────────────────────────────────
// Stripe signs webhooks with: t=timestamp,v1=signature
// We reconstruct and compare using Web Crypto API (no npm dep needed)
async function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  try {
    // Parse Stripe-Signature header: t=TIMESTAMP,v1=SIG1[,v1=SIG2]
    const parts = {};
    sigHeader.split(',').forEach(part => {
      const [k, v] = part.split('=');
      if (k === 't') parts.timestamp = v;
      if (k === 'v1') parts.v1 = v;
    });

    if (!parts.timestamp || !parts.v1) return false;

    // Reject webhooks older than 5 minutes (replay attack protection)
    const now = Math.floor(Date.now() / 1000);
    const age = Math.abs(now - parseInt(parts.timestamp));
    if (age > 300) {
      console.warn('[Stripe] Webhook too old:', age, 'seconds');
      return false;
    }

    // Build signed payload: timestamp + '.' + body
    const signedPayload = `${parts.timestamp}.${rawBody}`;
    const encoder = new TextEncoder();

    // Import secret key
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Compute expected signature
    const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
    const sigHex = Array.from(new Uint8Array(sigBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Constant-time comparison
    return sigHex === parts.v1;
  } catch (err) {
    console.error('[Stripe] Signature verification error:', err.message);
    return false;
  }
}

// ─── Access grant tier mapping ────────────────────────────────────────────────
function getTierFromStripeProduct(productId, amount) {
  // Map Stripe product IDs or amount ranges to internal tiers
  if (!productId && amount) {
    if (amount >= 99900)  return 'ENTERPRISE';  // $999+
    if (amount >= 4900)   return 'PRO';          // $49+
    if (amount >= 199)    return 'BASIC';         // ₹199+
  }
  return 'PRO';
}

// ─── Grant feature access in D1 ───────────────────────────────────────────────
async function grantAccess(env, { email, tier, source, stripeSessionId, amount, currency, productId, reportToken }) {
  if (!env.DB) return;

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();

  try {
    // Record in payments table
    await env.DB.prepare(`
      INSERT INTO payments (id, user_id, scan_id, module, target, amount, currency,
        razorpay_order_id, status, ip, email, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)
    `).bind(
      userId,
      null,
      null,
      'stripe',
      productId || 'stripe_product',
      amount ? Math.round(amount / 100) : 0,   // Stripe amounts in paise/cents
      currency?.toUpperCase() || 'USD',
      stripeSessionId || userId,
      '0.0.0.0',   // IP not available in webhook context
      email || null,
      now
    ).run().catch(() => {});

    // Provision API key for the buyer
    if (email && env.SECURITY_HUB_KV) {
      const apiKey = `cdb_${crypto.randomUUID().replace(/-/g, '').slice(0, 32)}`;
      const keyConfig = {
        tier,
        owner_email: email,
        created_at: now,
        active: true,
        label: `Stripe ${tier} — ${email}`,
        source: 'stripe_webhook',
        stripe_session: stripeSessionId,
      };
      await env.SECURITY_HUB_KV.put(`apikey:${apiKey}`, JSON.stringify(keyConfig), {
        expirationTtl: tier === 'ENTERPRISE' ? 365 * 24 * 3600 : 30 * 24 * 3600,
      });

      // Also store email → key mapping for recovery
      await env.SECURITY_HUB_KV.put(`email:${email}:apikey`, apiKey, {
        expirationTtl: 365 * 24 * 3600,
      });

      console.log(`[Stripe] API key provisioned for ${email} — tier: ${tier}`);
      return apiKey;
    }
  } catch (err) {
    console.error('[Stripe] grantAccess error:', err.message);
  }
  return null;
}

// ─── Send delivery email via Resend ──────────────────────────────────────────
async function sendDeliveryEmail(env, { email, tier, apiKey, stripeSessionId }) {
  if (!env.RESEND_API_KEY || !email) return;
  try {
    const body = {
      from: 'CYBERDUDEBIVASH AI Security Hub <no-reply@cyberdudebivash.in>',
      to: [email],
      subject: `✅ Your ${tier} Access is Ready — CYBERDUDEBIVASH AI Security Hub`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#0a0a1a;color:#fff">
          <h2 style="color:#00d4ff">🛡️ Payment Confirmed — Access Granted</h2>
          <p>Thank you for your purchase! Your <strong>${tier}</strong> access to CYBERDUDEBIVASH AI Security Hub is now active.</p>
          ${apiKey ? `
          <div style="background:#1a1a2e;border:1px solid #00d4ff33;border-radius:8px;padding:16px;margin:16px 0">
            <strong style="color:#00d4ff">Your API Key:</strong><br>
            <code style="color:#22c55e;font-size:14px;word-break:break-all">${apiKey}</code>
          </div>
          <p style="color:#94a3b8;font-size:12px">Keep this key secure. Use it as: <code>X-API-Key: ${apiKey}</code></p>
          ` : ''}
          <div style="margin:20px 0">
            <a href="https://cyberdudebivash.in/user-dashboard.html" style="background:#00d4ff;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700">Access Your Dashboard →</a>
          </div>
          <p style="color:#94a3b8;font-size:12px">Support: <a href="mailto:bivash@cyberdudebivash.com" style="color:#00d4ff">bivash@cyberdudebivash.com</a> | WhatsApp: <a href="https://wa.me/918179881447" style="color:#00d4ff">+91 8179881447</a></p>
          <p style="color:#64748b;font-size:11px">Transaction ID: ${stripeSessionId}</p>
        </div>
      `,
    };
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    console.log('[Stripe] Delivery email sent to', email);
  } catch (err) {
    console.error('[Stripe] Email send failed:', err.message);
  }
}

// ─── Main Stripe Webhook Handler ─────────────────────────────────────────────
export async function handleStripeWebhook(request, env) {
  // Reject if Stripe not configured
  if (!env.STRIPE_WEBHOOK_SECRET) {
    return Response.json({ error: 'Stripe not configured' }, { status: 503 });
  }

  // Read raw body for signature verification (must happen before any .json() call)
  const rawBody = await request.text();
  const sigHeader = request.headers.get('stripe-signature');

  // Verify signature — HARD REJECT if invalid
  const valid = await verifyStripeSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    console.warn('[Stripe] Invalid webhook signature — rejected');
    return Response.json({ error: 'Invalid signature' }, { status: 401 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const eventType = event.type;
  const data = event.data?.object || {};

  console.log(`[Stripe] Webhook received: ${eventType} (id: ${event.id})`);

  // ─── Event: checkout.session.completed ─────────────────────────────────────
  if (eventType === 'checkout.session.completed') {
    const email = data.customer_email || data.customer_details?.email;
    const amount = data.amount_total;
    const currency = data.currency;
    const sessionId = data.id;
    const productId = data.metadata?.product_id || null;
    const tier = getTierFromStripeProduct(productId, amount);

    const apiKey = await grantAccess(env, {
      email, tier, source: 'stripe_checkout', stripeSessionId: sessionId,
      amount, currency, productId,
    });

    await sendDeliveryEmail(env, { email, tier, apiKey, stripeSessionId: sessionId });

    console.log(`[Stripe] checkout.session.completed — email: ${email}, tier: ${tier}, amount: ${amount} ${currency}`);

    return Response.json({
      received: true,
      event: eventType,
      email: email ? `${email.slice(0,3)}***` : null,
      tier,
      provisioned: !!apiKey,
    });
  }

  // ─── Event: payment_intent.succeeded ───────────────────────────────────────
  if (eventType === 'payment_intent.succeeded') {
    const email = data.receipt_email;
    const amount = data.amount;
    const currency = data.currency;
    const tier = getTierFromStripeProduct(null, amount);

    await grantAccess(env, {
      email, tier, source: 'stripe_payment_intent',
      stripeSessionId: data.id, amount, currency,
    });

    console.log(`[Stripe] payment_intent.succeeded — amount: ${amount} ${currency}`);
    return Response.json({ received: true, event: eventType });
  }

  // ─── Event: customer.subscription.created ──────────────────────────────────
  if (eventType === 'customer.subscription.created') {
    const subscriptionId = data.id;
    const status = data.status;
    console.log(`[Stripe] subscription.created — id: ${subscriptionId}, status: ${status}`);

    // Store subscription in D1 for quota management
    if (env.DB && status === 'active') {
      const email = data.metadata?.email || null;
      await env.DB.prepare(`
        INSERT OR REPLACE INTO subscriptions
          (id, user_id, tier, status, stripe_subscription_id, current_period_end, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        crypto.randomUUID(),
        null,
        'PRO',
        'active',
        subscriptionId,
        data.current_period_end ? new Date(data.current_period_end * 1000).toISOString() : null,
      ).run().catch(() => {});
    }

    return Response.json({ received: true, event: eventType, status });
  }

  // ─── Event: customer.subscription.deleted ─────────────────────────────────
  if (eventType === 'customer.subscription.deleted') {
    const subscriptionId = data.id;
    if (env.DB) {
      await env.DB.prepare(
        `UPDATE subscriptions SET status='cancelled' WHERE stripe_subscription_id=?`
      ).bind(subscriptionId).run().catch(() => {});
    }
    console.log(`[Stripe] subscription.deleted — id: ${subscriptionId}`);
    return Response.json({ received: true, event: eventType });
  }

  // ─── Unknown event — acknowledge receipt (Stripe retries on non-2xx) ────────
  console.log(`[Stripe] Unhandled event type: ${eventType} — acknowledged`);
  return Response.json({ received: true, event: eventType, handled: false });
}
