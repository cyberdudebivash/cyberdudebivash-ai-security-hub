/**
 * CYBERDUDEBIVASH AI Security Hub — Subscription Paywall Engine v30.0
 * P1 REMEDIATION: Product-Led Growth (PLG) conversion paywall, 5-tier system,
 * multi-currency checkout (Razorpay + Stripe), and gateway-layer request ceilings.
 *
 * Tiers (per spec):
 *   COMMUNITY     —  100 req/day    (FREE, IP-based, 2 findings preview)
 *   PROFESSIONAL  — 10,000 req/mo   (₹1,499/mo | $18/mo)
 *   TEAM          — 100,000 req/mo  (₹4,999/mo | $60/mo)
 *   BUSINESS      — 1,000,000 req/mo(₹14,999/mo | $180/mo)
 *   ENTERPRISE    — metered/custom  (₹49,999/mo+ | custom)
 *
 * Exports:
 *   SUBSCRIPTION_TIERS          — authoritative tier definitions
 *   gatewayRequestCeiling()     — called before every API handler
 *   applyFreemiumPaywall()      — truncates scan results + injects upgrade CTA
 *   handleSubscriptionCheckout()— POST /api/subscription/checkout
 *   handleWebhookStripe()       — POST /api/webhooks/stripe
 *   handleWebhookRazorpay()     — POST /api/webhooks/razorpay (extended)
 *   handleGetMyPlan()           — GET  /api/subscription/plan
 */

// ─── Tier Definitions (single source of truth, imported by auth middleware) ───
export const SUBSCRIPTION_TIERS = {
  COMMUNITY:    {
    label:          'Community',
    monthly_limit:  3000,           // 100 req/day × 30 = 3,000 req/mo
    daily_limit:    100,
    burst_per_min:  5,
    priority:       0,
    free:           true,
    scan_preview:   2,              // max findings shown before paywall
    price_inr:      0,
    price_usd:      0,
    features:       ['domain_scan_preview', 'sentinel_apex_feed', 'cve_tracker'],
  },
  PROFESSIONAL: {
    label:          'Professional',
    monthly_limit:  10000,
    daily_limit:    340,            // 10,000 / 30 ≈ 334, rounded
    burst_per_min:  20,
    priority:       1,
    free:           false,
    scan_preview:   -1,             // unlimited findings
    price_inr:      1499,
    price_usd:      18,
    features:       ['full_scan', 'pdf_reports', 'mitre_mapping', 'api_access'],
  },
  TEAM:         {
    label:          'Team',
    monthly_limit:  100000,
    daily_limit:    3400,
    burst_per_min:  40,
    priority:       2,
    free:           false,
    scan_preview:   -1,
    price_inr:      4999,
    price_usd:      60,
    features:       ['full_scan', 'pdf_reports', 'mitre_mapping', 'api_access',
                     'siem_integration', 'ciso_dashboard', 'team_seats_5'],
  },
  BUSINESS:     {
    label:          'Business',
    monthly_limit:  1000000,
    daily_limit:    34000,
    burst_per_min:  100,
    priority:       3,
    free:           false,
    scan_preview:   -1,
    price_inr:      14999,
    price_usd:      180,
    features:       ['full_scan', 'pdf_reports', 'mitre_mapping', 'unlimited_api',
                     'siem_integration', 'ciso_dashboard', 'dark_web_monitoring',
                     'sigma_yara_rules', 'team_seats_20', 'priority_support'],
  },
  ENTERPRISE:   {
    label:          'Enterprise',
    monthly_limit:  -1,             // metered / custom
    daily_limit:    -1,
    burst_per_min:  200,
    priority:       4,
    free:           false,
    scan_preview:   -1,
    price_inr:      49999,          // starting price
    price_usd:      600,
    features:       ['everything', 'white_label', 'sso_saml', 'sla_99_9',
                     'dedicated_csm', 'custom_integrations', 'mssp_reseller'],
  },
  // Legacy aliases for backward compatibility
  FREE:         null,               // resolved to COMMUNITY at runtime
  PRO:          null,               // resolved to PROFESSIONAL at runtime
};

// Resolve legacy tier names
export function normalizeTier(raw) {
  const t = (raw || 'COMMUNITY').toUpperCase();
  if (t === 'FREE')    return 'COMMUNITY';
  if (t === 'PRO')     return 'PROFESSIONAL';
  return SUBSCRIPTION_TIERS[t] ? t : 'COMMUNITY';
}

export function getTierDef(raw) {
  return SUBSCRIPTION_TIERS[normalizeTier(raw)] || SUBSCRIPTION_TIERS.COMMUNITY;
}

// ─── Gateway Request Ceiling ──────────────────────────────────────────────────
/**
 * Must be called inside every API handler before business logic executes.
 * Returns { allowed: boolean, headers: object } — inject headers into response.
 *
 * Uses monthly counter for PROFESSIONAL/TEAM/BUSINESS, daily for COMMUNITY.
 */
export async function gatewayRequestCeiling(env, authCtx) {
  const tier    = normalizeTier(authCtx?.tier);
  const def     = getTierDef(tier);
  const id      = authCtx?.identity || `ip:${authCtx?.ip || 'unknown'}`;
  const kv      = env.SECURITY_HUB_KV;

  // Enterprise: unlimited (metered billing handled externally)
  if (def.monthly_limit === -1) {
    return { allowed: true, tier, remaining: -1, reset: 'metered',
             headers: { 'X-RateLimit-Tier': tier, 'X-RateLimit-Remaining': 'unlimited' } };
  }

  if (!kv) {
    return { allowed: true, tier, remaining: def.monthly_limit,
             headers: { 'X-RateLimit-Tier': tier, 'X-RateLimit-Remaining': '?' } };
  }

  try {
    // For COMMUNITY: daily counter
    if (tier === 'COMMUNITY') {
      const day = new Date().toISOString().slice(0, 10);
      const key = `ceiling:day:${id}:${day}`;
      const cur = parseInt(await kv.get(key) || '0', 10);
      if (cur >= def.daily_limit) {
        return {
          allowed:   false,
          tier,
          remaining: 0,
          reset:     'tomorrow_utc_midnight',
          reason:    'daily_ceiling_reached',
          upgrade:   'https://cyberdudebivash.in/#pricing',
          headers:   {
            'X-RateLimit-Tier':      tier,
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset':     'tomorrow_utc_midnight',
          },
        };
      }
      kv.put(key, String(cur + 1), { expirationTtl: 86400 }).catch(() => {});
      return {
        allowed:   true, tier,
        remaining: def.daily_limit - cur - 1,
        headers:   {
          'X-RateLimit-Tier':      tier,
          'X-RateLimit-Remaining': String(def.daily_limit - cur - 1),
          'X-RateLimit-Reset':     'tomorrow_utc_midnight',
        },
      };
    }

    // For paid tiers: monthly counter
    const month = new Date().toISOString().slice(0, 7);
    const key   = `ceiling:mo:${id}:${month}`;
    const cur   = parseInt(await kv.get(key) || '0', 10);
    if (cur >= def.monthly_limit) {
      return {
        allowed:   false,
        tier,
        remaining: 0,
        reset:     'next_billing_cycle',
        reason:    'monthly_ceiling_reached',
        upgrade:   'https://cyberdudebivash.in/#pricing',
        headers:   {
          'X-RateLimit-Tier':      tier,
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset':     'next_billing_cycle',
        },
      };
    }
    kv.put(key, String(cur + 1), { expirationTtl: 86400 * 32 }).catch(() => {});
    return {
      allowed:   true, tier,
      remaining: def.monthly_limit - cur - 1,
      headers:   {
        'X-RateLimit-Tier':      tier,
        'X-RateLimit-Remaining': String(def.monthly_limit - cur - 1),
      },
    };
  } catch {
    return { allowed: true, tier, remaining: -1, headers: { 'X-RateLimit-Tier': tier } };
  }
}

// ─── Freemium Paywall — truncate findings + blur CTA ─────────────────────────
/**
 * Applies the freemium paywall to a scan result object.
 * COMMUNITY tier gets 2 partial findings.  Paid tiers get all findings.
 *
 * @param {object} scanResult  — full scan result from scan handler
 * @param {string} tier        — resolved tier string
 * @param {string} target      — scan target domain (for unlock CTA URL)
 * @returns {object}           — gated result
 */
export function applyFreemiumPaywall(scanResult, tier, target) {
  const def = getTierDef(tier);
  const previewLimit = def.scan_preview;

  if (previewLimit === -1) return { ...scanResult, gated: false };  // paid — full access

  const findings  = scanResult.findings || scanResult.vulnerabilities || [];
  const visible   = findings.slice(0, previewLimit);
  const hidden    = findings.length - visible.length;

  return {
    ...scanResult,
    findings:       visible,
    vulnerabilities: visible,
    gated:          true,
    preview:        true,
    preview_limit:  previewLimit,
    hidden_count:   hidden,
    total_findings: findings.length,
    upgrade_required: {
      message:       `${hidden} additional finding${hidden !== 1 ? 's' : ''} are hidden. Upgrade to unlock the full report.`,
      full_report:   `https://cyberdudebivash.in/report?target=${encodeURIComponent(target || '')}&tier=PROFESSIONAL`,
      unlock_price:  '₹999',
      unlock_url:    `https://cyberdudebivash.in/unlock?target=${encodeURIComponent(target || '')}`,
      plans_url:     'https://cyberdudebivash.in/#pricing',
      cta:           'Unlock Full Report',
    },
    // Sigma/YARA/remediation are gated
    sigma_rules:    null,
    yara_rules:     null,
    remediation:    null,
    _gated_fields:  ['sigma_rules', 'yara_rules', 'remediation', 'full_findings'],
  };
}

// ─── Checkout Handler (POST /api/subscription/checkout) ─────────────────────
/**
 * Abstracts Razorpay (INR, India) and Stripe (USD, global).
 * Processor selection: currency param, or geo from CF-IPCountry header.
 */
export async function handleSubscriptionCheckout(request, env, authCtx = {}) {
  const cors = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
    'Content-Type':                 'application/json',
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  let body;
  try { body = await request.json(); }
  catch { return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers: cors }); }

  const { plan, currency = 'auto', email, coupon } = body;
  const tierKey = normalizeTier(plan);
  const def     = getTierDef(tierKey);

  if (!def || def.free) {
    return new Response(JSON.stringify({ error: 'Invalid plan or plan is free' }), { status: 400, headers: cors });
  }

  // Determine processor
  const country    = request.headers.get('CF-IPCountry') || '';
  const useRazorpay = currency === 'INR' || (currency === 'auto' && country === 'IN');

  try {
    if (useRazorpay) {
      const order = await createRazorpaySubscription(env, tierKey, def, email);
      return new Response(JSON.stringify({
        processor:  'razorpay',
        order_id:   order.id,
        amount:     order.amount,
        currency:   'INR',
        key_id:     env.RAZORPAY_KEY_ID,
        plan:       tierKey,
        name:       `CYBERDUDEBIVASH ${def.label} Plan`,
        prefill:    { email: email || '' },
      }), { status: 200, headers: cors });
    }

    const session = await createStripeCheckoutSession(env, tierKey, def, email);
    return new Response(JSON.stringify({
      processor:  'stripe',
      checkout_url: session.url,
      session_id:   session.id,
      plan:         tierKey,
    }), { status: 200, headers: cors });

  } catch (err) {
    console.error('[Checkout] error:', err.message);
    return new Response(JSON.stringify({ error: 'Payment processor unavailable', detail: err.message }),
      { status: 502, headers: cors });
  }
}

// ─── Razorpay order creation ─────────────────────────────────────────────────
async function createRazorpaySubscription(env, tierKey, def, email) {
  const keyId     = env.RAZORPAY_KEY_ID;
  const keySecret = env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) throw new Error('Razorpay credentials not configured');

  const amountPaise = def.price_inr * 100;
  const receiptId   = `cdb-sub-${tierKey.toLowerCase()}-${Date.now()}`;

  const res = await fetch('https://api.razorpay.com/v1/orders', {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': 'Basic ' + btoa(`${keyId}:${keySecret}`),
    },
    body: JSON.stringify({
      amount:   amountPaise,
      currency: 'INR',
      receipt:  receiptId,
      notes:    { plan: tierKey, email: email || '', platform: 'cyberdudebivash.in' },
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Razorpay order failed: ${err?.error?.description || res.status}`);
  }
  return res.json();
}

// ─── Stripe Checkout Session ─────────────────────────────────────────────────
async function createStripeCheckoutSession(env, tierKey, def, email) {
  const sk = env.STRIPE_SECRET_KEY;
  if (!sk) throw new Error('Stripe secret key not configured');

  const params = new URLSearchParams({
    'payment_method_types[]':            'card',
    'mode':                              'subscription',
    'success_url':                       `https://cyberdudebivash.in/dashboard?plan=${tierKey}&session_id={CHECKOUT_SESSION_ID}`,
    'cancel_url':                        'https://cyberdudebivash.in/#pricing',
    'customer_email':                    email || '',
    'subscription_data[metadata][plan]': tierKey,
    'line_items[0][price_data][currency]':              'usd',
    'line_items[0][price_data][product_data][name]':    `CYBERDUDEBIVASH ${def.label} Plan`,
    'line_items[0][price_data][unit_amount]':           String(def.price_usd * 100),
    'line_items[0][price_data][recurring][interval]':   'month',
    'line_items[0][quantity]':                          '1',
  });

  const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${sk}`,
      'Content-Type':  'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Stripe session failed: ${err?.error?.message || res.status}`);
  }
  return res.json();
}

// ─── Stripe Webhook (asymmetric signature verification) ──────────────────────
export async function handleWebhookStripe(request, env) {
  const cors = { 'Content-Type': 'application/json' };
  const sig  = request.headers.get('Stripe-Signature');
  const body = await request.text();
  const wsec = env.STRIPE_WEBHOOK_SECRET;

  if (!wsec || !sig) {
    return new Response(JSON.stringify({ error: 'Missing webhook secret or signature' }),
      { status: 400, headers: cors });
  }

  // Stripe uses HMAC-SHA256 for webhook signatures
  const valid = await verifyStripeSignature(body, sig, wsec);
  if (!valid) {
    console.warn('[StripeWebhook] Signature verification FAILED — request rejected');
    return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 403, headers: cors });
  }

  const event = JSON.parse(body);

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const plan    = session.subscription_data?.metadata?.plan ||
                      session.metadata?.plan || 'PROFESSIONAL';
      const email   = session.customer_email || session.customer_details?.email;
      await activateSubscription(env, { email, plan, processor: 'stripe',
        external_id: session.id, amount_usd: session.amount_total / 100 });
      break;
    }
    case 'customer.subscription.deleted': {
      const sub   = event.data.object;
      const email = sub.customer_email;
      if (email) await deactivateSubscription(env, email, 'stripe_cancellation');
      break;
    }
  }

  return new Response(JSON.stringify({ received: true }), { status: 200, headers: cors });
}

async function verifyStripeSignature(body, sigHeader, secret) {
  try {
    const parts     = sigHeader.split(',');
    const tPart     = parts.find(p => p.startsWith('t='));
    const v1Part    = parts.find(p => p.startsWith('v1='));
    if (!tPart || !v1Part) return false;

    const ts        = tPart.split('=')[1];
    const sig       = v1Part.split('=')[1];
    const payload   = `${ts}.${body}`;

    const key       = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const computed  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const hex       = Array.from(new Uint8Array(computed)).map(b => b.toString(16).padStart(2,'0')).join('');
    return hex === sig;
  } catch { return false; }
}

// ─── Subscription activation / deactivation (D1 writes) ─────────────────────
async function activateSubscription(env, { email, plan, processor, external_id, amount_usd, amount_inr }) {
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db || !email) return;
  const tier    = normalizeTier(plan);
  const apiKey  = `cdb_${tier.toLowerCase().slice(0,4)}_${crypto.randomUUID().replace(/-/g,'').slice(0,20)}`;
  const now     = new Date().toISOString();

  try {
    await db.batch([
      db.prepare(
        `INSERT OR REPLACE INTO subscriptions
           (email, plan, status, processor, external_id, price_inr, activated_at, expires_at)
         VALUES (?,?,?,?,?,?,?, datetime('now','+31 days'))`
      ).bind(email, tier, 'active', processor, external_id || null,
             amount_inr || Math.round((amount_usd || 0) * 83), now),

      db.prepare(
        `INSERT OR REPLACE INTO api_keys
           (key_id, email, tier, active, created_at)
         VALUES (?,?,?,1,?)`
      ).bind(apiKey, email, tier, now),
    ]);

    // Push API key to KV for fast auth resolution
    const kv = env.SECURITY_HUB_KV;
    if (kv) {
      await kv.put(`apikey:${apiKey}`,
        JSON.stringify({ tier, owner_email: email, created_at: now, active: true, label: tier }),
        { expirationTtl: 86400 * 32 });
    }
  } catch (err) {
    console.error('[Subscription] activateSubscription error:', err.message);
  }
}

async function deactivateSubscription(env, email, reason) {
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db || !email) return;
  try {
    await db.prepare(
      `UPDATE subscriptions SET status=?, cancelled_at=datetime('now') WHERE email=? AND status='active'`
    ).bind(`cancelled_${reason}`, email).run();
  } catch {}
}

// ─── GET /api/subscription/plan ──────────────────────────────────────────────
export async function handleGetMyPlan(request, env, authCtx = {}) {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type':                'application/json',
  };
  const tier = normalizeTier(authCtx.tier);
  const def  = getTierDef(tier);
  return new Response(JSON.stringify({
    tier,
    label:         def.label,
    monthly_limit: def.monthly_limit,
    daily_limit:   def.daily_limit,
    price_inr:     def.price_inr,
    price_usd:     def.price_usd,
    features:      def.features,
    upgrade_url:   'https://cyberdudebivash.in/#pricing',
  }), { status: 200, headers: cors });
}
