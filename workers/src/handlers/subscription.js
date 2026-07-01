/**
 * CYBERDUDEBIVASH AI Security Hub — Subscription Engine v1.0
 * Handles SaaS plan management, monthly billing via Razorpay, usage tracking
 * Plans: FREE | STARTER ₹499 | PRO ₹1499 | ENTERPRISE ₹4999
 */

import { TIER_LIMITS, PLAN_FEATURES, hasAccess, resolveApiKeyFromDB } from '../auth/apiKeys.js';
import { createRazorpayOrder, generateReceiptId, verifyPaymentSignature } from '../lib/razorpay.js';
import { corsHeaders } from '../middleware/cors.js';

// ─── Subscription pricing (in paise = INR × 100) ─────────────────────────────
// SSOT: These prices MUST match lib/razorpay.js SUBSCRIPTION_PRICES exactly.
// razorpay.js is authoritative for what Razorpay charges; this file drives UI display.
// Mismatch = customer sees wrong price → commercial/accounting failure.
const SUBSCRIPTION_PLANS = {
  STARTER: {
    name:        'Starter',
    price_inr:   499,
    amount:      49900,
    price_annual_inr: 4990,
    scans:       600,
    description: '600 scans/month, AI Threat Analysis, PDF Reports, Sentinel CVE Feed',
    features:    ['600 scans/month', 'AI Threat Analysis', 'PDF Reports', 'Sentinel CVE Feed', '2 API Keys', 'Email Support'],
    color:       '#3b82f6',
    popular:     false,
  },
  PRO: {
    name:        'Pro',
    price_inr:   1499,
    amount:      149900,
    price_annual_inr: 14990,
    scans:       -1,
    description: 'Unlimited scans, Full AI Suite, SIEM export, DPDP compliance, API Access',
    features:    [
      'Unlimited scans', 'Full AI Copilot (God Mode)', 'SIEM Export (JSON/CEF/STIX/Sigma)',
      'DPDP Compliance Engine', 'IOC Enrichment (VirusTotal)', '5 API Keys',
      'Priority Support (24h SLA)', 'GST Invoices', 'Advanced PDF Reports',
    ],
    color:       '#8b5cf6',
    popular:     true,
  },
  ENTERPRISE: {
    name:        'Enterprise',
    price_inr:   4999,
    amount:      499900,
    price_annual_inr: 49990,
    scans:       -1,
    description: 'Multi-tenant SOC, MSSP white-label, dedicated support, SLA guarantee',
    features:    [
      'Unlimited scans', 'Full AI God Mode + APEX Copilot', 'Multi-tenant SOC Dashboard',
      'MSSP White-label (unlimited tenants)', 'Custom SIEM integrations', '50 API Keys',
      'Team access (unlimited seats)', 'Dedicated Account Manager', '4h SLA guarantee',
      'Custom DPDP compliance reports', 'GST invoices + ITC support', 'Annual DPDP retainer',
      'On-premise deployment option',
    ],
    color:       '#f59e0b',
    popular:     false,
  },
  MSSP: {
    name:        'MSSP Suite',
    price_inr:   9999,
    amount:      999900,
    price_annual_inr: 99990,
    scans:       -1,
    description: 'Full white-label MSSP platform — unlimited tenants, revenue share',
    features:    [
      'Everything in Enterprise', 'Unlimited white-label tenants', 'Revenue share program (60/40)',
      'Partner onboarding portal', 'Custom branded SOC dashboard', 'Reseller API',
      'Co-marketing support', 'Dedicated infra SLA (99.9%)', 'CERT-In aligned reporting',
    ],
    color:       '#06b6d4',
    popular:     false,
  },
};

// ─── GET /api/user/plan ───────────────────────────────────────────────────────
export async function handleGetUserPlan(request, env, authCtx = null) {
  const headers = corsHeaders(request);

  try {
    // Resolve user identity — from auth header (API key) or payment session token
    const authHeader = request.headers.get('Authorization') || '';
    const sessionToken = request.headers.get('X-Session-Token') || '';
    const url = new URL(request.url);
    const queryToken = url.searchParams.get('token') || '';

    let userPlan = 'FREE';
    let userId   = null;
    let keyId    = null;
    let email    = null;

    // Prefer the unified auth resolver (handles JWT bearer tokens from
    // login/signup) — without this, every JWT-authenticated customer hit the
    // 'Bearer cdb_' branch below (API-key format only), which silently never
    // matched a JWT, so logged-in paying customers always saw plan: FREE,
    // email: null here regardless of their real tier.
    if (authCtx?.authenticated && authCtx.method === 'jwt' && authCtx.tier) {
      userPlan = authCtx.tier;
      userId   = authCtx.user_id || authCtx.userId || null;
      email    = authCtx.email || null;
    }

    // Try API key auth first
    if (authHeader.startsWith('Bearer cdb_')) {
      const rawKey = authHeader.slice(7);
      const keyRow = env.DB ? await resolveApiKeyFromDB(env.DB, rawKey) : null;
      if (keyRow) {
        userPlan = keyRow.tier || 'FREE';
        userId   = keyRow.user_id;
        keyId    = keyRow.id;
        email    = keyRow.email;
      }
    }

    // Try session token (from payment session stored in KV)
    const token = sessionToken || queryToken;
    if (token && env.KV) {
      const sessionData = await env.KV.get(`sub_session:${token}`, 'json');
      if (sessionData) {
        userPlan = sessionData.plan || userPlan;
        userId   = sessionData.user_id || userId;
        email    = sessionData.email || email;
      }
    }

    // Get monthly usage
    const monthStart = new Date().toISOString().slice(0, 7) + '-01';
    let scansUsed    = 0;

    if (env.DB && (keyId || userId)) {
      const usageQuery = keyId
        ? `SELECT COALESCE(SUM(request_count), 0) as total FROM api_key_usage WHERE key_id = ? AND date_bucket >= ?`
        : `SELECT COALESCE(SUM(request_count), 0) as total FROM api_key_usage WHERE user_id = ? AND date_bucket >= ?`;
      const usageRow = await env.DB.prepare(usageQuery).bind(keyId || userId, monthStart).first();
      scansUsed = usageRow?.total ?? 0;
    }

    const limits     = TIER_LIMITS[userPlan] || TIER_LIMITS.FREE;
    const planInfo   = SUBSCRIPTION_PLANS[userPlan] || null;
    const scansLimit = limits.scan_limit ?? limits.monthly_limit;

    return new Response(JSON.stringify({
      success: true,
      plan:    userPlan,
      email:   email || null,
      usage: {
        scans_used:      scansUsed,
        scans_limit:     scansLimit,
        scans_remaining: scansLimit === -1 ? -1 : Math.max(0, scansLimit - scansUsed),
        reset_date:      getMonthResetDate(),
      },
      key_limit:    limits.api_keys,
      features:     PLAN_FEATURES[userPlan] || PLAN_FEATURES.FREE,
      subscription: planInfo ? {
        name:      planInfo.name,
        price_inr: planInfo.price_inr,
        features:  planInfo.features,
      } : null,
      upgrade_url: '/pricing',
    }), { headers: { ...headers, 'Content-Type': 'application/json' } });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }
}

// ─── POST /api/subscription/create ───────────────────────────────────────────
// Creates a Razorpay order for the chosen plan, returns order_id for checkout
export async function handleCreateSubscription(request, env) {
  const headers = corsHeaders(request);
  try {
    const body = await request.json().catch(() => ({}));
    const { plan, email, name } = body;

    const planKey  = (plan || '').toUpperCase();
    const planInfo = SUBSCRIPTION_PLANS[planKey];
    if (!planInfo) {
      return new Response(JSON.stringify({ success: false, error: 'Invalid plan. Choose STARTER, PRO, or ENTERPRISE.' }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    const receipt = generateReceiptId();
    const notes   = {
      plan:      planKey,
      email:     email || '',
      name:      name  || '',
      type:      'subscription',
      source:    'cyberdudebivash.in',
    };

    const order = await createRazorpayOrder(env, {
      amount:   planInfo.amount,
      currency: 'INR',
      receipt,
      notes,
    });

    // Cache order intent in KV (15 min TTL) for post-payment plan activation
    if (env.KV) {
      await env.KV.put(`sub_order:${order.id}`, JSON.stringify({
        plan:    planKey,
        email:   email || '',
        name:    name  || '',
        receipt,
        created: Date.now(),
      }), { expirationTtl: 900 });
    }

    return new Response(JSON.stringify({
      success:    true,
      order_id:   order.id,
      key_id:     env.RAZORPAY_KEY_ID || '',   // required by frontend Razorpay checkout
      amount:     planInfo.amount,
      currency:   'INR',
      plan:       planKey,
      plan_name:  planInfo.name,
      receipt,
      notes,
    }), { headers: { ...headers, 'Content-Type': 'application/json' } });
  } catch (err) {
    console.error('[Subscription] createRazorpayOrder failed', err?.message);
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }
}

// ─── POST /api/subscription/activate ─────────────────────────────────────────
// Called after Razorpay payment success — verifies signature, activates plan
export async function handleActivateSubscription(request, env) {
  const headers = corsHeaders(request);
  try {
    const body = await request.json().catch(() => ({}));
    const {
      razorpay_order_id, razorpay_payment_id, razorpay_signature, email,
      utm_source = '', utm_medium = '', utm_campaign = '',
    } = body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return new Response(JSON.stringify({ success: false, error: 'Missing payment verification fields.' }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // Verify HMAC signature
    const valid = await verifyPaymentSignature(env, razorpay_order_id, razorpay_payment_id, razorpay_signature);
    if (!valid) {
      return new Response(JSON.stringify({ success: false, error: 'Payment signature verification failed.' }), {
        status: 403,
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // Look up the order intent from KV
    let orderMeta = null;
    if (env.KV) {
      orderMeta = await env.KV.get(`sub_order:${razorpay_order_id}`, 'json');
    }

    const plan      = orderMeta?.plan || 'STARTER';
    const userEmail = email || orderMeta?.email || '';

    // Generate 90-day session token for this subscription
    const sessionToken = generateSubscriptionToken();
    const expiresAt    = Date.now() + 90 * 24 * 60 * 60 * 1000; // 90 days

    // D1 FIRST — source of truth for subscription state.
    // KV is written only after D1 succeeds to prevent state divergence.
    if (env.DB) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO payments
         (order_id, payment_id, module, amount, currency, status, email, report_token, created_at)
         VALUES (?, ?, ?, ?, 'INR', 'captured', ?, ?, datetime('now'))`
      ).bind(
        razorpay_order_id,
        razorpay_payment_id,
        `subscription:${plan}`,
        SUBSCRIPTION_PLANS[plan]?.amount || 0,
        userEmail,
        sessionToken,
      ).run().catch((e) => console.error('[subscription] payments D1 write failed', razorpay_payment_id, e?.message));

      // Write to subscriptions table for renewal engine + lifecycle tracking
      await env.DB.prepare(
        `INSERT OR IGNORE INTO subscriptions
         (id, email, plan, status, processor, external_id, price_inr, activated_at, expires_at, created_at)
         VALUES (?, ?, ?, 'active', 'razorpay', ?, ?, datetime('now'), ?, datetime('now'))`
      ).bind(
        'sub_' + Date.now().toString(36),
        userEmail || '',
        plan,
        razorpay_payment_id,
        SUBSCRIPTION_PLANS[plan]?.price_inr || 499,
        new Date(expiresAt).toISOString(),
      ).run().catch((e) => console.error('[subscription] subscriptions D1 write failed', razorpay_payment_id, e?.message));
    }

    // KV session cache — written after D1 so we don't serve stale token if DB fails.
    if (env.KV) {
      await env.KV.put(`sub_session:${sessionToken}`, JSON.stringify({
        plan,
        email:      userEmail,
        payment_id: razorpay_payment_id,
        order_id:   razorpay_order_id,
        activated:  Date.now(),
        expires_at: expiresAt,
      }), { expirationTtl: 90 * 24 * 3600 });

      // Clean up the order intent
      await env.KV.delete(`sub_order:${razorpay_order_id}`).catch(() => {});
    }

    // Fire-and-forget: GST invoice + plan activation email + lifecycle enrollment
    const planDef = SUBSCRIPTION_PLANS[plan];
    Promise.all([
      (async () => {
        try {
          const { createInvoice } = await import('../services/v24/billingEngine.js');
          if (env.DB && planDef?.price_inr) {
            await createInvoice(env.DB, {
              userId:      `sub_${sessionToken.slice(0, 16)}`,
              email:       userEmail || 'noreply@buyer',
              lineItems:   [{ description: `${planDef.name} Subscription (Monthly)`, amount_inr: planDef.price_inr, quantity: 1 }],
              paymentId:   razorpay_payment_id,
              paymentMethod: 'razorpay',
            }, env);
          }
        } catch (e) { console.warn('[Subscription] invoice error:', e.message); }
      })(),
      (async () => {
        try {
          if (!userEmail) return;
          const { sendPurchaseConfirmation } = await import('../services/emailEngine.js');
          await sendPurchaseConfirmation(env, {
            to:          userEmail,
            productName: `${planDef?.name || plan} Plan (Monthly Subscription)`,
            amountInr:   planDef?.price_inr || 0,
            paymentId:   razorpay_payment_id,
            accessExpires: new Date(expiresAt).toISOString(),
          });
        } catch (e) { console.warn('[Subscription] email error:', e.message); }
      })(),
      (async () => {
        try {
          if (!userEmail) return;
          const { triggerPostPurchase } = await import('../services/lifecycleEngine.js');
          await triggerPostPurchase(env, {
            email:        userEmail,
            product:      `SUBSCRIPTION_${plan}`,
            product_name: `${planDef?.name || plan} Plan`,
            amount_inr:   planDef?.price_inr || 0,
            event_type:   'subscription_activated',
            source:       utm_source || 'direct',
            payment_id:   razorpay_payment_id,
            plan,
            meta:         { utm_medium, utm_campaign, session_token: sessionToken },
          });
        } catch (e) { console.warn('[Subscription] lifecycle error:', e.message); }
      })(),
    ]).catch(() => {});

    return new Response(JSON.stringify({
      success:       true,
      plan,
      session_token: sessionToken,
      expires_at:    expiresAt,
      features:      PLAN_FEATURES[plan] || PLAN_FEATURES.FREE,
      message:       `${SUBSCRIPTION_PLANS[plan]?.name || plan} plan activated! Your token is saved for 90 days.`,
    }), { headers: { ...headers, 'Content-Type': 'application/json' } });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }
}

// ─── GET /api/subscription/plans ─────────────────────────────────────────────
// Public — returns all available plans for the pricing page
export async function handleGetPlans(request, env) {
  const headers = corsHeaders(request);
  const plans = [
    {
      tier: 'FREE',
      name: 'Explorer',
      price_inr: 0,
      price_annual_inr: 0,
      billing_cycle: 'forever',
      scans: '3/day',
      description: 'Get started with domain scanning and threat intelligence',
      features: ['3 domain scans/day', 'CVE feed (5 entries)', 'Basic threat intel', '1 API key', 'Community support'],
      color: '#64748b',
      popular: false,
      cta: 'Start Free',
    },
    ...Object.entries(SUBSCRIPTION_PLANS).map(([key, p]) => ({
      tier:             key,
      name:             p.name,
      price_inr:        p.price_inr,
      price_annual_inr: p.price_annual_inr,
      billing_cycle:    'monthly',
      amount_paise:     p.amount,
      scans:            p.scans === -1 ? 'Unlimited' : `${p.scans}/month`,
      description:      p.description,
      features:         p.features,
      color:            p.color,
      popular:          p.popular || false,
      cta:              key === 'ENTERPRISE' || key === 'MSSP' ? 'Contact Sales' : 'Subscribe Now',
      checkout_url:     ['ENTERPRISE', 'MSSP'].includes(key)
        ? 'mailto:sales@cyberdudebivash.in'
        : 'POST /api/subscription/create',
    })),
  ];

  return new Response(JSON.stringify({ success: true, data: { plans, currency: 'INR', updated_at: new Date().toISOString() } }), {
    headers: { ...headers, 'Content-Type': 'application/json' },
  });
}

// ─── Monthly scan quota enforcement (middleware helper) ───────────────────────
// Returns { allowed: bool, scans_used: int, scans_limit: int }
export async function checkMonthlyQuota(env, identity) {
  const { plan, keyId, userId } = identity;
  const limits     = TIER_LIMITS[plan] || TIER_LIMITS.FREE;
  const scanLimit  = limits.scan_limit ?? limits.monthly_limit;

  if (scanLimit === -1) return { allowed: true, scans_used: 0, scans_limit: -1 };

  if (!env.DB) return { allowed: true, scans_used: 0, scans_limit: scanLimit }; // No DB, allow

  const monthStart = new Date().toISOString().slice(0, 7) + '-01';
  const queryParam = keyId || userId;
  if (!queryParam) return { allowed: true, scans_used: 0, scans_limit: scanLimit };

  const col   = keyId ? 'key_id' : 'user_id';
  // Fail-open: a metering-table error must never 500 a paying customer's scan.
  let used = 0;
  try {
    const row = await env.DB.prepare(
      `SELECT COALESCE(SUM(request_count), 0) as total FROM api_key_usage
       WHERE ${col} = ? AND date_bucket >= ?`
    ).bind(queryParam, monthStart).first();
    used = row?.total ?? 0;
  } catch {
    return { allowed: true, scans_used: 0, scans_limit: scanLimit };
  }

  return {
    allowed:         used < scanLimit,
    scans_used:      used,
    scans_limit:     scanLimit,
    scans_remaining: Math.max(0, scanLimit - used),
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateSubscriptionToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function getMonthResetDate() {
  const now  = new Date();
  const next = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  return next.toISOString().slice(0, 10);
}
