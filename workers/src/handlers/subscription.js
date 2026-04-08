/**
 * CYBERDUDEBIVASH AI Security Hub — Subscription Engine v1.0
 * Handles SaaS plan management, monthly billing via Razorpay, usage tracking
 * Plans: FREE | STARTER ₹499 | PRO ₹1499 | ENTERPRISE ₹4999
 */

import { TIER_LIMITS, PLAN_FEATURES, hasAccess, resolveApiKeyFromDB } from '../auth/apiKeys.js';
import { createRazorpayOrder, generateReceiptId, verifyPaymentSignature } from '../lib/razorpay.js';
import { corsHeaders } from '../middleware/cors.js';

// ─── Subscription pricing (in paise = INR × 100) ─────────────────────────────
const SUBSCRIPTION_PLANS = {
  STARTER: {
    name:        'Starter',
    price_inr:   499,
    amount:      49900,
    scans:       10,
    description: '10 scans/month, AI Analyze, PDF Reports',
    features:    ['10 scans/month', 'AI Threat Analysis', 'PDF Reports', '2 API Keys', 'Email Support'],
    color:       '#3b82f6',
  },
  PRO: {
    name:        'Pro',
    price_inr:   1499,
    amount:      149900,
    scans:       -1,
    description: 'Unlimited scans, Full AI Suite, API Access',
    features:    ['Unlimited scans', 'Full AI Brain V2', 'API Access', '5 API Keys', 'Priority Support', 'Advanced Reports'],
    color:       '#8b5cf6',
  },
  ENTERPRISE: {
    name:        'Enterprise',
    price_inr:   4999,
    amount:      499900,
    scans:       -1,
    description: 'Multi-user, API access, dedicated support',
    features:    ['Unlimited scans', 'Full AI Brain V2', 'API Access', '20 API Keys', 'Multi-User (10 seats)', 'Dedicated Support', 'Custom Integrations', 'SLA Guarantee'],
    color:       '#f59e0b',
  },
};

// ─── GET /api/user/plan ───────────────────────────────────────────────────────
export async function handleGetUserPlan(request, env) {
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
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, email } = body;

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

    // Store subscription session in KV
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
      await env.KV.delete(`sub_order:${razorpay_order_id}`);
    }

    // Record in D1 payments table if available
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
      ).run().catch(() => {}); // Non-fatal — KV is source of truth
    }

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
  const plans = Object.entries(SUBSCRIPTION_PLANS).map(([key, p]) => ({
    id:          key,
    name:        p.name,
    price_inr:   p.price_inr,
    scans:       p.scans === -1 ? 'Unlimited' : `${p.scans}/month`,
    description: p.description,
    features:    p.features,
    color:       p.color,
    popular:     key === 'PRO',
  }));

  return new Response(JSON.stringify({ success: true, plans }), {
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
  const row   = await env.DB.prepare(
    `SELECT COALESCE(SUM(request_count), 0) as total FROM api_key_usage
     WHERE ${col} = ? AND date_bucket >= ?`
  ).bind(queryParam, monthStart).first();

  const used = row?.total ?? 0;
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
