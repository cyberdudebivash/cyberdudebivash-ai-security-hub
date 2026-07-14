/**
 * CYBERDUDEBIVASH AI Security Hub — Subscription Engine v1.0
 * Handles SaaS plan management, monthly billing via Razorpay, usage tracking
 * Plans: FREE | STARTER ₹999 | PRO ₹1499 | ENTERPRISE ₹4999
 */

import { TIER_LIMITS, PLAN_FEATURES, hasAccess, resolveApiKeyFromDB } from '../auth/apiKeys.js';
import { corsHeaders } from '../middleware/cors.js';
// handleCreateSubscription/handleActivateSubscription below delegate to these
// rather than re-implementing order creation/verification — see their doc
// comments for why (this used to be a second, broken parallel implementation).
import { handleCreateOrder, handleVerifyPayment } from './payments.js';

// ─── Subscription pricing (in paise = INR × 100) ─────────────────────────────
// SSOT: These prices MUST match lib/razorpay.js SUBSCRIPTION_PRICES exactly.
// razorpay.js is authoritative for what Razorpay charges; this file drives UI display.
// Mismatch = customer sees wrong price → commercial/accounting failure.
const SUBSCRIPTION_PLANS = {
  STARTER: {
    name:        'Starter',
    price_inr:   999,
    amount:      99900,
    price_annual_inr: 9990,
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
// Compatibility shim over the canonical order-creation path
// (handlers/payments.js handleCreateOrder). This function used to run its own
// parallel Razorpay order-creation logic and cache the intent under a
// sub_order: KV key that only handleActivateSubscription (below) understood —
// a second, divergent order path from the one every other paid product on
// the platform uses, invisible to the payments table (D1) that billing
// history/admin views/webhooks all read from. Kept as its own route/function
// (not deleted, per backward-compatibility requirements) so any existing
// integration or cached frontend bundle calling POST /api/subscription/create
// keeps working — it now produces a real, correctly-recorded payments row
// via the same code path the pricing page's checkout uses, instead of a
// KV-only one nothing else on the platform could see.
export async function handleCreateSubscription(request, env, authCtx = {}) {
  const headers = corsHeaders(request);
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const { plan, email, name } = body;

  const planKey  = (plan || '').toUpperCase();
  const planInfo = SUBSCRIPTION_PLANS[planKey];
  if (!planInfo) {
    return new Response(JSON.stringify({ success: false, error: 'Invalid plan. Choose STARTER, PRO, ENTERPRISE, or MSSP.' }), {
      status: 400, headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }
  if (!email || !String(email).includes('@')) {
    return new Response(JSON.stringify({ success: false, error: 'A valid email is required to create a subscription order.' }), {
      status: 400, headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }

  const syntheticReq = new Request('https://internal/api/payments/create-order', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ module: 'subscription', target: email, plan: planKey, email, name }),
  });
  const res  = await handleCreateOrder(syntheticReq, env, authCtx);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return new Response(JSON.stringify({ success: false, error: data.error || 'Order creation failed.' }), {
      status: res.status, headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }

  // Old response shape (plan/plan_name/notes) preserved alongside the
  // canonical fields, so neither an old nor a new caller breaks.
  return new Response(JSON.stringify({
    success:   true,
    order_id:  data.order_id,
    key_id:    data.key_id,
    amount:    data.amount,
    currency:  data.currency,
    plan:      planKey,
    plan_name: planInfo.name,
    receipt:   data.receipt,
    notes:     { plan: planKey, email, name: name || '', type: 'subscription', source: 'cyberdudebivash.in' },
  }), { headers: { ...headers, 'Content-Type': 'application/json' } });
}

// ─── POST /api/subscription/activate ─────────────────────────────────────────
// Compatibility shim over the canonical, price-authoritative verify path
// (handlers/payments.js handleVerifyPayment). The former implementation's
// payments/subscriptions INSERTs used column names that don't exist in the
// live D1 schema (order_id/payment_id vs the real razorpay_order_id/
// razorpay_payment_id; processor/external_id/activated_at vs the real
// schema) — silently swallowed by .catch(), so every activation attempt was
// charged and never actually activated, and users.tier was never touched at
// all (see PR #142's incident writeup). PR #142 fixed the one known frontend
// caller (the dashboard's "Upgrade to Pro" button) by pointing it at the
// canonical path directly; this closes the same gap at the route/handler
// level too, so any other caller of this URL (an external integration, a
// future frontend regression pointing back at this route, direct API use)
// gets the same correct, tested behavior instead of the same silent failure.
export async function handleActivateSubscription(request, env, authCtx = {}) {
  const headers = corsHeaders(request);
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const {
    razorpay_order_id, razorpay_payment_id, razorpay_signature, email,
    utm_source = '', utm_medium = '', utm_campaign = '',
  } = body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return new Response(JSON.stringify({ success: false, error: 'Missing payment verification fields.' }), {
      status: 400, headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }

  // module/target sent here are only a fallback for the (rare) case where D1
  // has no record of this order — handleVerifyPayment's own authoritative
  // order lookup overrides them from the real payments row when one exists,
  // so this shim cannot be used to activate a plan other than what was paid
  // for, the same protection every other subscription entry point now has.
  const syntheticReq = new Request('https://internal/api/payments/verify', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      razorpay_order_id, razorpay_payment_id, razorpay_signature,
      module: 'subscription', target: email || 'unknown@cyberdudebivash.in', email,
      utm_source, utm_medium, utm_campaign,
    }),
  });
  const res  = await handleVerifyPayment(syntheticReq, env, authCtx);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return new Response(JSON.stringify({ success: false, error: data.error || 'Activation failed.' }), {
      status: res.status, headers: { ...headers, 'Content-Type': 'application/json' },
    });
  }

  // Old response shape (session_token/features/message) preserved; new
  // fields (token/refresh_token/user_id — the actual JWT tier grant) added
  // alongside so a caller upgrading to the real login flow can use them.
  return new Response(JSON.stringify({
    success:       true,
    plan:          data.plan,
    session_token: data.session_token,
    expires_at:    data.expires_at,
    token:         data.token,
    refresh_token: data.refresh_token,
    user_id:       data.user_id,
    features:      PLAN_FEATURES[data.plan] || PLAN_FEATURES.FREE,
    message:       data.message,
  }), { headers: { ...headers, 'Content-Type': 'application/json' } });
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
      scans: '5/day',
      description: 'Get started with domain scanning and threat intelligence',
      features: ['5 domain scans/day', 'CVE feed (5 entries)', 'Basic threat intel', 'AI threat correlation', 'Report generation (7-day retention)', '1 API key', 'Community support'],
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
function getMonthResetDate() {
  const now  = new Date();
  const next = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  return next.toISOString().slice(0, 10);
}
