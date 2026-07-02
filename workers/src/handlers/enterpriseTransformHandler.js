/**
 * CYBERDUDEBIVASH AI Security Hub — P16.0 Enterprise Transformation
 *
 * Endpoints:
 *   GET  /api/platform/kpi                     — P16.1 Platform KPI Command Center (MRR/ARR/CAC/LTV/Churn/NRR/ARPU)
 *   GET  /api/customer/billing/portal          — P16.2 Customer Self-Serve Billing Portal
 *   GET  /api/customer/billing/invoices        — P16.2 Invoice history & download links
 *   POST /api/customer/billing/cancel          — P16.2 Self-serve subscription cancellation
 *   POST /api/customer/billing/upgrade         — P16.2 Self-serve plan upgrade initiation
 *   GET  /api/customer/usage/live              — P16.2 Per-user live API usage metering
 *   GET  /api/platform/overage/report          — P16.3 Overage detection report (ADMIN)
 *   POST /api/platform/overage/charge          — P16.3 Trigger overage billing for a user (ADMIN)
 *   GET  /api/platform/kpi/executive           — P16.4 Executive KPI summary (CEO/Board format)
 *   GET  /api/platform/transform/observability — P16.5 P16 observability gate
 *
 * Architecture:
 *   Reuses D1 tables: subscriptions, api_key_usage, invoices, users, api_keys,
 *                     customer_entitlements, ops_usage_events, customer_profiles
 *   Reuses KV: SECURITY_HUB_KV (apikey:*, platform:kpi:*, usage:overage:*)
 *   NEVER duplicates: commercialPlatformHandler, revenueMetrics, subscriptionPaywallEngine
 */

import { TIER_LIMITS } from '../auth/apiKeys.js';
import { isRealUser } from '../auth/middleware.js';

// ── Auth helpers (reused pattern from P15) ───────────────────────────────────

const ADMIN_TIERS  = new Set(['OWNER', 'ADMIN']);
const PLAN_ORDER   = { FREE: 0, STARTER: 1, PRO: 2, ENTERPRISE: 3, MSSP: 4 };

function authGuard(authCtx) {
  if (!isRealUser(authCtx)) {
    return Response.json(
      { success: false, error: 'Authentication required', service: 'CDB-P16' },
      { status: 401 }
    );
  }
  return null;
}

function adminGuard(authCtx) {
  const g = authGuard(authCtx);
  if (g) return g;
  if (!ADMIN_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'Admin access required', service: 'CDB-P16' },
      { status: 403 }
    );
  }
  return null;
}

async function kvGet(env, key) {
  try { return JSON.parse(await env.SECURITY_HUB_KV.get(key)); } catch { return null; }
}

async function kvSet(env, key, value, ttl = 300) {
  try { await env.SECURITY_HUB_KV.put(key, JSON.stringify(value), { expirationTtl: ttl }); } catch {}
}

function resolveUserId(authCtx) {
  return authCtx?.userId || authCtx?.email || authCtx?.identity || 'anon';
}

// ── P16.1 — Platform KPI Command Center ──────────────────────────────────────

export async function handlePlatformKPI(request, env, authCtx) {
  const gate = adminGuard(authCtx);
  if (gate) return gate;

  const cacheKey = 'platform:kpi:v1';
  const cached   = await kvGet(env, cacheKey);
  if (cached) return Response.json({ success: true, cached: true, ...cached });

  const now  = new Date();
  const y    = now.getUTCFullYear();
  const m    = String(now.getUTCMonth() + 1).padStart(2, '0');
  const monthStart = `${y}-${m}-01`;

  // Pull from D1 — subscriptions, invoices, api_key_usage, users
  const [subRows, invoiceRows, userRows, usageRows] = await Promise.all([
    env.DB?.prepare(
      `SELECT plan, status, price_inr, trial_ends_at, created_at FROM subscriptions WHERE status IN ('active','trialing')`
    ).all().catch(() => ({ results: [] })),
    env.DB?.prepare(
      `SELECT total_inr, currency, status, created_at FROM invoices WHERE status='paid' AND created_at >= ? ORDER BY created_at DESC LIMIT 500`
    ).bind(`${y}-01-01`).all().catch(() => ({ results: [] })),
    env.DB?.prepare(
      `SELECT tier, status, created_at FROM users ORDER BY created_at DESC LIMIT 1000`
    ).all().catch(() => ({ results: [] })),
    env.DB?.prepare(
      `SELECT user_id, SUM(request_count) as reqs FROM api_key_usage WHERE period_start >= ? GROUP BY user_id`
    ).bind(monthStart).all().catch(() => ({ results: [] })),
  ]);

  const subs   = subRows?.results  || [];
  const invoices = invoiceRows?.results || [];
  const users  = userRows?.results || [];
  const usage  = usageRows?.results || [];

  // MRR — monthly recurring revenue from active subs
  const TIER_PRICE = { FREE: 0, STARTER: 29, PRO: 99, ENTERPRISE: 499, MSSP: 999 };
  const activeSubs = subs.filter(s => s.status === 'active');
  const mrr = activeSubs.reduce((sum, s) => {
    const price = s.amount_usd || TIER_PRICE[(s.tier || '').toUpperCase()] || 0;
    return sum + price;
  }, 0);
  const arr = mrr * 12;

  // Trial conversion candidates
  const trialSubs  = subs.filter(s => s.status === 'trialing');
  const trialCount = trialSubs.length;

  // Revenue YTD from paid invoices
  const revenueYTD = invoices.reduce((sum, inv) => sum + (parseFloat(inv.amount_usd) || 0), 0);

  // Churn — active this month vs total ever
  const totalUsers   = users.length;
  const activeMonthly = users.filter(u => {
    const d = new Date(u.created_at || 0);
    return d >= new Date(monthStart);
  }).length;

  // ARPU — average revenue per paid user
  const paidUsers = activeSubs.length;
  const arpu = paidUsers > 0 ? (mrr / paidUsers) : 0;

  // API consumption this month
  const totalApiReqs = usage.reduce((sum, r) => sum + (parseInt(r.reqs) || 0), 0);
  const apiUsers     = usage.length;

  // Tier distribution
  const tierDist = {};
  for (const u of users) {
    const t = (u.tier || 'FREE').toUpperCase();
    tierDist[t] = (tierDist[t] || 0) + 1;
  }

  // LTV/NRR/CAC require revenue history to compute meaningfully — null until real data available
  const ltv = null;
  const nrr = null;
  const cac_estimate = null;

  const kpi = {
    generated_at:     now.toISOString(),
    period:           `${y}-${m}`,
    mrr:              Math.round(mrr * 100) / 100,
    arr:              Math.round(arr * 100) / 100,
    arpu:             Math.round(arpu * 100) / 100,
    ltv_estimate:     null,
    ltv_note:         'Requires ≥3 months of revenue history to compute',
    nrr_estimate:     null,
    nrr_note:         'Requires subscription upgrade/downgrade event tracking',
    cac_estimate:     null,
    cac_note:         'Requires ad-spend and acquisition-channel data',
    revenue_ytd:      Math.round(revenueYTD * 100) / 100,
    active_paid_subs: paidUsers,
    trial_count:      trialCount,
    total_users:      totalUsers,
    new_users_mtd:    activeMonthly,
    tier_distribution: tierDist,
    api_requests_mtd:  totalApiReqs,
    api_active_users:  apiUsers,
    churn_rate_est:   totalUsers > 0 ? Math.round(((totalUsers - activeMonthly) / Math.max(totalUsers, 1)) * 1000) / 10 : 0,
  };
  // Aliases for the enterprise-kpi-dashboard.html frontend, which reads these
  // flat field names directly off the response root (not nested under `kpi`).
  kpi.nrr             = Math.round(nrr * 10000) / 100; // ratio -> percent
  kpi.churn_rate      = kpi.churn_rate_est;
  kpi.plan_distribution = tierDist;
  kpi.total_customers = totalUsers;

  await kvSet(env, cacheKey, kpi, 300);
  return Response.json({ success: true, cached: false, kpi });
}

// ── P16.2 — Customer Self-Serve Billing Portal ───────────────────────────────

export async function handleCustomerBillingPortal(request, env, authCtx) {
  const gate = authGuard(authCtx);
  if (gate) return gate;

  const userId = resolveUserId(authCtx);
  const email  = authCtx.email || null;

  const [subRow, invoiceRows, entitlementRows, keyRows] = await Promise.all([
    env.DB?.prepare(
      `SELECT id, plan, status, price_inr, trial_ends_at, current_period_end, cancel_at_period_end, created_at
       FROM subscriptions WHERE user_id=? OR email=? ORDER BY created_at DESC LIMIT 1`
    ).bind(userId, email).first().catch(() => null),
    env.DB?.prepare(
      `SELECT id, total_inr, currency, status, created_at, pdf_key
       FROM invoices WHERE user_id=? OR email=? ORDER BY created_at DESC LIMIT 12`
    ).bind(userId, email).all().catch(() => ({ results: [] })),
    env.DB?.prepare(
      `SELECT feature, granted_at, expires_at FROM customer_entitlements WHERE user_id=? AND (expires_at IS NULL OR expires_at > datetime('now'))`
    ).bind(userId).all().catch(() => ({ results: [] })),
    env.DB?.prepare(
      `SELECT id, label, tier, last_used_at FROM api_keys WHERE user_id=? OR email=? ORDER BY last_used_at DESC LIMIT 10`
    ).bind(userId, email).all().catch(() => ({ results: [] })),
  ]);

  const sub         = subRow || null;
  const invoices    = invoiceRows?.results || [];
  const features    = entitlementRows?.results || [];
  const keys        = keyRows?.results || [];
  const currentTier = sub?.plan || authCtx.tier || 'FREE';

  // Upgrade options — plans higher than current. Priced from TIER_LIMITS, the
  // same source of truth Razorpay checkout actually charges against, so what
  // the customer is shown here always matches what they're billed.
  const currentOrder  = PLAN_ORDER[(currentTier || '').toUpperCase()] || 0;
  const upgradeOptions = Object.entries(PLAN_ORDER)
    .filter(([, order]) => order > currentOrder)
    .map(([plan]) => ({
      plan,
      price_inr_month: TIER_LIMITS[plan]?.price_inr ?? 0,
      highlight: plan === 'PRO' ? 'Most Popular' : plan === 'ENTERPRISE' ? 'Best for Teams' : null,
    }));

  return Response.json({
    success: true,
    portal: {
      user_id:      userId,
      current_plan: currentTier,
      subscription: sub,
      invoices:     invoices.slice(0, 12),
      entitlements: features,
      api_keys:     keys,
      upgrade_options: upgradeOptions,
      can_cancel: sub?.status === 'active',
      cancel_url: '/api/customer/billing/cancel',
      upgrade_url: '/api/customer/billing/upgrade',
    },
  });
}

export async function handleCustomerInvoices(request, env, authCtx) {
  const gate = authGuard(authCtx);
  if (gate) return gate;

  const userId = resolveUserId(authCtx);
  const email  = authCtx.email || null;
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '24'), 100);
  const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);

  const rows = await env.DB?.prepare(
    `SELECT id, total_inr, currency, status, created_at, pdf_key
     FROM invoices WHERE user_id=? OR email=?
     ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).bind(userId, email, limit, offset).all().catch(() => ({ results: [] }));

  return Response.json({
    success: true,
    invoices: rows?.results || [],
    pagination: { limit, offset },
  });
}

// ── Customer pay-per-report purchase history ─────────────────────────────────
// The customer dashboard's Payment History tab used to call the owner-only
// /api/admin/analytics endpoint, which 403'd for every real customer and
// showed a misleading "Upgrade to PRO" message regardless of their actual
// plan or purchase history. This is the real, user-scoped equivalent.
export async function handleCustomerPayments(request, env, authCtx) {
  const gate = authGuard(authCtx);
  if (gate) return gate;

  const userId = resolveUserId(authCtx);
  const email  = authCtx.email || null;
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);

  const rows = await env.DB?.prepare(
    `SELECT id, module, target, amount, currency, status, plan, created_at, paid_at
     FROM payments WHERE user_id=? OR email=?
     ORDER BY created_at DESC LIMIT ?`
  ).bind(userId, email, limit).all().catch(() => ({ results: [] }));

  return Response.json({
    success:  true,
    payments: rows?.results || [],
  });
}

export async function handleCancelSubscription(request, env, authCtx) {
  const gate = authGuard(authCtx);
  if (gate) return gate;

  const userId = resolveUserId(authCtx);
  const email  = authCtx.email || null;
  const body   = await request.json().catch(() => ({}));
  const reason = (body.reason || 'user_requested').slice(0, 200);

  const sub = await env.DB?.prepare(
    `SELECT id, plan, status FROM subscriptions WHERE (user_id=? OR email=?) AND status='active' LIMIT 1`
  ).bind(userId, email).first().catch(() => null);

  if (!sub) {
    return Response.json({ success: false, error: 'No active subscription found' }, { status: 404 });
  }

  // Mark cancel_at_period_end — never immediate hard-cancel without refund review
  await env.DB?.prepare(
    `UPDATE subscriptions SET cancel_at_period_end=1, cancel_reason=?, updated_at=datetime('now') WHERE id=?`
  ).bind(reason, sub.id).run().catch(() => {});

  // Log to provisioning events
  await env.DB?.prepare(
    `INSERT INTO provisioning_log (user_id, event, metadata, created_at) VALUES (?, 'CANCEL_REQUESTED', ?, datetime('now'))`
  ).bind(userId, JSON.stringify({ subscription_id: sub.id, plan: sub.plan, reason })).run().catch(() => {});

  // Invalidate KPI cache so next pull reflects change
  await env.SECURITY_HUB_KV?.delete('platform:kpi:v1').catch(() => {});

  return Response.json({
    success: true,
    message: `Subscription will cancel at end of current billing period. You retain ${sub.plan} access until then.`,
    subscription_id: sub.id,
  });
}

export async function handleUpgradeInitiate(request, env, authCtx) {
  const gate = authGuard(authCtx);
  if (gate) return gate;

  const userId   = resolveUserId(authCtx);
  const body     = await request.json().catch(() => ({}));
  // Frontend sends target_plan; accept plan too for direct API callers.
  const newPlan  = (body.target_plan || body.plan || '').toUpperCase();

  if (!PLAN_ORDER[newPlan]) {
    return Response.json({ success: false, error: `Invalid plan: ${newPlan}` }, { status: 400 });
  }

  const currentTier  = (authCtx.tier || 'FREE').toUpperCase();
  const currentOrder = PLAN_ORDER[currentTier] || 0;
  const targetOrder  = PLAN_ORDER[newPlan]     || 0;

  if (targetOrder <= currentOrder) {
    return Response.json({
      success: false,
      error: `Cannot downgrade via this endpoint. Current plan: ${currentTier}. Contact support for downgrades.`,
    }, { status: 400 });
  }

  // Priced from TIER_LIMITS — the same source of truth the billing portal
  // displays prices from, so the amount charged always matches what was shown.
  const amountPaise = Math.round((TIER_LIMITS[newPlan]?.price_inr ?? 0) * 100) || 14990;

  // Create a real Razorpay order so the client SDK can open a verified checkout session
  let razorpayOrderId = null;
  const rzKey    = env.RAZORPAY_KEY_ID;
  const rzSecret = env.RAZORPAY_KEY_SECRET;
  if (rzKey && rzSecret) {
    const receipt = `upg_${newPlan.toLowerCase()}_${userId.slice(0, 8)}_${Date.now()}`;
    const r = await fetch('https://api.razorpay.com/v1/orders', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${btoa(`${rzKey}:${rzSecret}`)}` },
      body: JSON.stringify({
        amount:   amountPaise,
        currency: 'INR',
        receipt,
        notes: { user_id: userId, from_plan: currentTier, to_plan: newPlan },
      }),
    });
    if (r.ok) razorpayOrderId = (await r.json()).id;
  }

  // Record upgrade intent (with real order ID when available)
  const orderId = razorpayOrderId || `upg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  await env.DB?.prepare(
    `INSERT INTO provisioning_log (user_id, event, metadata, created_at) VALUES (?, 'UPGRADE_INITIATED', ?, datetime('now'))`
  ).bind(userId, JSON.stringify({ from: currentTier, to: newPlan, order_id: orderId, amount_paise: amountPaise })).run().catch(() => {});

  return Response.json({
    success: true,
    upgrade: {
      from_plan:         currentTier,
      to_plan:           newPlan,
      amount_inr:        amountPaise / 100,
      razorpay_order_id: razorpayOrderId,
      razorpay_key:      rzKey || null,
      order_id:          orderId,
      checkout_url:      `https://cyberdudebivash.in/upgrade.html?plan=${newPlan.toLowerCase()}&order=${orderId}`,
    },
  });
}

export async function handleLiveUsage(request, env, authCtx) {
  const gate = authGuard(authCtx);
  if (gate) return gate;

  const userId = resolveUserId(authCtx);
  const email  = authCtx.email || null;
  const tier   = (authCtx.tier || 'FREE').toUpperCase();
  const dailyLimit   = TIER_LIMITS[tier]?.daily_limit   ?? TIER_LIMITS.FREE.daily_limit;
  const monthlyLimit = TIER_LIMITS[tier]?.monthly_limit ?? TIER_LIMITS.FREE.monthly_limit;

  const today = new Date().toISOString().slice(0, 10);

  const [dailyRow, monthlyRow, keyRows, overageRow] = await Promise.all([
    env.DB?.prepare(
      `SELECT SUM(request_count) as reqs FROM api_key_usage
       WHERE (user_id=? OR email=?) AND period_start=?`
    ).bind(userId, email, today).first().catch(() => null),
    env.DB?.prepare(
      `SELECT SUM(request_count) as reqs FROM api_key_usage
       WHERE (user_id=? OR email=?) AND period_start >= date('now','start of month')`
    ).bind(userId, email).first().catch(() => null),
    env.DB?.prepare(
      `SELECT label, tier, request_count, last_used_at FROM api_keys
       WHERE user_id=? OR email=? ORDER BY request_count DESC LIMIT 5`
    ).bind(userId, email).all().catch(() => ({ results: [] })),
    env.DB?.prepare(
      `SELECT SUM(amount_usd) as total FROM invoices
       WHERE (user_id=? OR email=?) AND description='API Overage Charge' AND status IN ('pending','paid')
       AND created_at >= date('now','start of month')`
    ).bind(userId, email).first().catch(() => null),
  ]);

  const dailyReqs   = parseInt(dailyRow?.reqs  || 0);
  const monthlyReqs = parseInt(monthlyRow?.reqs || 0);
  const overageUsd  = parseFloat(overageRow?.total || 0);

  return Response.json({
    success: true,
    usage: {
      tier,
      daily:   { used: dailyReqs,   limit: dailyLimit,   pct: dailyLimit   > 0 ? Math.round((dailyReqs   / dailyLimit)   * 100) : 0 },
      monthly: { used: monthlyReqs, limit: monthlyLimit, pct: monthlyLimit > 0 ? Math.round((monthlyReqs / monthlyLimit) * 100) : 0 },
      total_requests:  monthlyReqs,
      overage_charges_usd: Math.round(overageUsd * 100) / 100,
      top_keys: keyRows?.results || [],
      upgrade_nudge: dailyLimit > 0 && dailyReqs >= dailyLimit * 0.8
        ? { message: `You're at ${Math.round((dailyReqs / dailyLimit) * 100)}% of your daily limit. Upgrade for more.`, url: '/upgrade.html' }
        : null,
    },
  });
}

// ── P16.3 — API Overage Billing Engine ───────────────────────────────────────

const OVERAGE_RATE = { PRO: 0.001, STARTER: 0.002 }; // $/req above limit

export async function handleOverageReport(request, env, authCtx) {
  const gate = adminGuard(authCtx);
  if (gate) return gate;

  const url   = new URL(request.url);
  const month = url.searchParams.get('month') || new Date().toISOString().slice(0, 7);
  const monthStart = `${month}-01`;

  const rows = await env.DB?.prepare(
    `SELECT ak.user_id, ak.email, ak.tier, SUM(aku.request_count) as total_reqs
     FROM api_key_usage aku
     JOIN api_keys ak ON aku.api_key_id = ak.id
     WHERE aku.period_start >= ?
     GROUP BY ak.user_id, ak.email, ak.tier
     HAVING total_reqs > 0
     ORDER BY total_reqs DESC
     LIMIT 200`
  ).bind(monthStart).all().catch(() => ({ results: [] }));

  const MONTHLY_LIMITS = { FREE: 150, STARTER: 3000, PRO: 15000, ENTERPRISE: -1, MSSP: -1 };

  const overages = (rows?.results || []).map(r => {
    const limit = MONTHLY_LIMITS[(r.tier || 'FREE').toUpperCase()];
    const overage = limit > 0 ? Math.max(0, (parseInt(r.total_reqs) || 0) - limit) : 0;
    const rate  = OVERAGE_RATE[(r.tier || '').toUpperCase()] || 0;
    return {
      user_id:    r.user_id,
      email:      r.email,
      tier:       r.tier,
      total_reqs: parseInt(r.total_reqs) || 0,
      limit,
      overage_reqs: overage,
      overage_amount_usd: Math.round(overage * rate * 100) / 100,
    };
  }).filter(r => r.overage_reqs > 0);

  const total_overage_usd = overages.reduce((s, r) => s + r.overage_amount_usd, 0);

  return Response.json({
    success: true,
    month,
    overage_users: overages.length,
    total_overage_usd: Math.round(total_overage_usd * 100) / 100,
    overages,
  });
}

export async function handleOverageCharge(request, env, authCtx) {
  const gate = adminGuard(authCtx);
  if (gate) return gate;

  const body   = await request.json().catch(() => ({}));
  const userId = body.user_id;
  const amount = parseFloat(body.amount_usd || 0);

  if (!userId || amount <= 0) {
    return Response.json({ success: false, error: 'user_id and amount_usd required' }, { status: 400 });
  }

  const chargeId = `ovg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  // Record overage invoice
  await env.DB?.prepare(
    `INSERT INTO invoices (id, user_id, amount_usd, currency, status, description, created_at)
     VALUES (?, ?, ?, 'USD', 'pending', 'API Overage Charge', datetime('now'))`
  ).bind(chargeId, userId, amount.toFixed(2)).run().catch(() => {});

  await env.DB?.prepare(
    `INSERT INTO provisioning_log (user_id, event, metadata, created_at)
     VALUES (?, 'OVERAGE_CHARGED', ?, datetime('now'))`
  ).bind(userId, JSON.stringify({ charge_id: chargeId, amount_usd: amount, admin: authCtx.identity })).run().catch(() => {});

  return Response.json({
    success: true,
    charge_id: chargeId,
    user_id:   userId,
    amount_usd: amount,
    status: 'pending',
    message: 'Overage invoice created. Payment will be collected on next billing cycle.',
  });
}

// ── P16.4 — Executive KPI Summary ────────────────────────────────────────────

export async function handleExecutiveKPI(request, env, authCtx) {
  const gate = adminGuard(authCtx);
  if (gate) return gate;

  // Reuse the KPI cache from P16.1
  const kpiCache = await kvGet(env, 'platform:kpi:v1');

  // Pull 3-month trend data
  const now = new Date();
  const months = [0, 1, 2].map(i => {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
  });

  const [snapshots] = await Promise.all([
    env.DB?.prepare(
      `SELECT period, mrr, arr, active_subscribers FROM mrr_snapshots
       WHERE period IN (?,?,?) ORDER BY period DESC`
    ).bind(...months).all().catch(() => ({ results: [] })),
  ]);

  const trend = snapshots?.results || [];

  const kpi = kpiCache || {};

  // Compute mom growth
  const latestMRR = kpi.mrr || 0;
  const prevMRR   = trend[1]?.mrr || latestMRR;
  const momGrowth = prevMRR > 0 ? Math.round(((latestMRR - prevMRR) / prevMRR) * 1000) / 10 : 0;

  return Response.json({
    success: true,
    executive_summary: {
      generated_at: new Date().toISOString(),
      headline: {
        mrr:         kpi.mrr || 0,
        arr:         kpi.arr || 0,
        mom_growth:  momGrowth,
        paid_subs:   kpi.active_paid_subs || 0,
        arpu:        kpi.arpu || 0,
        ltv:         kpi.ltv_estimate || 0,
        nrr:         kpi.nrr_estimate || 1.0,
        api_reqs_mtd: kpi.api_requests_mtd || 0,
      },
      tier_distribution: kpi.tier_distribution || {},
      mrr_trend: trend,
      health_signals: {
        trial_conversion_pending: kpi.trial_count || 0,
        churn_rate_est: kpi.churn_rate_est || 0,
        revenue_ytd: kpi.revenue_ytd || 0,
      },
      board_narrative: `Platform operating at ₹${(kpi.arr || 0).toLocaleString('en-IN')} ARR with ${kpi.active_paid_subs || 0} paying customers. `
        + `MoM revenue growth: ${momGrowth > 0 ? '+' : ''}${momGrowth}%. `
        + `${kpi.trial_count || 0} trials in conversion pipeline. `
        + `LTV/CAC ratio: N/A (requires revenue history ≥3 months).`,
    },
  });
}

// ── P16.5 — Observability Gate ───────────────────────────────────────────────

export async function handleTransformObservability(request, env, authCtx) {
  const gate = adminGuard(authCtx);
  if (gate) return gate;

  return Response.json({
    success: true,
    service: 'CDB-P16-ENTERPRISE-TRANSFORM',
    version: '16.0.0',
    endpoints: [
      'GET  /api/platform/kpi',
      'GET  /api/customer/billing/portal',
      'GET  /api/customer/billing/invoices',
      'POST /api/customer/billing/cancel',
      'POST /api/customer/billing/upgrade',
      'GET  /api/customer/usage/live',
      'GET  /api/platform/overage/report',
      'POST /api/platform/overage/charge',
      'GET  /api/platform/kpi/executive',
      'GET  /api/platform/transform/observability',
    ],
    kpi_cache_active: !!(await env.SECURITY_HUB_KV?.get('platform:kpi:v1').catch(() => null)),
    status: 'OPERATIONAL',
  });
}
