/**
 * CYBERDUDEBIVASH AI Security Hub — Monetization Engine v2.0
 *
 * Production-grade usage tracking, limit enforcement, and upgrade flow.
 *
 * Endpoints:
 *   GET  /api/billing/usage           → Detailed usage by module + quota status
 *   POST /api/billing/upgrade         → Initiate plan upgrade → Razorpay order
 *   GET  /api/billing/plans           → Enriched plan comparison with feature matrix
 *   POST /api/billing/downgrade       → Plan downgrade request
 *   GET  /api/billing/invoices        → Invoice history
 *   POST /api/billing/trial/start     → Start 14-day PRO trial
 *   GET  /api/billing/limits          → Real-time quota enforcement state
 */

import { ok, fail } from '../lib/response.js';

// ─── Plan definitions ─────────────────────────────────────────────────────────
export const PLANS = {
  FREE: {
    name:          'Free',
    display_name:  'Explorer',
    price_inr:     0,
    price_usd:     0,
    billing_cycle: 'forever',
    color:         '#64748b',
    quotas: {
      domain_scans_daily:    3,
      ai_scans_daily:        1,
      redteam_scans_daily:   0,
      identity_scans_daily:  1,
      compliance_reports:    1,
      api_calls_daily:       100,
      api_keys:              1,
      reports_monthly:       2,
      content_posts:         5,
      ai_analyze_calls:      5,   // /api/ai/analyze
      threat_confidence:     10,  // /api/threat-confidence/score
      monitors:              0,
      team_members:          1,
      orgs:                  1,
      siem_exports:          0,
      data_retention_days:   7,
    },
    features: {
      threat_graph:          false,
      ciso_dashboard:        false,
      executive_reports:     false,
      siem_export:           false,
      custom_rules:          false,
      api_access:            true,
      slack_alerts:          false,
      telegram_alerts:       true,
      sso:                   false,
      soc_mode:              false,
      red_team:              false,
      white_label:           false,
      dedicated_support:     false,
      custom_integrations:   false,
    }
  },
  PRO: {
    name:          'Pro',
    display_name:  'Pro Defender',
    price_inr:     2999,
    price_usd:     36,
    billing_cycle: 'monthly',
    color:         '#7c3aed',
    razorpay_plan_id: 'plan_pro_monthly',
    quotas: {
      domain_scans_daily:    50,
      ai_scans_daily:        20,
      redteam_scans_daily:   10,
      identity_scans_daily:  20,
      compliance_reports:    50,
      api_calls_daily:       5000,
      api_keys:              10,
      reports_monthly:       50,
      content_posts:         50,
      ai_analyze_calls:      200,
      threat_confidence:     500,
      monitors:              25,
      team_members:          10,
      orgs:                  3,
      siem_exports:          50,
      data_retention_days:   90,
    },
    features: {
      threat_graph:          true,
      ciso_dashboard:        true,
      executive_reports:     true,
      siem_export:           true,
      custom_rules:          true,
      api_access:            true,
      slack_alerts:          true,
      telegram_alerts:       true,
      sso:                   false,
      soc_mode:              true,
      red_team:              true,
      white_label:           false,
      dedicated_support:     false,
      custom_integrations:   false,
    }
  },
  ENTERPRISE: {
    name:          'Enterprise',
    display_name:  'Enterprise Fortress',
    price_inr:     24999,
    price_usd:     299,
    billing_cycle: 'monthly',
    color:         '#f59e0b',
    razorpay_plan_id: 'plan_enterprise_monthly',
    quotas: {
      domain_scans_daily:    -1,   // unlimited
      ai_scans_daily:        -1,
      redteam_scans_daily:   -1,
      identity_scans_daily:  -1,
      compliance_reports:    -1,
      api_calls_daily:       -1,
      api_keys:              -1,
      reports_monthly:       -1,
      content_posts:         -1,
      ai_analyze_calls:      -1,
      threat_confidence:     -1,
      monitors:              -1,
      team_members:          -1,
      orgs:                  -1,
      siem_exports:          -1,
      data_retention_days:   365,
    },
    features: {
      threat_graph:          true,
      ciso_dashboard:        true,
      executive_reports:     true,
      siem_export:           true,
      custom_rules:          true,
      api_access:            true,
      slack_alerts:          true,
      telegram_alerts:       true,
      sso:                   true,
      soc_mode:              true,
      red_team:              true,
      white_label:           true,
      dedicated_support:     true,
      custom_integrations:   true,
    }
  }
};

const KV_USAGE_PREFIX   = 'billing:usage:';
const KV_INVOICE_PREFIX = 'billing:invoice:';
const KV_TRIAL_PREFIX   = 'billing:trial:';
const TRIAL_DAYS        = 14;

// ─── Get today's date key ─────────────────────────────────────────────────────
function todayKey() {
  return new Date().toISOString().split('T')[0];
}

// ─── Load or init usage record ────────────────────────────────────────────────
async function loadUsage(env, userId) {
  if (!env?.SECURITY_HUB_KV) return initUsageRecord(userId);
  try {
    const key  = `${KV_USAGE_PREFIX}${userId}:${todayKey()}`;
    const data = await env.SECURITY_HUB_KV.get(key, { type: 'json' });
    return data || initUsageRecord(userId);
  } catch { return initUsageRecord(userId); }
}

function initUsageRecord(userId) {
  return {
    user_id:        userId,
    date:           todayKey(),
    counts: {
      domain_scans:       0,
      ai_scans:           0,
      redteam_scans:      0,
      identity_scans:     0,
      compliance_reports: 0,
      api_calls:          0,
      reports:            0,
      ai_analyze_calls:   0,
      threat_confidence:  0,
      siem_exports:       0,
    },
    last_updated: new Date().toISOString(),
  };
}

async function saveUsage(env, userId, record) {
  if (!env?.SECURITY_HUB_KV) return;
  const key = `${KV_USAGE_PREFIX}${userId}:${record.date}`;
  await env.SECURITY_HUB_KV.put(key, JSON.stringify(record), { expirationTtl: 86400 * 7 });
}

// ─── Get user tier ────────────────────────────────────────────────────────────
function getUserTier(authCtx) {
  return (authCtx?.tier || authCtx?.plan || 'FREE').toUpperCase();
}

// ─── Compute usage + quota status ────────────────────────────────────────────
function buildUsageStatus(usage, tier) {
  const plan   = PLANS[tier] || PLANS.FREE;
  const quotas = plan.quotas;
  const counts = usage.counts;

  const modules = Object.entries(counts).map(([module, used]) => {
    const quota   = quotas[`${module}_daily`] ?? quotas[module] ?? -1;
    const pct     = quota === -1 ? 0 : Math.min(100, Math.round((used / quota) * 100));
    const status  = quota === -1 ? 'UNLIMITED'
                  : pct >= 100   ? 'EXHAUSTED'
                  : pct >= 80    ? 'NEAR_LIMIT'
                  : 'OK';
    return { module, used, quota, usage_pct: pct, status };
  });

  const exhaustedModules  = modules.filter(m => m.status === 'EXHAUSTED').map(m => m.module);
  const nearLimitModules  = modules.filter(m => m.status === 'NEAR_LIMIT').map(m => m.module);

  return {
    plan:                plan.name,
    tier,
    date:                usage.date,
    modules,
    exhausted_modules:   exhaustedModules,
    near_limit_modules:  nearLimitModules,
    upgrade_recommended: exhaustedModules.length > 0 || nearLimitModules.length >= 2,
    upgrade_url:         '/pricing',
  };
}

// ─── GET /api/billing/usage ───────────────────────────────────────────────────
export async function handleGetUsage(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const tier   = getUserTier(authCtx);
  const usage  = await loadUsage(env, authCtx.userId);
  const status = buildUsageStatus(usage, tier);

  // Monthly usage rollup (last 30 days)
  let monthlyScans = 0;
  if (env?.SECURITY_HUB_KV) {
    try {
      const listResult = await env.SECURITY_HUB_KV.list({ prefix: `${KV_USAGE_PREFIX}${authCtx.userId}:` });
      const keys = listResult.keys || [];
      for (const k of keys.slice(0, 30)) {
        const rec = await env.SECURITY_HUB_KV.get(k.name, { type: 'json' });
        if (rec?.counts) {
          monthlyScans += Object.values(rec.counts).reduce((a,b) => a+b, 0);
        }
      }
    } catch {}
  }

  const plan = PLANS[tier] || PLANS.FREE;

  return ok(request, {
    ...status,
    current_plan: {
      name:           plan.display_name,
      tier,
      price_inr:      plan.price_inr,
      price_usd:      plan.price_usd,
      billing_cycle:  plan.billing_cycle,
      features:       plan.features,
    },
    monthly_total_scans: monthlyScans,
    next_upgrade: tier === 'FREE' ? {
      plan:          'PRO',
      price_inr:     PLANS.PRO.price_inr,
      price_usd:     PLANS.PRO.price_usd,
      key_benefits:  ['50x more scans', 'CISO Dashboard', 'Red Team access', 'SIEM export', 'Threat Graph'],
      cta_url:       '/pricing',
    } : tier === 'PRO' ? {
      plan:          'ENTERPRISE',
      price_inr:     PLANS.ENTERPRISE.price_inr,
      price_usd:     PLANS.ENTERPRISE.price_usd,
      key_benefits:  ['Unlimited scans', 'White label', 'SSO', 'Dedicated support', 'Custom integrations'],
      cta_url:       '/pricing',
    } : null,
    last_updated: usage.last_updated,
  });
}

// ─── POST /api/billing/upgrade ────────────────────────────────────────────────
export async function handleUpgrade(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let body = {};
  try { body = await request.json(); } catch {}

  const { plan, billing_cycle = 'monthly' } = body;
  const targetPlan = (plan || '').toUpperCase();

  if (!['PRO', 'ENTERPRISE'].includes(targetPlan)) {
    return fail(request, `plan must be PRO or ENTERPRISE`, 400, 'INVALID_PLAN');
  }

  const currentTier = getUserTier(authCtx);
  if (currentTier === targetPlan) {
    return fail(request, `You are already on the ${targetPlan} plan`, 400, 'ALREADY_ON_PLAN');
  }

  const planConfig = PLANS[targetPlan];
  const amount_inr = billing_cycle === 'annual'
    ? planConfig.price_inr * 10  // 2 months free on annual
    : planConfig.price_inr;

  // Generate Razorpay order (or fallback for test mode)
  const orderId = 'order_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  let razorpayOrder = null;

  if (env?.RAZORPAY_KEY_ID && env?.RAZORPAY_KEY_SECRET) {
    try {
      const credentials = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
      const rzRes = await fetch('https://api.razorpay.com/v1/orders', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${credentials}` },
        body:    JSON.stringify({
          amount:   amount_inr * 100,  // paise
          currency: 'INR',
          receipt:  orderId,
          notes:    { user_id: authCtx.userId, plan: targetPlan, billing_cycle },
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (rzRes.ok) razorpayOrder = await rzRes.json();
    } catch (e) {
      console.error('Razorpay order creation failed:', e.message);
    }
  }

  // Store pending upgrade intent
  if (env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put(
        `billing:upgrade_intent:${authCtx.userId}`,
        JSON.stringify({ orderId, targetPlan, billing_cycle, amount_inr, created_at: new Date().toISOString(), status: 'PENDING' }),
        { expirationTtl: 3600 }  // 1-hour window
      );
    } catch {}
  }

  return ok(request, {
    upgrade_initiated:   true,
    order_id:            razorpayOrder?.id || orderId,
    razorpay_order:      razorpayOrder,
    plan:                targetPlan,
    billing_cycle,
    amount_inr,
    amount_paise:        amount_inr * 100,
    currency:            'INR',
    razorpay_key:        env?.RAZORPAY_KEY_ID || null,
    payment_note:        billing_cycle === 'annual'
      ? `Annual plan — save ₹${planConfig.price_inr * 2} vs monthly`
      : `Monthly plan — cancel anytime`,
    activation_endpoint: '/api/subscription/activate',
    test_mode:           !razorpayOrder,
  });
}

// ─── GET /api/billing/plans ───────────────────────────────────────────────────
export async function handleGetBillingPlans(request, env, authCtx = {}) {
  const plans = Object.entries(PLANS).map(([key, p]) => ({
    tier:          key,
    name:          p.display_name,
    price_inr:     p.price_inr,
    price_usd:     p.price_usd,
    price_annual_inr: p.price_inr * 10,
    billing_cycle: p.billing_cycle,
    color:         p.color,
    quotas:        p.quotas,
    features:      p.features,
    popular:       key === 'PRO',
    cta_label:     key === 'FREE' ? 'Start Free' : key === 'PRO' ? 'Upgrade to Pro' : 'Contact Sales',
  }));

  const currentTier = authCtx?.authenticated ? getUserTier(authCtx) : null;

  return ok(request, { plans, current_tier: currentTier });
}

// ─── POST /api/billing/trial/start ───────────────────────────────────────────
export async function handleStartTrial(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const tier = getUserTier(authCtx);
  if (tier !== 'FREE') return fail(request, 'Trial only available for Free tier users', 400, 'INELIGIBLE');

  const trialKey = `${KV_TRIAL_PREFIX}${authCtx.userId}`;
  if (env?.SECURITY_HUB_KV) {
    try {
      const existing = await env.SECURITY_HUB_KV.get(trialKey, { type: 'json' });
      if (existing) return fail(request, 'PRO trial already used. Upgrade to continue.', 400, 'TRIAL_USED');
    } catch {}
  }

  const trialEnd = new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString();

  if (env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put(trialKey, JSON.stringify({
        user_id:    authCtx.userId,
        started_at: new Date().toISOString(),
        ends_at:    trialEnd,
        plan:       'PRO_TRIAL',
      }), { expirationTtl: TRIAL_DAYS * 86400 });
    } catch {}
  }

  return ok(request, {
    trial_activated: true,
    plan:            'PRO_TRIAL',
    ends_at:         trialEnd,
    days_remaining:  TRIAL_DAYS,
    message:         `Your 14-day PRO trial is now active. Upgrade before ${trialEnd.split('T')[0]} to keep access.`,
    upgrade_url:     '/pricing',
  });
}

// ─── GET /api/billing/limits ──────────────────────────────────────────────────
export async function handleGetLimits(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const tier  = getUserTier(authCtx);
  const plan  = PLANS[tier] || PLANS.FREE;

  return ok(request, {
    tier,
    quotas:      plan.quotas,
    features:    plan.features,
    is_unlimited: tier === 'ENTERPRISE',
  });
}

// ─── GET /api/billing/invoices ────────────────────────────────────────────────
export async function handleGetInvoices(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let invoices = [];
  if (env?.SECURITY_HUB_KV) {
    try {
      const result = await env.SECURITY_HUB_KV.list({ prefix: `${KV_INVOICE_PREFIX}${authCtx.userId}:` });
      for (const k of (result.keys || []).slice(0, 24)) {
        const inv = await env.SECURITY_HUB_KV.get(k.name, { type: 'json' });
        if (inv) invoices.push(inv);
      }
    } catch {}
  }

  return ok(request, { total: invoices.length, invoices });
}

// ─── POST /api/billing/downgrade ─────────────────────────────────────────────
export async function handleDowngrade(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const tier = getUserTier(authCtx);
  if (tier === 'FREE') return fail(request, 'You are already on the Free plan', 400, 'ALREADY_FREE');

  // Store downgrade request (processed at billing cycle end)
  if (env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put(
        `billing:downgrade_request:${authCtx.userId}`,
        JSON.stringify({ user_id: authCtx.userId, current_tier: tier, target_tier: 'FREE', requested_at: new Date().toISOString() }),
        { expirationTtl: 86400 * 35 }
      );
    } catch {}
  }

  return ok(request, {
    downgrade_scheduled: true,
    current_plan:        tier,
    downgrade_to:        'FREE',
    effective_date:      new Date(Date.now() + 30 * 86400000).toISOString().split('T')[0],
    message:             `Downgrade to Free scheduled. Your PRO features remain active until your next billing cycle ends.`,
    cancel_url:          '/api/billing/downgrade/cancel',
  });
}

// ─── Track usage (internal utility, called from scan handlers) ────────────────
export async function trackUsage(env, userId, module, count = 1) {
  if (!env?.SECURITY_HUB_KV || !userId) return;
  try {
    const usage = await loadUsage(env, userId);
    usage.counts[module] = (usage.counts[module] || 0) + count;
    usage.last_updated   = new Date().toISOString();
    await saveUsage(env, userId, usage);
  } catch {}
}

// ─── Enforce quota (returns { allowed, reason, usage }) ──────────────────────
export async function enforceUsageQuota(env, authCtx, module) {
  if (!authCtx?.userId) return { allowed: true };
  const tier   = getUserTier(authCtx);
  const plan   = PLANS[tier] || PLANS.FREE;
  const quota  = plan.quotas[`${module}_daily`] ?? plan.quotas[module] ?? -1;

  if (quota === -1) return { allowed: true, unlimited: true };

  const usage  = await loadUsage(env, authCtx.userId);
  const used   = usage.counts[module] || 0;

  if (used >= quota) {
    return {
      allowed:     false,
      reason:      `Daily ${module} limit reached (${used}/${quota})`,
      used,
      quota,
      tier,
      upgrade_url: '/pricing',
      upgrade_plan: tier === 'FREE' ? 'PRO' : 'ENTERPRISE',
    };
  }

  return { allowed: true, used, quota, remaining: quota - used };
}
