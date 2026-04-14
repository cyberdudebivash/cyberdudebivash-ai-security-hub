/**
 * CYBERDUDEBIVASH AI Security Hub — Revenue Engine 2.0 (v20.0)
 * ──────────────────────────────────────────────────────────────
 * Subscription Plans, Feature Gating, Usage-Based Billing, Upsell Engine.
 *
 * Plans:
 *   STARTER    ₹199/month  — basic scans, 50 API calls/day, community support
 *   PRO        ₹999/month  — AI brain, dark web, MITRE heatmap, 500 API calls/day
 *   ENTERPRISE ₹9999/month — unlimited, custom SLA, white-label, dedicated support
 *
 * Feature Gate Enforcement:
 *   Middleware checks user's plan before granting access to gated features.
 *   Returns 402 with upsell payload if feature is not included in current plan.
 *
 * Usage-Based Billing:
 *   Per-scan and per-API-call counters stored in KV.
 *   Overage charges computed at billing period end.
 */

// ─── Plan Definitions ─────────────────────────────────────────────────────────
export const SUBSCRIPTION_PLANS = {
  FREE: {
    id:          'FREE',
    name:        'Free',
    price_inr:   0,
    price_usd:   0,
    billing:     'forever',
    description: 'Get started — no credit card required',
    limits: {
      scans_per_day:    3,
      api_calls_per_day: 20,
      scan_modules:     ['domain'],
      report_export:    false,
      ai_brain:         false,
      dark_web:         false,
      threat_hunting:   false,
      executive_report: false,
      siem_export:      false,
      vuln_management:  false,
      zero_trust:       false,
      global_feed:      false,
      api_key:          false,
      support:          'community',
    },
    cta:      'Get Started Free',
    route:    '/signup',
    popular:  false,
    badge:    null,
  },

  STARTER: {
    id:          'STARTER',
    name:        'Starter',
    price_inr:   199,
    price_usd:   2.40,
    billing:     'monthly',
    description: 'For individuals and small teams',
    limits: {
      scans_per_day:    20,
      api_calls_per_day: 100,
      scan_modules:     ['domain', 'ai', 'identity'],
      report_export:    true,
      ai_brain:         true,
      dark_web:         false,
      threat_hunting:   false,
      executive_report: false,
      siem_export:      false,
      vuln_management:  true,
      zero_trust:       false,
      global_feed:      true,
      api_key:          true,
      support:          'email',
    },
    overage: {
      per_scan:     2,     // ₹2 per scan over limit
      per_api_call: 0.10,  // ₹0.10 per API call over limit
    },
    cta:      'Start for ₹199/mo',
    route:    '/checkout?plan=starter',
    popular:  false,
    badge:    null,
  },

  PRO: {
    id:          'PRO',
    name:        'Pro',
    price_inr:   999,
    price_usd:   11.99,
    billing:     'monthly',
    description: 'Full AI power for security professionals',
    limits: {
      scans_per_day:    100,
      api_calls_per_day: 500,
      scan_modules:     ['domain', 'ai', 'redteam', 'identity', 'compliance'],
      report_export:    true,
      ai_brain:         true,
      dark_web:         true,
      threat_hunting:   true,
      executive_report: true,
      siem_export:      true,
      vuln_management:  true,
      zero_trust:       true,
      global_feed:      true,
      api_key:          true,
      support:          'priority_email',
    },
    overage: {
      per_scan:     1,     // ₹1 per scan over limit
      per_api_call: 0.05,  // ₹0.05 per API call over limit
    },
    cta:      'Go Pro — ₹999/mo',
    route:    '/checkout?plan=pro',
    popular:  true,
    badge:    '🔥 Most Popular',
  },

  ENTERPRISE: {
    id:          'ENTERPRISE',
    name:        'Enterprise',
    price_inr:   9999,
    price_usd:   119.99,
    billing:     'monthly',
    description: 'Unlimited power for teams and enterprises',
    limits: {
      scans_per_day:    -1,   // unlimited
      api_calls_per_day: -1,  // unlimited
      scan_modules:     ['domain', 'ai', 'redteam', 'identity', 'compliance', 'custom'],
      report_export:    true,
      ai_brain:         true,
      dark_web:         true,
      threat_hunting:   true,
      executive_report: true,
      siem_export:      true,
      vuln_management:  true,
      zero_trust:       true,
      global_feed:      true,
      api_key:          true,
      white_label:      true,
      sso:              true,
      custom_sla:       true,
      dedicated_ciso:   true,
      multi_org:        true,
      support:          'dedicated_24x7',
    },
    cta:      'Contact Sales',
    route:    '/contact?plan=enterprise',
    popular:  false,
    badge:    '🏢 Enterprise',
  },
};

// ─── Feature → Minimum Plan Map ───────────────────────────────────────────────
const FEATURE_PLAN_MAP = {
  ai_brain:         'STARTER',
  global_feed:      'STARTER',
  api_key:          'STARTER',
  vuln_management:  'STARTER',
  report_export:    'STARTER',
  dark_web:         'PRO',
  threat_hunting:   'PRO',
  executive_report: 'PRO',
  siem_export:      'PRO',
  zero_trust:       'PRO',
  white_label:      'ENTERPRISE',
  sso:              'ENTERPRISE',
  dedicated_ciso:   'ENTERPRISE',
  multi_org:        'ENTERPRISE',
};

const PLAN_RANK = { FREE: 0, STARTER: 1, PRO: 2, ENTERPRISE: 3 };

function hasAccess(userTier, requiredPlan) {
  return (PLAN_RANK[userTier] || 0) >= (PLAN_RANK[requiredPlan] || 0);
}

// ─── KV Usage Tracking ────────────────────────────────────────────────────────
async function getUsage(env, userId, type) {
  if (!env?.SECURITY_HUB_KV || !userId) return 0;
  const day = new Date().toISOString().slice(0, 10);
  const raw = await env.SECURITY_HUB_KV.get(`usage:${type}:${userId}:${day}`).catch(() => null);
  return parseInt(raw || '0', 10);
}

async function incrementUsage(env, userId, type) {
  if (!env?.SECURITY_HUB_KV || !userId) return;
  const day = new Date().toISOString().slice(0, 10);
  const key = `usage:${type}:${userId}:${day}`;
  const cur = parseInt(await env.SECURITY_HUB_KV.get(key).catch(() => '0') || '0', 10);
  await env.SECURITY_HUB_KV.put(key, String(cur + 1), { expirationTtl: 86400 * 2 }).catch(() => {});
}

// ─── Handler: GET /api/revenue/plans ─────────────────────────────────────────
export async function handleGetPlansV20(request, env, authCtx) {
  const url       = new URL(request.url);
  const currency  = url.searchParams.get('currency') || 'INR';
  const userTier  = authCtx?.tier || 'FREE';

  const plans = Object.values(SUBSCRIPTION_PLANS).map(p => ({
    ...p,
    display_price: currency === 'USD'
      ? `$${p.price_usd}/mo`
      : (p.price_inr === 0 ? 'Free' : `₹${p.price_inr}/mo`),
    is_current: p.id === userTier,
    can_upgrade: PLAN_RANK[p.id] > PLAN_RANK[userTier],
  }));

  return Response.json({
    plans,
    current_plan:  userTier,
    currency,
    billing_info:  'All plans billed monthly. Cancel anytime.',
    payment_methods: ['UPI', 'Card', 'Net Banking', 'PayPal', 'Crypto'],
    platform:      'CYBERDUDEBIVASH AI Security Hub v20.0',
    generated_at:  new Date().toISOString(),
  });
}

// ─── Handler: POST /api/revenue/subscribe ────────────────────────────────────
export async function handleSubscribeV20(request, env, authCtx) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { plan, payment_method = 'razorpay', coupon = null } = body;

  if (!SUBSCRIPTION_PLANS[plan]) {
    return Response.json({
      error: 'Invalid plan',
      valid_plans: Object.keys(SUBSCRIPTION_PLANS).filter(p => p !== 'FREE'),
    }, { status: 400 });
  }

  const selectedPlan = SUBSCRIPTION_PLANS[plan];
  const userId       = authCtx.userId;
  const currentTier  = authCtx.tier || 'FREE';

  if (PLAN_RANK[plan] <= PLAN_RANK[currentTier]) {
    return Response.json({
      error: `You are already on ${currentTier}. Choose a higher tier.`,
      current_plan: currentTier,
    }, { status: 400 });
  }

  let finalPrice = selectedPlan.price_inr;

  // Coupon handling
  const VALID_COUPONS = {
    'CYBER10':  { discount_pct: 10, label: '10% off' },
    'LAUNCH50': { discount_pct: 50, label: '50% launch offer' },
    'CYBER20':  { discount_pct: 20, label: '20% off for newsletter subscribers' },
  };

  let couponApplied = null;
  if (coupon && VALID_COUPONS[coupon.toUpperCase()]) {
    const c      = VALID_COUPONS[coupon.toUpperCase()];
    finalPrice   = Math.round(finalPrice * (1 - c.discount_pct / 100));
    couponApplied = { code: coupon.toUpperCase(), ...c, final_price: finalPrice };
  }

  // Record subscription intent in KV (Razorpay order created separately via /api/payments)
  const subscriptionId = `sub_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const subscriptionRecord = {
    subscription_id: subscriptionId,
    user_id:         userId,
    plan,
    from_plan:       currentTier,
    price_inr:       finalPrice,
    payment_method,
    coupon:          couponApplied,
    status:          'pending_payment',
    created_at:      new Date().toISOString(),
    expires_at:      new Date(Date.now() + 30 * 86400000).toISOString(),
  };

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `subscription:pending:${userId}`,
      JSON.stringify(subscriptionRecord),
      { expirationTtl: 3600 }
    ).catch(() => {});
  }

  return Response.json({
    ok: true,
    subscription_id: subscriptionId,
    plan,
    price_inr:       finalPrice,
    original_price:  selectedPlan.price_inr,
    coupon:          couponApplied,
    payment_method,
    next_step:       payment_method === 'razorpay'
      ? 'POST /api/payments/order with subscription_id to get Razorpay order_id'
      : 'Contact billing@cyberdudebivash.com for manual payment',
    features_unlocked: Object.entries(selectedPlan.limits)
      .filter(([, v]) => v === true)
      .map(([k]) => k),
    platform: 'CYBERDUDEBIVASH AI Security Hub v20.0',
  });
}

// ─── Handler: GET /api/revenue/gate/:feature ─────────────────────────────────
export async function handleFeatureGate(request, env, authCtx) {
  const url     = new URL(request.url);
  const feature = url.pathname.split('/').pop();
  const tier    = authCtx?.tier || 'FREE';

  const required = FEATURE_PLAN_MAP[feature];
  if (!required) {
    return Response.json({
      feature,
      access:  true,
      reason:  'Feature available on all plans',
      tier,
    });
  }

  const allowed = hasAccess(tier, required);

  if (!allowed) {
    const upgrade = SUBSCRIPTION_PLANS[required];
    return Response.json({
      feature,
      access:       false,
      reason:       `Requires ${required} plan or higher`,
      current_plan: tier,
      required_plan: required,
      upgrade_cta:  {
        message:    `Unlock ${feature.replace(/_/g, ' ')} with ${upgrade.name} for just ${upgrade.price_inr === 0 ? 'Free' : '₹' + upgrade.price_inr + '/mo'}`,
        route:      upgrade.route,
        price_inr:  upgrade.price_inr,
      },
    }, { status: 402 });
  }

  // Check daily usage limits
  const userId  = authCtx?.userId;
  const plan    = SUBSCRIPTION_PLANS[tier];
  const scanUse = await getUsage(env, userId, 'scan');
  const apiUse  = await getUsage(env, userId, 'api');

  return Response.json({
    feature,
    access:       true,
    current_plan: tier,
    usage: {
      scans_today:     scanUse,
      api_calls_today: apiUse,
      scan_limit:      plan?.limits?.scans_per_day || 3,
      api_limit:       plan?.limits?.api_calls_per_day || 20,
    },
    platform: 'CYBERDUDEBIVASH AI Security Hub v20.0',
  });
}

// ─── Handler: GET /api/revenue/billing ───────────────────────────────────────
export async function handleBillingStatus(request, env, authCtx) {
  const userId = authCtx?.userId;
  const tier   = authCtx?.tier || 'FREE';
  const plan   = SUBSCRIPTION_PLANS[tier];

  // Fetch usage from KV
  const [scanUse, apiUse] = await Promise.all([
    getUsage(env, userId, 'scan'),
    getUsage(env, userId, 'api'),
  ]);

  // Fetch any pending subscription
  let pending = null;
  if (env?.SECURITY_HUB_KV && userId) {
    const raw = await env.SECURITY_HUB_KV.get(`subscription:pending:${userId}`).catch(() => null);
    if (raw) { try { pending = JSON.parse(raw); } catch {} }
  }

  const scanLimit = plan?.limits?.scans_per_day || 3;
  const apiLimit  = plan?.limits?.api_calls_per_day || 20;

  // Overage calculation
  const scanOverage = scanUse > scanLimit && scanLimit !== -1 ? scanUse - scanLimit : 0;
  const apiOverage  = apiUse > apiLimit && apiLimit !== -1   ? apiUse  - apiLimit  : 0;
  const overageCost = (scanOverage * (plan?.overage?.per_scan || 0))
                    + (apiOverage  * (plan?.overage?.per_api_call || 0));

  return Response.json({
    user_id:      userId,
    current_plan: tier,
    plan_details: {
      name:       plan?.name,
      price_inr:  plan?.price_inr,
      billing:    plan?.billing,
    },
    usage: {
      scans_today:     scanUse,
      scan_limit:      scanLimit === -1 ? 'unlimited' : scanLimit,
      scan_pct:        scanLimit === -1 ? 0 : Math.round((scanUse / scanLimit) * 100),
      api_calls_today: apiUse,
      api_limit:       apiLimit === -1 ? 'unlimited' : apiLimit,
      api_pct:         apiLimit === -1 ? 0 : Math.round((apiUse / apiLimit) * 100),
    },
    overage: {
      scan_overage:  scanOverage,
      api_overage:   apiOverage,
      estimated_cost_inr: overageCost,
    },
    pending_subscription: pending,
    upgrade_options: Object.values(SUBSCRIPTION_PLANS)
      .filter(p => PLAN_RANK[p.id] > PLAN_RANK[tier])
      .map(p => ({ plan: p.id, name: p.name, price_inr: p.price_inr, cta: p.cta, route: p.route })),
    platform:     'CYBERDUDEBIVASH AI Security Hub v20.0',
    generated_at: new Date().toISOString(),
  });
}

// ─── Middleware: enforce feature gate in route handlers ───────────────────────
/**
 * enforceFeatureGate(feature, tier)
 * Returns null if access granted, or a 402 Response if not.
 * Use inside any handler:
 *   const gate = enforceFeatureGate('dark_web', authCtx.tier);
 *   if (gate) return gate;
 */
export function enforceFeatureGate(feature, tier = 'FREE') {
  const required = FEATURE_PLAN_MAP[feature];
  if (!required) return null;
  if (hasAccess(tier, required)) return null;

  const upgrade = SUBSCRIPTION_PLANS[required];
  return Response.json({
    error:        'Feature not available on your current plan',
    feature,
    current_plan: tier,
    required_plan: required,
    upgrade_cta:  {
      message:   `Upgrade to ${upgrade.name} for ₹${upgrade.price_inr}/mo to unlock this feature`,
      route:     upgrade.route,
      price_inr: upgrade.price_inr,
    },
    platform: 'CYBERDUDEBIVASH AI Security Hub v20.0',
  }, { status: 402 });
}

// ─── Export usage incrementer for use in scan/API handlers ────────────────────
export { incrementUsage, getUsage };
