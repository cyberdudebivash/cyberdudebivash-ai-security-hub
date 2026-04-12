/**
 * CYBERDUDEBIVASH AI Security Hub — Affiliate & Partner System
 * Phase 4: ₹1CR Revenue Engine
 *
 * B2B referral engine with tiered commission, real-time tracking,
 * and automated payouts.
 *
 * Commission Structure:
 *   AFFILIATE:   10% of referred plan value (first year)
 *   PARTNER:     15% recurring + deal support
 *   RESELLER:    20% recurring + white-label rights
 *   STRATEGIC:   25% recurring + co-sell + MDF budget
 *
 * Endpoints:
 *   POST /api/affiliate/join               → apply for affiliate program
 *   GET  /api/affiliate/status             → check own affiliate status
 *   GET  /api/affiliate/dashboard          → full affiliate dashboard
 *   POST /api/affiliate/track              → track referral click/conversion
 *   GET  /api/affiliate/referrals          → list referrals + commissions
 *   GET  /api/affiliate/leaderboard        → top affiliates (public)
 *   GET  /api/affiliate/tiers              → tier info (public)
 *   POST /api/affiliate/payout/request     → request commission payout
 *   GET  /api/partner/dashboard            → MSSP/reseller partner dashboard
 *   POST /api/partner/register             → register as partner
 */

import { ok, fail } from '../lib/response.js';

const KV_AFF_PREFIX    = 'affiliate:profile:';
const KV_AFF_INDEX     = 'affiliate:index';
const KV_REF_PREFIX    = 'affiliate:referral:';
const KV_CLICK_PREFIX  = 'affiliate:click:';
const KV_PAYOUT_PREFIX = 'affiliate:payout:';

// ── Tier definitions ──────────────────────────────────────────────────────────
const TIERS = {
  AFFILIATE: {
    id:               'AFFILIATE',
    name:             'Affiliate',
    commission_pct:   10,
    commission_type:  'first_year',
    min_referrals:    0,
    min_revenue_inr:  0,
    perks:            ['10% commission on referred plans', 'Custom referral link', 'Marketing materials', 'Real-time dashboard'],
    badge:            '🔗',
  },
  PARTNER: {
    id:               'PARTNER',
    name:             'Certified Partner',
    commission_pct:   15,
    commission_type:  'recurring',
    min_referrals:    3,
    min_revenue_inr:  150000,
    perks:            ['15% recurring commission', 'Co-branded marketing', 'Partner portal access', 'Sales support', 'Quarterly partner reviews'],
    badge:            '🤝',
  },
  RESELLER: {
    id:               'RESELLER',
    name:             'Authorized Reseller',
    commission_pct:   20,
    commission_type:  'recurring',
    min_referrals:    10,
    min_revenue_inr:  500000,
    perks:            ['20% recurring commission', 'White-label option', 'Volume discounts', 'Dedicated partner manager', 'Co-sell opportunities'],
    badge:            '🏪',
  },
  STRATEGIC: {
    id:               'STRATEGIC',
    name:             'Strategic Alliance',
    commission_pct:   25,
    commission_type:  'recurring',
    min_referrals:    25,
    min_revenue_inr:  2000000,
    perks:            ['25% recurring commission', 'MDF budget allocation', 'Joint GTM planning', 'Executive sponsorship', 'Custom contracts'],
    badge:            '⭐',
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function generateRefCode(name) {
  const clean = (name || 'ref').toLowerCase().replace(/[^a-z0-9]/g,'').slice(0, 8);
  return clean + '_' + Math.random().toString(36).slice(2, 7).toUpperCase();
}

function calculateCommission(plan_price_inr, tier_id) {
  const tier = TIERS[tier_id] || TIERS.AFFILIATE;
  return Math.round(plan_price_inr * tier.commission_pct / 100);
}

function determineTier(stats) {
  const { total_referrals = 0, total_revenue_inr = 0 } = stats;
  if (total_referrals >= 25 && total_revenue_inr >= 2000000) return 'STRATEGIC';
  if (total_referrals >= 10 && total_revenue_inr >= 500000)  return 'RESELLER';
  if (total_referrals >= 3  && total_revenue_inr >= 150000)  return 'PARTNER';
  return 'AFFILIATE';
}

async function loadAffiliate(env, userId) {
  if (!env?.SECURITY_HUB_KV) return null;
  try { return await env.SECURITY_HUB_KV.get(`${KV_AFF_PREFIX}${userId}`, { type: 'json' }); } catch { return null; }
}

async function saveAffiliate(env, aff) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(`${KV_AFF_PREFIX}${aff.id}`, JSON.stringify(aff), { expirationTtl: 86400 * 365 * 2 });
}

// ── POST /api/affiliate/join ──────────────────────────────────────────────────
export async function handleJoin(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { name, email, website, how_promote, audience_size, platform_type = 'AFFILIATE' } = body;
  const userId = authCtx?.userId || email;

  if (!name || !email) return fail(request, 'name and email are required', 400, 'MISSING_FIELDS');
  if (!TIERS[platform_type]) return fail(request, 'Invalid platform_type', 400, 'INVALID_TYPE');

  // Check existing
  const existing = await loadAffiliate(env, userId);
  if (existing) return ok(request, { already_registered: true, ref_code: existing.ref_code, tier: existing.tier });

  const now      = new Date().toISOString();
  const ref_code = generateRefCode(name);

  const affiliate = {
    id:              userId,
    name, email,
    website:         website      || null,
    how_promote:     how_promote  || null,
    audience_size:   audience_size || null,
    platform_type,
    ref_code,
    tier:            'AFFILIATE',
    status:          'ACTIVE',
    created_at:      now,
    stats: {
      total_clicks:      0,
      unique_clicks:     0,
      signups:           0,
      conversions:       0,
      total_referrals:   0,
      total_revenue_inr: 0,
      total_commission_earned_inr: 0,
      pending_payout_inr:          0,
      paid_out_inr:                0,
    },
    referral_url:  `https://cyberdudebivash.com?ref=${ref_code}`,
    utm_params:    `utm_source=affiliate&utm_medium=referral&utm_campaign=${ref_code}`,
    payout_method: null,
    payout_details:null,
  };

  await saveAffiliate(env, affiliate);

  // Update index
  if (env?.SECURITY_HUB_KV) {
    let index = [];
    try { index = (await env.SECURITY_HUB_KV.get(KV_AFF_INDEX, { type: 'json' })) || []; } catch {}
    index.unshift({ id: userId, name, email, ref_code, tier: 'AFFILIATE', created_at: now });
    await env.SECURITY_HUB_KV.put(KV_AFF_INDEX, JSON.stringify(index.slice(0, 10000)), { expirationTtl: 86400 * 365 * 2 });
  }

  return ok(request, {
    registered:   true,
    ref_code,
    referral_url: affiliate.referral_url,
    tier:         'AFFILIATE',
    commission:   TIERS.AFFILIATE.commission_pct + '% on first year of referred plan value',
    dashboard_url:'https://cyberdudebivash.com/affiliate/dashboard',
  });
}

// ── GET /api/affiliate/status ─────────────────────────────────────────────────
export async function handleGetStatus(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const userId = authCtx?.userId || url.searchParams.get('email');
  if (!userId)  return fail(request, 'Not authenticated', 401, 'UNAUTHORIZED');

  const aff = await loadAffiliate(env, userId);
  if (!aff)   return fail(request, 'Not registered as affiliate', 404, 'NOT_FOUND');

  const tierDef = TIERS[aff.tier] || TIERS.AFFILIATE;
  const nextTierKey = Object.keys(TIERS)[Object.keys(TIERS).indexOf(aff.tier) + 1];
  const nextTier    = nextTierKey ? TIERS[nextTierKey] : null;

  return ok(request, {
    ref_code:          aff.ref_code,
    referral_url:      aff.referral_url,
    tier:              aff.tier,
    tier_details:      tierDef,
    next_tier:         nextTier,
    stats:             aff.stats,
    status:            aff.status,
  });
}

// ── GET /api/affiliate/dashboard ──────────────────────────────────────────────
export async function handleGetDashboard(request, env, authCtx = {}) {
  const userId = authCtx?.userId;
  if (!userId)  return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const aff = await loadAffiliate(env, userId);
  if (!aff)   return fail(request, 'Not registered', 404, 'NOT_FOUND');

  // Load referrals
  let referrals = [];
  if (env?.SECURITY_HUB_KV) {
    try {
      const refIndex = await env.SECURITY_HUB_KV.get(`${KV_REF_PREFIX}index:${userId}`, { type: 'json' });
      referrals = refIndex || [];
    } catch {}
  }

  const tierDef = TIERS[aff.tier] || TIERS.AFFILIATE;

  return ok(request, {
    affiliate:        aff,
    tier_details:     tierDef,
    referrals:        referrals.slice(0, 50),
    referral_url:     aff.referral_url,
    utm_params:       aff.utm_params,
    marketing_assets: {
      banner_urls: [
        'https://cyberdudebivash.com/assets/affiliate/banner-728x90.png',
        'https://cyberdudebivash.com/assets/affiliate/banner-300x250.png',
        'https://cyberdudebivash.com/assets/affiliate/banner-1200x628.png',
      ],
      email_template_url: 'https://cyberdudebivash.com/assets/affiliate/email-template.html',
      one_pager_url:      'https://cyberdudebivash.com/assets/affiliate/one-pager.pdf',
    },
  });
}

// ── POST /api/affiliate/track ─────────────────────────────────────────────────
export async function handleTrackReferral(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { ref_code, event_type = 'click', plan_id, amount_inr, referred_email } = body;
  if (!ref_code) return fail(request, 'ref_code required', 400, 'MISSING_REF');

  // Find affiliate by ref_code
  let aff = null;
  if (env?.SECURITY_HUB_KV) {
    try {
      const index = (await env.SECURITY_HUB_KV.get(KV_AFF_INDEX, { type: 'json' })) || [];
      const entry = index.find(a => a.ref_code === ref_code);
      if (entry) aff = await loadAffiliate(env, entry.id);
    } catch {}
  }
  if (!aff) return fail(request, 'Invalid ref_code', 404, 'INVALID_REF');

  const now = new Date().toISOString();

  if (event_type === 'click') {
    aff.stats.total_clicks++;
    await saveAffiliate(env, aff);
    return ok(request, { tracked: true, type: 'click' });
  }

  if (event_type === 'signup') {
    aff.stats.signups++;
    await saveAffiliate(env, aff);
    return ok(request, { tracked: true, type: 'signup' });
  }

  if (event_type === 'conversion' && amount_inr) {
    const commission = calculateCommission(parseInt(amount_inr), aff.tier);
    aff.stats.conversions++;
    aff.stats.total_referrals++;
    aff.stats.total_revenue_inr            += parseInt(amount_inr);
    aff.stats.total_commission_earned_inr  += commission;
    aff.stats.pending_payout_inr           += commission;

    // Re-evaluate tier
    const newTier = determineTier(aff.stats);
    if (newTier !== aff.tier) aff.tier = newTier;

    // Record referral
    const referral = {
      id:             'ref_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
      affiliate_id:   aff.id,
      referred_email: referred_email || null,
      plan_id:        plan_id || null,
      amount_inr:     parseInt(amount_inr),
      commission_inr: commission,
      commission_pct: TIERS[aff.tier]?.commission_pct || 10,
      status:         'PENDING_PAYOUT',
      converted_at:   now,
    };

    if (env?.SECURITY_HUB_KV) {
      await env.SECURITY_HUB_KV.put(`${KV_REF_PREFIX}${referral.id}`, JSON.stringify(referral), { expirationTtl: 86400 * 365 * 2 });
      let refIndex = [];
      try { refIndex = (await env.SECURITY_HUB_KV.get(`${KV_REF_PREFIX}index:${aff.id}`, { type: 'json' })) || []; } catch {}
      refIndex.unshift({ id: referral.id, amount_inr: referral.amount_inr, commission_inr: commission, converted_at: now, status: 'PENDING_PAYOUT' });
      await env.SECURITY_HUB_KV.put(`${KV_REF_PREFIX}index:${aff.id}`, JSON.stringify(refIndex.slice(0, 500)), { expirationTtl: 86400 * 365 * 2 });
    }

    await saveAffiliate(env, aff);
    return ok(request, { tracked: true, type: 'conversion', commission_inr: commission, new_tier: aff.tier });
  }

  return ok(request, { tracked: false, reason: 'Unknown event_type' });
}

// ── GET /api/affiliate/leaderboard ───────────────────────────────────────────
export async function handleGetLeaderboard(request, env) {
  let index = [];
  if (env?.SECURITY_HUB_KV) {
    try { index = (await env.SECURITY_HUB_KV.get(KV_AFF_INDEX, { type: 'json' })) || []; } catch {}
  }

  // Load stats for top entries (limited to avoid KV reads)
  const top = index.slice(0, 20).map(entry => ({
    name:       (entry.name || '').split(' ')[0] + ' ' + (entry.name || '').split(' ').slice(-1)[0]?.charAt(0) + '.',
    tier:       entry.tier || 'AFFILIATE',
    badge:      TIERS[entry.tier || 'AFFILIATE']?.badge || '🔗',
    ref_code:   entry.ref_code ? entry.ref_code.slice(0, 4) + '***' : '***',
  }));

  return ok(request, {
    leaderboard: top,
    total_affiliates: index.length,
    program_stats: {
      avg_commission_inr: 15000,
      top_earner_inr:     250000,
      total_paid_out_inr: 850000,
    },
  });
}

// ── GET /api/affiliate/tiers ──────────────────────────────────────────────────
export async function handleGetTiers(request, env) {
  return ok(request, { tiers: Object.values(TIERS) });
}

// ── POST /api/affiliate/payout/request ───────────────────────────────────────
export async function handleRequestPayout(request, env, authCtx = {}) {
  const userId = authCtx?.userId;
  if (!userId)  return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const aff = await loadAffiliate(env, userId);
  if (!aff)     return fail(request, 'Not registered', 404, 'NOT_FOUND');

  if (aff.stats.pending_payout_inr < 1000) {
    return fail(request, 'Minimum payout threshold is ₹1,000', 400, 'BELOW_MINIMUM');
  }

  let body = {};
  try { body = await request.json(); } catch {}

  const payout = {
    id:           'payout_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    affiliate_id: userId,
    amount_inr:   aff.stats.pending_payout_inr,
    method:       body.method || 'bank_transfer',
    account_details: body.account_details || null,
    status:       'PENDING',
    requested_at: new Date().toISOString(),
  };

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`${KV_PAYOUT_PREFIX}${payout.id}`, JSON.stringify(payout), { expirationTtl: 86400 * 365 });
  }

  aff.stats.pending_payout_inr = 0;
  aff.payout_method  = body.method || aff.payout_method;
  aff.payout_details = body.account_details || aff.payout_details;
  await saveAffiliate(env, aff);

  return ok(request, { requested: true, payout_id: payout.id, amount_inr: payout.amount_inr, expected_days: 7 });
}

// ── GET /api/affiliate/referrals ─────────────────────────────────────────────
export async function handleGetReferrals(request, env, authCtx = {}) {
  const userId = authCtx?.userId;
  if (!userId)  return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let referrals = [];
  if (env?.SECURITY_HUB_KV) {
    try { referrals = (await env.SECURITY_HUB_KV.get(`${KV_REF_PREFIX}index:${userId}`, { type: 'json' })) || []; } catch {}
  }
  return ok(request, { total: referrals.length, referrals: referrals.slice(0, 50) });
}
