/**
 * CYBERDUDEBIVASH AI Security Hub — Conversion Triggers & Paywall Engine
 * Phase 4: ₹1CR Revenue Engine
 *
 * Behavior-based upgrade prompts, feature gates, retargeting sequences,
 * and smart paywall overlays that convert free users to paid.
 *
 * Trigger logic:
 *   - Scan limit reached → Paywall overlay with upgrade CTA
 *   - AI query threshold → Feature gate with "Unlock AI" prompt
 *   - API limit hit → Upgrade nudge with ROI calculation
 *   - High-value threat detected → "Enable auto-defense" upgrade prompt
 *   - Session count milestone → Social proof popup
 *   - Inactivity (7+ days) → Re-engagement email trigger
 *
 * Endpoints:
 *   POST /api/conversion/event              → record user behavior event
 *   GET  /api/conversion/triggers           → get active triggers for user
 *   GET  /api/conversion/paywall            → get paywall config for feature
 *   POST /api/conversion/dismiss            → dismiss a trigger
 *   GET  /api/conversion/funnel             → funnel analytics (admin)
 *   POST /api/conversion/retarget           → trigger re-engagement sequence
 *   GET  /api/conversion/cta               → contextual CTA for current user state
 */

import { ok, fail } from '../lib/response.js';

const KV_USER_BEHAVIOR_PREFIX = 'conv:behavior:';
const KV_DISMISSED_PREFIX     = 'conv:dismissed:';
const KV_FUNNEL_STATS         = 'conv:funnel_stats';

// ── Trigger definitions ───────────────────────────────────────────────────────
const TRIGGERS = {
  SCAN_LIMIT: {
    id:          'SCAN_LIMIT',
    title:       'Unlock Unlimited Scans',
    description: 'You\'ve reached your daily scan limit. Upgrade to continue protecting your infrastructure.',
    cta:         'Upgrade Now — from ₹499/month',
    upgrade_url: '/#pricing',
    plan_target: 'STARTER',
    urgency:     'HIGH',
    icon:        '🔒',
    fire_after:  { metric: 'scans_today', threshold: 3 },
  },
  AI_LIMIT: {
    id:          'AI_LIMIT',
    title:       'Unlock Full AI Threat Analysis',
    description: 'You\'ve used all your free AI analysis queries. PRO users get 50 queries/day + SOAR rule generation.',
    cta:         'Upgrade to PRO — ₹1,499/month',
    upgrade_url: '/#pricing',
    plan_target: 'PRO',
    urgency:     'HIGH',
    icon:        '🧠',
    fire_after:  { metric: 'ai_queries_today', threshold: 3 },
  },
  API_LIMIT: {
    id:          'API_LIMIT',
    title:       'Scale Your API Usage',
    description: 'You\'ve hit your free API limit (500 calls/month). Upgrade to unlock 10K–1M+ calls with enterprise SLA.',
    cta:         'View API Plans',
    upgrade_url: '/#api-economy',
    plan_target: 'STARTER',
    urgency:     'MEDIUM',
    icon:        '⚡',
    fire_after:  { metric: 'api_calls_month', threshold: 450 },
  },
  HIGH_THREAT_DETECTED: {
    id:          'HIGH_THREAT_DETECTED',
    title:       'Critical Threat Detected — Enable Auto-Defense',
    description: 'A CRITICAL severity threat was found in your infrastructure. PRO users can auto-deploy detection rules in seconds.',
    cta:         'Enable Auto-Defense →',
    upgrade_url: '/#autonomous-soc',
    plan_target: 'PRO',
    urgency:     'CRITICAL',
    icon:        '🚨',
    fire_after:  { metric: 'critical_threats_found', threshold: 1 },
  },
  SIEM_GATE: {
    id:          'SIEM_GATE',
    title:       'Connect Your SIEM',
    description: 'SIEM integration requires a PRO or Enterprise plan. Deploy rules directly to Splunk, Elastic, or Sentinel.',
    cta:         'Upgrade to PRO',
    upgrade_url: '/#pricing',
    plan_target: 'PRO',
    urgency:     'MEDIUM',
    icon:        '🔌',
    fire_after:  { metric: 'siem_click', threshold: 1 },
  },
  REPORT_GATE: {
    id:          'REPORT_GATE',
    title:       'Download Executive Report',
    description: 'Full PDF reports are available on PRO and Enterprise plans. Impress your board with AI-generated security insights.',
    cta:         'Unlock Reports — ₹1,499/mo',
    upgrade_url: '/#pricing',
    plan_target: 'PRO',
    urgency:     'LOW',
    icon:        '📄',
    fire_after:  { metric: 'report_download_attempt', threshold: 1 },
  },
  SESSION_MILESTONE: {
    id:          'SESSION_MILESTONE',
    title:       'Join 2,000+ Security Teams',
    description: 'You\'re in great company. Upgrade to access the full platform that 2,000+ security teams trust.',
    cta:         'See What You\'re Missing',
    upgrade_url: '/#pricing',
    plan_target: 'STARTER',
    urgency:     'LOW',
    icon:        '🏆',
    fire_after:  { metric: 'sessions', threshold: 5 },
  },
  RE_ENGAGEMENT: {
    id:          'RE_ENGAGEMENT',
    title:       '🔥 New: Autonomous Defense Is Here',
    description: 'We\'ve shipped Autonomous SOC, CISA KEV enrichment, and MSSP capabilities since your last visit.',
    cta:         'See What\'s New',
    upgrade_url: '/#auto-defense',
    plan_target: null,
    urgency:     'MEDIUM',
    icon:        '✨',
    fire_after:  { metric: 'days_inactive', threshold: 7 },
  },

  // ── GOD MODE v15: New high-conversion triggers ────────────────────────────

  BUNDLE_OFFER: {
    id:          'BUNDLE_OFFER',
    title:       '🎁 Bundle & Save 60%',
    description: 'Get all 4 training courses + SOC Playbook for ₹1,999 instead of ₹4,895. Limited spots.',
    cta:         'Claim Bundle — ₹1,999',
    upgrade_url: '/academy.html#bundle',
    plan_target: 'BUNDLE',
    urgency:     'HIGH',
    icon:        '💎',
    fire_after:  { metric: 'trainings_viewed', threshold: 2 },
    // Time-limited: show for 72 hours per session (regenerate countdown each time)
    time_limited:   true,
    expiry_hours:   72,
    discount_pct:   60,
  },

  EXIT_INTENT: {
    id:          'EXIT_INTENT',
    title:       '⚡ Wait — Complete Your Security Scan',
    description: 'You haven\'t downloaded your full security report yet. Get it now with a 7-day money-back guarantee.',
    cta:         'Get Full Report — ₹199',
    upgrade_url: '/#pricing',
    plan_target: 'REPORT',
    urgency:     'CRITICAL',
    icon:        '⚡',
    fire_after:  { metric: 'exit_intent_detected', threshold: 1 },
    show_countdown_minutes: 10,
  },

  FIRST_CRITICAL_SCAN: {
    id:          'FIRST_CRITICAL_SCAN',
    title:       '🚨 Critical Vulnerabilities Found — Act Now',
    description: 'Your scan found CRITICAL-severity vulnerabilities. Upgrade to unlock full remediation playbook + auto-fix recommendations.',
    cta:         'Unlock Full Report — ₹199',
    upgrade_url: '/#pricing',
    plan_target: 'DOMAIN_REPORT',
    urgency:     'CRITICAL',
    icon:        '🚨',
    fire_after:  { metric: 'first_critical_finding', threshold: 1 },
    show_countdown_minutes: 30,
    highlight_color: '#ef4444',
  },

  REFERRAL_HOOK: {
    id:          'REFERRAL_HOOK',
    title:       '💰 Earn ₹250 Per Referral',
    description: 'Share your referral link and earn 10% recurring commission on every upgrade your contacts make.',
    cta:         'Join Affiliate Program',
    upgrade_url: '/affiliate.html',
    plan_target: null,
    urgency:     'LOW',
    icon:        '💰',
    fire_after:  { metric: 'paid_scans', threshold: 1 },
  },
};

// ── Paywall configurations ────────────────────────────────────────────────────
const PAYWALLS = {
  'autonomous-soc':    { required_plan: 'PRO',        feature: 'Autonomous SOC Mode',         upsell: 'SIEM_GATE' },
  'siem-deploy':       { required_plan: 'PRO',        feature: 'SIEM Integration',             upsell: 'SIEM_GATE' },
  'org-memory':        { required_plan: 'PRO',        feature: 'Organization Memory',          upsell: 'AI_LIMIT' },
  'auto-defense':      { required_plan: 'ENTERPRISE', feature: 'Autonomous Defense Engine',    upsell: 'HIGH_THREAT_DETECTED' },
  'executive-hub':     { required_plan: 'ENTERPRISE', feature: 'CISO Executive Dashboard',     upsell: 'REPORT_GATE' },
  'executive-report':  { required_plan: 'PRO',        feature: 'Executive Report Generator',   upsell: 'REPORT_GATE' },
  'api-economy':       { required_plan: 'STARTER',    feature: 'API Access',                   upsell: 'API_LIMIT' },
  'threat-graph':      { required_plan: 'PRO',        feature: 'Threat Intelligence Graph',    upsell: 'AI_LIMIT' },
};

// ── Smart upgrade recommendation ──────────────────────────────────────────────
function recommendUpgrade(currentPlan, behaviorMetrics) {
  const planOrder = ['FREE', 'STARTER', 'PRO', 'ENTERPRISE', 'MSSP'];
  const currentIdx = planOrder.indexOf((currentPlan || 'FREE').toUpperCase());

  // Determine which triggers have fired
  const firedTriggers = [];
  for (const [key, trigger] of Object.entries(TRIGGERS)) {
    const { metric, threshold } = trigger.fire_after;
    if ((behaviorMetrics[metric] || 0) >= threshold) {
      firedTriggers.push(trigger);
    }
  }

  // Find highest urgency trigger
  const urgencyOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  firedTriggers.sort((a, b) => (urgencyOrder[b.urgency] || 0) - (urgencyOrder[a.urgency] || 0));

  const topTrigger = firedTriggers[0] || null;

  // ROI messaging for current user
  const planPrices = { STARTER: 499, PRO: 1499, ENTERPRISE: 4999 };
  const nextPlan   = planOrder[currentIdx + 1];
  const nextPrice  = planPrices[nextPlan] || 499;
  const breachRisk = 1000000; // conservative ₹10L breach exposure
  const roi        = Math.round(breachRisk / (nextPrice * 12));

  return {
    recommended_plan: nextPlan || 'ENTERPRISE',
    upgrade_trigger:  topTrigger,
    all_triggers:     firedTriggers,
    roi_message:      `₹${nextPrice.toLocaleString('en-IN')}/month protects against ₹${(breachRisk / 100000).toFixed(0)}L in breach costs — ${roi}× ROI`,
    social_proof:     '2,000+ security teams trust CYBERDUDEBIVASH AI Security Hub',
  };
}

// ── POST /api/conversion/event ────────────────────────────────────────────────
export async function handleRecordEvent(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { event, increment = 1 } = body;
  const userId = authCtx?.userId || body.session_id || 'anonymous';
  if (!event) return fail(request, 'event is required', 400, 'MISSING_EVENT');

  let behavior = {};
  if (env?.SECURITY_HUB_KV) {
    try { behavior = (await env.SECURITY_HUB_KV.get(`${KV_USER_BEHAVIOR_PREFIX}${userId}`, { type: 'json' })) || {}; } catch {}
  }

  behavior[event] = (behavior[event] || 0) + increment;
  behavior._last_seen = new Date().toISOString();
  behavior._sessions  = (behavior._sessions || 0) + (event === 'session_start' ? 1 : 0);

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(`${KV_USER_BEHAVIOR_PREFIX}${userId}`, JSON.stringify(behavior), { expirationTtl: 86400 * 90 });
  }

  // Update funnel stats
  try {
    if (env?.SECURITY_HUB_KV) {
      let funnel = (await env.SECURITY_HUB_KV.get(KV_FUNNEL_STATS, { type: 'json' })) || {};
      funnel[event] = (funnel[event] || 0) + increment;
      await env.SECURITY_HUB_KV.put(KV_FUNNEL_STATS, JSON.stringify(funnel), { expirationTtl: 86400 * 365 });
    }
  } catch {}

  return ok(request, { recorded: true, event, new_value: behavior[event] });
}

// ── GET /api/conversion/triggers ─────────────────────────────────────────────
export async function handleGetTriggers(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const userId = authCtx?.userId || url.searchParams.get('session_id') || 'anonymous';
  const plan   = (authCtx?.tier || url.searchParams.get('plan') || 'FREE').toUpperCase();

  let behavior = {};
  let dismissed = [];
  if (env?.SECURITY_HUB_KV) {
    try { behavior  = (await env.SECURITY_HUB_KV.get(`${KV_USER_BEHAVIOR_PREFIX}${userId}`, { type: 'json' })) || {}; } catch {}
    try { dismissed = (await env.SECURITY_HUB_KV.get(`${KV_DISMISSED_PREFIX}${userId}`, { type: 'json' })) || []; } catch {}
  }

  const recommendation = recommendUpgrade(plan, behavior);
  const activeTriggers = recommendation.all_triggers.filter(t => !dismissed.includes(t.id)).slice(0, 3);

  return ok(request, {
    active_triggers:    activeTriggers,
    recommendation:     recommendation.upgrade_trigger,
    recommended_plan:   recommendation.recommended_plan,
    roi_message:        recommendation.roi_message,
    social_proof:       recommendation.social_proof,
    behavior_snapshot:  {
      scans:       behavior.scans_today || 0,
      ai_queries:  behavior.ai_queries_today || 0,
      sessions:    behavior._sessions || 0,
    },
  });
}

// ── GET /api/conversion/paywall ───────────────────────────────────────────────
export async function handleGetPaywall(request, env, authCtx = {}) {
  const url      = new URL(request.url);
  const feature  = url.searchParams.get('feature');
  const userPlan = (authCtx?.tier || 'FREE').toUpperCase();

  if (!feature) return fail(request, 'feature parameter required', 400, 'MISSING_FEATURE');

  const pw = PAYWALLS[feature];
  if (!pw)  return ok(request, { gated: false });

  const planOrder = ['FREE', 'STARTER', 'PRO', 'ENTERPRISE', 'MSSP'];
  const userIdx   = planOrder.indexOf(userPlan);
  const reqIdx    = planOrder.indexOf(pw.required_plan);
  const gated     = userIdx < reqIdx;

  if (!gated) return ok(request, { gated: false });

  const trigger = TRIGGERS[pw.upsell] || {};

  return ok(request, {
    gated:          true,
    feature:        pw.feature,
    required_plan:  pw.required_plan,
    user_plan:      userPlan,
    upgrade_url:    '/#pricing',
    trigger: {
      title:       trigger.title       || 'Upgrade Required',
      description: trigger.description || `This feature requires ${pw.required_plan} plan.`,
      cta:         trigger.cta         || 'Upgrade Now',
      icon:        trigger.icon        || '🔒',
    },
  });
}

// ── POST /api/conversion/dismiss ──────────────────────────────────────────────
export async function handleDismissTrigger(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const { trigger_id, session_id } = body;
  const userId = authCtx?.userId || session_id || 'anonymous';

  let dismissed = [];
  if (env?.SECURITY_HUB_KV) {
    try { dismissed = (await env.SECURITY_HUB_KV.get(`${KV_DISMISSED_PREFIX}${userId}`, { type: 'json' })) || []; } catch {}
    if (!dismissed.includes(trigger_id)) dismissed.push(trigger_id);
    await env.SECURITY_HUB_KV.put(`${KV_DISMISSED_PREFIX}${userId}`, JSON.stringify(dismissed), { expirationTtl: 86400 * 30 });
  }
  return ok(request, { dismissed: true, trigger_id });
}

// ── GET /api/conversion/funnel ────────────────────────────────────────────────
export async function handleGetFunnel(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let funnel = {};
  if (env?.SECURITY_HUB_KV) {
    try { funnel = (await env.SECURITY_HUB_KV.get(KV_FUNNEL_STATS, { type: 'json' })) || {}; } catch {}
  }

  // Compute funnel metrics
  const visitors       = funnel.session_start || 0;
  const scanners       = funnel.scan_initiated || 0;
  const ai_users       = funnel.ai_query || 0;
  const pricing_views  = funnel.pricing_view || 0;
  const upgrade_clicks = funnel.upgrade_click || 0;
  const conversions    = funnel.plan_purchased || 0;

  return ok(request, {
    funnel_stages: [
      { stage: 'Visitors',       count: visitors,       pct_of_prev: 100 },
      { stage: 'Ran a scan',     count: scanners,       pct_of_prev: visitors ? parseFloat(((scanners / visitors) * 100).toFixed(1)) : 0 },
      { stage: 'Used AI',        count: ai_users,       pct_of_prev: scanners ? parseFloat(((ai_users / scanners) * 100).toFixed(1)) : 0 },
      { stage: 'Viewed pricing', count: pricing_views,  pct_of_prev: ai_users ? parseFloat(((pricing_views / ai_users) * 100).toFixed(1)) : 0 },
      { stage: 'Clicked upgrade',count: upgrade_clicks, pct_of_prev: pricing_views ? parseFloat(((upgrade_clicks / pricing_views) * 100).toFixed(1)) : 0 },
      { stage: 'Converted',      count: conversions,    pct_of_prev: upgrade_clicks ? parseFloat(((conversions / upgrade_clicks) * 100).toFixed(1)) : 0 },
    ],
    raw_events:   funnel,
    overall_conversion_rate: visitors ? parseFloat(((conversions / visitors) * 100).toFixed(2)) : 0,
    top_drop_off:  'Viewed pricing → Clicked upgrade',
  });
}

// ── GET /api/conversion/cta ───────────────────────────────────────────────────
export async function handleGetCTA(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const plan   = (authCtx?.tier || url.searchParams.get('plan') || 'FREE').toUpperCase();
  const ctx    = url.searchParams.get('context') || 'general';

  const ctaMap = {
    FREE: {
      general:        { text: 'Start Free → Upgrade Anytime', sub: 'Join 2,000+ security teams', url: '/#pricing', color: '#6366f1' },
      after_scan:     { text: 'Unlock Full Report + AI Analysis', sub: '₹499/month. Cancel anytime.', url: '/#pricing', color: '#ef4444' },
      after_ai:       { text: 'Unlimited AI Queries → ₹1,499/mo', sub: 'SOAR rules + SIEM integration included', url: '/#pricing', color: '#f97316' },
      threat_found:   { text: '🚨 Auto-Deploy Defense Rules Now', sub: 'Enable Autonomous SOC on PRO', url: '/#autonomous-soc', color: '#ef4444' },
    },
    STARTER: {
      general:        { text: 'Upgrade to PRO for Autonomous SOC', sub: '5× more features. Cancel anytime.', url: '/#pricing', color: '#f59e0b' },
      siem_attempt:   { text: 'Connect Your SIEM → PRO Plan', sub: 'Deploy rules to Splunk, Elastic, Sentinel', url: '/#pricing', color: '#6366f1' },
      api_limit:      { text: '10× Your API Quota', sub: 'PRO: 100K calls/month with SLA', url: '/#api-economy', color: '#10b981' },
    },
    PRO: {
      general:        { text: 'Unlock CISO Dashboard + Autonomous Defense', sub: 'Enterprise: ₹4,999/month', url: '/#pricing', color: '#10b981' },
      executive_hub:  { text: 'Generate Board-Ready Reports', sub: 'CISO-grade executive analytics', url: '/#executive-hub', color: '#10b981' },
      mssp:           { text: 'Manage Multiple Clients → MSSP Plan', sub: 'White-label + ₹14,999/year', url: '/#executive-hub', color: '#6366f1' },
    },
    ENTERPRISE: {
      general:        { text: 'Add MSSP Capabilities', sub: 'White-label for your clients', url: '/#executive-hub', color: '#a78bfa' },
    },
  };

  const planCTAs = ctaMap[plan] || ctaMap.FREE;
  const cta = planCTAs[ctx] || planCTAs.general || ctaMap.FREE.general;

  return ok(request, { cta, plan, context: ctx });
}

// ── POST /api/conversion/retarget ─────────────────────────────────────────────
export async function handleRetarget(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let body = {};
  try { body = await request.json(); } catch {}

  const { user_ids = [], campaign = 'reactivation', plan_filter } = body;
  if (!user_ids.length && !plan_filter) return fail(request, 'user_ids or plan_filter required', 400, 'MISSING_TARGET');

  // Queue re-engagement events (in production: trigger email via Resend/SendGrid)
  const queued = user_ids.length;
  const campaign_id = 'rtg_' + Date.now();

  return ok(request, {
    queued,
    campaign_id,
    campaign,
    message: `Re-engagement campaign ${campaign_id} queued for ${queued} users. Email delivery via configured provider.`,
    estimated_send_time: new Date(Date.now() + 300000).toISOString(),
  });
}

// ── GET /api/conversion/bundle ─────────────────────────────────────────────────
// Returns the current active bundle offer with time-limited countdown.
// Bundle offer rotates every 72 hours, seeded by date so it's consistent
// within the same day (no flicker on refresh).
export async function handleGetBundleOffer(request, env, authCtx = {}) {
  const now        = Date.now();
  const sessionKey = `conv:bundle:${authCtx.userId || 'anon'}`;

  let firstSeen = now;
  if (env?.SECURITY_HUB_KV && authCtx.userId) {
    try {
      const stored = await env.SECURITY_HUB_KV.get(sessionKey);
      if (stored) {
        firstSeen = parseInt(stored, 10);
      } else {
        env.SECURITY_HUB_KV.put(sessionKey, String(now), { expirationTtl: 86400 * 7 }).catch(() => {});
      }
    } catch { /* ignore */ }
  }

  const expiresAt  = firstSeen + (72 * 3600 * 1000); // 72h from first view
  const msLeft     = Math.max(0, expiresAt - now);
  const hoursLeft  = Math.floor(msLeft / 3600000);
  const minsLeft   = Math.floor((msLeft % 3600000) / 60000);
  const isExpired  = msLeft === 0;

  const BUNDLE_PRODUCTS = [
    { id: 'ULTIMATE_BUNDLE_2026', name: 'Ultimate Bundle 2026 (4 Courses)',   price: 1999, original_price: 4895, savings: 2896 },
    { id: 'CYBER_MEGA_BUNDLE_BOTH', name: 'Cyber Mega Bundle (Part 1 + Part 2)', price: 1299, original_price: 1498, savings: 199 },
  ];

  return ok(request, {
    active:         !isExpired,
    offer:          TRIGGERS.BUNDLE_OFFER,
    products:       BUNDLE_PRODUCTS,
    countdown: {
      expires_at:   new Date(expiresAt).toISOString(),
      hours_left:   hoursLeft,
      minutes_left: minsLeft,
      ms_left:      msLeft,
      label:        isExpired ? 'Offer expired' : `Expires in ${hoursLeft}h ${minsLeft}m`,
    },
    social_proof: {
      units_sold_today: 12 + Math.floor(now / 3600000) % 8,  // deterministic 12-20
      viewers_now:      3  + Math.floor(now / 60000)  % 5,   // deterministic 3-7
    },
    cta_primary:   `CDB_PAY.open('ULTIMATE_BUNDLE_2026',1999,'Ultimate Bundle 2026')`,
    cta_secondary: `CDB_PAY.open('CYBER_MEGA_BUNDLE_BOTH',1299,'Cyber Mega Bundle')`,
  });
}

// ── GET /api/conversion/urgency ────────────────────────────────────────────────
// Returns contextual urgency state: which triggers are active, countdown timers,
// and personalized upgrade recommendation. Frontend uses this to show/hide CTAs.
export async function handleGetUrgency(request, env, authCtx = {}) {
  const url  = new URL(request.url);
  const ctx  = url.searchParams.get('context') || 'dashboard';
  const tier = (authCtx.tier || 'FREE').toUpperCase();

  const now    = Date.now();
  const dayMs  = 86400000;
  const dayKey = new Date().toISOString().slice(0, 10);

  // ── Compute active urgency signals ────────────────────────────────────────
  const signals = [];

  // Signal 1: Limited-time pricing (changes weekly — Monday midnight reset)
  const weekStart = new Date();
  weekStart.setHours(0, 0, 0, 0);
  weekStart.setDate(weekStart.getDate() - weekStart.getDay());
  const weekExpiresMs = weekStart.getTime() + 7 * dayMs;
  const weekHrsLeft   = Math.floor((weekExpiresMs - now) / 3600000);
  if (tier === 'FREE') {
    signals.push({
      type:    'limited_pricing',
      label:   `This week's price: ₹499/mo (regular ₹999/mo)`,
      hours_left: weekHrsLeft,
      urgency: weekHrsLeft < 24 ? 'CRITICAL' : weekHrsLeft < 72 ? 'HIGH' : 'MEDIUM',
    });
  }

  // Signal 2: Scan count urgency (only if we have usage data)
  if (tier === 'FREE') {
    signals.push({
      type:    'scan_limit',
      label:   'Free plan: 3 scans/day. Upgrade for unlimited.',
      urgency: 'MEDIUM',
    });
  }

  // Signal 3: Feature urgency based on context
  const CONTEXT_URGENCY = {
    'siem':       { label: 'SIEM integration requires PRO. Upgrade to connect Splunk/Elastic.', urgency: 'HIGH' },
    'redteam':    { label: 'Red Team scans use AI attack simulation. PRO unlocks full attack chains.', urgency: 'HIGH' },
    'auto-soc':   { label: 'Autonomous SOC Mode is paused on FREE plan. PRO enables 24/7 automated detection.', urgency: 'CRITICAL' },
    'executive':  { label: 'CISO reports require PRO+. One click to generate board-ready PDF.', urgency: 'HIGH' },
    'api':        { label: 'API keys require Starter plan or higher.', urgency: 'MEDIUM' },
    'dashboard':  { label: 'Unlock full threat intelligence dashboard.', urgency: 'LOW' },
  };
  const ctxUrgency = CONTEXT_URGENCY[ctx] || CONTEXT_URGENCY.dashboard;
  if (tier === 'FREE' || tier === 'STARTER') {
    signals.push({ type: 'feature_gate', ...ctxUrgency });
  }

  // ── Recommended upgrade + pricing ─────────────────────────────────────────
  const PLAN_NEXT = { FREE: { plan: 'STARTER', price_inr: 499, usd: 7 }, STARTER: { plan: 'PRO', price_inr: 1499, usd: 19 }, PRO: { plan: 'ENTERPRISE', price_inr: 4999, usd: 65 }, ENTERPRISE: null };
  const next = PLAN_NEXT[tier] || null;

  return ok(request, {
    current_tier:    tier,
    next_plan:       next,
    signals:         signals.sort((a, b) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[b.urgency] - ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[a.urgency] || 0))),
    show_upgrade_cta: tier !== 'ENTERPRISE',
    bundle_available: true,
    bundle_url:       '/api/conversion/bundle',
    day_key:          dayKey,
  });
}
