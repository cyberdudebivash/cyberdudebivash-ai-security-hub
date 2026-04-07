// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — AI Revenue Optimizer v8.1
// Phase 3: Behavioral analysis → auto-triggered upsells, upgrade paths,
//          product recommendations, churn prevention, and revenue maximization
//
// Pure business logic — no I/O. Pass env for DB/KV access.
// ═══════════════════════════════════════════════════════════════════════════

// ── Upgrade paths by current plan ────────────────────────────────────────────
const UPGRADE_PATHS = {
  free: {
    next:       'starter',
    price:      499,
    discount_offer: 299,   // ₹299 for first month
    headline:   'Unlock Full Threat Intelligence',
    cta:        'Upgrade to STARTER — ₹499/mo',
    triggers:   ['scan_limit_hit', 'feature_blocked', 'third_visit'],
  },
  starter: {
    next:       'pro',
    price:      1499,
    discount_offer: 1199,
    headline:   'Automate Your Entire Security Workflow',
    cta:        'Upgrade to PRO — ₹1,499/mo',
    triggers:   ['api_quota_hit', 'export_blocked', 'siem_blocked'],
  },
  pro: {
    next:       'enterprise',
    price:      4999,
    discount_offer: 3999,
    headline:   'Enterprise-Grade Threat Intelligence for Your Team',
    cta:        'Contact for ENTERPRISE — from ₹4,999/mo',
    triggers:   ['team_seats_needed', 'custom_api_needed', 'sla_required'],
  },
  enterprise: {
    next:       null,
    price:      null,
    headline:   'You are at the highest tier.',
    cta:        null,
    triggers:   [],
  },
};

// ── Product recommendations by user behavior ─────────────────────────────────
const PRODUCT_RULES = [
  {
    id:          'firewall_after_scan',
    condition:   (s) => s.scans >= 1 && s.plan === 'free',
    product:     'firewall_rules',
    price:       199,
    headline:    'Block This Threat Right Now',
    description: 'Deploy firewall rules generated from your scan in < 5 minutes.',
    urgency:     'LIMITED_TIME',
  },
  {
    id:          'ids_for_critical',
    condition:   (s) => (s.critical_cves || 0) >= 2,
    product:     'ids_signatures',
    price:       399,
    headline:    'Detect Active Exploits in Your Network',
    description: 'IDS/IPS signatures for all critical CVEs in your scan.',
    urgency:     'HIGH_RISK',
  },
  {
    id:          'playbook_for_pro',
    condition:   (s) => s.plan === 'pro' && (s.scans || 0) >= 3,
    product:     'ir_playbook',
    price:       999,
    headline:    'Incident Response Playbook — Ready in Minutes',
    description: '6-phase IR playbook auto-generated from your threat profile.',
    urgency:     'PROFESSIONAL',
  },
  {
    id:          'full_pack_value',
    condition:   (s) => (s.scans || 0) >= 2 && (s.critical_cves || 0) >= 1,
    product:     'full_defense_pack',
    price:       2499,
    headline:    'Get Everything You Need — Save 60%',
    description: 'All 7 defense tools bundled: Firewall + IDS + Playbook + Scripts + Hunts + Sigma + Briefing.',
    urgency:     'BUNDLE_DEAL',
  },
  {
    id:          'sigma_for_soc',
    condition:   (s) => s.plan === 'enterprise' || (s.has_siem === true),
    product:     'sigma_rules',
    price:       399,
    headline:    'Sigma Rules for Your SIEM',
    description: 'Push-ready Sigma detection rules for Splunk, Elastic, Chronicle.',
    urgency:     'SOC_TEAM',
  },
  {
    id:          'exec_briefing_enterprise',
    condition:   (s) => s.is_enterprise || s.plan === 'enterprise',
    product:     'exec_briefing',
    price:       299,
    headline:    'Boardroom-Ready Threat Briefing',
    description: 'Executive summary for non-technical stakeholders.',
    urgency:     'LEADERSHIP',
  },
  {
    id:          'api_credits_power_user',
    condition:   (s) => (s.api_calls_today || 0) >= 50 && s.plan === 'starter',
    product:     'api_credits',
    price:       499,
    headline:    'You\'re Hitting API Limits',
    description: 'Buy 1,000 API credit pack — no restrictions, no throttling.',
    urgency:     'LIMIT_HIT',
  },
  {
    id:          'enterprise_bundle_heavy',
    condition:   (s) => (s.scans || 0) >= 10 && (s.cves_tracked || 0) >= 20,
    product:     'enterprise_bundle',
    price:       9999,
    headline:    'You Need Enterprise Intelligence',
    description: 'Full enterprise bundle covering 20+ CVEs with all defense products.',
    urgency:     'POWER_USER',
  },
];

// ── Churn risk signals ────────────────────────────────────────────────────────
const CHURN_THRESHOLDS = {
  days_since_last_scan:  7,   // inactive ≥7 days
  session_drop_pct:     40,   // session count dropped ≥40%
  scan_drop_pct:        50,   // scan volume dropped ≥50%
  support_tickets:       2,   // ≥2 open tickets → friction
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. USER BEHAVIOR PROFILER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a behavioral profile for a user to drive personalized upsells.
 *
 * @param {object} env
 * @param {string} userId
 * @returns {object} user behavior snapshot
 */
export async function getUserBehaviorProfile(env, userId) {
  try {
    const [user, scanStats, apiStats, purchaseStats, funnelStats] = await Promise.all([
      // User record
      env.DB.prepare(`
        SELECT email, plan, created_at, updated_at, is_enterprise,
               lead_score, company
        FROM leads
        WHERE id = ? OR email = ?
        LIMIT 1
      `).bind(userId, userId).first(),

      // Scan behavior
      env.DB.prepare(`
        SELECT COUNT(*) as total_scans,
               MAX(created_at) as last_scan_at,
               SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
               SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count
        FROM scan_history
        WHERE user_id = ?
      `).bind(userId).first(),

      // API usage
      env.DB.prepare(`
        SELECT COUNT(*) as calls_today,
               SUM(weight) as total_weight
        FROM api_usage_log
        WHERE (api_key IN (SELECT key FROM api_keys WHERE user_id = ?))
          AND logged_at >= date('now')
      `).bind(userId).first(),

      // Purchase history
      env.DB.prepare(`
        SELECT COUNT(*) as total_purchases,
               COALESCE(SUM(amount), 0) as total_spent,
               MAX(created_at) as last_purchase_at
        FROM revenue_events
        WHERE user_id = ? OR email = (SELECT email FROM leads WHERE id = ? LIMIT 1)
      `).bind(userId, userId).first(),

      // Funnel events (last 30 days)
      env.DB.prepare(`
        SELECT stage, COUNT(*) as count
        FROM funnel_events
        WHERE user_id = ?
          AND created_at >= datetime('now', '-30 days')
        GROUP BY stage
      `).bind(userId).all(),
    ]);

    if (!user) {
      return { error: 'User not found', user_id: userId };
    }

    const funnelMap = {};
    for (const row of (funnelStats.results || [])) {
      funnelMap[row.stage] = row.count;
    }

    const daysSinceLastScan = scanStats?.last_scan_at
      ? Math.floor((Date.now() - new Date(scanStats.last_scan_at).getTime()) / 86400000)
      : 999;

    const daysSinceLastPurchase = purchaseStats?.last_purchase_at
      ? Math.floor((Date.now() - new Date(purchaseStats.last_purchase_at).getTime()) / 86400000)
      : 999;

    const accountAgeDays = user.created_at
      ? Math.floor((Date.now() - new Date(user.created_at).getTime()) / 86400000)
      : 0;

    return {
      user_id:                userId,
      email:                  user.email,
      plan:                   user.plan || 'free',
      is_enterprise:          !!user.is_enterprise,
      lead_score:             user.lead_score || 0,
      company:                user.company,
      account_age_days:       accountAgeDays,
      // Scan behavior
      scans:                  scanStats?.total_scans || 0,
      critical_cves:          scanStats?.critical_count || 0,
      high_cves:              scanStats?.high_count || 0,
      days_since_last_scan:   daysSinceLastScan,
      // API
      api_calls_today:        apiStats?.calls_today || 0,
      api_weight_today:       apiStats?.total_weight || 0,
      // Purchases
      total_purchases:        purchaseStats?.total_purchases || 0,
      total_spent:            purchaseStats?.total_spent || 0,
      days_since_last_purchase: daysSinceLastPurchase,
      // Funnel
      funnel_events:          funnelMap,
      has_siem:               !!(funnelMap['siem_export'] || funnelMap['siem_view']),
      // Engagement score (0–100)
      engagement_score:       computeEngagementScore({
        scans:                scanStats?.total_scans || 0,
        daysSinceLastScan,
        totalSpent:           purchaseStats?.total_spent || 0,
        funnelEvents:         funnelMap,
        plan:                 user.plan || 'free',
        apiCalls:             apiStats?.calls_today || 0,
      }),
    };
  } catch (err) {
    return { error: err.message, user_id: userId };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ENGAGEMENT SCORE CALCULATOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute a 0–100 engagement score from user behavior signals
 */
function computeEngagementScore({ scans, daysSinceLastScan, totalSpent, funnelEvents, plan, apiCalls }) {
  let score = 0;

  // Scan activity (max 30 pts)
  score += Math.min(scans * 3, 30);

  // Recency (max 20 pts)
  if (daysSinceLastScan <= 1)       score += 20;
  else if (daysSinceLastScan <= 3)  score += 15;
  else if (daysSinceLastScan <= 7)  score += 10;
  else if (daysSinceLastScan <= 14) score += 5;

  // Paid customer (max 20 pts)
  if      (plan === 'enterprise') score += 20;
  else if (plan === 'pro')        score += 15;
  else if (plan === 'starter')    score += 10;
  else if (totalSpent > 0)        score += 5;

  // API usage (max 15 pts)
  score += Math.min(Math.floor(apiCalls / 10) * 3, 15);

  // Funnel depth (max 15 pts)
  const funnelDepth = Object.keys(funnelEvents || {}).length;
  score += Math.min(funnelDepth * 3, 15);

  return Math.min(score, 100);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. UPSELL TRIGGER ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Determine which upsell to show based on user behavior.
 *
 * @param {object} profile — from getUserBehaviorProfile()
 * @param {string} context — 'scan_result' | 'dashboard' | 'api_response' | 'email'
 * @returns {object} upsell recommendation
 */
export function getUpsellTrigger(profile, context = 'dashboard') {
  const plan = profile.plan || 'free';
  const upgradePath = UPGRADE_PATHS[plan];

  if (!upgradePath || !upgradePath.next) {
    return { type: 'none', reason: 'Already on highest plan' };
  }

  // ── Determine urgency level ────────────────────────────────────────────────
  let urgencyLevel = 'SOFT'; // SOFT | MEDIUM | HARD
  let trigger      = null;

  if (context === 'scan_result') {
    if (plan === 'free') {
      urgencyLevel = 'HARD';
      trigger = 'scan_done_free_user';
    } else if (plan === 'starter' && (profile.critical_cves || 0) >= 2) {
      urgencyLevel = 'HARD';
      trigger = 'critical_cves_found';
    }
  }

  if (context === 'api_response') {
    if ((profile.api_calls_today || 0) >= 80) {
      urgencyLevel = 'HARD';
      trigger = 'api_limit_approaching';
    }
  }

  if (context === 'dashboard') {
    if (profile.days_since_last_scan >= 7 && plan !== 'free') {
      urgencyLevel = 'MEDIUM';
      trigger = 're_engagement';
    } else if (plan === 'free' && profile.scans >= 1) {
      urgencyLevel = 'MEDIUM';
      trigger = 'returning_free_user';
    }
  }

  // ── Build the upsell payload ───────────────────────────────────────────────
  const isUrgent    = urgencyLevel === 'HARD';
  const offerPrice  = isUrgent ? upgradePath.discount_offer : upgradePath.price;
  const discount    = isUrgent
    ? Math.round(((upgradePath.price - offerPrice) / upgradePath.price) * 100)
    : 0;

  // Time-limited offer (24h for hard upsells)
  const expiresAt = isUrgent
    ? new Date(Date.now() + 86400000).toISOString()
    : null;

  return {
    type:             'upgrade',
    urgency:          urgencyLevel,
    trigger,
    context,
    from_plan:        plan,
    to_plan:          upgradePath.next,
    headline:         isUrgent
      ? `⚠️ ${upgradePath.headline}`
      : upgradePath.headline,
    cta:              `${upgradePath.cta} (${offerPrice < upgradePath.price ? `₹${offerPrice} today` : `₹${upgradePath.price}/mo`})`,
    price_regular:    upgradePath.price,
    price_offer:      offerPrice,
    discount_pct:     discount,
    expires_at:       expiresAt,
    features_unlocked: getUpgradeFeatures(plan, upgradePath.next),
    social_proof:     getSocialProof(upgradePath.next),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PRODUCT RECOMMENDATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Recommend defense products / reports based on user behavior profile.
 *
 * @param {object} profile — from getUserBehaviorProfile()
 * @param {number} maxResults — max recommendations to return
 * @returns {Array} sorted recommendations
 */
export function getProductRecommendations(profile, maxResults = 3) {
  const matched = [];

  for (const rule of PRODUCT_RULES) {
    try {
      if (rule.condition(profile)) {
        matched.push({
          rule_id:      rule.id,
          product:      rule.product,
          price:        rule.price,
          headline:     rule.headline,
          description:  rule.description,
          urgency_type: rule.urgency,
          buy_url:      buildBuyUrl(rule.product, rule.price),
          preview_url:  `/api/defense/preview?product=${rule.product}`,
        });
      }
    } catch {
      // rule condition error — skip
    }
  }

  // Deduplicate by product
  const seen = new Set();
  const unique = matched.filter(r => {
    if (seen.has(r.product)) return false;
    seen.add(r.product);
    return true;
  });

  // Prioritize by urgency: HIGH_RISK > LIMIT_HIT > BUNDLE_DEAL > others
  const urgencyOrder = {
    HIGH_RISK: 0, LIMIT_HIT: 1, BUNDLE_DEAL: 2,
    PROFESSIONAL: 3, SOC_TEAM: 4, LEADERSHIP: 5,
    POWER_USER: 6, LIMITED_TIME: 7,
  };
  unique.sort((a, b) =>
    (urgencyOrder[a.urgency_type] ?? 99) - (urgencyOrder[b.urgency_type] ?? 99)
  );

  return unique.slice(0, maxResults);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CHURN RISK ANALYZER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Assess churn risk for a user and generate retention actions.
 *
 * @param {object} profile — from getUserBehaviorProfile()
 * @returns {object} churn risk assessment
 */
export function analyzeChurnRisk(profile) {
  const signals = [];
  let riskScore = 0;

  // Inactivity signal
  if (profile.days_since_last_scan >= CHURN_THRESHOLDS.days_since_last_scan) {
    const days = profile.days_since_last_scan;
    riskScore += days >= 30 ? 40 : days >= 14 ? 25 : 15;
    signals.push({
      signal:  'scan_inactivity',
      detail:  `No scans in ${days} days`,
      weight:  days >= 30 ? 40 : days >= 14 ? 25 : 15,
    });
  }

  // Low engagement
  if ((profile.engagement_score || 0) < 30 && profile.plan !== 'free') {
    riskScore += 20;
    signals.push({
      signal:  'low_engagement',
      detail:  `Engagement score ${profile.engagement_score}/100 (below 30)`,
      weight:  20,
    });
  }

  // Free user — no conversion after 14 days
  if (profile.plan === 'free' && (profile.account_age_days || 0) >= 14) {
    riskScore += 15;
    signals.push({
      signal:  'free_non_convert',
      detail:  `Free user for ${profile.account_age_days} days — never converted`,
      weight:  15,
    });
  }

  // Long time since last purchase
  if (profile.total_purchases > 0 && profile.days_since_last_purchase >= 60) {
    riskScore += 15;
    signals.push({
      signal:  'purchase_dropout',
      detail:  `Last purchase ${profile.days_since_last_purchase} days ago`,
      weight:  15,
    });
  }

  const riskLevel =
    riskScore >= 60 ? 'CRITICAL' :
    riskScore >= 40 ? 'HIGH'     :
    riskScore >= 20 ? 'MEDIUM'   :
    'LOW';

  const retentionActions = buildRetentionActions(riskLevel, profile);

  return {
    risk_level:         riskLevel,
    risk_score:         Math.min(riskScore, 100),
    signals,
    retention_actions:  retentionActions,
    should_trigger_email: riskLevel === 'HIGH' || riskLevel === 'CRITICAL',
    recommended_offer: riskLevel !== 'LOW' ? getChurnOfferDiscount(profile.plan) : null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. FULL AI OPTIMIZATION PASS  ← MASTER FUNCTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run a complete AI revenue optimization pass for a user.
 * Returns personalized upsells, product recommendations, churn risk,
 * and a prioritized action plan.
 *
 * @param {object} env
 * @param {string} userId
 * @param {string} context — interaction context (scan_result|dashboard|api_response|email)
 * @returns {object} Complete AI optimization output
 */
export async function runRevenueOptimization(env, userId, context = 'dashboard') {
  // Step 1: Build behavior profile
  const profile = await getUserBehaviorProfile(env, userId);

  if (profile.error) {
    return { success: false, error: profile.error };
  }

  // Step 2: Run all optimizers in parallel
  const [upsell, products, churnRisk] = await Promise.all([
    Promise.resolve(getUpsellTrigger(profile, context)),
    Promise.resolve(getProductRecommendations(profile, 3)),
    Promise.resolve(analyzeChurnRisk(profile)),
  ]);

  // Step 3: AI personalization (Workers AI if available)
  let aiInsight = null;
  if (env.AI && profile.scans > 0) {
    aiInsight = await generateAIInsight(env, profile, upsell, products);
  }

  // Step 4: Calculate revenue potential
  const revPotential = calculateRevenuePotential(profile, products, upsell);

  // Step 5: Priority action for UI
  const priorityAction = determinePriorityAction(upsell, products, churnRisk);

  // Step 6: Log optimization event to KV (fire-and-forget)
  logOptimizationEvent(env, userId, { upsell, products, churnRisk, revPotential }).catch(() => {});

  return {
    success:              true,
    user_id:              userId,
    plan:                 profile.plan,
    engagement_score:     profile.engagement_score,
    // Core optimization outputs
    upsell,
    product_recommendations: products,
    churn_risk:           churnRisk,
    // Revenue potential
    revenue_potential:    revPotential,
    // Priority action (what to show FIRST)
    priority_action:      priorityAction,
    // AI narrative (if Workers AI enabled)
    ai_insight:           aiInsight,
    // Metadata
    context,
    generated_at:         new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. BULK OPTIMIZATION  — run for all users (cron job)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run AI optimization for all at-risk or high-value users.
 * Designed to run from a cron trigger.
 *
 * @param {object} env
 * @returns {object} summary of optimization pass
 */
export async function runBulkOptimization(env) {
  try {
    // Get users who need attention: high-risk churn OR high engagement (upsell candidates)
    const users = await env.DB.prepare(`
      SELECT id, email, plan, lead_score, updated_at, created_at
      FROM leads
      WHERE plan != 'free'
         OR lead_score >= 60
      ORDER BY lead_score DESC
      LIMIT 500
    `).all();

    const results = {
      total:            (users.results || []).length,
      upsell_triggered: 0,
      churn_flagged:    0,
      email_queued:     0,
      errors:           0,
    };

    // Process in small batches to avoid D1 rate limits
    const BATCH = 20;
    const rows  = users.results || [];

    for (let i = 0; i < rows.length; i += BATCH) {
      const batch = rows.slice(i, i + BATCH);

      await Promise.all(batch.map(async (user) => {
        try {
          const profile   = await getUserBehaviorProfile(env, user.id || user.email);
          const churnRisk = analyzeChurnRisk(profile);
          const upsell    = getUpsellTrigger(profile, 'email');

          if (churnRisk.risk_level === 'HIGH' || churnRisk.risk_level === 'CRITICAL') {
            results.churn_flagged++;
            // Flag in KV for email system to pick up
            await env.SECURITY_HUB_KV?.put(
              `churn:risk:${user.email}`,
              JSON.stringify({ risk: churnRisk, upsell, ts: Date.now() }),
              { expirationTtl: 86400 }
            );
            if (churnRisk.should_trigger_email) {
              results.email_queued++;
              await queueRetentionEmail(env, user, churnRisk, upsell);
            }
          }

          if (upsell.urgency === 'HARD') {
            results.upsell_triggered++;
            await env.SECURITY_HUB_KV?.put(
              `upsell:pending:${user.email}`,
              JSON.stringify({ upsell, ts: Date.now() }),
              { expirationTtl: 86400 }
            );
          }
        } catch {
          results.errors++;
        }
      }));
    }

    return {
      success: true,
      ...results,
      run_at: new Date().toISOString(),
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. SCAN-RESULT MONETIZATION  — called after every scan
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Inject monetization opportunities into a scan result payload.
 * Call this right before returning scan results to the user.
 *
 * @param {object} env
 * @param {object} scanResult — the raw scan result
 * @param {object} authCtx    — { userId, plan, email }
 * @returns {object} enriched scan result with monetization data
 */
export async function monetizeScanResult(env, scanResult, authCtx) {
  const { userId, plan, email } = authCtx || {};

  // Build lightweight profile (fast — skip full DB query for anonymous)
  const profile = userId
    ? await getUserBehaviorProfile(env, userId)
    : {
        plan:         plan || 'free',
        scans:        1,
        critical_cves: (scanResult?.critical_count || 0),
        high_cves:    (scanResult?.high_count || 0),
        engagement_score: 20,
        is_enterprise: false,
        total_spent:  0,
        api_calls_today: 0,
        days_since_last_scan: 0,
        funnel_events: {},
        has_siem: false,
      };

  const upsell   = getUpsellTrigger(profile, 'scan_result');
  const products = getProductRecommendations(profile, 2);

  // Build defense product CTAs for the scan
  const defenseCtAs = products.map(p => ({
    product:     p.product,
    headline:    p.headline,
    price:       `₹${p.price}`,
    buy_url:     p.buy_url,
    urgency:     p.urgency_type,
  }));

  // Upgrade gate message (for FREE users)
  const upgradeGate = plan === 'free' ? {
    show:     true,
    message:  '🔒 Full report locked — Upgrade to STARTER to unlock all CVE details',
    cta:      'Upgrade for ₹499/mo',
    url:      '/upgrade?plan=starter&ref=scan_gate',
  } : null;

  return {
    ...scanResult,
    _monetization: {
      upgrade_gate:         upgradeGate,
      upsell,
      defense_products:     defenseCtAs,
      upgrade_url:          upsell.type !== 'none' ? buildUpgradeUrl(upsell.to_plan, 'scan_result') : null,
      social_proof:         getSocialProof(plan === 'free' ? 'starter' : plan),
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function getUpgradeFeatures(fromPlan, toPlan) {
  const featureMap = {
    'free→starter':   ['Unlimited scans', '100 API calls/day', 'PDF reports', 'Email alerts', 'CSV export'],
    'starter→pro':    ['1,000 API calls/day', 'SIEM export (STIX/CEF/Sigma)', 'Priority support', 'Threat hunt packs', 'Advanced correlation'],
    'pro→enterprise': ['Unlimited API', 'Custom STIX feeds', 'SLA guarantee', 'Dedicated onboarding', 'Multi-user seats', 'Custom integrations'],
  };
  return featureMap[`${fromPlan}→${toPlan}`] || [];
}

function getSocialProof(plan) {
  const proofMap = {
    starter:    '2,400+ security professionals use STARTER',
    pro:        '800+ SOC teams rely on PRO',
    enterprise: '50+ enterprises trust CYBERDUDEBIVASH for threat intel',
  };
  return proofMap[plan] || '10,000+ scans run on this platform';
}

function buildBuyUrl(product, price) {
  return `/api/checkout?product=${encodeURIComponent(product)}&price=${price}&ref=ai_rec`;
}

function buildUpgradeUrl(plan, ref) {
  return `/upgrade?plan=${plan}&ref=${ref}&discount=1`;
}

function getChurnOfferDiscount(plan) {
  const discounts = {
    starter:    { pct: 30, message: '30% off — stay with us!', duration: '3 months' },
    pro:        { pct: 20, message: '20% loyalty discount',    duration: '3 months' },
    enterprise: { pct: 10, message: 'Custom renewal offer',    duration: '6 months' },
  };
  return discounts[plan] || { pct: 20, message: 'Special retention offer', duration: '2 months' };
}

function buildRetentionActions(riskLevel, profile) {
  const actions = [];

  if (riskLevel === 'CRITICAL') {
    actions.push({ type: 'email',   timing: 'immediate', template: 'churn_save_hard', priority: 1 });
    actions.push({ type: 'in_app',  timing: 'next_visit', message: 'We miss you! Here\'s 30% off', priority: 2 });
  } else if (riskLevel === 'HIGH') {
    actions.push({ type: 'email',   timing: '24h', template: 're_engagement', priority: 1 });
    actions.push({ type: 'in_app',  timing: 'next_visit', message: 'Run a new scan — your free weekly scan is ready', priority: 2 });
  } else if (riskLevel === 'MEDIUM') {
    actions.push({ type: 'email',   timing: '48h', template: 'weekly_digest', priority: 1 });
  }

  if (profile.plan === 'free') {
    actions.push({ type: 'email', timing: '72h', template: 'free_to_paid_nudge', priority: 3 });
  }

  return actions;
}

function calculateRevenuePotential(profile, products, upsell) {
  let potential = 0;

  // Upgrade potential
  if (upsell.type !== 'none' && upsell.price_offer) {
    potential += upsell.price_offer;
  }

  // Product purchase potential
  for (const p of products) {
    potential += p.price * 0.05; // ~5% click-to-buy rate
  }

  return {
    immediate_inr:      Math.round(potential),
    monthly_inr:        upsell.price_offer || 0,
    annual_inr:         (upsell.price_offer || 0) * 12,
    products_potential: products.reduce((a, p) => a + p.price, 0),
  };
}

function determinePriorityAction(upsell, products, churnRisk) {
  // CRITICAL churn → retention is top priority
  if (churnRisk.risk_level === 'CRITICAL') {
    return {
      type:    'retention',
      message: 'Show retention offer immediately',
      offer:   churnRisk.recommended_offer,
    };
  }

  // Hard upsell → show upgrade prompt
  if (upsell.urgency === 'HARD') {
    return {
      type:    'upgrade',
      message: upsell.headline,
      cta:     upsell.cta,
      url:     buildUpgradeUrl(upsell.to_plan, 'priority_action'),
    };
  }

  // High-value product
  if (products.length > 0) {
    return {
      type:    'product',
      message: products[0].headline,
      product: products[0].product,
      price:   products[0].price,
      url:     products[0].buy_url,
    };
  }

  return { type: 'none' };
}

async function generateAIInsight(env, profile, upsell, products) {
  try {
    const prompt = [
      `You are a cybersecurity SaaS revenue advisor.`,
      `User profile: plan=${profile.plan}, scans=${profile.scans}, critical_cves=${profile.critical_cves}, engagement=${profile.engagement_score}/100.`,
      `Top upsell: ${upsell.headline || 'none'}.`,
      `Recommended products: ${products.map(p => p.product).join(', ') || 'none'}.`,
      `Write ONE sentence (max 20 words) of personalized advice to maximize their security posture and value from upgrading.`,
    ].join(' ');

    const response = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 60,
    });

    return response?.response?.trim() || null;
  } catch {
    return null;
  }
}

async function queueRetentionEmail(env, user, churnRisk, upsell) {
  try {
    const payload = {
      type:      'retention',
      email:     user.email,
      plan:      user.plan,
      risk:      churnRisk.risk_level,
      offer:     churnRisk.recommended_offer,
      upsell,
      queued_at: Date.now(),
    };

    await env.SECURITY_HUB_KV?.put(
      `email:queue:retention:${user.email}`,
      JSON.stringify(payload),
      { expirationTtl: 86400 }
    );
  } catch { /* silent */ }
}

async function logOptimizationEvent(env, userId, data) {
  try {
    await env.SECURITY_HUB_KV?.put(
      `opt:log:${userId}:${Date.now()}`,
      JSON.stringify(data),
      { expirationTtl: 86400 * 3 }
    );
  } catch { /* silent */ }
}
