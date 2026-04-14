// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Analytics & Revenue Dashboard Engine
// GTM Growth Engine Phase 6: Business Intelligence + Growth Metrics
// ═══════════════════════════════════════════════════════════════════════════

// ── Plan pricing (INR) ───────────────────────────────────────────────────────
const PLAN_MRR = {
  free:       0,
  starter:    499,
  pro:        1499,
  enterprise: 4999,
};

// ─────────────────────────────────────────────────────────────────────────────
// CORE REVENUE METRICS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute MRR (Monthly Recurring Revenue)
 * @param {object} env
 * @returns {object} { mrr, arr, by_plan }
 */
export async function computeMRR(env) {
  try {
    const result = await env.DB.prepare(`
      SELECT plan, COUNT(*) as count
      FROM leads
      WHERE plan != 'free'
      GROUP BY plan
    `).all();

    let mrr = 0;
    const byPlan = {};

    for (const row of (result.results || [])) {
      const planMRR = (PLAN_MRR[row.plan] || 0) * row.count;
      mrr += planMRR;
      byPlan[row.plan] = { customers: row.count, mrr: planMRR };
    }

    return {
      mrr,
      arr:     mrr * 12,
      by_plan: byPlan,
    };
  } catch (err) {
    return { mrr: 0, arr: 0, by_plan: {}, error: err.message };
  }
}

/**
 * Compute conversion funnel rates
 */
export async function computeConversionMetrics(env) {
  try {
    const [total, paying, enterprise, hot] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE plan != 'free'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE is_enterprise = 1`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE lead_score >= 80`).first(),
    ]);

    const totalLeads   = total?.n   || 0;
    const payingLeads  = paying?.n  || 0;
    const entLeads     = enterprise?.n || 0;
    const hotLeads     = hot?.n     || 0;

    const convRate     = totalLeads > 0 ? ((payingLeads / totalLeads) * 100).toFixed(1) : '0.0';
    const entConvRate  = entLeads   > 0 ? ((payingLeads / entLeads) * 100).toFixed(1) : '0.0';

    return {
      total_leads:           totalLeads,
      paying_customers:      payingLeads,
      enterprise_leads:      entLeads,
      hot_leads:             hotLeads,
      conversion_rate_pct:   `${convRate}%`,
      enterprise_conv_rate:  `${entConvRate}%`,
      free_to_paid_ratio:    totalLeads > 0 ? (payingLeads / totalLeads).toFixed(3) : '0',
    };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Compute daily growth metrics (new users, new scans, new paying)
 * @param {object} env
 * @param {number} days - lookback window
 */
export async function computeGrowthMetrics(env, days = 30) {
  const since = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

  try {
    const [newLeads, newPaying, newEnterprise, scanEvents, apiCalls] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE created_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE plan != 'free' AND converted_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE is_enterprise = 1 AND created_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM funnel_events WHERE stage = 'scan_done' AND created_at >= ?`).bind(since).first(),
      env.DB.prepare(`SELECT COALESCE(SUM(weight), 0) as n FROM api_usage_log WHERE logged_at >= ?`).bind(since).first(),
    ]);

    // Day-by-day new leads (last 7 days for sparkline)
    const dailyRows = await env.DB.prepare(`
      SELECT date(created_at) as day, COUNT(*) as new_leads
      FROM leads
      WHERE created_at >= date('now', '-7 days')
      GROUP BY day
      ORDER BY day ASC
    `).all();

    return {
      period_days:       days,
      new_leads:         newLeads?.n      || 0,
      new_paying:        newPaying?.n     || 0,
      new_enterprise:    newEnterprise?.n || 0,
      total_scans:       scanEvents?.n    || 0,
      api_calls:         apiCalls?.n      || 0,
      scans_per_day:     Math.round((scanEvents?.n || 0) / days),
      daily_lead_trend:  dailyRows.results || [],
    };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Compute churn approximation (users who downgraded or went inactive)
 */
export async function computeChurnMetrics(env) {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();

    const [churned, inactive] = await Promise.all([
      // Leads who were once paying but now on free (downgraded)
      env.DB.prepare(`
        SELECT COUNT(*) as n FROM leads
        WHERE plan = 'free' AND converted_at IS NOT NULL
      `).first(),
      // Paying leads inactive for 30+ days
      env.DB.prepare(`
        SELECT COUNT(*) as n FROM leads
        WHERE plan != 'free' AND updated_at < ?
      `).bind(thirtyDaysAgo).first(),
    ]);

    return {
      churned_estimate:   churned?.n  || 0,
      inactive_30d:       inactive?.n || 0,
    };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Compute content marketing performance
 */
export async function computeContentMetrics(env) {
  try {
    const [queued, sent, telegramPosts] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM content_queue WHERE status = 'pending'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM content_queue WHERE status = 'posted'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM content_queue WHERE platform = 'telegram'`).first(),
    ]);

    return {
      content_queued:       queued?.n       || 0,
      content_published:    sent?.n         || 0,
      telegram_posts:       telegramPosts?.n|| 0,
    };
  } catch (err) {
    return { content_queued: 0, content_published: 0, telegram_posts: 0 };
  }
}

/**
 * Compute email marketing metrics
 */
export async function computeEmailMetrics(env) {
  try {
    const [sent, opens, clicks, sequences] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM email_tracking WHERE event = 'sent'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM email_tracking WHERE event = 'open'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM email_tracking WHERE event = 'click'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM email_sequences WHERE status = 'active'`).first(),
    ]);

    const sentN   = sent?.n   || 0;
    const opensN  = opens?.n  || 0;
    const clicksN = clicks?.n || 0;

    return {
      emails_sent:         sentN,
      email_opens:         opensN,
      email_clicks:        clicksN,
      open_rate_pct:       sentN > 0 ? `${((opensN / sentN) * 100).toFixed(1)}%` : '0.0%',
      click_rate_pct:      sentN > 0 ? `${((clicksN / sentN) * 100).toFixed(1)}%` : '0.0%',
      active_sequences:    sequences?.n || 0,
    };
  } catch (err) {
    return { emails_sent: 0, error: err.message };
  }
}

/**
 * Compute SOC & platform usage metrics (security value delivered)
 */
export async function computeSecurityMetrics(env) {
  try {
    const [threatCount, critCount, socAlerts, decisions, defenseActions] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE severity = 'CRITICAL'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM soc_alerts`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM soc_decisions WHERE priority IN ('P1-CRITICAL','P2-HIGH')`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM soc_defense_actions`).first(),
    ]);

    return {
      total_threats_tracked: threatCount?.n    || 0,
      critical_cves:         critCount?.n      || 0,
      soc_alerts_generated:  socAlerts?.n      || 0,
      high_priority_decisions: decisions?.n    || 0,
      defense_actions_taken: defenseActions?.n || 0,
    };
  } catch (err) {
    return { error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MASTER DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build the full revenue + growth dashboard
 * @param {object} env
 * @returns {object} Full analytics dashboard
 */
export async function buildRevenueDashboard(env) {
  const [revenue, conversions, growth, churn, content, email, security] = await Promise.all([
    computeMRR(env),
    computeConversionMetrics(env),
    computeGrowthMetrics(env, 30),
    computeChurnMetrics(env),
    computeContentMetrics(env),
    computeEmailMetrics(env),
    computeSecurityMetrics(env),
  ]);

  // Growth velocity
  const prevMonthNew = growth.new_leads || 0;
  const growthVelocity = prevMonthNew > 0 ? 'growing' : 'flat';

  // Health score (0–100)
  const healthScore = computePlatformHealthScore({ revenue, conversions, growth });

  return {
    generated_at: new Date().toISOString(),
    platform:     'Sentinel APEX',
    health_score: healthScore,
    health_label: healthScore >= 75 ? '🟢 Healthy' : healthScore >= 40 ? '🟡 Needs Attention' : '🔴 Action Required',

    revenue: {
      mrr_inr:    revenue.mrr,
      arr_inr:    revenue.arr,
      mrr_formatted: `₹${revenue.mrr.toLocaleString('en-IN')}`,
      arr_formatted: `₹${revenue.arr.toLocaleString('en-IN')}`,
      by_plan:    revenue.by_plan,
    },

    conversions: {
      ...conversions,
      growth_velocity: growthVelocity,
    },

    growth_30d: growth,
    churn,

    marketing: {
      content,
      email,
    },

    security_value: security,

    insights: generateInsights({ revenue, conversions, growth, churn }),
  };
}

/**
 * Compute a platform health score (0–100)
 */
function computePlatformHealthScore({ revenue, conversions, growth }) {
  let score = 0;

  // Revenue contribution (max 40)
  if (revenue.mrr >= 50000) score += 40;
  else if (revenue.mrr >= 10000) score += 30;
  else if (revenue.mrr >= 2000) score += 20;
  else if (revenue.mrr >= 499) score += 10;

  // Conversion rate (max 30)
  const convPct = parseFloat(conversions.conversion_rate_pct) || 0;
  if (convPct >= 5) score += 30;
  else if (convPct >= 2) score += 20;
  else if (convPct >= 0.5) score += 10;

  // Growth (max 30)
  if ((growth.new_leads || 0) >= 100) score += 30;
  else if ((growth.new_leads || 0) >= 20) score += 20;
  else if ((growth.new_leads || 0) >= 5) score += 10;

  return Math.min(score, 100);
}

/**
 * Auto-generate actionable growth insights
 */
function generateInsights({ revenue, conversions, growth, churn }) {
  const insights = [];

  if (revenue.mrr === 0) {
    insights.push({ type: 'action', priority: 'critical', message: 'No MRR yet — focus on converting top hot leads first. Run sales pipeline.' });
  } else if (revenue.mrr < 5000) {
    insights.push({ type: 'action', priority: 'high', message: `MRR at ₹${revenue.mrr}. Target: convert 2 more PRO customers to hit ₹${revenue.mrr + 2998}.` });
  }

  if ((conversions.total_leads || 0) > 10 && (conversions.paying_customers || 0) === 0) {
    insights.push({ type: 'action', priority: 'critical', message: 'High lead count but 0 conversions. Check upgrade CTA placement and drip email delivery.' });
  }

  if ((conversions.enterprise_leads || 0) > 5 && (conversions.paying_customers || 0) < 2) {
    insights.push({ type: 'opportunity', priority: 'high', message: `${conversions.enterprise_leads} enterprise leads detected. Personal outreach could unlock ₹${conversions.enterprise_leads * 4999} MRR potential.` });
  }

  if ((growth.new_leads || 0) < 5) {
    insights.push({ type: 'action', priority: 'medium', message: 'Low lead velocity. Publish content from the content queue and boost LinkedIn posts.' });
  }

  if ((churn.inactive_30d || 0) > 0) {
    insights.push({ type: 'warning', priority: 'medium', message: `${churn.inactive_30d} paying users inactive 30d. Send re-engagement email before they churn.` });
  }

  if (insights.length === 0) {
    insights.push({ type: 'success', priority: 'low', message: '✅ Platform performing well. Keep scaling content and sales outreach.' });
  }

  return insights;
}

/**
 * Cache and retrieve dashboard (KV, 2-min TTL)
 */
export async function getCachedDashboard(env, forceRefresh = false) {
  const cacheKey = 'analytics:revenue_dashboard';

  if (!forceRefresh) {
    try {
      const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
      if (cached) return JSON.parse(cached);
    } catch {}
  }

  const dashboard = await buildRevenueDashboard(env);

  try {
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(dashboard), { expirationTtl: 120 });
  } catch {}

  return dashboard;
}

/**
 * Track a growth analytics event (page view, cta click, etc.)
 */
export async function trackGrowthEvent(env, event, properties = {}) {
  try {
    await env.DB.prepare(`
      INSERT INTO growth_analytics (id, event, properties, created_at)
      VALUES (?, ?, ?, datetime('now'))
    `).bind(
      crypto.randomUUID(),
      event,
      JSON.stringify(properties)
    ).run();
  } catch {
    // Non-blocking
  }
}
