// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Enhanced Revenue Dashboard v8.2
// Phase 6: Charts-ready data, trend analytics, growth metrics
//
// Provides structured data optimised for Recharts / Chart.js rendering:
//   • Daily / weekly / monthly revenue trend lines
//   • MRR growth waterfall (new, expansion, contraction, churn)
//   • Revenue breakdown pie / bar data
//   • Conversion funnel visualisation
//   • Top products leaderboard
//   • Cohort retention (first 30 / 60 / 90 days)
//   • Real-time activity feed (last 20 events)
//   • KPI cards with period-over-period deltas
// ═══════════════════════════════════════════════════════════════════════════

const PLAN_PRICE = { starter: 499, pro: 1499, enterprise: 4999 };
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
function err(msg, status = 400, code = 'ERR') {
  return json({ success: false, error: msg, code }, status);
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN ENHANCED DASHBOARD HANDLER
// GET /api/revenue/dashboard/enhanced
// ─────────────────────────────────────────────────────────────────────────────

export async function handleEnhancedDashboard(request, env, authCtx) {
  // Require PRO or ENTERPRISE (or admin)
  const plan = authCtx?.plan || 'free';
  if (!authCtx?.userId) return err('Authentication required', 401, 'UNAUTHENTICATED');
  if (!['pro', 'enterprise'].includes(plan) && authCtx?.role !== 'admin') {
    return err('PRO or ENTERPRISE plan required', 403, 'PLAN_REQUIRED');
  }

  const url      = new URL(request.url);
  const period   = url.searchParams.get('period')  || 'month';   // week|month|quarter|year
  const currency = url.searchParams.get('currency') || 'INR';
  const refresh  = url.searchParams.get('refresh')  === 'true';

  // Resolve date window
  const { days, bucketFmt, bucketLabel } = resolvePeriod(period);
  const since    = new Date(Date.now() - days * 86400000).toISOString();
  const prevFrom = new Date(Date.now() - days * 2 * 86400000).toISOString();

  // Cache (10-min TTL for pro, 2-min for enterprise real-time)
  const cacheTTL = plan === 'enterprise' ? 120 : 600;
  const cacheKey = `cache:dashboard:enhanced:${plan}:${period}`;

  if (!refresh) {
    try {
      const cached = await env.SECURITY_HUB_KV?.get(cacheKey);
      if (cached) return json({ success: true, cached: true, ...JSON.parse(cached) });
    } catch { /* miss */ }
  }

  try {
    // ── Run all queries in parallel ───────────────────────────────────────
    const [
      // 1. Daily revenue trend (current period)
      dailyTrend,
      // 2. Daily revenue trend (previous period — for delta)
      prevTrend,
      // 3. Revenue by source
      bySource,
      // 4. Subscribers by plan
      subsByPlan,
      // 5. Previous period subscribers
      prevSubsByPlan,
      // 6. Funnel stages
      funnelCurrent,
      // 7. Top products
      topProducts,
      // 8. Real-time activity feed
      recentEvents,
      // 9. Affiliate stats
      affiliateStats,
      // 10. AdSense
      adSenseStats,
      // 11. Gumroad
      gumroadStats,
      // 12. New users trend
      newUsersTrend,
      // 13. Cohort D30/D60/D90 retention
      cohortRetention,
    ] = await Promise.all([

      // 1. Daily revenue trend
      env.DB.prepare(`
        SELECT date(created_at) as day,
               COALESCE(SUM(amount), 0) as revenue,
               COUNT(*) as transactions,
               source
        FROM revenue_events
        WHERE created_at >= ?
        GROUP BY date(created_at), source
        ORDER BY day ASC
      `).bind(since).all(),

      // 2. Prev period total
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as events
        FROM revenue_events
        WHERE created_at >= ? AND created_at < ?
      `).bind(prevFrom, since).first(),

      // 3. Revenue by source
      env.DB.prepare(`
        SELECT source,
               COALESCE(SUM(amount), 0) as amount,
               COUNT(*) as count
        FROM revenue_events
        WHERE created_at >= ?
        GROUP BY source
        ORDER BY amount DESC
      `).bind(since).all(),

      // 4. Current subscribers
      env.DB.prepare(`
        SELECT plan, COUNT(*) as count
        FROM leads
        WHERE plan != 'free' AND status = 'active'
        GROUP BY plan
      `).all(),

      // 5. Previous period subscribers (as of period start)
      env.DB.prepare(`
        SELECT plan, COUNT(*) as count
        FROM leads
        WHERE plan != 'free' AND status = 'active'
          AND created_at < ?
        GROUP BY plan
      `).bind(since).all(),

      // 6. Funnel stages
      env.DB.prepare(`
        SELECT stage, COUNT(*) as count
        FROM funnel_events
        WHERE created_at >= ?
        GROUP BY stage
        ORDER BY count DESC
      `).bind(since).all(),

      // 7. Top products
      env.DB.prepare(`
        SELECT source,
               metadata as product,
               COUNT(*) as sales,
               COALESCE(SUM(amount), 0) as revenue,
               AVG(amount) as avg_price
        FROM revenue_events
        WHERE created_at >= ?
          AND source IN ('defense_product','full_defense_pack','enterprise_bundle','report_purchase','gumroad')
        GROUP BY source, metadata
        ORDER BY revenue DESC
        LIMIT 10
      `).bind(since).all(),

      // 8. Recent events feed
      env.DB.prepare(`
        SELECT source, amount, email, metadata, created_at
        FROM revenue_events
        ORDER BY created_at DESC
        LIMIT 20
      `).all(),

      // 9. Affiliate
      env.DB.prepare(`
        SELECT program,
               COUNT(*) as clicks,
               COALESCE(SUM(estimated_commission), 0) as est_commission
        FROM affiliate_clicks
        WHERE clicked_at >= ?
        GROUP BY program
        ORDER BY clicks DESC
      `).bind(since).all(),

      // 10. AdSense
      env.DB.prepare(`
        SELECT COALESCE(SUM(impressions), 0) as impressions,
               COALESCE(SUM(clicks), 0) as clicks,
               COALESCE(SUM(estimated_revenue), 0) as revenue
        FROM adsense_events
        WHERE recorded_at >= ?
      `).bind(since).first(),

      // 11. Gumroad
      env.DB.prepare(`
        SELECT COUNT(*) as sales,
               COALESCE(SUM(amount), 0) as revenue
        FROM gumroad_licenses
        WHERE status = 'active' AND created_at >= ?
      `).bind(since).first(),

      // 12. New users daily trend
      env.DB.prepare(`
        SELECT date(created_at) as day, COUNT(*) as new_users
        FROM leads
        WHERE created_at >= ?
        GROUP BY date(created_at)
        ORDER BY day ASC
      `).bind(since).all(),

      // 13. Cohort retention (users who had activity at 30/60/90 days after signup)
      env.DB.prepare(`
        SELECT
          COUNT(DISTINCT CASE WHEN julianday('now') - julianday(created_at) <= 30 THEN email END) as d30,
          COUNT(DISTINCT CASE WHEN julianday('now') - julianday(created_at) <= 60 THEN email END) as d60,
          COUNT(DISTINCT CASE WHEN julianday('now') - julianday(created_at) <= 90 THEN email END) as d90,
          COUNT(*) as total
        FROM leads
        WHERE plan != 'free' AND status = 'active'
      `).first(),
    ]);

    // ── Process daily trend into chart format ─────────────────────────────
    const trendMap = {};
    for (const row of (dailyTrend.results || [])) {
      if (!trendMap[row.day]) {
        trendMap[row.day] = { day: row.day, total: 0, transactions: 0 };
      }
      trendMap[row.day].total        += row.revenue || 0;
      trendMap[row.day].transactions += row.transactions || 0;
      trendMap[row.day][row.source]   = (trendMap[row.day][row.source] || 0) + (row.revenue || 0);
    }
    const trendData = Object.values(trendMap).sort((a, b) => a.day > b.day ? 1 : -1);

    // Fill missing days with 0
    const filledTrend = fillMissingDays(trendData, days);

    // ── Calculate KPIs + deltas ───────────────────────────────────────────
    const totalRevenue = (bySource.results || []).reduce((a, r) => a + (r.amount || 0), 0);
    const prevRevenue  = prevTrend?.total || 0;
    const revDelta     = prevRevenue > 0
      ? (((totalRevenue - prevRevenue) / prevRevenue) * 100).toFixed(1)
      : totalRevenue > 0 ? '+100' : '0';

    // MRR calculation
    const currentSubs = subsByPlan.results || [];
    const prevSubs    = prevSubsByPlan.results || [];
    let mrr = 0, prevMrr = 0;
    for (const s of currentSubs) mrr     += (PLAN_PRICE[s.plan] || 0) * s.count;
    for (const s of prevSubs)    prevMrr += (PLAN_PRICE[s.plan] || 0) * s.count;
    const mrrDelta = prevMrr > 0 ? (((mrr - prevMrr) / prevMrr) * 100).toFixed(1) : mrr > 0 ? '+100' : '0';

    // Total paying customers
    const totalCustomers     = currentSubs.reduce((a, s) => a + s.count, 0);
    const prevTotalCustomers = prevSubs.reduce((a, s) => a + s.count, 0);
    const custDelta          = prevTotalCustomers > 0
      ? (((totalCustomers - prevTotalCustomers) / prevTotalCustomers) * 100).toFixed(1)
      : '0';

    // ARPU
    const arpu     = totalCustomers > 0 ? Math.round(mrr / totalCustomers) : 0;
    const prevArpu = prevTotalCustomers > 0 ? Math.round(prevMrr / prevTotalCustomers) : 0;
    const arpuDelta = prevArpu > 0 ? (((arpu - prevArpu) / prevArpu) * 100).toFixed(1) : '0';

    // ── Funnel chart data ─────────────────────────────────────────────────
    const FUNNEL_STAGES = ['visit','scan_start','scan_done','email_capture','product_view','checkout_start','purchase'];
    const funnelMap = {};
    for (const row of (funnelCurrent.results || [])) funnelMap[row.stage] = row.count;

    const funnelChart = FUNNEL_STAGES.map((stage, i) => {
      const count = funnelMap[stage] || 0;
      const prev  = i > 0 ? (funnelMap[FUNNEL_STAGES[i - 1]] || 1) : (count || 1);
      return {
        stage,
        label:        stageLabelOf(stage),
        count,
        conversion:   prev > 0 ? parseFloat(((count / prev) * 100).toFixed(1)) : 0,
        dropoff:      prev > 0 ? parseFloat(((1 - count / prev) * 100).toFixed(1)) : 0,
        fill:         funnelColor(i),
      };
    });

    // ── Revenue pie chart data ────────────────────────────────────────────
    const COLORS = ['#6366f1','#22d3ee','#f59e0b','#10b981','#f43f5e','#8b5cf6','#ec4899','#14b8a6'];
    const pieData = (bySource.results || []).map((s, i) => ({
      name:    sourceLabel(s.source),
      value:   s.amount || 0,
      count:   s.count,
      percent: totalRevenue > 0 ? parseFloat(((s.amount / totalRevenue) * 100).toFixed(1)) : 0,
      fill:    COLORS[i % COLORS.length],
    }));

    // ── MRR waterfall ─────────────────────────────────────────────────────
    const mrrNew         = Math.max(0, mrr - prevMrr);
    const mrrChurn       = Math.max(0, prevMrr - mrr);
    const mrrExpansion   = 0; // would need plan upgrade tracking
    const mrrWaterfall   = [
      { name: 'Starting MRR',  value: prevMrr,       type: 'base'      },
      { name: 'New MRR',       value: mrrNew,         type: 'positive'  },
      { name: 'Expansion',     value: mrrExpansion,   type: 'positive'  },
      { name: 'Churn',         value: -mrrChurn,      type: 'negative'  },
      { name: 'Ending MRR',    value: mrr,            type: 'total'     },
    ];

    // ── Subscriber plan breakdown (pie) ────────────────────────────────────
    const subPieData = currentSubs.map((s, i) => ({
      name:    s.plan.charAt(0).toUpperCase() + s.plan.slice(1),
      value:   s.count,
      mrr:     (PLAN_PRICE[s.plan] || 0) * s.count,
      fill:    COLORS[i % COLORS.length],
    }));

    // ── New users trend ───────────────────────────────────────────────────
    const newUsersTrendFilled = fillMissingDays(
      (newUsersTrend.results || []).map(r => ({ day: r.day, new_users: r.new_users })),
      days,
      { new_users: 0 }
    );

    // ── Real-time activity feed (anonymised) ──────────────────────────────
    const activityFeed = (recentEvents.results || []).map(r => ({
      type:       r.source,
      label:      activityLabel(r.source, r.amount),
      amount:     r.amount || 0,
      time:       r.created_at,
      icon:       activityIcon(r.source),
    }));

    // ── Cohort retention rates ────────────────────────────────────────────
    const cohort = cohortRetention || {};
    const cohortChart = [
      { day: 'D-30', users: cohort.d30 || 0, rate: cohort.total > 0 ? parseFloat(((cohort.d30 || 0) / cohort.total * 100).toFixed(1)) : 0 },
      { day: 'D-60', users: cohort.d60 || 0, rate: cohort.total > 0 ? parseFloat(((cohort.d60 || 0) / cohort.total * 100).toFixed(1)) : 0 },
      { day: 'D-90', users: cohort.d90 || 0, rate: cohort.total > 0 ? parseFloat(((cohort.d90 || 0) / cohort.total * 100).toFixed(1)) : 0 },
    ];

    // ── Growth score (0–100 composite health score) ───────────────────────
    const growthScore = computeGrowthScore({
      mrrDelta: parseFloat(mrrDelta),
      convRate: funnelMap['purchase'] ? (funnelMap['purchase'] / Math.max(funnelMap['visit'] || 1, 1)) * 100 : 0,
      custDelta: parseFloat(custDelta),
      totalRevenue,
      prevRevenue,
    });

    // ── Build final payload ───────────────────────────────────────────────
    const payload = {
      // ── Period meta ─────────────────────────────────────────────────────
      period,
      period_label: periodLabel(period),
      window_days:  days,
      since,

      // ── KPI Cards ───────────────────────────────────────────────────────
      kpis: {
        total_revenue:    { value: totalRevenue,    prev: prevRevenue,  delta: `${revDelta}%`,  trend: parseFloat(revDelta) >= 0 ? 'up' : 'down' },
        mrr:              { value: mrr,             prev: prevMrr,      delta: `${mrrDelta}%`,  trend: parseFloat(mrrDelta) >= 0 ? 'up' : 'down' },
        arr:              { value: mrr * 12,        prev: prevMrr * 12, delta: `${mrrDelta}%`,  trend: parseFloat(mrrDelta) >= 0 ? 'up' : 'down' },
        paying_customers: { value: totalCustomers,  prev: prevTotalCustomers, delta: `${custDelta}%`, trend: parseFloat(custDelta) >= 0 ? 'up' : 'down' },
        arpu:             { value: arpu,            prev: prevArpu,     delta: `${arpuDelta}%`, trend: parseFloat(arpuDelta) >= 0 ? 'up' : 'down' },
        gumroad_revenue:  { value: gumroadStats?.revenue || 0, sales: gumroadStats?.sales || 0 },
        affiliate_clicks: { value: (affiliateStats.results || []).reduce((a, r) => a + r.clicks, 0), est_commission: (affiliateStats.results || []).reduce((a, r) => a + (r.est_commission || 0), 0) },
        adsense_revenue:  { value: adSenseStats?.revenue || 0, impressions: adSenseStats?.impressions || 0, clicks: adSenseStats?.clicks || 0 },
        growth_score:     { value: growthScore, label: growthLabel(growthScore) },
        conversion_rate:  {
          value: funnelMap['visit'] > 0
            ? parseFloat(((funnelMap['purchase'] || 0) / funnelMap['visit'] * 100).toFixed(2))
            : 0,
          unit: '%',
        },
      },

      // ── Chart data ────────────────────────────────────────────────────────
      charts: {
        revenue_trend:      filledTrend,        // Line chart: revenue over time
        new_users_trend:    newUsersTrendFilled, // Area chart: new signups over time
        revenue_by_source:  pieData,            // Pie/donut: revenue breakdown
        funnel:             funnelChart,        // Funnel: conversion stages
        mrr_waterfall:      mrrWaterfall,       // Waterfall: MRR change
        subscriber_plans:   subPieData,         // Pie: sub plan distribution
        cohort_retention:   cohortChart,        // Bar: cohort retention %
        affiliate_breakdown: (affiliateStats.results || []).map(r => ({
          name:  r.program,
          clicks: r.clicks,
          est:   r.est_commission,
        })),
      },

      // ── Top products leaderboard ──────────────────────────────────────────
      top_products: (topProducts.results || []).map((p, i) => ({
        rank:    i + 1,
        product: p.product || p.source,
        source:  p.source,
        sales:   p.sales,
        revenue: p.revenue,
        avg_price: Math.round(p.avg_price || 0),
      })),

      // ── Real-time activity feed ───────────────────────────────────────────
      activity_feed: activityFeed,

      // ── Insights & Recommendations ────────────────────────────────────────
      insights: generateDashboardInsights({
        mrr, prevMrr, mrrDelta,
        totalRevenue, prevRevenue, revDelta,
        funnelMap, topProducts: topProducts.results || [],
        adSense: adSenseStats, affiliate: affiliateStats.results || [],
      }),

      generated_at: new Date().toISOString(),
    };

    // Cache
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: cacheTTL }).catch(() => {});

    return json({ success: true, ...payload });

  } catch (e) {
    return err(`Enhanced dashboard error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/trends  — Trend analytics for a specific metric
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueTrends(request, env, authCtx) {
  if (!authCtx?.userId) return err('Authentication required', 401, 'UNAUTHENTICATED');
  if (!['pro','enterprise'].includes(authCtx?.plan) && authCtx?.role !== 'admin') {
    return err('PRO+ required', 403, 'PLAN_REQUIRED');
  }

  const url    = new URL(request.url);
  const metric = url.searchParams.get('metric') || 'revenue'; // revenue|users|scans|conversions
  const period = url.searchParams.get('period') || 'month';
  const { days } = resolvePeriod(period);
  const since  = new Date(Date.now() - days * 86400000).toISOString();

  try {
    let trendQuery;

    switch (metric) {
      case 'revenue':
        trendQuery = env.DB.prepare(`
          SELECT date(created_at) as day,
                 COALESCE(SUM(amount), 0) as value,
                 COUNT(*) as count
          FROM revenue_events
          WHERE created_at >= ?
          GROUP BY date(created_at)
          ORDER BY day ASC
        `).bind(since).all();
        break;

      case 'users':
        trendQuery = env.DB.prepare(`
          SELECT date(created_at) as day,
                 COUNT(*) as value,
                 SUM(CASE WHEN plan != 'free' THEN 1 ELSE 0 END) as paid
          FROM leads
          WHERE created_at >= ?
          GROUP BY date(created_at)
          ORDER BY day ASC
        `).bind(since).all();
        break;

      case 'scans':
        trendQuery = env.DB.prepare(`
          SELECT date(created_at) as day,
                 COUNT(*) as value
          FROM scan_history
          WHERE created_at >= ?
          GROUP BY date(created_at)
          ORDER BY day ASC
        `).bind(since).all();
        break;

      case 'conversions':
        trendQuery = env.DB.prepare(`
          SELECT date(created_at) as day,
                 COUNT(*) as value
          FROM funnel_events
          WHERE stage = 'purchase' AND created_at >= ?
          GROUP BY date(created_at)
          ORDER BY day ASC
        `).bind(since).all();
        break;

      default:
        return err('Invalid metric. Use: revenue|users|scans|conversions', 400, 'INVALID_METRIC');
    }

    const rows = await trendQuery;
    const filled = fillMissingDays(rows.results || [], days, { value: 0 });

    // Calculate moving average (7-day)
    const withMA = computeMovingAverage(filled, 'value', 7);

    // Overall stats
    const total   = filled.reduce((a, r) => a + (r.value || 0), 0);
    const avgDaily = filled.length > 0 ? Math.round(total / filled.length) : 0;
    const maxDay   = filled.reduce((a, r) => r.value > a.value ? r : a, filled[0] || { value: 0 });
    const minDay   = filled.reduce((a, r) => r.value < a.value ? r : a, filled[0] || { value: 0 });

    return json({
      success: true,
      metric,
      period,
      data:     withMA,
      summary: {
        total,
        avg_daily:  avgDaily,
        max:        { day: maxDay?.day, value: maxDay?.value },
        min:        { day: minDay?.day, value: minDay?.value },
        trend:      trendDirection(filled),
      },
    });
  } catch (e) {
    return err(`Trends error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/revenue/growth  — Growth score + levers
// ─────────────────────────────────────────────────────────────────────────────

export async function handleRevenueGrowth(request, env, authCtx) {
  if (!authCtx?.userId) return err('Authentication required', 401, 'UNAUTHENTICATED');

  try {
    const since30  = new Date(Date.now() - 30  * 86400000).toISOString();
    const since60  = new Date(Date.now() - 60  * 86400000).toISOString();

    const [curr30, prev30, currUsers, prevUsers, currConv, prevConv] = await Promise.all([
      env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as r FROM revenue_events WHERE created_at >= ?`).bind(since30).first(),
      env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as r FROM revenue_events WHERE created_at >= ? AND created_at < ?`).bind(since60, since30).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE plan != 'free' AND status = 'active'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM leads WHERE plan != 'free' AND status = 'active' AND created_at < ?`).bind(since30).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM funnel_events WHERE stage = 'purchase' AND created_at >= ?`).bind(since30).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM funnel_events WHERE stage = 'purchase' AND created_at >= ? AND created_at < ?`).bind(since60, since30).first(),
    ]);

    const revGrowth  = calcPctDelta(curr30?.r || 0, prev30?.r || 0);
    const userGrowth = calcPctDelta(currUsers?.n || 0, prevUsers?.n || 0);
    const convGrowth = calcPctDelta(currConv?.n || 0, prevConv?.n || 0);

    // Health levers
    const levers = [
      {
        lever:    'Revenue Growth',
        current:  `₹${Math.round(curr30?.r || 0)}`,
        delta:    `${revGrowth > 0 ? '+' : ''}${revGrowth.toFixed(1)}%`,
        status:   revGrowth >= 10 ? 'healthy' : revGrowth >= 0 ? 'neutral' : 'warning',
        tip:      revGrowth < 0 ? 'Launch a flash sale or bundle offer to recover revenue.' : 'Keep it up — consider price testing.',
      },
      {
        lever:    'Customer Growth',
        current:  String(currUsers?.n || 0),
        delta:    `${userGrowth > 0 ? '+' : ''}${userGrowth.toFixed(1)}%`,
        status:   userGrowth >= 5 ? 'healthy' : userGrowth >= 0 ? 'neutral' : 'warning',
        tip:      userGrowth < 0 ? 'Increase free→paid conversion with a timed discount.' : 'Run a referral program to accelerate growth.',
      },
      {
        lever:    'Conversion Growth',
        current:  String(currConv?.n || 0) + ' purchases',
        delta:    `${convGrowth > 0 ? '+' : ''}${convGrowth.toFixed(1)}%`,
        status:   convGrowth >= 10 ? 'healthy' : convGrowth >= 0 ? 'neutral' : 'warning',
        tip:      convGrowth < 0 ? 'Add urgency timers and social proof to scan results.' : 'A/B test CTA copy for higher CVR.',
      },
    ];

    const overallScore = computeGrowthScore({ mrrDelta: revGrowth, convRate: convGrowth, custDelta: userGrowth, totalRevenue: curr30?.r || 0, prevRevenue: prev30?.r || 0 });

    return json({
      success:       true,
      growth_score:  overallScore,
      growth_label:  growthLabel(overallScore),
      levers,
      summary: {
        revenue_30d:       curr30?.r || 0,
        revenue_prev_30d:  prev30?.r || 0,
        revenue_delta_pct: `${revGrowth.toFixed(1)}%`,
        customers:         currUsers?.n || 0,
        customer_delta_pct:`${userGrowth.toFixed(1)}%`,
        conversions_30d:   currConv?.n || 0,
        conv_delta_pct:    `${convGrowth.toFixed(1)}%`,
      },
    });
  } catch (e) {
    return err(`Growth error: ${e.message}`, 500, 'INTERNAL_ERROR');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function resolvePeriod(period) {
  switch (period) {
    case 'week':    return { days: 7,   bucketFmt: '%Y-%W', bucketLabel: 'Week' };
    case 'quarter': return { days: 90,  bucketFmt: '%Y-%m', bucketLabel: 'Month' };
    case 'year':    return { days: 365, bucketFmt: '%Y-%m', bucketLabel: 'Month' };
    default:        return { days: 30,  bucketFmt: '%Y-%m-%d', bucketLabel: 'Day' };
  }
}

function periodLabel(period) {
  return { week: 'Last 7 Days', month: 'Last 30 Days', quarter: 'Last 90 Days', year: 'Last 365 Days' }[period] || 'Last 30 Days';
}

function fillMissingDays(rows, days, defaults = {}) {
  const map = {};
  for (const r of rows) map[r.day] = r;

  const result = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().split('T')[0];
    result.push(map[d] || { day: d, total: 0, transactions: 0, ...defaults });
  }
  return result;
}

function computeMovingAverage(data, key, window) {
  return data.map((row, idx) => {
    const start = Math.max(0, idx - window + 1);
    const slice = data.slice(start, idx + 1);
    const avg   = slice.reduce((a, r) => a + (r[key] || 0), 0) / slice.length;
    return { ...row, [`${key}_ma${window}`]: Math.round(avg * 100) / 100 };
  });
}

function trendDirection(data) {
  if (data.length < 2) return 'flat';
  const first = data.slice(0, Math.ceil(data.length / 2)).reduce((a, r) => a + (r.value || 0), 0);
  const last  = data.slice(Math.floor(data.length / 2)).reduce((a, r) => a + (r.value || 0), 0);
  if (last > first * 1.05) return 'up';
  if (last < first * 0.95) return 'down';
  return 'flat';
}

function calcPctDelta(curr, prev) {
  if (prev === 0) return curr > 0 ? 100 : 0;
  return ((curr - prev) / prev) * 100;
}

function computeGrowthScore({ mrrDelta, convRate, custDelta, totalRevenue, prevRevenue }) {
  let score = 50; // base
  score += Math.min(mrrDelta * 0.5, 20);   // MRR growth (max +20)
  score += Math.min(convRate  * 0.3, 15);   // conversion rate (max +15)
  score += Math.min(custDelta * 0.5, 15);   // customer growth (max +15)
  if (totalRevenue > prevRevenue) score += 5; // revenue up bonus
  if (totalRevenue > 10000)       score += 5; // scale bonus
  return Math.max(0, Math.min(100, Math.round(score)));
}

function growthLabel(score) {
  if (score >= 80) return 'Excellent 🚀';
  if (score >= 65) return 'Good 📈';
  if (score >= 50) return 'Steady 😐';
  if (score >= 30) return 'Needs Attention ⚠️';
  return 'Critical 🔴';
}

function funnelColor(idx) {
  const colors = ['#6366f1','#818cf8','#a5b4fc','#c7d2fe','#ddd6fe','#ede9fe','#f5f3ff'];
  return colors[Math.min(idx, colors.length - 1)];
}

function stageLabelOf(stage) {
  const labels = {
    visit:          'Visitors',
    scan_start:     'Started Scan',
    scan_done:      'Completed Scan',
    email_capture:  'Email Captured',
    product_view:   'Viewed Product',
    checkout_start: 'Started Checkout',
    purchase:       'Purchased',
  };
  return labels[stage] || stage;
}

function sourceLabel(source) {
  const labels = {
    subscription:      'Subscriptions',
    gumroad:           'Gumroad',
    defense_product:   'Defense Products',
    full_defense_pack: 'Defense Bundle',
    enterprise_bundle: 'Enterprise Bundle',
    api_credits:       'API Credits',
    affiliate:         'Affiliate',
    report_purchase:   'Reports',
    enterprise_deal:   'Enterprise Deal',
    pending_checkout:  'Pending',
  };
  return labels[source] || source;
}

function activityLabel(source, amount) {
  const base = sourceLabel(source);
  return amount > 0 ? `${base} — ₹${amount}` : base;
}

function activityIcon(source) {
  const icons = {
    subscription: '💳', gumroad: '🛒', defense_product: '🛡',
    full_defense_pack: '📦', api_credits: '⚡', affiliate: '🔗',
    report_purchase: '📄', enterprise_deal: '🏢',
  };
  return icons[source] || '💰';
}

function generateDashboardInsights({ mrr, prevMrr, mrrDelta, totalRevenue, prevRevenue, revDelta, funnelMap, topProducts, adSense, affiliate }) {
  const insights = [];

  const mrrD = parseFloat(mrrDelta);
  if (mrrD > 15) {
    insights.push({ type: 'positive', message: `MRR grew ${mrrDelta}% this period — accelerate with a referral campaign.`, priority: 1 });
  } else if (mrrD < -5) {
    insights.push({ type: 'warning', message: `MRR declined ${Math.abs(mrrD)}% — activate churn-save emails immediately.`, priority: 1 });
  }

  const convRate = funnelMap['visit'] > 0 ? (funnelMap['purchase'] || 0) / funnelMap['visit'] * 100 : 0;
  if (convRate < 1) {
    insights.push({ type: 'warning', message: `Conversion rate is ${convRate.toFixed(2)}% — add urgency timers and social proof to scan results.`, priority: 2 });
  } else if (convRate > 5) {
    insights.push({ type: 'positive', message: `Strong ${convRate.toFixed(1)}% conversion rate — scale ad spend for more visitors.`, priority: 2 });
  }

  if ((adSense?.impressions || 0) === 0) {
    insights.push({ type: 'info', message: 'AdSense not yet active. Replace ca-pub-XXXXXXXX to start earning passive ad revenue.', priority: 3 });
  }

  if ((affiliate || []).length === 0 || (affiliate || []).reduce((a, r) => a + r.clicks, 0) < 10) {
    insights.push({ type: 'info', message: 'Low affiliate clicks. Add affiliate banners inside CVE scan results for passive commissions.', priority: 3 });
  }

  if (topProducts.length > 0) {
    const top = topProducts[0];
    insights.push({ type: 'positive', message: `Top product: "${top.product || top.source}" generated ₹${top.revenue} — create variations to 3× revenue.`, priority: 2 });
  }

  return insights.sort((a, b) => a.priority - b.priority);
}
