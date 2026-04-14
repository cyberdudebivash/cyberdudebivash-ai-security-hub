// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH AI Security Hub — Master Revenue Engine v8.1
// Phase 2: Aggregate ALL revenue sources into a unified financial picture
//
// Revenue streams:
//   1. Subscriptions    — Razorpay MRR/ARR (FREE/STARTER/PRO/ENTERPRISE)
//   2. Gumroad          — One-time product sales & bundles
//   3. Defense Products — Firewall rules, IDS sigs, IR playbooks, etc.
//   4. API Credits      — Pay-per-use API billing (STARTER/PRO overage)
//   5. Affiliate        — HTB, THM, Udemy, NordVPN click commissions
//   6. AdSense          — Display ad impressions/clicks
//   7. Reports          — Individual paid scan reports (₹199–₹9,999)
//   8. Enterprise Deals — Custom retainer agreements
// ═══════════════════════════════════════════════════════════════════════════

// ── Plan pricing (INR, monthly) ──────────────────────────────────────────────
export const PLAN_PRICING = {
  free:       0,
  starter:    499,
  pro:        1499,
  enterprise: 4999,
};

// ── Defense product catalog pricing (INR) ────────────────────────────────────
export const DEFENSE_PRICING = {
  firewall_rules:   199,
  ids_signatures:   399,
  ir_playbook:      999,
  hardening_script: 599,
  threat_hunt_pack: 799,
  sigma_rules:      399,
  exec_briefing:    299,
  full_defense_pack:  2499,
  enterprise_bundle:  9999,
};

// ── Report pricing tiers ─────────────────────────────────────────────────────
export const REPORT_PRICING = {
  basic:      199,
  standard:   499,
  premium:    999,
  enterprise: 9999,
};

// ── Affiliate commission estimates (INR per click/conversion) ────────────────
const AFFILIATE_EST_CPC = {
  hackthebox:  45,
  tryhackme:   35,
  udemy:       60,
  nordvpn:     120,
  default:     30,
};

// ── AdSense CPM estimates ─────────────────────────────────────────────────────
const ADSENSE_EST_CPM = 25; // ₹25 per 1,000 impressions (conservative)

// ─────────────────────────────────────────────────────────────────────────────
// 1. SUBSCRIPTION REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate subscription MRR/ARR from active leads
 */
export async function getSubscriptionRevenue(env) {
  try {
    // Active paid subscribers by plan
    const planRows = await env.DB.prepare(`
      SELECT plan, COUNT(*) as count
      FROM leads
      WHERE plan != 'free' AND status = 'active'
      GROUP BY plan
    `).all();

    let mrr = 0;
    const byPlan = {};

    for (const row of (planRows.results || [])) {
      const planMRR = (PLAN_PRICING[row.plan] || 0) * row.count;
      mrr += planMRR;
      byPlan[row.plan] = {
        subscribers: row.count,
        mrr:         planMRR,
        arr:         planMRR * 12,
      };
    }

    // Recent subscription revenue events from revenue_events table
    const recentRows = await env.DB.prepare(`
      SELECT COALESCE(SUM(amount), 0) as total,
             COUNT(*) as count
      FROM revenue_events
      WHERE source = 'subscription'
        AND created_at >= datetime('now', '-30 days')
    `).first();

    const recentRevenue = recentRows?.total || 0;

    // Churned in last 30 days
    const churnRows = await env.DB.prepare(`
      SELECT COUNT(*) as n
      FROM leads
      WHERE plan = 'free'
        AND updated_at >= datetime('now', '-30 days')
        AND status = 'churned'
    `).first();

    return {
      mrr,
      arr:             mrr * 12,
      by_plan:         byPlan,
      recent_30d:      recentRevenue,
      churned_30d:     churnRows?.n || 0,
      net_mrr_growth:  recentRevenue - ((churnRows?.n || 0) * PLAN_PRICING.starter),
    };
  } catch (err) {
    return { mrr: 0, arr: 0, by_plan: {}, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. GUMROAD PRODUCT REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate Gumroad one-time product sales
 */
export async function getGumroadRevenue(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [totals, byProduct, recent] = await Promise.all([
      // All-time totals
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as sales_count
        FROM gumroad_licenses
        WHERE status = 'active'
      `).first(),

      // By product
      env.DB.prepare(`
        SELECT product_id,
               COUNT(*) as sales,
               COALESCE(SUM(amount), 0) as revenue
        FROM gumroad_licenses
        WHERE status = 'active'
        GROUP BY product_id
        ORDER BY revenue DESC
        LIMIT 20
      `).all(),

      // Last N days
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as sales_count
        FROM gumroad_licenses
        WHERE status = 'active'
          AND created_at >= ?
      `).bind(since).first(),
    ]);

    return {
      all_time_revenue: totals?.total || 0,
      all_time_sales:   totals?.sales_count || 0,
      recent_revenue:   recent?.total || 0,
      recent_sales:     recent?.sales_count || 0,
      by_product:       byProduct.results || [],
      avg_order_value:
        (totals?.sales_count || 0) > 0
          ? Math.round((totals?.total || 0) / totals.sales_count)
          : 0,
    };
  } catch (err) {
    return { all_time_revenue: 0, recent_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DEFENSE PRODUCT REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate defense product sales from revenue_events
 */
export async function getDefenseProductRevenue(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [allTime, recent, topProducts] = await Promise.all([
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source IN ('defense_product', 'full_defense_pack', 'enterprise_bundle')
      `).first(),

      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source IN ('defense_product', 'full_defense_pack', 'enterprise_bundle')
          AND created_at >= ?
      `).bind(since).first(),

      env.DB.prepare(`
        SELECT metadata,
               COALESCE(SUM(amount), 0) as revenue,
               COUNT(*) as sales
        FROM revenue_events
        WHERE source IN ('defense_product', 'full_defense_pack', 'enterprise_bundle')
        GROUP BY metadata
        ORDER BY revenue DESC
        LIMIT 10
      `).all(),
    ]);

    // Catalog potential (how much we COULD make per CVE)
    const catalogPotential = Object.values(DEFENSE_PRICING).reduce((a, b) => a + b, 0);

    return {
      all_time_revenue: allTime?.total || 0,
      all_time_sales:   allTime?.count || 0,
      recent_revenue:   recent?.total || 0,
      recent_sales:     recent?.count || 0,
      top_products:     topProducts.results || [],
      catalog_potential_per_cve: catalogPotential,
      pricing:          DEFENSE_PRICING,
    };
  } catch (err) {
    return { all_time_revenue: 0, recent_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. API CREDIT REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate API usage billing / overage revenue
 */
export async function getApiCreditRevenue(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [allTime, recent, byEndpoint] = await Promise.all([
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'api_credits'
      `).first(),

      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'api_credits'
          AND created_at >= ?
      `).bind(since).first(),

      // API usage volume by endpoint
      env.DB.prepare(`
        SELECT endpoint,
               SUM(weight) as total_weight,
               COUNT(*) as calls
        FROM api_usage_log
        WHERE logged_at >= ?
        GROUP BY endpoint
        ORDER BY total_weight DESC
        LIMIT 10
      `).bind(since).all(),
    ]);

    return {
      all_time_revenue: allTime?.total || 0,
      all_time_events:  allTime?.count || 0,
      recent_revenue:   recent?.total  || 0,
      recent_events:    recent?.count  || 0,
      top_endpoints:    byEndpoint.results || [],
    };
  } catch (err) {
    return { all_time_revenue: 0, recent_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. AFFILIATE REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate affiliate click tracking & estimated earnings
 */
export async function getAffiliateRevenue(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [allClicks, recentClicks, byProgram, conversions] = await Promise.all([
      env.DB.prepare(`
        SELECT COUNT(*) as total_clicks
        FROM affiliate_clicks
      `).first(),

      env.DB.prepare(`
        SELECT COUNT(*) as total_clicks
        FROM affiliate_clicks
        WHERE clicked_at >= ?
      `).bind(since).first(),

      env.DB.prepare(`
        SELECT program,
               COUNT(*) as clicks,
               COALESCE(SUM(estimated_commission), 0) as est_commission
        FROM affiliate_clicks
        GROUP BY program
        ORDER BY clicks DESC
      `).all(),

      // Actual confirmed commissions from revenue_events
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as confirmed,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'affiliate'
          AND created_at >= ?
      `).bind(since).first(),
    ]);

    // Estimate revenue from clicks (CPC model)
    const programs = byProgram.results || [];
    let estimatedRevenue = 0;
    for (const p of programs) {
      const cpc = AFFILIATE_EST_CPC[p.program?.toLowerCase()] || AFFILIATE_EST_CPC.default;
      estimatedRevenue += (p.clicks || 0) * cpc * 0.05; // ~5% conversion est
    }

    return {
      all_time_clicks:        allClicks?.total_clicks || 0,
      recent_clicks:          recentClicks?.total_clicks || 0,
      confirmed_revenue:      conversions?.confirmed || 0,
      confirmed_count:        conversions?.count || 0,
      estimated_revenue:      Math.round(estimatedRevenue),
      total_revenue:          (conversions?.confirmed || 0) + Math.round(estimatedRevenue),
      by_program:             programs,
      commission_rates:       AFFILIATE_EST_CPC,
    };
  } catch (err) {
    return { all_time_clicks: 0, confirmed_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ADSENSE REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate AdSense impressions / estimated revenue
 */
export async function getAdSenseRevenue(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [allTime, recent, byUnit] = await Promise.all([
      env.DB.prepare(`
        SELECT COALESCE(SUM(impressions), 0) as impressions,
               COALESCE(SUM(clicks), 0) as clicks,
               COALESCE(SUM(estimated_revenue), 0) as revenue
        FROM adsense_events
      `).first(),

      env.DB.prepare(`
        SELECT COALESCE(SUM(impressions), 0) as impressions,
               COALESCE(SUM(clicks), 0) as clicks,
               COALESCE(SUM(estimated_revenue), 0) as revenue
        FROM adsense_events
        WHERE recorded_at >= ?
      `).bind(since).first(),

      env.DB.prepare(`
        SELECT ad_unit,
               SUM(impressions) as impressions,
               SUM(clicks) as clicks,
               COALESCE(SUM(estimated_revenue), 0) as revenue
        FROM adsense_events
        WHERE recorded_at >= ?
        GROUP BY ad_unit
        ORDER BY revenue DESC
      `).bind(since).all(),
    ]);

    // Estimate from impressions if no real data yet
    const estimatedFromImpressions = Math.round(
      ((recent?.impressions || 0) / 1000) * ADSENSE_EST_CPM
    );

    return {
      all_time_impressions: allTime?.impressions || 0,
      all_time_clicks:      allTime?.clicks || 0,
      all_time_revenue:     allTime?.revenue || 0,
      recent_impressions:   recent?.impressions || 0,
      recent_clicks:        recent?.clicks || 0,
      recent_revenue:       recent?.revenue || estimatedFromImpressions,
      by_unit:              byUnit.results || [],
      est_cpm_inr:          ADSENSE_EST_CPM,
    };
  } catch (err) {
    return { all_time_revenue: 0, recent_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. REPORT SALES REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate paid report download sales
 */
export async function getReportRevenue(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [allTime, recent, byTier] = await Promise.all([
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'report_purchase'
      `).first(),

      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'report_purchase'
          AND created_at >= ?
      `).bind(since).first(),

      env.DB.prepare(`
        SELECT metadata as tier,
               COUNT(*) as sales,
               COALESCE(SUM(amount), 0) as revenue
        FROM revenue_events
        WHERE source = 'report_purchase'
        GROUP BY metadata
        ORDER BY revenue DESC
      `).all(),
    ]);

    return {
      all_time_revenue: allTime?.total || 0,
      all_time_sales:   allTime?.count || 0,
      recent_revenue:   recent?.total  || 0,
      recent_sales:     recent?.count  || 0,
      by_tier:          byTier.results || [],
      pricing:          REPORT_PRICING,
    };
  } catch (err) {
    return { all_time_revenue: 0, recent_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. ENTERPRISE DEAL REVENUE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Track enterprise custom deals / retainers
 */
export async function getEnterpriseRevenue(env, days = 90) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [allTime, recent, active] = await Promise.all([
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'enterprise_deal'
      `).first(),

      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total,
               COUNT(*) as count
        FROM revenue_events
        WHERE source = 'enterprise_deal'
          AND created_at >= ?
      `).bind(since).first(),

      // Active enterprise subscribers
      env.DB.prepare(`
        SELECT COUNT(*) as n
        FROM leads
        WHERE is_enterprise = 1 AND plan = 'enterprise' AND status = 'active'
      `).first(),
    ]);

    return {
      all_time_revenue:    allTime?.total || 0,
      all_time_deals:      allTime?.count || 0,
      recent_revenue:      recent?.total  || 0,
      recent_deals:        recent?.count  || 0,
      active_enterprise:   active?.n || 0,
      avg_deal_size:       (allTime?.count || 0) > 0
        ? Math.round((allTime?.total || 0) / allTime.count)
        : 0,
    };
  } catch (err) {
    return { all_time_revenue: 0, recent_revenue: 0, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. USER LIFETIME VALUE (LTV)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute LTV per user segment
 */
export async function computeUserLTV(env) {
  try {
    const [avgSub, avgReports, avgProducts] = await Promise.all([
      // Average subscription tenure (months)
      env.DB.prepare(`
        SELECT plan,
               AVG(CAST(
                 (julianday('now') - julianday(created_at)) / 30.0
               AS INTEGER)) as avg_months
        FROM leads
        WHERE plan != 'free'
        GROUP BY plan
      `).all(),

      // Avg reports per paying user
      env.DB.prepare(`
        SELECT COUNT(*) * 1.0 /
               NULLIF((SELECT COUNT(*) FROM leads WHERE plan != 'free'), 0) as avg_reports
        FROM revenue_events
        WHERE source = 'report_purchase'
      `).first(),

      // Avg products per paying user
      env.DB.prepare(`
        SELECT COUNT(*) * 1.0 /
               NULLIF((SELECT COUNT(*) FROM leads WHERE plan != 'free'), 0) as avg_products
        FROM revenue_events
        WHERE source IN ('defense_product', 'full_defense_pack', 'gumroad')
      `).first(),
    ]);

    const ltvByPlan = {};
    for (const row of (avgSub.results || [])) {
      const months = row.avg_months || 6;
      const mrr    = PLAN_PRICING[row.plan] || 0;
      const reportLTV   = (avgReports?.avg_reports || 0) * REPORT_PRICING.standard;
      const productLTV  = (avgProducts?.avg_products || 0) * DEFENSE_PRICING.full_defense_pack;
      ltvByPlan[row.plan] = {
        avg_tenure_months: months,
        subscription_ltv:  mrr * months,
        report_ltv:        Math.round(reportLTV),
        product_ltv:       Math.round(productLTV),
        total_ltv:         Math.round((mrr * months) + reportLTV + productLTV),
      };
    }

    return { by_plan: ltvByPlan };
  } catch (err) {
    return { by_plan: {}, error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. FUNNEL METRICS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute full conversion funnel: Visitor → Scan → Email → Product → Paid
 */
export async function getFunnelMetrics(env, days = 30) {
  try {
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const stages = ['visit', 'scan_start', 'scan_done', 'email_capture', 'product_view', 'checkout_start', 'purchase'];

    const stageRows = await env.DB.prepare(`
      SELECT stage, COUNT(*) as count
      FROM funnel_events
      WHERE created_at >= ?
      GROUP BY stage
    `).bind(since).all();

    const stageCounts = {};
    for (const row of (stageRows.results || [])) {
      stageCounts[row.stage] = row.count;
    }

    const funnel = stages.map((stage, idx) => {
      const count    = stageCounts[stage] || 0;
      const prev     = idx > 0 ? (stageCounts[stages[idx - 1]] || 0) : count;
      const dropRate = prev > 0 ? ((1 - count / prev) * 100).toFixed(1) : '0.0';

      return {
        stage,
        count,
        drop_rate_pct: `${dropRate}%`,
      };
    });

    const visitors  = stageCounts['visit'] || 1; // avoid div/0
    const purchases = stageCounts['purchase'] || 0;
    const overall   = ((purchases / visitors) * 100).toFixed(2);

    return {
      funnel,
      overall_conversion_pct: `${overall}%`,
      total_visitors:         stageCounts['visit'] || 0,
      total_purchases:        purchases,
      window_days:            days,
    };
  } catch (err) {
    return { funnel: [], overall_conversion_pct: '0%', error: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. MASTER REVENUE AGGREGATOR  ← THE CORE FUNCTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aggregate ALL revenue sources into a single unified dashboard object.
 *
 * @param {object} env      — Cloudflare Worker env (DB, KV, etc.)
 * @param {object} options
 * @param {number} options.days     — lookback window for recent data (default 30)
 * @param {boolean} options.detailed — include per-stream detail (default true)
 *
 * @returns {object} Complete revenue dashboard
 */
export async function aggregateAllRevenue(env, { days = 30, detailed = true } = {}) {
  const startedAt = Date.now();

  // ── Fetch all streams in parallel ─────────────────────────────────────────
  const [
    subscriptions,
    gumroad,
    defenseProducts,
    apiCredits,
    affiliate,
    adsense,
    reports,
    enterprise,
    ltv,
    funnel,
  ] = await Promise.all([
    getSubscriptionRevenue(env),
    getGumroadRevenue(env, days),
    getDefenseProductRevenue(env, days),
    getApiCreditRevenue(env, days),
    getAffiliateRevenue(env, days),
    getAdSenseRevenue(env, days),
    getReportRevenue(env, days),
    getEnterpriseRevenue(env, days),
    computeUserLTV(env),
    getFunnelMetrics(env, days),
  ]);

  // ── Calculate totals ───────────────────────────────────────────────────────
  const revenueBySource = {
    subscriptions:    subscriptions.recent_30d    || subscriptions.mrr    || 0,
    gumroad:          gumroad.recent_revenue       || 0,
    defense_products: defenseProducts.recent_revenue || 0,
    api_credits:      apiCredits.recent_revenue    || 0,
    affiliate:        affiliate.confirmed_revenue  || affiliate.estimated_revenue || 0,
    adsense:          adsense.recent_revenue       || 0,
    reports:          reports.recent_revenue       || 0,
    enterprise:       enterprise.recent_revenue    || 0,
  };

  const totalRecentRevenue = Object.values(revenueBySource).reduce((a, b) => a + b, 0);

  const allTimeRevenue = {
    subscriptions:    subscriptions.arr || (subscriptions.mrr * 12) || 0,
    gumroad:          gumroad.all_time_revenue       || 0,
    defense_products: defenseProducts.all_time_revenue || 0,
    api_credits:      apiCredits.all_time_revenue    || 0,
    affiliate:        affiliate.confirmed_revenue    || 0,
    adsense:          adsense.all_time_revenue       || 0,
    reports:          reports.all_time_revenue       || 0,
    enterprise:       enterprise.all_time_revenue    || 0,
  };
  const totalAllTimeRevenue = Object.values(allTimeRevenue).reduce((a, b) => a + b, 0);

  // ── Revenue share breakdown ────────────────────────────────────────────────
  const revenueShare = {};
  for (const [source, amount] of Object.entries(revenueBySource)) {
    revenueShare[source] = totalRecentRevenue > 0
      ? `${((amount / totalRecentRevenue) * 100).toFixed(1)}%`
      : '0%';
  }

  // ── MRR metrics ───────────────────────────────────────────────────────────
  const mrr          = subscriptions.mrr || 0;
  const arr          = mrr * 12;
  const mrrGrowth    = subscriptions.net_mrr_growth || 0;

  // ── Top revenue stream ─────────────────────────────────────────────────────
  const topStream = Object.entries(revenueBySource)
    .sort(([, a], [, b]) => b - a)[0];

  // ── Conversion metrics ─────────────────────────────────────────────────────
  const conversionRate = funnel.overall_conversion_pct || '0%';
  const totalVisitors  = funnel.total_visitors || 0;
  const totalBuyers    = funnel.total_purchases || 0;

  // ── ARPU (Average Revenue Per User) ───────────────────────────────────────
  const totalSubscribers = Object.values(subscriptions.by_plan || {})
    .reduce((a, p) => a + (p.subscribers || 0), 0);
  const arpu = totalSubscribers > 0
    ? Math.round(totalRecentRevenue / totalSubscribers)
    : 0;

  // ── Build final response ───────────────────────────────────────────────────
  const result = {
    // ── Summary KPIs ────────────────────────────────────────────────────────
    kpis: {
      total_revenue_recent:  totalRecentRevenue,
      total_revenue_all_time: totalAllTimeRevenue,
      mrr,
      arr,
      mrr_growth:            mrrGrowth,
      arpu,
      conversion_rate:       conversionRate,
      total_visitors:        totalVisitors,
      total_buyers:          totalBuyers,
      top_revenue_stream:    topStream ? topStream[0] : 'none',
      top_stream_amount:     topStream ? topStream[1] : 0,
      window_days:           days,
    },

    // ── Revenue breakdown ────────────────────────────────────────────────────
    revenue_by_source: revenueBySource,
    revenue_share:     revenueShare,
    all_time_by_source: allTimeRevenue,

    // ── Funnel ───────────────────────────────────────────────────────────────
    funnel,

    // ── LTV ──────────────────────────────────────────────────────────────────
    user_ltv: ltv,

    // ── Recommendations ──────────────────────────────────────────────────────
    recommendations: generateRevenueRecommendations({
      subscriptions,
      gumroad,
      defenseProducts,
      apiCredits,
      affiliate,
      adsense,
      revenueBySource,
      mrr,
      conversionRate,
    }),

    // ── Detailed breakdown (optional) ────────────────────────────────────────
    ...(detailed ? {
      detail: {
        subscriptions,
        gumroad,
        defense_products: defenseProducts,
        api_credits:      apiCredits,
        affiliate,
        adsense,
        reports,
        enterprise,
      },
    } : {}),

    // ── Meta ─────────────────────────────────────────────────────────────────
    generated_at:  new Date().toISOString(),
    latency_ms:    Date.now() - startedAt,
  };

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. REVENUE RECOMMENDATIONS ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate actionable revenue recommendations based on current metrics
 */
function generateRevenueRecommendations(data) {
  const recs = [];

  const {
    subscriptions, gumroad, defenseProducts, apiCredits,
    affiliate, adsense, revenueBySource, mrr, conversionRate,
  } = data;

  const convRate = parseFloat(conversionRate) || 0;

  // ── Subscription health ──────────────────────────────────────────────────
  if (mrr < 5000) {
    recs.push({
      priority:    'HIGH',
      category:    'subscriptions',
      title:       'Grow MRR to ₹5,000+',
      action:      'Launch a 7-day PRO trial email sequence to free users. Target users with 3+ scans.',
      impact:      '₹' + (5000 - mrr) + ' additional MRR potential',
      effort:      'LOW',
    });
  }

  if ((subscriptions.churned_30d || 0) > 2) {
    recs.push({
      priority:    'HIGH',
      category:    'subscriptions',
      title:       'Reduce churn with exit surveys + save offers',
      action:      'Trigger 50% discount popup when user clicks cancel. Follow up with re-engagement email.',
      impact:      `Recovering ${subscriptions.churned_30d} churned users = ₹${subscriptions.churned_30d * PLAN_PRICING.starter}/mo`,
      effort:      'MEDIUM',
    });
  }

  // ── Defense products opportunity ─────────────────────────────────────────
  if ((defenseProducts.recent_sales || 0) === 0) {
    recs.push({
      priority:    'HIGH',
      category:    'defense_products',
      title:       'Start selling Defense Products NOW',
      action:      'Every CVE published auto-generates ₹2,499 Full Defense Pack. Add "Get Defense Tools" CTA to scan results.',
      impact:      '₹2,499 per CVE pack sold — zero marginal cost',
      effort:      'LOW',
    });
  }

  // ── Gumroad upsell ────────────────────────────────────────────────────────
  if ((gumroad.recent_sales || 0) < 5) {
    recs.push({
      priority:    'MEDIUM',
      category:    'gumroad',
      title:       'Bundle products into Gumroad mega-packs',
      action:      'Create a "Ultimate Threat Intel Bundle" on Gumroad at ₹4,999. Email existing leads.',
      impact:      '5 sales = ₹24,995 one-time revenue',
      effort:      'LOW',
    });
  }

  // ── Affiliate low clicks ──────────────────────────────────────────────────
  if ((affiliate.recent_clicks || 0) < 50) {
    recs.push({
      priority:    'MEDIUM',
      category:    'affiliate',
      title:       'Boost affiliate banner visibility',
      action:      'Add HackTheBox & TryHackMe banners to scan results page and inside CVE reports.',
      impact:      '50 clicks × 5% CR × ₹120/conv = ₹300/mo passive',
      effort:      'LOW',
    });
  }

  // ── API monetization ──────────────────────────────────────────────────────
  if ((apiCredits.recent_revenue || 0) === 0) {
    recs.push({
      priority:    'MEDIUM',
      category:    'api_credits',
      title:       'Launch public API credit system',
      action:      'Publish Threat Intel API docs. Sell API credit packs: 1000 calls = ₹499.',
      impact:      '10 customers × ₹499 = ₹4,990/mo API revenue',
      effort:      'MEDIUM',
    });
  }

  // ── Conversion rate ───────────────────────────────────────────────────────
  if (convRate < 3) {
    recs.push({
      priority:    'HIGH',
      category:    'conversion',
      title:       'Improve funnel conversion rate (currently below 3%)',
      action:      'Add urgency timer on scan results. Show "X users upgraded today" social proof.',
      impact:      '2× conversion rate = 2× all revenue streams',
      effort:      'LOW',
    });
  }

  // ── AdSense setup ─────────────────────────────────────────────────────────
  if ((adsense.all_time_impressions || 0) === 0) {
    recs.push({
      priority:    'MEDIUM',
      category:    'adsense',
      title:       'Activate AdSense publisher account',
      action:      'Replace ca-pub-XXXXXXXXXXXXXXXX with real AdSense publisher ID. Apply at adsense.google.com.',
      impact:      '10,000 monthly visitors × ₹25 CPM = ₹250/mo passive',
      effort:      'LOW',
    });
  }

  // Sort: HIGH → MEDIUM → LOW
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  recs.sort((a, b) => (order[a.priority] || 0) - (order[b.priority] || 0));

  return recs;
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. REVENUE EVENT RECORDER  — call this whenever money is made
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Record a revenue event into D1 (fire-and-forget)
 *
 * @param {object} env
 * @param {object} event
 * @param {string} event.source      — e.g. 'subscription', 'gumroad', 'defense_product'
 * @param {number} event.amount      — amount in INR
 * @param {string} [event.user_id]   — user identifier
 * @param {string} [event.email]     — user email
 * @param {string} [event.metadata]  — JSON string or descriptive string
 * @param {string} [event.payment_id]— Razorpay/Gumroad payment reference
 */
export async function recordRevenueEvent(env, event) {
  const id = crypto.randomUUID();
  try {
    await env.DB.prepare(`
      INSERT INTO revenue_events
        (id, source, amount, user_id, email, metadata, payment_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      id,
      event.source     || 'unknown',
      event.amount     || 0,
      event.user_id    || null,
      event.email      || null,
      event.metadata   || null,
      event.payment_id || null,
    ).run();
    return { success: true, id };
  } catch (err) {
    // Non-blocking — log to KV as backup
    try {
      const fallbackKey = `rev:fallback:${id}`;
      await env.SECURITY_HUB_KV?.put(
        fallbackKey,
        JSON.stringify({ ...event, id, ts: Date.now() }),
        { expirationTtl: 86400 * 7 } // keep 7 days
      );
    } catch { /* silent */ }
    return { success: false, error: err.message, id };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. QUICK REVENUE SNAPSHOT  — lightweight KPI summary for dashboards
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Ultra-fast revenue snapshot (2–3 queries only)
 * Use for header stats, real-time widgets, etc.
 */
export async function getRevenueSnapshot(env) {
  try {
    const [mrr, today, allTime] = await Promise.all([
      // MRR
      env.DB.prepare(`
        SELECT COALESCE(SUM(
          CASE plan
            WHEN 'starter'    THEN 499
            WHEN 'pro'        THEN 1499
            WHEN 'enterprise' THEN 4999
            ELSE 0
          END
        ), 0) as mrr
        FROM leads
        WHERE plan != 'free' AND status = 'active'
      `).first(),

      // Today's revenue
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total
        FROM revenue_events
        WHERE created_at >= date('now')
      `).first(),

      // All-time revenue
      env.DB.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total
        FROM revenue_events
      `).first(),
    ]);

    return {
      mrr:          mrr?.mrr       || 0,
      arr:          (mrr?.mrr || 0) * 12,
      today:        today?.total   || 0,
      all_time:     allTime?.total || 0,
      generated_at: new Date().toISOString(),
    };
  } catch (err) {
    return { mrr: 0, arr: 0, today: 0, all_time: 0, error: err.message };
  }
}
