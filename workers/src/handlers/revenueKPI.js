/**
 * CYBERDUDEBIVASH AI Security Hub — Revenue KPI Dashboard
 * Phase 5 P0: Measurable, Attributable, Repeatable, Scalable Revenue
 *
 * Routes (all owner-gated):
 *   GET /api/revenue/kpi             — Full KPI set: Visitors → MRR/ARR → CAC/LTV + breakdowns
 *   GET /api/revenue/funnel-analytics — Per-funnel drop-off across all 5 revenue funnels
 */

function jsonOk(data) {
  return Response.json(data, { status: 200, headers: { 'Content-Type': 'application/json' } });
}

function pct(part, total) {
  return total > 0 ? Math.round((part / total) * 100) : 0;
}

function dropOff(prev, curr) {
  return prev > 0 ? Math.round(((prev - curr) / prev) * 100) : 0;
}

/* ── GET /api/revenue/kpi ──────────────────────────────────────────────────── */
export async function handleRevenueKPI(request, env) {
  const db = env.DB || env.SECURITY_HUB_DB;
  if (!db) return jsonOk({ error: 'DB unavailable', visitors: 0, leads: {}, proposals: {}, customers: 0 });

  const url    = new URL(request.url);
  const days   = Math.min(Math.max(parseInt(url.searchParams.get('days') || '30'), 1), 365);
  const cutoff = new Date(Date.now() - days * 86400000).toISOString();
  const cutoffEpoch = Math.floor(new Date(cutoff).getTime() / 1000);
  const cutoffDate  = cutoff.slice(0, 10);

  try {
    const [
      visitorsRow,
      leadsRow,
      proposalsRow,
      customersRow,
      revenueRow,
      mrrRow,
      arrRow,
      cacRow,
      serviceRows,
      campaignRows,
      landingPageRows,
    ] = await Promise.all([
      // Visitors from funnel_events (email may be null for anonymous visitors — use DISTINCT)
      db.prepare(`SELECT COUNT(DISTINCT COALESCE(email,'__anon_'||id)) as total FROM funnel_events WHERE stage='visit' AND created_at >= ?`).bind(cutoff).first().catch(() => null),

      // Leads
      db.prepare(`
        SELECT COUNT(*) as total,
               COUNT(CASE WHEN funnel_stage = 'customer' OR converted_at IS NOT NULL THEN 1 END) as converted
        FROM leads WHERE created_at >= ?
      `).bind(cutoff).first().catch(() => null),

      // Proposals — proposals table uses INTEGER epoch for created_at
      db.prepare(`
        SELECT COUNT(*) as total,
               COUNT(CASE WHEN status IN ('sent','SENT') THEN 1 END) as sent,
               COUNT(CASE WHEN status IN ('accepted','ACCEPTED') THEN 1 END) as accepted,
               COALESCE(SUM(total_inr),0) as pipeline_value
        FROM proposals WHERE created_at >= ?
      `).bind(cutoffEpoch).first().catch(() => null),

      // Paying customers (distinct emails with successful payments)
      db.prepare(`SELECT COUNT(DISTINCT email) as total FROM payments WHERE status IN ('success','captured','paid') AND created_at >= ?`).bind(cutoff).first().catch(() => null),

      // Revenue (all confirmed payments in period)
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total, COUNT(*) as count FROM payments WHERE status IN ('success','captured','paid') AND created_at >= ?`).bind(cutoff).first().catch(() => null),

      // MRR — last 30 calendar days of confirmed payments (regardless of 'days' param)
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as monthly FROM payments WHERE status IN ('success','captured','paid') AND created_at >= date('now','-30 days')`).first().catch(() => null),

      // ARR — last 365 days / 12 (annualised monthly average)
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0)/12 as monthly_avg FROM payments WHERE status IN ('success','captured','paid') AND created_at >= date('now','-365 days')`).first().catch(() => null),

      // CAC — from cac_events (cost_inr = ad spend per conversion; 0 when organic)
      db.prepare(`
        SELECT COALESCE(AVG(NULLIF(cost_inr,0)),0) as avg_cac,
               COUNT(*) as conversions,
               COALESCE(SUM(mrr_generated),0) as attributed_revenue
        FROM cac_events WHERE converted=1 AND event_date >= ?
      `).bind(cutoffDate).first().catch(() => null),

      // Revenue by service (plan/product type)
      db.prepare(`
        SELECT COALESCE(NULLIF(TRIM(plan),''),'unknown') as service,
               COUNT(*) as transactions,
               COALESCE(SUM(amount_inr),0) as revenue_inr
        FROM payments
        WHERE status IN ('success','captured','paid') AND created_at >= ?
        GROUP BY COALESCE(NULLIF(TRIM(plan),''),'unknown')
        ORDER BY revenue_inr DESC LIMIT 10
      `).bind(cutoff).all().catch(() => ({ results: [] })),

      // Revenue by campaign (from cac_events attribution)
      db.prepare(`
        SELECT COALESCE(NULLIF(TRIM(campaign),''),'organic') as campaign,
               COUNT(*) as conversions,
               COALESCE(SUM(mrr_generated),0) as revenue_inr
        FROM cac_events WHERE converted=1 AND event_date >= ?
        GROUP BY COALESCE(NULLIF(TRIM(campaign),''),'organic')
        ORDER BY revenue_inr DESC LIMIT 10
      `).bind(cutoffDate).all().catch(() => ({ results: [] })),

      // Revenue by landing page (from analytics_events attribution tracking)
      db.prepare(`
        SELECT COALESCE(json_extract(properties_json,'$.landing_page'),'unknown') as landing_page,
               COUNT(*) as visits,
               COUNT(CASE WHEN event_type='attribution_customer' OR event_type='attribution_revenue' THEN 1 END) as conversions,
               COALESCE(SUM(CAST(json_extract(properties_json,'$.revenue_inr') AS REAL)),0) as revenue_inr
        FROM analytics_events
        WHERE event_type LIKE 'attribution_%' AND occurred_at >= ?
        GROUP BY COALESCE(json_extract(properties_json,'$.landing_page'),'unknown')
        ORDER BY revenue_inr DESC LIMIT 10
      `).bind(cutoff).all().catch(() => ({ results: [] })),
    ]);

    const totalRevenue   = revenueRow?.total || 0;
    const customers      = customersRow?.total || 0;
    const mrr            = Math.max(mrrRow?.monthly || 0, arrRow?.monthly_avg || 0);
    const arr            = mrr * 12;
    const avgOrderValue  = customers > 0 ? Math.round(totalRevenue / customers) : 0;
    const cacAvg         = Math.round(cacRow?.avg_cac || 0);
    // LTV = ARPU * (1 / monthly_churn_rate). Without churn data, assume 15% annual → 1.25% monthly
    const ltv            = mrr > 0 && customers > 0
      ? Math.round((mrr / Math.max(customers, 1)) / 0.0125)
      : avgOrderValue * 2;

    const leads      = leadsRow?.total || 0;
    const converted  = leadsRow?.converted || 0;
    const propSent   = proposalsRow?.sent || 0;
    const propAccepted = proposalsRow?.accepted || 0;

    return jsonOk({
      as_of:       new Date().toISOString(),
      period_days: days,

      visitors:    visitorsRow?.total || 0,

      leads: {
        total:          leads,
        converted:      converted,
        conversion_pct: pct(converted, leads),
      },

      proposals: {
        total:        proposalsRow?.total || 0,
        sent:         propSent,
        accepted:     propAccepted,
        win_rate_pct: pct(propAccepted, propSent),
        pipeline_inr: Math.round(proposalsRow?.pipeline_value || 0),
      },

      customers,

      revenue: {
        total_inr:     totalRevenue,
        transactions:  revenueRow?.count || 0,
        avg_order_inr: avgOrderValue,
      },

      mrr_inr: Math.round(mrr),
      arr_inr: Math.round(arr),

      cac_inr: cacAvg,
      ltv_inr: ltv,
      ltv_cac_ratio: cacAvg > 0 ? Math.round(ltv / cacAvg) : null,

      revenue_by_service:      (serviceRows?.results || []),
      revenue_by_campaign:     (campaignRows?.results || []),
      revenue_by_landing_page: (landingPageRows?.results || []),
    });
  } catch (e) {
    return jsonOk({ error: e.message, visitors: 0, leads: {}, proposals: {}, customers: 0 });
  }
}

/* ── GET /api/revenue/funnel-analytics ────────────────────────────────────── */
export async function handleFunnelAnalytics(request, env) {
  const db = env.DB || env.SECURITY_HUB_DB;
  if (!db) return jsonOk({ funnels: [] });

  const url    = new URL(request.url);
  const days   = Math.min(Math.max(parseInt(url.searchParams.get('days') || '30'), 1), 365);
  const cutoff = new Date(Date.now() - days * 86400000).toISOString();

  try {
    // Core funnel stage counts from funnel_events
    const stageKeys = ['visit', 'scan_start', 'scan_done', 'email_capture', 'product_view', 'checkout_start', 'purchase'];
    const stageCounts = await Promise.all(
      stageKeys.map(stage =>
        db.prepare(`SELECT COUNT(DISTINCT COALESCE(email,'__anon_'||id)) as cnt FROM funnel_events WHERE stage=? AND created_at >= ?`)
          .bind(stage, cutoff).first().catch(() => ({ cnt: 0 }))
      )
    );
    const s = {};
    stageKeys.forEach((k, i) => { s[k] = stageCounts[i]?.cnt || 0; });

    // Per-product purchase counts
    const [
      assessmentPurchases,
      aiAssessmentPurchases,
      apiSubscriptions,
      entLeads,
      entDeals,
      entWon,
      msspInquiries,
      msspPartners,
    ] = await Promise.all([
      db.prepare(`SELECT COUNT(*) as cnt FROM payments WHERE status IN ('success','captured','paid') AND (LOWER(plan) LIKE '%assessment%' OR LOWER(plan) LIKE '%scan%' OR LOWER(plan) LIKE '%security%') AND created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM payments WHERE status IN ('success','captured','paid') AND (LOWER(plan) LIKE '%ai%' OR LOWER(plan) LIKE '%intelligence%') AND created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM payments WHERE status IN ('success','captured','paid') AND LOWER(plan) IN ('starter','pro','enterprise','community','api','sentinel') AND created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM enterprise_leads WHERE created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM deal_pipeline WHERE stage IN ('qualified','demo','proposal','negotiation') AND created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM deal_pipeline WHERE stage='closed_won' AND created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM mssp_partners WHERE created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT COUNT(*) as cnt FROM mssp_partners WHERE status='active' AND created_at >= ?`).bind(cutoff).first().catch(() => ({ cnt: 0 })),
    ]);

    const ap   = assessmentPurchases?.cnt  || 0;
    const aiAp = aiAssessmentPurchases?.cnt || 0;
    const apis = apiSubscriptions?.cnt      || 0;
    const el   = entLeads?.cnt             || 0;
    const ed   = entDeals?.cnt             || 0;
    const ew   = entWon?.cnt               || 0;
    const mi   = msspInquiries?.cnt        || 0;
    const mp   = msspPartners?.cnt         || 0;

    const v  = s.visit;
    const ss = s.scan_start;
    const sd = s.scan_done;
    const ec = s.email_capture;

    function funnelStage(name, count, prevCount) {
      return {
        stage:       name,
        count,
        conversion_from_top: pct(count, v),
        conversion_from_prev: pct(count, prevCount),
        drop_off_pct: dropOff(prevCount, count),
      };
    }

    const funnels = [
      {
        id:   'security_assessment',
        name: 'Security Assessment',
        stages: [
          { stage: 'Visitors',            count: v,  conversion_from_top: 100, conversion_from_prev: 100, drop_off_pct: 0 },
          funnelStage('Scan Started',     ss, v),
          funnelStage('Scan Completed',   sd, ss),
          funnelStage('Email Captured',   ec, sd),
          funnelStage('Purchased',        ap, ec),
        ],
        overall_conversion_pct: pct(ap, v),
        purchases: ap,
      },
      {
        id:   'ai_security_assessment',
        name: 'AI Security Assessment',
        stages: [
          { stage: 'Visitors',            count: v,   conversion_from_top: 100, conversion_from_prev: 100, drop_off_pct: 0 },
          funnelStage('Scan Started',     ss,   v),
          funnelStage('Scan Completed',   sd,   ss),
          funnelStage('Email Captured',   ec,   sd),
          funnelStage('AI Assessment Purchased', aiAp, ec),
        ],
        overall_conversion_pct: pct(aiAp, v),
        purchases: aiAp,
      },
      {
        id:   'api_subscription',
        name: 'API / Subscription',
        stages: [
          { stage: 'Visitors',            count: v,   conversion_from_top: 100, conversion_from_prev: 100, drop_off_pct: 0 },
          funnelStage('Product Viewed',   s.product_view,    v),
          funnelStage('Checkout Started', s.checkout_start,  s.product_view),
          funnelStage('Subscribed',       apis,              s.checkout_start),
        ],
        overall_conversion_pct: pct(apis, v),
        purchases: apis,
      },
      {
        id:   'enterprise',
        name: 'Enterprise Sales',
        stages: [
          { stage: 'Visitors',            count: v,   conversion_from_top: 100, conversion_from_prev: 100, drop_off_pct: 0 },
          funnelStage('Inquiry / Lead',   el,   v),
          funnelStage('Qualified Deal',   ed,   el),
          funnelStage('Closed Won',       ew,   ed),
        ],
        overall_conversion_pct: pct(ew, v),
        purchases: ew,
      },
      {
        id:   'mssp',
        name: 'MSSP Partner',
        stages: [
          { stage: 'Visitors',            count: v,   conversion_from_top: 100, conversion_from_prev: 100, drop_off_pct: 0 },
          funnelStage('MSSP Inquiry',     mi, v),
          funnelStage('Active Partner',   mp, mi),
        ],
        overall_conversion_pct: pct(mp, v),
        purchases: mp,
      },
    ];

    return jsonOk({
      as_of:       new Date().toISOString(),
      period_days: days,
      funnels,
      summary: {
        total_visitors:  v,
        total_purchases: ap + aiAp + apis + ew + mp,
        blended_conversion_pct: pct(ap + aiAp + apis + ew + mp, v),
      },
    });
  } catch (e) {
    return jsonOk({ funnels: [], error: e.message });
  }
}
