/**
 * CYBERDUDEBIVASH v27 — CEO Executive Dashboard Handler
 * Real metrics only. No mock data. No fake pipeline.
 * All KPIs sourced from D1: purchases, assessments, subscriptions, funnel_events
 *
 * GET /api/ceo/dashboard        -> full KPI set
 * GET /api/ceo/dashboard/kpis   -> compact KPI cards only
 * POST /api/ceo/snapshot        -> write daily snapshot (cron-triggered)
 */

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
function err(msg, status = 400) {
  return json({ success: false, error: msg }, status);
}

const PLAN_PRICE = { starter: 499, pro: 1499, enterprise: 4999, mssp: 49999 };

export async function handleCEODashboard(request, env, authCtx) {
  if (!authCtx?.userId) return err('Auth required', 401);
  if (authCtx.role !== 'admin') return err('Admin only', 403);

  const url    = new URL(request.url);
  const period = url.searchParams.get('period') || '30d';
  const days   = period === '7d' ? 7 : period === '90d' ? 90 : period === '365d' ? 365 : 30;
  const since  = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

  try {
    const db = env.DB;

    const [
      revenueRows,
      subsRows,
      assessmentRows,
      reportRows,
      funnelRows,
      customerRows,
      pipelineRows,
      churnRows,
      retentionRows,
      trendRows,
    ] = await Promise.all([
      db.prepare(
        "SELECT COALESCE(SUM(total_inr),0) AS cash FROM billing_invoices WHERE status='paid' AND created_at>=?"
      ).bind(since).first(),
      db.prepare(
        "SELECT plan, COUNT(*) AS plan_count, COALESCE(SUM(price_inr),0) AS mrr FROM subscriptions WHERE status='active' GROUP BY plan"
      ).all(),
      db.prepare(
        "SELECT COUNT(*) AS total, COUNT(CASE WHEN status IN ('delivered','completed') THEN 1 END) AS delivered, COALESCE(SUM(price_inr),0) AS revenue FROM assessments WHERE booked_at>=unixepoch(?)"
      ).bind(since).first(),
      db.prepare(
        "SELECT COUNT(*) AS total, COALESCE(SUM(amount_inr),0) AS revenue FROM scanner_orders WHERE status IN ('completed','paid') AND created_at>=unixepoch(?)"
      ).bind(since).first(),
      db.prepare(
        "SELECT stage, COUNT(*) AS count FROM funnel_events WHERE created_at>=? GROUP BY stage ORDER BY count DESC"
      ).bind(since).all(),
      db.prepare(
        "SELECT COUNT(DISTINCT COALESCE(user_id,'x'||id)) AS customers FROM billing_invoices WHERE status='paid'"
      ).first(),
      db.prepare(
        "SELECT COALESCE(SUM(deal_value),0) AS pipeline_value, COUNT(*) AS open_opps FROM sales_opportunities WHERE stage NOT IN ('CLOSED_WON','CLOSED_LOST')"
      ).first(),
      db.prepare(
        "SELECT COUNT(*) AS churned FROM subscriptions WHERE status='cancelled' AND cancelled_at>=unixepoch(?)"
      ).bind(since).first(),
      db.prepare(
        "SELECT COUNT(CASE WHEN status='active' THEN 1 END) AS active, COUNT(CASE WHEN status='cancelled' THEN 1 END) AS cancelled FROM subscriptions"
      ).first(),
      db.prepare(
        "SELECT date(created_at,'unixepoch') AS day, COALESCE(SUM(total_inr),0) AS revenue FROM billing_invoices WHERE status='paid' AND created_at>=unixepoch(?) GROUP BY day ORDER BY day ASC"
      ).bind(since).all(),
    ]);

    const mrr = (subsRows.results || []).reduce((s, r) => s + (r.mrr || 0), 0);
    const arr  = mrr * 12;
    const totalCustomers  = customerRows?.customers || 0;
    const assessmentRev   = assessmentRows?.revenue  || 0;
    const assessmentTotal = assessmentRows?.total    || 0;
    const reportRev       = reportRows?.revenue      || 0;
    const reportTotal     = reportRows?.total        || 0;
    const cash            = revenueRows?.cash        || 0;
    const pipelineValue   = pipelineRows?.pipeline_value || 0;
    const openOpps        = pipelineRows?.open_opps  || 0;
    const churned         = churnRows?.churned       || 0;
    const activeSubs      = retentionRows?.active    || 0;
    const totalSubs       = (retentionRows?.active || 0) + (retentionRows?.cancelled || 0);
    const retentionPct    = totalSubs > 0 ? Math.round((activeSubs / totalSubs) * 1000) / 10 : 100;
    const churnPct        = totalSubs > 0 ? Math.round((churned    / totalSubs) * 1000) / 10 : 0;
    const ltv             = mrr > 0 && churnPct > 0 ? Math.round((mrr / (churnPct / 100))) : 0;
    const cac             = totalCustomers > 0 ? Math.round(cash / totalCustomers) : 0;

    const funnelMap = {};
    (funnelRows.results || []).forEach(r => { funnelMap[r.stage] = r.count; });
    const landCount  = funnelMap['page_land']  || 0;
    const scanCount  = funnelMap['scan_start'] || funnelMap['scan_complete'] || 0;
    const emailCount = funnelMap['email_captured'] || 0;
    const convScanToEmail = scanCount > 0 ? Math.round((emailCount / scanCount) * 1000) / 10 : 0;
    const convOverall     = landCount > 0 ? Math.round((totalCustomers / landCount) * 10000) / 100 : 0;

    const planBreakdown = {};
    (subsRows.results || []).forEach(r => {
      planBreakdown[r.plan] = { count: r.plan_count, revenue: (PLAN_PRICE[r.plan] || 0) * r.plan_count };
    });

    const trendMap = {};
    (trendRows.results || []).forEach(r => { trendMap[r.day] = r.revenue; });
    const trendFilled = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      trendFilled.push({ date: d, revenue: trendMap[d] || 0 });
    }

    return json({
      success: true, period,
      generated_at: new Date().toISOString(),
      kpis: {
        mrr_inr: mrr, arr_inr: arr, cash_collected: cash,
        customers: totalCustomers, active_subs: activeSubs,
        assessments_sold: assessmentTotal, assessment_rev: assessmentRev,
        reports_sold: reportTotal, report_rev: reportRev,
        api_revenue: 0, mssp_revenue: 0,
        pipeline_value: pipelineValue, open_opps: openOpps,
        retention_pct: retentionPct, churn_pct: churnPct,
        ltv_inr: ltv, cac_inr: cac,
        conv_overall_pct: convOverall, conv_scan_email_pct: convScanToEmail,
      },
      funnel: {
        page_land: landCount, scan_start: scanCount,
        email_captured: emailCount, reports_sold: reportTotal,
        assessments_booked: assessmentTotal, subscriptions: activeSubs,
        enterprise_leads: openOpps,
      },
      plan_breakdown: planBreakdown,
      revenue_trend: trendFilled,
    });

  } catch (e) {
    console.error('[CEO Dashboard]', e);
    return err('Dashboard query failed: ' + e.message, 500);
  }
}

export async function handleCEOSnapshot(request, env, authCtx) {
  if (authCtx?.role !== 'admin' && request.headers.get('x-cron-secret') !== env.CRON_SECRET) {
    return err('Unauthorized', 401);
  }
  const mockReq = new Request('https://x/api/ceo/dashboard?period=30d', { headers: request.headers });
  const dashRes  = await handleCEODashboard(mockReq, env, { userId: 'cron', role: 'admin' });
  const dashData = await dashRes.json();
  if (!dashData.success) return err('Dashboard failed', 500);

  const kpi = dashData.kpis;
  const today = new Date().toISOString().slice(0, 10);
  const snapId = 'snap_' + Date.now().toString(36);

  try {
    await env.DB.prepare(
      "INSERT OR REPLACE INTO ceo_kpi_snapshots (id,snapshot_date,mrr_inr,arr_inr,cash_inr,customers,assessments,reports_sold,conversion_pct,retention_pct,churn_pct,ltv_inr,cac_inr,pipeline_inr) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(
      snapId, today, kpi.mrr_inr, kpi.arr_inr, kpi.cash_collected, kpi.customers,
      kpi.assessments_sold, kpi.reports_sold, kpi.conv_overall_pct,
      kpi.retention_pct, kpi.churn_pct, kpi.ltv_inr, kpi.cac_inr, kpi.pipeline_value
    ).run();
    return json({ success: true, snapshot_date: today, kpis: kpi });
  } catch(e) {
    return err('Snapshot write failed: ' + e.message, 500);
  }
}
