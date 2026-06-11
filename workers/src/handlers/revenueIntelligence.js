/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * Revenue Intelligence — /api/revenue/intel/*
 *
 * Extends existing billing/subscription logic without touching it.
 * Adds: daily snapshots, MRR forecasting, cohort analysis,
 *        waterfall chart data, tier mix, churn risk signals.
 *
 * Tables: revenue_snapshots (schema_phase4.sql)
 * KV key: "revenue:forecast:{orgId}" TTL=3600
 */

const FORECAST_KV_TTL = 3600; // 1 hour

function genId() {
  return `rev_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
}

function today() { return new Date().toISOString().slice(0, 10); }

function requireAuth(authCtx)  { return authCtx?.authenticated === true; }
function requireAdmin(authCtx) { return authCtx?.role === 'admin'; }

// ─── POST /api/revenue/intel/snapshot ────────────────────────────────────────
// Admin-only: compute and persist today's revenue snapshot
export async function handleCreateSnapshot(request, env) {
  const authCtx = request.user || {};
  if (!requireAdmin(authCtx)) return Response.json({ error: 'Admin access required' }, { status: 403 });

  const orgId     = authCtx.org_id || 'default';
  const todayDate = today();

  try {
    // Aggregate subscription data from existing subscriptions table
    const [tierCounts, prevSnapshot] = await Promise.allSettled([
      (async () => {
        const r = await env.SECURITY_HUB_DB.prepare(
          `SELECT plan_type, COUNT(*) cnt FROM subscriptions
           WHERE status = 'active'
           GROUP BY plan_type`
        ).all();
        const tiers = { free: 0, pro: 0, enterprise: 0, mssp: 0 };
        for (const row of (r.results || [])) {
          const k = (row.plan_type || '').toLowerCase();
          tiers[k] = (tiers[k] || 0) + row.cnt;
        }
        return tiers;
      })(),
      env.SECURITY_HUB_DB.prepare(
        `SELECT mrr, churned_mrr, expansion_mrr, contraction_mrr, new_mrr, customer_count
         FROM revenue_snapshots
         WHERE org_id = ? AND snapshot_date < ?
         ORDER BY snapshot_date DESC LIMIT 1`
      ).bind(orgId, todayDate).first(),
    ]).then(r => r.map(x => x.status === 'fulfilled' ? x.value : null));

    const tiers = tierCounts || { free: 0, pro: 0, enterprise: 0, mssp: 0 };

    // MRR calculation from tier pricing
    const TIER_MRR = { pro: 49, enterprise: 299, mssp: 999 };
    const mrr = (tiers.pro || 0) * TIER_MRR.pro
              + (tiers.enterprise || 0) * TIER_MRR.enterprise
              + (tiers.mssp || 0) * TIER_MRR.mssp;

    const customerCount = (tiers.pro || 0) + (tiers.enterprise || 0) + (tiers.mssp || 0);
    const prevMRR = prevSnapshot?.mrr || 0;

    // Waterfall decomposition
    // Without fine-grained event data, estimate from subscription changes vs prev period
    const mrrDelta     = mrr - prevMRR;
    const expansionMrr = mrrDelta > 0 ? Math.max(0, mrrDelta * 0.7) : 0;
    const newMrr       = mrrDelta > 0 ? Math.max(0, mrrDelta * 0.3) : 0;
    const churnedMrr   = mrrDelta < 0 ? Math.abs(mrrDelta) * 0.8 : 0;
    const contraction  = mrrDelta < 0 ? Math.abs(mrrDelta) * 0.2 : 0;

    const id = genId();
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO revenue_snapshots
         (id, org_id, snapshot_date, mrr, arr, new_mrr, expansion_mrr, contraction_mrr,
          churned_mrr, net_new_mrr, customer_count, avg_revenue_per_customer,
          free_count, pro_count, enterprise_count, mssp_count, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
       ON CONFLICT(org_id, snapshot_date) DO UPDATE SET
         mrr=excluded.mrr, arr=excluded.arr, new_mrr=excluded.new_mrr,
         expansion_mrr=excluded.expansion_mrr, contraction_mrr=excluded.contraction_mrr,
         churned_mrr=excluded.churned_mrr, net_new_mrr=excluded.net_new_mrr,
         customer_count=excluded.customer_count,
         avg_revenue_per_customer=excluded.avg_revenue_per_customer,
         free_count=excluded.free_count, pro_count=excluded.pro_count,
         enterprise_count=excluded.enterprise_count, mssp_count=excluded.mssp_count`
    ).bind(
      id, orgId, todayDate,
      mrr, mrr * 12,
      newMrr, expansionMrr, contraction, churnedMrr,
      newMrr + expansionMrr - contraction - churnedMrr,
      customerCount,
      customerCount > 0 ? Math.round(mrr / customerCount) : 0,
      tiers.free || 0, tiers.pro || 0, tiers.enterprise || 0, tiers.mssp || 0
    ).run();

    // Invalidate KV forecast cache
    try {
      await env.SECURITY_HUB_KV.delete(`revenue:forecast:${orgId}`);
    } catch (_) {}

    return Response.json({
      success: true,
      snapshot: {
        date: todayDate, mrr, arr: mrr * 12,
        customer_count: customerCount,
        tier_mix: tiers,
      },
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/revenue/intel/history ──────────────────────────────────────────
// Time-series MRR data for trend charts
export async function handleRevenueHistory(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url   = new URL(request.url);
  const days  = Math.min(parseInt(url.searchParams.get('days') || '30'), 365);
  const orgId = (requireAdmin(authCtx) && url.searchParams.get('org_id'))
    ? url.searchParams.get('org_id') : (authCtx.org_id || 'default');

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT snapshot_date, mrr, arr, new_mrr, expansion_mrr, contraction_mrr,
              churned_mrr, net_new_mrr, customer_count, avg_revenue_per_customer,
              free_count, pro_count, enterprise_count, mssp_count
       FROM revenue_snapshots
       WHERE org_id = ? AND snapshot_date >= date('now', ? || ' days')
       ORDER BY snapshot_date ASC`
    ).bind(orgId, `-${days}`).all();

    return Response.json({ history: rows.results || [], days, org_id: orgId });
  } catch (e) {
    return Response.json({ error: e.message, history: [] }, { status: 500 });
  }
}

// ─── GET /api/revenue/intel/forecast ─────────────────────────────────────────
// 3-model MRR forecast: linear, conservative (0.7x), optimistic (1.3x)
export async function handleRevenueForecast(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = authCtx.org_id || 'default';
  const kvKey = `revenue:forecast:${orgId}`;

  // Try KV cache first
  try {
    const cached = await env.SECURITY_HUB_KV.get(kvKey, { type: 'json' });
    if (cached) return Response.json({ forecast: cached, source: 'cache' });
  } catch (_) {}

  try {
    // Pull last 90 days of MRR
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT snapshot_date, mrr, net_new_mrr FROM revenue_snapshots
       WHERE org_id = ? ORDER BY snapshot_date DESC LIMIT 90`
    ).bind(orgId).all();

    const history = (rows.results || []).reverse();

    if (history.length < 3) {
      return Response.json({ forecast: null, message: 'Insufficient data — run snapshots first' });
    }

    const latestMRR = history[history.length - 1]?.mrr || 0;

    // Compute average monthly growth rate from last 30 days of net_new
    const recent30 = history.slice(-30);
    const avgNetNew = recent30.reduce((acc, r) => acc + (r.net_new_mrr || 0), 0) / (recent30.length || 1);

    // Linear regression on MRR over time
    const n  = history.length;
    const xs = history.map((_, i) => i);
    const ys = history.map(r => r.mrr);
    const sumX  = xs.reduce((a, b) => a + b, 0);
    const sumY  = ys.reduce((a, b) => a + b, 0);
    const sumXY = xs.reduce((a, x, i) => a + x * ys[i], 0);
    const sumXX = xs.reduce((a, x) => a + x * x, 0);
    const slope = n * sumXY - sumX * sumY !== 0
      ? (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX)
      : avgNetNew;

    // Build 6-month projections (monthly steps)
    const months = ['M+1','M+2','M+3','M+4','M+5','M+6'];
    const linear = months.map((_, i) => Math.max(0, Math.round(latestMRR + slope * 30 * (i + 1))));
    const conservative = months.map((_, i) => Math.max(0, Math.round(latestMRR + slope * 30 * (i + 1) * 0.7)));
    const optimistic   = months.map((_, i) => Math.max(0, Math.round(latestMRR + slope * 30 * (i + 1) * 1.3)));

    // Churn risk: ratio of churned to total MRR over last 30 days
    const totalChurned = recent30.reduce((a, r) => a + Math.abs(r.net_new_mrr < 0 ? r.net_new_mrr : 0), 0);
    const churnRate    = latestMRR > 0 ? Math.round((totalChurned / latestMRR) * 100) : 0;

    const forecast = {
      current_mrr: latestMRR,
      current_arr: latestMRR * 12,
      growth_rate_daily: Math.round(slope * 100) / 100,
      avg_monthly_net_new: Math.round(avgNetNew),
      estimated_churn_pct: churnRate,
      projections: {
        labels: months,
        linear, conservative, optimistic,
      },
      six_month_linear_arr: (linear[5] || 0) * 12,
      generated_at: new Date().toISOString(),
    };

    // Cache for 1 hour
    try {
      await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(forecast), { expirationTtl: FORECAST_KV_TTL });
    } catch (_) {}

    return Response.json({ forecast, source: 'computed' });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/revenue/intel/waterfall ────────────────────────────────────────
// Monthly MRR waterfall: new / expansion / contraction / churn / net_new
export async function handleRevenueWaterfall(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = authCtx.org_id || 'default';

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT
         strftime('%Y-%m', snapshot_date) AS month,
         SUM(new_mrr)          AS new_mrr,
         SUM(expansion_mrr)    AS expansion_mrr,
         SUM(contraction_mrr)  AS contraction_mrr,
         SUM(churned_mrr)      AS churned_mrr,
         SUM(net_new_mrr)      AS net_new_mrr,
         MAX(mrr)              AS ending_mrr
       FROM revenue_snapshots
       WHERE org_id = ? AND snapshot_date >= date('now', '-6 months')
       GROUP BY month
       ORDER BY month ASC`
    ).bind(orgId).all();

    return Response.json({ waterfall: rows.results || [], org_id: orgId });
  } catch (e) {
    return Response.json({ error: e.message, waterfall: [] }, { status: 500 });
  }
}

// ─── GET /api/revenue/intel/cohorts ──────────────────────────────────────────
// Cohort analysis by plan_type — average MRR per cohort
export async function handleCohortAnalysis(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = authCtx.org_id || 'default';

  try {
    // Cohort = month the customer first subscribed
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT
         strftime('%Y-%m', created_at) AS cohort_month,
         plan_type,
         COUNT(*)                      AS customers,
         COUNT(CASE WHEN status = 'active' THEN 1 END) AS active_customers
       FROM subscriptions
       WHERE created_at >= date('now', '-12 months')
       GROUP BY cohort_month, plan_type
       ORDER BY cohort_month ASC, plan_type ASC`
    ).all();

    const TIER_MRR = { pro: 49, enterprise: 299, mssp: 999 };

    const cohorts = (rows.results || []).map(r => ({
      cohort_month: r.cohort_month,
      plan_type: r.plan_type,
      customers: r.customers,
      active_customers: r.active_customers,
      retention_pct: r.customers > 0 ? Math.round((r.active_customers / r.customers) * 100) : 0,
      cohort_mrr: (TIER_MRR[r.plan_type?.toLowerCase()] || 0) * r.active_customers,
    }));

    return Response.json({ cohorts, org_id: orgId });
  } catch (e) {
    return Response.json({ error: e.message, cohorts: [] }, { status: 500 });
  }
}

// ─── GET /api/revenue/intel/tiermix ──────────────────────────────────────────
// Current tier distribution and MRR contribution
export async function handleTierMix(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  try {
    // Get latest snapshot tier counts
    const latest = await env.SECURITY_HUB_DB.prepare(
      `SELECT free_count, pro_count, enterprise_count, mssp_count, mrr, customer_count, snapshot_date
       FROM revenue_snapshots WHERE org_id = ? ORDER BY snapshot_date DESC LIMIT 1`
    ).bind(authCtx.org_id || 'default').first();

    if (!latest) {
      return Response.json({ tier_mix: null, message: 'No revenue snapshot found' });
    }

    const TIER_MRR = { pro: 49, enterprise: 299, mssp: 999 };
    const tiers = [
      { tier: 'free',       count: latest.free_count || 0,       mrr_contribution: 0,                                         price: 0,    color: '#6b7280' },
      { tier: 'pro',        count: latest.pro_count || 0,        mrr_contribution: (latest.pro_count || 0) * TIER_MRR.pro,        price: 49,   color: '#3b82f6' },
      { tier: 'enterprise', count: latest.enterprise_count || 0, mrr_contribution: (latest.enterprise_count || 0) * TIER_MRR.enterprise, price: 299,  color: '#8b5cf6' },
      { tier: 'mssp',       count: latest.mssp_count || 0,       mrr_contribution: (latest.mssp_count || 0) * TIER_MRR.mssp,       price: 999,  color: '#f59e0b' },
    ];

    return Response.json({
      tier_mix: tiers,
      total_mrr: latest.mrr,
      total_customers: latest.customer_count,
      snapshot_date: latest.snapshot_date,
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
