/**
 * CYBERDUDEBIVASH® AI Security Hub
 * /api/revenue/metrics — Executive Revenue Dashboard
 *
 * Aggregates from EXISTING D1 tables (subscriptions, payments, users, assessments).
 * Zero new tables read. Cached in KV for 5 minutes.
 * Requires: admin | mssp_admin | enterprise role
 */

const CACHE_KEY = 'revenue_metrics_v2';
const CACHE_TTL = 300; // 5 minutes

export async function handleRevenueMetrics(request, env, authCtx) {
  // Role gate: admin, mssp_admin, or enterprise tier
  const allowed = ['admin', 'mssp_admin', 'enterprise'];
  if (!authCtx?.isAdmin && !['ENTERPRISE', 'MSSP'].includes((authCtx?.tier || '').toUpperCase())) {
    return Response.json({ error: 'Enterprise tier required', code: 403 }, { status: 403 });
  }

  // KV cache check
  try {
    const cached = await env.SECURITY_HUB_KV.get(CACHE_KEY, { type: 'json' });
    if (cached) return Response.json({ success: true, cached: true, ...cached });
  } catch (_) {}

  const db = env.SECURITY_HUB_DB;
  const metrics = await buildRevenueMetrics(db);

  // Cache result
  try {
    await env.SECURITY_HUB_KV.put(CACHE_KEY, JSON.stringify(metrics), { expirationTtl: CACHE_TTL });
  } catch (_) {}

  return Response.json({ success: true, cached: false, ...metrics });
}

async function buildRevenueMetrics(db) {
  const now = new Date();
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString();
  const twelveMonthsAgo = new Date(now.getFullYear() - 1, now.getMonth(), 1).toISOString();

  // ── Plan counts from users.tier ──────────────────────────────────────────
  // FIX (2026-07-06 revenue-mechanisms audit): this queried a `users.plan`
  // column with lowercase values ('pro','enterprise') that has never existed
  // — the real, live schema (workers/schema_bootstrap.sql) is `users.tier`
  // with uppercase values ('FREE','STARTER','PRO','ENTERPRISE','MSSP'), the
  // exact column /api/payment/verify actually writes on a real purchase
  // (handlers/payments.js handleVerifyPayment). The old query threw on every
  // call, was silently swallowed by the catch below, and left pro/enterprise
  // counts at 0 forever — this dashboard would report ₹0 MRR even with real
  // paying customers. STARTER and MSSP tiers were also never counted at all.
  let planCounts = { free: 0, starter: 0, pro: 0, enterprise: 0, mssp: 0, total: 0 };
  let newThisMonth = 0;
  let churnedThisMonth = 0;

  try {
    const subQuery = await db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN tier = 'FREE'       OR tier IS NULL THEN 1 ELSE 0 END) as free_count,
        SUM(CASE WHEN tier = 'STARTER'    THEN 1 ELSE 0 END) as starter_count,
        SUM(CASE WHEN tier = 'PRO'        THEN 1 ELSE 0 END) as pro_count,
        SUM(CASE WHEN tier = 'ENTERPRISE' THEN 1 ELSE 0 END) as ent_count,
        SUM(CASE WHEN tier = 'MSSP'       THEN 1 ELSE 0 END) as mssp_count
      FROM users
      WHERE status = 'active' OR status IS NULL
    `).first();

    if (subQuery) {
      planCounts.free       = subQuery.free_count    || 0;
      planCounts.starter    = subQuery.starter_count || 0;
      planCounts.pro        = subQuery.pro_count     || 0;
      planCounts.enterprise = subQuery.ent_count     || 0;
      planCounts.mssp       = subQuery.mssp_count    || 0;
      planCounts.total      = subQuery.total         || 0;
    }
  } catch (_) {
    // users table might have different schema — use safe defaults
    try {
      const countQ = await db.prepare('SELECT COUNT(*) as total FROM users').first();
      planCounts.total = countQ?.total || 0;
    } catch (_2) {}
  }

  // ── New subscribers this month ─────────────────────────────────────────
  try {
    const newQ = await db.prepare(
      `SELECT COUNT(*) as cnt FROM users WHERE created_at >= ? AND tier IN ('STARTER','PRO','ENTERPRISE','MSSP')`
    ).bind(startOfMonth).first();
    newThisMonth = newQ?.cnt || 0;
  } catch (_) {}

  // ── MRR calculation — canonical INR pricing (from subscriptionPaywallEngine.js SSOT)
  // STARTER: ₹499  PRO: ₹1,499  ENTERPRISE: ₹4,999  MSSP: ₹9,999
  const STARTER_PRICE_INR    = 499;
  const PRO_PRICE_INR        = 1499;
  const ENTERPRISE_PRICE_INR = 4999;
  const MSSP_PRICE_INR       = 9999;
  const mrr_inr  = planCounts.starter    * STARTER_PRICE_INR
                 + planCounts.pro        * PRO_PRICE_INR
                 + planCounts.enterprise * ENTERPRISE_PRICE_INR
                 + planCounts.mssp       * MSSP_PRICE_INR;
  // Keep legacy _cents fields as INR paise for any callers that divide by 100
  const mrr_cents  = mrr_inr * 100;
  const arr_cents  = mrr_cents * 12;
  const paying     = planCounts.starter + planCounts.pro + planCounts.enterprise + planCounts.mssp;
  const arpu_cents = paying > 0 ? Math.round(mrr_cents / paying) : 0;

  // ── Conversion rates ────────────────────────────────────────────────────
  const convFreeToAny     = planCounts.total > 0 ? ((paying / planCounts.total) * 100).toFixed(1) : '0.0';
  const convProToEnterprise = planCounts.pro > 0 ? ((planCounts.enterprise / planCounts.pro) * 100).toFixed(1) : '0.0';

  // ── Assessment pipeline ─────────────────────────────────────────────────
  let pipelineValue = 0;
  let assessmentsBooked = 0;
  let assessmentsCompleted = 0;

  try {
    const asmQ = await db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'scheduled' OR status = 'confirmed' THEN 1 ELSE 0 END) as booked
      FROM assessments
    `).first();
    if (asmQ) {
      assessmentsBooked    = asmQ.booked    || 0;
      assessmentsCompleted = asmQ.completed || 0;
      // Estimate pipeline: booked assessments × avg assessment value ($2,500)
      pipelineValue = assessmentsBooked * 250000; // cents
    }
  } catch (_) {}

  // ── Actual revenue collected: today / this week / this month ────────────
  // Distinct from MRR above (recurring subscription run-rate, derived from
  // tier counts) — this is real cash collected via /api/payment/verify,
  // same `payments` table/columns handlers/revenueOps.js already reads.
  // frontend/revenue-command-center.html's KPI tiles read these exact
  // field names (d.today/d.week/d.month) and previously had nothing to
  // read at all, always rendering ₹0.
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

  let revenueToday = 0, revenueWeek = 0, revenueMonth = 0;
  try {
    const [todayQ, weekQ, monthQ] = await Promise.all([
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM payments WHERE status='success' AND created_at >= ?`).bind(startOfToday).first(),
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM payments WHERE status='success' AND created_at >= ?`).bind(sevenDaysAgo).first(),
      db.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM payments WHERE status='success' AND created_at >= ?`).bind(startOfMonth).first(),
    ]);
    revenueToday = todayQ?.total || 0;
    revenueWeek  = weekQ?.total  || 0;
    revenueMonth = monthQ?.total || 0;
  } catch (_) {}

  // ── Monthly trend (last 12 months from revenue_snapshots if available) ──
  let mrrTrend = [];
  try {
    const snapshots = await db.prepare(
      `SELECT period, mrr_cents, total_subscribers FROM revenue_snapshots
       WHERE snapshot_at >= ? ORDER BY snapshot_at ASC LIMIT 12`
    ).bind(twelveMonthsAgo).all();
    mrrTrend = snapshots?.results?.map(r => ({
      month: r.period,
      mrr:   Math.round(r.mrr_cents / 100),
      subscribers: r.total_subscribers,
    })) || [];
  } catch (_) {}

  // If no historical snapshots, generate current-month synthetic point
  if (mrrTrend.length === 0) {
    const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    mrrTrend = [{ month: monthKey, mrr: Math.round(mrr_cents / 100), subscribers: paying }];
  }

  return {
    // Revenue
    today:        revenueToday,
    week:         revenueWeek,
    month:        revenueMonth,
    mrr:          Math.round(mrr_cents / 100),
    arr:          Math.round(arr_cents / 100),
    arpu:         Math.round(arpu_cents / 100),
    ltv_estimate: Math.round((arpu_cents * 18) / 100), // 18mo avg lifetime
    pipeline_value: Math.round(pipelineValue / 100),
    pipeline:     Math.round(pipelineValue / 100), // alias — frontend/revenue-command-center.html reads this exact name

    // Subscribers
    total_subscribers:         planCounts.total,
    free_users:                planCounts.free,
    starter_users:             planCounts.starter,
    pro_users:                 planCounts.pro,
    enterprise_users:          planCounts.enterprise,
    mssp_users:                planCounts.mssp,
    paying_subscribers:        paying,
    new_this_month:            newThisMonth,
    churned_this_month:        churnedThisMonth,

    // Conversions
    conversion_rate_to_paid:       convFreeToAny,
    conversion_rate_pro_to_ent:    convProToEnterprise,

    // Pipeline
    assessments_booked:    assessmentsBooked,
    assessments_completed: assessmentsCompleted,

    // Trends
    mrr_trend: mrrTrend,

    // Meta
    currency:    'USD',
    as_of:       new Date().toISOString(),
  };
}

// POST /api/revenue/snapshot — admin only, saves current metrics as a monthly snapshot
export async function handleRevenueSnapshot(request, env, authCtx) {
  if (authCtx?.role !== 'admin' && authCtx?.role !== 'mssp_admin') {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  const db = env.SECURITY_HUB_DB;
  const metrics = await buildRevenueMetrics(db);
  const now = new Date();
  const period = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const id = `snap_${Date.now()}`;

  try {
    await db.prepare(`
      INSERT INTO revenue_snapshots
        (id, snapshot_at, period, mrr_cents, arr_cents, total_subscribers,
         free_count, pro_count, enterprise_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(period) DO UPDATE SET
        mrr_cents = excluded.mrr_cents,
        arr_cents = excluded.arr_cents,
        total_subscribers = excluded.total_subscribers
    `).bind(
      id, now.toISOString(), period,
      Math.round(metrics.mrr * 100),
      Math.round(metrics.arr * 100),
      metrics.total_subscribers,
      metrics.free_users,
      metrics.pro_users,
      metrics.enterprise_users,
    ).run();

    // Bust cache
    await env.SECURITY_HUB_KV.delete(CACHE_KEY).catch(() => {});

    return Response.json({ success: true, period, message: 'Revenue snapshot saved' });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}
