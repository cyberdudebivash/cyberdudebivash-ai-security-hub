/**
 * CYBERDUDEBIVASH AI Security Hub — RevOS MRR Engine v23.0
 * Real MRR/ARR/Churn/LTV/CAC computation from D1 subscriptions
 *
 * Called by:
 *   - GET /api/revos/dashboard
 *   - GET /api/revos/mrr
 *   - Cron: 0 23 * * * (nightly snapshot)
 */

const PLAN_MRR = { FREE: 0, STARTER: 499, PRO: 1499, ENTERPRISE: 4999, MSSP: 9999 };

// ─── Core MRR calculation from live subscriptions ────────────────────────────
export async function computeLiveMRR(db) {
  if (!db) return buildEmptyMRR();
  try {
    const [rows, trialRows] = await Promise.all([
      db.prepare(`
        SELECT plan, COUNT(*) as count, SUM(price_inr) as total
        FROM subscriptions
        WHERE status = 'active'
        GROUP BY plan
      `).all(),
      db.prepare(`
        SELECT COUNT(*) as count FROM subscriptions WHERE status = 'trialing'
      `).first(),
    ]);

    let mrr = 0, breakdown = {};
    for (const row of (rows.results || [])) {
      const planMrr = (row.count || 0) * PLAN_MRR[row.plan || 'FREE'];
      mrr += planMrr;
      breakdown[row.plan] = { count: row.count, mrr: planMrr };
    }

    return {
      mrr_inr:          mrr,
      arr_inr:          mrr * 12,
      breakdown,
      trial_count:      trialRows?.count || 0,
      active_count:     Object.values(breakdown).reduce((s, p) => s + (p.count || 0), 0),
    };
  } catch { return buildEmptyMRR(); }
}

// ─── Nightly MRR snapshot writer ─────────────────────────────────────────────
export async function writeMRRSnapshot(db) {
  if (!db) return { ok: false };
  try {
    const live = await computeLiveMRR(db);
    const today = new Date().toISOString().slice(0, 10);

    // Get yesterday's snapshot for delta calculation
    const yesterday = await db.prepare(`
      SELECT mrr_inr, active_subs FROM mrr_snapshots
      ORDER BY snapshot_date DESC LIMIT 1
    `).first().catch(() => null);

    const prev_mrr = yesterday?.mrr_inr || 0;

    // Compute churn MRR from today's churn events
    const todayChurn = await db.prepare(`
      SELECT COALESCE(SUM(mrr_lost_inr), 0) as churned
      FROM churn_events WHERE date(churned_at) = date('now')
    `).first().catch(() => ({ churned: 0 }));

    const new_mrr        = Math.max(0, live.mrr_inr - prev_mrr + (todayChurn?.churned || 0));
    const churned_mrr    = todayChurn?.churned || 0;
    const net_new_mrr    = live.mrr_inr - prev_mrr;

    // Churn rate = churned MRR / prev MRR
    const churn_rate = prev_mrr > 0 ? (churned_mrr / prev_mrr) * 100 : 0;

    // Trial conversion rate (last 30 days)
    const trialConv = await db.prepare(`
      SELECT
        COUNT(CASE WHEN status='active' THEN 1 END) as converted,
        COUNT(*) as total
      FROM subscriptions
      WHERE trial_ends_at IS NOT NULL
        AND created_at > datetime('now','-30 days')
    `).first().catch(() => ({ converted: 0, total: 1 }));
    const trial_rate = trialConv?.total > 0
      ? (trialConv.converted / trialConv.total) * 100 : 0;

    // NRR = (beginning MRR + expansion - contraction - churn) / beginning MRR * 100
    const nrr = prev_mrr > 0 ? ((live.mrr_inr) / prev_mrr) * 100 : 100;

    await db.prepare(`
      INSERT OR REPLACE INTO mrr_snapshots
        (snapshot_date, mrr_inr, arr_inr, new_mrr, churned_mrr, net_new_mrr,
         active_subs, trial_subs, starter_count, pro_count, enterprise_count, mssp_count,
         trial_conversion_rate, churn_rate, nrr, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      today,
      live.mrr_inr, live.mrr_inr * 12,
      new_mrr, churned_mrr, net_new_mrr,
      live.active_count, live.trial_count,
      live.breakdown?.STARTER?.count || 0,
      live.breakdown?.PRO?.count || 0,
      live.breakdown?.ENTERPRISE?.count || 0,
      live.breakdown?.MSSP?.count || 0,
      Math.round(trial_rate * 10) / 10,
      Math.round(churn_rate * 100) / 100,
      Math.round(nrr * 10) / 10,
    ).run();

    return { ok: true, date: today, mrr: live.mrr_inr, arr: live.mrr_inr * 12 };
  } catch (e) { return { ok: false, error: e.message }; }
}

// ─── Revenue dashboard data (all KPIs) ───────────────────────────────────────
export async function getRevOSDashboard(db) {
  if (!db) return { success: false, error: 'No DB' };
  try {
    const [live, snapshots, churnData, ltvData, cacData, pipeline, monthly] = await Promise.all([
      computeLiveMRR(db),

      // Last 30 days of MRR snapshots for trend chart
      db.prepare(`
        SELECT snapshot_date, mrr_inr, arr_inr, churn_rate, nrr, active_subs,
               new_mrr, churned_mrr
        FROM mrr_snapshots
        ORDER BY snapshot_date DESC LIMIT 30
      `).all().catch(() => ({ results: [] })),

      // Churn stats (last 30 days)
      db.prepare(`
        SELECT
          COUNT(*) as total_churned,
          COALESCE(SUM(mrr_lost_inr), 0) as mrr_lost,
          AVG(tenure_days) as avg_tenure,
          reason, COUNT(*) as reason_count
        FROM churn_events
        WHERE churned_at > datetime('now','-30 days')
        GROUP BY reason
        ORDER BY reason_count DESC
      `).all().catch(() => ({ results: [] })),

      // LTV distribution
      db.prepare(`
        SELECT
          ltv_segment,
          COUNT(*) as count,
          COALESCE(AVG(total_revenue_inr), 0) as avg_ltv,
          COALESCE(AVG(predicted_ltv_inr), 0) as avg_predicted_ltv
        FROM customer_ltv
        GROUP BY ltv_segment
      `).all().catch(() => ({ results: [] })),

      // CAC by channel (last 30 days)
      db.prepare(`
        SELECT
          channel,
          COALESCE(SUM(cost_inr), 0) as total_cost,
          COUNT(CASE WHEN converted=1 THEN 1 END) as conversions,
          COALESCE(SUM(mrr_generated), 0) as mrr_from_channel
        FROM cac_events
        WHERE event_date > date('now','-30 days')
        GROUP BY channel
        ORDER BY conversions DESC
      `).all().catch(() => ({ results: [] })),

      // Deal pipeline value
      db.prepare(`
        SELECT stage, COUNT(*) as deals, COALESCE(SUM(deal_value_inr),0) as value
        FROM deal_pipeline
        GROUP BY stage
      `).all().catch(() => ({ results: [] })),

      // This month total revenue
      db.prepare(`
        SELECT total_revenue_inr, new_customers, churned_customers
        FROM revenue_monthly
        WHERE period = strftime('%Y-%m', datetime('now'))
      `).first().catch(() => null),
    ]);

    // Compute aggregate churn stats
    const churnResults = churnData.results || [];
    const totalChurned = churnResults.reduce((s, r) => s + (r.total_churned || 0), 0);
    const mrrLost = churnResults.reduce((s, r) => s + (r.mrr_lost || 0), 0);

    // CAC computation
    const cacResults = cacData.results || [];
    const totalCost = cacResults.reduce((s, r) => s + (r.total_cost || 0), 0);
    const totalConversions = cacResults.reduce((s, r) => s + (r.conversions || 0), 0);
    const blendedCAC = totalConversions > 0 ? Math.round(totalCost / totalConversions) : 0;

    // LTV:CAC ratio
    const ltvResults = ltvData.results || [];
    const avgLTV = ltvResults.length > 0
      ? ltvResults.reduce((s, r) => s + (r.avg_ltv || 0), 0) / ltvResults.length : 0;
    const ltvCacRatio = blendedCAC > 0 ? (avgLTV / blendedCAC).toFixed(1) : '∞';

    // Pipeline value
    const pipelineResults = pipeline.results || [];
    const totalPipelineValue = pipelineResults.reduce((s, r) => s + (r.value || 0), 0);
    const closedWon = pipelineResults.find(r => r.stage === 'closed_won');

    const snapshotList = (snapshots.results || []).reverse();
    const latest = snapshotList[snapshotList.length - 1];

    return {
      success: true,
      kpis: {
        mrr_inr:          live.mrr_inr,
        arr_inr:          live.mrr_inr * 12,
        active_subscribers: live.active_count,
        trial_count:      live.trial_count,
        churn_rate_pct:   latest?.churn_rate || 0,
        nrr_pct:          latest?.nrr || 100,
        mrr_lost_inr:     mrrLost,
        avg_ltv_inr:      Math.round(avgLTV),
        blended_cac_inr:  blendedCAC,
        ltv_cac_ratio:    ltvCacRatio,
        total_pipeline_inr: totalPipelineValue,
        monthly_revenue:  monthly?.total_revenue_inr || 0,
      },
      plan_breakdown:   live.breakdown,
      mrr_trend:        snapshotList.map(s => ({
        date:    s.snapshot_date,
        mrr:     s.mrr_inr,
        churn:   s.churn_rate,
        new_mrr: s.new_mrr,
        churned: s.churned_mrr,
      })),
      churn_reasons:    churnResults.map(r => ({ reason: r.reason, count: r.reason_count, mrr_lost: r.mrr_lost })),
      ltv_segments:     ltvResults,
      cac_by_channel:   cacResults,
      pipeline_stages:  pipelineResults,
      generated_at:     new Date().toISOString(),
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─── Update customer LTV after payment ───────────────────────────────────────
export async function updateCustomerLTV(db, userId, email, amountInr, category = 'sub') {
  if (!db || !userId) return;
  try {
    const col = {
      sub: 'sub_revenue_inr',
      marketplace: 'marketplace_revenue_inr',
      api: 'api_revenue_inr',
      report: 'report_revenue_inr',
    }[category] || 'sub_revenue_inr';

    await db.prepare(`
      INSERT INTO customer_ltv (user_id, email, total_revenue_inr, ${col}, payment_count, first_payment_at, last_payment_at)
      VALUES (?, ?, ?, ?, 1, datetime('now'), datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        total_revenue_inr = total_revenue_inr + ?,
        ${col}            = ${col} + ?,
        payment_count     = payment_count + 1,
        last_payment_at   = datetime('now'),
        updated_at        = datetime('now')
    `).bind(userId, email, amountInr, amountInr, amountInr, amountInr).run();

    // Recompute predicted LTV (simple: avg monthly * 24 months)
    await db.prepare(`
      UPDATE customer_ltv
      SET predicted_ltv_inr = CASE
        WHEN payment_count > 0 THEN CAST(total_revenue_inr / MAX(1, payment_count) * 24 AS INTEGER)
        ELSE total_revenue_inr
      END,
      ltv_segment = CASE
        WHEN total_revenue_inr > 50000 THEN 'champion'
        WHEN total_revenue_inr > 15000 THEN 'high'
        WHEN total_revenue_inr > 5000  THEN 'medium'
        ELSE 'low'
      END,
      updated_at = datetime('now')
      WHERE user_id = ?
    `).bind(userId).run();
  } catch {}
}

// ─── Record churn event ───────────────────────────────────────────────────────
export async function recordChurn(db, subscription, reason = 'unknown', detail = '') {
  if (!db || !subscription) return;
  try {
    const tenureDays = subscription.created_at
      ? Math.round((Date.now() - new Date(subscription.created_at).getTime()) / 86400000) : 0;

    await db.prepare(`
      INSERT INTO churn_events
        (subscription_id, user_id, email, plan, mrr_lost_inr, reason, reason_detail, was_trial, tenure_days)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      subscription.id, subscription.user_id, subscription.email,
      subscription.plan, PLAN_MRR[subscription.plan] || 0,
      reason, detail,
      subscription.status === 'trialing' ? 1 : 0,
      tenureDays,
    ).run();
  } catch {}
}

function buildEmptyMRR() {
  return { mrr_inr: 0, arr_inr: 0, breakdown: {}, trial_count: 0, active_count: 0 };
}
