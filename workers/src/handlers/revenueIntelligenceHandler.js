/**
 * CYBERDUDEBIVASH® AI Security Hub — P18.0
 * revenueIntelligenceHandler.js — Automated Revenue Intelligence & Churn Prevention Engine
 *
 * APIs:
 *   GET  /api/platform/revenue-intelligence           full dashboard payload
 *   GET  /api/platform/revenue-intelligence/churn-alerts  HIGH churn accounts
 *   POST /api/platform/revenue-intelligence/intervention  log intervention action
 *   GET  /api/platform/revenue-intelligence/upgrade-signals  expansion-ready accounts
 *   GET  /api/platform/revenue-intelligence/nrr-forecast     90-day NRR forecast
 *   GET  /api/platform/revenue-intelligence/observability     P18.0 health gate
 *
 * Reads: customer_health (P15.0), subscriptions, mrr_snapshots (P16.0)
 * Writes: revenue_interventions (new, schema-independent insert)
 * Reuses: customer_health D1 table populated by customerSuccess.js P15.0
 */

const TIER_PRICE = { FREE: 0, STARTER: 29, PRO: 99, ENTERPRISE: 499, MSSP: 999,
  COMMUNITY: 0, PROFESSIONAL: 49, TEAM: 149, BUSINESS: 299 };

const UPGRADE_PATH = {
  FREE: 'STARTER', STARTER: 'PRO', PRO: 'ENTERPRISE', ENTERPRISE: 'MSSP',
  COMMUNITY: 'PROFESSIONAL', PROFESSIONAL: 'TEAM', TEAM: 'BUSINESS', BUSINESS: 'ENTERPRISE',
};

function requireAdmin(req) {
  if (!req.user) return false;
  return ['admin', 'mssp_admin', 'platform_admin'].includes(req.user.role)
    || req.user.tier === 'MSSP';
}

function genId() {
  return 'ri_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

/**
 * Fetch all customer health rows with subscription tier data.
 * Joins customer_health LEFT JOIN users to get tier for ARR math.
 */
async function fetchEnrichedHealthRows(env) {
  const rows = await env.DB.prepare(`
    SELECT ch.org_id, ch.health_score, ch.adoption_score, ch.churn_risk,
           ch.expansion_score, ch.maturity_index, ch.last_scan_days_ago,
           ch.total_scans_30d, ch.risk_triggers, ch.playbook_id, ch.computed_at,
           u.tier, u.email
    FROM customer_health ch
    LEFT JOIN users u ON u.org_id = ch.org_id
    GROUP BY ch.org_id
    ORDER BY ch.health_score ASC
    LIMIT 500
  `).all().catch(() => ({ results: [] }));
  return rows.results || [];
}

/**
 * Compute MRR contribution for a tier string.
 */
function tierToMRR(tier) {
  if (!tier) return 0;
  return TIER_PRICE[tier.toUpperCase()] || 0;
}

/**
 * Classify intervention urgency from health data.
 */
function interventionUrgency(row) {
  if (row.churn_risk === 'HIGH' && row.health_score < 30) return 'CRITICAL';
  if (row.churn_risk === 'HIGH') return 'HIGH';
  if (row.churn_risk === 'MEDIUM' && row.health_score < 50) return 'HIGH';
  if (row.churn_risk === 'MEDIUM') return 'MEDIUM';
  if (row.expansion_score > 75 && row.health_score > 70) return 'EXPANSION';
  return 'MONITOR';
}

/**
 * Generate intervention recommendation text.
 */
function interventionRec(row) {
  const urgency = interventionUrgency(row);
  if (urgency === 'CRITICAL') return 'Immediate CSM outreach — high churn risk + low engagement. Trigger win-back playbook (pb-004).';
  if (urgency === 'HIGH') return 'Schedule discovery call within 48h. Review risk triggers. Offer complimentary health assessment.';
  if (urgency === 'MEDIUM') return 'Send automated re-engagement sequence. Surface new detection capabilities.';
  if (urgency === 'EXPANSION') return 'Expansion-ready: schedule upgrade demo. Highlight next-tier features.';
  return 'Healthy account — monitor quarterly.';
}

/**
 * Build 90-day NRR forecast from MRR snapshots + churn signals.
 */
async function buildNRRForecast(env, allRows) {
  // Fetch last 6 monthly MRR snapshots
  const snapshots = await env.DB.prepare(`
    SELECT month_year, total_mrr, new_mrr, churned_mrr, expansion_mrr
    FROM mrr_snapshots
    ORDER BY month_year DESC LIMIT 6
  `).all().catch(() => ({ results: [] }));

  const snaps = (snapshots.results || []).reverse();

  // Current at-risk MRR from live health signals
  const highRiskRows = allRows.filter(r => r.churn_risk === 'HIGH');
  const atRiskMRR = highRiskRows.reduce((s, r) => s + tierToMRR(r.tier), 0);
  const expansionRows = allRows.filter(r => interventionUrgency(r) === 'EXPANSION');
  const expansionMRR = expansionRows.reduce((s, r) => {
    const next = UPGRADE_PATH[r.tier?.toUpperCase()];
    return s + (next ? Math.max(0, (TIER_PRICE[next] || 0) - tierToMRR(r.tier)) : 0);
  }, 0);

  // NRR = (Starting MRR + Expansion - Churn - Contraction) / Starting MRR
  const currentMRR = snaps.length ? snaps[snaps.length - 1].total_mrr : 0;
  const avgChurnRate = snaps.length >= 2
    ? snaps.reduce((a, s) => a + (s.churned_mrr / Math.max(s.total_mrr, 1)), 0) / snaps.length
    : 0.02;
  const avgExpansionRate = snaps.length >= 2
    ? snaps.reduce((a, s) => a + (s.expansion_mrr / Math.max(s.total_mrr, 1)), 0) / snaps.length
    : 0.03;

  // 3-month projections
  const months = [];
  let projectedMRR = currentMRR;
  for (let m = 1; m <= 3; m++) {
    const churn = projectedMRR * avgChurnRate;
    const expansion = projectedMRR * avgExpansionRate;
    projectedMRR = projectedMRR - churn + expansion;
    const d = new Date();
    d.setMonth(d.getMonth() + m);
    months.push({
      month: d.toLocaleString('default', { month: 'short', year: 'numeric' }),
      projected_mrr: Math.round(projectedMRR),
      projected_churn_mrr: Math.round(churn),
      projected_expansion_mrr: Math.round(expansion),
    });
  }

  const nrr = currentMRR > 0
    ? Math.round(((currentMRR - atRiskMRR + expansionMRR) / currentMRR) * 100)
    : 100;

  return {
    current_mrr: currentMRR,
    at_risk_mrr: atRiskMRR,
    potential_expansion_mrr: expansionMRR,
    nrr_estimate_pct: nrr,
    nrr_health: nrr >= 110 ? 'EXCELLENT' : nrr >= 100 ? 'GOOD' : nrr >= 90 ? 'AT_RISK' : 'CRITICAL',
    historical_snapshots: snaps,
    three_month_forecast: months,
    avg_monthly_churn_rate_pct: Math.round(avgChurnRate * 100 * 10) / 10,
    avg_monthly_expansion_rate_pct: Math.round(avgExpansionRate * 100 * 10) / 10,
  };
}

// ── Exported Handlers ───────────────────────────────────────────────────────

export async function handleRevenueIntelligence(req, env) {
  if (!requireAdmin(req)) return Response.json({ error: 'Admin required' }, { status: 403 });

  const cacheKey = 'ri:dashboard:v1';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ ...cached, cached: true });

  try {
    const allRows = await fetchEnrichedHealthRows(env);

    const churnAlerts = allRows
      .filter(r => ['HIGH'].includes(r.churn_risk))
      .map(r => ({
        org_id: r.org_id,
        email: r.email,
        tier: r.tier,
        mrr: tierToMRR(r.tier),
        health_score: r.health_score,
        churn_risk: r.churn_risk,
        last_scan_days_ago: r.last_scan_days_ago,
        urgency: interventionUrgency(r),
        recommendation: interventionRec(r),
        playbook_id: r.playbook_id,
        risk_triggers: (() => { try { return JSON.parse(r.risk_triggers || '[]'); } catch { return []; } })(),
      }))
      .sort((a, b) => b.mrr - a.mrr);

    const upgradeSignals = allRows
      .filter(r => interventionUrgency(r) === 'EXPANSION')
      .map(r => ({
        org_id: r.org_id,
        email: r.email,
        current_tier: r.tier,
        next_tier: UPGRADE_PATH[r.tier?.toUpperCase()] || null,
        current_mrr: tierToMRR(r.tier),
        potential_mrr_increase: (() => {
          const next = UPGRADE_PATH[r.tier?.toUpperCase()];
          return next ? Math.max(0, (TIER_PRICE[next] || 0) - tierToMRR(r.tier)) : 0;
        })(),
        health_score: r.health_score,
        adoption_score: r.adoption_score,
        expansion_score: r.expansion_score,
        recommendation: interventionRec(r),
      }))
      .sort((a, b) => b.potential_mrr_increase - a.potential_mrr_increase);

    const totalAtRiskMRR = churnAlerts.reduce((s, r) => s + r.mrr, 0);
    const totalExpansionMRR = upgradeSignals.reduce((s, r) => s + r.potential_mrr_increase, 0);

    const summary = {
      total_accounts_monitored: allRows.length,
      high_churn_accounts: churnAlerts.length,
      at_risk_mrr: totalAtRiskMRR,
      expansion_opportunities: upgradeSignals.length,
      potential_expansion_mrr: totalExpansionMRR,
      avg_health_score: allRows.length
        ? Math.round(allRows.reduce((s, r) => s + r.health_score, 0) / allRows.length)
        : 0,
      generated_at: new Date().toISOString(),
    };

    const payload = { summary, churn_alerts: churnAlerts, upgrade_signals: upgradeSignals };
    await env.KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 }).catch(() => null);
    return Response.json(payload);
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleChurnAlerts(req, env) {
  if (!requireAdmin(req)) return Response.json({ error: 'Admin required' }, { status: 403 });

  const cacheKey = 'ri:churn_alerts:v1';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ alerts: cached, cached: true });

  try {
    const allRows = await fetchEnrichedHealthRows(env);
    const alerts = allRows
      .filter(r => r.churn_risk === 'HIGH' || (r.churn_risk === 'MEDIUM' && r.health_score < 40))
      .map(r => ({
        org_id: r.org_id,
        email: r.email,
        tier: r.tier,
        mrr: tierToMRR(r.tier),
        health_score: r.health_score,
        churn_risk: r.churn_risk,
        urgency: interventionUrgency(r),
        last_scan_days_ago: r.last_scan_days_ago,
        recommendation: interventionRec(r),
        playbook_id: r.playbook_id,
      }))
      .sort((a, b) => b.mrr - a.mrr || a.health_score - b.health_score);

    await env.KV?.put(cacheKey, JSON.stringify(alerts), { expirationTtl: 180 }).catch(() => null);
    return Response.json({ alerts, count: alerts.length, at_risk_mrr: alerts.reduce((s, r) => s + r.mrr, 0) });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleLogIntervention(req, env) {
  if (!requireAdmin(req)) return Response.json({ error: 'Admin required' }, { status: 403 });

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { org_id, action_type, notes, playbook_id } = body;
  if (!org_id || !action_type) return Response.json({ error: 'org_id and action_type required' }, { status: 400 });

  const validActions = ['EMAIL_SENT', 'CALL_SCHEDULED', 'DEMO_BOOKED', 'DISCOUNT_OFFERED', 'PLAYBOOK_STARTED', 'UPGRADE_INITIATED', 'WINBACK_INITIATED', 'RESOLVED'];
  if (!validActions.includes(action_type)) {
    return Response.json({ error: `action_type must be one of: ${validActions.join(', ')}` }, { status: 400 });
  }

  try {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS revenue_interventions (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        notes TEXT,
        playbook_id TEXT,
        performed_by TEXT,
        performed_at TEXT DEFAULT (datetime('now'))
      )
    `).run().catch(() => null);

    const id = genId();
    await env.DB.prepare(`
      INSERT INTO revenue_interventions (id, org_id, action_type, notes, playbook_id, performed_by)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(id, org_id, action_type, notes || null, playbook_id || null, req.user?.email || 'admin').run();

    // Invalidate churn alert cache for this org
    await env.KV?.delete('ri:churn_alerts:v1').catch(() => null);
    await env.KV?.delete('ri:dashboard:v1').catch(() => null);

    return Response.json({ success: true, intervention_id: id, org_id, action_type, recorded_at: new Date().toISOString() });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleUpgradeSignals(req, env) {
  if (!requireAdmin(req)) return Response.json({ error: 'Admin required' }, { status: 403 });

  const cacheKey = 'ri:upgrade_signals:v1';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ signals: cached, cached: true });

  try {
    const allRows = await fetchEnrichedHealthRows(env);
    const signals = allRows
      .filter(r => r.expansion_score > 65 && r.health_score > 60)
      .map(r => {
        const nextTier = UPGRADE_PATH[r.tier?.toUpperCase()];
        const mrrIncrease = nextTier ? Math.max(0, (TIER_PRICE[nextTier] || 0) - tierToMRR(r.tier)) : 0;
        return {
          org_id: r.org_id,
          email: r.email,
          current_tier: r.tier,
          next_tier: nextTier,
          mrr_increase: mrrIncrease,
          health_score: r.health_score,
          adoption_score: r.adoption_score,
          expansion_score: r.expansion_score,
          maturity_index: r.maturity_index,
          scans_30d: r.total_scans_30d,
          signal_strength: r.expansion_score > 85 ? 'STRONG' : r.expansion_score > 70 ? 'MODERATE' : 'WEAK',
          recommended_play: interventionRec(r),
        };
      })
      .sort((a, b) => b.mrr_increase - a.mrr_increase || b.expansion_score - a.expansion_score);

    await env.KV?.put(cacheKey, JSON.stringify(signals), { expirationTtl: 300 }).catch(() => null);
    return Response.json({
      signals,
      count: signals.length,
      total_potential_mrr_increase: signals.reduce((s, r) => s + r.mrr_increase, 0),
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleNRRForecast(req, env) {
  if (!requireAdmin(req)) return Response.json({ error: 'Admin required' }, { status: 403 });

  const cacheKey = 'ri:nrr_forecast:v1';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ forecast: cached, cached: true });

  try {
    const allRows = await fetchEnrichedHealthRows(env);
    const forecast = await buildNRRForecast(env, allRows);
    await env.KV?.put(cacheKey, JSON.stringify(forecast), { expirationTtl: 600 }).catch(() => null);
    return Response.json({ forecast });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleRevenueIntelObservability(req, env) {
  const checks = {
    customer_health_table: false,
    mrr_snapshots_table: false,
    kv_accessible: false,
    intervention_table: false,
  };

  try {
    await env.DB.prepare('SELECT 1 FROM customer_health LIMIT 1').run();
    checks.customer_health_table = true;
  } catch {}
  try {
    await env.DB.prepare('SELECT 1 FROM mrr_snapshots LIMIT 1').run();
    checks.mrr_snapshots_table = true;
  } catch {}
  try {
    await env.KV?.put('ri:health_check', '1', { expirationTtl: 10 });
    checks.kv_accessible = true;
  } catch {}
  try {
    await env.DB.prepare('SELECT 1 FROM revenue_interventions LIMIT 1').run();
    checks.intervention_table = true;
  } catch {}

  const allPass = checks.customer_health_table && checks.kv_accessible;
  return Response.json({
    layer: 'P18.0',
    name: 'Revenue Intelligence & Churn Prevention Engine',
    status: allPass ? 'OPERATIONAL' : 'DEGRADED',
    checks,
    endpoints: [
      'GET /api/platform/revenue-intelligence',
      'GET /api/platform/revenue-intelligence/churn-alerts',
      'POST /api/platform/revenue-intelligence/intervention',
      'GET /api/platform/revenue-intelligence/upgrade-signals',
      'GET /api/platform/revenue-intelligence/nrr-forecast',
      'GET /api/platform/revenue-intelligence/observability',
    ],
    timestamp: new Date().toISOString(),
  }, { status: allPass ? 200 : 503 });
}
