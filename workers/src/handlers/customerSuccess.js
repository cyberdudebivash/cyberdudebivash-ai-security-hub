/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * customerSuccess.js — Customer Health Scoring & Success Platform
 *
 * APIs:
 *   GET  /api/customer-success/health           own org (enterprise+)
 *   GET  /api/customer-success/health/:orgId    specific org (mssp_admin)
 *   GET  /api/customer-success/overview         platform-wide (admin)
 *   POST /api/customer-success/refresh          recompute scores (admin)
 *   GET  /api/customer-success/playbooks        available playbooks
 */

const PLAYBOOKS = [
  {
    id: 'pb-001', name: 'New Customer Onboarding',
    description: 'Run first scan, configure a monitor, enable alerts.',
    steps: ['Complete domain scan','Set up continuous monitor','Configure alert thresholds','Invite team members'],
    trigger: 'maturity=STARTER,health<30',
    estimated_days: 7,
  },
  {
    id: 'pb-002', name: 'Risk Reduction Playbook',
    description: 'Systematically address open CRITICAL and HIGH findings.',
    steps: ['Triage all CRITICAL findings','Open SOC cases for each','Assign owners','Review weekly'],
    trigger: 'churn_risk=HIGH',
    estimated_days: 14,
  },
  {
    id: 'pb-003', name: 'Expansion Playbook',
    description: 'Identify upgrade opportunity when adoption exceeds 80%.',
    steps: ['Review feature usage','Identify upsell trigger','Schedule call','Demo next tier'],
    trigger: 'adoption_score>80,expansion_score>70',
    estimated_days: 5,
  },
  {
    id: 'pb-004', name: 'Win-Back Playbook',
    description: 'Re-engage dormant accounts inactive for 30+ days.',
    steps: ['Send re-engagement email','Offer free assessment','Schedule demo','Provide platform update'],
    trigger: 'last_scan_days_ago>30',
    estimated_days: 10,
  },
  {
    id: 'pb-005', name: 'Enterprise Readiness',
    description: 'Prepare customer for Enterprise plan: compliance + AI security.',
    steps: ['Complete compliance assessment','Register AI assets','Run AI red team','Review full report'],
    trigger: 'maturity=DEVELOPING,expansion_score>60',
    estimated_days: 21,
  },
];

function genId() { return 'cs_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

function requireRole(req, roles) {
  if (!req.user) return false;
  return roles.includes(req.user.role) || roles.includes(req.user.tier);
}

/**
 * Compute health score for an org from D1 data.
 * Reads scan_results, soc_cases, users tables.
 */
async function computeHealthForOrg(orgId, env) {
  const db = env.DB;

  // Scan frequency (last 30 days)
  const scanRow = await db.prepare(
    `SELECT COUNT(*) as cnt, MAX(created_at) as last_scan
     FROM scan_results WHERE org_id = ? AND created_at >= datetime('now','-30 days')`
  ).bind(orgId).first().catch(() => ({ cnt: 0, last_scan: null }));

  const scans30d = scanRow?.cnt ?? 0;
  const lastScan = scanRow?.last_scan;
  const lastScanDaysAgo = lastScan
    ? Math.floor((Date.now() - new Date(lastScan).getTime()) / 86_400_000)
    : 999;

  // Case resolution rate
  const caseRow = await db.prepare(
    `SELECT COUNT(*) as total, SUM(CASE WHEN status='RESOLVED' OR status='CLOSED' THEN 1 ELSE 0 END) as resolved
     FROM soc_cases WHERE org_id = ?`
  ).bind(orgId).first().catch(() => ({ total: 0, resolved: 0 }));
  const resolutionRate = (caseRow?.total ?? 0) > 0
    ? (caseRow.resolved / caseRow.total)
    : 0.5;

  // Active features (count distinct API paths used — proxied via scan types present)
  const featureRow = await db.prepare(
    `SELECT COUNT(DISTINCT scan_type) as feat FROM scan_results WHERE org_id = ?`
  ).bind(orgId).first().catch(() => ({ feat: 0 }));
  const activeFeatureCount = Math.min(featureRow?.feat ?? 0, 5);

  // Subscription tier
  const userRow = await db.prepare(
    `SELECT tier FROM users WHERE org_id = ? LIMIT 1`
  ).bind(orgId).first().catch(() => null);
  const tier = userRow?.tier || 'FREE';

  // Score computation
  let scanScore = scans30d >= 10 ? 30 : scans30d >= 5 ? 20 : scans30d >= 1 ? 10 : 0;
  let featureScore = activeFeatureCount * 4;
  let resolutionScore = Math.round(resolutionRate * 20);
  let recencyScore = lastScanDaysAgo <= 7 ? 15 : lastScanDaysAgo <= 30 ? 10 : lastScanDaysAgo <= 90 ? 5 : 0;
  let tierScore = tier === 'enterprise' ? 15 : tier === 'pro' ? 10 : 0;
  const healthScore = Math.min(100, scanScore + featureScore + resolutionScore + recencyScore + tierScore);

  // Adoption score
  const adoptionScore = Math.min(100, featureScore * 5 + (scans30d >= 5 ? 50 : scans30d * 10));

  // Churn risk
  let churnRisk = 'NONE';
  if (lastScanDaysAgo >= 30) churnRisk = 'HIGH';
  else if (lastScanDaysAgo >= 14) churnRisk = 'MEDIUM';
  else if (healthScore < 30) churnRisk = 'LOW';

  // Expansion score
  const expansionScore = Math.min(100, adoptionScore + (tier === 'pro' ? 20 : tier === 'enterprise' ? 0 : 0));

  // Maturity index
  const maturityIndex = healthScore >= 80 ? 'CHAMPION'
    : healthScore >= 60 ? 'MATURE'
    : healthScore >= 35 ? 'DEVELOPING'
    : 'STARTER';

  // Risk triggers
  const riskTriggers = [];
  if (lastScanDaysAgo >= 30) riskTriggers.push('No scans in 30+ days');
  if (lastScanDaysAgo >= 14 && lastScanDaysAgo < 30) riskTriggers.push('No scans in 14+ days');
  if (healthScore < 30) riskTriggers.push('Low platform engagement');
  if (resolutionRate < 0.3) riskTriggers.push('Low case resolution rate');

  // Recommended playbook
  let playbook_id = null;
  if (churnRisk === 'HIGH') playbook_id = 'pb-004';
  else if (maturityIndex === 'STARTER') playbook_id = 'pb-001';
  else if (churnRisk === 'MEDIUM') playbook_id = 'pb-002';
  else if (expansionScore > 70) playbook_id = 'pb-003';

  return {
    orgId, healthScore, adoptionScore, churnRisk, expansionScore, maturityIndex,
    lastScanDaysAgo, scans30d, activeFeatureCount, tier, riskTriggers, playbook_id,
    resolutionRate: Math.round(resolutionRate * 100),
  };
}

async function upsertHealthRecord(data, env) {
  const id = genId();
  await env.DB.prepare(`
    INSERT INTO customer_health
      (id, org_id, health_score, adoption_score, churn_risk, expansion_score,
       maturity_index, last_scan_days_ago, total_scans_30d, active_features,
       risk_triggers, playbook_id, computed_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))
    ON CONFLICT(org_id) DO UPDATE SET
      health_score=excluded.health_score,
      adoption_score=excluded.adoption_score,
      churn_risk=excluded.churn_risk,
      expansion_score=excluded.expansion_score,
      maturity_index=excluded.maturity_index,
      last_scan_days_ago=excluded.last_scan_days_ago,
      total_scans_30d=excluded.total_scans_30d,
      active_features=excluded.active_features,
      risk_triggers=excluded.risk_triggers,
      playbook_id=excluded.playbook_id,
      computed_at=datetime('now'),
      updated_at=datetime('now')
  `).bind(
    id, data.orgId, data.healthScore, data.adoptionScore, data.churnRisk,
    data.expansionScore, data.maturityIndex, data.lastScanDaysAgo, data.scans30d,
    JSON.stringify(data.activeFeatureCount), JSON.stringify(data.riskTriggers),
    data.playbook_id
  ).run().catch(() => null);
}

export async function handleCustomerHealth(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const cacheKey = `customer_health_${req.user.org_id || 'default'}`;
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ health: cached, cached: true });

  const data = await computeHealthForOrg(req.user.org_id || 'default', env);
  await upsertHealthRecord(data, env);
  await env.KV?.put(cacheKey, JSON.stringify(data), { expirationTtl: 300 }).catch(() => null);

  return Response.json({ health: data });
}

export async function handleCustomerHealthByOrg(req, env, orgId) {
  if (!requireRole(req, ['admin', 'mssp_admin'])) {
    return Response.json({ error: 'MSSP Admin required' }, { status: 403 });
  }

  const data = await computeHealthForOrg(orgId, env);
  await upsertHealthRecord(data, env);

  return Response.json({ health: data });
}

export async function handleCustomerSuccessOverview(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  const cacheKey = 'cs_overview_v3';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ ...cached, cached: true });

  try {
    const rows = await env.DB.prepare(
      `SELECT health_score, adoption_score, churn_risk, maturity_index
       FROM customer_health ORDER BY computed_at DESC LIMIT 100`
    ).all();
    const data = rows.results || [];

    const total = data.length;
    const avgHealth = total ? Math.round(data.reduce((a, r) => a + r.health_score, 0) / total) : 0;
    const avgAdoption = total ? Math.round(data.reduce((a, r) => a + r.adoption_score, 0) / total) : 0;
    const churnCount = data.filter(r => ['HIGH', 'CRITICAL'].includes(r.churn_risk)).length;
    const matureCt = data.filter(r => ['MATURE', 'CHAMPION'].includes(r.maturity_index)).length;

    const overview = {
      total_orgs: total, avg_health_score: avgHealth, avg_adoption_score: avgAdoption,
      high_churn_count: churnCount, mature_count: matureCt,
      champion_count: data.filter(r => r.maturity_index === 'CHAMPION').length,
      starter_count: data.filter(r => r.maturity_index === 'STARTER').length,
    };

    await env.KV?.put(cacheKey, JSON.stringify(overview), { expirationTtl: 300 }).catch(() => null);
    return Response.json(overview);
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleRefreshHealthScores(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  try {
    // Get all distinct org_ids from scan_results
    const orgs = await env.DB.prepare(
      `SELECT DISTINCT org_id FROM scan_results WHERE org_id IS NOT NULL LIMIT 50`
    ).all();
    const orgIds = (orgs.results || []).map(r => r.org_id).filter(Boolean);
    if (!orgIds.includes('default')) orgIds.push('default');

    let refreshed = 0;
    for (const orgId of orgIds) {
      const data = await computeHealthForOrg(orgId, env);
      await upsertHealthRecord(data, env);
      await env.KV?.delete(`customer_health_${orgId}`).catch(() => null);
      refreshed++;
    }

    await env.KV?.delete('cs_overview_v3').catch(() => null);
    return Response.json({ success: true, refreshed, org_count: orgIds.length });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleCustomerSuccessPlaybooks(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = req.user.org_id || 'default';
  const health = await env.DB.prepare(
    `SELECT * FROM customer_health WHERE org_id = ?`
  ).bind(orgId).first().catch(() => null);

  const recommended = health?.playbook_id || null;
  const playbooks = PLAYBOOKS.map(p => ({
    ...p,
    is_recommended: p.id === recommended,
  }));

  return Response.json({ playbooks, recommended_id: recommended });
}
