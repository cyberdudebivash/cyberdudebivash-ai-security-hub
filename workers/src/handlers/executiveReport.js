/**
 * CYBERDUDEBIVASH AI Security Hub — Executive Report Engine
 *
 * Generates CISO-grade executive reports + revenue/MRR dashboards.
 * Aggregates data from org-memory, auto-defense, SIEM, threat-confidence.
 *
 * Endpoints:
 *   GET  /api/executive/dashboard   → CISO live dashboard payload
 *   GET  /api/executive/mrr         → MRR + revenue metrics
 *   POST /api/executive/report      → generate + store PDF-ready report
 *   GET  /api/executive/reports     → list stored reports
 *   GET  /api/executive/report/:id  → fetch specific report
 */

import { ok, fail } from '../lib/response.js';

const KV_MRR_KEY        = 'executive:mrr_config';
const KV_REPORTS_PREFIX = 'executive:report:';
const KV_REPORTS_INDEX  = 'executive:reports_index';
const DEFAULT_ORG       = 'default';

function getOrgId(authCtx) {
  return authCtx?.orgId || authCtx?.userId || DEFAULT_ORG;
}

// ── MRR & Revenue Calculation ─────────────────────────────────────────────────
const PLAN_PRICES = {
  FREE:       0,
  PRO:        49,
  ENTERPRISE: 499,
  MSSP:       999,
};

async function getMRRData(env, orgId) {
  let mrrConfig = {};
  if (env?.SECURITY_HUB_KV) {
    try { mrrConfig = (await env.SECURITY_HUB_KV.get(KV_MRR_KEY, { type: 'json' })) || {}; } catch {}
  }

  // Default demo data — in production this integrates with billing system
  const {
    free_users       = 120,
    pro_users        = 34,
    enterprise_users = 7,
    mssp_clients     = 2,
    api_revenue_monthly = 820,
    churn_rate       = 3.2,
    new_signups_30d  = 18,
    conversions_30d  = 4,
  } = mrrConfig;

  const mrr_subscriptions =
    (free_users * PLAN_PRICES.FREE) +
    (pro_users * PLAN_PRICES.PRO) +
    (enterprise_users * PLAN_PRICES.ENTERPRISE) +
    (mssp_clients * PLAN_PRICES.MSSP);

  const mrr_total  = mrr_subscriptions + api_revenue_monthly;
  const arr        = mrr_total * 12;
  const conversion_rate = new_signups_30d > 0
    ? parseFloat(((conversions_30d / new_signups_30d) * 100).toFixed(1))
    : 0;

  return {
    mrr_total,
    mrr_subscriptions,
    mrr_api:            api_revenue_monthly,
    arr,
    user_breakdown: {
      free:       free_users,
      pro:        pro_users,
      enterprise: enterprise_users,
      mssp:       mssp_clients,
    },
    total_paying:     pro_users + enterprise_users + mssp_clients,
    total_users:      free_users + pro_users + enterprise_users + mssp_clients,
    churn_rate,
    new_signups_30d,
    conversions_30d,
    conversion_rate,
    ltv_estimate:     Math.round((mrr_subscriptions / Math.max(1, pro_users + enterprise_users + mssp_clients)) * (100 / Math.max(1, churn_rate)) * 12),
    revenue_per_user: parseFloat((mrr_total / Math.max(1, pro_users + enterprise_users + mssp_clients)).toFixed(2)),
    growth_nudge:     conversion_rate < 10 ? 'Consider adding free → pro feature triggers to improve conversion above 10%.' : null,
  };
}

// ── Security Posture Aggregation ──────────────────────────────────────────────
async function getSecurityPosture(env, orgId) {
  let posture = {
    threats_blocked:    0,
    rules_deployed:     0,
    critical_open:      0,
    mean_time_to_detect: null,
    mean_time_to_respond: null,
    siem_integrations:  0,
    auto_defense_mode:  'UNKNOWN',
    compliance_score:   0,
    top_threats:        [],
    event_count:        0,
  };

  if (!env?.SECURITY_HUB_KV) return posture;

  try {
    // Load defense posture
    const dp = await env.SECURITY_HUB_KV.get(`defense:posture:${orgId}`, { type: 'json' });
    if (dp) {
      posture.threats_blocked   = dp.total_executions || 0;
      posture.rules_deployed    = dp.rules_deployed || 0;
      posture.auto_defense_mode = dp.mode || 'SAFE';
    }
  } catch {}

  try {
    // Load org memory patterns
    const patterns = await env.SECURITY_HUB_KV.get(`org_memory:patterns:${orgId}`, { type: 'json' });
    if (patterns) {
      posture.critical_open  = patterns.critical_count || 0;
      posture.event_count    = patterns.total_events || 0;
      posture.top_threats    = (patterns.top_threats || []).slice(0, 5);
      posture.attack_trend   = patterns.attack_trend || 'STABLE';
    }
  } catch {}

  try {
    // Count SIEM integrations
    const siemKeys = await env.SECURITY_HUB_KV.list({ prefix: `siem_config:${orgId}:` });
    posture.siem_integrations = siemKeys.keys?.length || 0;
  } catch {}

  // Compliance score heuristic
  posture.compliance_score = Math.min(100, Math.round(
    (posture.siem_integrations * 10) +
    (posture.rules_deployed * 2) +
    (posture.auto_defense_mode === 'AGGRESSIVE' ? 25 : posture.auto_defense_mode === 'ASSISTED' ? 15 : 5) +
    (posture.threats_blocked * 3)
  ));

  // MTTD/MTTR estimates based on defense mode
  const modeTimings = {
    AGGRESSIVE: { mttd: 2,  mttr: 8  },
    ASSISTED:   { mttd: 15, mttr: 60 },
    SAFE:       { mttd: 60, mttr: 240 },
    UNKNOWN:    { mttd: 120, mttr: 480 },
  };
  const timings = modeTimings[posture.auto_defense_mode] || modeTimings['UNKNOWN'];
  posture.mean_time_to_detect  = timings.mttd;
  posture.mean_time_to_respond = timings.mttr;

  return posture;
}

// ── Risk Summary ──────────────────────────────────────────────────────────────
function buildRiskSummary(posture, mrr) {
  const findings = [];

  if (posture.critical_open >= 5) {
    findings.push({
      severity: 'CRITICAL',
      finding:  `${posture.critical_open} open CRITICAL severity events require immediate incident response.`,
      impact:   'Potential for data breach, ransomware deployment, or service disruption.',
      action:   'Engage MYTHOS AI Analyst to generate and deploy detection rules.',
    });
  }
  if (posture.siem_integrations === 0) {
    findings.push({
      severity: 'HIGH',
      finding:  'No SIEM integrations configured.',
      impact:   'Manual response required for all threat events — MTTR is 8–12× higher.',
      action:   'Configure at least one SIEM integration (Splunk, Elastic, Sentinel).',
    });
  }
  if (posture.auto_defense_mode === 'SAFE' || posture.auto_defense_mode === 'UNKNOWN') {
    findings.push({
      severity: 'MEDIUM',
      finding:  'Auto-Defense is in SAFE mode — no autonomous rule deployment active.',
      impact:   'Threat response depends entirely on manual analyst actions.',
      action:   'Upgrade to ASSISTED or AGGRESSIVE mode to reduce MTTR.',
    });
  }
  if (posture.attack_trend === 'INCREASING') {
    findings.push({
      severity: 'HIGH',
      finding:  'Attack volume is trending upward month-over-month.',
      impact:   'Increased attack surface exposure without proportional detection capacity.',
      action:   'Consider enabling Autonomous SOC continuous monitoring.',
    });
  }
  if (mrr.conversion_rate < 5) {
    findings.push({
      severity: 'BUSINESS',
      finding:  `Conversion rate is ${mrr.conversion_rate}% — below the 10% target.`,
      impact:   `Estimated lost MRR: ~$${Math.round((mrr.total_users * 0.1 - mrr.conversions_30d) * PLAN_PRICES.PRO)}/mo.`,
      action:   'Implement in-product upgrade nudges on critical threat detection.',
    });
  }

  const risk_score = Math.min(100, findings.reduce((s, f) => {
    return s + ({ CRITICAL: 30, HIGH: 20, MEDIUM: 10, BUSINESS: 5 }[f.severity] || 0);
  }, 0));

  return { findings, risk_score, risk_level: risk_score >= 60 ? 'HIGH' : risk_score >= 30 ? 'MEDIUM' : 'LOW' };
}

// ── GET /api/executive/dashboard ─────────────────────────────────────────────
export async function handleGetDashboard(request, env, authCtx = {}) {
  const orgId   = getOrgId(authCtx);
  const [posture, mrr] = await Promise.all([
    getSecurityPosture(env, orgId),
    getMRRData(env, orgId),
  ]);
  const riskSummary = buildRiskSummary(posture, mrr);

  return ok(request, {
    org_id:           orgId,
    generated_at:     new Date().toISOString(),
    security_posture: posture,
    revenue:          mrr,
    risk_summary:     riskSummary,
    kpis: {
      threats_blocked:         posture.threats_blocked,
      rules_deployed:          posture.rules_deployed,
      compliance_score:        posture.compliance_score,
      mttd_minutes:            posture.mean_time_to_detect,
      mttr_minutes:            posture.mean_time_to_respond,
      mrr_total:               mrr.mrr_total,
      arr:                     mrr.arr,
      paying_customers:        mrr.total_paying,
      conversion_rate:         mrr.conversion_rate,
    },
  });
}

// ── GET /api/executive/mrr ───────────────────────────────────────────────────
export async function handleGetMRR(request, env, authCtx = {}) {
  const orgId = getOrgId(authCtx);
  const tier  = authCtx?.tier || 'FREE';
  if (!['ENTERPRISE', 'MSSP'].includes(tier)) {
    return fail(request, 'MRR dashboard requires ENTERPRISE or MSSP plan', 403, 'PLAN_REQUIRED');
  }
  const mrr = await getMRRData(env, orgId);
  return ok(request, { org_id: orgId, ...mrr, fetched_at: new Date().toISOString() });
}

// ── POST /api/executive/mrr/config ───────────────────────────────────────────
export async function handleSetMRRConfig(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  if (!['ENTERPRISE', 'MSSP'].includes(tier)) {
    return fail(request, 'MRR configuration requires ENTERPRISE or MSSP plan', 403, 'PLAN_REQUIRED');
  }
  let body = {};
  try { body = await request.json(); } catch {}

  const allowed = ['free_users','pro_users','enterprise_users','mssp_clients',
                   'api_revenue_monthly','churn_rate','new_signups_30d','conversions_30d'];
  const config = {};
  for (const key of allowed) {
    if (body[key] !== undefined) config[key] = parseFloat(body[key]) || 0;
  }

  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(KV_MRR_KEY, JSON.stringify(config), { expirationTtl: 86400 * 365 });
  }
  return ok(request, { updated: true, config });
}

// ── POST /api/executive/report ───────────────────────────────────────────────
export async function handleGenerateReport(request, env, authCtx = {}) {
  const orgId   = getOrgId(authCtx);
  const tier    = authCtx?.tier || 'FREE';
  if (tier === 'FREE') {
    return fail(request, 'Executive report generation requires PRO or higher', 403, 'PLAN_REQUIRED');
  }

  let body = {};
  try { body = await request.json(); } catch {}
  const { report_type = 'monthly', period_label = null } = body;

  const [posture, mrr] = await Promise.all([
    getSecurityPosture(env, orgId),
    getMRRData(env, orgId),
  ]);
  const riskSummary = buildRiskSummary(posture, mrr);

  const now     = new Date();
  const reportId = `rpt_${now.getTime()}_${Math.random().toString(36).slice(2, 6)}`;
  const label    = period_label || now.toISOString().slice(0, 7);

  const report = {
    id:            reportId,
    org_id:        orgId,
    report_type,
    period:        label,
    generated_at:  now.toISOString(),
    generated_by:  authCtx?.email || 'system',
    executive_summary: buildExecutiveSummary(posture, mrr, riskSummary),
    security_posture:  posture,
    revenue:           mrr,
    risk_summary:      riskSummary,
    kpis: {
      threats_blocked:   posture.threats_blocked,
      rules_deployed:    posture.rules_deployed,
      compliance_score:  posture.compliance_score,
      mttd_minutes:      posture.mean_time_to_detect,
      mttr_minutes:      posture.mean_time_to_respond,
      mrr_total:         mrr.mrr_total,
      arr:               mrr.arr,
      paying_customers:  mrr.total_paying,
    },
    recommendations: riskSummary.findings.map(f => `[${f.severity}] ${f.action}`),
  };

  // Persist report
  if (env?.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(
      `${KV_REPORTS_PREFIX}${orgId}:${reportId}`,
      JSON.stringify(report),
      { expirationTtl: 86400 * 365 }
    );
    // Update index
    let index = [];
    try { index = (await env.SECURITY_HUB_KV.get(`${KV_REPORTS_INDEX}:${orgId}`, { type: 'json' })) || []; } catch {}
    index.unshift({ id: reportId, period: label, type: report_type, generated_at: report.generated_at });
    index = index.slice(0, 50);
    await env.SECURITY_HUB_KV.put(`${KV_REPORTS_INDEX}:${orgId}`, JSON.stringify(index), { expirationTtl: 86400 * 365 });
  }

  return ok(request, { generated: true, report_id: reportId, report });
}

function buildExecutiveSummary(posture, mrr, risk) {
  const lines = [];
  lines.push(`During this period, the CYBERDUDEBIVASH AI Security Hub detected and processed **${posture.event_count} security events** across the organization.`);
  if (posture.threats_blocked > 0) {
    lines.push(`The Autonomous Defense Engine executed **${posture.threats_blocked} automated defense actions**, deploying **${posture.rules_deployed} detection rules** to configured SIEM platforms.`);
  }
  lines.push(`Current compliance posture score: **${posture.compliance_score}/100**. Mean time to detect: **${posture.mean_time_to_detect} minutes**. Mean time to respond: **${posture.mean_time_to_respond} minutes**.`);
  if (mrr.mrr_total > 0) {
    lines.push(`Platform revenue: **$${mrr.mrr_total.toLocaleString()}/month** (ARR: $${mrr.arr.toLocaleString()}). Paying customers: **${mrr.total_paying}** across ${mrr.user_breakdown.pro} PRO, ${mrr.user_breakdown.enterprise} ENTERPRISE, and ${mrr.user_breakdown.mssp} MSSP accounts.`);
  }
  lines.push(`Risk assessment: **${risk.risk_level}** (score: ${risk.risk_score}/100). ${risk.findings.length} actionable finding${risk.findings.length !== 1 ? 's' : ''} identified.`);
  return lines.join('\n\n');
}

// ── GET /api/executive/reports ───────────────────────────────────────────────
export async function handleListReports(request, env, authCtx = {}) {
  const orgId = getOrgId(authCtx);
  const tier  = authCtx?.tier || 'FREE';
  if (tier === 'FREE') {
    return fail(request, 'Report history requires PRO or higher', 403, 'PLAN_REQUIRED');
  }

  let index = [];
  if (env?.SECURITY_HUB_KV) {
    try { index = (await env.SECURITY_HUB_KV.get(`${KV_REPORTS_INDEX}:${orgId}`, { type: 'json' })) || []; } catch {}
  }
  return ok(request, { org_id: orgId, total: index.length, reports: index });
}

// ── GET /api/executive/report/:id ────────────────────────────────────────────
export async function handleGetReport(request, env, authCtx = {}) {
  const orgId    = getOrgId(authCtx);
  const url      = new URL(request.url);
  const reportId = url.pathname.split('/').pop();

  if (!reportId || !reportId.startsWith('rpt_')) {
    return fail(request, 'Invalid report ID', 400, 'INVALID_ID');
  }

  let report = null;
  if (env?.SECURITY_HUB_KV) {
    try { report = await env.SECURITY_HUB_KV.get(`${KV_REPORTS_PREFIX}${orgId}:${reportId}`, { type: 'json' }); } catch {}
  }
  if (!report) return fail(request, 'Report not found', 404, 'NOT_FOUND');
  return ok(request, report);
}
