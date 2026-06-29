/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * reliabilityEngineering.js — Platform Reliability Command Center
 *
 * APIs:
 *   GET  /api/reliability/sla          SLA report (enterprise+)
 *   GET  /api/reliability/error-budget error budget consumption (admin)
 *   GET  /api/reliability/capacity     capacity metrics (admin)
 *   GET  /api/reliability/incidents    reliability incident history (enterprise+)
 *   POST /api/reliability/incident     report reliability incident (admin)
 */

// SLA targets (availability % per service)
const SLA_TARGETS = {
  'Scan API':       { availability: 99.9, latency_p99_ms: 3000 },
  'Auth API':       { availability: 99.95, latency_p99_ms: 500 },
  'Dashboard SSE':  { availability: 99.5, latency_p99_ms: 1000 },
  'D1 Database':    { availability: 99.9, latency_p99_ms: 200 },
  'KV Cache':       { availability: 99.99, latency_p99_ms: 50 },
  'R2 Storage':     { availability: 99.9, latency_p99_ms: 500 },
  'CTI Workbench':  { availability: 99.9, latency_p99_ms: 1000 },
  'SOC Platform':   { availability: 99.9, latency_p99_ms: 800 },
  'MSSP API':       { availability: 99.9, latency_p99_ms: 1000 },
};

const MONTH_MINUTES = 30 * 24 * 60; // 43,200 min/month

function calcErrorBudget(slaTarget) {
  const allowedDowntime = MONTH_MINUTES * (1 - slaTarget / 100);
  return { total_minutes: allowedDowntime, sla_pct: slaTarget };
}

function requireRole(req, roles) {
  if (!req.user) return false;
  return roles.includes(req.user.role) || roles.includes(req.user.tier);
}

function genId() { return 'rel_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

export async function handleSLAReport(req, env) {
  if (!requireRole(req, ['admin', 'mssp_admin', 'enterprise'])) {
    return Response.json({ error: 'Enterprise plan required' }, { status: 403 });
  }

  const cacheKey = 'reliability_sla_v3';
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ ...cached, cached: true });

  try {
    // Use deep health probe data as proxy for availability measurement
    const probeHistory = await env.KV?.get('deep_health_v2', 'json').catch(() => null);

    // Compute SLA per service from probe data (or use synthetic data if no history)
    const services = Object.entries(SLA_TARGETS).map(([name, target]) => {
      // Real probe data would come from a ring buffer; here we use last probe result
      const probeStatus = probeHistory?.checks?.[name.toLowerCase().replace(/\s/g,'_')]?.status || 'healthy';
      const measured = probeStatus === 'healthy' ? target.availability : target.availability - 0.5;

      const budget = calcErrorBudget(target.availability);
      const consumed = Math.max(0, (target.availability - measured) / (100 - target.availability) * 100);

      return {
        service: name,
        sla_target: target.availability,
        measured_availability: measured,
        latency_target_ms: target.latency_p99_ms,
        error_budget_minutes: budget.total_minutes,
        error_budget_consumed_pct: Math.round(consumed),
        status: consumed < 25 ? 'HEALTHY' : consumed < 75 ? 'AT_RISK' : 'CRITICAL',
      };
    });

    const report = {
      period: '30d',
      generated_at: new Date().toISOString(),
      overall_sla: services.every(s => s.status === 'HEALTHY') ? 'COMPLIANT' : 'AT_RISK',
      services,
      total_error_budget_minutes: services.reduce((a, s) => a + s.error_budget_minutes, 0),
      critical_services: services.filter(s => s.status === 'CRITICAL').length,
    };

    await env.KV?.put(cacheKey, JSON.stringify(report), { expirationTtl: 60 }).catch(() => null);
    return Response.json(report);
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleErrorBudget(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  const budgets = Object.entries(SLA_TARGETS).map(([name, target]) => {
    const budget = calcErrorBudget(target.availability);
    return {
      service: name,
      sla_target_pct: target.availability,
      monthly_budget_minutes: Math.round(budget.total_minutes * 10) / 10,
      monthly_budget_seconds: Math.round(budget.total_minutes * 60),
      remaining_pct: 100, // Would be computed from actual outage history
      status: 'FULL',
    };
  });

  return Response.json({
    error_budgets: budgets,
    period: 'current_month',
    month: new Date().toISOString().slice(0, 7),
    note: 'Error budgets reset monthly. Consumption requires outage event tracking.',
  });
}

export async function handleCapacityMetrics(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  try {
    // Count rows in key tables as capacity proxy
    const [scanRows, caseRows, iocRows, eventRows, userRows] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM scan_results`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM soc_cases`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM cti_iocs`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM analytics_events`).first().catch(() => ({ cnt: 0 })),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM users`).first().catch(() => ({ cnt: 0 })),
    ]);

    const D1_ROW_LIMIT = 100_000; // Conservative D1 limit per table

    const metrics = {
      d1_tables: [
        { table: 'scan_results',    rows: scanRows?.cnt ?? 0,  limit: D1_ROW_LIMIT, pct: Math.round((scanRows?.cnt ?? 0) / D1_ROW_LIMIT * 100) },
        { table: 'soc_cases',       rows: caseRows?.cnt ?? 0,  limit: D1_ROW_LIMIT, pct: Math.round((caseRows?.cnt ?? 0) / D1_ROW_LIMIT * 100) },
        { table: 'cti_iocs',        rows: iocRows?.cnt ?? 0,   limit: D1_ROW_LIMIT, pct: Math.round((iocRows?.cnt ?? 0) / D1_ROW_LIMIT * 100) },
        { table: 'analytics_events',rows: eventRows?.cnt ?? 0, limit: D1_ROW_LIMIT, pct: Math.round((eventRows?.cnt ?? 0) / D1_ROW_LIMIT * 100) },
        { table: 'users',           rows: userRows?.cnt ?? 0,  limit: D1_ROW_LIMIT, pct: Math.round((userRows?.cnt ?? 0) / D1_ROW_LIMIT * 100) },
      ],
      worker_limits: {
        cpu_ms_per_request: '30000ms (Unbound)',
        memory_mb: '128MB',
        request_concurrency: 'Unlimited (Cloudflare edge)',
      },
      recommendations: [],
      generated_at: new Date().toISOString(),
    };

    // Generate capacity warnings
    metrics.d1_tables.forEach(t => {
      if (t.pct > 75) metrics.recommendations.push(`${t.table} at ${t.pct}% capacity — enable auto-pruning`);
    });
    if (!metrics.recommendations.length) metrics.recommendations.push('All tables within normal capacity bounds');

    return Response.json(metrics);
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

export async function handleListIncidents(req, env) {
  if (!requireRole(req, ['admin', 'enterprise'])) {
    return Response.json({ error: 'Enterprise plan required' }, { status: 403 });
  }

  // Use SOC cases with source='reliability' as reliability incidents
  const rows = await env.DB.prepare(
    `SELECT id, case_number, title, severity, status, created_at, resolved_at
     FROM soc_cases WHERE source = 'reliability' ORDER BY created_at DESC LIMIT 20`
  ).all().catch(() => ({ results: [] }));

  return Response.json({ incidents: rows.results || [], total: (rows.results || []).length });
}

export async function handleCreateIncident(req, env) {
  if (!requireRole(req, ['admin'])) {
    return Response.json({ error: 'Admin required' }, { status: 403 });
  }

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { title, severity = 'HIGH', summary = '' } = body;
  if (!title) return Response.json({ error: 'title required' }, { status: 400 });

  const caseId = genId();
  const caseNum = `REL-${new Date().toISOString().slice(2,7).replace('-','')}-${crypto.randomUUID().slice(0,4).toUpperCase()}`;
  const orgId = req.user.org_id || 'default';

  await env.DB.prepare(
    `INSERT INTO soc_cases (id, case_number, title, severity, status, source, org_id, summary, sla_hours, created_at, updated_at)
     VALUES (?,?,?,?,'OPEN','reliability',?,?,4,datetime('now'),datetime('now'))`
  ).bind(caseId, caseNum, title, severity, orgId, summary).run();

  return Response.json({ success: true, incident_id: caseId, case_number: caseNum, title, severity });
}
