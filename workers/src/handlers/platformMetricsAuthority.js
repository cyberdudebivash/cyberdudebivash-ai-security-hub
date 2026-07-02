import { isRealUser } from '../auth/middleware.js';
/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * Platform Metrics Authority — /api/authority/*
 *
 * THE single source of truth for all dashboard KPIs.
 * Eliminates data inconsistency by aggregating from D1 once per minute
 * and serving all widgets from the same KV snapshot.
 *
 * Cache: KV key "pma:snapshot:{orgId}" TTL=60s
 * Fallback: Reads D1 directly if KV miss
 */

const PMA_TTL       = 60;   // seconds
const PMA_KV_PREFIX = 'pma:snapshot:';
const GLOBAL_KEY    = 'pma:snapshot:__global__';

function genId() {
  return `pma_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function requireAdmin(authCtx) {
  return authCtx?.role === 'admin';
}

function requireAuth(authCtx) {
  return isRealUser(authCtx);
}

// ─── Core aggregation logic ───────────────────────────────────────────────────
async function computeSnapshot(env, orgId, isAdmin) {
  const isGlobal = orgId === '__global__';

  // Helper: run a D1 count query safely
  async function count(sql, params = []) {
    try {
      const r = await env.SECURITY_HUB_DB.prepare(sql).bind(...params).first();
      return r ? (r.cnt ?? r.count ?? 0) : 0;
    } catch { return 0; }
  }

  const todayStr = today();

  // Build WHERE clause for org scoping
  const orgFilter  = isGlobal ? '' : 'AND org_id = ?';
  const orgParam   = isGlobal ? [] : [orgId];

  const [
    scansToday,
    scans30d,
    criticalCves,
    openCases,
    criticalCases,
    activeThreats,
    threatActors,
    customerCount,
    latestHealth,
    latestMRR,
  ] = await Promise.allSettled([
    count(`SELECT COUNT(*) cnt FROM scan_results WHERE DATE(created_at) = ? ${orgFilter}`, [todayStr, ...orgParam]),
    count(`SELECT COUNT(*) cnt FROM scan_results WHERE created_at >= datetime('now','-30 days') ${orgFilter}`, [...orgParam]),
    count(`SELECT COUNT(*) cnt FROM scan_results WHERE severity = 'CRITICAL' AND DATE(created_at) = ? ${orgFilter}`, [todayStr, ...orgParam]),
    count(`SELECT COUNT(*) cnt FROM soc_cases WHERE status NOT IN ('CLOSED','RESOLVED') ${orgFilter}`, [...orgParam]),
    count(`SELECT COUNT(*) cnt FROM soc_cases WHERE severity = 'CRITICAL' AND status IN ('OPEN','INVESTIGATING') ${orgFilter}`, [...orgParam]),
    count(`SELECT COUNT(*) cnt FROM cti_iocs WHERE confidence_score >= 70 ${orgFilter}`, [...orgParam]),
    count('SELECT COUNT(*) cnt FROM cti_actors'),
    isAdmin || isGlobal
      ? count('SELECT COUNT(DISTINCT org_id) cnt FROM users')
      : Promise.resolve(1),
    (async () => {
      try {
        const r = await env.SECURITY_HUB_DB.prepare(
          `SELECT health_score FROM customer_health WHERE org_id = ? ORDER BY updated_at DESC LIMIT 1`
        ).bind(orgId === '__global__' ? 'default' : orgId).first();
        return r?.health_score ?? 100;
      } catch { return 100; }
    })(),
    (async () => {
      try {
        const r = await env.SECURITY_HUB_DB.prepare(
          `SELECT mrr FROM revenue_snapshots ORDER BY snapshot_date DESC LIMIT 1`
        ).first();
        return r?.mrr ?? 0;
      } catch { return 0; }
    })(),
  ]).then(results => results.map(r => r.status === 'fulfilled' ? r.value : 0));

  // Compute error budget status from reliability targets
  // Scan API target: 99.9% — 43,200 * (1 - 0.999) = 43.2 min budget/month
  // Rough computation: if open_cases > 10, consider budget stressed
  const budgetAlert = criticalCases > 5 ? 'WARNING' : criticalCases > 15 ? 'CRITICAL' : null;

  const mrr = latestMRR || 0;

  return {
    scans_today:      scansToday,
    scans_30d:        scans30d,
    critical_cves:    criticalCves,
    open_cases:       openCases,
    critical_cases:   criticalCases,
    active_threats:   activeThreats,
    threat_actors:    threatActors,
    customer_count:   customerCount,
    health_score:     latestHealth,
    platform_status:  criticalCases > 10 ? 'degraded' : 'operational',
    platform_degraded: criticalCases > 10,
    mrr,
    arr:              mrr * 12,
    budget_alert:     budgetAlert,
    computed_at:      new Date().toISOString(),
    valid_until:      new Date(Date.now() + PMA_TTL * 1000).toISOString(),
    org_id:           orgId,
  };
}

// ─── GET /api/authority/metrics ───────────────────────────────────────────────
export async function handleGetMetrics(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const url    = new URL(request.url);
  const isAdmin = requireAdmin(authCtx);

  // mssp_admin can request another org's snapshot
  let orgId = authCtx.org_id || 'default';
  if ((isAdmin || authCtx.role === 'mssp_admin') && url.searchParams.get('org_id')) {
    orgId = url.searchParams.get('org_id');
  }
  if (isAdmin && url.searchParams.get('global') === 'true') {
    orgId = '__global__';
  }

  const kvKey = PMA_KV_PREFIX + orgId;

  // 1. Try KV cache
  try {
    const cached = await env.SECURITY_HUB_KV.get(kvKey, { type: 'json' });
    if (cached && new Date(cached.valid_until) > new Date()) {
      return Response.json({ metrics: cached, source: 'cache' });
    }
  } catch (_) {}

  // 2. Compute from D1
  const snapshot = await computeSnapshot(env, orgId, isAdmin);

  // 3. Write to KV (non-blocking)
  try {
    await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(snapshot), { expirationTtl: PMA_TTL });
  } catch (_) {}

  // 4. Write fallback to D1
  try {
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO platform_metrics_snapshots
         (id, org_id, scans_today, scans_30d, critical_cves, open_cases, critical_cases,
          active_threats, threat_actors, customer_count, health_score, platform_status,
          mrr, arr, budget_alert, computed_at, valid_until)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(org_id) DO UPDATE SET
         scans_today=excluded.scans_today, scans_30d=excluded.scans_30d,
         critical_cves=excluded.critical_cves, open_cases=excluded.open_cases,
         critical_cases=excluded.critical_cases, active_threats=excluded.active_threats,
         threat_actors=excluded.threat_actors, customer_count=excluded.customer_count,
         health_score=excluded.health_score, platform_status=excluded.platform_status,
         mrr=excluded.mrr, arr=excluded.arr, budget_alert=excluded.budget_alert,
         computed_at=excluded.computed_at, valid_until=excluded.valid_until`
    ).bind(
      genId(), snapshot.org_id, snapshot.scans_today, snapshot.scans_30d,
      snapshot.critical_cves, snapshot.open_cases, snapshot.critical_cases,
      snapshot.active_threats, snapshot.threat_actors, snapshot.customer_count,
      snapshot.health_score, snapshot.platform_status, snapshot.mrr, snapshot.arr,
      snapshot.budget_alert, snapshot.computed_at, snapshot.valid_until
    ).run();
  } catch (_) {}

  return Response.json({ metrics: snapshot, source: 'computed' });
}

// ─── POST /api/authority/refresh ─────────────────────────────────────────────
// Admin-only: flush KV cache and force recompute
export async function handleRefreshMetrics(request, env) {
  const authCtx = request.user || {};
  if (!requireAdmin(authCtx)) {
    return Response.json({ error: 'Admin access required' }, { status: 403 });
  }

  const url   = new URL(request.url);
  const orgId = url.searchParams.get('org_id') || authCtx.org_id || 'default';
  const all   = url.searchParams.get('all') === 'true';

  if (all) {
    // Flush global key; individual org keys expire naturally
    try { await env.SECURITY_HUB_KV.delete(GLOBAL_KEY); } catch (_) {}
    return Response.json({ success: true, flushed: 'all' });
  }

  const kvKey = PMA_KV_PREFIX + orgId;
  try { await env.SECURITY_HUB_KV.delete(kvKey); } catch (_) {}

  // Immediate recompute
  const snapshot = await computeSnapshot(env, orgId, true);
  try {
    await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(snapshot), { expirationTtl: PMA_TTL });
  } catch (_) {}

  return Response.json({ success: true, metrics: snapshot, flushed: orgId });
}

// ─── GET /api/authority/history ──────────────────────────────────────────────
// Returns D1 snapshot history for trend sparklines
export async function handleMetricsHistory(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const url    = new URL(request.url);
  const days   = Math.min(parseInt(url.searchParams.get('days') || '7'), 30);
  const orgId  = authCtx.role === 'admin' && url.searchParams.get('org_id')
    ? url.searchParams.get('org_id')
    : (authCtx.org_id || 'default');

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT scans_today, open_cases, critical_cases, mrr, health_score, platform_status, computed_at
       FROM platform_metrics_snapshots
       WHERE org_id = ? AND computed_at >= datetime('now', ? || ' days')
       ORDER BY computed_at ASC`
    ).bind(orgId, `-${days}`).all();

    return Response.json({ history: rows.results || [], days, org_id: orgId });
  } catch (e) {
    return Response.json({ history: [], error: e.message });
  }
}

// ─── GET /api/authority/status ────────────────────────────────────────────────
// Lightweight liveness check — returns platform_status without full compute
export async function handlePlatformStatus(request, env) {
  try {
    const kvKey = PMA_KV_PREFIX + (request.user?.org_id || 'default');
    const cached = await env.SECURITY_HUB_KV.get(kvKey, { type: 'json' });
    if (cached) {
      return Response.json({
        status: cached.platform_status,
        degraded: cached.platform_degraded,
        budget_alert: cached.budget_alert,
        computed_at: cached.computed_at,
      });
    }
  } catch (_) {}

  return Response.json({ status: 'unknown', degraded: false, budget_alert: null });
}
