/**
 * CYBERDUDEBIVASH® — EOP v1.0 — Health Handler (Phase 1 + 2)
 *
 * GET /api/platform/health          — enhanced public health check
 * GET /api/platform/health/detailed — full ops diagnostics (admin-only)
 *
 * Schema:
 * {
 *   status: 'operational' | 'degraded' | 'partial_outage' | 'critical',
 *   severity: 'none' | 'low' | 'medium' | 'high',
 *   version, build_id, deploy_id, environment, timestamp, response_ms,
 *   summary: { healthy, degraded, unhealthy, unknown, total },
 *   components: [{ name, type, status, latency_ms, detail? }]
 * }
 */

import { Alerts } from '../../lib/alertEngine.js';
import { withRetry } from '../../lib/resilience.js';

const LATENCY_WARN_MS = 1000; // flag as degraded if any component exceeds this
// D1 occasionally returns a transient "requests queued for too long" overload
// error under concurrent load (verified live) that clears within seconds —
// each probe retries once before reporting the component unhealthy, so a
// momentary blip doesn't get permanently baked into operational_history's
// rolling 24h uptime stats (recordHistory below) or trip the public status page.
const D1_PROBE_RETRIES = 2;
const D1_PROBE_BACKOFF_MS = 150;

// ─── Phase 1: Enhanced public health ─────────────────────────────────────────
export async function handleHealthV2(request, env) {
  const t0 = Date.now();

  const [worker, db, kv, r2, intel, payments, auth, scheduler, queue] = await Promise.all([
    probeWorker(),
    probeD1(env),
    probeKV(env),
    probeR2(env),
    probeIntel(env),
    probePayments(env),
    probeAuth(env),
    probeScheduler(env),
    probeQueue(env),
  ]);

  const components = [worker, db, kv, r2, intel, payments, auth, scheduler, queue];
  const { status, severity } = deriveStatus(components);

  // Fire async alerts for unhealthy components (non-blocking)
  fireAlerts(env, components);

  // Record to operational_history (non-blocking)
  recordHistory(env, components, status);

  return Response.json({
    status,
    severity,
    version:      env.VERSION || '40.0.0',
    build_id:     env.COMMIT || 'unknown',
    environment:  env.ENVIRONMENT || 'production',
    timestamp:    new Date().toISOString(),
    response_ms:  Date.now() - t0,
    summary: {
      healthy:   components.filter(c => c.status === 'operational').length,
      degraded:  components.filter(c => c.status === 'degraded').length,
      unhealthy: components.filter(c => c.status === 'partial_outage' || c.status === 'major_outage').length,
      unknown:   components.filter(c => c.status === 'unknown').length,
      total:     components.length,
    },
    components,
  }, { headers: { 'Cache-Control': 'no-store' } });
}

// ─── Phase 2: Detailed ops diagnostics (admin-only) ──────────────────────────
export async function handleHealthDetailed(request, env, authCtx) {
  // `authCtx.admin` (no "is" prefix) is never set anywhere — the real field
  // is `authCtx.isAdmin`. Not a live gap in practice: every admin path
  // (ADMIN_KEY, RBAC SUPERADMIN) also sets tier: 'ENTERPRISE', which already
  // passes the primary condition below — but fixing for correctness/clarity.
  if (!authCtx?.authenticated || authCtx?.tier !== 'ENTERPRISE' && !authCtx?.isAdmin) {
    // Allow owner + admin; block public
    const isOwner = authCtx?.isAdmin ||
      (env.OWNER_EMAIL && authCtx?.email === env.OWNER_EMAIL);
    if (!isOwner) {
      return Response.json({ error: 'Admin access required' }, { status: 403 });
    }
  }

  const t0 = Date.now();

  const [worker, db, kv, r2, intel, payments, auth, scheduler, queue] = await Promise.all([
    probeWorker(),
    probeD1(env),
    probeKV(env),
    probeR2(env),
    probeIntel(env),
    probePayments(env),
    probeAuth(env),
    probeScheduler(env),
    probeQueue(env),
  ]);

  const components = [worker, db, kv, r2, intel, payments, auth, scheduler, queue];
  const { status, severity } = deriveStatus(components);

  // Fetch recent errors + alert history in parallel
  const [recentErrors, recentAlerts, lastDeployment, uptimeSummary, activeIncidents] = await Promise.all([
    fetchRecentErrors(env, 20),
    fetchRecentAlerts(env, 10),
    fetchLastDeployment(env),
    fetchUptimeSummary(env),
    fetchActiveIncidents(env),
  ]);

  return Response.json({
    status,
    severity,
    version:          env.VERSION || '40.0.0',
    build_id:         env.COMMIT || 'unknown',
    environment:      env.ENVIRONMENT || 'production',
    timestamp:        new Date().toISOString(),
    response_ms:      Date.now() - t0,
    summary: {
      healthy:   components.filter(c => c.status === 'operational').length,
      degraded:  components.filter(c => c.status === 'degraded').length,
      unhealthy: components.filter(c => c.status === 'partial_outage' || c.status === 'major_outage').length,
      unknown:   components.filter(c => c.status === 'unknown').length,
      total:     components.length,
    },
    components,
    deployment: lastDeployment,
    uptime:     uptimeSummary,
    active_incidents: activeIncidents,
    recent_errors: recentErrors,
    recent_alerts: recentAlerts,
    platform_capabilities: {
      mfa:              true,
      sso_oidc:         true,
      multi_tenant:     true,
      razorpay_payments: true,
      threat_intel:     true,
      ai_copilot:       true,
      scan_engine:      true,
      api_keys:         true,
    },
  });
}

// ─── Component probes ─────────────────────────────────────────────────────────

function probeWorker() {
  return { name: 'Worker', type: 'compute', status: 'operational', latency_ms: 0, detail: 'executing' };
}

export async function probeD1(env) {
  if (!env.DB) return { name: 'D1 Database', type: 'database', status: 'major_outage', latency_ms: -1, error: 'binding_missing' };
  const t0 = Date.now();
  try {
    const row = await withRetry(
      () => env.DB.prepare('SELECT 1 AS alive').first(),
      D1_PROBE_RETRIES, D1_PROBE_BACKOFF_MS, 'eop:probeD1'
    );
    const latency = Date.now() - t0;
    const status = row?.alive === 1
      ? (latency > LATENCY_WARN_MS ? 'degraded' : 'operational')
      : 'partial_outage';
    return { name: 'D1 Database', type: 'database', status, latency_ms: latency };
  } catch (e) {
    return { name: 'D1 Database', type: 'database', status: 'major_outage', latency_ms: Date.now() - t0, error: e.message?.slice(0, 80) };
  }
}

async function probeKV(env) {
  if (!env.KV) return { name: 'KV Store', type: 'cache', status: 'major_outage', latency_ms: -1, error: 'binding_missing' };
  const probe = `health_${Date.now()}`;
  const t0 = Date.now();
  try {
    await env.KV.put(probe, '1', { expirationTtl: 60 });
    const val = await env.KV.get(probe);
    await env.KV.delete(probe).catch(() => {});
    const latency = Date.now() - t0;
    const ok = val === '1';
    return { name: 'KV Store', type: 'cache', status: ok ? (latency > LATENCY_WARN_MS ? 'degraded' : 'operational') : 'degraded', latency_ms: latency };
  } catch (e) {
    return { name: 'KV Store', type: 'cache', status: 'major_outage', latency_ms: Date.now() - t0, error: e.message?.slice(0, 80) };
  }
}

async function probeR2(env) {
  if (!env.SCAN_RESULTS) return { name: 'R2 Storage', type: 'storage', status: 'unknown', latency_ms: -1, detail: 'binding_not_configured' };
  const t0 = Date.now();
  try {
    await env.SCAN_RESULTS.list({ limit: 1 });
    const latency = Date.now() - t0;
    return { name: 'R2 Storage', type: 'storage', status: latency > LATENCY_WARN_MS ? 'degraded' : 'operational', latency_ms: latency };
  } catch (e) {
    return { name: 'R2 Storage', type: 'storage', status: 'degraded', latency_ms: Date.now() - t0, error: e.message?.slice(0, 80) };
  }
}

export async function probeIntel(env) {
  if (!env.DB) return { name: 'Threat Intelligence', type: 'intelligence', status: 'unknown', latency_ms: -1 };
  const t0 = Date.now();
  try {
    const row = await withRetry(
      () => env.DB.prepare(
        "SELECT COUNT(*) as c FROM threat_intel WHERE ingested_at > datetime('now','-7 days')"
      ).first(),
      D1_PROBE_RETRIES, D1_PROBE_BACKOFF_MS, 'eop:probeIntel'
    );
    const latency = Date.now() - t0;
    const count = row?.c ?? 0;
    const status = count > 0 ? 'operational' : 'degraded';
    return { name: 'Threat Intelligence', type: 'intelligence', status, latency_ms: latency, detail: `${count} entries last 7d` };
  } catch (e) {
    return { name: 'Threat Intelligence', type: 'intelligence', status: 'degraded', latency_ms: Date.now() - t0, error: e.message?.slice(0, 80) };
  }
}

export async function probePayments(env) {
  if (!env.DB) return { name: 'Payment System', type: 'payments', status: 'unknown', latency_ms: -1 };
  const t0 = Date.now();
  try {
    const row = await withRetry(
      () => env.DB.prepare('SELECT COUNT(*) as c FROM orders').first(),
      D1_PROBE_RETRIES, D1_PROBE_BACKOFF_MS, 'eop:probePayments'
    ).catch(() => null);
    const latency = Date.now() - t0;
    const razorpayConfigured = !!(env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET);
    return {
      name: 'Payment System', type: 'payments',
      status: razorpayConfigured ? 'operational' : 'degraded',
      latency_ms: latency,
      detail: razorpayConfigured ? `gateway configured, ${row?.c ?? 0} orders` : 'razorpay credentials not set',
    };
  } catch (e) {
    return { name: 'Payment System', type: 'payments', status: 'degraded', latency_ms: Date.now() - t0, error: e.message?.slice(0, 80) };
  }
}

export async function probeAuth(env) {
  if (!env.DB || !env.JWT_SECRET) {
    return { name: 'Authentication', type: 'auth', status: env.JWT_SECRET ? 'operational' : 'major_outage', latency_ms: -1, detail: env.JWT_SECRET ? 'db_missing' : 'jwt_secret_not_set' };
  }
  const t0 = Date.now();
  try {
    const row = await withRetry(
      () => env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE status = ?').bind('active').first(),
      D1_PROBE_RETRIES, D1_PROBE_BACKOFF_MS, 'eop:probeAuth'
    );
    const latency = Date.now() - t0;
    return { name: 'Authentication', type: 'auth', status: 'operational', latency_ms: latency, detail: `${row?.c ?? 0} active users` };
  } catch (e) {
    return { name: 'Authentication', type: 'auth', status: 'degraded', latency_ms: Date.now() - t0, error: e.message?.slice(0, 80) };
  }
}

async function probeScheduler(env) {
  if (!env.DB) return { name: 'Scheduler', type: 'scheduler', status: 'unknown', latency_ms: -1 };
  try {
    const row = await env.DB.prepare(
      "SELECT * FROM uptime_log WHERE service = 'api' ORDER BY checked_at DESC LIMIT 1"
    ).first().catch(() => null);
    if (!row) return { name: 'Scheduler', type: 'scheduler', status: 'unknown', latency_ms: 0, detail: 'no_cron_records_yet' };
    const ageMs = Date.now() - new Date(row.checked_at + 'Z').getTime();
    const ageMin = ageMs / 60000;
    const status = ageMin < 70 ? 'operational' : ageMin < 180 ? 'degraded' : 'partial_outage';
    return { name: 'Scheduler', type: 'scheduler', status, latency_ms: 0, detail: `last cron ${Math.round(ageMin)}min ago` };
  } catch (e) {
    return { name: 'Scheduler', type: 'scheduler', status: 'unknown', latency_ms: 0, error: e.message?.slice(0, 80) };
  }
}

async function probeQueue(env) {
  // Queues have no runtime probe API — check binding presence
  const bound = !!env.SCAN_QUEUE;
  return { name: 'Scan Queue', type: 'queue', status: bound ? 'operational' : 'unknown', latency_ms: 0, detail: bound ? 'binding_present' : 'binding_not_configured' };
}

// ─── Status derivation ────────────────────────────────────────────────────────

function deriveStatus(components) {
  const critical = components.filter(c => c.type !== 'queue' && c.status === 'major_outage').length;
  const partial  = components.filter(c => c.status === 'partial_outage').length;
  const degraded = components.filter(c => c.status === 'degraded').length;

  if (critical >= 2) return { status: 'critical',        severity: 'high' };
  if (critical === 1) return { status: 'partial_outage', severity: 'high' };
  if (partial  >= 1)  return { status: 'partial_outage', severity: 'medium' };
  if (degraded >= 2)  return { status: 'degraded',       severity: 'medium' };
  if (degraded === 1) return { status: 'degraded',       severity: 'low' };
  return { status: 'operational', severity: 'none' };
}

// ─── Async side-effects (non-blocking) ───────────────────────────────────────

function fireAlerts(env, components) {
  for (const c of components) {
    if (c.status === 'major_outage') {
      if (c.type === 'database')  Alerts.dbFailure(env, c.error || 'probe failed').catch(() => {});
      else if (c.type === 'cache') Alerts.kvFailure(env, c.error || 'probe failed').catch(() => {});
      else if (c.type === 'auth') Alerts.authFailure(env, c.error || 'probe failed').catch(() => {});
    } else if (c.status === 'degraded' && c.latency_ms > LATENCY_WARN_MS) {
      Alerts.highLatency(env, c.name, c.latency_ms).catch(() => {});
    }
  }
}

export function recordHistory(env, components, overallStatus) {
  if (!env.DB) return;
  const version = env.VERSION || '40.0.0';
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);

  for (const c of components) {
    const id = `oh-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`;
    env.DB.prepare(
      `INSERT INTO operational_history (id, component, status, latency_ms, version, error_detail, checked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, c.name, c.status, c.latency_ms >= 0 ? c.latency_ms : 0, version, c.error || null, now)
      .run().catch(() => {});
  }
}

// ─── Helpers for detailed endpoint ───────────────────────────────────────────

async function fetchRecentErrors(env, limit = 20) {
  if (!env.DB) return [];
  try {
    const rows = await env.DB.prepare(
      `SELECT id, area, message, context, created_at FROM system_errors ORDER BY created_at DESC LIMIT ?`
    ).bind(limit).all();
    return rows.results || [];
  } catch (_) { return []; }
}

async function fetchRecentAlerts(env, limit = 10) {
  if (!env.DB) return [];
  try {
    const rows = await env.DB.prepare(
      `SELECT alert_type, component, message, sent_via, sent_at FROM ops_alert_log ORDER BY sent_at DESC LIMIT ?`
    ).bind(limit).all();
    return rows.results || [];
  } catch (_) { return []; }
}

async function fetchLastDeployment(env) {
  if (!env.DB) return null;
  try {
    return await env.DB.prepare(
      `SELECT id, version, commit_sha, deployed_by, status, deployed_at FROM deployments ORDER BY deployed_at DESC LIMIT 1`
    ).first().catch(() => null);
  } catch (_) { return null; }
}

async function fetchUptimeSummary(env) {
  if (!env.DB) return null;
  try {
    const row = await env.DB.prepare(`
      SELECT
        COUNT(*) AS checks,
        COUNT(CASE WHEN status='operational' THEN 1 END) AS ok,
        AVG(latency_ms) AS avg_latency
      FROM operational_history
      WHERE checked_at > datetime('now','-24 hours')
        AND component = 'D1 Database'
    `).first().catch(() => null);
    if (!row?.checks) return null;
    return {
      period: '24h',
      uptime_pct: row.checks > 0 ? Math.round((row.ok / row.checks) * 1000) / 10 : null,
      avg_latency_ms: row.avg_latency ? Math.round(row.avg_latency) : null,
      sample_count: row.checks,
    };
  } catch (_) { return null; }
}

async function fetchActiveIncidents(env) {
  if (!env.DB) return [];
  try {
    const rows = await env.DB.prepare(
      `SELECT id, title, severity, status, affected_services, started_at
       FROM incidents WHERE status != 'resolved' ORDER BY started_at DESC`
    ).all();
    return rows.results || [];
  } catch (_) { return []; }
}
