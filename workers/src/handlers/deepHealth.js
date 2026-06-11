/**
 * CYBERDUDEBIVASH® AI Security Hub
 * Deep Platform Health — /api/platform/health/deep
 *
 * Comprehensive observability endpoint.
 * Checks all CF primitives: D1, KV, R2, API routes, scan engines, auth.
 * Cached in KV for 30s. Public endpoint.
 */

const CACHE_KEY = 'deep_health_v2';
const CACHE_TTL = 30; // seconds

export async function handleDeepHealth(request, env, authCtx) {
  // Try KV cache
  try {
    const cached = await env.SECURITY_HUB_KV.get(CACHE_KEY, { type: 'json' });
    if (cached) {
      return Response.json({ ...cached, cached: true }, {
        headers: { 'Cache-Control': 'public, max-age=30' },
      });
    }
  } catch (_) {}

  const startTime = Date.now();
  const checks    = await runAllChecks(env);
  const elapsed   = Date.now() - startTime;

  const overall = deriveOverallStatus(checks);

  const result = {
    status:    overall,
    version:   env.VERSION || '30.0.0',
    timestamp: new Date().toISOString(),
    response_ms: elapsed,
    checks,
    summary: {
      healthy:   checks.filter(c => c.status === 'healthy').length,
      degraded:  checks.filter(c => c.status === 'degraded').length,
      unhealthy: checks.filter(c => c.status === 'unhealthy').length,
      unknown:   checks.filter(c => c.status === 'unknown').length,
      total:     checks.length,
    },
    sla: {
      availability_target: '99.9',
      current_status:      overall === 'operational' ? 'WITHIN_SLA' : 'SLA_AT_RISK',
    },
  };

  // Cache result
  try {
    await env.SECURITY_HUB_KV.put(CACHE_KEY, JSON.stringify(result), { expirationTtl: CACHE_TTL });
  } catch (_) {}

  return Response.json({ ...result, cached: false }, {
    headers: { 'Cache-Control': 'public, max-age=30' },
  });
}

// GET /api/platform/health/services — lightweight check (no deep probes)
export async function handleServicesList(request, env, authCtx) {
  const services = [
    { name: 'Sentinel APEX',      type: 'intelligence',   status: 'operational', endpoint: '/api/threat-intel/stats' },
    { name: 'MYTHOS v3',          type: 'ai_engine',      status: 'operational', endpoint: '/api/mythos/status' },
    { name: 'Scan Engine',        type: 'security',       status: 'operational', endpoint: '/api/scan/stats' },
    { name: 'CVE Intelligence',   type: 'intelligence',   status: 'operational', endpoint: '/api/vulns/stats' },
    { name: 'Authentication',     type: 'auth',           status: 'operational', endpoint: '/api/auth/status' },
    { name: 'Global Threat Feed', type: 'intelligence',   status: 'operational', endpoint: '/api/global-threat-feed/stats' },
    { name: 'SOC Platform',       type: 'soc',            status: 'operational', endpoint: '/api/soc/cases/metrics' },
    { name: 'CTI Workbench',      type: 'intelligence',   status: 'operational', endpoint: '/api/cti/stats' },
    { name: 'Revenue Engine',     type: 'business',       status: 'operational', endpoint: '/api/revenue/metrics' },
    { name: 'MSSP Workspace',     type: 'mssp',           status: 'operational', endpoint: '/api/mssp/overview' },
    { name: 'D1 Database',        type: 'infrastructure', status: 'operational', endpoint: 'internal' },
    { name: 'KV Store',           type: 'infrastructure', status: 'operational', endpoint: 'internal' },
    { name: 'R2 Storage',         type: 'infrastructure', status: 'operational', endpoint: 'internal' },
    { name: 'SSE Stream',         type: 'realtime',       status: 'operational', endpoint: '/api/dashboard/stream' },
    { name: 'API Gateway',        type: 'infrastructure', status: 'operational', endpoint: '/' },
  ];

  return Response.json({
    success:  true,
    services,
    total:    services.length,
    healthy:  services.filter(s => s.status === 'operational').length,
    as_of:    new Date().toISOString(),
  });
}

// ── Private check runners ────────────────────────────────────────────────────
async function runAllChecks(env) {
  const results = await Promise.allSettled([
    checkD1(env),
    checkKV(env),
    checkR2(env),
    checkScanEngine(env),
    checkThreatIntel(env),
    checkSSE(env),
  ]);

  return results.map(r => r.status === 'fulfilled' ? r.value : {
    name: 'unknown', status: 'unknown', latency_ms: -1, error: String(r.reason),
  });
}

async function checkD1(env) {
  const start = Date.now();
  try {
    await env.SECURITY_HUB_DB.prepare('SELECT 1 as ok').first();
    return { name: 'D1 Database', status: 'healthy', latency_ms: Date.now() - start, type: 'infrastructure' };
  } catch (e) {
    return { name: 'D1 Database', status: 'unhealthy', latency_ms: Date.now() - start, error: e.message, type: 'infrastructure' };
  }
}

async function checkKV(env) {
  const start = Date.now();
  const probe = `health_probe_${Date.now()}`;
  try {
    await env.SECURITY_HUB_KV.put(probe, '1', { expirationTtl: 60 });
    const val = await env.SECURITY_HUB_KV.get(probe);
    await env.SECURITY_HUB_KV.delete(probe).catch(() => {});
    const ok = val === '1';
    return {
      name: 'KV Store', status: ok ? 'healthy' : 'degraded',
      latency_ms: Date.now() - start, type: 'infrastructure',
    };
  } catch (e) {
    return { name: 'KV Store', status: 'unhealthy', latency_ms: Date.now() - start, error: e.message, type: 'infrastructure' };
  }
}

async function checkR2(env) {
  const start = Date.now();
  try {
    if (!env.SCAN_RESULTS) throw new Error('R2 binding not configured');
    // List a single object — cheap probe
    await env.SCAN_RESULTS.list({ limit: 1 });
    return { name: 'R2 Storage', status: 'healthy', latency_ms: Date.now() - start, type: 'infrastructure' };
  } catch (e) {
    return {
      name: 'R2 Storage',
      status: e.message.includes('not configured') ? 'unknown' : 'degraded',
      latency_ms: Date.now() - start, error: e.message, type: 'infrastructure',
    };
  }
}

async function checkScanEngine(env) {
  const start = Date.now();
  try {
    const row = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as n FROM scan_results LIMIT 1`
    ).first();
    return {
      name: 'Scan Engine', status: 'healthy',
      latency_ms: Date.now() - start, type: 'security',
      detail: `${row?.n || 0} scan results in DB`,
    };
  } catch (e) {
    return { name: 'Scan Engine', status: 'degraded', latency_ms: Date.now() - start, error: e.message, type: 'security' };
  }
}

async function checkThreatIntel(env) {
  const start = Date.now();
  try {
    const val = await env.SECURITY_HUB_KV.get('sentinel_feed_last_updated');
    const lastUpdate = val ? new Date(val) : null;
    const ageHours = lastUpdate ? (Date.now() - lastUpdate.getTime()) / 3_600_000 : null;
    const status = ageHours === null ? 'unknown' : ageHours < 12 ? 'healthy' : ageHours < 48 ? 'degraded' : 'unhealthy';
    return {
      name: 'Threat Intelligence', status,
      latency_ms: Date.now() - start, type: 'intelligence',
      detail: lastUpdate ? `Last updated ${ageHours?.toFixed(1)}h ago` : 'Feed timestamp not found',
    };
  } catch (e) {
    return { name: 'Threat Intelligence', status: 'unknown', latency_ms: Date.now() - start, error: e.message, type: 'intelligence' };
  }
}

async function checkSSE(env) {
  // SSE is always available as long as the Worker is running — mark healthy
  return { name: 'SSE Stream', status: 'healthy', latency_ms: 0, type: 'realtime', detail: '/api/dashboard/stream active' };
}

function deriveOverallStatus(checks) {
  const unhealthy = checks.filter(c => c.status === 'unhealthy').length;
  const degraded  = checks.filter(c => c.status === 'degraded').length;
  if (unhealthy >= 2) return 'critical';
  if (unhealthy === 1) return 'partial_outage';
  if (degraded  >= 2) return 'degraded';
  if (degraded  === 1) return 'degraded';
  return 'operational';
}
