// ============================================================
// workers/health.ts
// GET  /api/health                — full platform health status
// GET  /api/health/cve-count      — single live CVE count (dashboard ticker)
// GET  /api/health/metrics        — all platform metrics (dashboard)
// GET  /api/health/status-bar     — lightweight status bar payload
//
// All values come from D1 queries via metrics.ts.
// Zero hardcoded numbers. Cache TTL: 60 seconds.
// ============================================================

import type { Env } from '../types/index.js';
import { getPlatformMetrics } from './lib/metrics.js';
import { corsHeaders, jsonResponse, ok, err } from './lib/utils.js';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin') ?? '';
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== 'GET') {
      return jsonResponse(err('METHOD_NOT_ALLOWED', 'GET only'), 405, cors);
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '');

    try {
      switch (path) {
        case '/api/health':
        case '/api/mythos/health':
          return handleFullHealth(env, cors);

        case '/api/health/cve-count':
        case '/api/mythos/health/cve-count':
          return handleCveCount(env, cors);

        case '/api/health/metrics':
        case '/api/mythos/status':
          return handleMetrics(env, cors);

        case '/api/health/status-bar':
        case '/api/mythos/health/status-bar':
          return handleStatusBar(env, cors);

        default:
          return jsonResponse(err('NOT_FOUND', 'Endpoint not found'), 404, cors);
      }
    } catch (e) {
      console.error('[health] Error:', e);
      return jsonResponse(err('INTERNAL_ERROR', 'Health check failed'), 500, cors);
    }
  },
};

// ── Full health ───────────────────────────────────────────────
async function handleFullHealth(env: Env, cors: Record<string, string>): Promise<Response> {
  const metrics = await getPlatformMetrics(env);

  return jsonResponse(ok({
    health: metrics.health,
    summary: {
      overall: metrics.health.overall,
      components_ok: Object.values(metrics.health).filter(v => v === 'ok').length,
      components_degraded: Object.values(metrics.health).filter(v => v === 'degraded').length,
      components_down: Object.values(metrics.health).filter(v => v === 'down').length,
    },
    cve_pipeline: {
      total: metrics.cve.total_tracked,
      critical: metrics.cve.critical_count,
      kev: metrics.cve.kev_count,
      ingested_last_24h: metrics.cve.ingested_last_24h,
      last_ingestion_at: metrics.cve.last_ingestion_at,
    },
    computed_at: metrics.computed_at,
    cache_ttl_seconds: metrics.cache_ttl_seconds,
  }, {
    computed_at: metrics.computed_at,
    cache_ttl_seconds: metrics.cache_ttl_seconds,
    version: env.PLATFORM_VERSION ?? 'v30.0.0',
  }), 200, {
    ...cors,
    'Cache-Control': `public, max-age=${metrics.cache_ttl_seconds}, stale-while-revalidate=30`,
  });
}

// ── CVE count only (dashboard ticker) ────────────────────────
// Used by the marquee, ticker, and footer counter.
// This endpoint is the ONLY source of truth for CVE counts.
async function handleCveCount(env: Env, cors: Record<string, string>): Promise<Response> {
  const metrics = await getPlatformMetrics(env);

  return jsonResponse(ok({
    total: metrics.cve.total_tracked,
    critical: metrics.cve.critical_count,
    kev: metrics.cve.kev_count,
    ingested_last_24h: metrics.cve.ingested_last_24h,
    last_ingestion_at: metrics.cve.last_ingestion_at,
    // Human-readable for dashboard display
    display: {
      total_label: metrics.cve.total_tracked > 0
        ? `${metrics.cve.total_tracked.toLocaleString('en-IN')}+`
        : '—',
      critical_label: String(metrics.cve.critical_count),
      kev_label: String(metrics.cve.kev_count),
      last_updated_label: metrics.cve.last_ingestion_at
        ? formatTimestamp(metrics.cve.last_ingestion_at)
        : 'Never',
      pipeline_status: metrics.health.cve_ingester,
    },
  }, {
    computed_at: metrics.computed_at,
    cache_ttl_seconds: metrics.cache_ttl_seconds,
    version: env.PLATFORM_VERSION ?? 'v30.0.0',
  }), 200, {
    ...cors,
    'Cache-Control': `public, max-age=${metrics.cache_ttl_seconds}, stale-while-revalidate=30`,
  });
}

// ── Full platform metrics (admin dashboard) ───────────────────
async function handleMetrics(env: Env, cors: Record<string, string>): Promise<Response> {
  const metrics = await getPlatformMetrics(env);

  // Format INR amounts for display
  const fmtInr = (paise: number) =>
    `₹${(paise / 100).toLocaleString('en-IN', { maximumFractionDigits: 0 })}`;

  return jsonResponse(ok({
    ...metrics,
    display: {
      cve_total: metrics.cve.total_tracked > 0
        ? `${metrics.cve.total_tracked.toLocaleString('en-IN')}+`
        : '—',
      scans_completed: metrics.scans.total_completed > 0
        ? `${metrics.scans.total_completed.toLocaleString('en-IN')}+`
        : '0',
      active_scans: String(metrics.scans.active_now),
      paying_customers: String(metrics.subscriptions.total_active),
      soar_rules: metrics.soar.total_generated > 0
        ? `${metrics.soar.total_generated}+`
        : '0',
      mrr: fmtInr(metrics.subscriptions.mrr_paise),
      arr: fmtInr(metrics.subscriptions.arr_paise),
      revenue_today: fmtInr(metrics.subscriptions.revenue_today_paise),
    },
  }, {
    computed_at: metrics.computed_at,
    cache_ttl_seconds: metrics.cache_ttl_seconds,
    version: env.PLATFORM_VERSION ?? 'v30.0.0',
  }), 200, {
    ...cors,
    'Cache-Control': `public, max-age=${metrics.cache_ttl_seconds}, stale-while-revalidate=30`,
  });
}

// ── Status bar (lightweight, for the sticky header) ──────────
async function handleStatusBar(env: Env, cors: Record<string, string>): Promise<Response> {
  const metrics = await getPlatformMetrics(env);
  const h = metrics.health;

  return jsonResponse(ok({
    api:           { status: h.api,           icon: statusIcon(h.api) },
    db:            { status: h.db,            icon: statusIcon(h.db) },
    cache:         { status: h.cache,         icon: statusIcon(h.cache) },
    sentinel_apex: { status: h.sentinel_apex, icon: statusIcon(h.sentinel_apex) },
    overall:       h.overall,
    threat_level:  computeThreatLevel(metrics.cve.critical_count, metrics.cve.kev_count),
    active_scans:  metrics.scans.active_now,
    version:       env.PLATFORM_VERSION ?? 'v30.0.0',
    timestamp_utc: new Date().toISOString(),
  }), 200, {
    ...cors,
    'Cache-Control': 'public, max-age=30, stale-while-revalidate=10',
  });
}

// ── Helpers ───────────────────────────────────────────────────
function statusIcon(status: string): string {
  switch (status) {
    case 'ok':       return '✓';
    case 'degraded': return '⚠';
    case 'down':     return '✗';
    default:         return '?';
  }
}

function computeThreatLevel(critical: number, kev: number): string {
  if (kev > 50 || critical > 100) return 'CRITICAL';
  if (kev > 20 || critical > 50)  return 'HIGH';
  if (kev > 5  || critical > 20)  return 'MODERATE';
  if (critical > 0)                return 'LOW';
  return 'MINIMAL';
}

function formatTimestamp(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleTimeString('en-IN', {
      hour: '2-digit', minute: '2-digit', hour12: false,
      timeZone: 'Asia/Kolkata',
    });
  } catch {
    return 'Unknown';
  }
}
