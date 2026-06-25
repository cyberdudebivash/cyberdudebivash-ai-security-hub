/**
 * CYBERDUDEBIVASH® AI Security Hub — Cyber Signal Radar Handler v1.0
 * P3.0-001 / P3.0-007 / P3.0-008
 *
 * Public routes (no auth):
 *   GET /api/radar/snapshot          — unified public snapshot (5-min cache)
 *   GET /api/radar/latest            — latest CVE signals
 *   GET /api/radar/summary           — severity summary stats
 *   GET /api/radar/trending          — trending threats by EPSS/CVSS
 *
 * Enterprise routes (auth required):
 *   GET /api/radar/enterprise           — full enterprise snapshot
 *   GET /api/radar/enterprise/signals   — extended signal list with confidence scores
 */

import { RadarService, CACHE_HEADER_TTL } from '../services/radarService.js';

const PUBLISHER = 'CYBERDUDEBIVASH® Cyber Signal Radar';

const BASE_HEADERS = {
  'X-Radar-By':    `${PUBLISHER} v1.0`,
  'X-Powered-By':  'Cloudflare Workers',
};

function jsonOk(data, ttl = CACHE_HEADER_TTL) {
  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': `public, max-age=${ttl}, stale-while-revalidate=60`,
      ...BASE_HEADERS,
    },
  });
}

function jsonErr(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg, status }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...BASE_HEADERS },
  });
}

// ── P3.0-001 — GET /api/radar/snapshot ───────────────────────────────────────
async function handleSnapshot(request, env) {
  try {
    const svc  = new RadarService(env);
    const data = await svc.getPublicSnapshot();
    const res  = jsonOk(data);
    // P3.0-009: edge-cache the snapshot on Cloudflare's CDN (free, no KV quota)
    try {
      const cacheReq = new Request(`https://cdb-edge-cache/radar:snapshot:v1`);
      const cached   = await caches.default.match(cacheReq);
      if (!cached) {
        const toCache = res.clone();
        const h = new Headers(toCache.headers);
        h.set('Cache-Control', `public, max-age=${CACHE_HEADER_TTL}`);
        await caches.default.put(cacheReq, new Response(await toCache.text(), { headers: h }));
      }
    } catch {}
    return res;
  } catch (e) {
    console.error('[Radar] snapshot error:', e?.message);
    return jsonErr('Radar temporarily unavailable', 503);
  }
}

// ── P3.0-007 — GET /api/radar/latest ─────────────────────────────────────────
async function handleLatest(request, env) {
  try {
    const url   = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10) || 20, 20);
    const svc   = new RadarService(env);
    const items = await svc.getLatest({ limit });
    return jsonOk({ items, count: items.length, timestamp: new Date().toISOString(), publisher: PUBLISHER });
  } catch (e) {
    return jsonErr('Unavailable', 503);
  }
}

// ── P3.0-007 — GET /api/radar/summary ────────────────────────────────────────
async function handleSummary(request, env) {
  try {
    const svc  = new RadarService(env);
    const data = await svc.getSummary();
    return jsonOk(data);
  } catch (e) {
    return jsonErr('Unavailable', 503);
  }
}

// ── P3.0-007 — GET /api/radar/trending ───────────────────────────────────────
async function handleTrending(request, env) {
  try {
    const url   = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '10', 10) || 10, 10);
    const svc   = new RadarService(env);
    const items = await svc.getTrending({ limit });
    return jsonOk({ items, count: items.length, timestamp: new Date().toISOString(), publisher: PUBLISHER });
  } catch (e) {
    return jsonErr('Unavailable', 503);
  }
}

// ── P3.0-008 — Enterprise endpoints (auth required) ──────────────────────────
async function handleEnterprise(request, env, authCtx, subpath) {
  if (!authCtx?.authenticated) {
    return jsonErr('Authentication required — provide Authorization: Bearer <token> or X-API-Key header', 401);
  }
  const allowedTiers = ['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN'];
  if (!allowedTiers.includes((authCtx.tier || '').toUpperCase())) {
    return jsonErr('Enterprise plan required. Upgrade at https://cyberdudebivash.in/#pricing', 403);
  }
  try {
    const svc      = new RadarService(env);
    const url      = new URL(request.url);
    const industry = url.searchParams.get('industry') || null;

    if (subpath === '/signals') {
      const snap = await svc.getEnterpriseSnapshot({ industry });
      return jsonOk({
        signals:               snap.signals,
        severity_distribution: snap.severity_distribution,
        top_campaigns:         snap.top_campaigns,
        active_threat_actors:  snap.active_threat_actors,
        ransomware_activity:   snap.ransomware_activity,
        ai_threats_detected:   snap.ai_threats_detected,
        total_signals:         snap.total_signals,
        timestamp:             snap.timestamp,
        tier:                  authCtx.tier || 'ENTERPRISE',
      }, 60);
    }

    // Default enterprise full snapshot
    const snap = await svc.getEnterpriseSnapshot({ industry });
    return jsonOk({ ...snap, user_tier: authCtx.tier || 'ENTERPRISE' }, 60);
  } catch (e) {
    console.error('[Radar] enterprise error:', e?.message);
    return jsonErr('Enterprise radar unavailable', 503);
  }
}

// ── Main router ────────────────────────────────────────────────────────────────
export async function handleRadar(request, env, authCtx, path) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: BASE_HEADERS });
  }
  if (request.method !== 'GET') return jsonErr('Method not allowed', 405);

  if (path === '/api/radar/snapshot')  return handleSnapshot(request, env);
  if (path === '/api/radar/latest')    return handleLatest(request, env);
  if (path === '/api/radar/summary')   return handleSummary(request, env);
  if (path === '/api/radar/trending')  return handleTrending(request, env);

  if (path === '/api/radar/enterprise' || path.startsWith('/api/radar/enterprise/')) {
    const sub = path.slice('/api/radar/enterprise'.length) || '';
    return handleEnterprise(request, env, authCtx, sub);
  }

  return jsonErr('Not found', 404);
}
