/**
 * CYBERDUDEBIVASH AI Security Hub — Global Threat Intel display handlers
 * The DISPLAY stage of the Global Intel Firehose (services/globalIntelFirehose.js).
 *
 *   GET /api/global-intel            → paginated feed, BREAKING + freshest first
 *   GET /api/global-intel/briefing   → the latest hourly briefing (KV snapshot)
 *   GET /api/global-intel/sources    → the live source registry (transparency)
 *   POST /api/global-intel/refresh   → ADMIN: trigger an on-demand pipeline run
 */

import { ok, fail } from '../lib/response.js';
import { runGlobalIntelFirehose, ensureGlobalIntelTable, INTEL_SOURCES } from '../services/globalIntelFirehose.js';

const VALID_CATEGORIES = ['news', 'research', 'advisory', 'ioc', 'ransomware', 'breach', 'apt', 'malware', 'phishing', 'exploit', 'vulnerability'];

function rowToItem(r) {
  const parse = (s, d) => { try { return JSON.parse(s || d); } catch { return JSON.parse(d); } };
  return {
    intel_id:     r.intel_id,
    title:        r.title,
    summary:      r.summary,
    url:          r.url,
    source:       r.source,
    source_name:  r.source_name,
    category:     r.category,
    region:       r.region,
    severity:     r.severity,
    threat_score: r.threat_score,
    is_breaking:  !!r.is_breaking,
    cve_ids:      parse(r.cve_ids, '[]'),
    actors:       parse(r.actors, '[]'),
    malware:      parse(r.malware, '[]'),
    iocs:         parse(r.iocs, '[]'),
    tags:         parse(r.tags, '[]'),
    published_at: r.published_at,
    ingested_at:  r.ingested_at,
  };
}

// ─── GET /api/global-intel ────────────────────────────────────────────────────
export async function handleGlobalIntelFeed(request, env) {
  const url      = new URL(request.url);
  const limit    = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '30', 10)));
  const offset   = Math.max(0, parseInt(url.searchParams.get('offset') || '0', 10));
  const category = (url.searchParams.get('category') || '').toLowerCase();
  const severity = (url.searchParams.get('severity') || '').toUpperCase();
  const source   = url.searchParams.get('source') || '';
  const q        = (url.searchParams.get('q') || '').trim().slice(0, 80);
  // sort: 'breaking' (default — breaking then freshest), 'recent', or 'score'
  const sort     = (url.searchParams.get('sort') || 'breaking').toLowerCase();

  const db = env?.SECURITY_HUB_DB;
  if (!db) return fail(request, 'Database unavailable', 503);

  try {
    await ensureGlobalIntelTable(db);

    const where = [];
    const binds = [];
    if (category && VALID_CATEGORIES.includes(category)) { where.push('category = ?'); binds.push(category); }
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity)) { where.push('severity = ?'); binds.push(severity); }
    if (source) { where.push('source = ?'); binds.push(source); }
    if (q) { where.push('(title LIKE ? OR summary LIKE ?)'); binds.push(`%${q}%`, `%${q}%`); }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const orderSql = sort === 'recent'
      ? 'ORDER BY published_at DESC'
      : sort === 'score'
        ? 'ORDER BY threat_score DESC, published_at DESC'
        // default: breaking items first, then newest, then score — a true "live" feed.
        : 'ORDER BY is_breaking DESC, published_at DESC, threat_score DESC';

    const [rows, countRow] = await Promise.all([
      db.prepare(`SELECT * FROM global_intel ${whereSql} ${orderSql} LIMIT ? OFFSET ?`).bind(...binds, limit, offset).all(),
      db.prepare(`SELECT COUNT(*) AS total FROM global_intel ${whereSql}`).bind(...binds).first(),
    ]);

    const items = (rows.results || []).map(rowToItem);
    return ok(request, {
      items,
      total:       countRow?.total ?? 0,
      limit,
      offset,
      sort,
      category:    category || 'all',
      last_updated: items[0]?.ingested_at || null,
    });
  } catch (e) {
    return fail(request, 'Query failed: ' + (e?.message || 'unknown'), 500);
  }
}

// ─── GET /api/global-intel/briefing ──────────────────────────────────────────
export async function handleGlobalIntelBriefing(request, env) {
  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get('global_intel:briefing:v1', { type: 'json' });
      if (cached) return ok(request, { briefing: cached, cached: true });
    } catch {}
  }
  // No snapshot yet — compute one on demand so the first-ever call is never empty.
  try {
    const result = await runGlobalIntelFirehose(env);
    const cached  = env?.SECURITY_HUB_KV ? await env.SECURITY_HUB_KV.get('global_intel:briefing:v1', { type: 'json' }) : null;
    return ok(request, { briefing: cached, run: result, cached: false });
  } catch (e) {
    return fail(request, 'Briefing unavailable: ' + (e?.message || 'unknown'), 500);
  }
}

// ─── GET /api/global-intel/sources ───────────────────────────────────────────
export async function handleGlobalIntelSources(request, env) {
  return ok(request, {
    total: INTEL_SOURCES.length,
    by_category: INTEL_SOURCES.reduce((m, s) => (m[s.category] = (m[s.category] || 0) + 1, m), {}),
    by_region:   INTEL_SOURCES.reduce((m, s) => (m[s.region] = (m[s.region] || 0) + 1, m), {}),
    sources: INTEL_SOURCES.map(s => ({ id: s.id, name: s.name, category: s.category, region: s.region, weight: s.weight })),
  });
}

// ─── POST /api/global-intel/refresh (ADMIN) ──────────────────────────────────
export async function handleGlobalIntelRefresh(request, env) {
  const configured = (env.ADMIN_TOKEN || '').trim();
  if (!configured) return fail(request, 'Admin token not configured', 503);
  const auth = request.headers.get('Authorization') || '';
  const presented = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  let okAuth = presented.length > 0 && presented.length === configured.length;
  if (okAuth) {
    let diff = 0;
    for (let i = 0; i < configured.length; i++) diff |= configured.charCodeAt(i) ^ presented.charCodeAt(i);
    okAuth = diff === 0;
  }
  if (!okAuth) return fail(request, 'Unauthorized', 401);

  const result = await runGlobalIntelFirehose(env);
  return ok(request, { triggered: true, result });
}
