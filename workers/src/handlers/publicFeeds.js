/**
 * CYBERDUDEBIVASH® AI Security Hub — Public Threat-Intel Feeds
 *
 * Implements the five public endpoints advertised in the platform footer /
 * ecosystem panel, which previously 404'd:
 *   GET /api/feed.json                  — public threat feed (recent advisories)
 *   GET /api/v1/intel/latest.json       — latest intel items (machine-readable)
 *   GET /api/v1/intel/apex.json         — Sentinel APEX curated critical feed
 *   GET /api/v1/intel/ai_summary.json   — deterministic AI threat-landscape summary
 *   GET /api/reports/latest.json        — latest intelligence report digest
 *
 * All feeds are backed by REAL data from the `threat_intel` table. Queries are
 * drift-defensive (the table has two historical column shapes): a rich query is
 * tried first, then a minimal guaranteed-column query, then an empty feed — a
 * schema mismatch can never 500 a public endpoint. Responses are served from the
 * Cloudflare CDN edge cache (free, no KV quota) and carry CORS + cache headers.
 */

const PUBLISHER = 'CYBERDUDEBIVASH® Sentinel APEX';
const UPGRADE_URL = 'https://cyberdudebivash.in/#pricing';

// ─── Drift-defensive intel reader ─────────────────────────────────────────────
// Maps a threat_intel row from EITHER historical column shape:
//   schema_threat_intel.sql → id / cvss      (the live ingestion shape)
//   schema_master.sql        → cve_id / cvss_score
function normalizeItem(r) {
  const cve = r.cve_id || r.id || null;
  return {
    id:           cve,
    cve,
    title:        r.title || 'Security advisory',
    summary:      r.description ? String(r.description).slice(0, 280) : null,
    severity:     String(r.severity || 'MEDIUM').toUpperCase(),
    cvss:         r.cvss ?? r.cvss_score ?? null,
    source:       r.source || PUBLISHER,
    published_at: r.published_at || r.created_at || null,
  };
}

async function fetchRecentIntel(env, { limit = 50, severities = null } = {}) {
  if (!env?.DB) return [];
  const sevBind   = severities && severities.length ? severities.map(s => s.toUpperCase()) : [];
  const sevClause = sevBind.length ? ` WHERE UPPER(severity) IN (${sevBind.map(() => '?').join(',')})` : '';

  // Tier 1 — SELECT * avoids any SELECT-column drift; order by published_at
  // (guaranteed: written by the ingestion engine and used by the live feed).
  try {
    const rows = await env.DB.prepare(
      `SELECT * FROM threat_intel${sevClause} ORDER BY published_at DESC LIMIT ?`
    ).bind(...sevBind, limit).all();
    return (rows?.results || []).map(normalizeItem);
  } catch { /* fall through */ }

  // Tier 2 — no ORDER BY / no WHERE (in case even severity/published_at differ);
  // filter + cap in JS. A schema mismatch can never 500 a public feed.
  try {
    const rows = await env.DB.prepare(`SELECT * FROM threat_intel LIMIT 500`).all();
    let items = (rows?.results || []).map(normalizeItem);
    if (sevBind.length) items = items.filter(i => sevBind.includes(i.severity));
    return items.slice(0, limit);
  } catch { /* fail-open: empty feed */ }

  return [];
}

async function severityCounts(env) {
  const m = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  if (!env?.DB) return { ...m, total: 0 };
  try {
    const rows = await env.DB.prepare(
      `SELECT UPPER(severity) as sev, COUNT(*) as c FROM threat_intel GROUP BY UPPER(severity)`
    ).all();
    for (const row of (rows?.results || [])) if (row.sev in m) m[row.sev] = row.c;
  } catch { /* fail-open */ }
  return { ...m, total: m.CRITICAL + m.HIGH + m.MEDIUM + m.LOW };
}

// ─── Edge-cached JSON responder ───────────────────────────────────────────────
async function cachedJson(cacheKey, ttl, build) {
  try {
    const edge = caches.default;
    const req  = new Request(`https://cdb-edge-cache/${cacheKey}`);
    const hit  = await edge.match(req);
    if (hit) {
      const data = await hit.clone().json().catch(() => null);
      if (data) return jsonResponse({ ...data, cached: true }, ttl);
    }
    const data = await build();
    const resp = jsonResponse(data, ttl);
    edge.put(req, resp.clone()).catch(() => {});
    return resp;
  } catch {
    // local dev / edge unavailable — build directly
    return jsonResponse(await build(), ttl);
  }
}

function jsonResponse(obj, ttl) {
  return new Response(JSON.stringify(obj, null, 2), {
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': `public, max-age=${ttl}, s-maxage=${ttl}`,
      'X-Powered-By':  PUBLISHER,
    },
  });
}

// ─── Feed builders ────────────────────────────────────────────────────────────
async function buildFeed(env) {
  const items = await fetchRecentIntel(env, { limit: 50 });
  return {
    feed:        'CYBERDUDEBIVASH Public Threat Feed',
    publisher:   PUBLISHER,
    license:     'Free tier — attribution required. Full API: ' + UPGRADE_URL,
    generated_at: new Date().toISOString(),
    count:       items.length,
    items,
  };
}

async function buildLatest(env) {
  const items = await fetchRecentIntel(env, { limit: 100 });
  return {
    version:      'v1',
    feed:         'latest',
    publisher:    PUBLISHER,
    generated_at: new Date().toISOString(),
    count:        items.length,
    items,
  };
}

async function buildApex(env) {
  const items = await fetchRecentIntel(env, { limit: 50, severities: ['CRITICAL', 'HIGH'] });
  return {
    version:      'v1',
    feed:         'sentinel-apex',
    publisher:    PUBLISHER,
    description:  'Curated critical & high-severity advisories from Sentinel APEX',
    generated_at: new Date().toISOString(),
    count:        items.length,
    items,
  };
}

async function buildAiSummary(env) {
  const c = await severityCounts(env);
  const level = c.CRITICAL >= 10 ? 'CRITICAL' : c.CRITICAL >= 3 || c.HIGH >= 20 ? 'HIGH'
              : c.HIGH >= 5 || c.total >= 1 ? 'MODERATE' : 'LOW';
  const headline = c.total === 0
    ? 'No active advisories in the current window.'
    : `${c.total} tracked advisories — ${c.CRITICAL} critical, ${c.HIGH} high. Overall posture: ${level}.`;
  return {
    version:      'v1',
    feed:         'ai-summary',
    publisher:    PUBLISHER,
    generated_at: new Date().toISOString(),
    threat_level: level,
    headline,
    counts:       c,
    recommendations: [
      'Prioritise remediation of CRITICAL/KEV-listed CVEs within 72 hours.',
      'Enforce MFA on all privileged and remotely-accessible accounts.',
      'Audit AI/LLM endpoints against the OWASP LLM Top 10.',
      'Validate exposure of internet-facing services flagged in the latest feed.',
    ],
    full_intelligence: UPGRADE_URL,
  };
}

async function buildReports(env) {
  const items = await fetchRecentIntel(env, { limit: 10, severities: ['CRITICAL', 'HIGH'] });
  const reports = items.map((it, i) => ({
    id:        it.cve || `BRIEF-${i + 1}`,
    type:      'threat-brief',
    title:     it.title,
    severity:  it.severity,
    published_at: it.published_at,
    summary:   it.summary,
  }));
  return {
    feed:         'latest-reports',
    publisher:    PUBLISHER,
    generated_at: new Date().toISOString(),
    count:        reports.length,
    reports,
    premium_reports: {
      note: 'Full 30-day landscape, APT targeting, SIGMA/YARA & STIX 2.1 bundles available.',
      catalog: 'https://cyberdudebivash.in/#marketplace',
    },
  };
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────
export async function handlePublicFeeds(request, env, path) {
  switch (path) {
    case '/api/feed.json':                return cachedJson('feed:public:v2',     300, () => buildFeed(env));
    case '/api/v1/intel/latest.json':     return cachedJson('feed:latest:v2',     300, () => buildLatest(env));
    case '/api/v1/intel/apex.json':       return cachedJson('feed:apex:v2',       300, () => buildApex(env));
    case '/api/v1/intel/ai_summary.json': return cachedJson('feed:aisummary:v2',  600, () => buildAiSummary(env));
    case '/api/reports/latest.json':      return cachedJson('feed:reports:v2',    600, () => buildReports(env));
    default:
      return Response.json({ error: 'Unknown feed' }, { status: 404 });
  }
}

export const PUBLIC_FEED_PATHS = [
  '/api/feed.json',
  '/api/v1/intel/latest.json',
  '/api/v1/intel/apex.json',
  '/api/v1/intel/ai_summary.json',
  '/api/reports/latest.json',
];
