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

import { SEED_ENTRIES } from '../services/threatIngestion.js';
import {
  resolveFeedTier, enforceDailyLimit, gateItems, upgradeMeta,
  pricingMatrix, toStixBundle,
} from './intelMonetization.js';

const PUBLISHER = 'CYBERDUDEBIVASH® Sentinel APEX';
const UPGRADE_URL = 'https://cyberdudebivash.in/#pricing';

function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message, upgrade_url: UPGRADE_URL }, null, 2), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Powered-By': PUBLISHER },
  });
}

function parseLimit(request) {
  try {
    const n = parseInt(new URL(request.url).searchParams.get('limit') || '', 10);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch { return null; }
}

// ─── Drift-defensive intel reader ─────────────────────────────────────────────
// Maps a threat_intel row from EITHER historical column shape:
//   schema_threat_intel.sql → id / cvss      (the live ingestion shape)
//   schema_master.sql        → cve_id / cvss_score
function normalizeItem(r) {
  const cve = r.cve_id || r.id || null;
  // Full payload — premium fields are present for paid tiers and stripped for
  // FREE by gateItems(). A missing column simply yields null (drift-safe).
  return {
    id:            cve,
    cve,
    title:         r.title || 'Security advisory',
    summary:       r.description ? String(r.description).slice(0, 280) : null,
    severity:      String(r.severity || 'MEDIUM').toUpperCase(),
    cvss:          r.cvss ?? r.cvss_score ?? null,
    cvss_vector:   r.cvss_vector ?? null,
    epss_score:    r.epss_score ?? null,
    epss_percentile: r.epss_percentile ?? null,
    exploit_status:  r.exploit_status ?? null,
    actively_exploited: (r.actively_exploited ?? (r.exploit_status === 'confirmed' ? 1 : 0)) ? 1 : 0,
    known_ransomware: r.known_ransomware ? 1 : 0,
    weakness_types:   safeJson(r.weakness_types),
    source:        r.source || PUBLISHER,
    source_url:    r.source_url ?? (cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null),
    published_at:  r.published_at || r.created_at || null,
  };
}

function safeJson(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch { return []; } }
  return [];
}

// Platform-wide ultimate fallback: the curated SEED_ENTRIES, identical to what
// the rest of the intel layer serves when threat_intel is empty. Keeps the
// public feeds consistent with the dashboard instead of showing nothing.
function seedItems(severities) {
  const sevSet = severities && severities.length ? new Set(severities.map(s => s.toUpperCase())) : null;
  let items = (SEED_ENTRIES || []).map(normalizeItem);
  if (sevSet) items = items.filter(i => sevSet.has(i.severity));
  return items;
}

// Returns { items, source } — source is 'd1' for genuinely live database rows
// or 'seed' for the curated fallback, so every public feed can honestly flag
// whether a given response is live intel or the reference baseline, instead
// of silently substituting stale data with no signal to the consumer.
async function fetchRecentIntel(env, { limit = 50, severities = null } = {}) {
  const sevBind   = severities && severities.length ? severities.map(s => s.toUpperCase()) : [];
  const sevClause = sevBind.length ? ` WHERE UPPER(severity) IN (${sevBind.map(() => '?').join(',')})` : '';

  if (env?.SECURITY_HUB_DB) {
    // Tier 1 — SELECT * avoids SELECT-column drift; order by published_at.
    try {
      const rows = await env.SECURITY_HUB_DB.prepare(
        `SELECT * FROM threat_intel${sevClause} ORDER BY published_at DESC LIMIT ?`
      ).bind(...sevBind, limit).all();
      const items = (rows?.results || []).map(normalizeItem);
      if (items.length) return { items, source: 'd1' };
    } catch { /* fall through */ }

    // Tier 2 — no ORDER BY / no WHERE; filter + cap in JS. Never 500s.
    try {
      const rows = await env.SECURITY_HUB_DB.prepare(`SELECT * FROM threat_intel LIMIT 500`).all();
      let items = (rows?.results || []).map(normalizeItem);
      if (sevBind.length) items = items.filter(i => sevBind.includes(i.severity));
      if (items.length) return { items: items.slice(0, limit), source: 'd1' };
    } catch { /* fall through to seed */ }
  }

  // Tier 3 — curated seed fallback (platform-consistent, never empty, NEVER
  // to be presented to the consumer as live data — callers must surface
  // `source` so the customer can tell live intel from the reference baseline).
  return { items: seedItems(severities).slice(0, limit), source: 'seed' };
}

function tally(items) {
  const m = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const it of items) if (it.severity in m) m[it.severity] += 1;
  return { ...m, total: m.CRITICAL + m.HIGH + m.MEDIUM + m.LOW };
}

async function severityCounts(env) {
  if (env?.SECURITY_HUB_DB) {
    try {
      const rows = await env.SECURITY_HUB_DB.prepare(
        `SELECT UPPER(severity) as sev, COUNT(*) as c FROM threat_intel GROUP BY UPPER(severity)`
      ).all();
      const m = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      for (const row of (rows?.results || [])) if (row.sev in m) m[row.sev] = row.c;
      const total = m.CRITICAL + m.HIGH + m.MEDIUM + m.LOW;
      if (total > 0) return { ...m, total, source: 'd1' };
    } catch { /* fall through to seed */ }
  }
  // Seed fallback — consistent with the platform's other intel surfaces.
  return { ...tally(seedItems(null)), source: 'seed' };
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

function jsonResponse(obj, ttl, extraHeaders = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': `public, max-age=${ttl}, s-maxage=${ttl}`,
      'X-Powered-By':  PUBLISHER,
      ...extraHeaders,
    },
  });
}

// ─── Feed builders (tier-aware) ───────────────────────────────────────────────
async function buildFeed(env, ent, reqLimit) {
  const { items: raw, source } = await fetchRecentIntel(env, { limit: ent.max_results });
  const items = gateItems(raw, ent, reqLimit);
  return {
    feed:        'CYBERDUDEBIVASH Public Threat Feed',
    publisher:   PUBLISHER,
    tier:        ent.tier,
    license:     ent.tier === 'FREE' ? 'Free tier — attribution required. Full API: ' + UPGRADE_URL : 'Licensed API access',
    generated_at: new Date().toISOString(),
    data_source: source,
    live:        source !== 'seed',
    count:       items.length,
    items,
    upgrade:     upgradeMeta(ent),
  };
}

async function buildLatest(env, ent, reqLimit) {
  const { items: raw, source } = await fetchRecentIntel(env, { limit: ent.max_results });
  const items = gateItems(raw, ent, reqLimit);
  return {
    version: 'v1', feed: 'latest', publisher: PUBLISHER, tier: ent.tier,
    generated_at: new Date().toISOString(), data_source: source, live: source !== 'seed',
    count: items.length, items,
    upgrade: upgradeMeta(ent),
  };
}

async function buildApex(env, ent, reqLimit) {
  const { items: raw, source } = await fetchRecentIntel(env, { limit: ent.max_results, severities: ['CRITICAL', 'HIGH'] });
  const items = gateItems(raw, ent, reqLimit);
  return {
    version: 'v1', feed: 'sentinel-apex', publisher: PUBLISHER, tier: ent.tier,
    description: 'Curated critical & high-severity advisories from Sentinel APEX',
    generated_at: new Date().toISOString(), data_source: source, live: source !== 'seed',
    count: items.length, items,
    upgrade: upgradeMeta(ent),
  };
}

// KEV feed — the actively-exploited catalog (the crown jewel). FREE gets a
// recent slice; paid tiers get the full ~1,600-entry catalog.
async function fetchKEV(env, limit) {
  if (env?.SECURITY_HUB_DB) {
    try {
      const rows = await env.SECURITY_HUB_DB.prepare(
        `SELECT * FROM threat_intel WHERE exploit_status='confirmed' ORDER BY published_at DESC LIMIT ?`
      ).bind(limit).all();
      const items = (rows?.results || []).map(normalizeItem);
      if (items.length) return { items, source: 'd1' };
    } catch { /* fall through */ }
  }
  return {
    items: seedItems(null).filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').slice(0, limit),
    source: 'seed',
  };
}

async function buildKev(env, ent, reqLimit) {
  const { items: raw, source } = await fetchKEV(env, ent.kev_full ? ent.max_results : 25);
  const items = gateItems(raw, ent, reqLimit);
  return {
    version: 'v1', feed: 'cisa-kev', publisher: PUBLISHER, tier: ent.tier,
    description: 'CISA Known Exploited Vulnerabilities — confirmed in-the-wild exploitation',
    full_catalog: ent.kev_full,
    generated_at: new Date().toISOString(), data_source: source, live: source !== 'seed',
    count: items.length, items,
    upgrade: upgradeMeta(ent),
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
    data_source:  c.source,
    live:         c.source !== 'seed',
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

async function buildReports(env, ent) {
  const cap = Math.min(ent?.max_results ?? 10, 25);
  const { items: raw, source } = await fetchRecentIntel(env, { limit: cap, severities: ['CRITICAL', 'HIGH'] });
  const reports = raw.map((it, i) => ({
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
    data_source:  source,
    live:         source !== 'seed',
    count:        reports.length,
    reports,
    premium_reports: {
      note: 'Full 30-day landscape, APT targeting, SIGMA/YARA & STIX 2.1 bundles available.',
      catalog: 'https://cyberdudebivash.in/#marketplace',
    },
  };
}

// ─── STIX 2.1 export (premium) ────────────────────────────────────────────────
async function buildStix(env, ent, reqLimit) {
  const { items: raw } = await fetchKEV(env, ent.max_results);
  const items = raw.slice(0, Math.min(ent.max_results, reqLimit || ent.max_results));
  return toStixBundle(items, { tlp: 'clear' });
}

function rateHeaders(rl, ent) {
  return {
    'X-RateLimit-Tier':      ent.tier,
    'X-RateLimit-Limit':     String(rl.limit),
    'X-RateLimit-Remaining': String(rl.remaining),
  };
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────
// FREE (no key) → edge-cached, gated responses (identical for everyone).
// Keyed (paid)  → dynamic, full-detail responses, rate-limited per key.
export async function handlePublicFeeds(request, env, path) {
  const ent = await resolveFeedTier(request, env);
  if (ent.invalidKey) return jsonError('Invalid API key — obtain one at ' + UPGRADE_URL, 401);

  // Public pricing — always available, heavily cached.
  if (path === '/api/v1/intel/pricing.json') return jsonResponse(pricingMatrix(), 3600);

  const reqLimit = parseLimit(request);

  // STIX export is a paid-only entitlement.
  if (path === '/api/v1/intel/stix.json') {
    if (!ent.stix) {
      return jsonError('STIX 2.1 export requires a Pro plan or above. Upgrade: ' + UPGRADE_URL, 402);
    }
    const rl = await enforceDailyLimit(env, ent, ent.identity);
    if (!rl.allowed) return jsonError('Daily quota exceeded for your plan. Upgrade: ' + UPGRADE_URL, 429);
    return jsonResponse(await buildStix(env, ent, reqLimit), 300, rateHeaders(rl, ent));
  }

  // Paid (keyed) callers → dynamic, full-detail, rate-limited (no shared cache).
  if (ent.keyed) {
    const rl = await enforceDailyLimit(env, ent, ent.identity);
    if (!rl.allowed) return jsonError('Daily quota exceeded for your plan. Upgrade: ' + UPGRADE_URL, 429);
    const headers = rateHeaders(rl, ent);
    switch (path) {
      case '/api/feed.json':                return jsonResponse(await buildFeed(env, ent, reqLimit),     60, headers);
      case '/api/v1/intel/latest.json':     return jsonResponse(await buildLatest(env, ent, reqLimit),  60, headers);
      case '/api/v1/intel/apex.json':       return jsonResponse(await buildApex(env, ent, reqLimit),    60, headers);
      case '/api/v1/intel/kev.json':        return jsonResponse(await buildKev(env, ent, reqLimit),     60, headers);
      case '/api/v1/intel/ai_summary.json': return jsonResponse(await buildAiSummary(env),              60, headers);
      case '/api/reports/latest.json':      return jsonResponse(await buildReports(env, ent),           60, headers);
      default:                              return jsonError('Unknown feed', 404);
    }
  }

  // FREE (anonymous) → edge-cached gated responses. Cache key carries the FREE
  // tier so a paid response can never leak into the shared cache.
  switch (path) {
    case '/api/feed.json':                return cachedJson('feed:public:free:v4',    300, () => buildFeed(env, ent, reqLimit));
    case '/api/v1/intel/latest.json':     return cachedJson('feed:latest:free:v4',    300, () => buildLatest(env, ent, reqLimit));
    case '/api/v1/intel/apex.json':       return cachedJson('feed:apex:free:v4',      300, () => buildApex(env, ent, reqLimit));
    case '/api/v1/intel/kev.json':        return cachedJson('feed:kev:free:v4',       300, () => buildKev(env, ent, reqLimit));
    case '/api/v1/intel/ai_summary.json': return cachedJson('feed:aisummary:free:v4', 600, () => buildAiSummary(env));
    case '/api/reports/latest.json':      return cachedJson('feed:reports:free:v4',   600, () => buildReports(env, ent));
    default:                              return jsonError('Unknown feed', 404);
  }
}

export const PUBLIC_FEED_PATHS = [
  '/api/feed.json',
  '/api/v1/intel/latest.json',
  '/api/v1/intel/apex.json',
  '/api/v1/intel/ai_summary.json',
  '/api/reports/latest.json',
  '/api/v1/intel/kev.json',
  '/api/v1/intel/stix.json',
  '/api/v1/intel/pricing.json',
];
