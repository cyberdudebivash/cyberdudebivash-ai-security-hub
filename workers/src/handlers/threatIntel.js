/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Intelligence API Handler v2.0
 *
 * Endpoints:
 *   GET  /api/threat-intel          → paginated feed (FREE: 5, PRO: 50, ENT: 100)
 *   GET  /api/threat-intel/stats    → aggregate stats
 *   GET  /api/threat-intel/:id      → single advisory detail
 *   POST /api/threat-intel/ingest   → manual ingestion trigger (ADMIN only)
 *   GET  /api/v1/threat-intel       → versioned API (PRO+, API key required)
 *   GET  /api/v1/iocs               → IOC registry (ENTERPRISE+)
 *
 * Data hierarchy (fallback chain):
 *   1. D1 database (primary, persistent)
 *   2. KV cache of last ingestion result
 *   3. Built-in seed data (always available)
 */

import { runIngestion, SEED_ENTRIES }  from '../services/threatIngestion.js';
import { enrichBatch, buildFeedSummary } from '../services/enrichment.js';
import { extractIOCsFromText }           from '../services/iocExtractor.js';
import { ok, fail }                      from '../lib/response.js';

const FEED_CACHE_KEY   = 'threat_intel:feed:v2';
const FEED_CACHE_TTL   = 3600; // 1 hour KV cache

// ─── Parse + sanitize pagination params ──────────────────────────────────────
function parsePagination(url) {
  const page  = Math.max(1, parseInt(url.searchParams.get('page')  || '1', 10));
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '20', 10)));
  const severity = (url.searchParams.get('severity') || '').toUpperCase();
  const source   = url.searchParams.get('source') || '';
  const query    = (url.searchParams.get('q') || '').trim().slice(0, 100);
  const sortBy   = url.searchParams.get('sort') || 'severity'; // severity | date | cvss
  return { page, limit, severity, source, query, sortBy, offset: (page - 1) * limit };
}

// ─── Determine plan tier limits ───────────────────────────────────────────────
function getPlanLimits(tier = 'FREE') {
  const limits = {
    FREE:       { max_results: 5,  ioc_access: false, export: false, full_detail: false },
    STARTER:    { max_results: 20, ioc_access: false, export: false, full_detail: true  },
    PRO:        { max_results: 50, ioc_access: true,  export: true,  full_detail: true  },
    ENTERPRISE: { max_results: 100, ioc_access: true, export: true,  full_detail: true  },
  };
  return limits[tier] || limits.FREE;
}

// ─── Redact IOC fields for non-PRO users ─────────────────────────────────────
function applyMonetizationGate(entry, planLimits) {
  const out = { ...entry };

  // Parse JSON strings
  try { out.tags = typeof out.tags === 'string' ? JSON.parse(out.tags) : out.tags; } catch { out.tags = []; }
  try { out.affected_products = typeof out.affected_products === 'string' ? JSON.parse(out.affected_products) : out.affected_products; } catch { out.affected_products = []; }
  try { out.weakness_types = typeof out.weakness_types === 'string' ? JSON.parse(out.weakness_types) : out.weakness_types; } catch { out.weakness_types = []; }

  if (!planLimits.ioc_access) {
    // Gate IOCs behind PRO
    out.iocs = { gated: true, upgrade_url: 'https://tools.cyberdudebivash.com/#pricing', hint: 'Upgrade to PRO to see IOC details' };
  } else {
    try { out.iocs = typeof out.iocs === 'string' ? JSON.parse(out.iocs) : out.iocs; } catch { out.iocs = []; }
  }

  if (!planLimits.full_detail) {
    // FREE: truncate description
    if (out.description) out.description = out.description.slice(0, 150) + '… [Upgrade for full details]';
    out.cvss_vector        = null;
    out.affected_products  = out.affected_products?.slice(0, 1);
    out.weakness_types     = [];
    out.mitre_technique    = null;
  }

  return out;
}

// ─── Query D1 for threat intel entries ───────────────────────────────────────
async function queryD1(db, { limit, offset, severity, source, query, sortBy }) {
  if (!db) return null;

  try {
    // Build WHERE clause
    const conditions = [];
    const bindings   = [];

    if (severity && ['CRITICAL','HIGH','MEDIUM','LOW'].includes(severity)) {
      conditions.push('severity = ?');
      bindings.push(severity);
    }
    if (source) {
      conditions.push('source = ?');
      bindings.push(source);
    }
    if (query) {
      conditions.push('(title LIKE ? OR description LIKE ? OR id LIKE ?)');
      bindings.push(`%${query}%`, `%${query}%`, `%${query}%`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    // Build ORDER clause
    const orderMap = {
      severity: `CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC, cvss DESC`,
      date:     `published_at DESC, created_at DESC`,
      cvss:     `cvss DESC, severity DESC`,
    };
    const order = orderMap[sortBy] || orderMap.severity;

    // Count total
    const countRow = await db.prepare(
      `SELECT COUNT(*) as total FROM threat_intel ${where}`
    ).bind(...bindings).first();
    const total = countRow?.total ?? 0;

    if (total === 0) return null; // trigger fallback

    // Fetch entries
    const rows = await db.prepare(
      `SELECT * FROM threat_intel ${where} ORDER BY ${order} LIMIT ? OFFSET ?`
    ).bind(...bindings, limit, offset).all();

    return { entries: rows?.results || [], total };
  } catch (e) {
    console.error('[threatIntel] D1 query failed:', e.message);
    return null;
  }
}

// ─── Get feed from KV cache ───────────────────────────────────────────────────
async function getFromKVCache(env) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const cached = await env.SECURITY_HUB_KV.get(FEED_CACHE_KEY, { type: 'json' });
    return cached;
  } catch {
    return null;
  }
}

// ─── Build feed from seed + enrichment (ultimate fallback) ───────────────────
function buildSeedFeed() {
  const enriched = enrichBatch(SEED_ENTRIES.map(e => ({ ...e })));
  enriched.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));
  return enriched;
}

// ─── GET /api/threat-intel ────────────────────────────────────────────────────
export async function handleGetThreatIntel(request, env, authCtx = {}) {
  const url        = new URL(request.url);
  const pagination = parsePagination(url);
  const tier       = authCtx?.tier || 'FREE';
  const planLimits = getPlanLimits(tier);
  const nocache    = url.searchParams.get('nocache') === '1';

  // Enforce plan tier limits on result count
  const effectiveLimit = Math.min(pagination.limit, planLimits.max_results);
  const effectiveOffset = pagination.offset;

  let entries  = [];
  let total    = 0;
  let dataSource = 'seed';

  // ── 1. Try D1 database (primary) ──
  const d1Result = await queryD1(env?.DB, {
    limit:    effectiveLimit + 5, // fetch a few extra for dedup
    offset:   effectiveOffset,
    severity: pagination.severity,
    source:   pagination.source,
    query:    pagination.query,
    sortBy:   pagination.sortBy,
  });

  if (d1Result && d1Result.total > 0) {
    entries    = d1Result.entries;
    total      = d1Result.total;
    dataSource = 'd1';
  } else {
    // ── 2. Try KV cache ──
    if (!nocache) {
      const kvFeed = await getFromKVCache(env);
      if (kvFeed?.entries?.length > 0) {
        let kvEntries = kvFeed.entries;
        // Apply filters manually
        if (pagination.severity) kvEntries = kvEntries.filter(e => e.severity === pagination.severity);
        if (pagination.source)   kvEntries = kvEntries.filter(e => e.source   === pagination.source);
        if (pagination.query) {
          const q = pagination.query.toLowerCase();
          kvEntries = kvEntries.filter(e =>
            (e.title || '').toLowerCase().includes(q) ||
            (e.description || '').toLowerCase().includes(q) ||
            (e.id || '').toLowerCase().includes(q)
          );
        }
        total   = kvEntries.length;
        entries = kvEntries.slice(effectiveOffset, effectiveOffset + effectiveLimit);
        dataSource = 'kv_cache';
      }
    }

    // ── 3. Ultimate fallback: built-in seed ──
    if (entries.length === 0) {
      const seed = buildSeedFeed();
      let filtered = seed;
      if (pagination.severity) filtered = filtered.filter(e => e.severity === pagination.severity);
      if (pagination.query) {
        const q = pagination.query.toLowerCase();
        filtered = filtered.filter(e =>
          (e.title || '').toLowerCase().includes(q) ||
          (e.description || '').toLowerCase().includes(q)
        );
      }
      total   = filtered.length;
      entries = filtered.slice(effectiveOffset, effectiveOffset + effectiveLimit);
      dataSource = 'seed';

      // Auto-seed D1 in the background so next request hits the database
      if (env?.DB && dataSource === 'seed') {
        runIngestion(env).catch(() => {});
      }
    }
  }

  // Enrich entries that haven't been enriched yet
  const enrichedEntries = entries.map(e => ({
    ...e,
    ...( !e.enriched ? enrichBatch([e])[0] : {} ),
  }));

  // Apply monetization gate
  const gatedEntries = enrichedEntries.slice(0, effectiveLimit).map(e => applyMonetizationGate(e, planLimits));

  // Build summary stats from current page
  const summary = buildFeedSummary(enrichedEntries);

  const data = {
    entries:     gatedEntries,
    total,
    page:        pagination.page,
    limit:       effectiveLimit,
    total_pages: Math.ceil(total / effectiveLimit),
    summary,
    data_source:  dataSource,
    plan:         tier,
    plan_limits:  planLimits,
    last_updated: new Date().toISOString(),
    // Upgrade CTA for FREE users
    ...(tier === 'FREE' ? {
      upgrade_cta: {
        message:     `Showing ${gatedEntries.length} of ${total} advisories. Upgrade to see more.`,
        pro_url:     'https://tools.cyberdudebivash.com/#pricing',
        features:    ['Full IOC details', 'Unlimited advisories', 'CVE export', 'API access'],
      }
    } : {}),
  };

  return ok(request, data);
}

// ─── GET /api/threat-intel/stats ─────────────────────────────────────────────
export async function handleThreatIntelStats(request, env, authCtx = {}) {
  let stats = null;

  // Try D1 for aggregate stats
  if (env?.DB) {
    try {
      const [total, bySev, bySource, exploited, ransomware, lastRun] = await Promise.all([
        env.DB.prepare('SELECT COUNT(*) as n FROM threat_intel').first(),
        env.DB.prepare(`
          SELECT severity, COUNT(*) as n FROM threat_intel GROUP BY severity
        `).all(),
        env.DB.prepare(`
          SELECT source, COUNT(*) as n FROM threat_intel GROUP BY source
        `).all(),
        env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE exploit_status = 'confirmed'`).first(),
        env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE known_ransomware = 1`).first(),
        env.DB.prepare(`
          SELECT ran_at, inserted, sources, success FROM ingestion_runs ORDER BY ran_at DESC LIMIT 1
        `).first().catch(() => null),
      ]);

      const bySevMap = {};
      for (const r of bySev.results || []) bySevMap[r.severity] = r.n;
      const bySrcMap = {};
      for (const r of bySource.results || []) bySrcMap[r.source] = r.n;

      stats = {
        total_advisories:    total?.n ?? 0,
        critical:            bySevMap.CRITICAL ?? 0,
        high:                bySevMap.HIGH ?? 0,
        medium:              bySevMap.MEDIUM ?? 0,
        low:                 bySevMap.LOW ?? 0,
        confirmed_exploited: exploited?.n ?? 0,
        ransomware_linked:   ransomware?.n ?? 0,
        by_source:           bySrcMap,
        last_ingestion:      lastRun ? {
          ran_at:   lastRun.ran_at,
          inserted: lastRun.inserted,
          sources:  typeof lastRun.sources === 'string' ? JSON.parse(lastRun.sources) : lastRun.sources,
          success:  !!lastRun.success,
        } : null,
      };
    } catch {}
  }

  // Fallback: stats from seed data
  if (!stats) {
    const summary = buildFeedSummary(SEED_ENTRIES);
    stats = {
      ...summary,
      total_advisories: SEED_ENTRIES.length,
      last_ingestion:   null,
    };
  }

  return ok(request, { stats, generated_at: new Date().toISOString() });
}

// ─── GET /api/threat-intel/:id ────────────────────────────────────────────────
export async function handleGetThreatIntelEntry(request, env, authCtx = {}, entryId) {
  const tier       = authCtx?.tier || 'FREE';
  const planLimits = getPlanLimits(tier);

  let entry = null;

  // Try D1
  if (env?.DB) {
    try {
      entry = await env.DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(entryId).first();
    } catch {}
  }

  // Try seed
  if (!entry) {
    entry = SEED_ENTRIES.find(e => e.id === entryId) || null;
  }

  if (!entry) {
    return fail(request, `Advisory ${entryId} not found`, 404, 'NOT_FOUND');
  }

  const enriched = enrichBatch([entry])[0];

  // IOC extraction on-demand for PRO+
  if (planLimits.ioc_access) {
    const iocList = extractIOCsFromText(entry.description || '');
    enriched.iocs = iocList;
  }

  const gated = applyMonetizationGate(enriched, planLimits);

  return ok(request, { entry: gated });
}

// ─── POST /api/threat-intel/ingest ───────────────────────────────────────────
// Manual trigger — ENTERPRISE admin only
export async function handleManualIngest(request, env, authCtx = {}) {
  if (!['PRO', 'ENTERPRISE'].includes(authCtx?.tier)) {
    return fail(request, 'Manual ingestion requires ENTERPRISE plan', 403, 'FORBIDDEN');
  }

  try {
    const result = await runIngestion(env);
    // Invalidate KV cache so next request gets fresh D1 data
    if (env?.SECURITY_HUB_KV) {
      env.SECURITY_HUB_KV.delete(FEED_CACHE_KEY).catch(() => {});
    }
    return ok(request, { ingestion: result });
  } catch (e) {
    return fail(request, `Ingestion failed: ${e.message}`, 500);
  }
}

// ─── GET /api/v1/threat-intel ─────────────────────────────────────────────────
// Versioned API — PRO/ENTERPRISE API key only
export async function handleV1ThreatIntel(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const tier   = authCtx?.tier || 'FREE';
  const limits = getPlanLimits(tier);
  const format = url.searchParams.get('format') || 'json';
  const pag    = parsePagination(url);

  const d1Result = await queryD1(env?.DB, {
    limit:  limits.max_results,
    offset: pag.offset,
    severity: pag.severity,
    source:   pag.source,
    query:    pag.query,
    sortBy:   pag.sortBy,
  });

  const entries = d1Result?.entries || buildSeedFeed();
  const enriched = enrichBatch(entries.map(e => ({ ...e })));
  const gated    = enriched.map(e => applyMonetizationGate(e, limits));

  // ENTERPRISE: support CSV export
  if (format === 'csv' && tier === 'ENTERPRISE') {
    const header = 'id,severity,cvss,title,source,published_at,exploit_status,known_ransomware\n';
    const rows   = gated.map(e =>
      [e.id, e.severity, e.cvss, `"${(e.title || '').replace(/"/g, '""')}"`, e.source, e.published_at, e.exploit_status, e.known_ransomware].join(',')
    ).join('\n');
    return new Response(header + rows, {
      headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=threat-intel.csv' }
    });
  }

  return ok(request, {
    entries:    gated,
    total:      d1Result?.total || entries.length,
    page:       pag.page,
    limit:      limits.max_results,
    plan:       tier,
  });
}

// ─── GET /api/v1/iocs ────────────────────────────────────────────────────────
// IOC Registry — ENTERPRISE only
export async function handleV1IOCs(request, env, authCtx = {}) {
  if (authCtx?.tier !== 'ENTERPRISE') {
    return fail(request, 'IOC registry API requires ENTERPRISE plan', 403, 'ENTERPRISE_REQUIRED');
  }

  const url   = new URL(request.url);
  const type  = url.searchParams.get('type') || '';
  const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10));

  if (!env?.DB) {
    return fail(request, 'Database unavailable', 503, 'DB_UNAVAILABLE');
  }

  try {
    const where    = type ? 'WHERE type = ?' : '';
    const bindings = type ? [type, limit] : [limit];
    const rows     = await env.DB.prepare(
      `SELECT ir.*, ti.severity, ti.title as intel_title
       FROM ioc_registry ir
       JOIN threat_intel ti ON ti.id = ir.intel_id
       ${where}
       ORDER BY ir.created_at DESC
       LIMIT ?`
    ).bind(...bindings).all();

    const countRow = await env.DB.prepare(
      `SELECT COUNT(*) as n FROM ioc_registry ${where}`
    ).bind(...(type ? [type] : [])).first();

    return ok(request, {
      iocs:  rows.results || [],
      total: countRow?.n ?? 0,
      type:  type || 'all',
    });
  } catch (e) {
    return fail(request, `IOC query failed: ${e.message}`, 500);
  }
}
