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
import { csvRow } from '../lib/csvSafe.js';
import { enrichBatch, buildFeedSummary } from '../services/enrichment.js';
import { extractIOCsFromText }           from '../services/iocExtractor.js';
import { correlateEntry, buildCorrelationSummary } from '../services/correlationEngine.js';
import { buildGraphFromD1, buildGraph }  from '../services/graphEngine.js';
import { runHunting }                    from '../services/huntingEngine.js';
import { ok, fail }                      from '../lib/response.js';

const FEED_CACHE_KEY    = 'threat_intel:feed:v2';
const FEED_CACHE_TTL    = 3600;  // 1 hour — long-term KV cache (full feed)
const HOT_CACHE_KEY     = 'threat_intel:hot:v2';
const HOT_CACHE_TTL     = 60;   // Phase 8: 60s hot cache for frequent queries
const STATS_CACHE_KEY   = 'threat_intel:stats:v2';
const STATS_CACHE_TTL   = 120;  // 2 min stats cache

// ─── Parse + sanitize pagination params ──────────────────────────────────────
function parsePagination(url) {
  const page  = Math.max(1, parseInt(url.searchParams.get('page')  || '1', 10));
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '20', 10)));
  const severity = (url.searchParams.get('severity') || '').toUpperCase();
  const source   = url.searchParams.get('source') || '';
  const query    = (url.searchParams.get('q') || '').trim().slice(0, 100);
  const sortBy   = url.searchParams.get('sort') || 'severity';
  return { page, limit, severity, source, query, sortBy, offset: (page - 1) * limit };
}

// ─── Determine plan tier limits ───────────────────────────────────────────────
function getPlanLimits(tier = 'FREE') {
  const limits = {
    FREE:           { max_results: 5,   ioc_access: false, export: false, full_detail: false, detection_rules: false },
    STARTER:        { max_results: 20,  ioc_access: false, export: false, full_detail: true,  detection_rules: false },
    PRO:            { max_results: 50,  ioc_access: true,  export: true,  full_detail: true,  detection_rules: true  },
    ENTERPRISE:     { max_results: 100, ioc_access: true,  export: true,  full_detail: true,  detection_rules: true  },
    ENTERPRISE_SOC: { max_results: 500, ioc_access: true,  export: true,  full_detail: true,  detection_rules: true  },
  };
  return limits[tier] || limits.FREE;
}

// ─── Redact fields for non-PRO users ─────────────────────────────────────────
function applyMonetizationGate(entry, planLimits) {
  const out = { ...entry };

  try { out.tags = typeof out.tags === 'string' ? JSON.parse(out.tags) : out.tags; } catch { out.tags = []; }
  try { out.affected_products = typeof out.affected_products === 'string' ? JSON.parse(out.affected_products) : out.affected_products; } catch { out.affected_products = []; }
  try { out.weakness_types = typeof out.weakness_types === 'string' ? JSON.parse(out.weakness_types) : out.weakness_types; } catch { out.weakness_types = []; }

  const PREMIUM_FIELDS = ['sigma_rule', 'kql_query', 'kql_detection', 'yara_rule',
                           'suricata_rule', 'ids_signature', 'firewall_script',
                           'ir_playbook', 'hunting_query', 'detection_logic'];
  if (!planLimits.detection_rules) {
    for (const field of PREMIUM_FIELDS) {
      if (out[field] !== undefined) {
        out[field] = {
          gated:       true,
          field:       field,
          plan_required: 'PRO_DEFENSE',
          upgrade_url: '/pricing#pro',
          preview:     out[field] ? String(out[field]).slice(0, 40) + '…[PRO required]' : null,
        };
      }
    }
    if (Array.isArray(out.defense_solutions)) {
      out.defense_solutions = out.defense_solutions.map(ds => {
        const gatedDs = { ...ds };
        for (const field of PREMIUM_FIELDS) {
          if (gatedDs[field]) gatedDs[field] = { gated: true, plan_required: 'PRO_DEFENSE' };
        }
        return gatedDs;
      });
    }
  }

  if (!planLimits.ioc_access) {
    out.iocs = { gated: true, upgrade_url: '/pricing#pro', hint: 'Upgrade to PRO to see IOC details' };
  } else {
    try { out.iocs = typeof out.iocs === 'string' ? JSON.parse(out.iocs) : out.iocs; } catch { out.iocs = []; }
  }

  if (!planLimits.full_detail) {
    if (out.description) out.description = out.description.slice(0, 150) + '… [Upgrade for full details]';
    out.cvss_vector        = null;
    out.affected_products  = out.affected_products?.slice(0, 1);
    out.weakness_types     = [];
    out.mitre_technique    = null;
    out.mitre_tactics      = [];
    out.exploit_references = null;
  }

  return out;
}

// ─── Query D1 for threat intel entries ───────────────────────────────────────
async function queryD1(db, { limit, offset, severity, source, query, sortBy }) {
  if (!db) return null;

  try {
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

    const orderMap = {
      severity: `CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC, cvss DESC`,
      date:     `published_at DESC, created_at DESC`,
      cvss:     `cvss DESC, severity DESC`,
    };
    const order = orderMap[sortBy] || orderMap.severity;

    const countRow = await db.prepare(
      `SELECT COUNT(*) as total FROM threat_intel ${where}`
    ).bind(...bindings).first();
    const total = countRow?.total ?? 0;

    if (total === 0) return null;

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
async function getFromKVCache(env, hot = false) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const key    = hot ? HOT_CACHE_KEY : FEED_CACHE_KEY;
    const cached = await env.SECURITY_HUB_KV.get(key, { type: 'json' });
    return cached;
  } catch {
    return null;
  }
}

// ─── Write to KV hot cache ────────────────────────────────────────────────────
async function writeHotCache(env, data) {
  if (!env?.SECURITY_HUB_KV) return;
  env.SECURITY_HUB_KV.put(HOT_CACHE_KEY, JSON.stringify(data), { expirationTtl: HOT_CACHE_TTL }).catch(() => {});
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

  const effectiveLimit  = Math.min(pagination.limit, planLimits.max_results);
  const effectiveOffset = pagination.offset;

  let entries    = [];
  let total      = 0;
  let dataSource = 'seed';

  const isUnfiltered = !pagination.severity && !pagination.source && !pagination.query && !nocache;
  if (isUnfiltered) {
    const hotCached = await getFromKVCache(env, true);
    if (hotCached?.entries?.length > 0) {
      const hotEntries = hotCached.entries.slice(effectiveOffset, effectiveOffset + effectiveLimit);
      const gatedHot   = hotEntries.map(e => applyMonetizationGate(e, planLimits));
      return ok(request, {
        entries:     gatedHot,
        total:       hotCached.total || gatedHot.length,
        page:        pagination.page,
        limit:       effectiveLimit,
        total_pages: Math.ceil((hotCached.total || gatedHot.length) / effectiveLimit),
        summary:     buildFeedSummary(hotEntries),
        data_source: 'kv_hot',
        plan:        tier,
        plan_limits: planLimits,
        last_updated: hotCached.cached_at || new Date().toISOString(),
        cache_ttl:   HOT_CACHE_TTL,
      });
    }
  }

  // 1. Try D1 database (primary) — BINDING: SECURITY_HUB_DB
  const d1Result = await queryD1(env?.SECURITY_HUB_DB, {
    limit:    effectiveLimit + 5,
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

    if (isUnfiltered && pagination.page === 1) {
      writeHotCache(env, { entries, total, cached_at: new Date().toISOString() });
    }
  } else {
    // 2. Try KV cache
    if (!nocache) {
      const kvFeed = await getFromKVCache(env, false);
      if (kvFeed?.entries?.length > 0) {
        let kvEntries = kvFeed.entries;
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

    // 3. Ultimate fallback: built-in seed
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

      // Auto-trigger background ingestion when serving seed data — BINDING: SECURITY_HUB_DB
      if (env?.SECURITY_HUB_DB && dataSource === 'seed') {
        runIngestion(env).catch(() => {});
      }
    }
  }

  const enrichedEntries = entries.map(e => ({
    ...e,
    ...( !e.enriched ? enrichBatch([e])[0] : {} ),
  }));

  const gatedEntries = enrichedEntries.slice(0, effectiveLimit).map(e => applyMonetizationGate(e, planLimits));
  const summary = buildFeedSummary(enrichedEntries);

  return ok(request, {
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
    ...(tier === 'FREE' ? {
      upgrade_cta: {
        message:     `Showing ${gatedEntries.length} of ${total} advisories. Upgrade to see more.`,
        pro_url:     'https://tools.cyberdudebivash.com/#pricing',
        features:    ['Full IOC details', 'Unlimited advisories', 'CVE export', 'API access'],
      }
    } : {}),
  });
}

// ─── GET /api/threat-intel/stats ─────────────────────────────────────────────
export async function handleThreatIntelStats(request, env, authCtx = {}) {
  let stats = null;

  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get(STATS_CACHE_KEY, { type: 'json' });
      if (cached?.stats) return ok(request, { ...cached, cache_hit: true });
    } catch {}
  }

  // Try D1 for aggregate stats — BINDING: SECURITY_HUB_DB
  if (env?.SECURITY_HUB_DB) {
    try {
      const [total, bySev, bySource, exploited, ransomware, lastRun] = await Promise.all([
        env.SECURITY_HUB_DB.prepare('SELECT COUNT(*) as n FROM threat_intel').first(),
        env.SECURITY_HUB_DB.prepare(`SELECT severity, COUNT(*) as n FROM threat_intel GROUP BY severity`).all(),
        env.SECURITY_HUB_DB.prepare(`SELECT source, COUNT(*) as n FROM threat_intel GROUP BY source`).all(),
        env.SECURITY_HUB_DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE exploit_status = 'confirmed'`).first(),
        env.SECURITY_HUB_DB.prepare(`SELECT COUNT(*) as n FROM threat_intel WHERE known_ransomware = 1`).first(),
        env.SECURITY_HUB_DB.prepare(`SELECT ran_at, inserted, sources, success FROM ingestion_runs ORDER BY ran_at DESC LIMIT 1`).first().catch(() => null),
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

  if (!stats) {
    const summary = buildFeedSummary(SEED_ENTRIES);
    stats = { ...summary, total_advisories: SEED_ENTRIES.length, last_ingestion: null };
  }

  const result = { stats, generated_at: new Date().toISOString() };

  if (env?.SECURITY_HUB_KV && stats) {
    env.SECURITY_HUB_KV.put(STATS_CACHE_KEY, JSON.stringify(result), { expirationTtl: STATS_CACHE_TTL }).catch(() => {});
  }

  return ok(request, result);
}

// ─── GET /api/threat-intel/:id ────────────────────────────────────────────────
export async function handleGetThreatIntelEntry(request, env, authCtx = {}, entryId) {
  const tier       = authCtx?.tier || 'FREE';
  const planLimits = getPlanLimits(tier);
  let entry = null;

  // Try D1 — BINDING: SECURITY_HUB_DB
  if (env?.SECURITY_HUB_DB) {
    try {
      entry = await env.SECURITY_HUB_DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(entryId).first();
    } catch {}
  }

  if (!entry) entry = SEED_ENTRIES.find(e => e.id === entryId) || null;
  if (!entry) return fail(request, `Advisory ${entryId} not found`, 404, 'NOT_FOUND');

  const enriched = enrichBatch([entry])[0];

  if (planLimits.ioc_access) {
    enriched.iocs = extractIOCsFromText(entry.description || '');
  }

  return ok(request, { entry: applyMonetizationGate(enriched, planLimits) });
}

// ─── POST /api/threat-intel/ingest ───────────────────────────────────────────
export async function handleManualIngest(request, env, authCtx = {}) {
  if (!['PRO', 'ENTERPRISE'].includes(authCtx?.tier)) {
    return fail(request, 'Manual ingestion requires ENTERPRISE plan', 403, 'FORBIDDEN');
  }
  try {
    const result = await runIngestion(env);
    if (env?.SECURITY_HUB_KV) {
      env.SECURITY_HUB_KV.delete(FEED_CACHE_KEY).catch(() => {});
    }
    return ok(request, { ingestion: result });
  } catch (e) {
    return fail(request, `Ingestion failed: ${e.message}`, 500);
  }
}

// ─── GET /api/v1/threat-intel ─────────────────────────────────────────────────
export async function handleV1ThreatIntel(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const tier   = authCtx?.tier || 'FREE';
  const limits = getPlanLimits(tier);
  const format = url.searchParams.get('format') || 'json';
  const pag    = parsePagination(url);

  // Dashboard/API consistency fix: this used to always request/report
  // limits.max_results regardless of what the caller asked for, so the same
  // nominal request (e.g. limit=20) returned a different-sized — and
  // differently paginated — entry set than /api/threat-intel, which has
  // always correctly capped to min(requested, plan max). A customer
  // comparing dashboard vs API output for the same query saw a mismatch.
  // Apply the identical cap here so both surfaces return the same records
  // for the same effective limit.
  const effectiveLimit = Math.min(pag.limit, limits.max_results);

  // BINDING: SECURITY_HUB_DB
  const d1Result = await queryD1(env?.SECURITY_HUB_DB, {
    limit:    effectiveLimit,
    offset:   pag.offset,
    severity: pag.severity,
    source:   pag.source,
    query:    pag.query,
    sortBy:   pag.sortBy,
  });

  const entries  = (d1Result?.entries || buildSeedFeed()).slice(0, effectiveLimit);
  const enriched = enrichBatch(entries.map(e => ({ ...e })));
  const gated    = enriched.map(e => applyMonetizationGate(e, limits));

  if (format === 'csv' && tier === 'ENTERPRISE') {
    const header = 'id,severity,cvss,title,source,published_at,exploit_status,known_ransomware\n';
    const rows   = gated.map(e =>
      csvRow([e.id, e.severity, e.cvss, e.title || '', e.source, e.published_at, e.exploit_status, e.known_ransomware])
    ).join('\n');
    return new Response(header + rows, {
      headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=threat-intel.csv' }
    });
  }

  const total = d1Result?.total || entries.length;
  return ok(request, {
    entries:     gated,
    total,
    page:        pag.page,
    limit:       effectiveLimit,
    total_pages: Math.ceil(total / effectiveLimit),
    plan:        tier,
  });
}

// ─── GET /api/v1/iocs ────────────────────────────────────────────────────────
export async function handleV1IOCs(request, env, authCtx = {}) {
  if (authCtx?.tier !== 'ENTERPRISE') {
    return fail(request, 'IOC registry API requires ENTERPRISE plan', 403, 'ENTERPRISE_REQUIRED');
  }

  const url   = new URL(request.url);
  const type  = url.searchParams.get('type') || '';
  const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10));

  // BINDING: SECURITY_HUB_DB
  if (!env?.SECURITY_HUB_DB) {
    return fail(request, 'Database unavailable', 503, 'DB_UNAVAILABLE');
  }

  try {
    const where    = type ? 'WHERE type = ?' : '';
    const bindings = type ? [type, limit] : [limit];
    const rows     = await env.SECURITY_HUB_DB.prepare(
      `SELECT ir.*, ti.severity, ti.title as intel_title
       FROM ioc_registry ir
       JOIN threat_intel ti ON ti.id = ir.intel_id
       ${where}
       ORDER BY ir.created_at DESC
       LIMIT ?`
    ).bind(...bindings).all();

    const countRow = await env.SECURITY_HUB_DB.prepare(
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

// ═══════════════════════════════════════════════════════════════════════════════
// SSE — GET /api/threat-intel/stream
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleThreatIntelStream(request, env, authCtx = {}) {
  const tier       = authCtx?.tier || 'FREE';
  const planLimits = getPlanLimits(tier);
  const url        = new URL(request.url);
  const since      = url.searchParams.get('since') || null;
  const watermarkDate = since ? new Date(since) : null;

  // BINDING: SECURITY_HUB_DB
  async function getSnapshot() {
    if (env?.SECURITY_HUB_DB) {
      try {
        const sinceFilter = watermarkDate
          ? `WHERE (updated_at > '${watermarkDate.toISOString()}' OR created_at > '${watermarkDate.toISOString()}')`
          : '';
        const rows = await env.SECURITY_HUB_DB.prepare(
          `SELECT id, title, severity, cvss, exploit_status, known_ransomware,
                  epss_score, actively_exploited, exploit_available,
                  source, source_url, published_at, tags, description, weakness_types
           FROM threat_intel
           ${sinceFilter}
           ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC, cvss DESC
           LIMIT ?`
        ).bind(planLimits.max_results).all();
        return (rows?.results || []).map(e => applyMonetizationGate(e, planLimits));
      } catch {}
    }
    return buildSeedFeed().slice(0, planLimits.max_results).map(e => applyMonetizationGate(e, planLimits));
  }

  const { readable, writable } = new TransformStream();
  const writer  = writable.getWriter();
  const encoder = new TextEncoder();

  const sseWrite = (eventName, data) =>
    writer.write(encoder.encode(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`));
  const sseComment = (c) =>
    writer.write(encoder.encode(`: ${c}\n\n`));

  const streamLoop = async () => {
    try {
      await sseWrite('connected', {
        message: 'Sentinel APEX stream connected', tier, plan_limits: planLimits,
        timestamp: new Date().toISOString(),
      });

      const snapshot = await getSnapshot();
      await sseWrite('snapshot', {
        entries: snapshot, count: snapshot.length, watermark: new Date().toISOString(),
        data_source: env?.SECURITY_HUB_DB ? 'd1' : 'seed',
      });

      let ticks = 0;
      for (let i = 0; i < 4; i++) {
        await new Promise(r => setTimeout(r, 25000));
        ticks++;
        if (ticks % 2 === 0) {
          try {
            const refresh = await getSnapshot();
            const newEntries = watermarkDate ? refresh : refresh.slice(0, 5);
            if (newEntries.length > 0) {
              await sseWrite('update', { entries: newEntries, count: newEntries.length, watermark: new Date().toISOString() });
            }
          } catch {}
        } else {
          await sseComment(`heartbeat ${new Date().toISOString()}`);
        }
      }
      await sseWrite('end', { message: 'Stream cycle complete. Reconnect for updates.', timestamp: new Date().toISOString() });
    } catch (err) {
      try { await sseWrite('error', { message: 'Stream error — reconnecting automatically', code: err?.message }); } catch {}
    } finally {
      writer.close().catch(() => {});
    }
  };

  if (env?.waitUntil) env.waitUntil(streamLoop());
  else streamLoop().catch(() => {});

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type':                'text/event-stream; charset=utf-8',
      'Cache-Control':               'no-cache, no-store, must-revalidate',
      'Connection':                  'keep-alive',
      'X-Accel-Buffering':           'no',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers':'Authorization, Content-Type',
      'X-Sentinel-Stream':           'v2',
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /api/v1/correlations
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleV1Correlations(request, env, authCtx = {}) {
  if (!['PRO', 'ENTERPRISE'].includes(authCtx?.tier)) {
    return fail(request, 'Correlation API requires PRO or ENTERPRISE plan', 403, 'PLAN_REQUIRED');
  }

  const url   = new URL(request.url);
  const cveId = url.searchParams.get('cve') || '';
  const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10));
  let entries = [];

  // BINDING: SECURITY_HUB_DB
  if (env?.SECURITY_HUB_DB) {
    try {
      const rows = await env.SECURITY_HUB_DB.prepare(
        `SELECT * FROM threat_intel
         ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC
         LIMIT 100`
      ).all();
      entries = rows?.results || [];
    } catch {}
  }

  if (entries.length === 0) entries = SEED_ENTRIES.map(e => ({ ...e }));

  if (cveId) {
    const target = entries.find(e => e.id === cveId);
    if (!target) return fail(request, `CVE ${cveId} not found in feed`, 404, 'NOT_FOUND');
    const correlation = await correlateEntry(target, entries, env);
    return ok(request, { correlation, entry: applyMonetizationGate(target, getPlanLimits(authCtx.tier)) });
  }

  const summary = buildCorrelationSummary(entries);
  const topEntries = entries.filter(e => e.severity === 'CRITICAL' || (e.cvss || 0) >= 9.0).slice(0, limit);
  const correlations = [];
  for (const entry of topEntries) {
    const corr = await correlateEntry(entry, entries, env);
    if (corr.threat_actor || corr.related_cves.length > 0) {
      correlations.push({ cve_id: entry.id, severity: entry.severity, cvss: entry.cvss, ...corr });
    }
  }

  return ok(request, { summary, correlations, total: correlations.length, plan: authCtx.tier });
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /api/v1/graph
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleV1Graph(request, env, authCtx = {}) {
  if (!['PRO', 'ENTERPRISE'].includes(authCtx?.tier)) {
    return fail(request, 'IOC graph API requires PRO or ENTERPRISE plan', 403, 'PLAN_REQUIRED');
  }

  const url    = new URL(request.url);
  const nodeId = url.searchParams.get('node') || '';
  const limit  = Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10));
  const graph  = await buildGraphFromD1(env, limit);

  if (nodeId) {
    const getNeighborhood = (g, id) => {
      const n = g.nodes.find(nd => nd.id === id || nd.value === id);
      if (!n) return { nodes: [], edges: [] };
      const edgeList = g.edges.filter(e => e.source === n.id || e.target === n.id);
      const nodeIds  = new Set([n.id, ...edgeList.map(e => e.source), ...edgeList.map(e => e.target)]);
      return { nodes: g.nodes.filter(nd => nodeIds.has(nd.id)), edges: edgeList };
    };
    return ok(request, { graph: getNeighborhood(graph, nodeId), root_node: nodeId });
  }

  return ok(request, { graph, plan: authCtx.tier });
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /api/v1/hunting
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleV1Hunting(request, env, authCtx = {}) {
  if (!['PRO', 'ENTERPRISE'].includes(authCtx?.tier)) {
    return fail(request, 'Threat hunting API requires PRO or ENTERPRISE plan', 403, 'PLAN_REQUIRED');
  }

  const url    = new URL(request.url);
  const minSev = (url.searchParams.get('min_severity') || 'medium').toLowerCase();
  const limit  = Math.min(100, parseInt(url.searchParams.get('limit') || '100', 10));
  let entries  = [];

  // BINDING: SECURITY_HUB_DB
  if (env?.SECURITY_HUB_DB) {
    try {
      const rows = await env.SECURITY_HUB_DB.prepare(
        `SELECT * FROM threat_intel WHERE severity IN ('CRITICAL', 'HIGH') ORDER BY cvss DESC LIMIT ?`
      ).bind(limit).all();
      entries = rows?.results || [];
    } catch {}
  }

  if (entries.length === 0) entries = SEED_ENTRIES.map(e => ({ ...e }));

  const huntResults = runHunting(entries);
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  huntResults.alerts = huntResults.alerts.filter(a => (sevOrder[a.severity] ?? 4) <= (sevOrder[minSev] ?? 2));

  // BINDING: SECURITY_HUB_DB
  if (authCtx.tier === 'ENTERPRISE' && env?.SECURITY_HUB_DB && huntResults.alerts.length > 0) {
    const critAlerts = huntResults.alerts.filter(a => a.severity === 'critical');
    for (const alert of critAlerts.slice(0, 10)) {
      env.SECURITY_HUB_DB.prepare(
        `INSERT OR IGNORE INTO hunting_alerts (id, type, severity, message, evidence) VALUES (?, ?, ?, ?, ?)`
      ).bind(alert.id, alert.type, alert.severity, alert.message, JSON.stringify(alert.evidence || {})
      ).run().catch(() => {});
    }
  }

  return ok(request, { ...huntResults, plan: authCtx.tier, entry_count: entries.length });
}
