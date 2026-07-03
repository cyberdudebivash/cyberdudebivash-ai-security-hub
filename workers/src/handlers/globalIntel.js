/**
 * CYBERDUDEBIVASH AI Security Hub — Global Threat Intel display handlers
 * The DISPLAY stage of the Global Intel Firehose (services/globalIntelFirehose.js).
 *
 *   GET  /api/global-intel            → paginated feed, BREAKING + freshest first
 *   GET  /api/global-intel/briefing   → the latest hourly briefing (KV snapshot)
 *   GET  /api/global-intel/sources    → the live source registry (transparency)
 *   POST /api/global-intel/refresh    → ADMIN: trigger an on-demand pipeline run
 *
 * MONETIZATION: every read is authenticated + rate-limited + tier-gated. FREE
 * sees a capped teaser (limited items, truncated summaries, enrichment counts
 * but not the IOCs/actors/malware/CVE detail); PRO+ get the full firehose. The
 * expensive full-pipeline recompute is ADMIN-only and never triggered by an
 * anonymous GET — the public briefing is derived cheaply from KV/D1.
 */

import { ok, fail } from '../lib/response.js';
import { resolveAuthV5, isOwner } from '../auth/middleware.js';
import { checkRateLimitV2, rateLimitResponse } from '../middleware/rateLimit.js';
import { runGlobalIntelFirehose, ensureGlobalIntelTable, INTEL_SOURCES } from '../services/globalIntelFirehose.js';

const VALID_CATEGORIES = ['news', 'research', 'advisory', 'ioc', 'ransomware', 'breach', 'apt', 'malware', 'phishing', 'exploit', 'vulnerability'];

// ─── Tier plan limits (monetization boundary) ────────────────────────────────
const GI_PLANS = {
  FREE:           { max: 6,   ioc: false, enrich: false, briefing_items: 5,  export: false },
  STARTER:        { max: 15,  ioc: false, enrich: true,  briefing_items: 8,  export: false },
  PRO:            { max: 50,  ioc: true,  enrich: true,  briefing_items: 12, export: true  },
  ENTERPRISE:     { max: 100, ioc: true,  enrich: true,  briefing_items: 12, export: true  },
  ENTERPRISE_SOC: { max: 200, ioc: true,  enrich: true,  briefing_items: 12, export: true  },
  MSSP:           { max: 200, ioc: true,  enrich: true,  briefing_items: 12, export: true  },
};
function planFor(tier) { return GI_PLANS[tier] || GI_PLANS.FREE; }

async function authOf(request, env) {
  return resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', identity: 'ip:anon', authenticated: false }));
}

const parseJson = (s, d = '[]') => { try { return JSON.parse(s || d); } catch { return JSON.parse(d); } };

function rowToItem(r) {
  return {
    intel_id: r.intel_id, title: r.title, summary: r.summary, url: r.url,
    source: r.source, source_name: r.source_name, category: r.category, region: r.region,
    severity: r.severity, threat_score: r.threat_score, is_breaking: !!r.is_breaking,
    cve_ids: parseJson(r.cve_ids), actors: parseJson(r.actors), malware: parseJson(r.malware),
    iocs: parseJson(r.iocs), tags: parseJson(r.tags),
    published_at: r.published_at, ingested_at: r.ingested_at,
  };
}

// ─── Gate a single item to the caller's plan ─────────────────────────────────
function gateItem(it, p) {
  const base = {
    intel_id: it.intel_id, title: it.title, url: it.url,
    source: it.source, source_name: it.source_name, category: it.category, region: it.region,
    severity: it.severity, threat_score: it.threat_score, is_breaking: it.is_breaking,
    published_at: it.published_at,
  };
  if (!p.enrich) {
    // FREE teaser: truncated summary, enrichment locked (counts only, not detail).
    const s = it.summary || '';
    return {
      ...base,
      summary: s.length > 140 ? s.slice(0, 140) + '…' : s,
      cve_ids: [], actors: [], malware: [], tags: [it.category],
      iocs: { gated: true, upgrade_url: '/pricing#pro' },
      enrichment_gated: true,
      enrichment_counts: { cves: it.cve_ids.length, actors: it.actors.length, malware: it.malware.length, iocs: it.iocs.length },
    };
  }
  return {
    ...base,
    summary: it.summary, cve_ids: it.cve_ids, actors: it.actors, malware: it.malware,
    tags: it.tags,
    iocs: p.ioc ? it.iocs : { gated: true, upgrade_url: '/pricing#pro', hint: 'Upgrade to PRO for live IOCs' },
  };
}

// ─── GET /api/global-intel ────────────────────────────────────────────────────
export async function handleGlobalIntelFeed(request, env) {
  const authCtx = await authOf(request, env);
  const rl = await checkRateLimitV2(env, authCtx, 'global-intel');
  if (!rl.allowed) return rateLimitResponse(rl, 'global-intel');

  const tier = authCtx.tier || 'FREE';
  const p    = planFor(tier);

  const url      = new URL(request.url);
  const reqLimit = Math.max(1, parseInt(url.searchParams.get('limit') || '30', 10));
  const limit    = Math.min(reqLimit, p.max);
  const offset   = Math.max(0, parseInt(url.searchParams.get('offset') || '0', 10));
  const category = (url.searchParams.get('category') || '').toLowerCase();
  const severity = (url.searchParams.get('severity') || '').toUpperCase();
  const source   = url.searchParams.get('source') || '';
  const q        = (url.searchParams.get('q') || '').trim().slice(0, 80);
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
        : 'ORDER BY is_breaking DESC, published_at DESC, threat_score DESC';

    const [rows, countRow] = await Promise.all([
      db.prepare(`SELECT * FROM global_intel ${whereSql} ${orderSql} LIMIT ? OFFSET ?`).bind(...binds, limit, offset).all(),
      db.prepare(`SELECT COUNT(*) AS total FROM global_intel ${whereSql}`).bind(...binds).first(),
    ]);

    const raw   = (rows.results || []).map(rowToItem);
    const items = raw.map(it => gateItem(it, p));
    const total = countRow?.total ?? 0;

    return ok(request, {
      items,
      total,
      limit,
      offset,
      sort,
      category: category || 'all',
      plan: tier,
      plan_limits: { max_results: p.max, ioc_access: p.ioc, full_enrichment: p.enrich, export: p.export },
      last_updated: raw[0]?.ingested_at || null,
      rate_remaining: rl.remaining,
      ...(p.enrich ? {} : {
        upgrade_cta: {
          message: `Showing ${items.length} of ${total} live intel items with limited detail. Upgrade to PRO for the full firehose, IOCs, threat-actor & malware attribution, and export.`,
          pro_url: '/pricing#pro',
          features: ['Full worldwide feed (50+ items)', 'Live IOCs', 'Actor & malware attribution', 'CVE correlation', 'Export'],
        },
      }),
    });
  } catch (e) {
    return fail(request, 'Query failed: ' + (e?.message || 'unknown'), 500);
  }
}

// ─── Cheap briefing derived from stored D1 rows (no outbound fetch) ───────────
async function briefingFromD1(db, p) {
  await ensureGlobalIntelTable(db);
  const [sev, cat, breakingRow, topRows] = await Promise.all([
    db.prepare(`SELECT severity, COUNT(*) n FROM global_intel GROUP BY severity`).all(),
    db.prepare(`SELECT category, COUNT(*) n FROM global_intel GROUP BY category`).all(),
    db.prepare(`SELECT COUNT(*) n FROM global_intel WHERE is_breaking = 1 AND published_at >= datetime('now','-6 hours')`).first(),
    db.prepare(`SELECT * FROM global_intel ORDER BY is_breaking DESC, published_at DESC, threat_score DESC LIMIT 40`).all(),
  ]);

  const by_severity = {}; for (const r of sev.results || []) by_severity[r.severity] = r.n;
  const by_category = {}; for (const r of cat.results || []) by_category[r.category] = r.n;
  const breaking = breakingRow?.n || 0;
  const top = (topRows.results || []).map(rowToItem);

  const actors  = Array.from(new Set(top.flatMap(i => i.actors))).slice(0, 15);
  const malware = Array.from(new Set(top.flatMap(i => i.malware))).slice(0, 15);
  const cves    = Array.from(new Set(top.flatMap(i => i.cve_ids))).slice(0, 20);

  const level = (by_severity.CRITICAL || 0) >= 3 ? 'CRITICAL'
    : (by_severity.CRITICAL || (by_severity.HIGH || 0) >= 5) ? 'HIGH'
    : (by_severity.HIGH ? 'ELEVATED' : 'GUARDED');

  return {
    generated_at: new Date().toISOString(),
    threat_level: level,
    headline: `${breaking} breaking item(s) in the last 6h · ${by_severity.CRITICAL || 0} critical, ${by_severity.HIGH || 0} high across ${Object.keys(by_category).length} categories`,
    total_items: Object.values(by_severity).reduce((a, b) => a + b, 0),
    breaking_count: breaking,
    by_severity, by_category,
    // Attribution detail is a PRO asset — FREE gets counts, not the lists.
    active_actors:  p.enrich ? actors  : [],
    active_malware: p.enrich ? malware : [],
    referenced_cves:p.enrich ? cves    : [],
    attribution_locked: !p.enrich,
    attribution_counts: { actors: actors.length, malware: malware.length, cves: cves.length },
    top_intel: top.slice(0, p.briefing_items).map(t => ({
      intel_id: t.intel_id, title: t.title, url: t.url, source_name: t.source_name,
      category: t.category, severity: t.severity, threat_score: t.threat_score,
      is_breaking: t.is_breaking, published_at: t.published_at,
    })),
  };
}

// ─── GET /api/global-intel/briefing ──────────────────────────────────────────
export async function handleGlobalIntelBriefing(request, env) {
  const authCtx = await authOf(request, env);
  const rl = await checkRateLimitV2(env, authCtx, 'global-intel');
  if (!rl.allowed) return rateLimitResponse(rl, 'global-intel');

  const tier = authCtx.tier || 'FREE';
  const p    = planFor(tier);

  // Prefer the hourly KV snapshot written by the cron, but ALWAYS re-gate it for
  // the caller's tier (never serve the full PRO attribution to a FREE caller).
  let briefing = null;
  if (env?.SECURITY_HUB_KV) {
    try { briefing = await env.SECURITY_HUB_KV.get('global_intel:briefing:v1', { type: 'json' }); } catch {}
  }
  if (briefing) {
    if (!p.enrich) {
      briefing = {
        ...briefing,
        active_actors: [], active_malware: [], referenced_cves: [],
        attribution_locked: true,
        attribution_counts: {
          actors: (briefing.active_actors || []).length,
          malware: (briefing.active_malware || []).length,
          cves: (briefing.referenced_cves || []).length,
        },
        top_intel: (briefing.top_intel || []).slice(0, p.briefing_items),
      };
    } else {
      briefing = { ...briefing, top_intel: (briefing.top_intel || []).slice(0, p.briefing_items) };
    }
  } else if (env?.SECURITY_HUB_DB) {
    // No snapshot yet — derive a cheap one from D1. We do NOT run the 30-source
    // pipeline here: that expensive recompute is cron/ADMIN-only, so an
    // anonymous GET can never trigger a burst of outbound fetches.
    try { briefing = await briefingFromD1(env.SECURITY_HUB_DB, p); } catch {}
  }

  if (!briefing) return ok(request, { briefing: null, status: 'warming_up', hint: 'First worldwide sweep runs on the hourly cron.' });
  return ok(request, {
    briefing,
    plan: tier,
    ...(p.enrich ? {} : { upgrade_cta: { message: 'Upgrade to PRO for full threat-actor & malware attribution and the complete briefing.', pro_url: '/pricing#pro' } }),
  });
}

// ─── GET /api/global-intel/sources ───────────────────────────────────────────
export async function handleGlobalIntelSources(request, env) {
  const authCtx = await authOf(request, env);
  const rl = await checkRateLimitV2(env, authCtx, 'global-intel');
  if (!rl.allowed) return rateLimitResponse(rl, 'global-intel');
  return ok(request, {
    total: INTEL_SOURCES.length,
    by_category: INTEL_SOURCES.reduce((m, s) => (m[s.category] = (m[s.category] || 0) + 1, m), {}),
    by_region:   INTEL_SOURCES.reduce((m, s) => (m[s.region] = (m[s.region] || 0) + 1, m), {}),
    sources: INTEL_SOURCES.map(s => ({ id: s.id, name: s.name, category: s.category, region: s.region, weight: s.weight })),
  });
}

// ─── POST /api/global-intel/refresh (ADMIN / owner only) ─────────────────────
export async function handleGlobalIntelRefresh(request, env) {
  // Owner/admin JWT OR the ADMIN_TOKEN bearer may trigger the expensive run.
  const authCtx = await authOf(request, env);
  let authorized = isOwner(authCtx);

  if (!authorized) {
    const configured = (env.ADMIN_TOKEN || '').trim();
    if (!configured) return fail(request, 'Admin authorization required', 403);
    const auth = request.headers.get('Authorization') || '';
    const presented = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    let okAuth = presented.length > 0 && presented.length === configured.length;
    if (okAuth) {
      let diff = 0;
      for (let i = 0; i < configured.length; i++) diff |= configured.charCodeAt(i) ^ presented.charCodeAt(i);
      okAuth = diff === 0;
    }
    authorized = okAuth;
  }
  if (!authorized) return fail(request, 'Admin authorization required', 403);

  const result = await runGlobalIntelFirehose(env);
  return ok(request, { triggered: true, result });
}
