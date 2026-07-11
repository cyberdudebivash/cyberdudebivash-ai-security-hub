/**
 * CYBERDUDEBIVASH® AI Security Hub — Threat Intel Pro Handler v1.0
 *
 * World-class threat intelligence API — enterprise-grade endpoints:
 *
 *   GET  /api/intel/analyst          → AI analyst chat (NL threat queries)
 *   GET  /api/intel/actors           → APT actor profiles with attribution
 *   GET  /api/intel/actor/:id        → Single actor deep profile
 *   GET  /api/intel/tactics          → MITRE ATT&CK tactics catalog
 *   GET  /api/intel/techniques       → MITRE ATT&CK techniques (searchable)
 *   POST /api/intel/attack-map       → Map CVE entries to ATT&CK
 *   GET  /api/intel/heatmap          → ATT&CK heatmap for current threat data
 *   GET  /api/intel/risk-score/:id   → Composite risk score for CVE
 *   GET  /api/intel/risk-queue       → Priority risk queue (top threats)
 *   GET  /api/intel/stix             → STIX 2.1 bundle export
 *   GET  /api/taxii/discovery        → TAXII 2.1 discovery document
 *   GET  /api/taxii/collections      → TAXII 2.1 collection list
 *   GET  /api/taxii/collections/:id/objects → TAXII 2.1 feed
 *   GET  /api/intel/sector/:sector   → Sector-specific intelligence brief
 *   GET  /api/intel/cve-brief/:id    → AI-generated CVE deep-dive brief
 *   GET  /api/intel/epss/:id         → EPSS score for CVE
 *   POST /api/intel/analyst/query    → AI analyst POST endpoint
 */

import { mapToAttack, mapBatchToAttack, buildAttackHeatmap, TACTICS, TECHNIQUES, getTechnique, searchTechniques } from '../services/mitreAttackService.js';
import { getActor, getAllActors, getActorsBySector, getActorsByCVE, getActorsByTechnique, attributeCVE, getActorStats } from '../services/aptActorProfiles.js';
import { scoreCVE, scoreBatch, fetchEPSS, analyzeRiskDistribution } from '../services/compositeRiskScoring.js';
import { analyzeQuery, generateCVEBrief, generateSectorBrief } from '../services/aiThreatAnalyst.js';
import { buildSTIXBundle, buildBundleFromD1, buildTAXIIDiscovery, buildTAXIICollections } from '../services/stix21Engine.js';
import { ok, fail } from '../lib/response.js';
import { checkRateLimitCost, rateLimitResponse } from '../middleware/rateLimit.js';

// ─── CORS + Security headers ──────────────────────────────────────────────────
const BASE_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
  'X-Content-Type-Options':       'nosniff',
  'X-Frame-Options':              'DENY',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...BASE_HEADERS, 'Content-Type': 'application/json' },
  });
}

// ─── Plan tier guard ──────────────────────────────────────────────────────────
function tierAtLeast(authCtx, required) {
  const ORDER = { FREE: 0, STARTER: 1, PRO: 2, ENTERPRISE: 3, ENTERPRISE_SOC: 4 };
  const userTier = authCtx?.tier || 'FREE';
  return (ORDER[userTier] ?? 0) >= (ORDER[required] ?? 0);
}

// ─── Load entries from D1 ─────────────────────────────────────────────────────
async function loadEntries(env, limit = 100, severity = null) {
  if (!env?.DB) return [];
  try {
    const where = severity ? `WHERE severity = ?` : '';
    const bind  = severity ? [severity.toUpperCase(), limit] : [limit];
    const rows  = await env.DB.prepare(
      `SELECT * FROM threat_intel ${where}
       ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 2 END DESC, cvss DESC
       LIMIT ?`
    ).bind(...bind).all();
    return rows?.results || [];
  } catch { return []; }
}

// ─── Main router ──────────────────────────────────────────────────────────────
export async function handleThreatIntelPro(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const path   = url.pathname.replace(/\/+$/, '');
  const method = request.method.toUpperCase();

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: BASE_HEADERS });
  }

  // ── GET /api/intel/actors ─────────────────────────────────────────────────
  if (path === '/api/intel/actors' && method === 'GET') {
    const sector   = url.searchParams.get('sector') || null;
    const sortBy   = url.searchParams.get('sort') || 'risk_score';
    const search   = url.searchParams.get('q') || '';

    let actors = sector ? getActorsBySector(sector) : getAllActors();

    if (search) {
      const q = search.toLowerCase();
      actors = actors.filter(a =>
        a.id.toLowerCase().includes(q) ||
        a.aliases?.some(alias => alias.toLowerCase().includes(q)) ||
        a.origin.toLowerCase().includes(q) ||
        a.target_sectors?.some(s => s.includes(q))
      );
    }

    if (sortBy === 'risk_score') actors.sort((a, b) => b.risk_score - a.risk_score);
    else if (sortBy === 'name') actors.sort((a, b) => a.id.localeCompare(b.id));

    const stats = getActorStats();

    return jsonResponse({
      actors,
      total:       actors.length,
      stats,
      filter:      { sector, sort: sortBy, search },
      generated_at: new Date().toISOString(),
    });
  }

  // ── GET /api/intel/actor/:id ──────────────────────────────────────────────
  if (path.match(/^\/api\/intel\/actor\/[^/]+$/) && method === 'GET') {
    const actorId = decodeURIComponent(path.split('/').pop());
    const actor   = getActor(actorId);

    if (!actor) {
      return jsonResponse({ error: `Actor '${actorId}' not found` }, 404);
    }

    // Find CVEs associated with this actor in D1
    let associatedCVEs = [];
    if (actor.cve_associations?.length && env?.DB) {
      try {
        const placeholders = actor.cve_associations.slice(0, 10).map(() => '?').join(',');
        const rows = await env.DB.prepare(
          `SELECT id, title, severity, cvss, exploit_status, known_ransomware, published_at
           FROM threat_intel WHERE id IN (${placeholders})`
        ).bind(...actor.cve_associations.slice(0, 10)).all();
        associatedCVEs = rows?.results || [];
      } catch {}
    }

    return jsonResponse({
      actor,
      associated_cves: associatedCVEs,
      techniques_stix_ids: actor.primary_techniques,
      generated_at: new Date().toISOString(),
    });
  }

  // ── GET /api/intel/tactics ────────────────────────────────────────────────
  if (path === '/api/intel/tactics' && method === 'GET') {
    return jsonResponse({
      tactics:   Object.values(TACTICS),
      total:     Object.keys(TACTICS).length,
      spec_version: 'ATT&CK v14 Enterprise',
      source:    'https://attack.mitre.org/',
    });
  }

  // ── GET /api/intel/techniques ─────────────────────────────────────────────
  if (path === '/api/intel/techniques' && method === 'GET') {
    const search  = url.searchParams.get('q') || '';
    const tactic  = url.searchParams.get('tactic') || '';

    let techs = Object.values(TECHNIQUES);
    if (search) techs = searchTechniques(search);
    if (tactic) {
      const tl = tactic.toLowerCase();
      techs = techs.filter(t => {
        const tacticObj = TACTICS[t.tactic];
        return t.tactic === tactic ||
          tacticObj?.shortname === tl ||
          tacticObj?.name?.toLowerCase().includes(tl);
      });
    }

    return jsonResponse({
      techniques: techs.map(t => ({
        ...t,
        tactic_name: TACTICS[t.tactic]?.name || t.tactic,
        url:         `https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`,
      })),
      total:      techs.length,
    });
  }

  // ── POST /api/intel/attack-map ────────────────────────────────────────────
  if (path === '/api/intel/attack-map' && method === 'POST') {
    let body = {};
    try { body = await request.json(); } catch {}

    const entries = body.entries || [];
    if (!entries.length) {
      return jsonResponse({ error: 'entries array required' }, 400);
    }

    const mapped = mapBatchToAttack(entries.slice(0, 100));
    return jsonResponse({ mapped, total: mapped.length });
  }

  // ── GET /api/intel/heatmap ────────────────────────────────────────────────
  if (path === '/api/intel/heatmap' && method === 'GET') {
    const cacheKey = 'intel:heatmap:v2';

    if (env?.SECURITY_HUB_KV) {
      try {
        const cached = await env.SECURITY_HUB_KV.get(cacheKey, { type: 'json' });
        if (cached) return jsonResponse({ ...cached, cache: 'hit' });
      } catch {}
    }

    const entries = await loadEntries(env, 200);
    const mapped  = mapBatchToAttack(entries);
    const raw     = buildAttackHeatmap(mapped);

    // Transform into the shapes the workbench frontend expects:
    //   heatmap   — dict keyed by technique ID
    //   by_tactic — dict keyed by tactic name, each with { total, techniques[] }
    const heatmapByTech = {};
    for (const t of raw.techniques) {
      heatmapByTech[t.technique_id] = {
        count:          t.count,
        name:           t.technique_name,
        cve_ids:        t.cve_ids,
        tactic_id:      t.tactic_id,
        tactic_name:    t.tactic_name,
        critical_count: t.critical_count,
        url:            t.url,
      };
    }
    const byTactic = {};
    for (const t of raw.techniques) {
      const key = t.tactic_name;
      if (!byTactic[key]) byTactic[key] = { total: 0, techniques: [] };
      byTactic[key].total += t.count;
      byTactic[key].techniques.push(t);
    }

    const result = {
      heatmap:              heatmapByTech,
      by_tactic:            byTactic,
      total_techniques:     raw.techniques.length,
      total_entries_mapped: raw.total_entries_mapped,
      generated_at:         raw.generated_at,
    };

    if (env?.SECURITY_HUB_KV) {
      env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: 900 }).catch(() => {});
    }

    return jsonResponse({ ...result, cache: 'miss' });
  }

  // ── GET /api/intel/risk-score/:id ─────────────────────────────────────────
  if (path.match(/^\/api\/intel\/risk-score\/[^/]+$/) && method === 'GET') {
    const cveId = decodeURIComponent(path.split('/').pop());
    let entry = null;

    if (env?.DB) {
      try {
        entry = await env.DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(cveId).first();
      } catch {}
    }

    if (!entry) {
      return jsonResponse({ error: `CVE ${cveId} not found` }, 404);
    }

    const [epssScores, aptActors] = await Promise.all([
      fetchEPSS([cveId], env),
      Promise.resolve(attributeCVE(entry)),
    ]);

    const scoring = scoreCVE(entry, epssScores[cveId] ?? null, aptActors);
    const attackMapping = mapToAttack(entry);

    return jsonResponse({
      cve_id:          cveId,
      title:           entry.title,
      ...scoring,
      attack_mapping:  attackMapping,
      attributed_actors: aptActors,
    });
  }

  // ── GET /api/intel/risk-queue ─────────────────────────────────────────────
  if (path === '/api/intel/risk-queue' && method === 'GET') {
    const limit    = Math.min(50, parseInt(url.searchParams.get('limit') || '25', 10));
    const severity = url.searchParams.get('severity') || null;
    const cacheKey = `intel:risk-queue:${severity || 'all'}:${limit}`;

    // Try KV cache (5 min)
    if (env?.SECURITY_HUB_KV) {
      try {
        const cached = await env.SECURITY_HUB_KV.get(cacheKey, { type: 'json' });
        if (cached) return jsonResponse({ ...cached, cache: 'hit' });
      } catch {}
    }

    const entries = await loadEntries(env, 100, severity);
    const scored  = await scoreBatch(entries, env);
    scored.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

    const queue    = scored.slice(0, limit).map(e => ({
      id:             e.id,
      title:          e.title,
      severity:       e.severity,
      cvss:           e.cvss,
      priority_score: e.priority_score,
      risk_tier:      e.risk_tier,
      urgency_label:  e.urgency_label,
      remediation_sla: e.remediation_sla,
      epss_score:     e.epss_score,
      is_kev:         e.is_kev,
      is_ransomware:  e.is_ransomware,
      published_at:   e.published_at,
      exploit_status: e.exploit_status,
    }));

    const analysis = analyzeRiskDistribution(scored);

    // Hoist distribution fields to top level so frontend reads data.distribution / data.total_assessed directly
    const result = {
      queue,
      entries:          queue,              // alias — frontend reads data.entries || data.queue
      distribution:     analysis.distribution,
      total_assessed:   analysis.total_assessed,
      average_score:    analysis.average_score,
      environment_risk: analysis.environment_risk,
      environment_score: analysis.environment_score,
      top_priority:     analysis.top_priority,
      total:            scored.length,
      generated_at:     new Date().toISOString(),
    };

    if (env?.SECURITY_HUB_KV) {
      env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 }).catch(() => {});
    }

    return jsonResponse({ ...result, cache: 'miss' });
  }

  // ── GET /api/intel/epss/:id ───────────────────────────────────────────────
  if (path.match(/^\/api\/intel\/epss\/[^/]+$/) && method === 'GET') {
    const cveId = decodeURIComponent(path.split('/').pop());
    const scores = await fetchEPSS([cveId], env);
    return jsonResponse({
      cve_id:     cveId,
      epss_score: scores[cveId] ?? null,
      percentile: scores[cveId] ? `Top ${Math.round((1 - scores[cveId]) * 100)}%` : null,
      source:     'FIRST.org EPSS',
      note:       'EPSS = probability of exploitation in the next 30 days',
    });
  }

  // ── GET /api/intel/stix ───────────────────────────────────────────────────
  if (path === '/api/intel/stix' && method === 'GET') {
    const format   = url.searchParams.get('format') || 'json';
    const severity = url.searchParams.get('severity') || null;
    const limit    = Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10));

    const bundle = await buildBundleFromD1(env, {
      limit,
      severity,
      includeActors: tierAtLeast(authCtx, 'ENTERPRISE'),
      includeIOCs:   tierAtLeast(authCtx, 'PRO'),
    });

    if (format === 'json') {
      return new Response(JSON.stringify(bundle, null, 2), {
        headers: {
          ...BASE_HEADERS,
          'Content-Type':        'application/stix+json;version=2.1',
          'Content-Disposition': `attachment; filename="sentinel-apex-stix-${new Date().toISOString().slice(0,10)}.json"`,
        },
      });
    }

    return jsonResponse(bundle);
  }

  // ── GET /api/taxii/discovery ──────────────────────────────────────────────
  if (path === '/api/taxii/discovery' && method === 'GET') {
    const origin = new URL(request.url).origin;
    return new Response(JSON.stringify(buildTAXIIDiscovery(origin)), {
      headers: { ...BASE_HEADERS, 'Content-Type': 'application/taxii+json;version=2.1' },
    });
  }

  // ── GET /api/taxii/collections ────────────────────────────────────────────
  if (path === '/api/taxii/collections' && method === 'GET') {
    const origin = new URL(request.url).origin;
    return new Response(JSON.stringify(buildTAXIICollections(origin)), {
      headers: { ...BASE_HEADERS, 'Content-Type': 'application/taxii+json;version=2.1' },
    });
  }

  // ── GET /api/taxii/collections/:id/objects ────────────────────────────────
  if (path.match(/^\/api\/taxii\/collections\/[^/]+\/objects$/) && method === 'GET') {
    const collectionId = path.split('/')[4];
    const limit        = Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10));

    let bundle;
    switch (collectionId) {
      case 'cve-feed':
        bundle = await buildBundleFromD1(env, { limit, includeActors: false, includeIOCs: false });
        break;
      case 'kev-feed':
        bundle = await buildBundleFromD1(env, { limit, kev_only: true, includeActors: false, includeIOCs: false });
        break;
      case 'ioc-feed':
        if (!tierAtLeast(authCtx, 'PRO')) {
          return new Response(JSON.stringify({ error: 'PRO plan required for IOC feed', upgrade: '/pricing' }), {
            status: 403,
            headers: { ...BASE_HEADERS, 'Content-Type': 'application/taxii+json;version=2.1' },
          });
        }
        bundle = await buildBundleFromD1(env, { limit, includeActors: false, includeIOCs: true });
        break;
      case 'actor-feed':
        if (!tierAtLeast(authCtx, 'ENTERPRISE')) {
          return new Response(JSON.stringify({ error: 'ENTERPRISE plan required for actor feed', upgrade: '/pricing' }), {
            status: 403,
            headers: { ...BASE_HEADERS, 'Content-Type': 'application/taxii+json;version=2.1' },
          });
        }
        bundle = await buildBundleFromD1(env, { limit: 20, includeActors: true, includeIOCs: false });
        break;
      default:
        return new Response(JSON.stringify({ error: `Collection '${collectionId}' not found` }), {
          status: 404,
          headers: { ...BASE_HEADERS, 'Content-Type': 'application/taxii+json;version=2.1' },
        });
    }

    return new Response(JSON.stringify({ objects: bundle.objects }), {
      headers: {
        ...BASE_HEADERS,
        'Content-Type':   'application/taxii+json;version=2.1',
        'X-TAXII-Date-Added-First': bundle._meta?.generated_at || new Date().toISOString(),
        'X-TAXII-Date-Added-Last':  bundle._meta?.generated_at || new Date().toISOString(),
      },
    });
  }

  // ── GET /api/intel/sector/:sector ─────────────────────────────────────────
  if (path.match(/^\/api\/intel\/sector\/[^/]+$/) && method === 'GET') {
    // Generates an AI sector brief (real LLM call, generateSectorBrief() below) —
    // was reachable with zero auth or rate limiting, an open cost-abuse vector.
    const rl = await checkRateLimitCost(env, authCtx, 'intel/sector');
    if (!rl.allowed) return rateLimitResponse(rl, 'intel-sector-brief');

    const sector  = decodeURIComponent(path.split('/').pop());
    const actors  = getActorsBySector(sector).slice(0, 5);
    const entries = await loadEntries(env, 50);

    // Filter entries relevant to this sector (keyword match)
    const sectorKeywords = [sector.toLowerCase()];
    const sectorEntries = entries.filter(e => {
      const text = (e.title + ' ' + e.description + ' ' + (e.tags || '')).toLowerCase();
      return sectorKeywords.some(k => text.includes(k));
    }).slice(0, 20);

    let briefResult = null;
    try {
      briefResult = await generateSectorBrief(sector, env);
    } catch {}

    return jsonResponse({
      sector,
      relevant_actors: actors,
      relevant_cves:   sectorEntries,
      total_actors:    actors.length,
      total_cves:      sectorEntries.length,
      response:        briefResult?.response || null,
      model:           briefResult?.model    || null,
      provider:        briefResult?.provider || null,
      latency_ms:      briefResult?.latency_ms || null,
      generated_at:    new Date().toISOString(),
    });
  }

  // ── GET /api/intel/cve-brief/:id ──────────────────────────────────────────
  if (path.match(/^\/api\/intel\/cve-brief\/[^/]+$/) && method === 'GET') {
    // Generates an AI CVE deep-dive brief (real LLM call, generateCVEBrief()
    // below) — was reachable with zero auth or rate limiting.
    const rl = await checkRateLimitCost(env, authCtx, 'intel/cve-brief');
    if (!rl.allowed) return rateLimitResponse(rl, 'intel-cve-brief');

    const cveId = decodeURIComponent(path.split('/').pop());
    let entry = null;

    if (env?.DB) {
      try {
        entry = await env.DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(cveId).first();
      } catch {}
    }

    if (!entry) {
      return jsonResponse({ error: `CVE ${cveId} not found` }, 404);
    }

    const [aptActors, epssScores] = await Promise.all([
      Promise.resolve(attributeCVE(entry)),
      fetchEPSS([cveId], env),
    ]);

    const attackMapping = mapToAttack(entry);
    const scoring       = scoreCVE(entry, epssScores[cveId] ?? null, aptActors);

    let briefResult = null;
    try {
      briefResult = await generateCVEBrief(entry, env, { aptActors, attackMapping, tier: authCtx?.tier });
    } catch {}

    return jsonResponse({
      cve_id:            cveId,
      entry,
      scoring,
      attack_mapping:    attackMapping,
      attributed_actors: aptActors,
      response:          briefResult?.response  || null,
      model:             briefResult?.model     || null,
      provider:          briefResult?.provider  || null,
      latency_ms:        briefResult?.latency_ms || null,
      generated_at:      new Date().toISOString(),
    });
  }

  // ── POST /api/intel/analyst/query (or GET with ?q=) ───────────────────────
  if ((path === '/api/intel/analyst' || path === '/api/intel/analyst/query') && (method === 'GET' || method === 'POST')) {
    // AI analyst chat (real LLM call via analyzeQuery() -> callLLM() below) —
    // was reachable by anyone, unauthenticated, with no rate limiting at all:
    // an open cost-abuse vector (every message triggers a paid LLM API call).
    const rl = await checkRateLimitCost(env, authCtx, 'intel/analyst');
    if (!rl.allowed) return rateLimitResponse(rl, 'intel-analyst');

    let query      = url.searchParams.get('q') || '';
    let session_id = url.searchParams.get('session') || null;

    if (method === 'POST') {
      try {
        const body  = await request.json();
        query      = body.query || body.q || query;
        session_id = body.session_id || session_id;
      } catch {}
    }

    if (query.length > 2000) query = query.slice(0, 2000);

    if (!query.trim()) {
      return jsonResponse({
        error: 'Query parameter required',
        hint:  'Use ?q=<your threat intelligence question> or POST with {"query": "..."}',
        examples: [
          'What are the most critical CVEs being exploited right now?',
          'Analyze CVE-2024-3400',
          'What APT groups target the healthcare sector?',
          'What MITRE ATT&CK techniques does LockBit use?',
          'Show me all ransomware-linked vulnerabilities',
        ],
      }, 400);
    }

    try {
      const result = await analyzeQuery(query, env, {
        session_id,
        tier: authCtx?.tier || 'FREE',
      });
      return jsonResponse(result);
    } catch (err) {
      return jsonResponse({ error: 'Analyst unavailable', details: err.message }, 503);
    }
  }

  // ── Actor attribution for a CVE ───────────────────────────────────────────
  if (path.match(/^\/api\/intel\/attribute\/[^/]+$/) && method === 'GET') {
    const cveId = decodeURIComponent(path.split('/').pop());
    let entry = null;
    if (env?.DB) {
      try { entry = await env.DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(cveId).first(); } catch {}
    }
    const actors = entry ? attributeCVE(entry) : getActorsByCVE(cveId);
    return jsonResponse({ cve_id: cveId, attributed_actors: actors, total: actors.length });
  }

  return jsonResponse({ error: 'Intel endpoint not found', path }, 404);
}
