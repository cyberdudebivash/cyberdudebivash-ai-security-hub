/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * globalSearch.js — Enterprise Global Search Platform
 *
 * APIs:
 *   GET  /api/search                  global search (auth required)
 *   POST /api/search/saved            save a search
 *   GET  /api/search/saved            list saved searches
 *   DELETE /api/search/saved/:id      delete saved search
 */

function genId() { return 'srch_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

const ENTITY_TYPES = ['ioc', 'actor', 'case', 'customer', 'scan', 'workflow'];

function scoreResult(item, query) {
  const q = query.toLowerCase();
  const text = (item._searchText || '').toLowerCase();
  if (text === q) return 100;
  if (text.startsWith(q)) return 80;
  if (text.includes(q)) return 60;
  return 40;
}

export async function handleGlobalSearch(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url   = new URL(req.url);
  const q     = (url.searchParams.get('q') || '').trim();
  const types = (url.searchParams.get('type') || '').split(',').filter(Boolean);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const orgId = req.user.org_id || 'default';

  if (!q || q.length < 2) return Response.json({ results: [], total: 0, query: q });

  const cacheKey = `search_${Buffer.from(q + orgId + types.join(',')).toString('base64').slice(0, 32)}`;
  const cached = await env.KV?.get(cacheKey, 'json').catch(() => null);
  if (cached) return Response.json({ ...cached, cached: true });

  const likeQ = `%${q}%`;
  const results = [];

  const runTypes = types.length ? types : ENTITY_TYPES;

  await Promise.allSettled([
    // IOCs
    runTypes.includes('ioc') ? (async () => {
      const rows = await env.DB.prepare(
        `SELECT id, ioc_type, value, severity, source, created_at
         FROM cti_iocs WHERE value LIKE ? LIMIT 15`
      ).bind(likeQ).all();
      (rows.results || []).forEach(r => results.push({
        type: 'ioc', entity_type: 'IOC', id: r.id,
        title: r.value, subtitle: `${r.ioc_type} · ${r.severity}`,
        severity: r.severity, source: r.source, date: r.created_at,
        _searchText: r.value, url: null,
      }));
    })() : Promise.resolve(),

    // Threat Actors
    runTypes.includes('actor') ? (async () => {
      const rows = await env.DB.prepare(
        `SELECT id, name, nation_state, threat_level, created_at
         FROM cti_actors WHERE name LIKE ? OR aliases LIKE ? LIMIT 10`
      ).bind(likeQ, likeQ).all();
      (rows.results || []).forEach(r => results.push({
        type: 'actor', entity_type: 'Threat Actor', id: r.id,
        title: r.name, subtitle: `${r.nation_state || 'Unknown'} · ${r.threat_level}`,
        severity: r.threat_level, date: r.created_at,
        _searchText: r.name, url: null,
      }));
    })() : Promise.resolve(),

    // SOC Cases
    runTypes.includes('case') ? (async () => {
      const rows = await env.DB.prepare(
        `SELECT id, case_number, title, severity, status, created_at
         FROM soc_cases WHERE (title LIKE ? OR case_number LIKE ? OR summary LIKE ?)
         AND org_id = ? LIMIT 10`
      ).bind(likeQ, likeQ, likeQ, orgId).all();
      (rows.results || []).forEach(r => results.push({
        type: 'case', entity_type: 'SOC Case', id: r.id,
        title: r.title, subtitle: `${r.case_number} · ${r.status}`,
        severity: r.severity, date: r.created_at,
        _searchText: r.title + ' ' + r.case_number, url: null,
      }));
    })() : Promise.resolve(),

    // MSSP Customers (mssp_admin only)
    runTypes.includes('customer') && ['admin','mssp_admin'].includes(req.user.role) ? (async () => {
      const rows = await env.DB.prepare(
        `SELECT id, org_name, org_slug, tier, status, created_at
         FROM mssp_customers WHERE org_name LIKE ? OR contact_email LIKE ? LIMIT 10`
      ).bind(likeQ, likeQ).all();
      (rows.results || []).forEach(r => results.push({
        type: 'customer', entity_type: 'MSSP Customer', id: r.id,
        title: r.org_name, subtitle: `${r.tier} · ${r.status}`,
        severity: null, date: r.created_at,
        _searchText: r.org_name, url: null,
      }));
    })() : Promise.resolve(),

    // Scan Results
    runTypes.includes('scan') ? (async () => {
      const rows = await env.DB.prepare(
        `SELECT id, target, scan_type, risk_score, created_at
         FROM scan_results WHERE target LIKE ? AND org_id = ? LIMIT 10`
      ).bind(likeQ, orgId).all();
      (rows.results || []).forEach(r => results.push({
        type: 'scan', entity_type: 'Scan Result', id: r.id,
        title: r.target, subtitle: `${r.scan_type} · Risk ${r.risk_score}/100`,
        severity: r.risk_score >= 80 ? 'CRITICAL' : r.risk_score >= 60 ? 'HIGH' : 'MEDIUM',
        date: r.created_at, _searchText: r.target, url: null,
      }));
    })() : Promise.resolve(),

    // Workflows
    runTypes.includes('workflow') ? (async () => {
      const rows = await env.DB.prepare(
        `SELECT id, name, trigger_type, is_active, created_at
         FROM workflows WHERE name LIKE ? AND org_id = ? LIMIT 10`
      ).bind(likeQ, orgId).all();
      (rows.results || []).forEach(r => results.push({
        type: 'workflow', entity_type: 'Workflow', id: r.id,
        title: r.name, subtitle: `${r.trigger_type} · ${r.is_active ? 'Active' : 'Inactive'}`,
        severity: null, date: r.created_at,
        _searchText: r.name, url: null,
      }));
    })() : Promise.resolve(),
  ]);

  // Score + sort
  const scored = results
    .map(r => ({ ...r, score: scoreResult(r, q) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);

  // Remove internal field
  const clean = scored.map(({ _searchText, ...r }) => r);

  const facets = {
    types: ENTITY_TYPES.reduce((acc, t) => {
      acc[t] = clean.filter(r => r.type === t).length;
      return acc;
    }, {}),
  };

  const output = { results: clean, total: clean.length, query: q, facets };
  await env.KV?.put(cacheKey, JSON.stringify(output), { expirationTtl: 30 }).catch(() => null);

  // Track search event
  await env.DB.prepare(
    `INSERT INTO analytics_events (id, event_type, user_id, org_id, properties_json, occurred_at)
     VALUES (?,?,?,?,?,datetime('now'))`
  ).bind(genId(), 'search.executed', req.user.id || null, orgId,
    JSON.stringify({ query_length: q.length, result_count: clean.length, types: runTypes })
  ).run().catch(() => null);

  return Response.json(output);
}

export async function handleSaveSearch(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { name, query, facets = {}, entity_types = [] } = body;
  if (!name || !query) return Response.json({ error: 'name and query required' }, { status: 400 });

  const id = genId();
  const orgId = req.user.org_id || 'default';
  const userId = req.user.id || 'unknown';

  await env.DB.prepare(
    `INSERT INTO saved_searches (id, user_id, org_id, name, query, facets_json, entity_types, created_at)
     VALUES (?,?,?,?,?,?,?,datetime('now'))`
  ).bind(id, userId, orgId, name, query, JSON.stringify(facets), JSON.stringify(entity_types)).run();

  return Response.json({ success: true, id, name, query });
}

export async function handleListSavedSearches(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const userId = req.user.id || 'unknown';
  const orgId  = req.user.org_id || 'default';

  const rows = await env.DB.prepare(
    `SELECT id, name, query, facets_json, hit_count, last_run_at, created_at
     FROM saved_searches WHERE user_id = ? OR org_id = ?
     ORDER BY created_at DESC LIMIT 20`
  ).bind(userId, orgId).all().catch(() => ({ results: [] }));

  return Response.json({ saved_searches: rows.results || [] });
}

export async function handleDeleteSavedSearch(req, env, searchId) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const userId = req.user.id || 'unknown';
  const result = await env.DB.prepare(
    `DELETE FROM saved_searches WHERE id = ? AND user_id = ?`
  ).bind(searchId, userId).run().catch(() => null);

  if (!result?.meta?.changes) return Response.json({ error: 'Not found or not authorized' }, { status: 404 });
  return Response.json({ success: true });
}
