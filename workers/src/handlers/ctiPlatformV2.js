/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * CTI Platform V2 — /api/cti/v2/*
 *
 * Extends ctiWorkbench.js (NEVER modifies it).
 * Adds: watchlists, IOC enrichment, STIX 2.1 export, collections.
 *
 * Tables: cti_watchlists, cti_watchlist_entries (schema_phase4.sql)
 */

const STIX_SPEC_VERSION = '2.1';
const BUNDLE_ID_PREFIX  = 'bundle--';

function genId(prefix = 'wl') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

function requireAuth(authCtx) { return authCtx?.authenticated === true; }

// ─── GET /api/cti/v2/watchlists ───────────────────────────────────────────────
export async function handleListWatchlists(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = authCtx.org_id || 'default';

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT w.id, w.name, w.description, w.ioc_types, w.alert_on_match,
              w.match_count, w.created_by, w.created_at,
              COUNT(e.id) AS entry_count
       FROM cti_watchlists w
       LEFT JOIN cti_watchlist_entries e ON e.watchlist_id = w.id
       WHERE w.org_id = ?
       GROUP BY w.id
       ORDER BY w.created_at DESC`
    ).bind(orgId).all();

    return Response.json({ watchlists: rows.results || [], org_id: orgId });
  } catch (e) {
    return Response.json({ error: e.message, watchlists: [] }, { status: 500 });
  }
}

// ─── POST /api/cti/v2/watchlists ─────────────────────────────────────────────
export async function handleCreateWatchlist(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { name, description, ioc_types, alert_on_match = true } = body;
  if (!name?.trim()) return Response.json({ error: 'name required' }, { status: 400 });

  const id    = genId('wl');
  const orgId = authCtx.org_id || 'default';
  const types = Array.isArray(ioc_types) ? ioc_types : ['ip','domain','hash','url','email'];

  try {
    await env.SECURITY_HUB_DB.prepare(
      `INSERT INTO cti_watchlists (id, org_id, name, description, ioc_types, alert_on_match, created_by, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,datetime('now'),datetime('now'))`
    ).bind(id, orgId, name.trim(), description || null, JSON.stringify(types),
      alert_on_match ? 1 : 0, authCtx.userId || authCtx.email || null).run();

    return Response.json({ success: true, watchlist_id: id, name: name.trim() });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── GET /api/cti/v2/watchlists/:id/entries ──────────────────────────────────
export async function handleListWatchlistEntries(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url         = new URL(request.url);
  const watchlistId = url.pathname.split('/')[5];
  const orgId       = authCtx.org_id || 'default';

  try {
    const wl = await env.SECURITY_HUB_DB.prepare(
      `SELECT id FROM cti_watchlists WHERE id = ? AND org_id = ?`
    ).bind(watchlistId, orgId).first();
    if (!wl) return Response.json({ error: 'Watchlist not found' }, { status: 404 });

    const entries = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, ioc_value, ioc_type, confidence, tags, added_by, added_at
       FROM cti_watchlist_entries WHERE watchlist_id = ?
       ORDER BY added_at DESC`
    ).bind(watchlistId).all();

    return Response.json({ entries: entries.results || [], watchlist_id: watchlistId });
  } catch (e) {
    return Response.json({ error: e.message, entries: [] }, { status: 500 });
  }
}

// ─── POST /api/cti/v2/watchlists/:id/entries ─────────────────────────────────
export async function handleAddWatchlistEntry(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url         = new URL(request.url);
  const watchlistId = url.pathname.split('/')[5];
  const orgId       = authCtx.org_id || 'default';

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { ioc_value, ioc_type, confidence = 70, tags } = body;
  if (!ioc_value?.trim()) return Response.json({ error: 'ioc_value required' }, { status: 400 });

  const VALID_TYPES = ['ip','domain','hash','url','email','cidr','asn','cve'];
  if (!ioc_type || !VALID_TYPES.includes(ioc_type)) {
    return Response.json({ error: `ioc_type must be one of: ${VALID_TYPES.join(', ')}` }, { status: 400 });
  }

  // Validate the watchlist belongs to this org
  try {
    const wl = await env.SECURITY_HUB_DB.prepare(
      `SELECT id FROM cti_watchlists WHERE id = ? AND org_id = ?`
    ).bind(watchlistId, orgId).first();
    if (!wl) return Response.json({ error: 'Watchlist not found' }, { status: 404 });

    const id = genId('wle');
    await env.SECURITY_HUB_DB.prepare(
      `INSERT OR IGNORE INTO cti_watchlist_entries
         (id, watchlist_id, org_id, ioc_value, ioc_type, confidence, tags, added_by, added_at)
       VALUES (?,?,?,?,?,?,?,?,datetime('now'))`
    ).bind(id, watchlistId, orgId, ioc_value.trim(), ioc_type,
      Math.min(100, Math.max(0, parseInt(confidence))),
      tags ? JSON.stringify(tags) : null,
      authCtx.userId || authCtx.email || null).run();

    // Update watchlist entry count
    await env.SECURITY_HUB_DB.prepare(
      `UPDATE cti_watchlists SET updated_at = datetime('now') WHERE id = ?`
    ).bind(watchlistId).run();

    return Response.json({ success: true, entry_id: id });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── DELETE /api/cti/v2/watchlists/:id ───────────────────────────────────────
export async function handleDeleteWatchlist(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url         = new URL(request.url);
  const watchlistId = url.pathname.split('/')[5];
  const orgId       = authCtx.org_id || 'default';

  try {
    const r = await env.SECURITY_HUB_DB.prepare(
      `DELETE FROM cti_watchlists WHERE id = ? AND org_id = ?`
    ).bind(watchlistId, orgId).run();
    if (r.meta?.changes === 0) return Response.json({ error: 'Watchlist not found' }, { status: 404 });
    return Response.json({ success: true, deleted: watchlistId });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

// ─── POST /api/cti/v2/watchlists/match ───────────────────────────────────────
// Check if a list of IOC values appear in any watchlist for this org
export async function handleWatchlistMatch(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { iocs } = body; // array of strings
  if (!Array.isArray(iocs) || !iocs.length) {
    return Response.json({ error: 'iocs array required' }, { status: 400 });
  }

  const orgId = authCtx.org_id || 'default';
  const safe  = iocs.slice(0, 100).map(v => String(v).trim()).filter(Boolean);

  try {
    const placeholders = safe.map(() => '?').join(',');
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT e.ioc_value, e.ioc_type, e.confidence, w.name AS watchlist_name, w.id AS watchlist_id
       FROM cti_watchlist_entries e
       JOIN cti_watchlists w ON w.id = e.watchlist_id
       WHERE e.org_id = ? AND e.ioc_value IN (${placeholders})`
    ).bind(orgId, ...safe).all();

    const matches = rows.results || [];
    return Response.json({ matches, total_checked: safe.length, hit_count: matches.length });
  } catch (e) {
    return Response.json({ error: e.message, matches: [] }, { status: 500 });
  }
}

// ─── GET /api/cti/v2/ioc/enrich ──────────────────────────────────────────────
// IOC enrichment: cross-reference against cti_iocs + cti_actors + watchlists
export async function handleEnrichIOC(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url   = new URL(request.url);
  const value = url.searchParams.get('value')?.trim();
  const type  = url.searchParams.get('type') || 'auto';

  if (!value) return Response.json({ error: 'value parameter required' }, { status: 400 });

  const orgId = authCtx.org_id || 'default';

  // Run enrichment queries in parallel
  const [iocHit, actorMatch, watchlistHits] = await Promise.allSettled([
    // Check cti_iocs table
    (async () => {
      const r = await env.SECURITY_HUB_DB.prepare(
        `SELECT id, ioc_type, value, severity, confidence_score, tags, source,
                first_seen, last_seen, description
         FROM cti_iocs WHERE value = ? LIMIT 1`
      ).bind(value).first();
      return r || null;
    })(),
    // Check if any actor mentions this IOC in their description/aliases
    (async () => {
      const r = await env.SECURITY_HUB_DB.prepare(
        `SELECT id, name, nation_state, threat_level, confidence_score
         FROM cti_actors
         WHERE description LIKE ? OR aliases LIKE ?
         LIMIT 3`
      ).bind(`%${value}%`, `%${value}%`).all();
      return r.results || [];
    })(),
    // Check watchlists
    (async () => {
      const r = await env.SECURITY_HUB_DB.prepare(
        `SELECT e.confidence, w.name, w.id
         FROM cti_watchlist_entries e
         JOIN cti_watchlists w ON w.id = e.watchlist_id
         WHERE e.ioc_value = ? AND e.org_id = ?`
      ).bind(value, orgId).all();
      return r.results || [];
    })(),
  ]).then(results => results.map(r => r.status === 'fulfilled' ? r.value : null));

  // Compute enriched risk score
  let riskScore   = 0;
  let riskFactors = [];

  if (iocHit) {
    riskScore += iocHit.confidence_score || 0;
    riskFactors.push(`Matched known IOC (confidence: ${iocHit.confidence_score}%)`);
  }
  if (actorMatch?.length) {
    riskScore = Math.min(100, riskScore + 20 * actorMatch.length);
    riskFactors.push(`Associated with ${actorMatch.length} threat actor(s)`);
  }
  if (watchlistHits?.length) {
    riskScore = Math.min(100, riskScore + 15);
    riskFactors.push(`On ${watchlistHits.length} watchlist(s)`);
  }

  return Response.json({
    value,
    type: iocHit?.ioc_type || type,
    enrichment: {
      known_ioc: iocHit,
      associated_actors: actorMatch,
      watchlist_hits: watchlistHits,
      risk_score: Math.round(riskScore),
      risk_level: riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'LOW',
      risk_factors: riskFactors,
      enriched_at: new Date().toISOString(),
    },
  });
}

// ─── GET /api/cti/v2/stix/export ─────────────────────────────────────────────
// Export threat intelligence as STIX 2.1 bundle
export async function handleSTIXExport(request, env) {
  const authCtx = request.user || {};
  if (!requireAuth(authCtx)) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
  const types  = url.searchParams.get('types')?.split(',') || ['actor','ioc'];
  const orgId  = authCtx.org_id || 'default';

  const objects = [];

  try {
    // Export threat actors as STIX Threat Actor objects
    if (types.includes('actor')) {
      const actors = await env.SECURITY_HUB_DB.prepare(
        `SELECT id, name, aliases, nation_state, motivation, sophistication,
                threat_level, confidence_score, description, mitre_group_id, created_at
         FROM cti_actors LIMIT ?`
      ).bind(Math.ceil(limit / 2)).all();

      for (const a of (actors.results || [])) {
        objects.push({
          type: 'threat-actor',
          spec_version: STIX_SPEC_VERSION,
          id: `threat-actor--${a.id}`,
          created: a.created_at || new Date().toISOString(),
          modified: a.created_at || new Date().toISOString(),
          name: a.name,
          aliases: (() => { try { return JSON.parse(a.aliases || '[]'); } catch { return []; } })(),
          description: a.description || '',
          threat_actor_types: [a.sophistication?.toLowerCase() || 'unknown'],
          sophistication: (a.sophistication || 'unknown').toLowerCase(),
          resource_level: 'government',
          primary_motivation: (a.motivation || 'unknown').toLowerCase().replace(' ', '-'),
          confidence: a.confidence_score || 0,
          external_references: a.mitre_group_id ? [{
            source_name: 'mitre-attack',
            external_id: a.mitre_group_id,
            url: `https://attack.mitre.org/groups/${a.mitre_group_id}/`,
          }] : [],
        });
      }
    }

    // Export IOCs as STIX Indicator objects
    if (types.includes('ioc')) {
      const iocs = await env.SECURITY_HUB_DB.prepare(
        `SELECT id, ioc_type, value, severity, confidence_score, description, first_seen, last_seen
         FROM cti_iocs WHERE confidence_score >= 50
         ORDER BY confidence_score DESC LIMIT ?`
      ).bind(Math.ceil(limit / 2)).all();

      for (const ioc of (iocs.results || [])) {
        const patternMap = {
          ip:     `[ipv4-addr:value = '${ioc.value}']`,
          domain: `[domain-name:value = '${ioc.value}']`,
          url:    `[url:value = '${ioc.value}']`,
          hash:   `[file:hashes.'SHA-256' = '${ioc.value}']`,
          email:  `[email-addr:value = '${ioc.value}']`,
        };
        objects.push({
          type: 'indicator',
          spec_version: STIX_SPEC_VERSION,
          id: `indicator--${ioc.id}`,
          created: ioc.first_seen || new Date().toISOString(),
          modified: ioc.last_seen || new Date().toISOString(),
          name: `${(ioc.ioc_type || 'ioc').toUpperCase()}: ${ioc.value}`,
          description: ioc.description || '',
          indicator_types: ['malicious-activity'],
          pattern: patternMap[ioc.ioc_type] || `[artifact:mime_type = 'unknown']`,
          pattern_type: 'stix',
          valid_from: ioc.first_seen || new Date().toISOString(),
          confidence: ioc.confidence_score || 50,
          labels: [ioc.severity?.toLowerCase() || 'unknown'],
        });
      }
    }

    const bundle = {
      type: 'bundle',
      id: `${BUNDLE_ID_PREFIX}${genId()}`,
      spec_version: STIX_SPEC_VERSION,
      objects,
      _meta: {
        generated_at: new Date().toISOString(),
        object_count: objects.length,
        exporter: 'CYBERDUDEBIVASH AI Security Hub v34.0',
        org_id: orgId,
      },
    };

    return new Response(JSON.stringify(bundle, null, 2), {
      headers: {
        'Content-Type': 'application/stix+json; version=2.1',
        'X-STIX-Version': STIX_SPEC_VERSION,
      },
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
