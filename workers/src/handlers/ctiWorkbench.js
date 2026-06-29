/**
 * CYBERDUDEBIVASH® AI Security Hub
 * CTI Workbench — /api/cti/*
 *
 * Threat actor profiles, IOC database, enrichment.
 * D1-backed (cti_actors + cti_iocs from schema_phase2.sql).
 * Public: actor list, IOC search (read-only)
 * Auth required: IOC submission, watchlist management
 */

function genId(prefix = 'ioc') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

// GET /api/cti/actors
export async function handleListActors(request, env, authCtx) {
  const url     = new URL(request.url);
  const limit   = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
  const offset  = parseInt(url.searchParams.get('offset') || '0');
  const threat  = url.searchParams.get('threat_level');
  const nation  = url.searchParams.get('nation');
  const sector  = url.searchParams.get('sector');

  let where  = [];
  let params = [];
  if (threat) { where.push('threat_level = ?'); params.push(threat.toUpperCase()); }
  if (nation) { where.push('nation_state = ?'); params.push(nation); }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, name, aliases, nation_state, motivation, sophistication,
              threat_level, confidence_score, target_sectors, last_active,
              mitre_group_id, description
       FROM cti_actors ${whereClause}
       ORDER BY confidence_score DESC, last_active DESC
       LIMIT ? OFFSET ?`
    ).bind(...params, limit, offset).all();

    const total = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as n FROM cti_actors ${whereClause}`
    ).bind(...params).first();

    const actors = (rows?.results || []).map(a => ({
      ...a,
      aliases:        safeJson(a.aliases, []),
      target_sectors: safeJson(a.target_sectors, []),
      known_techniques: safeJson(a.known_techniques, []),
    }));

    // If DB is empty, seed from KV threat intel data
    if (actors.length === 0) {
      const seeded = await seedActorsFromKV(env);
      return Response.json({ success: true, actors: seeded, total: seeded.length, seeded: true });
    }

    return Response.json({ success: true, actors, total: total?.n || 0, limit, offset });
  } catch (e) {
    // Fallback to KV-based data if D1 table not yet created
    const fallback = await getFallbackActors(env);
    return Response.json({ success: true, actors: fallback, total: fallback.length, source: 'kv_fallback' });
  }
}

// GET /api/cti/actors/:id
export async function handleGetActor(request, env, authCtx, actorId) {
  try {
    const actor = await env.SECURITY_HUB_DB.prepare(
      `SELECT * FROM cti_actors WHERE id = ?`
    ).bind(actorId).first();

    if (!actor) return Response.json({ error: 'Actor not found' }, { status: 404 });

    // Get associated IOCs
    const iocs = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, ioc_type, value, severity, first_seen, last_seen, tags
       FROM cti_iocs WHERE related_actor_id = ? AND is_active = 1
       ORDER BY severity DESC, last_seen DESC LIMIT 20`
    ).bind(actorId).all();

    return Response.json({
      success: true,
      actor: {
        ...actor,
        aliases:          safeJson(actor.aliases, []),
        known_techniques: safeJson(actor.known_techniques, []),
        known_tools:      safeJson(actor.known_tools, []),
        target_sectors:   safeJson(actor.target_sectors, []),
      },
      iocs: iocs?.results || [],
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/cti/ioc/search?q=&type=&severity=
export async function handleIOCSearch(request, env, authCtx) {
  const url  = new URL(request.url);
  const q    = url.searchParams.get('q') || '';
  const type = url.searchParams.get('type');
  const sev  = url.searchParams.get('severity');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);

  if (!q && !type) {
    return Response.json({ error: 'Provide q (search term) or type parameter' }, { status: 400 });
  }

  let where  = ['is_active = 1'];
  let params = [];

  if (q) { where.push('value LIKE ?'); params.push(`%${q}%`); }
  if (type) { where.push('ioc_type = ?'); params.push(type.toUpperCase()); }
  if (sev)  { where.push('severity = ?'); params.push(sev.toUpperCase()); }

  try {
    const rows = await env.SECURITY_HUB_DB.prepare(
      `SELECT id, ioc_type, value, severity, source, first_seen, last_seen,
              tags, reputation_score, geo_country, related_campaign
       FROM cti_iocs WHERE ${where.join(' AND ')}
       ORDER BY
         CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
         last_seen DESC
       LIMIT ?`
    ).bind(...params, limit).all();

    const results = (rows?.results || []).map(r => ({
      ...r,
      tags: safeJson(r.tags, []),
    }));

    return Response.json({ success: true, results, count: results.length, query: q });
  } catch (e) {
    return Response.json({ success: false, error: e.message, results: [] }, { status: 500 });
  }
}

// POST /api/cti/ioc — submit new IOC
export async function handleAddIOC(request, env, authCtx) {
  if (!authCtx?.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }
  if (authCtx.tier === 'FREE') {
    return Response.json({ error: 'Pro tier required to submit IOCs' }, { status: 403 });
  }

  let body;
  try { body = await request.json(); }
  catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { ioc_type, value, severity = 'MEDIUM', tags = [], related_actor_id, notes } = body;
  if (!ioc_type || !value) {
    return Response.json({ error: 'ioc_type and value required' }, { status: 400 });
  }

  const validTypes = ['IP','DOMAIN','HASH_MD5','HASH_SHA1','HASH_SHA256','URL','EMAIL','CVE','BITCOIN_ADDR'];
  if (!validTypes.includes(ioc_type.toUpperCase())) {
    return Response.json({ error: `ioc_type must be one of: ${validTypes.join(', ')}` }, { status: 400 });
  }

  const id  = genId('ioc');
  const now = new Date().toISOString();

  try {
    await env.SECURITY_HUB_DB.prepare(`
      INSERT INTO cti_iocs
        (id, ioc_type, value, severity, source, tags, related_actor_id,
         notes, first_seen, last_seen, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ioc_type, value) DO UPDATE SET
        last_seen = excluded.last_seen,
        severity  = CASE
          WHEN CAST(excluded.severity AS TEXT) = 'CRITICAL' THEN 'CRITICAL'
          ELSE cti_iocs.severity
        END
    `).bind(
      id, ioc_type.toUpperCase(), value.toLowerCase(),
      severity.toUpperCase(), 'user_submitted',
      JSON.stringify(tags), related_actor_id || null,
      notes || null, now, now, now,
    ).run();

    return Response.json({ success: true, id, message: 'IOC recorded' }, { status: 201 });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// GET /api/cti/stats
export async function handleCTIStats(request, env, authCtx) {
  try {
    const actorStats = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical
       FROM cti_actors`
    ).first();

    const iocStats = await env.SECURITY_HUB_DB.prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
              SUM(CASE WHEN ioc_type = 'CVE' THEN 1 ELSE 0 END) as cves,
              SUM(CASE WHEN ioc_type = 'IP'  THEN 1 ELSE 0 END) as ips,
              SUM(CASE WHEN ioc_type IN ('HASH_MD5','HASH_SHA1','HASH_SHA256') THEN 1 ELSE 0 END) as hashes
       FROM cti_iocs WHERE is_active = 1`
    ).first();

    return Response.json({
      success: true,
      actors:  { total: actorStats?.total || 0, critical: actorStats?.critical || 0 },
      iocs:    {
        total:    iocStats?.total    || 0,
        critical: iocStats?.critical || 0,
        cves:     iocStats?.cves     || 0,
        ips:      iocStats?.ips      || 0,
        hashes:   iocStats?.hashes   || 0,
      },
    });
  } catch (_) {
    return Response.json({ success: true, actors: { total: 0 }, iocs: { total: 0 }, source: 'empty' });
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
function safeJson(str, fallback) {
  try { return typeof str === 'string' ? JSON.parse(str) : (str || fallback); }
  catch (_) { return fallback; }
}

// Seed actors from existing KV threat-intel data on first access
async function seedActorsFromKV(env) {
  // Return built-in APT profiles (static seed data)
  return BUILTIN_ACTORS;
}

async function getFallbackActors(env) {
  return BUILTIN_ACTORS;
}

// Curated baseline from MITRE ATT&CK — last_active reflects publicly reported dates,
// not platform-observed activity. source:'mitre_attck_baseline' distinguishes from live D1 data.
const BUILTIN_ACTORS = [
  {
    id: 'apt-lazarus', name: 'Lazarus Group', aliases: ['Hidden Cobra','ZINC','Guardians of Peace'],
    nation_state: 'North Korea', motivation: 'Financial/Espionage', sophistication: 'ADVANCED',
    threat_level: 'CRITICAL', confidence_score: 95, mitre_group_id: 'G0032',
    target_sectors: ['Financial','Defense','Cryptocurrency','Government'],
    description: 'Nation-state APT linked to DPRK, responsible for major financial heists and ransomware campaigns.',
    last_active: null, last_active_note: 'Ongoing — see MITRE ATT&CK G0032', source: 'mitre_attck_baseline',
  },
  {
    id: 'apt-sandworm', name: 'Sandworm', aliases: ['Voodoo Bear','TeleBots','BlackEnergy'],
    nation_state: 'Russia', motivation: 'Disruption/Espionage', sophistication: 'ADVANCED',
    threat_level: 'CRITICAL', confidence_score: 92, mitre_group_id: 'G0034',
    target_sectors: ['Energy','Government','Defense','Critical Infrastructure'],
    description: 'Russian GRU-linked APT known for destructive malware including NotPetya and Industroyer.',
    last_active: null, last_active_note: 'Ongoing — see MITRE ATT&CK G0034', source: 'mitre_attck_baseline',
  },
  {
    id: 'apt-cozy-bear', name: 'Cozy Bear', aliases: ['APT29','The Dukes','YTTRIUM'],
    nation_state: 'Russia', motivation: 'Espionage', sophistication: 'ADVANCED',
    threat_level: 'CRITICAL', confidence_score: 94, mitre_group_id: 'G0016',
    target_sectors: ['Government','Healthcare','Technology','Think Tanks'],
    description: 'SVR-linked APT conducting long-term espionage operations. Responsible for SolarWinds compromise.',
    last_active: null, last_active_note: 'Ongoing — see MITRE ATT&CK G0016', source: 'mitre_attck_baseline',
  },
  {
    id: 'apt-fin7', name: 'FIN7', aliases: ['Carbanak','Navigator Group'],
    nation_state: null, motivation: 'Financial', sophistication: 'HIGH',
    threat_level: 'HIGH', confidence_score: 88, mitre_group_id: 'G0046',
    target_sectors: ['Retail','Hospitality','Finance','Restaurant'],
    description: 'Financially-motivated cybercriminal group targeting POS systems and financial data.',
    last_active: null, last_active_note: 'See MITRE ATT&CK G0046', source: 'mitre_attck_baseline',
  },
  {
    id: 'apt-hafnium', name: 'HAFNIUM', aliases: ['Silk Typhoon'],
    nation_state: 'China', motivation: 'Espionage', sophistication: 'ADVANCED',
    threat_level: 'CRITICAL', confidence_score: 90, mitre_group_id: 'G0125',
    target_sectors: ['Defense','Law Firms','Research','NGOs'],
    description: 'Chinese state-sponsored APT known for zero-day exploitation of Microsoft Exchange Server.',
    last_active: null, last_active_note: 'See MITRE ATT&CK G0125', source: 'mitre_attck_baseline',
  },
  {
    id: 'apt-scattered-spider', name: 'Scattered Spider', aliases: ['0ktapus','Starfraud','UNC3944'],
    nation_state: null, motivation: 'Financial/Disruption', sophistication: 'HIGH',
    threat_level: 'HIGH', confidence_score: 85, mitre_group_id: 'G1015',
    target_sectors: ['Technology','Finance','Telecom','Hospitality'],
    description: 'English-speaking cybercriminal group known for social engineering and identity-based attacks.',
    last_active: null, last_active_note: 'See MITRE ATT&CK G1015', source: 'mitre_attck_baseline',
  },
];
