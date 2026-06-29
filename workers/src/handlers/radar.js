/**
 * CYBERDUDEBIVASH® AI Security Hub — Cyber Signal Radar Handler v2.0
 * P3.0-001 / P3.0-007 / P3.0-008 / P4.0-001–004
 *
 * Public routes (no auth):
 *   GET /api/radar/snapshot          — unified public snapshot (5-min cache)
 *   GET /api/radar/latest            — latest CVE signals
 *   GET /api/radar/summary           — severity summary stats
 *   GET /api/radar/trending          — trending threats by EPSS/CVSS
 *   GET /api/radar/threat-actors     — MITRE ATT&CK correlated actor intelligence
 *   GET /api/radar/campaigns         — campaign summaries with sectors/CVEs/timeline
 *   GET /api/radar/sectors           — industry vertical threat breakdown (7 sectors)
 *
 * Enterprise routes (auth required):
 *   GET /api/radar/enterprise           — full enterprise snapshot
 *   GET /api/radar/enterprise/signals   — extended signal list with confidence scores
 */

import { RadarService, CACHE_HEADER_TTL } from '../services/radarService.js';

const PUBLISHER = 'CYBERDUDEBIVASH® Cyber Signal Radar';

const BASE_HEADERS = {
  'X-Radar-By':    `${PUBLISHER} v1.0`,
  'X-Powered-By':  'Cloudflare Workers',
};

function jsonOk(data, ttl = CACHE_HEADER_TTL) {
  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': `public, max-age=${ttl}, stale-while-revalidate=60`,
      ...BASE_HEADERS,
    },
  });
}

function jsonErr(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg, status }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...BASE_HEADERS },
  });
}

// ── P3.0-001 — GET /api/radar/snapshot ───────────────────────────────────────
async function handleSnapshot(request, env) {
  try {
    const svc  = new RadarService(env);
    const data = await svc.getPublicSnapshot();
    const res  = jsonOk(data);
    // P3.0-009: edge-cache the snapshot on Cloudflare's CDN (free, no KV quota)
    try {
      const cacheReq = new Request(`https://cdb-edge-cache/radar/snapshot/v1`);
      const cached   = await caches.default.match(cacheReq);
      if (!cached) {
        const toCache = res.clone();
        const h = new Headers(toCache.headers);
        h.set('Cache-Control', `public, max-age=${CACHE_HEADER_TTL}`);
        await caches.default.put(cacheReq, new Response(await toCache.text(), { headers: h }));
      }
    } catch {}
    return res;
  } catch (e) {
    console.error('[Radar] snapshot error:', e?.message);
    return jsonErr('Radar temporarily unavailable', 503);
  }
}

// ── P3.0-007 — GET /api/radar/latest ─────────────────────────────────────────
async function handleLatest(request, env) {
  try {
    const url   = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20', 10) || 20, 20);
    const svc   = new RadarService(env);
    const items = await svc.getLatest({ limit });
    return jsonOk({ items, count: items.length, timestamp: new Date().toISOString(), publisher: PUBLISHER });
  } catch (e) {
    return jsonErr('Unavailable', 503);
  }
}

// ── P3.0-007 — GET /api/radar/summary ────────────────────────────────────────
async function handleSummary(request, env) {
  try {
    const svc  = new RadarService(env);
    const data = await svc.getSummary();
    return jsonOk(data);
  } catch (e) {
    return jsonErr('Unavailable', 503);
  }
}

// ── P3.0-007 — GET /api/radar/trending ───────────────────────────────────────
async function handleTrending(request, env) {
  try {
    const url   = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '10', 10) || 10, 10);
    const svc   = new RadarService(env);
    const items = await svc.getTrending({ limit });
    return jsonOk({ items, count: items.length, timestamp: new Date().toISOString(), publisher: PUBLISHER });
  } catch (e) {
    return jsonErr('Unavailable', 503);
  }
}

// ── P4.0 — Risk score: CVSS×5 + EPSS×20 + KEV+15 + Ransomware+10 ─────────────
export function riskScore(signal) {
  const cvss   = parseFloat(signal.cvss || 0) || 0;
  const epss   = parseFloat(signal.epss || signal.epss_score || 0) || 0;
  const kev    = !!(signal.actively_exploited);
  const ransom = !!(signal.known_ransomware);
  return Math.min(100, Math.round(cvss * 5 + epss * 20 + (kev ? 15 : 0) + (ransom ? 10 : 0)));
}

// ── MITRE ATT&CK group correlation (public knowledge base, June 2026) ─────────
const MITRE_ATT_CK = {
  'APT29':            { group_id: 'G0016', aliases: ['Cozy Bear', 'Midnight Blizzard', 'NOBELIUM', 'UNC2452'], country: 'Russia', techniques: ['T1566', 'T1078', 'T1003', 'T1550'] },
  'APT28':            { group_id: 'G0007', aliases: ['Fancy Bear', 'Forest Blizzard', 'Sofacy', 'Pawn Storm'], country: 'Russia', techniques: ['T1566', 'T1203', 'T1068', 'T1059'] },
  'Lazarus Group':    { group_id: 'G0032', aliases: ['Lazarus', 'HIDDEN COBRA', 'Zinc', 'Labyrinth Chollima'], country: 'North Korea', techniques: ['T1566', 'T1027', 'T1486', 'T1041'] },
  'Sandworm':         { group_id: 'G0034', aliases: ['Sandworm Team', 'Electrum', 'Voodoo Bear', 'Seashell Blizzard'], country: 'Russia', techniques: ['T1078', 'T1190', 'T1059', 'T1485'] },
  'APT41':            { group_id: 'G0096', aliases: ['Double Dragon', 'Winnti', 'BARIUM', 'Earth Baku'], country: 'China', techniques: ['T1190', 'T1078', 'T1059', 'T1036'] },
  'Volt Typhoon':     { group_id: 'G1017', aliases: ['BRONZE SILHOUETTE', 'Vanguard Panda', 'DEV-0391'], country: 'China', techniques: ['T1190', 'T1505', 'T1078', 'T1021'] },
  'Salt Typhoon':     { group_id: 'G1045', aliases: ['FamousSparrow', 'GhostEmperor'], country: 'China', techniques: ['T1190', 'T1505', 'T1083', 'T1560'] },
  'Scattered Spider': { group_id: 'G1015', aliases: ['UNC3944', 'Muddled Libra', 'Octo Tempest'], country: 'Unknown', techniques: ['T1566', 'T1621', 'T1078', 'T1537'] },
  'BlackCat':         { group_id: null, aliases: ['ALPHV', 'Noberus'], country: 'Unknown', techniques: ['T1486', 'T1190', 'T1078', 'T1059'] },
  'LockBit':          { group_id: null, aliases: ['Gold Mystic', 'LockBit 3.0'], country: 'Unknown', techniques: ['T1486', 'T1078', 'T1059', 'T1562'] },
  'Clop':             { group_id: null, aliases: ['TA505', 'FIN11', 'GOLD TAHOE'], country: 'Unknown', techniques: ['T1190', 'T1486', 'T1560', 'T1567'] },
  'RansomHub':        { group_id: null, aliases: [], country: 'Unknown', techniques: ['T1486', 'T1190', 'T1078'] },
  'Play':             { group_id: null, aliases: ['Playcrypt', 'FANCYCAT'], country: 'Unknown', techniques: ['T1190', 'T1486', 'T1078'] },
  'Black Basta':      { group_id: null, aliases: ['Water Curupira'], country: 'Unknown', techniques: ['T1566', 'T1486', 'T1078', 'T1059'] },
  'Akira':            { group_id: null, aliases: [], country: 'Unknown', techniques: ['T1190', 'T1486', 'T1078', 'T1059'] },
};

function resolveMitre(actorName) {
  if (!actorName) return null;
  const norm = actorName.trim().toLowerCase();
  for (const [k, v] of Object.entries(MITRE_ATT_CK)) {
    if (k.toLowerCase() === norm) return { canonical_name: k, ...v };
    if (v.aliases.some(a => a.toLowerCase() === norm)) return { canonical_name: k, ...v };
  }
  return null;
}

// ── Sector classification: keyword match on title + tags ──────────────────────
const SECTOR_KEYWORDS = {
  Finance:       ['bank', 'fintech', 'financial', 'payment', 'swift', 'trading', 'insurance', 'credit', 'brokerage', 'treasury'],
  Healthcare:    ['hospital', 'medical', 'health', 'pharma', 'clinical', 'hipaa', 'patient', 'ehr', 'biotech', 'fda'],
  Government:    ['government', 'federal', 'defense', 'military', 'nato', 'election', 'public sector', 'municipal', 'cisa', 'dod'],
  Manufacturing: ['scada', 'ics', 'industrial', 'manufacturing', 'ot/', 'plc', 'factory', 'automation', 'cnc'],
  Education:     ['university', 'education', 'school', 'academic', 'research institute', 'student', 'college'],
  Retail:        ['retail', 'ecommerce', 'e-commerce', 'pos ', 'point-of-sale', 'supply chain', 'logistics', 'warehouse'],
  Energy:        ['energy', 'power grid', 'oil', 'gas', 'utility', 'nuclear', 'pipeline', 'electricity', 'substation'],
};

function classifySignalSectors(signal) {
  const text = `${signal.title || ''} ${(signal.tags || []).join(' ')}`.toLowerCase();
  const matched = [];
  for (const [sector, keywords] of Object.entries(SECTOR_KEYWORDS)) {
    if (keywords.some(kw => text.includes(kw))) matched.push(sector);
  }
  return matched;
}

// ── P4.0-001 — GET /api/radar/threat-actors ───────────────────────────────────
async function handleThreatActors(request, env) {
  try {
    const svc     = new RadarService(env);
    const snap    = await svc.getEnterpriseSnapshot();
    const signals = snap.signals || [];

    const actorMap = {};
    for (const sig of signals) {
      const actor = sig.threat_actor;
      if (!actor) continue;
      if (!actorMap[actor]) {
        actorMap[actor] = { name: actor, signal_count: 0, severities: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 }, max_cvss: 0, max_risk: 0, cves: [] };
      }
      const e = actorMap[actor];
      e.signal_count++;
      if (e.severities[sig.severity] !== undefined) e.severities[sig.severity]++;
      if (sig.cvss > e.max_cvss) e.max_cvss = sig.cvss;
      const rs = riskScore(sig);
      if (rs > e.max_risk) e.max_risk = rs;
      if (sig.id?.startsWith('CVE-') && !e.cves.includes(sig.id)) e.cves.push(sig.id);
    }

    const threat_actors = Object.values(actorMap)
      .sort((a, b) => b.max_risk - a.max_risk || b.signal_count - a.signal_count)
      .slice(0, 20)
      .map(a => {
        const mitre = resolveMitre(a.name);
        return {
          name:            a.name,
          signal_count:    a.signal_count,
          severity_dist:   a.severities,
          max_cvss:        a.max_cvss,
          risk_score:      a.max_risk,
          cves:            a.cves.slice(0, 10),
          mitre_group_id:  mitre?.group_id  || null,
          mitre_aliases:   mitre?.aliases   || [],
          country:         mitre?.country   || 'Unknown',
          att_ck_techniques: mitre?.techniques || [],
        };
      });

    return jsonOk({ threat_actors, count: threat_actors.length, timestamp: snap.timestamp, publisher: PUBLISHER }, 120);
  } catch (e) {
    console.error('[Radar] threat-actors error:', e?.message);
    return jsonErr('Unavailable', 503);
  }
}

// ── P4.0-002 — GET /api/radar/campaigns ──────────────────────────────────────
async function handleCampaigns(request, env) {
  try {
    const svc     = new RadarService(env);
    const snap    = await svc.getEnterpriseSnapshot();
    const signals = snap.signals || [];

    const campMap = {};
    for (const sig of signals) {
      const camp = sig.campaign;
      if (!camp) continue;
      if (!campMap[camp]) {
        campMap[camp] = { name: camp, signal_count: 0, severities: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 },
          max_cvss: 0, max_risk: 0, sectors: new Set(), cves: [], actors: new Set(),
          ransomware_groups: new Set(), first_seen: null, last_seen: null };
      }
      const e = campMap[camp];
      e.signal_count++;
      if (e.severities[sig.severity] !== undefined) e.severities[sig.severity]++;
      if (sig.cvss > e.max_cvss) e.max_cvss = sig.cvss;
      const rs = riskScore(sig);
      if (rs > e.max_risk) e.max_risk = rs;
      classifySignalSectors(sig).forEach(s => e.sectors.add(s));
      if (sig.id?.startsWith('CVE-') && !e.cves.includes(sig.id)) e.cves.push(sig.id);
      if (sig.threat_actor)    e.actors.add(sig.threat_actor);
      if (sig.ransomware_group) e.ransomware_groups.add(sig.ransomware_group);
      if (sig.published_at) {
        if (!e.first_seen || sig.published_at < e.first_seen) e.first_seen = sig.published_at;
        if (!e.last_seen  || sig.published_at > e.last_seen)  e.last_seen  = sig.published_at;
      }
    }

    const campaigns = Object.values(campMap)
      .sort((a, b) => b.max_risk - a.max_risk || b.signal_count - a.signal_count)
      .slice(0, 20)
      .map(c => ({
        name:              c.name,
        signal_count:      c.signal_count,
        severity_dist:     c.severities,
        max_cvss:          c.max_cvss,
        risk_score:        c.max_risk,
        targeted_sectors:  [...c.sectors],
        cves:              c.cves.slice(0, 10),
        threat_actors:     [...c.actors],
        ransomware_groups: [...c.ransomware_groups],
        first_seen:        c.first_seen,
        last_seen:         c.last_seen,
      }));

    return jsonOk({ campaigns, count: campaigns.length, timestamp: snap.timestamp, publisher: PUBLISHER }, 120);
  } catch (e) {
    console.error('[Radar] campaigns error:', e?.message);
    return jsonErr('Unavailable', 503);
  }
}

// ── P4.0-004 — GET /api/radar/sectors ────────────────────────────────────────
async function handleSectors(request, env) {
  try {
    const svc     = new RadarService(env);
    const snap    = await svc.getEnterpriseSnapshot();
    const signals = snap.signals || [];

    const sectorData = {};
    for (const name of [...Object.keys(SECTOR_KEYWORDS), 'Cross-Sector']) {
      sectorData[name] = { name, signal_count: 0, critical_count: 0, high_count: 0, max_risk: 0, top_cves: [] };
    }

    for (const sig of signals) {
      const matched = classifySignalSectors(sig);
      const targets = matched.length ? matched : ['Cross-Sector'];
      const rs = riskScore(sig);
      for (const sector of targets) {
        const e = sectorData[sector];
        if (!e) continue;
        e.signal_count++;
        if (sig.severity === 'CRITICAL') e.critical_count++;
        if (sig.severity === 'HIGH') e.high_count++;
        if (rs > e.max_risk) e.max_risk = rs;
        if (sig.id?.startsWith('CVE-') && e.top_cves.length < 5 && !e.top_cves.includes(sig.id)) e.top_cves.push(sig.id);
      }
    }

    const sectors = Object.values(sectorData)
      .filter(s => s.signal_count > 0)
      .sort((a, b) => b.max_risk - a.max_risk || b.signal_count - a.signal_count);

    return jsonOk({ sectors, count: sectors.length, timestamp: snap.timestamp, publisher: PUBLISHER }, 120);
  } catch (e) {
    console.error('[Radar] sectors error:', e?.message);
    return jsonErr('Unavailable', 503);
  }
}

// ── P3.0-008 — Enterprise endpoints (auth required) ──────────────────────────
async function handleEnterprise(request, env, authCtx, subpath) {
  if (!authCtx?.authenticated) {
    return jsonErr('Authentication required — provide Authorization: Bearer <token> or X-API-Key header', 401);
  }
  const allowedTiers = ['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN'];
  if (!allowedTiers.includes((authCtx.tier || '').toUpperCase())) {
    return jsonErr('Enterprise plan required. Upgrade at https://cyberdudebivash.in/#pricing', 403);
  }
  try {
    const svc      = new RadarService(env);
    const url      = new URL(request.url);
    const industry = url.searchParams.get('industry') || null;

    if (subpath === '/signals') {
      const snap = await svc.getEnterpriseSnapshot({ industry });
      return jsonOk({
        signals:               snap.signals,
        severity_distribution: snap.severity_distribution,
        top_campaigns:         snap.top_campaigns,
        active_threat_actors:  snap.active_threat_actors,
        ransomware_activity:   snap.ransomware_activity,
        ai_threats_detected:   snap.ai_threats_detected,
        total_signals:         snap.total_signals,
        timestamp:             snap.timestamp,
        tier:                  authCtx.tier || 'ENTERPRISE',
      }, 60);
    }

    // Default enterprise full snapshot
    const snap = await svc.getEnterpriseSnapshot({ industry });
    return jsonOk({ ...snap, user_tier: authCtx.tier || 'ENTERPRISE' }, 60);
  } catch (e) {
    console.error('[Radar] enterprise error:', e?.message);
    return jsonErr('Enterprise radar unavailable', 503);
  }
}

// ── Main router ────────────────────────────────────────────────────────────────
export async function handleRadar(request, env, authCtx, path) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: BASE_HEADERS });
  }
  if (request.method !== 'GET') return jsonErr('Method not allowed', 405);

  if (path === '/api/radar/snapshot')      return handleSnapshot(request, env);
  if (path === '/api/radar/latest')        return handleLatest(request, env);
  if (path === '/api/radar/summary')       return handleSummary(request, env);
  if (path === '/api/radar/trending')      return handleTrending(request, env);
  if (path === '/api/radar/threat-actors') return handleThreatActors(request, env);
  if (path === '/api/radar/campaigns')     return handleCampaigns(request, env);
  if (path === '/api/radar/sectors')       return handleSectors(request, env);

  if (path === '/api/radar/enterprise' || path.startsWith('/api/radar/enterprise/')) {
    const sub = path.slice('/api/radar/enterprise'.length) || '';
    return handleEnterprise(request, env, authCtx, sub);
  }

  return jsonErr('Not found', 404);
}
