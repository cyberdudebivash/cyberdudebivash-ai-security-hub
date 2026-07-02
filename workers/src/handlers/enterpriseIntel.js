/**
 * CYBERDUDEBIVASH® AI Security Hub — Enterprise Intelligence Handler v1.0
 * P4.0-006 — Premium authenticated intelligence API
 *
 * All routes require Authorization: Bearer <token> or X-API-Key header.
 * Minimum tier: PRO, ENTERPRISE, MSSP, OWNER, ADMIN.
 *
 * Routes (registered in index.js):
 *   GET /api/enterprise/intelligence  — full risk-scored signal intelligence
 *   GET /api/enterprise/risk          — risk-ranked signals with filtering
 *   GET /api/enterprise/campaigns     — detailed campaign intelligence
 *   GET /api/enterprise/actors        — detailed actor intelligence
 */

import { RadarService } from '../services/radarService.js';
import { isRealUser } from '../auth/middleware.js';

const PUBLISHER = 'CYBERDUDEBIVASH® Sentinel APEX Intelligence';
const ALLOWED_TIERS = ['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN'];

// Risk score: CVSS×5 + EPSS×20 + KEV+15 + Ransomware+10, capped 100
function riskScore(signal) {
  const cvss   = parseFloat(signal.cvss || 0) || 0;
  const epss   = parseFloat(signal.epss || signal.epss_score || 0) || 0;
  const kev    = !!(signal.actively_exploited);
  const ransom = !!(signal.known_ransomware);
  return Math.min(100, Math.round(cvss * 5 + epss * 20 + (kev ? 15 : 0) + (ransom ? 10 : 0)));
}

// Sector classification: keyword match on title + tags
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
  return Object.entries(SECTOR_KEYWORDS)
    .filter(([, kws]) => kws.some(kw => text.includes(kw)))
    .map(([sector]) => sector);
}

// Enrich a signal with risk_score and targeted_sectors
function enrichSignal(signal) {
  return {
    ...signal,
    risk_score:       riskScore(signal),
    targeted_sectors: classifySignalSectors(signal),
  };
}

function jsonOk(data, ttl = 60) {
  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': `private, max-age=${ttl}`,
      'X-Intel-By':    `${PUBLISHER} v1.0`,
      'X-Powered-By':  'Cloudflare Workers',
    },
  });
}

function jsonErr(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg, status, publisher: PUBLISHER }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function checkAuth(authCtx) {
  if (!isRealUser(authCtx)) {
    return jsonErr('Authentication required — provide Authorization: Bearer <token> or X-API-Key header', 401);
  }
  if (!ALLOWED_TIERS.includes((authCtx.tier || '').toUpperCase())) {
    return jsonErr('Enterprise plan required. Upgrade at https://cyberdudebivash.in/#pricing', 403);
  }
  return null;
}

// ── GET /api/enterprise/intelligence ─────────────────────────────────────────
// Full risk-scored signal intelligence with filtering by industry/severity/min_risk
export async function handleEnterpriseIntelligence(request, env, authCtx) {
  const authErr = checkAuth(authCtx);
  if (authErr) return authErr;

  try {
    const url      = new URL(request.url);
    const industry = (url.searchParams.get('industry') || '').toLowerCase();
    const severity = (url.searchParams.get('severity') || '').toUpperCase();
    const min_risk = parseInt(url.searchParams.get('min_risk') || '0', 10) || 0;
    const limit    = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);

    const svc  = new RadarService(env);
    const snap = await svc.getEnterpriseSnapshot({ industry: industry || null });
    let signals = (snap.signals || []).map(enrichSignal);

    if (severity) signals = signals.filter(s => s.severity === severity);
    if (min_risk) signals = signals.filter(s => s.risk_score >= min_risk);

    signals = signals
      .sort((a, b) => b.risk_score - a.risk_score || b.cvss - a.cvss)
      .slice(0, limit);

    return jsonOk({
      signals,
      count:                signals.length,
      total_signals:        snap.total_signals,
      severity_distribution: snap.severity_distribution,
      timestamp:            snap.timestamp,
      tier:                 authCtx.tier,
      filters:              { industry: industry || null, severity: severity || null, min_risk },
      publisher:            PUBLISHER,
    });
  } catch (e) {
    console.error('[EnterpriseIntel] intelligence error:', e?.message);
    return jsonErr('Intelligence feed temporarily unavailable', 503);
  }
}

// ── GET /api/enterprise/risk ──────────────────────────────────────────────────
// Risk-ranked signals with distribution summary and tier breakdown
export async function handleEnterpriseRisk(request, env, authCtx) {
  const authErr = checkAuth(authCtx);
  if (authErr) return authErr;

  try {
    const url      = new URL(request.url);
    const min_risk = parseInt(url.searchParams.get('min_risk') || '50', 10) || 50;
    const limit    = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);

    const svc  = new RadarService(env);
    const snap = await svc.getEnterpriseSnapshot();
    const enriched = (snap.signals || []).map(enrichSignal);

    // Risk tier distribution
    const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const s of enriched) {
      if (s.risk_score >= 80)      dist.CRITICAL++;
      else if (s.risk_score >= 60) dist.HIGH++;
      else if (s.risk_score >= 40) dist.MEDIUM++;
      else                          dist.LOW++;
    }

    const filtered = enriched
      .filter(s => s.risk_score >= min_risk)
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, limit)
      .map(s => ({
        id:                 s.id,
        title:              s.title,
        severity:           s.severity,
        cvss:               s.cvss,
        epss:               s.epss,
        risk_score:         s.risk_score,
        confidence:         s.confidence,
        actively_exploited: s.actively_exploited,
        known_ransomware:   s.known_ransomware,
        threat_actor:       s.threat_actor,
        targeted_sectors:   s.targeted_sectors,
        published_at:       s.published_at,
      }));

    return jsonOk({
      risk_signals:         filtered,
      count:                filtered.length,
      risk_distribution:    dist,
      total_signals:        enriched.length,
      avg_risk_score:       enriched.length ? Math.round(enriched.reduce((s, x) => s + x.risk_score, 0) / enriched.length) : 0,
      timestamp:            snap.timestamp,
      tier:                 authCtx.tier,
      filters:              { min_risk },
      publisher:            PUBLISHER,
    });
  } catch (e) {
    console.error('[EnterpriseIntel] risk error:', e?.message);
    return jsonErr('Risk intelligence temporarily unavailable', 503);
  }
}

// ── GET /api/enterprise/campaigns ────────────────────────────────────────────
// Detailed campaign intelligence with actor correlation and sector targeting
export async function handleEnterpriseCampaigns(request, env, authCtx) {
  const authErr = checkAuth(authCtx);
  if (authErr) return authErr;

  try {
    const url    = new URL(request.url);
    const sector = url.searchParams.get('sector') || null;

    const svc     = new RadarService(env);
    const snap    = await svc.getEnterpriseSnapshot();
    const signals = (snap.signals || []).map(enrichSignal);

    const campMap = {};
    for (const sig of signals) {
      const camp = sig.campaign;
      if (!camp) continue;
      if (!campMap[camp]) {
        campMap[camp] = {
          name: camp, signal_count: 0,
          severities: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 },
          max_cvss: 0, max_risk: 0, total_risk: 0,
          sectors: new Set(), cves: [], actors: new Set(),
          ransomware_groups: new Set(), first_seen: null, last_seen: null,
        };
      }
      const e = campMap[camp];
      e.signal_count++;
      if (e.severities[sig.severity] !== undefined) e.severities[sig.severity]++;
      if (sig.cvss > e.max_cvss) e.max_cvss = sig.cvss;
      if (sig.risk_score > e.max_risk) e.max_risk = sig.risk_score;
      e.total_risk += sig.risk_score;
      sig.targeted_sectors.forEach(s => e.sectors.add(s));
      if (sig.id?.startsWith('CVE-') && !e.cves.includes(sig.id)) e.cves.push(sig.id);
      if (sig.threat_actor)    e.actors.add(sig.threat_actor);
      if (sig.ransomware_group) e.ransomware_groups.add(sig.ransomware_group);
      if (sig.published_at) {
        if (!e.first_seen || sig.published_at < e.first_seen) e.first_seen = sig.published_at;
        if (!e.last_seen  || sig.published_at > e.last_seen)  e.last_seen  = sig.published_at;
      }
    }

    let campaigns = Object.values(campMap).map(c => ({
      name:              c.name,
      signal_count:      c.signal_count,
      severity_dist:     c.severities,
      max_cvss:          c.max_cvss,
      max_risk_score:    c.max_risk,
      avg_risk_score:    Math.round(c.total_risk / c.signal_count),
      targeted_sectors:  [...c.sectors],
      cves:              c.cves,
      threat_actors:     [...c.actors],
      ransomware_groups: [...c.ransomware_groups],
      first_seen:        c.first_seen,
      last_seen:         c.last_seen,
    }));

    if (sector) {
      campaigns = campaigns.filter(c => c.targeted_sectors.some(s => s.toLowerCase() === sector.toLowerCase()));
    }

    campaigns.sort((a, b) => b.max_risk_score - a.max_risk_score || b.signal_count - a.signal_count);

    return jsonOk({
      campaigns,
      count:     campaigns.length,
      timestamp: snap.timestamp,
      tier:      authCtx.tier,
      filters:   { sector },
      publisher: PUBLISHER,
    });
  } catch (e) {
    console.error('[EnterpriseIntel] campaigns error:', e?.message);
    return jsonErr('Campaign intelligence temporarily unavailable', 503);
  }
}

// ── GET /api/enterprise/actors ────────────────────────────────────────────────
// Detailed actor intelligence with confidence, sectors, CVEs, MITRE correlation
export async function handleEnterpriseActors(request, env, authCtx) {
  const authErr = checkAuth(authCtx);
  if (authErr) return authErr;

  try {
    const url      = new URL(request.url);
    const country  = (url.searchParams.get('country') || '').toLowerCase();
    const min_risk = parseInt(url.searchParams.get('min_risk') || '0', 10) || 0;

    // Static MITRE ATT&CK correlation (public knowledge base)
    const MITRE = {
      'APT29':            { group_id: 'G0016', aliases: ['Cozy Bear', 'Midnight Blizzard', 'NOBELIUM'], country: 'Russia', techniques: ['T1566', 'T1078', 'T1003', 'T1550'] },
      'APT28':            { group_id: 'G0007', aliases: ['Fancy Bear', 'Forest Blizzard', 'Sofacy'], country: 'Russia', techniques: ['T1566', 'T1203', 'T1068', 'T1059'] },
      'Lazarus Group':    { group_id: 'G0032', aliases: ['Lazarus', 'HIDDEN COBRA', 'Zinc'], country: 'North Korea', techniques: ['T1566', 'T1027', 'T1486', 'T1041'] },
      'Sandworm':         { group_id: 'G0034', aliases: ['Sandworm Team', 'Electrum', 'Voodoo Bear'], country: 'Russia', techniques: ['T1078', 'T1190', 'T1059', 'T1485'] },
      'APT41':            { group_id: 'G0096', aliases: ['Double Dragon', 'Winnti', 'BARIUM'], country: 'China', techniques: ['T1190', 'T1078', 'T1059', 'T1036'] },
      'Volt Typhoon':     { group_id: 'G1017', aliases: ['BRONZE SILHOUETTE', 'Vanguard Panda'], country: 'China', techniques: ['T1190', 'T1505', 'T1078', 'T1021'] },
      'Salt Typhoon':     { group_id: 'G1045', aliases: ['FamousSparrow'], country: 'China', techniques: ['T1190', 'T1505', 'T1083', 'T1560'] },
      'Scattered Spider': { group_id: 'G1015', aliases: ['UNC3944', 'Muddled Libra'], country: 'Unknown', techniques: ['T1566', 'T1621', 'T1078', 'T1537'] },
      'BlackCat':         { group_id: null, aliases: ['ALPHV', 'Noberus'], country: 'Unknown', techniques: ['T1486', 'T1190', 'T1078', 'T1059'] },
      'LockBit':          { group_id: null, aliases: ['Gold Mystic'], country: 'Unknown', techniques: ['T1486', 'T1078', 'T1059', 'T1562'] },
      'Clop':             { group_id: null, aliases: ['TA505', 'FIN11'], country: 'Unknown', techniques: ['T1190', 'T1486', 'T1560', 'T1567'] },
      'RansomHub':        { group_id: null, aliases: [], country: 'Unknown', techniques: ['T1486', 'T1190', 'T1078'] },
      'Play':             { group_id: null, aliases: ['Playcrypt'], country: 'Unknown', techniques: ['T1190', 'T1486', 'T1078'] },
      'Black Basta':      { group_id: null, aliases: ['Water Curupira'], country: 'Unknown', techniques: ['T1566', 'T1486', 'T1078', 'T1059'] },
      'Akira':            { group_id: null, aliases: [], country: 'Unknown', techniques: ['T1190', 'T1486', 'T1078', 'T1059'] },
    };

    function resolveMitre(name) {
      if (!name) return null;
      const norm = name.trim().toLowerCase();
      for (const [k, v] of Object.entries(MITRE)) {
        if (k.toLowerCase() === norm || v.aliases.some(a => a.toLowerCase() === norm)) {
          return { canonical_name: k, ...v };
        }
      }
      return null;
    }

    const svc     = new RadarService(env);
    const snap    = await svc.getEnterpriseSnapshot();
    const signals = (snap.signals || []).map(enrichSignal);

    const actorMap = {};
    for (const sig of signals) {
      const actor = sig.threat_actor;
      if (!actor) continue;
      if (!actorMap[actor]) {
        actorMap[actor] = {
          name: actor, signal_count: 0, confidence_total: 0,
          severities: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 },
          max_cvss: 0, max_risk: 0, total_risk: 0,
          sectors: new Set(), cves: [], campaigns: new Set(), ransomware_groups: new Set(),
        };
      }
      const e = actorMap[actor];
      e.signal_count++;
      e.confidence_total += sig.confidence || 0;
      if (e.severities[sig.severity] !== undefined) e.severities[sig.severity]++;
      if (sig.cvss > e.max_cvss) e.max_cvss = sig.cvss;
      if (sig.risk_score > e.max_risk) e.max_risk = sig.risk_score;
      e.total_risk += sig.risk_score;
      sig.targeted_sectors.forEach(s => e.sectors.add(s));
      if (sig.id?.startsWith('CVE-') && !e.cves.includes(sig.id)) e.cves.push(sig.id);
      if (sig.campaign)        e.campaigns.add(sig.campaign);
      if (sig.ransomware_group) e.ransomware_groups.add(sig.ransomware_group);
    }

    let actors = Object.values(actorMap).map(a => {
      const mitre = resolveMitre(a.name);
      return {
        name:               a.name,
        signal_count:       a.signal_count,
        avg_confidence:     Math.round(a.confidence_total / a.signal_count),
        severity_dist:      a.severities,
        max_cvss:           a.max_cvss,
        max_risk_score:     a.max_risk,
        avg_risk_score:     Math.round(a.total_risk / a.signal_count),
        targeted_sectors:   [...a.sectors],
        cves:               a.cves,
        campaigns:          [...a.campaigns],
        ransomware_groups:  [...a.ransomware_groups],
        mitre_group_id:     mitre?.group_id || null,
        mitre_aliases:      mitre?.aliases  || [],
        country:            mitre?.country  || 'Unknown',
        att_ck_techniques:  mitre?.techniques || [],
      };
    });

    if (country) actors = actors.filter(a => a.country.toLowerCase().includes(country));
    if (min_risk) actors = actors.filter(a => a.max_risk_score >= min_risk);
    actors.sort((a, b) => b.max_risk_score - a.max_risk_score || b.signal_count - a.signal_count);

    return jsonOk({
      threat_actors: actors,
      count:         actors.length,
      timestamp:     snap.timestamp,
      tier:          authCtx.tier,
      filters:       { country: country || null, min_risk },
      publisher:     PUBLISHER,
    });
  } catch (e) {
    console.error('[EnterpriseIntel] actors error:', e?.message);
    return jsonErr('Actor intelligence temporarily unavailable', 503);
  }
}
