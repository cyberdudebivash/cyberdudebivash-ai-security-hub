/**
 * CYBERDUDEBIVASH® Sentinel APEX — Customer Intelligence Handler v1.0
 * P5.0 — Multi-tenant customer intelligence & MSSP platform
 *
 * D1 tables:  customer_profiles, customer_assets (auto-created on first use)
 * KV caches:  customer:profile:{id} (1h), customer:radar:{id} (5m), customer:risk:{id} (5m)
 *
 * Routes (registered in index.js):
 *   GET    /api/customer/profile      — get/init intelligence profile
 *   PUT    /api/customer/profile      — create/update profile
 *   GET    /api/customer/radar        — personalized threat radar
 *   GET    /api/customer/risk         — organization risk score + recommendations
 *   GET    /api/customer/assets       — list registered assets
 *   POST   /api/customer/assets       — register domain/IP/ASN/tech/CVE watchlist
 *   DELETE /api/customer/assets/:id   — remove asset
 *   GET    /api/customer/report       — executive report (?format=json|html)
 */

import { RadarService } from '../services/radarService.js';
import { isRealUser } from '../auth/middleware.js';

const PUB = 'CYBERDUDEBIVASH® Sentinel APEX Customer Intelligence';
const KV_PROFILE_TTL = 3600;
const KV_RADAR_TTL   = 300;
const KV_RISK_TTL    = 300;
const ASSET_LIMIT    = 100;

const VALID_ASSET_TYPES = ['domain','ip_range','asn','cloud_account','technology','cve_watchlist'];
const VALID_ORG_SIZES   = ['SMB','MID','ENTERPRISE','GOVERNMENT','CRITICAL_INFRA'];

// ── Helpers ───────────────────────────────────────────────────────────────────
function jsonOk(data, ttl = 60) {
  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': `private, max-age=${ttl}`,
      'X-Intel-By':    `${PUB} v1.0`,
      'X-Powered-By':  'Cloudflare Workers',
    },
  });
}

function htmlOk(html) {
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function jsonErr(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg, status }), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function reqAuth(authCtx) {
  if (!isRealUser(authCtx)) return jsonErr('Authentication required', 401);
  return null;
}

function safeJson(v, fb = []) {
  if (!v) return fb;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch { return fb; }
}

function nid() {
  return `ast_${crypto.randomUUID().replace(/-/g,'').slice(0,16)}`;
}

// MSSP multi-tenant scope: MSSP/OWNER/ADMIN can pass ?customer_id= to act on behalf
function tenantScope(authCtx, url) {
  const tier = (authCtx.tier || '').toUpperCase();
  const isMSSP = ['MSSP', 'OWNER', 'ADMIN'].includes(tier);
  const cid = url.searchParams.get('customer_id');
  return { targetId: (isMSSP && cid) ? cid : authCtx.userId, isMSSP };
}

// ── Scoring (local — no cross-handler import) ─────────────────────────────────
function riskScore(s) {
  const cvss = parseFloat(s.cvss || 0) || 0;
  const epss = parseFloat(s.epss || s.epss_score || 0) || 0;
  return Math.min(100, Math.round(
    cvss * 5 + epss * 20 + (s.actively_exploited ? 15 : 0) + (s.known_ransomware ? 10 : 0)
  ));
}

const SECTOR_KW = {
  Finance:       ['bank','fintech','financial','payment','swift','trading','insurance','credit'],
  Healthcare:    ['hospital','medical','health','pharma','clinical','hipaa','patient','ehr'],
  Government:    ['government','federal','defense','military','nato','election','public sector'],
  Manufacturing: ['scada','ics','industrial','manufacturing','ot/','plc','factory','automation'],
  Education:     ['university','education','school','academic','research','student'],
  Retail:        ['retail','ecommerce','e-commerce','pos ','supply chain','logistics'],
  Energy:        ['energy','power grid','oil','gas','utility','nuclear','pipeline'],
};

function sigSectors(s) {
  const text = `${s.title||''} ${(s.tags||[]).join(' ')}`.toLowerCase();
  return Object.entries(SECTOR_KW).filter(([,kws]) => kws.some(k => text.includes(k))).map(([sec]) => sec);
}

// ── D1 table bootstrap (once per isolate) ─────────────────────────────────────
let _tablesReady = false;
async function ensureTables(db) {
  if (_tablesReady) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS customer_profiles (
        id TEXT PRIMARY KEY,
        org_id TEXT,
        org_name TEXT,
        industry TEXT,
        country TEXT,
        org_size TEXT,
        technology_stack TEXT DEFAULT '[]',
        cloud_providers TEXT DEFAULT '[]',
        business_critical_assets TEXT DEFAULT '[]',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS customer_assets (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        org_id TEXT,
        asset_type TEXT NOT NULL,
        asset_value TEXT NOT NULL,
        label TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
    ]);
    _tablesReady = true;
  } catch {}
}

// ── Personalization engine (P5.0-002) ─────────────────────────────────────────
// Ranks signals by relevance to the customer profile: CVE watchlist hits score
// highest (+30), then industry match (+15), then tech stack match (+10).
function personalizeSignals(signals, profile, watchCVEs, techStack) {
  const industry  = (profile?.industry || '').toLowerCase();
  const techLower = (techStack || []).map(t => String(t).toLowerCase());
  const watchSet  = new Set((watchCVEs || []).map(c => (c || '').toLowerCase()));

  return signals.map(sig => {
    const rs      = riskScore(sig);
    const sectors = sigSectors(sig);
    const sigText = `${sig.title||''} ${(sig.tags||[]).join(' ')}`.toLowerCase();
    const direct  = watchSet.has((sig.id || '').toLowerCase());
    const indMat  = !!(industry && sectors.some(s => s.toLowerCase() === industry));
    const techMat = !!(techLower.length && techLower.some(t => sigText.includes(t)));
    return {
      ...sig,
      risk_score:       rs,
      targeted_sectors: sectors,
      relevance_score:  rs + (direct ? 30 : 0) + (indMat ? 15 : 0) + (techMat ? 10 : 0),
      direct_hit:       direct,
      industry_match:   indMat,
      tech_match:       techMat,
    };
  }).sort((a, b) => b.relevance_score - a.relevance_score || b.risk_score - a.risk_score);
}

// ── Org risk score (P5.0-004) ─────────────────────────────────────────────────
// Distinct from signal-level risk_score. Aggregates exposure across profile.
function computeOrgRisk(pSignals, watchCVEs) {
  if (!pSignals.length) return { score: 0, label: 'LOW', base_score: 0, factors: [] };

  const top20     = pSignals.slice(0, 20);
  const base      = Math.round(top20.reduce((s, x) => s + x.risk_score, 0) / top20.length);
  const directKEV = pSignals.filter(s => s.direct_hit && s.actively_exploited);
  const techExp   = pSignals.filter(s => s.tech_match && s.actively_exploited);
  const ransom    = pSignals.filter(s => s.known_ransomware);
  const kevBonus  = Math.min(25, directKEV.length * 8);
  const techBonus = Math.min(15, techExp.length * 5);
  const ransBonus = Math.min(10, ransom.length * 3);
  const score     = Math.min(100, Math.round(base + kevBonus + techBonus + ransBonus));
  const label     = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  const factors   = [];

  if (directKEV.length)
    factors.push({ type: 'DIRECT_CVE_HIT', count: directKEV.length, impact: kevBonus,
      detail: `${directKEV.length} watched CVE(s) actively exploited in the wild` });
  if (techExp.length)
    factors.push({ type: 'TECH_EXPOSURE', count: techExp.length, impact: techBonus,
      detail: `${techExp.length} exploited vulnerabilities affecting your registered technology stack` });
  if (ransom.length)
    factors.push({ type: 'RANSOMWARE_RISK', count: ransom.length, impact: ransBonus,
      detail: `${ransom.length} ransomware-linked signal(s) active in threat landscape` });
  if (pSignals.filter(s => s.actively_exploited).length)
    factors.push({ type: 'KEV_SIGNALS', count: pSignals.filter(s => s.actively_exploited).length, impact: 0,
      detail: `${pSignals.filter(s => s.actively_exploited).length} CISA KEV / confirmed exploit signal(s) in personalized radar` });

  return { score, label, base_score: base, factors };
}

// ── Recommended actions ───────────────────────────────────────────────────────
function buildRecs(orgRisk, pSignals, profile) {
  const acts = [];
  const directKEV = pSignals.filter(s => s.direct_hit && s.actively_exploited);
  const top = pSignals[0];
  const tech = safeJson(profile?.technology_stack);

  if (directKEV.length)
    acts.push({ priority: 'CRITICAL', action: `Immediate patch: ${directKEV.slice(0,3).map(s=>s.id).join(', ')} — actively exploited, in your CVE watchlist` });
  if (orgRisk.score >= 80) {
    acts.push({ priority: 'CRITICAL', action: 'Activate incident response plan — organization risk in CRITICAL range' });
    acts.push({ priority: 'CRITICAL', action: 'Initiate emergency CAB review for critical patches within 24 hours' });
  }
  if (pSignals.filter(s => s.actively_exploited).length > 5)
    acts.push({ priority: 'HIGH', action: 'Accelerate patch cycle — multiple KEV-listed vulnerabilities active in your threat profile' });
  if (pSignals.filter(s => s.known_ransomware).length) {
    acts.push({ priority: 'HIGH', action: 'Verify offline backup integrity and test restoration against current ransomware TTPs' });
    acts.push({ priority: 'HIGH', action: 'Review network segmentation to limit ransomware lateral movement paths' });
  }
  if (top?.threat_actor)
    acts.push({ priority: 'HIGH', action: `Threat actor ${top.threat_actor} active — review SIEM detection rules for their known ATT&CK techniques` });
  if (tech.length)
    acts.push({ priority: 'MEDIUM', action: `Review and patch technology stack: ${tech.slice(0,3).join(', ')} — verify all versions are current` });
  acts.push({ priority: 'MEDIUM', action: 'Validate MFA enforcement across all privileged accounts and external-facing services' });
  acts.push({ priority: 'MEDIUM', action: 'Review WAF and firewall rules — ensure coverage of active exploit patterns in current threat profile' });
  acts.push({ priority: 'LOW',    action: 'Schedule tabletop exercise against the top threat scenario in your personalized radar' });
  acts.push({ priority: 'LOW',    action: 'Update threat intelligence feeds and SIEM detection rules for newly identified TTPs' });

  return acts.slice(0, 10);
}

// ── P5.0-001 — GET /api/customer/profile ─────────────────────────────────────
export async function handleGetProfile(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;
  const cacheKey = `customer:profile:${targetId}`;

  if (kv) {
    try { const c = await kv.get(cacheKey, 'json'); if (c) return jsonOk({ profile: c, _cached: true, publisher: PUB }); } catch {}
  }

  await ensureTables(db);
  const row = await db.prepare('SELECT * FROM customer_profiles WHERE id = ?').bind(targetId).first().catch(() => null);

  const profile = row ? {
    id:                    row.id,
    org_id:                row.org_id || row.id,
    org_name:              row.org_name,
    industry:              row.industry,
    country:               row.country,
    org_size:              row.org_size,
    technology_stack:      safeJson(row.technology_stack),
    cloud_providers:       safeJson(row.cloud_providers),
    business_critical_assets: safeJson(row.business_critical_assets),
    created_at:            row.created_at,
    updated_at:            row.updated_at,
  } : {
    id: targetId, org_id: targetId, org_name: null, industry: null, country: null, org_size: null,
    technology_stack: [], cloud_providers: [], business_critical_assets: [], _new: true,
  };

  if (kv && !profile._new) {
    try { await kv.put(cacheKey, JSON.stringify(profile), { expirationTtl: KV_PROFILE_TTL }); } catch {}
  }

  return jsonOk({ profile, publisher: PUB });
}

// ── P5.0-001 — PUT /api/customer/profile ─────────────────────────────────────
export async function handleUpdateProfile(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;

  let body;
  try { body = await request.json(); } catch { return jsonErr('Invalid JSON body', 400); }

  const org_size = body.org_size && VALID_ORG_SIZES.includes(String(body.org_size).toUpperCase())
    ? String(body.org_size).toUpperCase() : null;

  await ensureTables(db);

  await db.prepare(`
    INSERT INTO customer_profiles (id, org_id, org_name, industry, country, org_size,
      technology_stack, cloud_providers, business_critical_assets, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET
      org_id = excluded.org_id, org_name = excluded.org_name, industry = excluded.industry,
      country = excluded.country, org_size = excluded.org_size,
      technology_stack = excluded.technology_stack, cloud_providers = excluded.cloud_providers,
      business_critical_assets = excluded.business_critical_assets,
      updated_at = datetime('now')
  `).bind(
    targetId,
    body.org_id || targetId,
    body.org_name || null,
    body.industry || null,
    body.country  || null,
    org_size,
    JSON.stringify(Array.isArray(body.technology_stack) ? body.technology_stack : []),
    JSON.stringify(Array.isArray(body.cloud_providers)  ? body.cloud_providers  : []),
    JSON.stringify(Array.isArray(body.business_critical_assets) ? body.business_critical_assets : []),
  ).run();

  if (kv) {
    try { await Promise.all([
      kv.delete(`customer:profile:${targetId}`),
      kv.delete(`customer:radar:${targetId}`),
      kv.delete(`customer:risk:${targetId}`),
    ]); } catch {}
  }

  return jsonOk({ success: true, id: targetId, publisher: PUB });
}

// ── P5.0-002 — GET /api/customer/radar ───────────────────────────────────────
export async function handleGetPersonalizedRadar(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const limit    = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 100);
  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;
  const cacheKey = `customer:radar:${targetId}`;

  if (kv) {
    try {
      const c = await kv.get(cacheKey, 'json');
      if (c) return jsonOk({ ...c, signals: (c.signals||[]).slice(0, limit), count: Math.min(c.signals?.length||0, limit), _cached: true });
    } catch {}
  }

  await ensureTables(db);

  const [profileRow, watchRows, techRows] = await Promise.all([
    db.prepare('SELECT * FROM customer_profiles WHERE id = ?').bind(targetId).first().catch(() => null),
    db.prepare(`SELECT asset_value FROM customer_assets WHERE owner_id = ? AND asset_type = 'cve_watchlist'`).bind(targetId).all().catch(() => ({ results: [] })),
    db.prepare(`SELECT asset_value FROM customer_assets WHERE owner_id = ? AND asset_type = 'technology'`).bind(targetId).all().catch(() => ({ results: [] })),
  ]);

  const profile = profileRow ? { ...profileRow, technology_stack: safeJson(profileRow.technology_stack) } : {};
  const watchCVEs = (watchRows.results || []).map(a => a.asset_value);
  const techStack = [...safeJson(profileRow?.technology_stack), ...(techRows.results || []).map(a => a.asset_value)];

  const svc     = new RadarService(env);
  const snap    = await svc.getEnterpriseSnapshot({ industry: profile.industry || null });
  const signals = snap.signals || [];
  const pers    = personalizeSignals(signals, profile, watchCVEs, techStack);

  const topSignals = pers.slice(0, limit).map(s => ({
    id: s.id, title: s.title, severity: s.severity, cvss: s.cvss, epss: s.epss,
    risk_score: s.risk_score, confidence: s.confidence,
    actively_exploited: s.actively_exploited, known_ransomware: s.known_ransomware,
    threat_actor: s.threat_actor, targeted_sectors: s.targeted_sectors,
    direct_hit: s.direct_hit, industry_match: s.industry_match, tech_match: s.tech_match,
    relevance_score: s.relevance_score, published_at: s.published_at,
  }));

  const result = {
    signals:           topSignals,
    total_in_pipeline: signals.length,
    direct_hits:       pers.filter(s => s.direct_hit).length,
    industry_matches:  pers.filter(s => s.industry_match).length,
    tech_matches:      pers.filter(s => s.tech_match).length,
    profile_industry:  profile.industry || null,
    watchlist_cve_count: watchCVEs.length,
    timestamp:         snap.timestamp,
    publisher:         PUB,
  };

  if (kv) {
    try { await kv.put(cacheKey, JSON.stringify({ ...result, signals: pers.slice(0, 100).map(s => ({
      id: s.id, title: s.title, severity: s.severity, cvss: s.cvss, epss: s.epss,
      risk_score: s.risk_score, confidence: s.confidence,
      actively_exploited: s.actively_exploited, known_ransomware: s.known_ransomware,
      threat_actor: s.threat_actor, targeted_sectors: s.targeted_sectors,
      direct_hit: s.direct_hit, industry_match: s.industry_match, tech_match: s.tech_match,
      relevance_score: s.relevance_score, published_at: s.published_at,
    })) }), { expirationTtl: KV_RADAR_TTL }); } catch {}
  }

  return jsonOk({ ...result, count: topSignals.length });
}

// ── P5.0-004 — GET /api/customer/risk ────────────────────────────────────────
export async function handleGetOrgRisk(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;
  const cacheKey = `customer:risk:${targetId}`;

  if (kv) {
    try { const c = await kv.get(cacheKey, 'json'); if (c) return jsonOk({ ...c, _cached: true }); } catch {}
  }

  await ensureTables(db);

  const [profileRow, watchRows, techRows] = await Promise.all([
    db.prepare('SELECT * FROM customer_profiles WHERE id = ?').bind(targetId).first().catch(() => null),
    db.prepare(`SELECT asset_value FROM customer_assets WHERE owner_id = ? AND asset_type = 'cve_watchlist'`).bind(targetId).all().catch(() => ({ results: [] })),
    db.prepare(`SELECT asset_value FROM customer_assets WHERE owner_id = ? AND asset_type = 'technology'`).bind(targetId).all().catch(() => ({ results: [] })),
  ]);

  const profile   = profileRow ? { ...profileRow, technology_stack: safeJson(profileRow.technology_stack) } : {};
  const watchCVEs = (watchRows.results || []).map(a => a.asset_value);
  const techStack = [...safeJson(profileRow?.technology_stack), ...(techRows.results || []).map(a => a.asset_value)];

  const svc  = new RadarService(env);
  const snap = await svc.getEnterpriseSnapshot({ industry: profile.industry || null });
  const pers = personalizeSignals(snap.signals || [], profile, watchCVEs, techStack);

  const orgRisk = computeOrgRisk(pers, watchCVEs);
  const recs    = buildRecs(orgRisk, pers, profile);

  const result = {
    org_risk:              orgRisk,
    recommendations:       recs,
    active_signals:        pers.filter(s => s.actively_exploited).length,
    watchlist_alerts:      pers.filter(s => s.direct_hit).length,
    total_personalized:    pers.length,
    severity_distribution: snap.severity_distribution,
    timestamp:             snap.timestamp,
    publisher:             PUB,
  };

  if (kv) {
    try { await kv.put(cacheKey, JSON.stringify(result), { expirationTtl: KV_RISK_TTL }); } catch {}
  }

  return jsonOk(result);
}

// ── P5.0-003 — GET /api/customer/assets ──────────────────────────────────────
export async function handleGetAssets(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const type = url.searchParams.get('type') || null;
  const db = env.SECURITY_HUB_DB;

  await ensureTables(db);

  const rows = type
    ? await db.prepare('SELECT * FROM customer_assets WHERE owner_id = ? AND asset_type = ? ORDER BY created_at DESC').bind(targetId, type).all().catch(() => ({ results: [] }))
    : await db.prepare('SELECT * FROM customer_assets WHERE owner_id = ? ORDER BY asset_type, created_at DESC').bind(targetId).all().catch(() => ({ results: [] }));

  const byType = {};
  for (const a of (rows.results || [])) {
    if (!byType[a.asset_type]) byType[a.asset_type] = [];
    byType[a.asset_type].push(a);
  }

  return jsonOk({ assets: rows.results || [], by_type: byType, count: (rows.results || []).length, publisher: PUB });
}

// ── P5.0-003 — POST /api/customer/assets ─────────────────────────────────────
export async function handleRegisterAsset(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;

  let body;
  try { body = await request.json(); } catch { return jsonErr('Invalid JSON body', 400); }

  const asset_type = (body.asset_type || '').toLowerCase();
  if (!VALID_ASSET_TYPES.includes(asset_type))
    return jsonErr(`asset_type must be one of: ${VALID_ASSET_TYPES.join(', ')}`, 400);
  if (!body.asset_value)
    return jsonErr('asset_value is required', 400);

  await ensureTables(db);

  const cnt = await db.prepare('SELECT COUNT(*) as c FROM customer_assets WHERE owner_id = ?').bind(targetId).first().catch(() => ({ c: 0 }));
  if ((cnt?.c || 0) >= ASSET_LIMIT)
    return jsonErr(`Asset limit (${ASSET_LIMIT}) reached. Contact support to expand.`, 429);

  const id = nid();
  await db.prepare('INSERT INTO customer_assets (id, owner_id, org_id, asset_type, asset_value, label) VALUES (?,?,?,?,?,?)')
    .bind(id, targetId, body.org_id || targetId, asset_type, String(body.asset_value).slice(0, 500), body.label || null)
    .run();

  if (kv) {
    try { await Promise.all([kv.delete(`customer:radar:${targetId}`), kv.delete(`customer:risk:${targetId}`)]); } catch {}
  }

  return jsonOk({ success: true, id, asset_type, asset_value: body.asset_value, publisher: PUB });
}

// ── P5.0-003 — DELETE /api/customer/assets/:id ───────────────────────────────
export async function handleDeleteAsset(request, env, authCtx, assetId) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;
  if (!assetId) return jsonErr('Asset ID required', 400);

  const url = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;

  await ensureTables(db);
  await db.prepare('DELETE FROM customer_assets WHERE id = ? AND owner_id = ?').bind(assetId, targetId).run().catch(() => null);

  if (kv) {
    try { await Promise.all([kv.delete(`customer:radar:${targetId}`), kv.delete(`customer:risk:${targetId}`)]); } catch {}
  }

  return jsonOk({ success: true, deleted: assetId, publisher: PUB });
}

// ── P5.0-006 — GET /api/customer/report ──────────────────────────────────────
export async function handleGetReport(request, env, authCtx) {
  const authErr = reqAuth(authCtx);
  if (authErr) return authErr;

  const url    = new URL(request.url);
  const { targetId } = tenantScope(authCtx, url);
  const fmt    = (url.searchParams.get('format') || 'json').toLowerCase();
  const db     = env.SECURITY_HUB_DB;

  await ensureTables(db);

  const [profileRow, assetRows] = await Promise.all([
    db.prepare('SELECT * FROM customer_profiles WHERE id = ?').bind(targetId).first().catch(() => null),
    db.prepare('SELECT * FROM customer_assets WHERE owner_id = ? ORDER BY asset_type').bind(targetId).all().catch(() => ({ results: [] })),
  ]);

  const profile  = profileRow ? { ...profileRow, technology_stack: safeJson(profileRow.technology_stack), cloud_providers: safeJson(profileRow.cloud_providers) } : { id: targetId };
  const allAssets = assetRows.results || [];
  const watchCVEs = allAssets.filter(a => a.asset_type === 'cve_watchlist').map(a => a.asset_value);
  const techStack = [...safeJson(profileRow?.technology_stack), ...allAssets.filter(a => a.asset_type === 'technology').map(a => a.asset_value)];

  const svc    = new RadarService(env);
  const snap   = await svc.getEnterpriseSnapshot({ industry: profile.industry || null });
  const pers   = personalizeSignals(snap.signals || [], profile, watchCVEs, techStack);
  const orgRisk = computeOrgRisk(pers, watchCVEs);
  const recs   = buildRecs(orgRisk, pers, profile);

  const activeKEV  = pers.filter(s => s.actively_exploited).slice(0, 5);
  const directHits = pers.filter(s => s.direct_hit);
  const campaigns  = [...new Set(pers.filter(s => s.campaign).map(s => s.campaign))].slice(0, 5);
  const actors     = [...new Set(pers.filter(s => s.threat_actor).map(s => s.threat_actor))].slice(0, 5);

  const report = {
    report_id:  `RPT-${Date.now()}`,
    generated_at: new Date().toISOString(),
    period:     'Current threat landscape',
    organization: {
      id:          targetId,
      name:        profile.org_name   || 'Your Organization',
      industry:    profile.industry   || 'Not specified',
      country:     profile.country    || 'Not specified',
      org_size:    profile.org_size   || 'Not specified',
      technology_stack: safeJson(profile.technology_stack),
      cloud_providers:  safeJson(profile.cloud_providers),
    },
    executive_summary: {
      organization_risk_score:      orgRisk.score,
      risk_label:                   orgRisk.label,
      total_signals:                pers.length,
      actively_exploited_signals:   activeKEV.length,
      direct_cve_hits:              directHits.length,
      headline: orgRisk.score >= 80
        ? `CRITICAL risk: immediate action required across ${orgRisk.factors.length} risk vector(s). ${directHits.length} watched CVE(s) are actively exploited.`
        : orgRisk.score >= 60
        ? `HIGH risk: ${activeKEV.length} actively-exploited vulnerabilities in your threat profile. Prioritize patching.`
        : orgRisk.score >= 40
        ? `MODERATE risk: ${directHits.length} watchlist CVE hit(s) detected. Continue accelerated patch cadence.`
        : 'LOW risk exposure. Maintain routine patch management and threat monitoring.',
    },
    threat_landscape: {
      severity_distribution: snap.severity_distribution,
      ai_threat_summary:     snap.ai_threat_summary,
      top_threat_actors:     actors,
      active_campaigns:      campaigns,
      top_actively_exploited: activeKEV.map(s => ({ id: s.id, title: s.title, severity: s.severity, cvss: s.cvss, risk_score: s.risk_score })),
    },
    organization_risk: {
      ...orgRisk,
      watchlist_cves:    watchCVEs,
      registered_assets: allAssets.length,
      direct_hits:       directHits.map(s => ({ id: s.id, title: s.title, severity: s.severity, risk_score: s.risk_score })),
    },
    recommended_actions: recs,
    publisher: PUB,
  };

  return fmt === 'html' ? htmlOk(buildReportHTML(report)) : jsonOk(report);
}

// ── HTML executive report ─────────────────────────────────────────────────────
function buildReportHTML(r) {
  const rc = r.executive_summary.risk_label === 'CRITICAL' ? '#ef4444'
    : r.executive_summary.risk_label === 'HIGH' ? '#f59e0b'
    : r.executive_summary.risk_label === 'MEDIUM' ? '#3b82f6' : '#10b981';
  const pc = p => p==='CRITICAL'?'#ef4444':p==='HIGH'?'#f59e0b':p==='MEDIUM'?'#3b82f6':'#10b981';
  const sc = s => s==='CRITICAL'?'badge-crit':s==='HIGH'?'badge-high':s==='MEDIUM'?'badge-med':'badge-low';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executive Threat Intelligence Report — ${r.organization.name}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#060614;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
.page{max-width:900px;margin:0 auto;padding:40px 32px}
h2{font-size:15px;font-weight:700;margin:28px 0 10px;padding-bottom:8px;border-bottom:1px solid #1a1a3e}
h3{font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.hdr{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;margin-bottom:24px;border-bottom:2px solid #1a1a3e;flex-wrap:wrap;gap:16px}
.brand{font-size:11px;color:#475569;text-align:right;font-family:monospace;line-height:1.8}
.h1{font-size:26px;font-weight:800;color:#fff;margin-bottom:6px}
.meta{font-size:11px;color:#64748b}
.kpi-row{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.kpi{background:#0c0c24;border:1px solid #1a1a3e;border-radius:10px;padding:14px 18px;flex:1;min-width:130px}
.kpi-l{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:#64748b;margin-bottom:4px}
.kpi-v{font-size:26px;font-weight:800;line-height:1}
.sec{background:#0c0c24;border:1px solid #1a1a3e;border-radius:10px;padding:18px;margin-bottom:14px}
.summary{background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.15);border-radius:8px;padding:14px;margin-bottom:18px;font-size:13px;color:#cbd5e1}
.bar-bg{background:rgba(255,255,255,.06);border-radius:6px;height:10px;margin:10px 0 14px}
.bar-fill{height:10px;border-radius:6px}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:10px;font-weight:700}
.badge-crit{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.badge-high{background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3)}
.badge-med{background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3)}
.badge-low{background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{font-size:10px;text-transform:uppercase;color:#475569;padding:6px 8px;border-bottom:1px solid #1a1a3e;text-align:left}
td{padding:7px 8px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle}
tr:last-child td{border-bottom:none}
.act-row{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04);align-items:flex-start}
.act-row:last-child{border-bottom:none}
.act-p{font-size:10px;font-weight:700;min-width:68px;padding:2px 6px;border-radius:4px;text-align:center}
.act-t{font-size:13px;color:#cbd5e1}
.factor{margin-top:8px;padding:10px;background:rgba(255,255,255,.03);border-radius:6px}
.factor-type{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;margin-bottom:3px}
.factor-detail{font-size:12px;color:#94a3b8}
.footer{margin-top:36px;padding-top:18px;border-top:1px solid #1a1a3e;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
@media print{body{background:#fff;color:#111}.sec,.kpi{background:#f9f9f9;border-color:#ddd}.kpi-v{color:#111}th,td{color:#111;border-color:#eee}.summary{background:#f0f9ff;border-color:#bcd}h2{border-color:#ddd}}
</style>
</head>
<body>
<div class="page">
  <div class="hdr">
    <div>
      <div class="h1">Executive Threat Intelligence Report</div>
      <div class="meta">${r.organization.name} &nbsp;·&nbsp; ${r.organization.industry} &nbsp;·&nbsp; ${r.organization.country}</div>
      <div class="meta" style="margin-top:4px">Generated: ${new Date(r.generated_at).toLocaleString('en-US',{dateStyle:'long',timeStyle:'short'})}</div>
    </div>
    <div class="brand">CYBERDUDEBIVASH®<br>SENTINEL APEX<br>${r.report_id}</div>
  </div>

  <div class="summary">${r.executive_summary.headline}</div>

  <div class="kpi-row">
    <div class="kpi"><div class="kpi-l">Org Risk Score</div><div class="kpi-v" style="color:${rc}">${r.executive_summary.organization_risk_score}</div><div style="font-size:10px;color:${rc};font-weight:700;margin-top:3px">${r.executive_summary.risk_label}</div></div>
    <div class="kpi"><div class="kpi-l">Total Signals</div><div class="kpi-v" style="color:#e2e8f0">${r.executive_summary.total_signals}</div><div class="meta">In threat profile</div></div>
    <div class="kpi"><div class="kpi-l">Actively Exploited</div><div class="kpi-v" style="color:#ef4444">${r.executive_summary.actively_exploited_signals}</div><div class="meta">KEV confirmed</div></div>
    <div class="kpi"><div class="kpi-l">CVE Watchlist Hits</div><div class="kpi-v" style="color:#f59e0b">${r.executive_summary.direct_cve_hits}</div><div class="meta">Direct matches</div></div>
  </div>

  <h2>Organization Risk</h2>
  <div class="sec">
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:8px">
      <span style="font-size:52px;font-weight:900;color:${rc};line-height:1">${r.organization_risk.score}</span>
      <div><span class="badge badge-${sc(r.executive_summary.risk_label)}">${r.executive_summary.risk_label}</span><div style="font-size:12px;color:#64748b;margin-top:6px">Composite score: CVSS×5 + EPSS×20 + KEV+15 + Ransomware+10 + exposure bonuses</div></div>
    </div>
    <div class="bar-bg"><div class="bar-fill" style="width:${r.organization_risk.score}%;background:${rc}"></div></div>
    ${r.organization_risk.factors.map(f=>`<div class="factor"><div class="factor-type" style="color:${pc(f.type.includes('DIRECT')||f.type.includes('KEV')?'CRITICAL':'HIGH')}">${f.type.replace(/_/g,' ')}${f.impact?` (+${f.impact} pts)`:''}</div><div class="factor-detail">${f.detail}</div></div>`).join('')}
    ${r.organization_risk.direct_hits.length?`<div style="margin-top:14px"><h3>Watchlist CVEs — Active in Wild</h3>
    <table><thead><tr><th>CVE / ID</th><th>Severity</th><th>Risk Score</th></tr></thead>
    <tbody>${r.organization_risk.direct_hits.map(h=>`<tr><td style="font-weight:600">${h.id}</td><td><span class="badge badge-${sc(h.severity)}">${h.severity}</span></td><td style="font-weight:700;color:${h.risk_score>=80?'#ef4444':h.risk_score>=60?'#f59e0b':'#3b82f6'}">${h.risk_score}</td></tr>`).join('')}
    </tbody></table></div>`:''}
  </div>

  <h2>Threat Landscape</h2>
  <div class="sec">
    <p style="color:#94a3b8;margin-bottom:14px;font-size:13px">${r.threat_landscape.ai_threat_summary}</p>
    ${r.threat_landscape.top_actively_exploited.length?`<h3>Active Exploits in Threat Profile</h3>
    <table><thead><tr><th>ID</th><th>Severity</th><th>CVSS</th><th>Risk</th></tr></thead>
    <tbody>${r.threat_landscape.top_actively_exploited.map(t=>`<tr><td style="font-weight:600">${t.id}</td><td><span class="badge badge-${sc(t.severity)}">${t.severity}</span></td><td>${(t.cvss||0).toFixed(1)}</td><td style="font-weight:700;color:${t.risk_score>=80?'#ef4444':t.risk_score>=60?'#f59e0b':'#3b82f6'}">${t.risk_score}</td></tr>`).join('')}
    </tbody></table>`:``}
    ${r.threat_landscape.top_threat_actors.length?`<div style="margin-top:14px"><h3>Threat Actors</h3><p style="font-size:13px;color:#94a3b8">${r.threat_landscape.top_threat_actors.join(', ')}</p></div>`:''}
    ${r.threat_landscape.active_campaigns.length?`<div style="margin-top:10px"><h3>Active Campaigns</h3><p style="font-size:13px;color:#94a3b8">${r.threat_landscape.active_campaigns.join(', ')}</p></div>`:''}
  </div>

  <h2>Recommended Actions</h2>
  <div class="sec">
    ${r.recommended_actions.map(a=>`<div class="act-row"><span class="act-p" style="background:${pc(a.priority)}22;color:${pc(a.priority)};border:1px solid ${pc(a.priority)}44">${a.priority}</span><span class="act-t">${a.action}</span></div>`).join('')}
  </div>

  <div class="footer">
    <span class="meta">CYBERDUDEBIVASH® Sentinel APEX Customer Intelligence · ${r.report_id}</span>
    <a href="https://cyberdudebivash.in/#pricing" style="color:#00d4ff;font-size:12px">Upgrade to Enterprise SOC →</a>
  </div>
</div>
</body>
</html>`;
}
