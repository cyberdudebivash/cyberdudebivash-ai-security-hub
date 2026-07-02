/**
 * CYBERDUDEBIVASH AI Security Hub — AI Security Decision Platform v1.0 (P11.0)
 *
 * Endpoints:
 *   GET  /api/decision/summary          — P11.1 full decision + correlation overview
 *   GET  /api/decision/actions          — P11.5 top-10 recommended actions for org
 *   GET  /api/decision/business-impact  — P11.3 5-dimension business impact scoring
 *   GET  /api/decision/priorities       — P11.2 P1/P2 priority queue with correlation
 *   GET  /api/decision/executive        — P11.6 per-role AI copilot summaries
 *
 * Reuses (NEVER duplicates):
 *   services/decisionEngine.js       — runDecisionEngine(), storeDecisions()
 *   core/adaptiveCyberBrain.js       — generateAdaptiveRecommendations()
 *   services/radarService.js         — RadarService.getTrending()
 *   services/compositeRiskScoring.js — scoreCVE(), analyzeRiskDistribution()
 *   core/mythosAIProvider.js         — callClaude()
 *
 * Performance:
 *   KV cache key: decision:v1:<endpoint>:<userId|platform>   TTL: 300s
 *   Target: <50ms (cache hit)  <400ms (uncached)
 *
 * Tier gate: PRO / ENTERPRISE / MSSP / OWNER / ADMIN
 */

import { runDecisionEngine, storeDecisions }          from '../services/decisionEngine.js';
import { generateAdaptiveRecommendations }             from '../core/adaptiveCyberBrain.js';
import { RadarService }                                from '../services/radarService.js';
import { scoreCVE, analyzeRiskDistribution }           from '../services/compositeRiskScoring.js';
import { callClaude }                                  from '../core/mythosAIProvider.js';
import { isRealUser } from '../auth/middleware.js';

// ─── Tier gate ────────────────────────────────────────────────────────────────
const ALLOWED_TIERS = new Set(['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN']);

function checkTier(authCtx) {
  if (!isRealUser(authCtx)) {
    return Response.json(
      { success: false, error: 'Authentication required — provide Authorization: Bearer <token>', service: 'CDB-DECISION' },
      { status: 401 }
    );
  }
  if (!ALLOWED_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'PRO plan or above required for AI Decision Platform', upgrade: 'https://tools.cyberdudebivash.com/#pricing', service: 'CDB-DECISION' },
      { status: 403 }
    );
  }
  return null;
}

// ─── KV cache helpers ─────────────────────────────────────────────────────────
const CACHE_TTL = 300; // 5 minutes

async function kvGet(env, key) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function kvSet(env, key, value) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(value), { expirationTtl: CACHE_TTL });
  } catch {}
}

function cacheKey(endpoint, userId) {
  return `decision:v1:${endpoint}:${userId || 'platform'}`;
}

// ─── Shared D1 data fetcher — all 5 endpoints use the same 3 parallel queries ─
async function fetchDecisionData(env, userId) {
  if (!env?.DB) return { vulnRows: [], assetRows: [], actorRows: [], asmRows: [] };

  const [vulnResult, assetResult, actorResult, asmResult] = await Promise.all([
    env.DB.prepare(`
      SELECT cve_id, title, cvss_score, epss_score, actively_exploited,
             known_ransomware, severity, source, mitre_technique, description
      FROM threat_intel
      WHERE severity IN ('CRITICAL','HIGH')
      ORDER BY cvss_score DESC LIMIT 30
    `).all().catch(() => ({ results: [] })),

    userId
      ? env.DB.prepare(`
          SELECT asset_value, asset_type
          FROM customer_assets
          WHERE owner_id = ? AND asset_type IN ('cve_watchlist','technology')
          LIMIT 50
        `).bind(userId).all().catch(() => ({ results: [] }))
      : Promise.resolve({ results: [] }),

    env.DB.prepare(`
      SELECT name, sector, active FROM threat_actors WHERE active = 1 LIMIT 20
    `).all().catch(() => ({ results: [] })),

    userId
      ? env.DB.prepare(`
          SELECT target, asm_score FROM asm_targets WHERE user_id = ? ORDER BY asm_score DESC LIMIT 10
        `).bind(userId).all().catch(() => ({ results: [] }))
      : Promise.resolve({ results: [] }),
  ]);

  return {
    vulnRows:  vulnResult.results  || [],
    assetRows: assetResult.results || [],
    actorRows: actorResult.results || [],
    asmRows:   asmResult.results   || [],
  };
}

// ─── Transform D1 rows into decisionEngine-compatible entries ─────────────────
function toDecisionEntries(vulnRows) {
  return vulnRows.map(r => ({
    id:                r.cve_id        || `UNKNOWN-${Math.random().toString(36).slice(2)}`,
    cvss:              r.cvss_score    || 0,
    epss_score:        r.epss_score    || 0,
    actively_exploited: !!(r.actively_exploited),
    known_ransomware:  !!(r.known_ransomware),
    exploit_status:    r.actively_exploited ? 'confirmed' : 'unconfirmed',
    source:            r.source        || 'nvd',
    severity:          r.severity      || 'HIGH',
    mitre_technique:   r.mitre_technique || null,
    title:             r.title         || r.cve_id || 'Unknown',
    description:       r.description   || null,
    tags:              '[]',
  }));
}

// ─── P11.3: Business Impact Scoring ──────────────────────────────────────────
// Pure deterministic function — no AI, no fabrication, reads only from real data.
function computeBusinessImpact(vulnRows, actorRows, assetRows, asmRows, sector = 'technology') {
  const kevCount   = vulnRows.filter(v => v.actively_exploited).length;
  const critCount  = vulnRows.filter(v => v.cvss_score >= 9).length;
  const ransomCount= vulnRows.filter(v => v.known_ransomware).length;
  const highEpss   = vulnRows.filter(v => v.epss_score > 0.5).length;
  const asmRisk    = asmRows.length > 0
    ? Math.round(asmRows.reduce((s, r) => s + (r.asm_score || 0), 0) / asmRows.length)
    : 0;

  // Sector risk multiplier
  const sectorMult = {
    finance: 1.4, healthcare: 1.35, government: 1.3, education: 1.1,
    retail: 1.15, energy: 1.45, manufacturing: 1.2, technology: 1.0,
  };
  const mult = sectorMult[sector.toLowerCase()] || 1.0;

  // Operational Risk: ASM exposure + KEV count
  const operational = Math.min(100, Math.round((asmRisk * 0.4 + kevCount * 12 + critCount * 5) * mult));

  // Financial Risk: ransomware links + critical CVEs
  const financial = Math.min(100, Math.round((ransomCount * 20 + critCount * 8 + highEpss * 6) * mult));

  // Compliance Risk: KEV is a mandate under CISA BOD 22-01, active APTs imply breach risk
  const activeActors = actorRows.filter(a => a.active).length;
  const compliance = Math.min(100, Math.round((kevCount * 15 + activeActors * 8 + critCount * 4) * mult));

  // Service Risk: external attack surface + EPSS
  const service = Math.min(100, Math.round((asmRisk * 0.5 + highEpss * 10 + kevCount * 8) * mult));

  // Reputation Risk: publicly known exploited CVEs
  const reputation = Math.min(100, Math.round((kevCount * 10 + ransomCount * 15 + activeActors * 5) * mult));

  const overall = Math.round((operational + financial + compliance + service + reputation) / 5);
  const rating  = overall >= 75 ? 'CRITICAL' : overall >= 55 ? 'HIGH' : overall >= 35 ? 'MEDIUM' : 'LOW';

  return {
    overall_score:  overall,
    overall_rating: rating,
    dimensions: {
      operational: { score: operational, label: 'Operational Risk',  drivers: ['Attack surface exposure', 'KEV vulnerabilities', 'Critical CVEs'] },
      financial:   { score: financial,   label: 'Financial Risk',    drivers: ['Ransomware associations', 'Critical vulnerability count', 'High exploitation probability'] },
      compliance:  { score: compliance,  label: 'Compliance Risk',   drivers: ['CISA KEV mandate (BOD 22-01)', 'Active APT attribution', 'Unpatched critical CVEs'] },
      service:     { score: service,     label: 'Service Risk',      drivers: ['External attack surface', 'High-EPSS vulnerabilities', 'Active KEV exploitation'] },
      reputation:  { score: reputation,  label: 'Reputation Risk',   drivers: ['Publicly exploited CVEs', 'Ransomware campaign links', 'Active threat actor targeting'] },
    },
    sector_multiplier: mult,
    data_basis: {
      kev_count:    kevCount,
      critical_cves: critCount,
      ransomware_linked: ransomCount,
      high_epss:    highEpss,
      active_actors: activeActors,
      asm_avg_score: asmRisk,
    },
  };
}

// ─── P11.2: Correlation summary (lightweight — reuses in-memory data, not graphEngine) ─
function buildCorrelationSummary(vulnRows, actorRows, assetRows) {
  const watchedCves = assetRows
    .filter(a => a.asset_type === 'cve_watchlist')
    .map(a => a.asset_value);

  const correlatedVulns = vulnRows.filter(v =>
    watchedCves.includes(v.cve_id) || v.actively_exploited || v.known_ransomware
  );

  // Group by MITRE technique
  const mitreMap = {};
  for (const v of vulnRows) {
    if (v.mitre_technique) {
      mitreMap[v.mitre_technique] = (mitreMap[v.mitre_technique] || 0) + 1;
    }
  }
  const topMitre = Object.entries(mitreMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([id, count]) => ({ technique_id: id, cve_count: count }));

  // Asset overlap
  const techStack = assetRows.filter(a => a.asset_type === 'technology').map(a => a.asset_value);

  return {
    correlated_cves:    correlatedVulns.map(v => v.cve_id).filter(Boolean).slice(0, 10),
    correlated_cve_count: correlatedVulns.length,
    active_actor_count: actorRows.length,
    top_mitre_techniques: topMitre,
    customer_watchlist_matches: watchedCves.length,
    exposed_tech_stack: techStack.slice(0, 10),
    correlation_confidence: correlatedVulns.length > 0 ? 'HIGH' : watchedCves.length > 0 ? 'MEDIUM' : 'LOW',
    note: correlatedVulns.length === 0
      ? 'Register assets at POST /api/customer/assets for personalized correlation'
      : null,
  };
}

// ─── Radar signals (best-effort — empty on failure) ──────────────────────────
async function fetchRadarSignals(env) {
  try {
    const svc = new RadarService(env);
    return (await svc.getTrending({ limit: 10 })) || [];
  } catch { return []; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 1: GET /api/decision/summary  — P11.1
// Full decision overview: decisions + correlation + business impact + actions
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleDecisionSummary(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx?.userId ?? authCtx?.user_id ?? null;
  const ck = cacheKey('summary', userId);
  const hit = await kvGet(env, ck);
  if (hit) return Response.json({ ...hit, _cache: 'HIT' });

  const url    = new URL(request.url);
  const sector = url.searchParams.get('sector') || 'technology';

  const { vulnRows, assetRows, actorRows, asmRows } = await fetchDecisionData(env, userId);
  const entries   = toDecisionEntries(vulnRows);
  const result    = runDecisionEngine(entries);
  const impact    = computeBusinessImpact(vulnRows, actorRows, assetRows, asmRows, sector);
  const corr      = buildCorrelationSummary(vulnRows, actorRows, assetRows);
  const radar     = await fetchRadarSignals(env);

  // Adaptive recommendations (reuse P10.6 engine)
  const watchedCves = assetRows.filter(a => a.asset_type === 'cve_watchlist').map(a => a.asset_value);
  const vulns = vulnRows.map(r => ({
    cve_id: r.cve_id, cvss: r.cvss_score, epss: r.epss_score,
    in_kev: !!(r.actively_exploited), title: r.title,
  }));
  const findings = vulnRows
    .filter(v => watchedCves.includes(v.cve_id) || v.actively_exploited)
    .slice(0, 8)
    .map(v => ({
      severity: v.cvss_score >= 9 ? 'CRITICAL' : 'HIGH',
      title: v.title || v.cve_id,
      description: v.description || `CVSS ${v.cvss_score}`,
      remediation: `Apply vendor patch for ${v.cve_id}`,
      category: v.actively_exploited ? 'kev_exploit' : 'vulnerability',
    }));
  const adaptive = await generateAdaptiveRecommendations(env, {
    findings: findings.length ? findings : vulnRows.filter(v => v.cvss_score >= 9).slice(0, 5).map(v => ({
      severity: 'CRITICAL', title: v.title || v.cve_id, description: v.description || `CVSS ${v.cvss_score}`,
      remediation: `Apply vendor patch for ${v.cve_id}`, category: 'vulnerability',
    })),
    vulns: vulns.slice(0, 15),
    adaptiveScore: impact.overall_score,
    attackChains: [],
    sector,
    tier: authCtx.tier || 'PRO',
    userId,
  });

  const body = {
    success:              true,
    service:              'CDB-DECISION-SUMMARY',
    generated_at:         new Date().toISOString(),
    overall_threat_level: result.overall_threat_level,
    decision_counts: {
      p1_critical:   result.p1_count,
      p2_high:       result.p2_count,
      total:         result.total,
      escalation_required: result.escalation_required,
    },
    business_impact:      impact,
    correlation:          corr,
    top_decisions:        (result.decisions || []).slice(0, 5),
    top_actions:          (adaptive.actions  || []).slice(0, 5),
    quick_wins:           adaptive.quick_wins || [],
    radar_signals:        radar.length,
    data_sources: [
      'Sentinel APEX Threat Intelligence',
      'CISA KEV', 'NVD', 'Cyber Signal Radar',
      'Customer Asset Registry', 'Attack Surface Monitor',
    ],
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P11.0 Decision Platform',
  };

  await kvSet(env, ck, body);
  return Response.json(body);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 2: GET /api/decision/actions  — P11.5
// Top-10 prioritized recommended actions for this org
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleDecisionActions(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx?.userId ?? authCtx?.user_id ?? null;
  const ck = cacheKey('actions', userId);
  const hit = await kvGet(env, ck);
  if (hit) return Response.json({ ...hit, _cache: 'HIT' });

  const url    = new URL(request.url);
  const sector = url.searchParams.get('sector') || 'technology';

  const { vulnRows, assetRows, asmRows, actorRows } = await fetchDecisionData(env, userId);
  const entries = toDecisionEntries(vulnRows);
  const result  = runDecisionEngine(entries);
  const impact  = computeBusinessImpact(vulnRows, actorRows, assetRows, asmRows, sector);

  const vulns = vulnRows.map(r => ({
    cve_id: r.cve_id, cvss: r.cvss_score, epss: r.epss_score,
    in_kev: !!(r.actively_exploited), title: r.title,
  }));
  const findings = vulnRows.filter(v => v.actively_exploited || v.cvss_score >= 9).slice(0, 8).map(v => ({
    severity: v.cvss_score >= 9 ? 'CRITICAL' : 'HIGH',
    title: v.title || v.cve_id,
    description: v.description || `CVE CVSS ${v.cvss_score}`,
    remediation: `Apply vendor patch for ${v.cve_id}`,
    category: v.actively_exploited ? 'kev_exploit' : 'vulnerability',
  }));

  const adaptive = await generateAdaptiveRecommendations(env, {
    findings,
    vulns: vulns.slice(0, 15),
    adaptiveScore: impact.overall_score,
    attackChains: [],
    sector,
    tier: authCtx.tier || 'PRO',
    userId,
  });

  const asmAssets = asmRows.map(r => r.target).filter(Boolean);
  const techStack = assetRows.filter(a => a.asset_type === 'technology').map(a => a.asset_value);

  // Merge decision engine actions + adaptive recommendations
  const decisionActions = (result.decisions || [])
    .filter(d => ['P1-CRITICAL', 'P2-HIGH'].includes(d.priority))
    .slice(0, 5)
    .map((d, i) => ({
      rank:              i + 1,
      source:            'decision_engine',
      title:             `${d.decision.replace(/_/g,' ').toUpperCase()}: ${d.cve_id}`,
      detail:            d.reason,
      priority:          d.priority,
      urgency:           d.priority === 'P1-CRITICAL' ? 'IMMEDIATE' : 'WITHIN_24H',
      confidence:        d.confidence,
      cve_id:            d.cve_id,
      risk_score:        d.risk_score,
      actions:           d.actions_recommended || [],
      affected_assets:   asmAssets.slice(0, 3).length > 0 ? asmAssets.slice(0, 3) : ['Register assets for asset-specific guidance'],
    }));

  const brainActions = (adaptive.actions || []).slice(0, 5).map((a, i) => ({
    rank:            decisionActions.length + i + 1,
    source:          'adaptive_brain',
    title:           a.title,
    detail:          a.detail || a.title,
    priority:        a.priority === 1 ? 'P1-CRITICAL' : a.priority === 2 ? 'P2-HIGH' : 'P3-MEDIUM',
    urgency:         a.urgency,
    confidence:      'MEDIUM',
    cve_id:          a.cve || null,
    risk_score:      null,
    actions:         [],
    affected_assets: techStack.slice(0, 3),
  }));

  const allActions = [...decisionActions, ...brainActions].slice(0, 10);

  const body = {
    success:         true,
    service:         'CDB-DECISION-ACTIONS',
    generated_at:    new Date().toISOString(),
    total_actions:   allActions.length,
    actions:         allActions,
    soc_playbook:    adaptive.soc_playbook,
    quick_wins:      adaptive.quick_wins || [],
    estimated_total_effort: adaptive.estimated_total_effort,
    powered_by:      'CYBERDUDEBIVASH SENTINEL APEX AI — P11.0',
  };

  await kvSet(env, ck, body);
  return Response.json(body);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 3: GET /api/decision/business-impact  — P11.3
// 5-dimension business impact assessment
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleDecisionBusinessImpact(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx?.userId ?? authCtx?.user_id ?? null;
  const url    = new URL(request.url);
  const sector = url.searchParams.get('sector') || 'technology';
  const ck = cacheKey(`biz-impact:${sector}`, userId);
  const hit = await kvGet(env, ck);
  if (hit) return Response.json({ ...hit, _cache: 'HIT' });

  const { vulnRows, assetRows, actorRows, asmRows } = await fetchDecisionData(env, userId);
  const impact = computeBusinessImpact(vulnRows, actorRows, assetRows, asmRows, sector);

  // Composite risk distribution from scoring engine
  const scored = vulnRows.map(r => scoreCVE(r, r.epss_score));
  const distribution = analyzeRiskDistribution(scored);

  const body = {
    success:          true,
    service:          'CDB-DECISION-BIZ-IMPACT',
    generated_at:     new Date().toISOString(),
    sector,
    business_impact:  impact,
    risk_distribution: distribution,
    mitigations: {
      immediate: impact.overall_score >= 75
        ? ['Activate incident response plan', 'Brief CISO and board within 4 hours', 'Initiate emergency patch cycle']
        : impact.overall_score >= 55
        ? ['Accelerate patch cycle for KEV vulnerabilities', 'Review external attack surface', 'Update threat model']
        : ['Continue standard patch cadence', 'Monitor CISA KEV for new additions', 'Quarterly risk review'],
      note: 'These are recommendations only — no automated actions are taken',
    },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P11.0',
  };

  await kvSet(env, ck, body);
  return Response.json(body);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 4: GET /api/decision/priorities  — P11.2
// P1/P2 priority queue with threat correlation
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleDecisionPriorities(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx?.userId ?? authCtx?.user_id ?? null;
  const ck = cacheKey('priorities', userId);
  const hit = await kvGet(env, ck);
  if (hit) return Response.json({ ...hit, _cache: 'HIT' });

  const { vulnRows, assetRows, actorRows, asmRows } = await fetchDecisionData(env, userId);
  const entries = toDecisionEntries(vulnRows);
  const result  = runDecisionEngine(entries);
  const corr    = buildCorrelationSummary(vulnRows, actorRows, assetRows);

  const p1 = (result.decisions || []).filter(d => d.priority === 'P1-CRITICAL');
  const p2 = (result.decisions || []).filter(d => d.priority === 'P2-HIGH');

  // Store P1/P2 decisions in D1 (fire-and-forget)
  if (result.decisions?.length) {
    storeDecisions(env, result).catch(() => {});
  }

  const body = {
    success:       true,
    service:       'CDB-DECISION-PRIORITIES',
    generated_at:  new Date().toISOString(),
    summary: {
      overall_threat_level: result.overall_threat_level,
      p1_count:  p1.length,
      p2_count:  p2.length,
      total:     result.total,
      escalation_required: result.escalation_required,
    },
    p1_critical: p1.slice(0, 10),
    p2_high:     p2.slice(0, 10),
    correlation:  corr,
    by_decision:  result.by_decision || {},
    powered_by:   'CYBERDUDEBIVASH SENTINEL APEX AI — P11.0',
  };

  await kvSet(env, ck, body);
  return Response.json(body);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 5: GET /api/decision/executive  — P11.6
// AI-generated per-role executive copilot summaries
// Roles: CEO, CISO, SOC, Board, Compliance, Operations
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleDecisionExecutive(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx?.userId ?? authCtx?.user_id ?? null;
  const url    = new URL(request.url);
  const role   = (url.searchParams.get('role') || 'ciso').toLowerCase();
  const sector = url.searchParams.get('sector') || 'technology';

  const VALID_ROLES = new Set(['ceo', 'ciso', 'soc', 'board', 'compliance', 'operations']);
  const effectiveRole = VALID_ROLES.has(role) ? role : 'ciso';

  const ck = cacheKey(`executive:${effectiveRole}:${sector}`, userId);
  const hit = await kvGet(env, ck);
  if (hit) return Response.json({ ...hit, _cache: 'HIT' });

  const { vulnRows, assetRows, actorRows, asmRows } = await fetchDecisionData(env, userId);
  const entries = toDecisionEntries(vulnRows);
  const result  = runDecisionEngine(entries);
  const impact  = computeBusinessImpact(vulnRows, actorRows, assetRows, asmRows, sector);

  const kevCount  = vulnRows.filter(v => v.actively_exploited).length;
  const critCount = vulnRows.filter(v => v.cvss_score >= 9).length;
  const p1Count   = result.p1_count || 0;

  // Role-specific prompt templates
  const ROLE_PROMPTS = {
    ceo: `You are the AI security advisor to the CEO. Write a 3-sentence executive summary about the company's current cybersecurity risk posture. Data: Business impact score ${impact.overall_score}/100 (${impact.overall_rating}), ${kevCount} actively exploited vulnerabilities, ${critCount} critical CVEs, ${actorRows.length} active threat actor groups targeting ${sector} sector. Focus on business continuity risk and resource decisions. No technical jargon.`,

    ciso: `Write a CISO-level security briefing in 4 sentences. Data: Overall threat level ${result.overall_threat_level}, ${p1Count} P1-critical decisions requiring immediate action, ${kevCount} CISA KEV vulnerabilities, ${critCount} critical CVEs. Compliance impact score: ${impact.dimensions.compliance.score}/100. Operational risk: ${impact.dimensions.operational.score}/100. Include remediation priority and team action guidance.`,

    soc: `Write a SOC team morning briefing in 3 sentences. Data: ${p1Count} P1 escalation items, ${result.p2_count} P2 high-priority patches, ${kevCount} actively exploited CVEs requiring immediate patch, ${actorRows.length} active threat actors tracked. Focus on triage priority and detection actions.`,

    board: `Write a 3-sentence board-level cybersecurity update. Data: Business impact score ${impact.overall_score}/100, financial risk ${impact.dimensions.financial.score}/100, compliance risk ${impact.dimensions.compliance.score}/100, reputation risk ${impact.dimensions.reputation.score}/100. Sector: ${sector}. Frame risk in business continuity and regulatory terms. Suggest one board resolution.`,

    compliance: `Write a 3-sentence compliance and regulatory risk summary. Data: ${kevCount} CISA KEV vulnerabilities (BOD 22-01 mandatory patch), compliance impact score ${impact.dimensions.compliance.score}/100, ${actorRows.length} active APT groups. Cover NIST CSF, ISO 27001, and sector-specific regulatory exposure in ${sector}.`,

    operations: `Write a 3-sentence operational security status briefing. Data: Service risk ${impact.dimensions.service.score}/100, ${asmRows.length} attack surface targets monitored, ${vulnRows.length} vulnerabilities in scope, ${kevCount} requiring emergency patch. Focus on service continuity, change management, and patch deployment timeline.`,
  };

  let aiSummary = null;
  try {
    const aiResult = await callClaude(env, {
      prompt: ROLE_PROMPTS[effectiveRole],
      tier:   authCtx.tier || 'PRO',
      max_tokens: 300,
      temperature: 0.3,
    });
    aiSummary = aiResult?.content?.trim() || null;
  } catch {}

  // Fallback summary if AI unavailable
  if (!aiSummary) {
    aiSummary = `Current threat level: ${result.overall_threat_level}. Business impact score: ${impact.overall_score}/100 (${impact.overall_rating}). ${kevCount} actively exploited vulnerabilities require immediate attention.`;
  }

  const body = {
    success:         true,
    service:         'CDB-DECISION-EXECUTIVE',
    generated_at:    new Date().toISOString(),
    role:            effectiveRole,
    sector,
    summary:         aiSummary,
    key_metrics: {
      threat_level:   result.overall_threat_level,
      business_impact: impact.overall_score,
      p1_actions:     p1Count,
      kev_count:      kevCount,
      critical_cves:  critCount,
      active_actors:  actorRows.length,
    },
    dimensions:      impact.dimensions,
    available_roles: ['ceo', 'ciso', 'soc', 'board', 'compliance', 'operations'],
    powered_by:      'CYBERDUDEBIVASH SENTINEL APEX AI — P11.0',
  };

  await kvSet(env, ck, body);
  return Response.json(body);
}
