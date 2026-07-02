/**
 * CYBERDUDEBIVASH AI Security Hub — P12.0 Enterprise AI SOC Command Platform
 *
 * Endpoints:
 *   GET /api/soc/command/state        — P12.1 unified SOC command state
 *   GET /api/soc/command/copilot      — P12.5 SOC copilot (analysis + guidance)
 *   GET /api/soc/command/workflow     — P12.6 workflow + SLA queue
 *   GET /api/soc/command/observability — P12.8 latency + cache hit metrics
 *   GET /api/soc/stream               — P12.4 unified real-time SSE event stream
 *
 * Reuses (NEVER duplicates):
 *   core/adaptiveCyberBrain.js  — generateAdaptiveRecommendations()
 *   core/mythosAIProvider.js    — callClaude()
 *   services/radarService.js    — RadarService
 *   handlers/socInvestigations.js — D1 tables (soc_cases, soc_decisions, soc_timeline)
 *
 * Performance:
 *   KV prefix: soc:v1:<endpoint>:<userId>  TTL: 300s (state), 120s (copilot)
 *   Target: <50ms cache hit  <400ms uncached
 *
 * Tier gate: PRO / ENTERPRISE / MSSP / OWNER / ADMIN
 */

import { generateAdaptiveRecommendations } from '../core/adaptiveCyberBrain.js';
import { callClaude }                      from '../core/mythosAIProvider.js';
import { RadarService }                    from '../services/radarService.js';
import { isRealUser } from '../auth/middleware.js';

// ─── Tier gate ────────────────────────────────────────────────────────────────
const ALLOWED_TIERS = new Set(['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN']);

function checkTier(authCtx) {
  if (!isRealUser(authCtx)) {
    return Response.json(
      { success: false, error: 'Authentication required', service: 'CDB-SOC-COMMAND' },
      { status: 401 }
    );
  }
  if (!ALLOWED_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'PRO plan or above required for AI SOC Command Platform', upgrade: 'https://tools.cyberdudebivash.com/#pricing', service: 'CDB-SOC-COMMAND' },
      { status: 403 }
    );
  }
  return null;
}

// ─── KV cache helpers ─────────────────────────────────────────────────────────
async function kvGet(env, key) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function kvSet(env, key, value, ttl = 300) {
  if (!env?.SECURITY_HUB_KV) return;
  try { await env.SECURITY_HUB_KV.put(key, JSON.stringify(value), { expirationTtl: ttl }); }
  catch {}
}

function cacheKey(endpoint, userId) {
  return `soc:v1:${endpoint}:${userId || 'platform'}`;
}

// ─── Shared D1 fetcher ────────────────────────────────────────────────────────
async function fetchSOCData(env, userId) {
  if (!env?.DB) {
    return { vulnRows: [], actorRows: [], assetRows: [], asmRows: [], caseRows: [], decisionRows: [] };
  }
  const db = env.DB;
  try {
    const [tiRes, actorRes, assetRes, asmRes, caseRes, decRes] = await Promise.all([
      db.prepare(
        `SELECT cve_id, title, cvss_score, epss_score, actively_exploited, known_ransomware,
                severity, source, mitre_technique, description
         FROM threat_intel ORDER BY cvss_score DESC LIMIT 100`
      ).all().catch(() => ({ results: [] })),
      db.prepare(
        `SELECT name, sector, active FROM threat_actors LIMIT 50`
      ).all().catch(() => ({ results: [] })),
      db.prepare(
        `SELECT asset_value, asset_type FROM customer_assets LIMIT 100`
      ).all().catch(() => ({ results: [] })),
      db.prepare(
        `SELECT target, asm_score FROM asm_targets LIMIT 50`
      ).all().catch(() => ({ results: [] })),
      db.prepare(
        `SELECT id, case_number, title, severity, status, assignee_id, sla_due_at,
                mitre_tactics, created_at, updated_at
         FROM soc_cases WHERE status NOT IN ('RESOLVED','CLOSED')
         ORDER BY severity DESC, created_at DESC LIMIT 50`
      ).all().catch(() => ({ results: [] })),
      db.prepare(
        `SELECT id, cve_id, decision, priority, confidence, risk_score, reason, created_at
         FROM soc_decisions ORDER BY created_at DESC LIMIT 50`
      ).all().catch(() => ({ results: [] })),
    ]);
    return {
      vulnRows:     tiRes.results    || [],
      actorRows:    actorRes.results || [],
      assetRows:    assetRes.results || [],
      asmRows:      asmRes.results   || [],
      caseRows:     caseRes.results  || [],
      decisionRows: decRes.results   || [],
    };
  } catch { return { vulnRows: [], actorRows: [], assetRows: [], asmRows: [], caseRows: [], decisionRows: [] }; }
}

// ─── P12.1 — SOC COMMAND STATE ────────────────────────────────────────────────
export async function handleSOCCommandState(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const ck     = cacheKey('command_state', userId);
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const t0 = Date.now();
  const { vulnRows, actorRows, assetRows, asmRows, caseRows, decisionRows } = await fetchSOCData(env, userId);

  const critVulns    = vulnRows.filter(r => r.cvss_score >= 9);
  const kevVulns     = vulnRows.filter(r => r.actively_exploited);
  const activeActors = actorRows.filter(r => r.active);
  const openCases    = caseRows.filter(r => ['OPEN','IN_PROGRESS','ESCALATED'].includes(r.status));
  const critCases    = caseRows.filter(r => r.severity === 'CRITICAL');
  const escalatedCases = caseRows.filter(r => r.status === 'ESCALATED');
  const slaBreached  = caseRows.filter(r => r.sla_due_at && new Date(r.sla_due_at) < new Date());
  const p1Decisions  = decisionRows.filter(r => r.priority === 'P1-CRITICAL');

  // Threat level (same thresholds as decisionHandler)
  const kevCount  = kevVulns.length;
  const critCount = critVulns.length;
  let threatLevel = 'NOMINAL';
  let threatScore = 10;
  if (kevCount > 50 || critCount > 100) { threatLevel = 'CRITICAL'; threatScore = 95; }
  else if (kevCount > 20 || critCount > 50) { threatLevel = 'HIGH';  threatScore = 75; }
  else if (kevCount > 5  || critCount > 20) { threatLevel = 'ELEVATED'; threatScore = 50; }
  else if (kevCount > 0  || critCount > 0)  { threatLevel = 'GUARDED'; threatScore = 30; }

  // Radar status (best-effort — never fail)
  let radarStatus = null;
  try {
    const rs = new RadarService(env);
    radarStatus = await rs.getStatus?.() ?? null;
  } catch {}

  const body = {
    success:      true,
    service:      'CDB-SOC-COMMAND',
    generated_at: new Date().toISOString(),
    soc_state: {
      threat_level:    threatLevel,
      threat_score:    threatScore,
      active_cases:    openCases.length,
      critical_cases:  critCases.length,
      escalated_cases: escalatedCases.length,
      sla_breached:    slaBreached.length,
      active_actors:   activeActors.length,
      p1_decisions:    p1Decisions.length,
      kev_count:       kevCount,
      high_severity:   vulnRows.filter(r => r.cvss_score >= 7).length,
    },
    case_queue: {
      open:      openCases.length,
      escalated: escalatedCases.length,
      sla_at_risk: slaBreached.length,
      top_cases: openCases.slice(0, 5).map(c => ({
        id:       c.id,
        title:    c.title,
        severity: c.severity,
        status:   c.status,
        sla_due_at: c.sla_due_at || null,
      })),
    },
    threat_summary: {
      critical_cves:  critVulns.slice(0, 5).map(v => ({ cve_id: v.cve_id, cvss: v.cvss_score, kev: Boolean(v.actively_exploited) })),
      kev_count:      kevCount,
      active_actors:  activeActors.length,
      ransomware_cvEs: vulnRows.filter(r => r.known_ransomware).length,
    },
    automation_status: {
      p1_decisions:     p1Decisions.length,
      total_decisions:  decisionRows.length,
      recent_decisions: decisionRows.slice(0, 5).map(d => ({
        id:       d.id,
        cve_id:   d.cve_id,
        decision: d.decision,
        priority: d.priority,
        created_at: d.created_at,
      })),
    },
    attack_surface: {
      monitored_targets: asmRows.length,
      avg_asm_score: asmRows.length
        ? Math.round(asmRows.reduce((s, r) => s + (r.asm_score || 0), 0) / asmRows.length)
        : 0,
    },
    radar_status: radarStatus,
    data_sources: ['threat_intel', 'soc_cases', 'soc_decisions', 'threat_actors', 'customer_assets', 'asm_targets'],
    latency_ms: Date.now() - t0,
  };

  await kvSet(env, ck, body, 300);
  return Response.json(body);
}

// ─── P12.5 — SOC COPILOT ─────────────────────────────────────────────────────
export async function handleSOCCopilot(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const url    = new URL(request.url);
  const role   = url.searchParams.get('role') || 'soc';
  const ck     = cacheKey(`copilot_${role}`, userId);
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const { vulnRows, actorRows, assetRows, caseRows, decisionRows } = await fetchSOCData(env, userId);

  // Build adaptive context for recommendation engine
  const vulns = vulnRows.map(r => ({
    cve_id:   r.cve_id,
    cvss:     r.cvss_score,
    epss:     r.epss_score,
    in_kev:   Boolean(r.actively_exploited),
    severity: r.severity,
    title:    r.title,
    mitre:    r.mitre_technique,
  }));

  const findings = assetRows.filter(a => a.asset_type === 'cve_watchlist').map(a => ({
    title:    a.asset_value,
    severity: 'HIGH',
    category: 'watchlist',
  }));

  const adaptive = await generateAdaptiveRecommendations(env, {
    findings,
    vulns,
    adaptiveScore: Math.min(100, vulns.length * 5),
    attackChains:  [],
    sector:        'technology',
    tier:          authCtx.tier || 'PRO',
    userId,
  });

  const actions      = adaptive.actions || [];
  const critCount    = vulnRows.filter(r => r.cvss_score >= 9).length;
  const kevCount     = vulnRows.filter(r => r.actively_exploited).length;
  const openCases    = caseRows.filter(r => ['OPEN','IN_PROGRESS','ESCALATED'].includes(r.status));
  const slaBreached  = caseRows.filter(r => r.sla_due_at && new Date(r.sla_due_at) < new Date());
  const p1Actions    = actions.filter(a => a.urgency === 'IMMEDIATE' || a.priority === 1);

  // Deterministic guidance sections from real data
  const containmentSteps = [
    ...p1Actions.slice(0, 3).map((a, i) => ({ step: i + 1, action: a.title, urgency: a.urgency || 'HIGH', effort: a.effort || 'TBD' })),
    ...(kevCount > 0 ? [{ step: p1Actions.length + 1, action: `Apply emergency patches for ${kevCount} CISA KEV vulnerability${kevCount > 1 ? 'ies' : 'y'}`, urgency: 'IMMEDIATE', effort: '2–4h' }] : []),
  ].slice(0, 5);

  const recoveryPlan = actions.filter(a => a.priority >= 2 && a.priority <= 4).slice(0, 4).map((a, i) => ({
    phase: i + 1,
    action: a.title,
    timeline: a.effort || '1 week',
    impact: a.impact || 'HIGH',
  }));

  const escalationReason = slaBreached.length > 0
    ? `${slaBreached.length} case${slaBreached.length > 1 ? 's have' : ' has'} breached SLA — immediate escalation required.`
    : openCases.filter(c => c.severity === 'CRITICAL').length > 0
      ? `${openCases.filter(c => c.severity === 'CRITICAL').length} critical case${openCases.filter(c => c.severity === 'CRITICAL').length > 1 ? 's are' : ' is'} open — senior analyst review recommended.`
      : 'No immediate escalation required. Continue routine monitoring.';

  // Deterministic fallback summaries
  let socSummary = `Threat level: ${critCount > 10 ? 'HIGH' : critCount > 0 ? 'ELEVATED' : 'NOMINAL'}. ${critCount} critical CVEs, ${kevCount} actively exploited, ${openCases.length} active cases.`;
  let analystGuidance = `Focus on ${p1Actions.length > 0 ? `${p1Actions.length} immediate-priority action${p1Actions.length > 1 ? 's' : ''}` : 'routine monitoring'}. ${kevCount > 0 ? `CISA KEV remediation deadline is 24h.` : ''}`;

  // Attempt AI narrative enrichment (never fail)
  try {
    const prompt = `You are an enterprise SOC analyst. Write a 3-sentence ${role} briefing. Data: ${critCount} critical CVEs, ${kevCount} CISA KEV exploits, ${openCases.length} open cases, ${slaBreached.length} SLA breaches, ${actorRows.filter(a => a.active).length} active threat actors. Provide actionable guidance. No markdown headers.`;
    const aiRes = await callClaude(env, { prompt, tier: authCtx.tier || 'PRO', max_tokens: 250, temperature: 0.3 });
    if (aiRes?.content?.trim()) {
      socSummary = aiRes.content.trim();
      analystGuidance = socSummary;
    }
  } catch {}

  const body = {
    success:              true,
    service:              'CDB-SOC-COPILOT',
    generated_at:         new Date().toISOString(),
    role,
    soc_summary:          socSummary,
    investigation_summary: `${openCases.length} active investigation${openCases.length !== 1 ? 's' : ''}. ${slaBreached.length} SLA breach${slaBreached.length !== 1 ? 'es' : ''}. ${decisionRows.filter(d => d.priority === 'P1-CRITICAL').length} P1-critical decisions pending.`,
    analyst_guidance:     analystGuidance,
    containment_steps:    containmentSteps,
    recovery_plan:        recoveryPlan,
    escalation_advice:    escalationReason,
    key_metrics: {
      critical_threats: critCount,
      kev_count:        kevCount,
      open_cases:       openCases.length,
      sla_breached:     slaBreached.length,
      p1_actions:       p1Actions.length,
      active_actors:    actorRows.filter(a => a.active).length,
    },
    recommended_actions:  actions.slice(0, 5).map(a => ({ title: a.title, urgency: a.urgency, priority: a.priority, effort: a.effort })),
    powered_by:           'CYBERDUDEBIVASH SENTINEL APEX AI — P12.5',
  };

  await kvSet(env, ck, body, 120);
  return Response.json(body);
}

// ─── P12.6 — WORKFLOW QUEUE ───────────────────────────────────────────────────
export async function handleSOCWorkflowQueue(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const ck     = cacheKey('workflow_queue', userId);
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const db = env.DB;
  let caseRows = [], execRows = [], auditRows = [];

  if (db) {
    [caseRows, execRows, auditRows] = await Promise.all([
      db.prepare(
        `SELECT id, case_number, title, severity, status, assignee_id, sla_hours,
                sla_due_at, created_at, updated_at
         FROM soc_cases WHERE status NOT IN ('CLOSED') ORDER BY severity DESC, created_at DESC LIMIT 50`
      ).all().then(r => r.results || []).catch(() => []),
      db.prepare(
        `SELECT id, workflow_id, status, started_at, finished_at, error_message
         FROM workflow_executions ORDER BY started_at DESC LIMIT 20`
      ).all().then(r => r.results || []).catch(() => []),
      db.prepare(
        `SELECT event_type, description, actor, occurred_at
         FROM soc_timeline ORDER BY occurred_at DESC LIMIT 20`
      ).all().then(r => r.results || []).catch(() => []),
    ]);
  }

  const now = new Date();
  const activeCases  = caseRows.filter(c => ['OPEN','IN_PROGRESS','ESCALATED'].includes(c.status));
  const resolvedCases = caseRows.filter(c => c.status === 'RESOLVED');
  const escalations  = caseRows.filter(c => c.status === 'ESCALATED');

  // SLA analysis
  const slaBreached  = activeCases.filter(c => c.sla_due_at && new Date(c.sla_due_at) < now);
  const slaAtRisk    = activeCases.filter(c => {
    if (!c.sla_due_at) return false;
    const msLeft = new Date(c.sla_due_at) - now;
    return msLeft > 0 && msLeft < 4 * 3600 * 1000; // < 4h remaining
  });
  const slaHealthy   = activeCases.filter(c => {
    if (!c.sla_due_at) return false;
    return new Date(c.sla_due_at) > now && !slaAtRisk.find(r => r.id === c.id);
  });

  const body = {
    success:       true,
    service:       'CDB-SOC-WORKFLOW',
    generated_at:  new Date().toISOString(),
    active_cases:  activeCases.map(c => ({
      id:          c.id,
      case_number: c.case_number,
      title:       c.title,
      severity:    c.severity,
      status:      c.status,
      assignee_id: c.assignee_id || null,
      sla_due_at:  c.sla_due_at || null,
      sla_breached: c.sla_due_at ? new Date(c.sla_due_at) < now : false,
      created_at:  c.created_at,
    })),
    sla_summary: {
      total:    activeCases.length,
      breached: slaBreached.length,
      at_risk:  slaAtRisk.length,
      healthy:  slaHealthy.length,
      no_sla:   activeCases.filter(c => !c.sla_due_at).length,
    },
    escalations:   escalations.map(c => ({ id: c.id, title: c.title, severity: c.severity, created_at: c.created_at })),
    resolved_today: resolvedCases.filter(c => c.updated_at?.startsWith(now.toISOString().slice(0, 10))).length,
    workflow_executions: execRows.slice(0, 10).map(e => ({
      id:         e.id,
      workflow_id: e.workflow_id,
      status:     e.status,
      started_at: e.started_at,
    })),
    audit_trail: auditRows.slice(0, 10),
    pending_approvals: escalations.filter(c => !c.assignee_id).map(c => ({
      case_id: c.id,
      title:   c.title,
      reason:  'Escalated — awaiting assignment',
    })),
  };

  await kvSet(env, ck, body, 120);
  return Response.json(body);
}

// ─── P12.8 — OBSERVABILITY ────────────────────────────────────────────────────
export async function handleSOCObservability(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  // Measure D1 latency
  let d1Latency = null, kvLatency = null;
  const db = env.DB;

  if (db) {
    const d1Start = Date.now();
    try { await db.prepare('SELECT 1').first(); } catch {}
    d1Latency = Date.now() - d1Start;
  }

  if (env?.SECURITY_HUB_KV) {
    const kvStart = Date.now();
    try { await env.SECURITY_HUB_KV.get('soc:v1:health_probe'); } catch {}
    kvLatency = Date.now() - kvStart;
  }

  // Cache hit ratio — inspect known P12 cache keys
  const cacheKeys = [
    'soc:v1:command_state:platform',
    'soc:v1:copilot_soc:platform',
    'soc:v1:workflow_queue:platform',
  ];
  let hits = 0;
  if (env?.SECURITY_HUB_KV) {
    for (const k of cacheKeys) {
      try {
        const v = await env.SECURITY_HUB_KV.get(k);
        if (v) hits++;
      } catch {}
    }
  }
  const cacheHitRatio = cacheKeys.length > 0 ? (hits / cacheKeys.length) : 0;

  return Response.json({
    success:        true,
    service:        'CDB-SOC-OBS',
    generated_at:   new Date().toISOString(),
    d1_latency_ms:  d1Latency,
    kv_latency_ms:  kvLatency,
    cache_hit_ratio: parseFloat(cacheHitRatio.toFixed(2)),
    cached_endpoints: hits,
    total_endpoints:  cacheKeys.length,
    worker_health:  d1Latency !== null ? (d1Latency < 100 ? 'healthy' : d1Latency < 500 ? 'degraded' : 'critical') : 'unknown',
    endpoints_monitored: [
      'GET /api/soc/command/state',
      'GET /api/soc/command/copilot',
      'GET /api/soc/command/workflow',
      'GET /api/soc/stream',
      'GET /api/knowledge-graph',
      'GET /api/soc/investigate/:caseId',
    ],
    performance_targets: {
      cache_hit_ms:  50,
      uncached_ms:   400,
    },
  });
}

// ─── P12.4 — UNIFIED SOC EVENT STREAM (SSE) ───────────────────────────────────
export async function handleSOCEventStream(request, env, authCtx) {
  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  const gate = checkTier(authCtx);
  if (gate) return gate;

  const { readable, writable } = new TransformStream();
  const writer  = writable.getWriter();
  const encoder = new TextEncoder();

  const send = (eventType, data) => {
    try {
      const payload = eventType === 'keepalive'
        ? ': keepalive\n\n'
        : `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
      return writer.write(encoder.encode(payload));
    } catch { return Promise.resolve(); }
  };

  let closed = false;
  request.signal?.addEventListener('abort', () => {
    closed = true;
    writer.close().catch(() => {});
  });

  // ─── Helpers ──────────────────────────────────────────────────────────────
  const db = env.DB;

  const getLatestCVEs = async () => {
    if (!db) return [];
    try {
      const res = await db.prepare(
        `SELECT cve_id, title, cvss_score, severity, actively_exploited, source, created_at
         FROM threat_intel ORDER BY created_at DESC LIMIT 5`
      ).all();
      return res.results || [];
    } catch { return []; }
  };

  const getLatestCases = async () => {
    if (!db) return [];
    try {
      const res = await db.prepare(
        `SELECT id, case_number, title, severity, status, created_at
         FROM soc_cases WHERE status NOT IN ('CLOSED','RESOLVED')
         ORDER BY created_at DESC LIMIT 5`
      ).all();
      return res.results || [];
    } catch { return []; }
  };

  const getLatestDecisions = async () => {
    if (!db) return [];
    try {
      const res = await db.prepare(
        `SELECT cve_id, decision, priority, created_at
         FROM soc_decisions ORDER BY created_at DESC LIMIT 5`
      ).all();
      return res.results || [];
    } catch { return []; }
  };

  const getActiveActors = async () => {
    if (!db) return [];
    try {
      const res = await db.prepare(
        `SELECT name, sector FROM threat_actors WHERE active = 1 LIMIT 5`
      ).all();
      return res.results || [];
    } catch { return []; }
  };

  // ─── Initial burst ────────────────────────────────────────────────────────
  const sendInitial = async () => {
    const [cves, cases, decisions, actors] = await Promise.all([
      getLatestCVEs(), getLatestCases(), getLatestDecisions(), getActiveActors(),
    ]);

    for (const cve of cves) {
      await send(cve.actively_exploited ? 'kev_alert' : 'cve_alert', {
        cve_id:   cve.cve_id,
        title:    cve.title,
        severity: cve.severity,
        cvss:     cve.cvss_score,
        source:   cve.source,
        ts:       cve.created_at || new Date().toISOString(),
      });
    }

    for (const c of cases) {
      await send('case_update', {
        case_id:     c.id,
        case_number: c.case_number,
        title:       c.title,
        severity:    c.severity,
        status:      c.status,
        ts:          c.created_at || new Date().toISOString(),
      });
    }

    for (const d of decisions) {
      await send('decision_update', {
        cve_id:   d.cve_id,
        decision: d.decision,
        priority: d.priority,
        ts:       d.created_at || new Date().toISOString(),
      });
    }

    if (actors.length > 0) {
      await send('actor_update', {
        active_actors: actors.map(a => ({ name: a.name, sector: a.sector })),
        ts: new Date().toISOString(),
      });
    }
  };

  // ─── Main stream loop ─────────────────────────────────────────────────────
  const runStream = async () => {
    await sendInitial();

    let tick = 0;
    const TICK_MS    = 5_000;
    const POLL_MS    = 30_000;
    const KEEPALIVE_MS = 25_000;
    let   keepaliveTick = 0;
    let   pollTick      = 0;

    while (!closed) {
      await new Promise(r => setTimeout(r, TICK_MS));
      if (closed) break;

      tick         += TICK_MS;
      keepaliveTick += TICK_MS;
      pollTick      += TICK_MS;

      if (keepaliveTick >= KEEPALIVE_MS) {
        keepaliveTick = 0;
        await send('keepalive', {});
      }

      if (pollTick >= POLL_MS) {
        pollTick = 0;
        try {
          const [cves, cases, decisions] = await Promise.all([
            getLatestCVEs(), getLatestCases(), getLatestDecisions(),
          ]);
          for (const cve of cves.filter(c => c.actively_exploited)) {
            await send('kev_alert', {
              cve_id: cve.cve_id, cvss: cve.cvss_score, ts: new Date().toISOString(),
            });
          }
          if (cases.length > 0) {
            await send('case_update', { count: cases.length, ts: new Date().toISOString() });
          }
          if (decisions.filter(d => d.priority === 'P1-CRITICAL').length > 0) {
            await send('executive_alert', {
              message: `${decisions.filter(d => d.priority === 'P1-CRITICAL').length} P1-CRITICAL decision(s) pending action`,
              ts: new Date().toISOString(),
            });
          }
        } catch {}
      }
    }
  };

  runStream().catch(() => { closed = true; writer.close().catch(() => {}); });

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type':                'text/event-stream; charset=utf-8',
      'Cache-Control':               'no-cache, no-store, must-revalidate',
      'Connection':                  'keep-alive',
      'X-Accel-Buffering':           'no',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
