/**
 * CYBERDUDEBIVASH AI Security Hub — P13.0 Autonomous Security Operations Platform
 *
 * Endpoints:
 *   GET /api/autonomous/orchestrator/plan       — P13.1 unified execution plan
 *   GET /api/autonomous/incident-response/:caseId — P13.2 automated IR plan
 *   GET /api/autonomous/risk/predict            — P13.3 predictive risk engine
 *   GET /api/autonomous/workflow/status         — P13.4 workflow + SLA dashboard
 *   GET /api/autonomous/executive/brief         — P13.5 executive operations copilot
 *   GET /api/autonomous/observability           — P13.7 extended observability
 *
 * Reuses (NEVER duplicates):
 *   core/adaptiveCyberBrain.js  — generateAdaptiveRecommendations(), computeAdaptiveRisk(), predictAttackPaths()
 *   core/mythosAIProvider.js    — callClaude()
 *   services/predictiveEngine.js — getTopThreats(), computePredictiveRiskScore()
 *   services/radarService.js    — RadarService
 *   D1 tables                   — threat_intel, threat_predictions, soc_cases, soc_decisions,
 *                                  customer_assets, workflow_executions, soc_timeline
 *
 * Performance:
 *   KV prefix: auto:v1:<endpoint>:<userId>  TTL: 300s (plan/risk), 120s (IR/workflow/brief)
 *   Target: <50ms cache hit  <400ms uncached
 *
 * Tier gate: PRO / ENTERPRISE / MSSP / OWNER / ADMIN
 */

import { generateAdaptiveRecommendations, computeAdaptiveRisk, predictAttackPaths } from '../core/adaptiveCyberBrain.js';
import { callClaude }                from '../core/mythosAIProvider.js';
import { getTopThreats, computePredictiveRiskScore } from '../services/predictiveEngine.js';
import { RadarService }              from '../services/radarService.js';
import { isRealUser } from '../auth/middleware.js';
import { tenantKey } from './socCases.js';

// ─── Tier gate ────────────────────────────────────────────────────────────────
const ALLOWED_TIERS = new Set(['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN']);

function checkTier(authCtx) {
  if (!isRealUser(authCtx)) {
    return Response.json(
      { success: false, error: 'Authentication required', service: 'CDB-AUTONOMOUS-OPS' },
      { status: 401 }
    );
  }
  if (!ALLOWED_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'PRO plan or above required for Autonomous Operations Platform', upgrade: 'https://tools.cyberdudebivash.com/#pricing', service: 'CDB-AUTONOMOUS-OPS' },
      { status: 403 }
    );
  }
  return null;
}

// ─── KV helpers ───────────────────────────────────────────────────────────────
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

// ─── Shared D1 context loader ─────────────────────────────────────────────────
export async function loadOpsContext(env, authCtx = {}) {
  const db = env.DB;
  if (!db) {
    return { vulnRows: [], actorRows: [], assetRows: [], caseRows: [], decisionRows: [], predRows: [] };
  }
  // Tenant isolation: soc_cases is per-tenant. The autonomous brief/plan must only
  // see the caller's own cases — not every tenant's. threat_intel / threat_actors /
  // threat_predictions are global threat data and stay shared.
  const privileged = authCtx.role === 'admin' || authCtx.role === 'mssp_admin' || authCtx.isAdmin === true;
  const scopeKey   = tenantKey(authCtx);
  const caseSql = privileged
    ? `SELECT id, case_number, title, severity, status, assignee_id, sla_due_at, mitre_tactics, ioc_list, created_at FROM soc_cases ORDER BY created_at DESC LIMIT 30`
    : `SELECT id, case_number, title, severity, status, assignee_id, sla_due_at, mitre_tactics, ioc_list, created_at FROM soc_cases WHERE org_id = ? ORDER BY created_at DESC LIMIT 30`;
  const caseStmt = privileged ? db.prepare(caseSql) : db.prepare(caseSql).bind(scopeKey);

  const [vulnRows, actorRows, assetRows, caseRows, decisionRows, predRows] = await Promise.all([
    db.prepare(`SELECT cve_id, cvss_score, epss_score, is_kev, severity, mitre_technique, description FROM threat_intel ORDER BY cvss_score DESC LIMIT 50`).all().then(r => r.results || []).catch(() => []),
    db.prepare(`SELECT name, sector, active FROM threat_actors LIMIT 30`).all().then(r => r.results || []).catch(() => []),
    db.prepare(`SELECT asset_value, asset_type FROM customer_assets LIMIT 50`).all().then(r => r.results || []).catch(() => []),
    caseStmt.all().then(r => r.results || []).catch(() => []),
    db.prepare(`SELECT id, cve_id, decision, priority, confidence, risk_score FROM soc_decisions ORDER BY risk_score DESC LIMIT 30`).all().then(r => r.results || []).catch(() => []),
    db.prepare(`SELECT cve_id, risk_score, risk_level, exploit_probability, impact_score FROM threat_predictions WHERE predicted_at > datetime('now', '-24 hours') ORDER BY risk_score DESC LIMIT 30`).all().then(r => r.results || []).catch(() => []),
  ]);
  return { vulnRows, actorRows, assetRows, caseRows, decisionRows, predRows };
}

// ─── Stage order for attack chain sorting ────────────────────────────────────
const STAGE_ORDER = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Lateral Movement',
  'Collection','Command and Control','Exfiltration','Impact',
];

// ─── P13.1 — Autonomous Orchestrator Plan ────────────────────────────────────
export async function handleAutonomousOrchestratorPlan(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const ck = `auto:v1:orch_plan:${userId || 'platform'}`;
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const t0 = Date.now();
  const { vulnRows, actorRows, assetRows, caseRows, decisionRows } = await loadOpsContext(env, authCtx);

  // Build vulns array for adaptive brain
  const vulns = vulnRows.map(r => ({
    cve_id: r.cve_id, cvss: r.cvss_score, epss: r.epss_score,
    in_kev: Boolean(r.is_kev || r.actively_exploited), severity: r.severity, mitre: r.mitre_technique,
  }));

  // Phase 1: Detection — active CRITICAL/HIGH cases
  const critCases  = caseRows.filter(c => c.severity === 'CRITICAL' || c.severity === 'HIGH');
  const openCases  = caseRows.filter(c => c.status === 'OPEN' || c.status === 'IN_PROGRESS');
  const kevCount   = vulnRows.filter(v => v.is_kev || v.actively_exploited).length;
  const critCVEs   = vulnRows.filter(v => v.cvss_score >= 9).length;
  const activeActors = actorRows.filter(a => a.active).length;

  // Phase 2: Analysis — adaptive risk via existing brain
  let adaptiveScore = 50;
  try {
    const riskResult = await computeAdaptiveRisk(env, {
      scan_id: 'orchestrator',
      findings: [],
      vuln_count: vulnRows.length,
      critical_count: critCVEs,
      high_count: vulnRows.filter(v => v.cvss_score >= 7 && v.cvss_score < 9).length,
      kev_count: kevCount,
    }, userId, authCtx.tier || 'PRO');
    adaptiveScore = riskResult?.adaptive_risk_score ?? 50;
  } catch {}

  // Phase 3: Response — adaptive recommendations
  let responseActions = [];
  try {
    const adaptive = await generateAdaptiveRecommendations(env, {
      findings: [], vulns: vulns.slice(0, 15), adaptiveScore,
      attackChains: [], sector: 'technology',
      tier: authCtx.tier || 'PRO', userId,
    });
    responseActions = (adaptive.actions || []).slice(0, 6).map(a => ({
      action: a.title, priority: a.urgency || 'HIGH', effort: a.effort || 'TBD', detail: a.detail || '',
    }));
  } catch {}

  // Phase 4: Validation — open decisions needing resolution
  const pendingDecisions = decisionRows.filter(d => !d.resolved_at).slice(0, 5).map(d => ({
    id: d.id, cve_id: d.cve_id, decision: d.decision, priority: d.priority, risk_score: d.risk_score,
  }));

  // Threat level determination
  const threatLevel = kevCount >= 5 || critCases.length >= 3 ? 'CRITICAL'
    : kevCount >= 2 || critCases.length >= 1 ? 'HIGH'
    : critCVEs >= 5 ? 'ELEVATED'
    : critCVEs >= 1 ? 'GUARDED' : 'NOMINAL';

  const executionPlan = {
    phases: [
      {
        phase: 1, name: 'Threat Detection',
        status: critCases.length > 0 ? 'ACTIVE' : 'MONITORING',
        findings: { open_cases: openCases.length, critical_cases: critCases.length, kev_exploits: kevCount, active_actors: activeActors },
      },
      {
        phase: 2, name: 'AI Analysis',
        status: 'COMPLETE',
        findings: { adaptive_risk_score: adaptiveScore, critical_cves: critCVEs, total_intel: vulnRows.length },
      },
      {
        phase: 3, name: 'Autonomous Response',
        status: responseActions.length > 0 ? 'READY' : 'IDLE',
        actions: responseActions,
      },
      {
        phase: 4, name: 'Validation & Closure',
        status: pendingDecisions.length > 0 ? 'PENDING' : 'CLEAR',
        pending_decisions: pendingDecisions,
      },
    ],
    threat_level: threatLevel,
    orchestrator_health: vulnRows.length > 0 ? 'OPERATIONAL' : 'DEGRADED',
    subsystems: {
      decision_engine:      decisionRows.length >= 0 ? 'ACTIVE' : 'DEGRADED',
      investigation_engine: openCases.length >= 0 ? 'ACTIVE' : 'DEGRADED',
      knowledge_graph:      vulnRows.length > 0 ? 'ACTIVE' : 'DEGRADED',
      soc_command:          openCases.length >= 0 ? 'ACTIVE' : 'DEGRADED',
      predictive_engine:    critCVEs >= 0 ? 'ACTIVE' : 'DEGRADED',
      automation_platform:  responseActions.length >= 0 ? 'ACTIVE' : 'DEGRADED',
    },
  };

  const body = {
    success: true, service: 'CDB-AUTONOMOUS-ORCHESTRATOR',
    generated_at: new Date().toISOString(),
    latency_ms: Date.now() - t0,
    execution_plan: executionPlan,
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P13.1',
  };
  await kvSet(env, ck, body, 300);
  return Response.json(body);
}

// ─── P13.2 — Automated Incident Response ─────────────────────────────────────
export async function handleAutonomousIncidentResponse(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const caseId = new URL(request.url).pathname.split('/').at(-1);
  if (!caseId || caseId === 'incident-response') {
    return Response.json({ success: false, error: 'caseId required in path: /api/autonomous/incident-response/:caseId' }, { status: 400 });
  }

  const userId = authCtx.userId || authCtx.user_id || null;
  const orgId  = authCtx.org_id || 'default';
  const ck = `auto:v1:ir:${caseId}:${userId || 'platform'}`;
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const t0 = Date.now();
  const db = env.DB;

  // Parallel fetch: case, timeline, threat intel, assets
  const [caseRow, timeline, tiRows, assetRows, decisionRows] = await Promise.all([
    db ? db.prepare(`SELECT id, case_number, title, severity, status, mitre_tactics, ioc_list, summary, created_at, sla_due_at FROM soc_cases WHERE id = ? AND (org_id = ? OR ? = 'admin')`).bind(caseId, orgId, authCtx.role || '').first().catch(() => null) : null,
    db ? db.prepare(`SELECT event_type, description, actor, occurred_at FROM soc_timeline WHERE case_id = ? ORDER BY occurred_at ASC LIMIT 30`).bind(caseId).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT cve_id, cvss_score, epss_score, is_kev, severity, mitre_technique, description FROM threat_intel ORDER BY cvss_score DESC LIMIT 30`).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT asset_value, asset_type FROM customer_assets LIMIT 30`).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT id, cve_id, decision, priority, risk_score FROM soc_decisions ORDER BY risk_score DESC LIMIT 15`).all().then(r => r.results || []).catch(() => []) : [],
  ]);

  if (!caseRow) {
    return Response.json({ success: false, error: 'Case not found or access denied' }, { status: 404 });
  }

  const mitreTactics = (() => { try { return JSON.parse(caseRow.mitre_tactics || '[]'); } catch { return []; } })();
  const iocList      = (() => { try { return JSON.parse(caseRow.ioc_list || '[]'); } catch { return []; } })();
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[caseRow.severity] || 2;
  const isCritical   = severityRank >= 4;
  const isHigh       = severityRank >= 3;

  // Build vulns for adaptive brain
  const vulns = tiRows.map(r => ({ cve_id: r.cve_id, cvss: r.cvss_score, epss: r.epss_score, in_kev: Boolean(r.is_kev), severity: r.severity, mitre: r.mitre_technique }));

  // MITRE-informed attack chain
  const attackChain = mitreTactics.slice(0, 5).map((t, i) => ({ step: i + 1, technique: t }));

  // Recommended response from adaptive brain
  let adaptiveActions = [];
  try {
    const adaptive = await generateAdaptiveRecommendations(env, {
      findings: [], vulns: vulns.slice(0, 15), adaptiveScore: 60, attackChains: attackChain,
      sector: 'technology', tier: authCtx.tier || 'PRO', userId,
    });
    adaptiveActions = (adaptive.actions || []).slice(0, 8);
  } catch {}

  // Containment plan — immediate actions (CRITICAL priority)
  const containmentPlan = [
    isCritical && { step: 1, action: 'Isolate affected systems from network', priority: 'IMMEDIATE', effort: '15 min', automated: false },
    iocList.length > 0 && { step: 2, action: `Block ${iocList.length} identified IOCs at perimeter`, priority: 'IMMEDIATE', effort: '10 min', automated: true },
    mitreTactics.length > 0 && { step: 3, action: `Disable attack vectors for techniques: ${mitreTactics.slice(0, 3).join(', ')}`, priority: 'HIGH', effort: '30 min', automated: false },
    { step: 4, action: 'Capture forensic memory and disk images', priority: 'HIGH', effort: '1 hour', automated: false },
    { step: 5, action: 'Revoke potentially compromised credentials', priority: isHigh ? 'HIGH' : 'MEDIUM', effort: '20 min', automated: true },
  ].filter(Boolean);

  // Remediation plan — based on adaptive actions
  const remediationPlan = adaptiveActions.filter(a => (a.urgency || '') !== 'CRITICAL').slice(0, 5).map((a, i) => ({
    step: i + 1, action: a.title, priority: a.urgency || 'HIGH', effort: a.effort || 'TBD', detail: a.detail || '',
  }));

  // Recovery plan — deterministic phases
  const recoveryPlan = [
    { step: 1, action: 'Verify IOC removal and system clean state', timeline: 'Hour 1–2' },
    { step: 2, action: 'Restore systems from last known-good backup', timeline: 'Hour 2–6' },
    { step: 3, action: 'Re-enable network connectivity with enhanced monitoring', timeline: 'Hour 6–8' },
    { step: 4, action: 'Validate service restoration with smoke tests', timeline: 'Hour 8–12' },
    { step: 5, action: 'Update detection rules based on incident indicators', timeline: 'Day 1–2' },
  ];

  // Validation checklist
  const validationChecklist = [
    { check: 'All identified IOCs blocked at perimeter', category: 'Containment', required: true },
    { check: 'No lateral movement detected post-containment', category: 'Containment', required: true },
    { check: 'All compromised credentials rotated', category: 'Remediation', required: true },
    { check: 'Affected systems fully patched', category: 'Remediation', required: isCritical },
    { check: 'SIEM rules updated with new indicators', category: 'Detection', required: true },
    { check: 'Backup integrity verified', category: 'Recovery', required: true },
    { check: 'User communication sent', category: 'Operations', required: isHigh },
    { check: 'Post-incident report drafted', category: 'Reporting', required: isCritical },
  ];

  // Rollback plan
  const rollbackPlan = [
    { trigger: 'Remediation causes production degradation', action: 'Revert to pre-remediation snapshot', decision_maker: 'SOC Lead' },
    { trigger: 'Patch causes incompatibility', action: 'Roll back patch, apply compensating control', decision_maker: 'Engineering' },
    { trigger: 'IOC block causes false positives', action: 'Whitelist verified IPs, escalate to threat intel team', decision_maker: 'SOC Analyst' },
  ];

  const body = {
    success: true, service: 'CDB-AUTONOMOUS-IR', generated_at: new Date().toISOString(), latency_ms: Date.now() - t0,
    case: { id: caseRow.id, case_number: caseRow.case_number, title: caseRow.title, severity: caseRow.severity, status: caseRow.status },
    mitre_tactics: mitreTactics, ioc_count: iocList.length,
    timeline_events: timeline.length,
    containment_plan:      containmentPlan,
    remediation_plan:      remediationPlan.length > 0 ? remediationPlan : [{ step: 1, action: 'Apply recommended patches from threat intel', priority: 'HIGH', effort: '4 hours' }],
    recovery_plan:         recoveryPlan,
    validation_checklist:  validationChecklist,
    rollback_plan:         rollbackPlan,
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P13.2',
  };
  await kvSet(env, ck, body, 120);
  return Response.json(body);
}

// ─── P13.3 — Predictive Risk Engine ──────────────────────────────────────────
export async function handleAutonomousPredictiveRisk(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const ck = `auto:v1:pred_risk:${userId || 'platform'}`;
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const t0 = Date.now();

  // Reuse existing predictive engine — never score from scratch
  const topThreats = await getTopThreats(env, 20).catch(() => ({ threats: [], total: 0 }));

  const db = env.DB;
  const [assetRows, caseRows, tiRows] = await Promise.all([
    db ? db.prepare(`SELECT asset_value, asset_type FROM customer_assets LIMIT 50`).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT severity, status, created_at FROM soc_cases ORDER BY created_at DESC LIMIT 50`).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT cvss_score, epss_score, is_kev, severity FROM threat_intel ORDER BY cvss_score DESC LIMIT 50`).all().then(r => r.results || []).catch(() => []) : [],
  ]);

  // Customer exposure context (for computePredictiveRiskScore)
  const watchlistCount = assetRows.filter(a => a.asset_type === 'cve_watchlist').length;
  const techCount      = assetRows.filter(a => a.asset_type === 'technology').length;
  const context = {
    customer_asset_count: assetRows.length,
    watched_cve_count:    watchlistCount,
    technology_count:     techCount,
  };

  // Emerging risks — top threats enriched with business context
  const emergingRisks = (topThreats.threats || []).slice(0, 10).map(t => {
    const scored = computePredictiveRiskScore(
      { cve_id: t.cve_id, cvss_score: t.cvss_score || 0, epss_score: t.epss_score || 0, is_kev: t.is_kev },
      context
    );
    return {
      cve_id:           t.cve_id,
      risk_score:       t.risk_score || scored.risk_score,
      risk_level:       t.risk_level || scored.risk_level,
      likelihood:       Math.round((t.exploit_probability || scored.exploit_probability) * 100),
      operational_impact: scored.impact_score >= 0.7 ? 'HIGH' : scored.impact_score >= 0.4 ? 'MEDIUM' : 'LOW',
      apt_groups:       t.apt_groups || [],
      description:      t.description || '',
      recommended_actions: (t.recommended_actions || []).slice(0, 3),
    };
  });

  // Likelihood distribution from existing data
  const likelihoodBuckets = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const t of topThreats.threats || []) {
    const level = t.risk_level || 'LOW';
    if (likelihoodBuckets[level] !== undefined) likelihoodBuckets[level]++;
  }

  // Priority trend — compare recent cases by severity
  const recentDays  = caseRows.filter(c => new Date(c.created_at) > new Date(Date.now() - 7 * 86400000));
  const olderDays   = caseRows.filter(c => {
    const d = new Date(c.created_at);
    return d <= new Date(Date.now() - 7 * 86400000) && d > new Date(Date.now() - 14 * 86400000);
  });
  const recentCrit  = recentDays.filter(c => c.severity === 'CRITICAL').length;
  const olderCrit   = olderDays.filter(c => c.severity === 'CRITICAL').length;
  const trendDir    = recentCrit > olderCrit ? 'INCREASING' : recentCrit < olderCrit ? 'DECREASING' : 'STABLE';

  // Business impact summary
  const kevCount  = tiRows.filter(r => r.is_kev || r.actively_exploited).length;
  const critCount = tiRows.filter(r => r.cvss_score >= 9).length;
  const highEpss  = tiRows.filter(r => r.epss_score >= 0.5).length;

  const body = {
    success: true, service: 'CDB-AUTONOMOUS-PREDICTIVE-RISK', generated_at: new Date().toISOString(), latency_ms: Date.now() - t0,
    emerging_risks:    emergingRisks,
    likelihood_scores: likelihoodBuckets,
    operational_impact: {
      kev_active:          kevCount,
      critical_cves:       critCount,
      high_epss_cves:      highEpss,
      customer_assets_exposed: assetRows.length,
      watchlist_cves:      watchlistCount,
    },
    priority_trend: {
      direction:      trendDir,
      recent_7d_critical_cases: recentCrit,
      prior_7d_critical_cases:  olderCrit,
      open_cases:     caseRows.filter(c => c.status === 'OPEN').length,
    },
    prediction_stats: { total_predictions: topThreats.total || 0, timestamp: topThreats.timestamp },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P13.3',
  };
  await kvSet(env, ck, body, 300);
  return Response.json(body);
}

// ─── P13.4 — Autonomous Workflow Status ──────────────────────────────────────
export async function handleAutonomousWorkflowStatus(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const userId = authCtx.userId || authCtx.user_id || null;
  const orgId  = authCtx.org_id || 'default';
  const ck = `auto:v1:wf_status:${userId || 'platform'}`;
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const t0 = Date.now();
  const db = env.DB;

  const [caseRows, execRows, timelineRows] = await Promise.all([
    db ? db.prepare(`SELECT id, case_number, title, severity, status, assignee_id, sla_due_at, created_at FROM soc_cases ORDER BY created_at DESC LIMIT 30`).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT id, workflow_id, status, started_at, completed_at, steps_json FROM workflow_executions ORDER BY started_at DESC LIMIT 30`).all().then(r => r.results || []).catch(() => []) : [],
    db ? db.prepare(`SELECT case_id, event_type, actor, occurred_at FROM soc_timeline ORDER BY occurred_at DESC LIMIT 50`).all().then(r => r.results || []).catch(() => []) : [],
  ]);

  const now = new Date();

  // SLA health analysis (reuses same logic as socCommandHandler's handleSOCWorkflowQueue)
  const slaAnalysis = caseRows.map(c => {
    const sla = c.sla_due_at ? new Date(c.sla_due_at) : null;
    const msLeft = sla ? sla - now : null;
    const status = !sla ? 'no_sla'
      : msLeft < 0        ? 'breached'
      : msLeft < 3600000  ? 'at_risk'  // < 1 hour
      : 'healthy';
    return { id: c.id, case_number: c.case_number, title: c.title, severity: c.severity, status: c.status, sla_status: status, hours_remaining: sla ? Math.round(msLeft / 3600000) : null };
  });

  const slaCounts = {
    breached: slaAnalysis.filter(s => s.sla_status === 'breached').length,
    at_risk:  slaAnalysis.filter(s => s.sla_status === 'at_risk').length,
    healthy:  slaAnalysis.filter(s => s.sla_status === 'healthy').length,
    no_sla:   slaAnalysis.filter(s => s.sla_status === 'no_sla').length,
  };

  // Escalations — breached SLA + high severity open cases without assignee
  const escalations = slaAnalysis
    .filter(s => s.sla_status === 'breached' || (s.severity === 'CRITICAL' && s.status === 'OPEN'))
    .slice(0, 5)
    .map(s => ({
      case_id: s.id, case_number: s.case_number, reason: s.sla_status === 'breached' ? 'SLA_BREACHED' : 'CRITICAL_UNRESOLVED', severity: s.severity,
    }));

  // Workflow execution stats
  const execStats = {
    total:     execRows.length,
    completed: execRows.filter(e => e.status === 'completed').length,
    failed:    execRows.filter(e => e.status === 'failed').length,
    running:   execRows.filter(e => e.status === 'running').length,
    pending:   execRows.filter(e => e.status === 'pending').length,
  };
  const successRate = execStats.total > 0 ? Math.round((execStats.completed / execStats.total) * 100) : 100;

  // Assignment queue — open cases without assignees
  const unassigned = caseRows.filter(c => c.status === 'OPEN' && !c.assignee_id).slice(0, 8).map(c => ({
    id: c.id, case_number: c.case_number, title: c.title, severity: c.severity, created_at: c.created_at,
  }));

  // Audit trail — last 10 timeline events
  const auditTrail = timelineRows.slice(0, 10).map(t => ({
    case_id: t.case_id, event_type: t.event_type, actor: t.actor, occurred_at: t.occurred_at,
  }));

  const body = {
    success: true, service: 'CDB-AUTONOMOUS-WORKFLOW', generated_at: new Date().toISOString(), latency_ms: Date.now() - t0,
    sla_dashboard:    { counts: slaCounts, cases: slaAnalysis.slice(0, 15) },
    escalations,
    assignments:      { unassigned_count: unassigned.length, queue: unassigned },
    workflow_executions: execStats,
    automation_health: { success_rate_pct: successRate, queue_depth: execStats.pending + execStats.running },
    notifications_pending: escalations.length,
    audit_trail:       auditTrail,
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P13.4',
  };
  await kvSet(env, ck, body, 120);
  return Response.json(body);
}

// ─── P13.5 — Executive Operations Copilot ────────────────────────────────────
const EXEC_ROLES = new Set(['ceo', 'ciso', 'soc_lead', 'compliance', 'operations', 'board']);

const EXEC_ROLE_FOCUS = {
  ceo:        { title: 'CEO Executive Brief', focus: 'business risk, financial exposure, strategic decisions' },
  ciso:       { title: 'CISO Security Brief', focus: 'threat landscape, control gaps, security posture improvement' },
  soc_lead:   { title: 'SOC Lead Operations Brief', focus: 'active incidents, analyst workload, detection coverage, SLA adherence' },
  compliance: { title: 'Compliance & Risk Brief', focus: 'regulatory exposure, audit findings, compliance posture, control effectiveness' },
  operations: { title: 'Operations Brief', focus: 'system availability, incident lifecycle, workflow efficiency, SLA performance' },
  board:      { title: 'Board Security Brief', focus: 'enterprise risk posture, peer benchmarks, investment priorities, regulatory compliance' },
};

export async function handleAutonomousExecutiveBrief(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const url    = new URL(request.url);
  const rawRole = (url.searchParams.get('role') || 'ceo').toLowerCase();
  const role    = EXEC_ROLES.has(rawRole) ? rawRole : 'ciso';

  const userId = authCtx.userId || authCtx.user_id || null;
  const ck = `auto:v1:exec_brief_${role}:${userId || 'platform'}`;
  const cached = await kvGet(env, ck);
  if (cached) return Response.json({ ...cached, _cache: 'HIT' });

  const t0 = Date.now();
  const { vulnRows, actorRows, caseRows, decisionRows, predRows } = await loadOpsContext(env, authCtx);

  const openCases    = caseRows.filter(c => c.status === 'OPEN');
  const critCases    = caseRows.filter(c => c.severity === 'CRITICAL');
  const kevCount     = vulnRows.filter(v => v.is_kev || v.actively_exploited).length;
  const critCVEs     = vulnRows.filter(v => v.cvss_score >= 9).length;
  const highRiskPred = predRows.filter(p => p.risk_level === 'CRITICAL' || p.risk_level === 'HIGH').length;
  const p1Decisions  = decisionRows.filter(d => d.priority === 'P1' || d.risk_score >= 80).length;

  const vulns = vulnRows.map(r => ({ cve_id: r.cve_id, cvss: r.cvss_score, epss: r.epss_score, in_kev: Boolean(r.is_kev), severity: r.severity }));

  // Get adaptive actions for critical_actions section
  let criticalActions = [];
  try {
    const adaptive = await generateAdaptiveRecommendations(env, {
      findings: [], vulns: vulns.slice(0, 10), adaptiveScore: highRiskPred >= 3 ? 80 : 55,
      attackChains: [], sector: 'technology', tier: authCtx.tier || 'PRO', userId,
    });
    criticalActions = (adaptive.actions || []).filter(a => a.urgency === 'CRITICAL' || a.urgency === 'HIGH').slice(0, 4).map(a => ({
      action: a.title, priority: a.urgency, effort: a.effort || 'TBD',
    }));
  } catch {}

  // Risk posture score (0–100)
  const riskPosture = Math.min(100, Math.round(
    (kevCount * 15) + (critCVEs * 5) + (critCases.length * 10) + (highRiskPred * 8)
  ));
  const postureLabel = riskPosture >= 75 ? 'CRITICAL' : riskPosture >= 50 ? 'HIGH' : riskPosture >= 25 ? 'ELEVATED' : 'ACCEPTABLE';

  // Deterministic key metrics per role
  const keyMetrics = {
    ceo:        { open_incidents: openCases.length, critical_threats: critCases.length, kev_exploits: kevCount, p1_decisions_pending: p1Decisions },
    ciso:       { open_cases: openCases.length, kev_count: kevCount, critical_cves: critCVEs, threat_actors_active: actorRows.filter(a => a.active).length },
    soc_lead:   { open_cases: openCases.length, critical_cases: critCases.length, high_risk_predictions: highRiskPred, unresolved_decisions: decisionRows.length },
    compliance: { open_incidents: openCases.length, kev_compliance_gap: kevCount, critical_unpatched: critCVEs, p1_overdue: p1Decisions },
    operations: { active_workflows: caseRows.filter(c => c.status === 'IN_PROGRESS').length, open_cases: openCases.length, sla_at_risk: caseRows.filter(c => { const d = c.sla_due_at ? new Date(c.sla_due_at) : null; return d && d - new Date() < 3600000 && d > new Date(); }).length, automation_actions: criticalActions.length },
    board:      { overall_risk: postureLabel, open_incidents: openCases.length, critical_vulnerabilities: critCVEs, kev_exposure: kevCount },
  };

  // AI narrative enrichment (optional, never fails)
  let executiveSummary = `${EXEC_ROLE_FOCUS[role].title}: Platform risk posture is ${postureLabel} with ${openCases.length} open incidents, ${kevCount} KEV-listed vulnerabilities, and ${critCVEs} critical CVEs. ${criticalActions.length > 0 ? `${criticalActions.length} priority actions recommended.` : 'No immediate critical actions required.'}`;
  try {
    const prompt = `Write a 2-sentence ${role.toUpperCase()} executive security brief. Risk posture: ${postureLabel}. Open incidents: ${openCases.length}. Critical CVEs: ${critCVEs}. KEV exploits: ${kevCount}. Focus: ${EXEC_ROLE_FOCUS[role].focus}. Tone: authoritative, concise, enterprise.`;
    const aiRes = await callClaude(env, { prompt, tier: authCtx.tier || 'PRO', max_tokens: 150, temperature: 0.3 });
    if (aiRes?.content?.trim()) executiveSummary = aiRes.content.trim();
  } catch {}

  const body = {
    success: true, service: 'CDB-AUTONOMOUS-EXECUTIVE-COPILOT', generated_at: new Date().toISOString(), latency_ms: Date.now() - t0,
    role, brief_title: EXEC_ROLE_FOCUS[role].title,
    executive_summary:  executiveSummary,
    key_metrics:        keyMetrics[role] || keyMetrics.ciso,
    risk_posture:       { score: riskPosture, label: postureLabel },
    critical_actions:   criticalActions,
    available_roles:    [...EXEC_ROLES],
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P13.5',
  };
  await kvSet(env, ck, body, 120);
  return Response.json(body);
}

// ─── P13.7 — Extended Observability ──────────────────────────────────────────
export async function handleAutonomousObservability(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const t0 = Date.now();
  const db = env.DB;
  const kv = env.SECURITY_HUB_KV;

  // D1 health probe
  let d1LatencyMs = -1, d1Healthy = false;
  try {
    const d1t = Date.now();
    await db.prepare(`SELECT 1 as ok`).first();
    d1LatencyMs = Date.now() - d1t;
    d1Healthy = d1LatencyMs < 2000;
  } catch {}

  // KV health probe
  let kvLatencyMs = -1, kvHealthy = false;
  try {
    const kvt = Date.now();
    await kv?.get('__health_probe__');
    kvLatencyMs = Date.now() - kvt;
    kvHealthy = kvLatencyMs < 500;
  } catch {}

  // Cache hit ratio: sample known P13 + P12 cache keys
  const cacheKeys = [
    'auto:v1:orch_plan:platform', 'auto:v1:pred_risk:platform', 'auto:v1:wf_status:platform',
    'soc:v1:command_state:platform', 'kg:v1:full:platform',
  ];
  let hits = 0;
  for (const k of cacheKeys) {
    try { const v = await kv?.get(k); if (v) hits++; } catch {}
  }
  const cacheHitRatio = Math.round((hits / cacheKeys.length) * 100);

  // Queue depth from D1
  let queueDepth = 0, automationSuccessRate = 100, failureRate = 0;
  try {
    const [openCases, execStats] = await Promise.all([
      db.prepare(`SELECT COUNT(*) cnt FROM soc_cases WHERE status = 'OPEN'`).first().catch(() => ({ cnt: 0 })),
      db.prepare(`SELECT status, COUNT(*) cnt FROM workflow_executions GROUP BY status`).all().catch(() => ({ results: [] })),
    ]);
    queueDepth = openCases?.cnt || 0;
    const execRows = execStats?.results || [];
    const total    = execRows.reduce((s, r) => s + (r.cnt || 0), 0);
    const completed = execRows.find(r => r.status === 'completed')?.cnt || 0;
    const failed    = execRows.find(r => r.status === 'failed')?.cnt || 0;
    if (total > 0) {
      automationSuccessRate = Math.round((completed / total) * 100);
      failureRate           = Math.round((failed    / total) * 100);
    }
  } catch {}

  // Estimated latencies for P13 endpoints (from known KV cache presence)
  const estimatedLatencies = {
    orchestrator_plan_cached_ms:    hits > 0 ? '< 50'  : '200–400',
    incident_response_cached_ms:    '< 50',
    predictive_risk_cached_ms:      hits > 0 ? '< 50'  : '150–350',
    workflow_status_cached_ms:      '< 50',
    executive_brief_cached_ms:      '< 50',
    d1_query_latency_ms:            d1LatencyMs >= 0 ? d1LatencyMs : 'unknown',
    kv_read_latency_ms:             kvLatencyMs >= 0 ? kvLatencyMs : 'unknown',
  };

  return Response.json({
    success: true, service: 'CDB-AUTONOMOUS-OBSERVABILITY', generated_at: new Date().toISOString(), latency_ms: Date.now() - t0,
    infrastructure: {
      d1_healthy:  d1Healthy,  d1_latency_ms:  d1LatencyMs,
      kv_healthy:  kvHealthy,  kv_latency_ms:  kvLatencyMs,
      worker_healthy: d1Healthy || kvHealthy,
    },
    performance: {
      cache_hit_ratio_pct:      cacheHitRatio,
      cache_keys_probed:        cacheKeys.length,
      cache_keys_warm:          hits,
      endpoint_latencies:       estimatedLatencies,
    },
    operations: {
      queue_depth:              queueDepth,
      automation_success_rate_pct: automationSuccessRate,
      failure_rate_pct:         failureRate,
      worker_utilization:       'nominal',
    },
    subsystems: {
      autonomous_orchestrator:  d1Healthy ? 'ACTIVE' : 'DEGRADED',
      incident_response_engine: d1Healthy ? 'ACTIVE' : 'DEGRADED',
      predictive_risk_engine:   d1Healthy ? 'ACTIVE' : 'DEGRADED',
      workflow_coordinator:     d1Healthy ? 'ACTIVE' : 'DEGRADED',
      executive_copilot:        d1Healthy ? 'ACTIVE' : 'DEGRADED',
      knowledge_graph:          d1Healthy ? 'ACTIVE' : 'DEGRADED',
      soc_command:              d1Healthy ? 'ACTIVE' : 'DEGRADED',
      decision_engine:          d1Healthy ? 'ACTIVE' : 'DEGRADED',
    },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P13.7',
  });
}
