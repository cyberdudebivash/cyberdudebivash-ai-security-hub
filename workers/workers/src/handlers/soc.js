/**
 * CYBERDUDEBIVASH AI Security Hub — SOC API Handler v1.0
 * Sentinel APEX v3: Global Threat Intelligence + SOC Automation + Autonomous Defense
 *
 * Endpoints:
 *   GET  /api/v1/alerts           → SOC detection alerts (PRO/ENTERPRISE)
 *   GET  /api/v1/decisions        → AI decision engine results (ENTERPRISE)
 *   GET  /api/v1/defense-actions  → Autonomous defense action log (ENTERPRISE)
 *   GET  /api/v1/federation       → Global feed + source scores + node identity (PRO/ENTERPRISE)
 *   POST /api/v1/soc/analyze      → Run full SOC pipeline on-demand (ENTERPRISE)
 *   GET  /api/v1/soc/posture      → Defense posture summary (PRO/ENTERPRISE)
 *   GET  /api/soc/dashboard       → SOC dashboard data (plan-gated)
 */

import { runDetection, getStoredAlerts, storeDetectionResults } from '../services/detectionEngine.js';
import { buildResponsePlan, storeResponsePlan }                  from '../services/responseEngine.js';
import { runDecisionEngine, storeDecisions }                     from '../services/decisionEngine.js';
import { runAutonomousDefense, storeDefenseActions, getDefensePosture } from '../services/defenseEngine.js';
import { runFederation, getNodeIdentity }                        from '../services/federationEngine.js';
import { SEED_ENTRIES }                                          from '../services/threatIngestion.js';
import { enrichBatch }                                           from '../services/enrichment.js';
import { ok, fail }                                              from '../lib/response.js';

// ─── Plan gates ───────────────────────────────────────────────────────────────
const PLAN_CAPS = {
  FREE:       { alerts: 0,   decisions: false, defense: false, federation: false, soc_analyze: false },
  STARTER:    { alerts: 10,  decisions: false, defense: false, federation: false, soc_analyze: false },
  PRO:        { alerts: 50,  decisions: false, defense: false, federation: true,  soc_analyze: false },
  ENTERPRISE: { alerts: 200, decisions: true,  defense: true,  federation: true,  soc_analyze: true  },
};

function getCap(tier) { return PLAN_CAPS[tier] || PLAN_CAPS.FREE; }

// ─── Fetch entries from D1 or seed fallback ───────────────────────────────────
async function fetchEntries(env, limit = 100) {
  if (env?.DB) {
    try {
      const rows = await env.DB.prepare(
        `SELECT * FROM threat_intel
         WHERE severity IN ('CRITICAL','HIGH')
         ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC, cvss DESC
         LIMIT ?`
      ).bind(limit).all();
      if (rows?.results?.length > 0) return rows.results;
    } catch {}
  }
  return SEED_ENTRIES.map(e => ({ ...e }));
}

// ─── GET /api/v1/alerts ───────────────────────────────────────────────────────
export async function handleGetAlerts(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = getCap(tier);

  if (caps.alerts === 0) {
    return fail(request, 'SOC alert API requires STARTER or higher plan', 403, 'PLAN_REQUIRED');
  }

  const url       = new URL(request.url);
  const severity  = url.searchParams.get('severity') || '';
  const alertType = url.searchParams.get('type') || '';
  const limit     = Math.min(caps.alerts, parseInt(url.searchParams.get('limit') || '50', 10));

  // Try stored alerts from D1
  let alerts = await getStoredAlerts(env, limit, severity || null);

  // If no stored alerts — run detection on current feed
  if (alerts.length === 0) {
    const entries       = await fetchEntries(env, 100);
    const enriched      = enrichBatch(entries.map(e => ({ ...e })));
    const detResult     = runDetection(enriched);
    alerts = detResult.alerts;

    // Filter
    if (severity)  alerts = alerts.filter(a => a.severity === severity.toUpperCase());
    if (alertType) alerts = alerts.filter(a => a.alert_type === alertType);

    alerts = alerts.slice(0, limit);

    // Store for subsequent requests (async, non-blocking)
    storeDetectionResults(env, detResult).catch(() => {});
  }

  return ok(request, {
    alerts,
    total:        alerts.length,
    plan:         tier,
    generated_at: new Date().toISOString(),
  });
}

// ─── GET /api/v1/decisions ────────────────────────────────────────────────────
export async function handleGetDecisions(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = getCap(tier);

  if (!caps.decisions) {
    return fail(request, 'AI decision engine requires ENTERPRISE plan', 403, 'ENTERPRISE_REQUIRED');
  }

  const url   = new URL(request.url);
  const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10));

  // Try D1 stored decisions
  if (env?.DB) {
    try {
      const rows = await env.DB.prepare(
        `SELECT * FROM soc_decisions ORDER BY created_at DESC LIMIT ?`
      ).bind(limit).all();

      if (rows?.results?.length > 0) {
        return ok(request, {
          decisions:    rows.results,
          total:        rows.results.length,
          source:       'd1_cache',
          plan:         tier,
          generated_at: new Date().toISOString(),
        });
      }
    } catch {}
  }

  // Run fresh decision engine
  const entries     = await fetchEntries(env, 100);
  const enriched    = enrichBatch(entries.map(e => ({ ...e })));
  const detResult   = runDetection(enriched);
  const decResult   = runDecisionEngine(enriched, detResult);

  const decisions = decResult.decisions.slice(0, limit);

  // Store async
  storeDecisions(env, decResult).catch(() => {});

  return ok(request, {
    decisions,
    total:               decisions.length,
    overall_threat_level: decResult.overall_threat_level,
    escalation_required: decResult.escalation_required,
    p1_count:            decResult.p1_count,
    p2_count:            decResult.p2_count,
    by_decision:         decResult.by_decision,
    plan:                tier,
    generated_at:        new Date().toISOString(),
  });
}

// ─── GET /api/v1/defense-actions ──────────────────────────────────────────────
export async function handleGetDefenseActions(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = getCap(tier);

  if (!caps.defense) {
    return fail(request, 'Autonomous defense API requires ENTERPRISE plan', 403, 'ENTERPRISE_REQUIRED');
  }

  const url   = new URL(request.url);
  const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '30', 10));
  const fresh = url.searchParams.get('fresh') === '1';

  // Try stored defense actions from D1
  if (env?.DB && !fresh) {
    try {
      const rows = await env.DB.prepare(
        `SELECT * FROM soc_defense_actions ORDER BY created_at DESC LIMIT ?`
      ).bind(limit).all();

      if (rows?.results?.length > 0) {
        const posture = await getDefensePosture(env);
        return ok(request, {
          defense_actions: rows.results,
          total:           rows.results.length,
          defense_posture: posture,
          source:          'd1_cache',
          plan:            tier,
          generated_at:    new Date().toISOString(),
        });
      }
    } catch {}
  }

  // Run fresh autonomous defense
  const entries      = await fetchEntries(env, 100);
  const enriched     = enrichBatch(entries.map(e => ({ ...e })));
  const detResult    = runDetection(enriched);
  const decResult    = runDecisionEngine(enriched, detResult);
  const defResult    = runAutonomousDefense(enriched, decResult.decisions);
  const posture      = await getDefensePosture(env);

  const defActions = defResult.defense_actions.slice(0, limit);

  // Store async
  storeDefenseActions(env, defResult).catch(() => {});

  return ok(request, {
    defense_actions:  defActions,
    total:            defActions.length,
    by_action:        defResult.by_action,
    defense_posture:  { ...posture, score: defResult.defense_posture, level: defResult.posture_level },
    containment_sim:  defResult.containment_sim,
    plan:             tier,
    generated_at:     new Date().toISOString(),
  });
}

// ─── GET /api/v1/federation ───────────────────────────────────────────────────
export async function handleGetFederation(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = getCap(tier);

  if (!caps.federation) {
    return fail(request, 'Global federation feed requires PRO or ENTERPRISE plan', 403, 'PLAN_REQUIRED');
  }

  // Try KV cache first (5 min TTL)
  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get('sentinel:federation:latest', { type: 'json' });
      if (cached?.global_feed?.length > 0) {
        return ok(request, { ...cached, cache_hit: true, plan: tier });
      }
    } catch {}
  }

  // Run fresh federation (uses existing D1/seed as base)
  const existingEntries = await fetchEntries(env, 80);
  const fedResult       = await runFederation(env, existingEntries);

  return ok(request, {
    ...fedResult,
    // Limit feed size by plan
    global_feed: fedResult.global_feed.slice(0, tier === 'ENTERPRISE' ? 100 : 50),
    plan:        tier,
  });
}

// ─── POST /api/v1/soc/analyze — Full SOC pipeline on-demand ──────────────────
export async function handleSOCAnalyze(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = getCap(tier);

  if (!caps.soc_analyze) {
    return fail(request, 'On-demand SOC analysis requires ENTERPRISE plan', 403, 'ENTERPRISE_REQUIRED');
  }

  const startTime = Date.now();

  // Full pipeline: fetch → enrich → detect → decide → respond → defend
  const entries       = await fetchEntries(env, 100);
  const enriched      = enrichBatch(entries.map(e => ({ ...e })));
  const detResult     = runDetection(enriched);
  const decResult     = runDecisionEngine(enriched, detResult);
  const respPlan      = buildResponsePlan(detResult);
  const defResult     = runAutonomousDefense(enriched, decResult.decisions);

  // Store all results asynchronously
  Promise.all([
    storeDetectionResults(env, detResult),
    storeDecisions(env, decResult),
    storeResponsePlan(env, respPlan),
    storeDefenseActions(env, defResult),
  ]).catch(() => {});

  return ok(request, {
    pipeline: 'sentinel_apex_v3',
    entries_analyzed:    enriched.length,
    detection: {
      total_alerts:    detResult.total,
      by_severity:     detResult.by_severity,
      critical_alerts: (detResult.by_severity?.CRITICAL || 0),
    },
    decisions: {
      total:               decResult.total,
      overall_threat_level: decResult.overall_threat_level,
      escalation_required:  decResult.escalation_required,
      p1_escalations:       decResult.p1_count,
    },
    response: {
      total_actions:   respPlan.total,
      immediate:       respPlan.immediate_count,
      by_priority:     respPlan.by_priority,
    },
    defense: {
      total_actions:   defResult.total_actions,
      posture_score:   defResult.defense_posture,
      posture_level:   defResult.posture_level,
    },
    // Include top alerts, decisions, actions
    top_alerts:          detResult.alerts.slice(0, 5),
    top_decisions:       decResult.decisions.slice(0, 5),
    top_defense_actions: defResult.defense_actions.slice(0, 5),
    pipeline_ms:         Date.now() - startTime,
    plan:                tier,
    analyzed_at:         new Date().toISOString(),
  });
}

// ─── GET /api/v1/soc/posture ──────────────────────────────────────────────────
export async function handleGetSOCPosture(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';
  const caps = getCap(tier);

  if (caps.alerts === 0) {
    return fail(request, 'SOC posture requires STARTER or higher plan', 403, 'PLAN_REQUIRED');
  }

  const [defPosture, alertCount, decisionCount] = await Promise.all([
    getDefensePosture(env),
    env?.DB
      ? env.DB.prepare(`SELECT COUNT(*) as n FROM soc_alerts WHERE created_at >= datetime('now', '-24 hours')`).first().catch(() => ({ n: 0 }))
      : Promise.resolve({ n: 0 }),
    env?.DB
      ? env.DB.prepare(`SELECT COUNT(*) as n FROM soc_decisions WHERE priority IN ('P1-CRITICAL','P2-HIGH') AND created_at >= datetime('now', '-24 hours')`).first().catch(() => ({ n: 0 }))
      : Promise.resolve({ n: 0 }),
  ]);

  // Compute overall SOC posture
  const alertsToday    = alertCount?.n || 0;
  const decisionsToday = decisionCount?.n || 0;
  const postureScore   = defPosture?.score ?? (defPosture?.posture === 'ACTIVE' ? 75 : 50);
  const postureLevel   = postureScore >= 80 ? 'STRONG' : postureScore >= 50 ? 'MODERATE' : 'WEAK';

  return ok(request, {
    posture: {
      score:            postureScore,
      level:            postureLevel,
      defense_status:   defPosture?.posture || 'STANDBY',
      alerts_24h:       alertsToday,
      decisions_24h:    decisionsToday,
      actions_24h:      defPosture?.actions_today || 0,
      top_actions:      defPosture?.top_actions || [],
    },
    threat_indicators: {
      active_defense:   (defPosture?.actions_today || 0) > 0,
      escalation_risk:  decisionsToday > 0,
      alert_surge:      alertsToday > 10,
    },
    plan:             tier,
    generated_at:     new Date().toISOString(),
  });
}

// ─── GET /api/soc/dashboard — Full SOC dashboard (plan-gated) ─────────────────
export async function handleSOCDashboard(request, env, authCtx = {}) {
  const tier = authCtx?.tier || 'FREE';

  if (tier === 'FREE') {
    return ok(request, {
      tier: 'FREE',
      upgrade_required: true,
      message: 'SOC Dashboard requires STARTER or higher plan',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
      preview: {
        platform: 'CYBERDUDEBIVASH AI Security Hub — Sentinel APEX v3',
        features: ['Real-time threat detection', 'AI decision engine', 'Autonomous defense', 'Global feed federation'],
      },
    });
  }

  // Parallel fetch all SOC data
  const [entries, posture] = await Promise.all([
    fetchEntries(env, 50),
    getDefensePosture(env),
  ]);

  const enriched  = enrichBatch(entries.map(e => ({ ...e })));
  const detResult = runDetection(enriched);

  // PRO gets detection + basic dashboard
  // ENTERPRISE gets full pipeline
  let decResult, respPlan, defResult;
  if (tier === 'ENTERPRISE') {
    decResult = runDecisionEngine(enriched, detResult);
    respPlan  = buildResponsePlan(detResult);
    defResult = runAutonomousDefense(enriched, decResult.decisions);
  }

  return ok(request, {
    dashboard: 'sentinel_apex_v3',
    node_identity: getNodeIdentity(env),
    threat_summary: {
      total_entries:     enriched.length,
      critical:          enriched.filter(e => e.severity === 'CRITICAL').length,
      high:              enriched.filter(e => e.severity === 'HIGH').length,
      actively_exploited: enriched.filter(e => e.exploit_status === 'confirmed').length,
      avg_cvss:          (enriched.reduce((s, e) => s + (e.cvss || 0), 0) / Math.max(enriched.length, 1)).toFixed(1),
    },
    detection: {
      total_alerts:     detResult.total,
      by_severity:      detResult.by_severity,
      by_type:          detResult.by_type,
      top_alerts:       detResult.alerts.slice(0, tier === 'ENTERPRISE' ? 10 : 5),
    },
    // ENTERPRISE-only sections
    decisions: tier === 'ENTERPRISE' ? {
      total:               decResult.total,
      overall_threat_level: decResult.overall_threat_level,
      escalation_required: decResult.escalation_required,
      top_decisions:       decResult.decisions.slice(0, 5),
    } : { gated: true, requires: 'ENTERPRISE' },
    response: tier === 'ENTERPRISE' ? {
      total_actions:    respPlan.total,
      immediate:        respPlan.immediate_count,
      top_actions:      respPlan.actions.slice(0, 5),
    } : { gated: true, requires: 'ENTERPRISE' },
    defense: tier === 'ENTERPRISE' ? {
      total_actions:    defResult.total_actions,
      posture_score:    defResult.defense_posture,
      posture_level:    defResult.posture_level,
      top_actions:      defResult.defense_actions.slice(0, 5),
    } : { gated: true, requires: 'ENTERPRISE' },
    defense_posture: posture,
    plan:            tier,
    generated_at:    new Date().toISOString(),
  });
}
