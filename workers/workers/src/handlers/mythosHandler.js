/**
 * CYBERDUDEBIVASH MYTHOS — HTTP Route Handler v1.0
 * ══════════════════════════════════════════════════
 * API endpoints for the MYTHOS Orchestrator:
 *   POST /api/mythos/run       — trigger orchestration
 *   GET  /api/mythos/status    — live pipeline status
 *   GET  /api/mythos/jobs/:id  — job details + results
 *   POST /api/mythos/validate  — validate any artifact
 *   POST /api/mythos/analyze   — analyze a CVE
 *   GET  /api/mythos/metrics   — lifetime metrics
 */

import { runMythosOrchestration, getMythosStatus, getMythosJob } from '../services/mythosOrchestrator.js';
import { validateArtifact }  from '../services/validationEngine.js';
import { analyzeIntel }      from '../agents/intelAgent.js';
import { buildTaskPlan }     from '../agents/plannerAgent.js';

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
});

// ── POST /api/mythos/run ──────────────────────────────────────────────────────
export async function handleMythosRun(request, env, authCtx) {
  if (authCtx?.role !== 'admin') return json({ success: false, error: 'Admin access required' }, 403);

  const live = await env.SECURITY_HUB_KV?.get('mythos:status', 'json').catch(() => null);
  if (live?.running) return json({
    success: false, error: 'Orchestration already running',
    job_id: live.job_id, started_at: live.started_at,
  }, 409);

  const body       = await request.json().catch(() => ({}));
  const maxItems   = Math.min(parseInt(body.max_items || '5'), 20);
  const filterCve  = body.cve_id || null;

  // Fire-and-forget — orchestration runs asynchronously
  const jobPromise = runMythosOrchestration(env, { maxItems, filterCveId: filterCve });
  jobPromise.catch(err => console.error('[MYTHOS API] run crashed:', err));

  // Give KV 150ms to record the new job_id before we read it back
  await new Promise(r => setTimeout(r, 150));
  const newStatus = await env.SECURITY_HUB_KV?.get('mythos:status', 'json').catch(() => null);

  return json({
    success:    true,
    message:    `MYTHOS orchestration started — processing up to ${maxItems} threat intel items`,
    job_id:     newStatus?.job_id || 'starting',
    status_url: '/api/mythos/status',
    poll_url:   `/api/mythos/jobs/${newStatus?.job_id || 'latest'}`,
  });
}

// ── GET /api/mythos/status ────────────────────────────────────────────────────
export async function handleMythosStatus(request, env, authCtx) {
  try {
    const status = await getMythosStatus(env);
    return json({ success: true, ...status });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/jobs/:jobId ───────────────────────────────────────────────
export async function handleMythosJob(request, env, authCtx, jobId) {
  if (!jobId) return json({ success: false, error: 'Job ID required' }, 400);
  const job = await getMythosJob(env, jobId);
  if (!job) return json({ success: false, error: `Job not found: ${jobId}` }, 404);
  return json({ success: true, job });
}

// ── POST /api/mythos/validate ─────────────────────────────────────────────────
export async function handleMythosValidate(request, env, authCtx) {
  const body = await request.json().catch(() => null);
  if (!body?.content || !body?.type)
    return json({ success: false, error: 'Required fields: content (string), type (string)' }, 400);

  const validation = validateArtifact(body.content, body.type);
  return json({
    success:    true,
    validation,
    summary:    validation.valid
      ? `✅ Artifact valid — quality score ${validation.score}/100`
      : `❌ Validation failed — ${validation.errors.length} error(s): ${validation.errors.join('; ')}`,
  });
}

// ── POST /api/mythos/analyze ──────────────────────────────────────────────────
export async function handleMythosAnalyze(request, env, authCtx) {
  const body = await request.json().catch(() => null);
  if (!body) return json({ success: false, error: 'Request body required' }, 400);

  try {
    // Accept: { intel: {...} } OR { cve_id: "CVE-XXXX-YYYY" }
    let intel = body.intel || body;
    if (body.cve_id && !body.intel) {
      const row = await env.DB?.prepare(
        `SELECT * FROM threat_intel WHERE id = ? OR cve_id = ? LIMIT 1`
      ).bind(body.cve_id, body.cve_id).first();
      if (!row) return json({ success: false, error: `CVE ${body.cve_id} not found in database` }, 404);
      intel = row;
    }

    const analysis = await analyzeIntel(intel, env);
    const plan     = buildTaskPlan(intel, analysis);

    return json({
      success:   true,
      intel_id:  intel.id || intel.cve_id,
      analysis:  { risk_level: analysis.risk_level, risk_score: analysis.risk_score,
                   urgency: analysis.urgency, ai_enhanced: analysis.ai_enhanced,
                   narrative: analysis.narrative, attack_vectors: analysis.attack_vectors,
                   mitre_techniques: analysis.mitre_techniques, immediate_actions: analysis.immediate_actions },
      task_plan: { plan_id: plan.plan_id, tool_count: plan.tool_count, urgency: plan.urgency,
                   tools: plan.tools, estimated_value_inr: plan.estimated_value_inr },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ── GET /api/mythos/metrics ───────────────────────────────────────────────────
export async function handleMythosMetrics(request, env, authCtx) {
  try {
    const [metrics, lastRun, mktStats, intelStats] = await Promise.all([
      env.SECURITY_HUB_KV?.get('mythos:metrics', 'json').catch(() => null),
      env.SECURITY_HUB_KV?.get('mythos:last_run', 'json').catch(() => null),
      env.DB?.prepare(`SELECT COUNT(*) as total, SUM(purchase_count) as sales, SUM(view_count) as views FROM defense_solutions WHERE is_active=1`).first().catch(() => null),
      env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN solution_generated=1 THEN 1 ELSE 0 END) as processed FROM threat_intel`).first().catch(() => null),
    ]);
    return json({
      success:    true,
      mythos:     metrics || { total_runs: 0, total_tools: 0, total_published: 0, total_failed: 0 },
      last_run:   lastRun || null,
      marketplace:{ total_solutions: mktStats?.total || 0, total_sales: mktStats?.sales || 0, total_views: mktStats?.views || 0 },
      intel_feed: { total: intelStats?.total || 0, processed: intelStats?.processed || 0,
                    pending: (intelStats?.total || 0) - (intelStats?.processed || 0) },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
