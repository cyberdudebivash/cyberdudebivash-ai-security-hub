/**
 * CYBERDUDEBIVASH MYTHOS ORCHESTRATOR CORE v1.0
 * ═══════════════════════════════════════════════════════════════════════
 * FULLY AUTONOMOUS AI CYBERSECURITY RESPONSE ENGINE
 *
 * PIPELINE:
 *   [Intel Feed] → [Intel Agent] → [Planner Agent] → [Task Breakdown]
 *   → [Tool Builder] → [Execution Sandbox] → [Validation Engine]
 *   → [Self-Correction Loop] → [Solution Pack] → [Marketplace Publisher]
 *   → [Dashboard Output]
 * ═══════════════════════════════════════════════════════════════════════
 */

import { getPendingSolutionIntel, markSolutionGenerated } from './intelIngestionEngine.js';
import { generateDefenseTool, calculatePrice, storeDefenseSolution } from './sentinelDefenseEngine.js';
import { analyzeIntel }        from '../agents/intelAgent.js';
import { buildTaskPlan }       from '../agents/plannerAgent.js';
import { validateArtifact }    from './validationEngine.js';
import {
  generatePythonDetectionScript, generateIDSSignature, generateWAFRule,
  generateSigmaRule, generateHardeningScript, generateIRPlaybook,
  generateYARARule, generateThreatHuntPack,
  generateExecutiveBriefing, generateAPISecurityModule,
} from '../lib/solutionTemplates.js';

// ── KV namespace keys ─────────────────────────────────────────────────────────
const KV = {
  STATUS:  'mythos:status',
  LAST:    'mythos:last_run',
  METRICS: 'mythos:metrics',
  JOB:     id => `mythos:jobs:${id}`,
  PROG:    id => `mythos:progress:${id}`,
};

// ── Tool generator dispatch table ─────────────────────────────────────────────
const GENERATORS = {
  firewall_script:  (i, a) => generateWAFRule(i, a),
  sigma_rule:       (i, a) => generateSigmaRule(i, a),
  yara_rule:        (i, a) => generateYARARule(i, a),
  ir_playbook:      (i, a) => generateIRPlaybook(i, a),
  ids_signature:    (i, a) => generateIDSSignature(i, a),
  hardening_script: (i, a) => generateHardeningScript(i, a),
  threat_hunt_pack: (i, a) => generateThreatHuntPack(i, a),
  python_scanner:   (i, a) => generatePythonDetectionScript(i, a),
  exec_briefing:    (i, a) => generateExecutiveBriefing(i, a),
  api_module:       (i, a) => generateAPISecurityModule(i, a),
};

// ── Execute one tool-generation task with self-correction loop ────────────────
async function executeToolTask(task, intel, analysis, env) {
  const gen = GENERATORS[task.tool_type];
  if (!gen) return { success: false, error: `No generator for: ${task.tool_type}`, tool_type: task.tool_type };

  const MAX = task.max_retries || 3;
  let content = null, validation = null;

  for (let attempt = 1; attempt <= MAX; attempt++) {
    try {
      // ── STAGE 6: Tool Builder ───────────────────────────────────────────
      content = gen(intel, analysis);
      if (!content || typeof content !== 'string' || content.trim().length < 50) {
        throw new Error(`Generator returned empty/invalid content on attempt ${attempt}`);
      }

      // ── STAGE 7: Execution Sandbox (syntax + logic check) ──────────────
      validation = validateArtifact(content, task.tool_type);

      if (!validation.safe) {
        // Safety violation — HARD STOP, do not retry
        return { success: false, error: 'Safety gate violation', tool_type: task.tool_type,
                 violations: validation.errors, attempts: attempt };
      }

      if (validation.valid) {
        // ── STAGE 10: Marketplace Publisher ────────────────────────────
        const pricing = calculatePrice(intel, task.tool_type);
        await storeDefenseSolution(env, intel, task.tool_type, content, pricing);
        return { success: true, tool_type: task.tool_type, attempt, content_length: content.length,
                 score: validation.score, price_inr: pricing?.inr || pricing?.price_inr || 0 };
      }

      // ── STAGE 8: Self-Correction — log errors and retry ─────────────
      console.warn(`[MYTHOS] ${task.id} attempt ${attempt}/${MAX} failed validation:`, validation.errors.join('; '));

      if (attempt === MAX) {
        // Final attempt: publish marginal content if length is acceptable
        if (content.length > 300 && validation.errors.length <= 2 && validation.safe) {
          const pricing = calculatePrice(intel, task.tool_type);
          await storeDefenseSolution(env, intel, task.tool_type, content, pricing);
          return { success: true, tool_type: task.tool_type, attempt, content_length: content.length,
                   score: validation.score, quality: 'MARGINAL', price_inr: pricing?.inr || 0 };
        }
        return { success: false, error: `Validation failed after ${MAX} attempts`,
                 tool_type: task.tool_type, last_errors: validation.errors, attempts: attempt };
      }
    } catch (err) {
      console.error(`[MYTHOS] ${task.id} attempt ${attempt} threw:`, err.message);
      if (attempt === MAX) return { success: false, error: err.message, tool_type: task.tool_type, attempts: attempt };
    }
  }
  return { success: false, error: 'Max retries exceeded', tool_type: task.tool_type };
}

// ── Process a single intel item through the full 12-stage pipeline ────────────
async function processIntelItem(intel, env, jobId) {
  const result = {
    intel_id: intel.id || intel.cve_id,
    cve_id:   intel.cve_id || intel.id,
    severity: intel.severity,
    started_at: new Date().toISOString(),
    stages: {},
    tools_generated: [],
    tools_failed:    [],
    published: false,
    error: null,
  };

  try {
    // ── STAGE 2: Intel Agent ──────────────────────────────────────────────
    result.stages.intel_agent = 'RUNNING';
    const analysis = await analyzeIntel(intel, env);
    result.stages.intel_agent = 'COMPLETE';
    result.analysis_summary = { risk_level: analysis.risk_level, risk_score: analysis.risk_score,
                                urgency: analysis.urgency, ai_enhanced: analysis.ai_enhanced };

    // ── STAGE 3-4: Planner Agent + Task Breakdown ─────────────────────────
    result.stages.planner = 'RUNNING';
    const plan = buildTaskPlan(intel, analysis);
    result.stages.planner = 'COMPLETE';
    result.plan_summary = { plan_id: plan.plan_id, tools: plan.tools, tool_count: plan.tool_count };

    // ── STAGES 5-9: Tool Builder → Validation → Self-Correction → Pack ────
    result.stages.generation = 'RUNNING';
    const toolTasks = plan.tasks.filter(t => t.type === 'GENERATE_TOOL');

    for (const task of toolTasks) {
      const tr = await executeToolTask(task, intel, analysis, env);
      if (tr.success) {
        result.tools_generated.push({ tool_type: tr.tool_type, attempts: tr.attempts,
                                      score: tr.score, price_inr: tr.price_inr, quality: tr.quality || 'GOOD' });
      } else {
        result.tools_failed.push({ tool_type: tr.tool_type, error: tr.error });
      }
      // Persist progress to KV so API can show real-time status
      await env.SECURITY_HUB_KV?.put(KV.PROG(jobId), JSON.stringify({
        intel_id: result.intel_id, done: result.tools_generated.length,
        failed: result.tools_failed.length, total: toolTasks.length,
      }), { expirationTtl: 3600 }).catch(() => {});
    }
    result.stages.generation = 'COMPLETE';

    // ── STAGE 10-11: Solution Pack + Marketplace Publish ─────────────────
    result.stages.publish = 'RUNNING';
    if (result.tools_generated.length > 0) {
      await markSolutionGenerated(env, result.intel_id, `mythos_${jobId}`);
      result.published = true;
      // Invalidate marketplace cache
      const keys = await env.SECURITY_HUB_KV?.list({ prefix: 'cache:defense:' }).catch(() => ({ keys: [] }));
      await Promise.all((keys?.keys || []).map(k => env.SECURITY_HUB_KV?.delete(k.name).catch(() => {})));
    }
    result.stages.publish = 'COMPLETE';

  } catch (err) {
    console.error(`[MYTHOS] processIntelItem ${result.intel_id} crashed:`, err);
    result.error = err.message;
    result.stages.error = err.message;
  }

  result.completed_at = new Date().toISOString();
  result.duration_ms  = Date.now() - new Date(result.started_at).getTime();
  return result;
}

// ── Finalize job: persist to KV + D1 + update metrics ────────────────────────
async function finalizeJob(env, jobId, result) {
  result.completed_at = new Date().toISOString();
  result.duration_ms  = Date.now() - new Date(result.started_at).getTime();

  // Full job result → KV (7-day TTL)
  await env.SECURITY_HUB_KV?.put(KV.JOB(jobId), JSON.stringify(result), { expirationTtl: 604800 }).catch(() => {});

  // Last-run metadata → KV
  await env.SECURITY_HUB_KV?.put(KV.LAST, JSON.stringify({
    job_id: jobId, completed_at: result.completed_at, status: result.status,
    tools_generated: result.total_tools, total_published: result.total_published, duration_ms: result.duration_ms,
  }), { expirationTtl: 604800 }).catch(() => {});

  // Aggregated lifetime metrics → KV
  try {
    const m = await env.SECURITY_HUB_KV?.get(KV.METRICS, 'json') || {};
    await env.SECURITY_HUB_KV?.put(KV.METRICS, JSON.stringify({
      total_runs:      (m.total_runs      || 0) + 1,
      total_tools:     (m.total_tools     || 0) + (result.total_tools     || 0),
      total_published: (m.total_published || 0) + (result.total_published || 0),
      total_failed:    (m.total_failed    || 0) + (result.total_failed    || 0),
      last_run:        result.completed_at,
    }), { expirationTtl: 86400 * 30 });
  } catch { /* metrics are non-critical */ }

  // Clear running flag
  await env.SECURITY_HUB_KV?.put(KV.STATUS, JSON.stringify({
    running: false, last_job_id: jobId, last_run_at: result.completed_at, last_status: result.status,
  }), { expirationTtl: 604800 }).catch(() => {});

  // D1 audit log (non-blocking)
  env.DB?.prepare(
    `INSERT OR IGNORE INTO mythos_runs
     (id, status, tools_generated, tools_published, tools_failed, duration_ms, intel_count, run_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(jobId, result.status, result.total_tools || 0, result.total_published || 0,
         result.total_failed || 0, result.duration_ms || 0,
         result.total_intel || 0, result.completed_at).run().catch(e => console.warn('[MYTHOS] D1 log:', e.message));
}

// ── MASTER ORCHESTRATION RUN (exported) ──────────────────────────────────────
export async function runMythosOrchestration(env, opts = {}) {
  const jobId     = `job_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const maxItems  = Math.min(opts.maxItems || 5, 20);

  // Set running status in KV immediately
  await env.SECURITY_HUB_KV?.put(KV.STATUS, JSON.stringify({
    running: true, job_id: jobId, started_at: new Date().toISOString(),
  }), { expirationTtl: 3600 }).catch(() => {});

  const job = {
    job_id: jobId, status: 'RUNNING', started_at: new Date().toISOString(),
    total_intel: 0, total_tools: 0, total_published: 0, total_failed: 0,
    items_processed: [], errors: [],
  };

  // Persist initial state
  await env.SECURITY_HUB_KV?.put(KV.JOB(jobId), JSON.stringify(job), { expirationTtl: 86400 }).catch(() => {});

  try {
    // ── STAGE 1: Intel Feed ───────────────────────────────────────────────
    const intelItems = opts.intelItems || await getPendingSolutionIntel(env, maxItems);

    if (!intelItems?.length) {
      job.status  = 'COMPLETE';
      job.message = 'No unprocessed threat intel — all items already have defense solutions';
      await finalizeJob(env, jobId, job);
      return job;
    }
    job.total_intel = intelItems.length;

    // ── Process each item through the full pipeline ───────────────────────
    for (const intel of intelItems) {
      try {
        const itemResult = await processIntelItem(intel, env, jobId);
        job.items_processed.push(itemResult);
        job.total_tools     += itemResult.tools_generated.length;
        job.total_failed    += itemResult.tools_failed.length;
        if (itemResult.published) job.total_published++;
      } catch (err) {
        job.errors.push({ intel_id: intel.id || intel.cve_id, error: err.message });
      }
    }
    job.status = job.errors.length && !job.total_published ? 'FAILED' : 'COMPLETE';

  } catch (err) {
    console.error('[MYTHOS] Orchestration run crashed:', err);
    job.status = 'FAILED';
    job.error  = err.message;
  }

  await finalizeJob(env, jobId, job);
  return job;
}

// ── Get orchestration status (exported) ──────────────────────────────────────
export async function getMythosStatus(env) {
  const [status, lastRun, metrics] = await Promise.all([
    env.SECURITY_HUB_KV?.get(KV.STATUS,  'json').catch(() => null),
    env.SECURITY_HUB_KV?.get(KV.LAST,    'json').catch(() => null),
    env.SECURITY_HUB_KV?.get(KV.METRICS, 'json').catch(() => null),
  ]);

  let recentRuns = [];
  try {
    const rows = await env.DB?.prepare(
      `SELECT id, status, tools_generated, tools_published, tools_failed, duration_ms, intel_count, run_at
       FROM mythos_runs ORDER BY run_at DESC LIMIT 5`
    ).all();
    recentRuns = rows?.results || [];
  } catch { /* table may not exist yet — first run */ }

  return {
    orchestrator:    'CYBERDUDEBIVASH MYTHOS CORE v1.0',
    is_running:      !!status?.running,
    current_job:     status?.running ? status.job_id : null,
    last_run:        lastRun  || null,
    metrics:         metrics  || { total_runs: 0, total_tools: 0, total_published: 0, total_failed: 0 },
    recent_runs:     recentRuns,
    pipeline_stages: [
      '1. Intel Feed', '2. Intel Agent (AI)', '3. Planner Agent',
      '4. Task Breakdown', '5. Tool Builder', '6. Execution Sandbox',
      '7. Validation Engine', '8. Self-Correction Loop',
      '9. Solution Pack', '10. Marketplace Publisher', '11. Dashboard Output',
    ],
  };
}

// ── Get specific job result (exported) ───────────────────────────────────────
export async function getMythosJob(env, jobId) {
  if (jobId === 'latest') {
    const last = await env.SECURITY_HUB_KV?.get(KV.LAST, 'json').catch(() => null);
    if (!last?.job_id) return null;
    jobId = last.job_id;
  }
  return env.SECURITY_HUB_KV?.get(KV.JOB(jobId), 'json').catch(() => null);
}

// ── Cron entry point (exported) ───────────────────────────────────────────────
export async function runMythosCron(env) {
  console.log('[MYTHOS CRON] Starting autonomous orchestration run...');
  try {
    const result = await runMythosOrchestration(env, { maxItems: 5 });
    console.log(`[MYTHOS CRON] Done — ${result.total_tools} tools generated, ${result.total_published} published`);
    return result;
  } catch (err) {
    console.error('[MYTHOS CRON] Critical failure:', err);
    throw err;
  }
}
