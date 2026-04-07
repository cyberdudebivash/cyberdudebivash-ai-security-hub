/**
 * AGENT HANDLER — REST API for Agentic AI Autonomous Remediation Engine (System 1)
 *
 * Routes:
 *   POST /api/agent/execute           — Execute a specific agent action
 *   GET  /api/agent/logs              — Paginated action history
 *   GET  /api/agent/status            — System status + queue stats
 *   POST /api/agent/rollback          — Rollback a previous action
 *   GET  /api/agent/waf               — Active WAF patches
 *   POST /api/agent/waf/patch         — Manual WAF patch
 *   POST /api/agent/waf/rollback      — Rollback specific patch
 *   GET  /api/agent/waf/stats         — WAF stats
 *   POST /api/agent/process-queue     — Process pending event queue (manual trigger)
 */

import { executeThreatResponse, runThreatResponseBatch } from '../agents/threatResponseAgent.js';
import { executeCredentialRotation }                     from '../agents/credentialRotationAgent.js';
import { executeIsolation }                              from '../agents/isolationAgent.js';
import { executePatching, rollbackPatch, listActivePatches, getWAFStats } from '../agents/patchingAgent.js';
import { executeRollback }                               from '../agents/actionExecutor.js';
import { consumeEvents, ackEvent, getQueueStats }        from '../agents/agentBus.js';
import { processCVEEvent }                               from '../agents/threatResponseAgent.js';
import { decideAnomalyResponse }                         from '../agents/decisionEngine.js';
import { autoBlockIP, isIPBlocked }                      from '../agents/isolationAgent.js';
import { autoRotateOnAnomaly }                           from '../agents/credentialRotationAgent.js';

function now() { return new Date().toISOString(); }

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Route dispatcher for /api/agent/*
 */
export async function handleAgentRequest(request, env, authCtx, subpath) {
  const method = request.method;

  // POST /api/agent/execute
  if (subpath === 'execute' && method === 'POST') {
    return handleExecute(request, env, authCtx);
  }

  // GET /api/agent/logs
  if (subpath === 'logs' && method === 'GET') {
    return handleLogs(request, env);
  }

  // GET /api/agent/status
  if (subpath === 'status' && method === 'GET') {
    return handleStatus(request, env);
  }

  // POST /api/agent/rollback
  if (subpath === 'rollback' && method === 'POST') {
    return handleRollback(request, env, authCtx);
  }

  // GET /api/agent/waf
  if (subpath === 'waf' && method === 'GET') {
    const patches = await listActivePatches(env);
    return jsonRes(patches);
  }

  // POST /api/agent/waf/patch
  if (subpath === 'waf/patch' && method === 'POST') {
    const result = await executePatching(env, request, authCtx);
    return jsonRes(result, result.status || 200);
  }

  // POST /api/agent/waf/rollback
  if (subpath === 'waf/rollback' && method === 'POST') {
    const result = await rollbackPatch(env, request, authCtx);
    return jsonRes(result, result.status || 200);
  }

  // GET /api/agent/waf/stats
  if (subpath === 'waf/stats' && method === 'GET') {
    const stats = await getWAFStats(env);
    return jsonRes(stats);
  }

  // POST /api/agent/process-queue
  if (subpath === 'process-queue' && method === 'POST') {
    return handleProcessQueue(request, env);
  }

  return jsonRes({ error: 'Not found', subpath }, 404);
}

/**
 * Execute any agent action
 * Body: { agent_type, ...agent-specific params }
 * agent_type: 'threat_response' | 'credential_rotation' | 'isolation' | 'patching'
 */
async function handleExecute(request, env, authCtx) {
  let body;
  try { body = await request.json(); }
  catch { return jsonRes({ error: 'Invalid JSON body' }, 400); }

  const { agent_type } = body;
  if (!agent_type) return jsonRes({ error: 'agent_type required' }, 400);

  // Re-create a fake request with the same body for agent functions that expect request
  const agentRequest = new Request(request.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  let result;
  switch (agent_type) {
    case 'threat_response':
      result = await executeThreatResponse(env, agentRequest, authCtx);
      break;

    case 'credential_rotation':
      result = await executeCredentialRotation(env, agentRequest, authCtx);
      break;

    case 'isolation':
      result = await executeIsolation(env, agentRequest, authCtx);
      break;

    case 'patching':
      result = await executePatching(env, agentRequest, authCtx);
      break;

    default:
      return jsonRes({ error: `Unknown agent_type: ${agent_type}. Valid: threat_response, credential_rotation, isolation, patching` }, 400);
  }

  const status = result?.status || (result?.error ? 400 : 200);
  return jsonRes(result, status);
}

/**
 * GET /api/agent/logs
 * Query params: agent_type, target, status, limit (max 100), offset
 */
async function handleLogs(request, env) {
  const url    = new URL(request.url);
  const type   = url.searchParams.get('agent_type') || '';
  const target = url.searchParams.get('target')     || '';
  const status = url.searchParams.get('status')     || '';
  const limit  = Math.min(parseInt(url.searchParams.get('limit')  || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  let query = `
    SELECT id, agent_type, action_type, target, target_type,
           trigger_source, risk_level, decision_score, execution_status,
           duration_ms, rollback_available, created_at, completed_at, error_message
    FROM agent_actions
    WHERE 1=1
  `;
  const binds = [];

  if (type)   { query += ` AND agent_type=?`;     binds.push(type); }
  if (target) { query += ` AND target LIKE ?`;    binds.push(`%${target}%`); }
  if (status) { query += ` AND execution_status=?`; binds.push(status); }

  query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  binds.push(limit, offset);

  const rows = await env.DB.prepare(query).bind(...binds).all().catch(() => ({ results: [] }));

  // Total count for pagination
  let countQuery = `SELECT COUNT(*) as cnt FROM agent_actions WHERE 1=1`;
  const countBinds = [];
  if (type)   { countQuery += ` AND agent_type=?`;     countBinds.push(type); }
  if (target) { countQuery += ` AND target LIKE ?`;    countBinds.push(`%${target}%`); }
  if (status) { countQuery += ` AND execution_status=?`; countBinds.push(status); }

  const total = await env.DB.prepare(countQuery).bind(...countBinds).first().catch(() => ({ cnt: 0 }));

  return jsonRes({
    logs:      rows.results || [],
    total:     total?.cnt || 0,
    limit,
    offset,
    timestamp: now(),
  });
}

/**
 * GET /api/agent/status
 * Returns: queue stats, recent action summary, system health
 */
async function handleStatus(request, env) {
  const [queueStats, recentSummary, actionCounts, wafStats] = await Promise.all([
    getQueueStats(env),
    env.DB.prepare(`
      SELECT execution_status, COUNT(*) as cnt
      FROM agent_actions
      WHERE created_at > datetime('now', '-1 hour')
      GROUP BY execution_status
    `).all().catch(() => ({ results: [] })),
    env.DB.prepare(`
      SELECT agent_type, execution_status, COUNT(*) as cnt
      FROM agent_actions
      WHERE created_at > datetime('now', '-24 hours')
      GROUP BY agent_type, execution_status
    `).all().catch(() => ({ results: [] })),
    getWAFStats(env),
  ]);

  // Build summary object
  const last1h = {};
  for (const r of (recentSummary.results || [])) {
    last1h[r.execution_status] = r.cnt;
  }

  const byAgent = {};
  for (const r of (actionCounts.results || [])) {
    if (!byAgent[r.agent_type]) byAgent[r.agent_type] = {};
    byAgent[r.agent_type][r.execution_status] = r.cnt;
  }

  return jsonRes({
    system:        'OPERATIONAL',
    queue:         queueStats,
    last_1h:       last1h,
    last_24h_by_agent: byAgent,
    waf:           { active_patches: wafStats.active_patches },
    timestamp:     now(),
  });
}

/**
 * POST /api/agent/rollback
 * Body: { action_id }
 */
async function handleRollback(request, env, authCtx) {
  let body;
  try { body = await request.json(); }
  catch { return jsonRes({ error: 'Invalid JSON body' }, 400); }

  const { action_id } = body;
  if (!action_id) return jsonRes({ error: 'action_id required' }, 400);

  const action = await env.DB.prepare(
    `SELECT id, action_type, target, execution_status, rollback_available FROM agent_actions WHERE id=? LIMIT 1`
  ).bind(action_id).first().catch(() => null);

  if (!action) return jsonRes({ error: `Action ${action_id} not found` }, 404);
  if (!action.rollback_available) return jsonRes({ error: 'Rollback not available for this action' }, 409);
  if (action.execution_status === 'ROLLED_BACK') return jsonRes({ error: 'Already rolled back' }, 409);

  const result = await executeRollback(env, action_id);

  return jsonRes({
    success:    result.success,
    action_id,
    target:     action.target,
    timestamp:  now(),
    detail:     result.detail,
  }, result.success ? 200 : 500);
}

/**
 * POST /api/agent/process-queue
 * Manually triggers event queue processing (normally done by cron)
 */
async function handleProcessQueue(request, env) {
  const events = await consumeEvents(env, 20);
  if (events.length === 0) {
    return jsonRes({ processed: 0, message: 'No pending events', timestamp: now() });
  }

  const results = [];

  for (const event of events) {
    try {
      let result = null;

      if (event.event_type === 'cve_detected') {
        result = await processCVEEvent(env, event);
      } else if (event.event_type === 'anomaly_detected') {
        const decision = decideAnomalyResponse(event.payload || {});
        const actions  = [];

        for (const action of decision.actions) {
          if (action.action_type === 'block_ip' && action.target) {
            const r = await autoBlockIP(env, action.target, 'anomaly_auto_block', decision.risk_level, event.id);
            actions.push(r);
          }
          if (action.action_type === 'rotate_credentials' && action.target) {
            const r = await autoRotateOnAnomaly(env, action.target, event.payload);
            if (r) actions.push(r);
          }
        }
        result = { event_type: 'anomaly_detected', actions_taken: actions.length, actions };
      }

      await ackEvent(env, event.id, true);
      results.push({ event_id: event.id, event_type: event.event_type, success: true, result });

    } catch (e) {
      await ackEvent(env, event.id, false, e.message);
      results.push({ event_id: event.id, event_type: event.event_type, success: false, error: e.message });
    }
  }

  return jsonRes({
    processed:  results.length,
    succeeded:  results.filter(r => r.success).length,
    failed:     results.filter(r => !r.success).length,
    results,
    timestamp:  now(),
  });
}
