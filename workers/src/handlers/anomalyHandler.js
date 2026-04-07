/**
 * ANOMALY HANDLER — REST API for Behavioral Anomaly Detection Engine (System 2)
 *
 * Routes:
 *   GET  /api/anomaly/stats              — System-wide anomaly stats (24h)
 *   GET  /api/anomaly/:user_id           — Latest anomaly score for a user
 *   GET  /api/anomaly/:user_id/history   — Historical anomaly events for a user
 *   POST /api/anomaly/scan               — Manually trigger anomaly detection for user
 *   POST /api/anomaly/record             — Record a behavior event
 *   POST /api/anomaly/batch              — Run batch anomaly scan (cron-equivalent)
 */

import {
  detectAnomaly,
  getUserAnomalyHistory,
  getAnomalyStats,
  recordBehaviorEvent,
  runAnomalyBatch,
} from '../services/anomalyEngine.js';
import { decideAnomalyResponse }  from '../agents/decisionEngine.js';
import { autoBlockIP }             from '../agents/isolationAgent.js';
import { autoRotateOnAnomaly }     from '../agents/credentialRotationAgent.js';

function now() { return new Date().toISOString(); }

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Route dispatcher for /api/anomaly/*
 */
export async function handleAnomalyRequest(request, env, authCtx, subpath) {
  const method = request.method;

  // GET /api/anomaly/stats
  if (subpath === 'stats' && method === 'GET') {
    const stats = await getAnomalyStats(env);
    return jsonRes(stats);
  }

  // POST /api/anomaly/batch
  if (subpath === 'batch' && method === 'POST') {
    const result = await runAnomalyBatch(env);
    return jsonRes(result);
  }

  // POST /api/anomaly/record
  if (subpath === 'record' && method === 'POST') {
    return handleRecordEvent(request, env);
  }

  // POST /api/anomaly/scan  (explicit scan with body)
  if (subpath === 'scan' && method === 'POST') {
    return handleScan(request, env);
  }

  // Routes with user_id segment
  // /api/anomaly/:user_id
  // /api/anomaly/:user_id/history
  const parts = subpath.split('/');

  if (parts.length >= 1 && parts[0]) {
    const userId = parts[0];

    if (parts.length === 1 && method === 'GET') {
      // GET /api/anomaly/:user_id
      return handleGetUserAnomaly(userId, env);
    }

    if (parts.length === 2 && parts[1] === 'history' && method === 'GET') {
      // GET /api/anomaly/:user_id/history
      const url   = new URL(request.url);
      const limit = parseInt(url.searchParams.get('limit') || '20');
      const history = await getUserAnomalyHistory(env, userId, Math.min(limit, 100));
      return jsonRes(history);
    }
  }

  return jsonRes({ error: 'Not found', subpath }, 404);
}

/**
 * GET /api/anomaly/:user_id
 * Runs live anomaly detection against user's latest behavior event
 */
async function handleGetUserAnomaly(userId, env) {
  const result = await detectAnomaly(env, userId);

  if (result.error) {
    return jsonRes(result, result.status || 500);
  }

  // Auto-respond if anomaly score is critical
  let autoResponse = null;
  if (result.anomaly_score >= 80) {
    const decision   = decideAnomalyResponse({
      anomaly_score: result.anomaly_score,
      anomaly_types: result.anomaly_types,
      user_id:       userId,
    });

    const actions = [];
    for (const action of decision.actions) {
      if (action.action_type === 'disable_session' || action.action_type === 'rotate_credentials') {
        const r = await autoRotateOnAnomaly(env, userId, {
          anomaly_score: result.anomaly_score,
          anomaly_types: result.anomaly_types,
        });
        if (r) actions.push({ type: 'credential_rotation', ...r });
      }
    }

    if (actions.length > 0) {
      autoResponse = { triggered: true, actions_taken: actions.length, actions };
    }
  }

  return jsonRes({
    ...result,
    auto_response: autoResponse,
  });
}

/**
 * POST /api/anomaly/scan
 * Body: { user_id, event_data? }
 * event_data: optional behavior event object to score against baseline
 */
async function handleScan(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonRes({ error: 'Invalid JSON body' }, 400); }

  const { user_id, event_data = {} } = body;
  if (!user_id) return jsonRes({ error: 'user_id required' }, 400);

  const result = await detectAnomaly(env, user_id, event_data);

  return jsonRes(result, result.error ? 500 : 200);
}

/**
 * POST /api/anomaly/record
 * Record a behavior event for a user (from middleware or external source)
 * Body: { user_id, ip, endpoint, method, status_code, payload_size,
 *         response_time, user_agent, country_code, session_id }
 */
async function handleRecordEvent(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonRes({ error: 'Invalid JSON body' }, 400); }

  const { user_id, ip = '', ...requestData } = body;
  if (!user_id) return jsonRes({ error: 'user_id required' }, 400);

  const recorded = await recordBehaviorEvent(env, user_id, ip, requestData);

  return jsonRes({
    recorded:         recorded.recorded,
    user_id,
    requests_per_min: recorded.requests_per_min,
    geo_anomaly:      recorded.geo_anomaly,
    timestamp:        now(),
  });
}
