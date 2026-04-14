/**
 * PREDICTIVE HANDLER — REST API for Predictive Threat Intelligence Engine (System 3)
 *
 * Routes:
 *   GET  /api/predict/threats           — Top threats (24h predictions)
 *   GET  /api/predict/stats             — Prediction stats dashboard data
 *   GET  /api/predict/:cve_id           — Full prediction for specific CVE
 *   GET  /api/predict/:cve_id/trend     — Score trend over time
 *   POST /api/predict/batch             — Run full prediction batch (cron-equivalent)
 *   POST /api/predict/score             — Score a CVE with custom context
 */

import {
  predictCVEThreat,
  getTopThreats,
  getCVEPredictionTrend,
  getPredictiveStats,
  runPredictiveBatch,
  computePredictiveRiskScore,
} from '../services/predictiveEngine.js';

function now() { return new Date().toISOString(); }

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Route dispatcher for /api/predict/*
 */
export async function handlePredictiveRequest(request, env, authCtx, subpath) {
  const method = request.method;

  // GET /api/predict/threats
  if (subpath === 'threats' && method === 'GET') {
    const url   = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '20');
    const data  = await getTopThreats(env, Math.min(limit, 100));
    return jsonRes(data);
  }

  // GET /api/predict/stats
  if (subpath === 'stats' && method === 'GET') {
    const stats = await getPredictiveStats(env);
    return jsonRes(stats);
  }

  // POST /api/predict/batch
  if (subpath === 'batch' && method === 'POST') {
    const result = await runPredictiveBatch(env);
    return jsonRes(result);
  }

  // POST /api/predict/score — score a CVE with optional context override
  if (subpath === 'score' && method === 'POST') {
    return handleScoreCVE(request, env);
  }

  // /api/predict/:cve_id  and  /api/predict/:cve_id/trend
  const parts = subpath.split('/');
  if (parts.length >= 1 && parts[0]) {
    const cveId = decodeURIComponent(parts[0]);

    // GET /api/predict/:cve_id/trend
    if (parts.length === 2 && parts[1] === 'trend' && method === 'GET') {
      const url  = new URL(request.url);
      const days = parseInt(url.searchParams.get('days') || '7');
      const data = await getCVEPredictionTrend(env, cveId, Math.min(days, 30));
      return jsonRes(data);
    }

    // GET /api/predict/:cve_id
    if (parts.length === 1 && method === 'GET') {
      return handleGetCVEPrediction(cveId, request, env);
    }
  }

  return jsonRes({ error: 'Not found', subpath }, 404);
}

/**
 * GET /api/predict/:cve_id
 * Full prediction for a specific CVE with optional context query params
 * Query: internet_facing, asset_count, patch_lag_days, is_production, affected_users
 */
async function handleGetCVEPrediction(cveId, request, env) {
  const url = new URL(request.url);

  const contextOverride = {};
  if (url.searchParams.has('internet_facing'))
    contextOverride.internet_facing = url.searchParams.get('internet_facing') !== 'false';
  if (url.searchParams.has('asset_count'))
    contextOverride.asset_count = parseInt(url.searchParams.get('asset_count'));
  if (url.searchParams.has('patch_lag_days'))
    contextOverride.patch_lag_days = parseInt(url.searchParams.get('patch_lag_days'));
  if (url.searchParams.has('is_production'))
    contextOverride.is_production = url.searchParams.get('is_production') !== 'false';
  if (url.searchParams.has('affected_users'))
    contextOverride.affected_users = parseInt(url.searchParams.get('affected_users'));

  const result = await predictCVEThreat(env, cveId, contextOverride);

  return jsonRes(result, result.status || 200);
}

/**
 * POST /api/predict/score
 * Score a CVE with full custom context (no DB lookup needed if all fields provided)
 * Body: { cve_id?, cvss, epss, is_kev, description?, cvss_vector?, age_days?,
 *         context: { internet_facing, asset_count, patch_lag_days, ... } }
 */
async function handleScoreCVE(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonRes({ error: 'Invalid JSON body' }, 400); }

  const { cve_id, cvss, epss, is_kev, description, cvss_vector, age_days, context = {} } = body;

  // If cve_id provided, try full prediction from DB
  if (cve_id) {
    const result = await predictCVEThreat(env, cve_id, context);
    return jsonRes(result, result.status || 200);
  }

  // Otherwise compute inline score from provided params
  if (cvss === undefined) {
    return jsonRes({ error: 'Either cve_id or cvss is required' }, 400);
  }

  const scoring = computePredictiveRiskScore(
    { cvss: parseFloat(cvss), epss: parseFloat(epss || 0), is_kev: !!is_kev,
      description: description || '', cvss_vector: cvss_vector || '',
      age_days: parseInt(age_days || 0) },
    context
  );

  return jsonRes({
    ...scoring,
    input: { cvss, epss, is_kev, age_days, context },
    timestamp: now(),
  });
}
