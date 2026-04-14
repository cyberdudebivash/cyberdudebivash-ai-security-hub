/**
 * CYBERDUDEBIVASH AI Security Hub — Async Job Handler v5.0
 * POST /api/scan/async/:module — enqueue scan job, return job_id immediately
 * GET  /api/jobs/:job_id       — poll job status
 * GET  /api/jobs/:job_id/result — retrieve full scan result
 */

import { enqueueScanJob, getJobStatus } from '../lib/queue.js';
import { getResultByJobId }             from '../lib/r2.js';
import { validateDomain, parseBody }    from '../middleware/validation.js';
import { inspectForAttacks, sanitizeString } from '../middleware/security.js';

const VALID_MODULES = ['domain','ai','redteam','identity','compliance'];

// ─── POST /api/scan/async/:module ─────────────────────────────────────────────
export async function handleAsyncScan(request, env, authCtx, module) {
  if (!VALID_MODULES.includes(module)) {
    return Response.json({
      error:    'Unknown scan module',
      valid:    VALID_MODULES,
      example:  'POST /api/scan/async/domain',
    }, { status: 400 });
  }

  const body   = await parseBody(request);
  const rawTarget = body?.domain || body?.target || body?.model_name || body?.identifier || '';

  if (inspectForAttacks(rawTarget)) {
    return Response.json({ error: 'Invalid input detected' }, { status: 400 });
  }

  // Module-specific validation
  let target = sanitizeString(rawTarget);
  if (module === 'domain') {
    const val = validateDomain(target);
    if (!val.valid) {
      return Response.json({ error: 'Validation failed', message: val.message, field: 'domain' }, { status: 422 });
    }
    target = val.value;
  } else if (!target || target.length < 2) {
    return Response.json({ error: 'target/identifier required' }, { status: 422 });
  }

  // Enqueue
  const jobResult = await enqueueScanJob(env, {
    module,
    target,
    payload: body,
  }, authCtx);

  const statusCode = jobResult.deduplicated ? 200 : 202;

  return Response.json({
    ...jobResult,
    note: jobResult.deduplicated
      ? 'Returned existing job — same target scanned within the last hour'
      : `Job queued. Poll ${jobResult.poll_url} to track progress.`,
    usage: {
      poll:    `GET /api/jobs/${jobResult.job_id}`,
      result:  `GET /api/jobs/${jobResult.job_id}/result`,
    },
  }, { status: statusCode, headers: { 'X-Job-ID': jobResult.job_id } });
}

// ─── GET /api/jobs/:job_id ────────────────────────────────────────────────────
export async function handleJobStatus(request, env, authCtx, jobId) {
  if (!jobId || jobId.length < 6) {
    return Response.json({ error: 'Invalid job ID' }, { status: 400 });
  }

  const job = await getJobStatus(env, jobId);
  if (!job) {
    return Response.json({
      error:  'Job not found',
      hint:   'Jobs expire 24h after completion. Re-run the scan if needed.',
      job_id: jobId,
    }, { status: 404 });
  }

  // Build status response (omit full result — use /result endpoint for that)
  const response = {
    job_id:       job.job_id,
    status:       job.status,
    module:       job.module,
    target:       job.target,
    tier:         job.tier,
    priority:     job.priority,
    created_at:   job.created_at,
    updated_at:   job.updated_at,
    started_at:   job.started_at  || null,
    completed_at: job.completed_at || null,
    // Summary (available when completed)
    risk_score:   job.risk_score   ?? null,
    risk_level:   job.risk_level   ?? null,
    grade:        job.grade        ?? null,
    // Error info (if failed)
    error:        job.error        || null,
    // Links
    result_url:   job.status === 'completed' ? `/api/jobs/${jobId}/result` : null,
    report_id:    job.report_id    || null,
  };

  // HTTP status reflects job state for easy polling
  const httpStatus = {
    queued:     202,
    processing: 202,
    completed:  200,
    failed:     500,
  }[job.status] ?? 200;

  return Response.json(response, {
    status: httpStatus,
    headers: {
      'X-Job-Status': job.status,
      'X-Job-ID':     jobId,
      // Polling hint: completed/failed — no need to poll again
      'Retry-After': ['completed','failed'].includes(job.status) ? '' : '3',
    },
  });
}

// ─── GET /api/jobs/:job_id/result ─────────────────────────────────────────────
export async function handleJobResult(request, env, authCtx, jobId) {
  if (!jobId || jobId.length < 6) {
    return Response.json({ error: 'Invalid job ID' }, { status: 400 });
  }

  const job = await getJobStatus(env, jobId);
  if (!job) {
    return Response.json({ error: 'Job not found', job_id: jobId }, { status: 404 });
  }

  if (job.status === 'queued' || job.status === 'processing') {
    return Response.json({
      error:     'Result not ready',
      status:    job.status,
      job_id:    jobId,
      poll_url:  `/api/jobs/${jobId}`,
      hint:      'Job is still in progress — retry in a few seconds',
    }, { status: 202 });
  }

  if (job.status === 'failed') {
    return Response.json({
      error:    'Scan job failed',
      job_id:   jobId,
      reason:   job.error || 'Unknown error',
      hint:     'Re-queue the scan or contact support',
      requeue:  `POST /api/scan/async/${job.module}`,
    }, { status: 500 });
  }

  // Fetch full result from R2/KV
  const scanResult = await getResultByJobId(env, jobId);
  if (!scanResult) {
    return Response.json({
      error:  'Result unavailable',
      hint:   'Result may have expired (24h TTL). Re-run the scan.',
      job_id: jobId,
    }, { status: 410 });
  }

  return Response.json({
    job_id:     jobId,
    status:     'completed',
    retrieved_at: new Date().toISOString(),
    scan_result: scanResult,
  }, { status: 200, headers: { 'X-Job-ID': jobId } });
}

// ─── GET /api/history (D1-backed, authenticated users) ───────────────────────
export async function handleD1History(request, env, authCtx) {
  if (!authCtx.user_id) {
    // Fall back to KV-based history for non-authenticated users
    const { getScanHistory } = await import('../lib/reportEngine.js');
    const history = await getScanHistory(env, authCtx, 20);
    return Response.json({ identity: authCtx.identity, count: history.length, scans: history });
  }

  if (!env?.DB) {
    return Response.json({ error: 'Database unavailable' }, { status: 503 });
  }

  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 100);
  const module = url.searchParams.get('module') || null;
  const from   = url.searchParams.get('from')   || null; // ISO date
  const to     = url.searchParams.get('to')      || null; // ISO date

  let query  = `SELECT * FROM scan_history WHERE user_id = ?`;
  const vals = [authCtx.user_id];

  if (module) { query += ` AND module = ?`;   vals.push(module); }
  if (from)   { query += ` AND scanned_at >= ?`; vals.push(from); }
  if (to)     { query += ` AND scanned_at <= ?`; vals.push(to); }

  query += ` ORDER BY scanned_at DESC LIMIT ?`;
  vals.push(limit);

  let results = [];
  try {
    const { results: rows } = await env.DB.prepare(query).bind(...vals).all();
    results = rows ?? [];
  } catch {
    return Response.json({ error: 'History query failed' }, { status: 500 });
  }

  return Response.json({
    user_id: authCtx.user_id,
    tier:    authCtx.tier,
    count:   results.length,
    limit,
    filters: { module: module || null, from: from || null, to: to || null },
    scans:   results,
  });
}
