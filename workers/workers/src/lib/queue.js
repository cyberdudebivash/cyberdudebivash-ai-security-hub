/**
 * CYBERDUDEBIVASH AI Security Hub — Async Queue Engine v5.0
 * Cloudflare Queues: scan job producer + consumer
 * Job lifecycle: queued → processing → completed | failed
 * Idempotent processing, retry-safe, priority-aware
 *
 * Job states stored in KV (fast reads for status polling)
 * Full results stored in R2 (large JSON payloads)
 * Metadata mirrored to D1 for queryable scan history
 */

import { resolveDomain, inferTLSGrade }    from './dns.js';
import { fullBlacklistCheck }              from './dnsbl.js';
import { domainScanEngine }               from '../engine.js';
import { storeReport, buildReport }        from './reportEngine.js';
import { storeResultR2 }                   from './r2.js';
import { triggerAlerts }                   from './alerts.js';

// ─── Job ID generator ─────────────────────────────────────────────────────────
export function generateJobId() {
  const ts  = Date.now().toString(36);
  const rnd = Math.random().toString(36).slice(2, 8);
  return `job_${ts}${rnd}`;
}

// ─── Priority from tier ───────────────────────────────────────────────────────
export function tierPriority(tier) {
  return tier === 'ENTERPRISE' ? 2 : tier === 'PRO' ? 1 : 0;
}

// ─── KV key helpers ───────────────────────────────────────────────────────────
const kvJobKey     = (jobId) => `job:${jobId}`;
const kvDedupKey   = (module, target) => `dedup:${module}:${target.toLowerCase()}`;

// ─── Deduplication check (1h window) ─────────────────────────────────────────
export async function checkDedup(env, module, target) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const key   = kvDedupKey(module, target);
    const jobId = await env.SECURITY_HUB_KV.get(key);
    if (!jobId) return null;
    // Return existing job if it exists and is not failed
    const existing = await getJobStatus(env, jobId);
    if (existing && existing.status !== 'failed') return existing;
    return null;
  } catch { return null; }
}

async function markDedup(env, module, target, jobId) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const key = kvDedupKey(module, target);
    await env.SECURITY_HUB_KV.put(key, jobId, { expirationTtl: 3600 }); // 1h dedup window
  } catch {}
}

// ─── Job status (KV — fast) ───────────────────────────────────────────────────
export async function getJobStatus(env, jobId) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(kvJobKey(jobId));
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function setJobStatus(env, jobId, status, extra = {}) {
  if (!env?.SECURITY_HUB_KV) return;
  const current = await getJobStatus(env, jobId) || {};
  const updated = {
    ...current,
    job_id:   jobId,
    status,
    updated_at: new Date().toISOString(),
    ...extra,
  };
  // TTL: completed/failed jobs kept 24h, active jobs kept 2h
  const ttl = ['completed','failed'].includes(status) ? 86400 : 7200;
  try {
    await env.SECURITY_HUB_KV.put(kvJobKey(jobId), JSON.stringify(updated), { expirationTtl: ttl });
  } catch {}
}

// ─── D1 job record ────────────────────────────────────────────────────────────
async function updateD1Job(env, jobId, fields = {}) {
  if (!env?.DB) return;
  try {
    const setClause = Object.keys(fields).map(k => `${k} = ?`).join(', ');
    const values    = [...Object.values(fields), jobId];
    await env.DB.prepare(`UPDATE scan_jobs SET ${setClause} WHERE id = ?`)
      .bind(...values).run();
  } catch {}
}

async function insertD1Job(env, jobId, jobData) {
  if (!env?.DB) return;
  try {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO scan_jobs
       (id, user_id, identity, module, target, priority, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'queued', datetime('now'))`
    ).bind(
      jobId,
      jobData.user_id || null,
      jobData.identity || 'anonymous',
      jobData.module,
      jobData.target,
      jobData.priority || 0,
    ).run();
  } catch {}
}

async function insertD1History(env, jobId, scanResult, authCtx) {
  if (!env?.DB || !authCtx?.user_id) return;
  try {
    await env.DB.prepare(
      `INSERT INTO scan_history (user_id, job_id, scan_id, target, module, risk_score, risk_level, grade, data_source, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed')`
    ).bind(
      authCtx.user_id, jobId,
      scanResult.scan_metadata?.scan_id || null,
      scanResult.target, scanResult.module,
      scanResult.risk_score ?? null, scanResult.risk_level ?? null,
      scanResult.grade ?? null, scanResult.data_source ?? null,
    ).run();
  } catch {}
}

// ─── Enqueue a new scan job ───────────────────────────────────────────────────
export async function enqueueScanJob(env, jobData, authCtx = {}) {
  const { module, target, payload } = jobData;

  // Deduplication — return existing job if same target scanned recently
  const dedupJob = await checkDedup(env, module, target);
  if (dedupJob) {
    return { job_id: dedupJob.job_id, status: 'deduped', deduplicated: true, existing_job: dedupJob };
  }

  const jobId    = generateJobId();
  const priority = tierPriority(authCtx.tier || 'FREE');

  const message = {
    job_id:    jobId,
    module,
    target,
    payload:   payload || {},
    priority,
    user_id:   authCtx.user_id   || null,
    identity:  authCtx.identity  || null,
    tier:      authCtx.tier      || 'FREE',
    enqueued_at: new Date().toISOString(),
  };

  // Set initial KV state
  await setJobStatus(env, jobId, 'queued', {
    job_id:      jobId,
    module,
    target,
    priority,
    identity:    authCtx.identity,
    tier:        authCtx.tier || 'FREE',
    created_at:  new Date().toISOString(),
  });

  // Mirror to D1
  await insertD1Job(env, jobId, {
    user_id:  authCtx.user_id,
    identity: authCtx.identity,
    module,
    target,
    priority,
  });

  // Mark dedup
  await markDedup(env, module, target, jobId);

  // Enqueue to Cloudflare Queue
  if (env?.SCAN_QUEUE) {
    await env.SCAN_QUEUE.send(message, {
      delaySeconds: priority > 0 ? 0 : 2, // FREE tier gets 2s delay (priority queue)
      contentType:  'json',
    });
  } else {
    // No queue available — process synchronously (dev/fallback mode)
    console.warn('[QUEUE] SCAN_QUEUE not bound — processing synchronously');
    await processJobSync(env, message, authCtx);
  }

  return {
    job_id:       jobId,
    status:       'queued',
    module,
    target,
    priority,
    tier:         authCtx.tier || 'FREE',
    poll_url:     `/api/jobs/${jobId}`,
    result_url:   `/api/jobs/${jobId}/result`,
    created_at:   new Date().toISOString(),
    estimated_eta: priority >= 2 ? '< 5s' : priority === 1 ? '< 10s' : '< 30s',
  };
}

// ─── Queue consumer — processes a batch of messages ──────────────────────────
export async function processQueueBatch(batch, env) {
  for (const message of batch.messages) {
    const job = message.body;
    try {
      await processJob(env, job);
      message.ack();
    } catch (err) {
      console.error(`[QUEUE] Job ${job.job_id} failed:`, err?.message);
      // Retry on transient failures — permanent failures acked to avoid DLQ spam
      if (message.attempts < 3) {
        message.retry({ delaySeconds: 10 * message.attempts });
      } else {
        await setJobStatus(env, job.job_id, 'failed', {
          error:        err?.message || 'Unknown error after 3 attempts',
          failed_at:    new Date().toISOString(),
        });
        await updateD1Job(env, job.job_id, {
          status:       'failed',
          error_message: err?.message?.slice(0, 500) || 'Unknown error',
          completed_at:  new Date().toISOString().replace('T',' ').replace('Z',''),
        });
        message.ack(); // Ack to prevent infinite retry on permanent failures
      }
    }
  }
}

// ─── Core job processor ───────────────────────────────────────────────────────
async function processJob(env, job) {
  const { job_id, module, target, payload = {} } = job;

  // Mark processing
  await setJobStatus(env, job_id, 'processing', { started_at: new Date().toISOString() });
  await updateD1Job(env, job_id, { status: 'processing', started_at: new Date().toISOString().replace('T',' ').replace('Z','') });

  let scanResult;
  const authCtx = { user_id: job.user_id, identity: job.identity, tier: job.tier };

  switch (module) {
    case 'domain':
      scanResult = await runDomainScan(target, env);
      break;
    default:
      // Other modules (ai, redteam, identity, compliance) — import dynamically
      scanResult = await runGenericScan(module, target, payload, env);
  }

  // Store full result in R2
  const r2Key = await storeResultR2(env, job_id, scanResult);

  // Build and store report
  const report = buildReport(scanResult, { email: job.email, tier: job.tier });
  await storeReport(env, report);

  // Update job status in KV + D1
  await setJobStatus(env, job_id, 'completed', {
    completed_at: new Date().toISOString(),
    risk_score:   scanResult.risk_score ?? null,
    risk_level:   scanResult.risk_level ?? null,
    grade:        scanResult.grade ?? null,
    r2_key:       r2Key,
    report_id:    report.report_id,
    module,
    target,
  });

  await updateD1Job(env, job_id, {
    status:      'completed',
    risk_score:  scanResult.risk_score ?? null,
    risk_level:  scanResult.risk_level ?? null,
    r2_key:      r2Key,
    completed_at: new Date().toISOString().replace('T',' ').replace('Z',''),
  });

  // Mirror to scan_history (authenticated users only)
  await insertD1History(env, job_id, scanResult, authCtx);

  // Trigger alerts if risk is high or blacklisted
  await triggerAlerts(env, scanResult, authCtx).catch(() => {});

  return scanResult;
}

// ─── Domain scan (real DNS + DNSBL) ──────────────────────────────────────────
async function runDomainScan(domain, env) {
  let dns = null, tls = null, bl = null, dataSource = 'deterministic_fallback';
  try {
    [dns, tls] = await Promise.all([ resolveDomain(domain), inferTLSGrade(domain) ]);
    bl         = await fullBlacklistCheck(domain, dns?.ipv4 ?? []);
    dataSource = 'live_dns';
  } catch {}

  if (dataSource === 'live_dns' && dns) {
    // Import domain handler logic inline to avoid circular deps
    const { buildRealResult } = await import('../handlers/domain.js').catch(() => ({}));
    if (buildRealResult) return buildRealResult(domain, dns, tls, bl);
  }
  return { ...domainScanEngine(domain), data_source: dataSource };
}

// ─── Generic scan dispatcher ──────────────────────────────────────────────────
async function runGenericScan(module, target, payload, env) {
  const engines = {
    ai:         () => import('../engine.js').then(m => m.aiScanEngine(target, payload.use_case || 'other')),
    redteam:    () => import('../engine.js').then(m => m.redteamScanEngine(target, payload.attack_surface)),
    identity:   () => import('../engine.js').then(m => m.identityScanEngine(target)),
    compliance: () => import('../engine.js').then(m => m.complianceScanEngine(payload.framework || 'ISO27001', target)),
  };
  const fn = engines[module];
  if (!fn) throw new Error(`Unknown scan module: ${module}`);
  return fn();
}

// ─── Synchronous fallback (when Queue not available) ─────────────────────────
async function processJobSync(env, job, authCtx) {
  try {
    await processJob(env, job);
  } catch (err) {
    await setJobStatus(env, job.job_id, 'failed', { error: err?.message });
  }
}
