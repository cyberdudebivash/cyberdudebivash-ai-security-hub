/* Async scan job ownership (Journey 8).
 *
 * DEFECT (found live): GET /api/jobs/:id and /api/jobs/:id/result fetched the
 * job by id and returned its status/scan result WITHOUT checking that the job
 * belonged to the caller. Live proof: user B read user A's job status AND result
 * (both 200) — a cross-tenant scan-result leak (IDOR). Dedup was also global
 * (module:target), which itself handed one tenant's job to another.
 *
 * Fix: jobOwnedBy() gate on both endpoints (match user_id, else identity; fail
 * closed; 404 to avoid leaking existence) + per-identity dedup key.
 */
import { describe, it, expect, vi } from 'vitest';

// handleJobInsights calls generateAIInsights(), which can make a real AI-provider
// request (routeAICall) — mock it so these tests stay fast/deterministic and never
// hit the network, matching the pattern in multiAgentSOC.test.mjs.
vi.mock('../src/lib/aiBrain.js', () => ({
  generateAIInsights: vi.fn().mockResolvedValue({ executive_brief: 'mocked insight' }),
}));

import { handleJobStatus, handleJobInsights } from '../src/handlers/jobs.js';

// KV shim: returns the stored job for any key containing its id (getJobStatus
// requests kvJobKey(jobId), which embeds the id).
function kvFor(job) {
  return { async get(k) { return String(k).includes(job.job_id) ? JSON.stringify(job) : null; } };
}
const req = (id) => new Request(`https://x/api/jobs/${id}`);
const JOB = {
  job_id: 'job_abc123', status: 'completed', module: 'domain', target: 'example.com',
  user_id: 'alice', identity: 'user:alice',
};

describe('async job status is readable only by its owner', () => {
  const env = { SECURITY_HUB_KV: kvFor(JOB) };

  it('the owner (alice) can read the job (200)', async () => {
    const res = await handleJobStatus(req('job_abc123'), env, { user_id: 'alice', identity: 'user:alice' }, 'job_abc123');
    expect(res.status).toBe(200);
  });
  it('a different user (bob) gets 404, not the result', async () => {
    const res = await handleJobStatus(req('job_abc123'), env, { user_id: 'bob', identity: 'user:bob' }, 'job_abc123');
    expect(res.status).toBe(404);
  });
  it('an anonymous caller gets 404', async () => {
    const res = await handleJobStatus(req('job_abc123'), env, {}, 'job_abc123');
    expect(res.status).toBe(404);
  });

  it('an anonymous job is bound to its creating identity (IP)', async () => {
    const anonJob = { ...JOB, user_id: null, identity: 'ip:1.2.3.4' };
    const e = { SECURITY_HUB_KV: kvFor(anonJob) };
    const same = await handleJobStatus(req('job_abc123'), e, { identity: 'ip:1.2.3.4' }, 'job_abc123');
    const diff = await handleJobStatus(req('job_abc123'), e, { identity: 'ip:9.9.9.9' }, 'job_abc123');
    expect(same.status).toBe(200);
    expect(diff.status).toBe(404);
  });
});

/* GET /api/insights/:jobId (handleJobInsights) — documented in the public API
 * since v8.0 but never wired anywhere in workers/src/index.js (404 in production,
 * found in an API-surface audit). Implemented by reusing the exact same
 * getJobStatus + jobOwnedBy ownership gate as handleJobStatus/handleJobResult
 * above, so it inherits the same cross-tenant protection — this is the
 * regression coverage for that. */
describe('GET /api/insights/:jobId is readable only by the job owner', () => {
  const COMPLETED_JOB = { ...JOB, r2_key: 'kv:result:job_abc123' };

  function envFor(job, result) {
    const kv = kvFor(job);
    return {
      SECURITY_HUB_KV: {
        async get(k) {
          if (String(k) === 'result:job_abc123') return result ? JSON.stringify(result) : null;
          return kv.get(k);
        },
      },
    };
  }
  const RESULT = { findings: [{ severity: 'HIGH' }], risk_score: 40, target: 'example.com' };

  it('the owner (alice) gets insights (200)', async () => {
    const env = envFor(COMPLETED_JOB, RESULT);
    const res = await handleJobInsights(req('job_abc123'), env, { user_id: 'alice', identity: 'user:alice' }, 'job_abc123');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.insights).toBeDefined();
  });

  it('a different user (bob) gets 404, not the insights', async () => {
    const env = envFor(COMPLETED_JOB, RESULT);
    const res = await handleJobInsights(req('job_abc123'), env, { user_id: 'bob', identity: 'user:bob' }, 'job_abc123');
    expect(res.status).toBe(404);
  });

  it('an anonymous caller gets 404', async () => {
    const env = envFor(COMPLETED_JOB, RESULT);
    const res = await handleJobInsights(req('job_abc123'), env, {}, 'job_abc123');
    expect(res.status).toBe(404);
  });

  it('a still-processing job returns 202, not insights', async () => {
    const processingJob = { ...JOB, status: 'processing' };
    const env = envFor(processingJob, null);
    const res = await handleJobInsights(req('job_abc123'), env, { user_id: 'alice', identity: 'user:alice' }, 'job_abc123');
    expect(res.status).toBe(202);
  });

  it('an unknown job ID returns 404', async () => {
    const env = { SECURITY_HUB_KV: { async get() { return null; } } };
    const res = await handleJobInsights(req('job_nonexistent'), env, { user_id: 'alice' }, 'job_nonexistent');
    expect(res.status).toBe(404);
  });
});
