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
import { describe, it, expect } from 'vitest';
import { handleJobStatus } from '../src/handlers/jobs.js';

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
