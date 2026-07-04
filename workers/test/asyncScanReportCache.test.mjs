/* Async-scan → report-generation gap (Customer Acceptance Program, Journey B).
 *
 * Live-reproduced defect: a customer runs an ASYNC scan
 * (POST /api/scan/async/domain → job → scan_id), then POST /api/report/generate
 * with that scan_id returned 422 "Could not resolve scan result".
 *
 * Root cause: the synchronous scan handlers call cacheScanResultForReport, but
 * the async/queue path (processJob in queue.js) stored the result in R2/D1 and
 * KV job-status yet never wrote the scan_id-keyed KV cache that
 * handleReportGenerate reads via getCachedScanResult. So report-by-scan_id
 * only ever worked for sync scans, not the primary async flow.
 *
 * Fix: processJob now calls cacheScanResultForReport(env, authCtx,
 * scanResult.scan_id, scanResult) after computing the result.
 *
 * This test drives the real processQueueBatch → processJob path (DNS mocked so
 * it takes the live_dns → buildRealResult branch that assigns a scan_id) and
 * asserts the report cache is populated and handleReportGenerate resolves it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock only the network layer so runDomainScan takes the real live_dns branch.
// We don't care about DNS internals here — only that processJob caches whatever
// scan result (with a scan_id) the engine produces. So: make the network layer
// return truthy objects (so runDomainScan takes the live_dns branch) and mock
// buildRealResult to return a canned, report-compatible result with a scan_id.
vi.mock('../src/lib/dns.js', () => ({
  resolveDomain: async () => ({ resolves: true, ipv4: ['93.184.216.34'] }),
  inferTLSGrade: async () => ({ tls_grade: 'A' }),
}));
vi.mock('../src/lib/dnsbl.js', () => ({
  fullBlacklistCheck: async () => ({ any_blacklisted: false, combined_threat_score: 0 }),
}));
let __scanSeq = 0;
vi.mock('../src/handlers/domain.js', () => ({
  buildRealResult: (domain) => ({
    scan_id: `sc_test_${++__scanSeq}`,
    module: 'domain_scanner', target: domain,
    risk_score: 65, risk_level: 'HIGH', grade: 'D', data_source: 'live_dns',
    findings: [
      { id: 'DOM-001', title: 'Missing DNSSEC', severity: 'HIGH', description: 'x', recommendation: 'y' },
    ],
  }),
}));

const { processQueueBatch } = await import('../src/lib/queue.js');
const { getCachedScanResult } = await import('../src/lib/scanResultCache.js');
const { handleReportGenerate } = await import('../src/handlers/report.js');

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, String(value)); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
    _store: store,
  };
}

// A batch message shaped like enqueueScanJob's producer payload.
function makeBatch(job) {
  return { messages: [{ body: job, ack() {}, retry() {} }] };
}

describe('async scan caches its result for report generation', () => {
  let env, authUser;
  beforeEach(() => {
    env = { SECURITY_HUB_KV: makeKV() }; // no DB/R2 — both are optional & guarded
    authUser = { user_id: 'u_pilot_1' };
  });

  it('processJob writes the scan_id-keyed report cache (scoped to the owner)', async () => {
    const job = {
      job_id: 'job_test_1', module: 'domain', target: 'example.com',
      user_id: 'u_pilot_1', identity: 'u_pilot_1', tier: 'FREE',
    };
    await processQueueBatch(makeBatch(job), env);

    // The job must have completed and produced a scan_id in KV job-status.
    const status = JSON.parse(await env.SECURITY_HUB_KV.get('job:job_test_1'));
    expect(status.status).toBe('completed');

    // Find the scan_id the engine assigned (top-level on the scan result).
    // Report cache key is scan:${user_id}:${scan_id}. Locate it in the store.
    const cacheKeys = [...env.SECURITY_HUB_KV._store.keys()].filter(k => k.startsWith('scan:u_pilot_1:'));
    expect(cacheKeys.length).toBe(1);

    const scanId = cacheKeys[0].split(':')[2];
    const cached = await getCachedScanResult(env, authUser, scanId);
    expect(cached).toBeTruthy();
    expect(cached.target).toBe('example.com');
    expect(cached.scan_id).toBe(scanId);
    expect(cached.data_source).toBe('live_dns');
  });

  it('handleReportGenerate resolves the async scan_id (no more 422)', async () => {
    const job = {
      job_id: 'job_test_2', module: 'domain', target: 'example.com',
      user_id: 'u_pilot_1', identity: 'u_pilot_1', tier: 'FREE',
    };
    await processQueueBatch(makeBatch(job), env);
    const scanId = [...env.SECURITY_HUB_KV._store.keys()]
      .filter(k => k.startsWith('scan:u_pilot_1:'))[0].split(':')[2];

    const req = new Request('https://x/api/report/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId }),
    });
    const res = await handleReportGenerate(req, env, authUser);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.report_id).toBeTruthy();
  });

  it('does NOT leak the cache to a different tenant', async () => {
    const job = {
      job_id: 'job_test_3', module: 'domain', target: 'example.com',
      user_id: 'u_pilot_1', identity: 'u_pilot_1', tier: 'FREE',
    };
    await processQueueBatch(makeBatch(job), env);
    const scanId = [...env.SECURITY_HUB_KV._store.keys()]
      .filter(k => k.startsWith('scan:u_pilot_1:'))[0].split(':')[2];

    // A different user must not resolve u_pilot_1's scan.
    const other = await getCachedScanResult(env, { user_id: 'u_attacker' }, scanId);
    expect(other).toBeNull();
  });
});
