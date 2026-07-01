/* Regression tests — the "Generate Report" feature (Reports tab, STARTER+) was
 * completely broken end-to-end: nothing ever wrote the scan_id-keyed KV cache
 * that handleReportGenerate reads from, so every click 422'd with "Could not
 * resolve scan result". Separately, the frontend read `scan.id` (a random D1
 * primary key) instead of `scan.scan_id`, so even a working cache would have
 * been looked up under the wrong key. And the download endpoint always
 * returned raw JSON labeled as a ".json" attachment despite the UI promising
 * "Download PDF".
 *
 * Proves: (1) cacheScanResultForReport/getCachedScanResult round-trip under
 * the exact key scheme handleReportGenerate expects; (2) handleReportGenerate
 * now resolves a real scan by scan_id instead of always 422ing; (3) the
 * download endpoint serves the real styled HTML report, not a bare JSON blob,
 * once one has been generated. */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cacheScanResultForReport, getCachedScanResult } from '../src/lib/scanResultCache.js';
import { handleReportGenerate, handleReportDownload } from '../src/handlers/report.js';

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, String(value)); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
    _store: store,
  };
}

function jsonReq(body) {
  return new Request('https://x/api/report/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const SAMPLE_SCAN_RESULT = {
  module: 'domain_scanner',
  target: 'acme-corp.com',
  risk_score: 62,
  risk_level: 'HIGH',
  grade: 'D',
  findings: [
    { id: 'DOM-001', title: 'Missing DNSSEC', severity: 'HIGH', description: 'DNSSEC not configured.', recommendation: 'Enable DNSSEC.' },
    { id: 'DOM-002', title: 'Weak TLS', severity: 'CRITICAL', description: 'TLS 1.0 supported.', recommendation: 'Disable TLS 1.0/1.1.' },
  ],
};

describe('scanResultCache — key symmetry for authenticated and anonymous callers', () => {
  it('round-trips a scan result for a logged-in user under the scoped key', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const authCtx = { user_id: 'u_123' };
    await cacheScanResultForReport(env, authCtx, 'sc_abc123', SAMPLE_SCAN_RESULT);
    const out = await getCachedScanResult(env, authCtx, 'sc_abc123');
    expect(out).toEqual(SAMPLE_SCAN_RESULT);
  });

  it('round-trips for an anonymous/API-key caller under the unscoped key', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    await cacheScanResultForReport(env, {}, 'sc_anon456', SAMPLE_SCAN_RESULT);
    const out = await getCachedScanResult(env, {}, 'sc_anon456');
    expect(out).toEqual(SAMPLE_SCAN_RESULT);
  });

  it('does not leak one user\'s cached scan to a different user_id', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    await cacheScanResultForReport(env, { user_id: 'u_123' }, 'sc_shared', SAMPLE_SCAN_RESULT);
    const out = await getCachedScanResult(env, { user_id: 'u_999' }, 'sc_shared');
    expect(out).toBeNull();
  });
});

describe('handleReportGenerate — previously 422\'d on every real customer click', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_KV: makeKV() }; });

  it('still 422s when the scan_id was never cached (nothing to resolve)', async () => {
    const res = await handleReportGenerate(jsonReq({ scan_id: 'sc_never_ran' }), env, { user_id: 'u_1' });
    expect(res.status).toBe(422);
  });

  it('resolves a real report once the scan handler has cached its result, and generates a styled HTML report', async () => {
    const authCtx = { user_id: 'u_1', tier: 'STARTER' };
    await cacheScanResultForReport(env, authCtx, 'sc_real001', SAMPLE_SCAN_RESULT);

    const genRes = await handleReportGenerate(jsonReq({ scan_id: 'sc_real001' }), env, authCtx);
    expect(genRes.status).toBe(201);
    const body = await genRes.json();
    expect(body.success).toBe(true);
    expect(body.download_token).toBeTruthy();
    expect(body.report.target).toBe('acme-corp.com');
    expect(body.report.executive_summary.critical_count).toBe(1);

    // The download endpoint should now serve the real HTML report, not a JSON blob
    const dlRes = await handleReportDownload({ url: `https://x/api/report/${body.download_token}` }, env, authCtx);
    expect(dlRes.headers.get('Content-Type')).toContain('text/html');
    const html = await dlRes.text();
    expect(html).toContain('acme-corp.com');
    expect(html).toContain('Weak TLS');
  });

  it('accepts an inline scan_result directly (no scan_id needed)', async () => {
    const res = await handleReportGenerate(jsonReq({ scan_result: SAMPLE_SCAN_RESULT }), env, { user_id: 'u_1' });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.report.target).toBe('acme-corp.com');
  });
});
