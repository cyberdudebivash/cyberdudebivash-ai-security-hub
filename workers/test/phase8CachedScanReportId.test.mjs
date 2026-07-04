/* Phase VIII scale-simulation defect — cache-hit scan_id must be reportable.
 *
 * Live-reproduced at scale (100-org simulation, HTTP only): a customer scans a
 * domain that another customer (or an earlier request) already scanned, so the
 * shared domain-level response cache HITs. The scan response body carried the
 * ORIGINAL cached scan's id, while cacheScanResultForReport + the X-Scan-ID
 * header used a fresh per-request id. The customer read the body id and called
 * POST /api/report/generate {scan_id} → 422 "Could not resolve scan result",
 * because the report cache was keyed under the fresh id, not the body id.
 * Symptom for the customer: "I just ran a scan and the report says it doesn't
 * exist" — a broken scan→report workflow that only appears once a domain has
 * been cached, i.e. exactly at multi-customer scale.
 *
 * Fix (domain.js cache-hit branch): stamp the fresh per-request scanId onto the
 * returned payload (scan_id + scan_metadata.scan_id) so body id == X-Scan-ID ==
 * report-cache key == history row, and await the report-cache write so a report
 * generated immediately after the scan resolves it.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { handleDomainScan } from '../src/handlers/domain.js';
import { handleReportGenerate } from '../src/handlers/report.js';
import { getCachedScanResult } from '../src/lib/scanResultCache.js';

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, String(value)); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async delete(key) { store.delete(key); },
    _store: store,
  };
}

// A realistic cached domain result, carrying an ORIGINAL scan id that predates
// this customer — this is what makes the shared cache dangerous.
const STALE_ID = 'sc_original_from_another_customer';
function seedDomainCache(kv, domain) {
  kv._store.set(`scan:domain:${domain}`, JSON.stringify({
    scan_id: STALE_ID,
    module: 'domain_scanner', target: domain, engine_version: '5.0.0',
    scan_status: 'measured', risk_score: 70, risk_level: 'HIGH', grade: 'D',
    data_source: 'live_dns', resolves: true,
    findings: [{ id: 'DOM-001', title: 'Weak TLS', severity: 'HIGH', description: 'x', recommendation: 'y' }],
    scan_metadata: { scan_id: STALE_ID, scan_timestamp: '2026-01-01T00:00:00.000Z', engine_version: '5.0.0' },
    _cached_at: Date.now(),
  }));
}

function scanReq(domain) {
  return new Request('https://cyberdudebivash.in/api/scan/domain', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
}

describe('cache-hit domain scan returns a reportable scan_id (Phase VIII)', () => {
  let env, authCtx;
  beforeEach(() => {
    env = { SECURITY_HUB_KV: makeKV() };       // no DB/R2 — both optional & guarded
    authCtx = { user_id: 'u_customer_A', tier: 'FREE' };
    seedDomainCache(env.SECURITY_HUB_KV, 'example.com');
  });

  it('stamps a fresh per-request scan_id on the cache hit (not the stale shared id)', async () => {
    const res = await handleDomainScan(scanReq('example.com'), env, authCtx);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-Cache')).toBe('HIT');
    const body = await res.json();
    const headerId = res.headers.get('X-Scan-ID');

    // The customer must NOT be handed another customer's scan id...
    expect(body.scan_id).not.toBe(STALE_ID);
    // ...and the body id must equal the header id (single identity per request).
    expect(body.scan_id).toBe(headerId);
    // scan_metadata (if surfaced) must agree too.
    if (body.scan_metadata) expect(body.scan_metadata.scan_id).toBe(body.scan_id);
  });

  it('report generation resolves the scan_id the customer received', async () => {
    const res = await handleDomainScan(scanReq('example.com'), env, authCtx);
    const body = await res.json();

    // The exact id the customer sees must be in their report cache.
    const cached = await getCachedScanResult(env, authCtx, body.scan_id);
    expect(cached).toBeTruthy();
    expect(cached.target).toBe('example.com');

    // End-to-end: POST /api/report/generate with the body id → 201 (no 422).
    const rep = await handleReportGenerate(
      new Request('https://cyberdudebivash.in/api/report/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: body.scan_id }),
      }), env, authCtx);
    expect(rep.status).toBe(201);
    const repBody = await rep.json();
    expect(repBody.success).toBe(true);
    expect(repBody.report_id).toBeTruthy();
  });

  it('the stale shared id is NOT resolvable as this customer report (no cross-customer leak)', async () => {
    await handleDomainScan(scanReq('example.com'), env, authCtx);
    // The original id belonged to another customer's request; it must not
    // resolve under this customer's identity.
    const leaked = await getCachedScanResult(env, authCtx, STALE_ID);
    expect(leaked).toBeNull();
  });

  it('two customers scanning the same cached domain get distinct, individually reportable ids', async () => {
    const a = await (await handleDomainScan(scanReq('example.com'), env, { user_id: 'u_A', tier: 'FREE' })).json();
    const b = await (await handleDomainScan(scanReq('example.com'), env, { user_id: 'u_B', tier: 'FREE' })).json();
    expect(a.scan_id).not.toBe(b.scan_id);
    expect(await getCachedScanResult(env, { user_id: 'u_A' }, a.scan_id)).toBeTruthy();
    expect(await getCachedScanResult(env, { user_id: 'u_B' }, b.scan_id)).toBeTruthy();
    // A's id must not resolve for B (tenant isolation on the report cache).
    expect(await getCachedScanResult(env, { user_id: 'u_B' }, a.scan_id)).toBeNull();
  });
});
