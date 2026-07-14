/* Regression locks — OBJ-11 (anonymous feed limits) + report-expiry lifecycle.
 *
 * Scale-simulation evidence (100 orgs / 10 archetypes over HTTP, 2026-07-06):
 *   1. The anonymous FREE intel feeds advertised "100 requests/day, 10 req/min"
 *      (pricing page + pricing.json) but the anonymous branch of
 *      handlePublicFeeds never called the limiter — 15 rapid keyless calls all
 *      returned 200. This contradicted the "advertised == enforced" pricing
 *      certification; per the Verifiable-Statement Rule (standards §10) the
 *      evidence wins and enforcement was aligned up to the promise
 *      (fail-open on KV outage per accepted R-14).
 *   2. Report links promise 7-day expiry; the 410 path had no test coverage.
 *   3. Published scan burst rates are test-bound to the enforced constants so
 *      pricing copy can never drift from the middleware again (§8.6:
 *      "limits are disclosed before they bite").
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { handlePublicFeeds } from '../src/handlers/publicFeeds.js';
import { handleReportDownload } from '../src/handlers/report.js';
import { TIERS } from '../src/middleware/auth.js';

function memKV() {
  const store = new Map();
  return {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, String(v)); },
    _store: store,
  };
}

describe('anonymous FREE intel feeds enforce the advertised per-minute limit (OBJ-11)', () => {
  it('the 11th rapid keyless call in one minute is 429', async () => {
    const env = { SECURITY_HUB_KV: memKV() }; // no DB → curated fallback feed
    const statuses = [];
    for (let i = 0; i < 12; i++) {
      const r = await handlePublicFeeds(
        new Request('http://localhost/api/v1/intel/kev.json'), env, '/api/v1/intel/kev.json');
      statuses.push(r.status);
    }
    expect(statuses.slice(0, 10).every(s => s === 200)).toBe(true);
    expect(statuses[10]).toBe(429);
    expect(statuses[11]).toBe(429);
  });

  it('fails open when KV is unavailable (availability over enforcement, R-14)', async () => {
    const r = await handlePublicFeeds(
      new Request('http://localhost/api/v1/intel/kev.json'), {}, '/api/v1/intel/kev.json');
    expect(r.status).toBe(200);
  });

  it('pricing.json stays exempt (customers must always be able to read pricing)', async () => {
    const env = { SECURITY_HUB_KV: memKV() };
    for (let i = 0; i < 11; i++) {
      await handlePublicFeeds(new Request('http://localhost/api/v1/intel/kev.json'), env, '/api/v1/intel/kev.json');
    }
    const r = await handlePublicFeeds(
      new Request('http://localhost/api/v1/intel/pricing.json'), env, '/api/v1/intel/pricing.json');
    expect(r.status).toBe(200);
  });
});

describe('report links honor their promised expiry', () => {
  const reportFixture = (expiresAt) => JSON.stringify({
    report_id: 'r-ops-test', target: 'example.com',
    generated_at: '2026-07-01T00:00:00Z', expires_at: expiresAt,
  });

  async function download(expiresAt) {
    const kv = memKV();
    kv._store.set('report_token:tok-ops-test-1234', 'r-ops-test');
    kv._store.set('report:r-ops-test', reportFixture(expiresAt));
    return handleReportDownload(
      new Request('http://localhost/api/report/tok-ops-test-1234'),
      { SECURITY_HUB_KV: kv }, {});
  }

  it('an expired report returns 410 Gone, not the content', async () => {
    const r = await download('2026-07-02T00:00:00Z');
    expect(r.status).toBe(410);
    expect((await r.json()).error).toMatch(/expired/i);
  });

  it('an unexpired report still downloads', async () => {
    const r = await download('2126-01-01T00:00:00Z');
    expect(r.status).toBe(200);
  });

  it('an unknown token gets an honest 404 with the 7-day retention hint', async () => {
    const r = await handleReportDownload(
      new Request('http://localhost/api/report/never-issued-token'),
      { SECURITY_HUB_KV: memKV() }, {});
    expect(r.status).toBe(404);
    expect((await r.json()).hint).toMatch(/7 days/);
  });
});

describe('published scan burst rates equal the enforced constants', () => {
  it('pricing cards state exactly what the middleware enforces', () => {
    // Checks TIERS' actual runtime values rather than grepping middleware/auth.js's
    // source text for a hardcoded literal — the prior source-regex approach could
    // never have caught STARTER drifting (it was missing from TIERS entirely,
    // silently falling back to FREE's rate; see CAP-PROD-002 rate-limit authority
    // consolidation) since there was no literal "STARTER: {...burst_per_min: 5}"
    // text to match in the first place. Testing the real value catches that class
    // of gap instead of only confirming a number appears somewhere in the file.
    const html = readFileSync(new URL('../../frontend/index.html', import.meta.url), 'utf8');
    for (const [tier, rate] of [['FREE', 2], ['STARTER', 5], ['PRO', 20], ['ENTERPRISE', 60]]) {
      expect(TIERS[tier].burst_per_min, `${tier}.burst_per_min`).toBe(rate);
    }
    expect(html).toContain('2 scans/min burst');
    expect(html).toContain('5 scans/min burst');
    expect(html).toContain('20 scans/min burst');
    expect(html).toContain('60 scans/min burst');
  });
});
