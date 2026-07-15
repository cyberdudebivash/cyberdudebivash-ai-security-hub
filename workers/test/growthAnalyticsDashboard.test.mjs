/* Regression test — CAP-DASH-003 (Product & Growth Analytics dashboard).
 * frontend/growth-analytics.js was real, complete, and correctly admin-gated
 * server-side, but no page ever loaded it via a <script> tag — the Growth
 * tab never appeared anywhere. Wiring it into frontend/index.html (alongside
 * its sibling command-center panel loaders) surfaced two pre-existing shape
 * mismatches between this handler and its own frontend consumer that had
 * never been exercised end-to-end before:
 *   1. handleGrowthMetrics returned its payload flat (`Response.json(metrics)`)
 *      while the frontend expected `{ metrics: {...} }` — and while its own
 *      sibling endpoints (funnel, adoption) both already use a wrapped shape.
 *   2. The backend computed `activation_rate_7d`; the frontend read
 *      `activation_rate` (no suffix) — always undefined.
 * Both are fixed here: the backend now wraps consistently with its siblings,
 * and the frontend reads the real field name. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import worker from '../src/index.js';

function genericEnv(extra = {}) {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
          async run() { return { success: true }; },
        };
      },
    },
    KV: { get: async () => null, put: async () => {}, delete: async () => {} },
    ...extra,
  };
}

function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

function adminEnv() {
  return genericEnv({ ADMIN_KEY: 'test-admin-key' });
}

describe('CAP-DASH-003 — GET /api/analytics/p3/growth response shape (real, not mocked)', () => {
  it('wraps the payload as { metrics, period }, matching its sibling funnel/adoption endpoints', async () => {
    const res = await worker.fetch(
      new Request('https://x/api/analytics/p3/growth', { headers: { 'x-api-key': 'test-admin-key' } }),
      adminEnv(), ctxStub(),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.metrics).toBeDefined();
    expect(body.period).toBe('30d');
    // Flat top-level fields must NOT exist — this is the exact bug: the frontend
    // destructures `{ metrics }` and would silently read undefined if the API
    // ever regresses back to a flat shape.
    expect(body.dau).toBeUndefined();
  });

  it('computes activation_rate_7d under metrics — the exact field name the frontend now reads', async () => {
    const res = await worker.fetch(
      new Request('https://x/api/analytics/p3/growth', { headers: { 'x-api-key': 'test-admin-key' } }),
      adminEnv(), ctxStub(),
    );
    const { metrics } = await res.json();
    expect(metrics).toHaveProperty('activation_rate_7d');
    expect(typeof metrics.activation_rate_7d).toBe('number');
  });

  it('the cached path returns the same wrapped shape as the fresh-computation path', async () => {
    const cachedPayload = { metrics: { dau: 5, wau: 20, mau: 80, activation_rate_7d: 40 }, period: '30d' };
    const env = adminEnv();
    env.KV.get = async () => cachedPayload;
    const res = await worker.fetch(
      new Request('https://x/api/analytics/p3/growth', { headers: { 'x-api-key': 'test-admin-key' } }),
      env, ctxStub(),
    );
    const body = await res.json();
    expect(body.metrics).toEqual(cachedPayload.metrics);
    expect(body.period).toBe('30d');
    expect(body.cached).toBe(true);
  });
});

describe('CAP-DASH-003 — frontend wiring (real file content, not a mock)', () => {
  const html = readFileSync(new URL('../../frontend/index.html', import.meta.url), 'utf8');
  const js = readFileSync(new URL('../../frontend/growth-analytics.js', import.meta.url), 'utf8');

  it('frontend/index.html loads growth-analytics.js', () => {
    expect(html).toMatch(/<script[^>]*src="\/growth-analytics\.js"/);
  });

  it('growth-analytics.js reads the real backend field name (activation_rate_7d), not the old mismatched one', () => {
    expect(js).toContain('metrics.activation_rate_7d');
    expect(js).not.toContain('metrics.activation_rate ');
    expect(js).not.toContain('metrics.activation_rate)');
    expect(js).not.toContain('metrics.activation_rate ||');
  });

  it('growth-analytics.js still targets the shared command-center shell other panels use', () => {
    expect(js).toContain(".cdb-cc-nav");
    expect(js).toContain(".cdb-cc-body");
  });
});
