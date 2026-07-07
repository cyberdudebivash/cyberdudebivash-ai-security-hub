/* Regression test — RBAC-0. handlers/productAnalytics.js's own header comment
 * claims growth/funnel/adoption/prune are admin-only, but nothing in code
 * enforced it — any caller (including anonymous) could read growth KPIs and
 * funnel/adoption analytics, or prune stored events. Now enforced via
 * requireCan(..., 'admin:analytics:read'). The event-ingestion endpoint is
 * intentionally left public (it's the client-side tracking call itself). */
import { describe, it, expect } from 'vitest';
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
    SECURITY_HUB_DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
          async run() { return { success: true }; },
        };
      },
    },
    SECURITY_HUB_KV: { get: async () => null, put: async () => {}, delete: async () => {} },
    ...extra,
  };
}

function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

describe('Product Analytics admin routes (RBAC-0) — now actually enforced', () => {
  it('GET /api/analytics/p3/growth rejects an anonymous caller', async () => {
    const res = await worker.fetch(new Request('https://x/api/analytics/p3/growth'), genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('GET /api/analytics/p3/funnel rejects an anonymous caller', async () => {
    const res = await worker.fetch(new Request('https://x/api/analytics/p3/funnel'), genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('GET /api/analytics/p3/adoption rejects an anonymous caller', async () => {
    const res = await worker.fetch(new Request('https://x/api/analytics/p3/adoption'), genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('POST /api/analytics/p3/prune rejects an anonymous caller', async () => {
    const res = await worker.fetch(new Request('https://x/api/analytics/p3/prune', { method: 'POST' }), genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('the ADMIN_KEY bypass is admitted to growth metrics', async () => {
    const env = genericEnv({ ADMIN_KEY: 'test-admin-key' });
    const res = await worker.fetch(new Request('https://x/api/analytics/p3/growth', { headers: { 'x-api-key': 'test-admin-key' } }), env, ctxStub());
    expect(res.status).not.toBe(403);
  });

  it('POST /api/analytics/p3/event (client-side tracking ingest) remains public — unaffected', async () => {
    const res = await worker.fetch(
      new Request('https://x/api/analytics/p3/event', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ event: 'page_view' }) }),
      genericEnv(), ctxStub(),
    );
    expect(res.status).not.toBe(403);
  });
});
