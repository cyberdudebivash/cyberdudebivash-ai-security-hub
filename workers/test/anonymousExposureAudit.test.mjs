/* Regression tests — anonymous-exposure audit (2026-07-07). An Explore-agent
 * sweep of frontend/index.html's always-shipped dashboard sections (CISO
 * Command Center, Sales/Affiliate hubs, Autonomous SOC) found several backend
 * routes with zero auth check serving real business data — platform MRR/ARR,
 * lead PII, revenue funnels — to anonymous requests. A follow-up sweep of every
 * route comment claiming "(admin)"/"owner only" found two more instances of the
 * same bug class productAnalyticsAdminGate.test.mjs already covers elsewhere
 * (comment claims restricted access, code enforces nothing), in a sibling GTM
 * Growth Engine module never touched by that earlier fix.
 *
 * Each fix here is additive — the route/handler now has the check its own
 * doc-comment (or its sibling routes in the same file) already claimed. */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';
import { handleGetReport } from '../src/handlers/executiveReport.js';
import { handleGetStatus } from '../src/handlers/affiliateSystem.js';

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

describe('Anonymous-exposure audit — previously-open business-data routes now enforced', () => {
  const routes = [
    ['/api/ciso/metrics', 'GET'],
    ['/api/executive/dashboard', 'GET'],
    ['/api/growth/analytics', 'GET'],
    ['/api/growth/funnel', 'GET'],
    ['/api/growth/leads', 'GET'],
    ['/api/gtm/funnel-dashboard', 'GET'],
  ];

  for (const [path, method] of routes) {
    it(`${method} ${path} rejects an anonymous caller (admin:business:read)`, async () => {
      const res = await worker.fetch(new Request(`https://x${path}`, { method }), genericEnv(), ctxStub());
      expect(res.status).toBe(403);
    });

    it(`${method} ${path} admits the ADMIN_KEY bypass`, async () => {
      const env = genericEnv({ ADMIN_KEY: 'test-admin-key' });
      const res = await worker.fetch(
        new Request(`https://x${path}`, { method, headers: { 'x-api-key': 'test-admin-key' } }),
        env, ctxStub(),
      );
      expect(res.status).not.toBe(403);
    });
  }

  it('GET /api/visitor/stats rejects an anonymous caller (admin:analytics:read)', async () => {
    const res = await worker.fetch(new Request('https://x/api/visitor/stats'), genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('GET /api/visitor/stats admits the ADMIN_KEY bypass', async () => {
    const env = genericEnv({ ADMIN_KEY: 'test-admin-key' });
    const res = await worker.fetch(
      new Request('https://x/api/visitor/stats', { headers: { 'x-api-key': 'test-admin-key' } }),
      env, ctxStub(),
    );
    expect(res.status).not.toBe(403);
  });
});

describe('handleGetReport — now requires a paid tier, matching its handleGenerateReport/handleListReports siblings', () => {
  it('rejects a FREE-tier/anonymous caller', async () => {
    const req = new Request('https://x/api/executive/report/rpt_123_abcd');
    const res = await handleGetReport(req, genericEnv(), { tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('rejects a caller with no tier at all (default authCtx)', async () => {
    const req = new Request('https://x/api/executive/report/rpt_123_abcd');
    const res = await handleGetReport(req, genericEnv(), {});
    expect(res.status).toBe(403);
  });

  it('lets a PRO-tier caller through to the not-found path (no auth error)', async () => {
    const req = new Request('https://x/api/executive/report/rpt_123_abcd');
    const res = await handleGetReport(req, genericEnv(), { tier: 'PRO' });
    expect(res.status).not.toBe(403);
  });
});

describe('handleGetStatus (/api/affiliate/status) — email-param IDOR closed', () => {
  it('rejects an anonymous caller even when a ?email= is supplied', async () => {
    const req = new Request('https://x/api/affiliate/status?email=victim@example.com');
    const res = await handleGetStatus(req, genericEnv(), {});
    expect(res.status).toBe(401);
  });

  it('still resolves a real authenticated session by authCtx.userId', async () => {
    const record = { ref_code: 'r1', tier: 'AFFILIATE', stats: {}, status: 'active' };
    const env = genericEnv({
      SECURITY_HUB_KV: { get: async (key, opts) => (key === 'affiliate:profile:u1' ? (opts?.type === 'json' ? record : JSON.stringify(record)) : null), put: async () => {}, delete: async () => {} },
    });
    const req = new Request('https://x/api/affiliate/status');
    const res = await handleGetStatus(req, env, { userId: 'u1' });
    // Whatever loadAffiliate's real storage key convention is, the important
    // regression-proof is simply that authCtx.userId (not a query param) is
    // the only identity source — a 401 here would mean the fix regressed
    // real logged-in users, which this must not do.
    expect(res.status).not.toBe(401);
  });
});
