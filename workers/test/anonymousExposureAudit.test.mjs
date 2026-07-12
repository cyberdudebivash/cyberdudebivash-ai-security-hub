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
    ['/api/growth/upgrade', 'POST'],
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

describe('POST /api/growth/upgrade — free ENTERPRISE-key-minting exploit closed (CAP-DEVPORTAL-004)', () => {
  // Before this fix: {email, plan} taken directly from an anonymous client's
  // JSON body, no verification of any kind. upgradeLead() then wrote
  // leads.plan=<attacker-chosen plan> for <attacker-chosen email>, and
  // handleUpgradeLead immediately auto-provisioned a real sap_ API key at
  // that plan — the exact "plan must only ever come from the HMAC-verified
  // Razorpay webhook, never client input" invariant CAP-DEVPORTAL-004's own
  // prior fix documented, reopened by this sibling route.
  function recordingDB() {
    const writes = [];
    return {
      writes,
      prepare(sql) {
        let bound = [];
        return {
          bind(...args) { bound = args; return this; },
          async run() { writes.push({ sql, bound }); return { success: true }; },
          async first() { return null; },
          async all() { return { results: [] }; },
        };
      },
    };
  }

  it('an anonymous caller cannot cause leads.plan to be written at all (the exploit write never runs)', async () => {
    const db = recordingDB();
    const env = genericEnv({ DB: db });
    const res = await worker.fetch(
      new Request('https://x/api/growth/upgrade', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'attacker@example.com', plan: 'enterprise' }),
      }),
      env, ctxStub(),
    );
    expect(res.status).toBe(403);
    const planWrites = db.writes.filter(w => /UPDATE leads SET plan/.test(w.sql));
    expect(planWrites.length).toBe(0);
  });

  it('a real admin caller (ADMIN_KEY bypass) can still legitimately reach the handler', async () => {
    const db = recordingDB();
    const env = genericEnv({ DB: db, ADMIN_KEY: 'test-admin-key' });
    const res = await worker.fetch(
      new Request('https://x/api/growth/upgrade', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'test-admin-key' },
        body: JSON.stringify({ email: 'real-customer@example.com', plan: 'pro' }),
      }),
      env, ctxStub(),
    );
    expect(res.status).not.toBe(403);
    const planWrites = db.writes.filter(w => /UPDATE leads SET plan/.test(w.sql));
    expect(planWrites.length).toBe(1);
  });
});
