/* Regression test — two rounds, same session.
 *
 * Round 1: revenue.js/revenueDashboard.js/defenseMarketplace.js gated
 * PRO/ENTERPRISE-only revenue features on `authCtx.plan`/`authCtx.role`,
 * fields never set on a directly-constructed authCtx — real customers were
 * unconditionally blocked. Fixed to check authCtx.tier/isAdmin.
 *
 * Round 2 (this file's real point): that first fix broke live production.
 * index.js does NOT always pass the full authCtx to these handlers — for
 * handleChurnRisk, handleFunnelMetrics, handleEnhancedDashboard,
 * handleRevenueTrends, and handleGetSolution, it constructs a NARROWED
 * object: { userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }
 * (or similar). authCtx.role is itself correctly derived by
 * withAuthAliases() before that narrowing (2026-07-06 revenue-mechanisms
 * audit, P1-4) — so the ORIGINAL plan/role checks were already correct for
 * those exact call sites. Checking tier/isAdmin only broke them for every
 * real customer, live, until this fix.
 *
 * This suite tests BOTH shapes a real index.js route can actually produce —
 * the full authCtx (msspTenantPlatform.js, v24Handler.js,
 * platformMetricsAuthority.js, handleRevenueMetrics, handleRevenueDashboard
 * after its call-site fix) and the narrowed { userId, plan, role } wrapper
 * (handleChurnRisk, handleFunnelMetrics, handleEnhancedDashboard,
 * handleRevenueTrends, handleGetSolution) — because testing only one shape
 * is exactly what let the round-1 regression through undetected. */
import { describe, it, expect } from 'vitest';
import { handleRevenueDashboard, handleChurnRisk, handleFunnelMetrics } from '../src/handlers/revenue.js';
import { handleEnhancedDashboard, handleRevenueTrends } from '../src/handlers/revenueDashboard.js';
import { handleGetSolution } from '../src/handlers/defenseMarketplace.js';

// ── Shape A: full authCtx (resolveAuthV5 output) ───────────────────────────
const FULL_FREE       = { authenticated: true, userId: 'u1', tier: 'FREE' };
const FULL_ENTERPRISE = { authenticated: true, userId: 'u2', tier: 'ENTERPRISE' };
const FULL_PRO        = { authenticated: true, userId: 'u3', tier: 'PRO' };
const FULL_OWNER      = { authenticated: true, userId: 'admin', isAdmin: true };

// ── Shape B: index.js's narrowed wrapper — { userId, plan, role } ─────────
// Mirrors index.js's actual `{ userId: authCtx.userId, plan:
// authCtx.tier?.toLowerCase(), role: authCtx.role }` construction exactly —
// including that `role` only exists at all once withAuthAliases() derives
// it (never a raw 'admin' string a client could forge).
const WRAP_FREE       = { userId: 'u1', plan: 'free' };
const WRAP_ENTERPRISE = { userId: 'u2', plan: 'enterprise' };
const WRAP_PRO        = { userId: 'u3', plan: 'pro' };
const WRAP_OWNER      = { userId: 'admin', plan: 'free', role: 'admin' };

function fakeEnv() {
  const noop = { async all(){ return { results: [] }; }, async first(){ return null; }, async run(){ return { meta: { changes: 0 } }; } };
  const stmt = () => ({ bind: () => noop, ...noop });
  return { DB: { prepare: stmt, batch: async () => [] }, SECURITY_HUB_KV: { get: async () => null, put: async () => {} } };
}

describe('revenue.js — plan gate works with both a full authCtx and index.js\'s narrowed wrapper', () => {
  it('handleRevenueDashboard (full authCtx, its actual call-site shape post-fix): FREE rejected, ENTERPRISE admitted', async () => {
    expect((await handleRevenueDashboard(new Request('https://x'), fakeEnv(), FULL_FREE)).status).toBe(403);
    expect((await handleRevenueDashboard(new Request('https://x'), fakeEnv(), FULL_ENTERPRISE)).status).not.toBe(403);
  });

  it('handleChurnRisk (narrowed wrapper, its actual call-site shape): FREE rejected, PRO admitted', async () => {
    expect((await handleChurnRisk(new Request('https://x'), fakeEnv(), WRAP_FREE)).status).toBe(403);
    expect((await handleChurnRisk(new Request('https://x'), fakeEnv(), WRAP_PRO)).status).not.toBe(403);
  });

  it('handleChurnRisk: also works if ever called with a full authCtx instead', async () => {
    expect((await handleChurnRisk(new Request('https://x'), fakeEnv(), FULL_FREE)).status).toBe(403);
    expect((await handleChurnRisk(new Request('https://x'), fakeEnv(), FULL_PRO)).status).not.toBe(403);
  });

  it('handleFunnelMetrics (narrowed wrapper): FREE rejected, admin (role) admitted', async () => {
    expect((await handleFunnelMetrics(new Request('https://x'), fakeEnv(), WRAP_FREE)).status).toBe(403);
    expect((await handleFunnelMetrics(new Request('https://x'), fakeEnv(), WRAP_OWNER)).status).not.toBe(403);
  });

  it('handleFunnelMetrics: also works if ever called with a full authCtx instead', async () => {
    expect((await handleFunnelMetrics(new Request('https://x'), fakeEnv(), FULL_FREE)).status).toBe(403);
    expect((await handleFunnelMetrics(new Request('https://x'), fakeEnv(), FULL_OWNER)).status).not.toBe(403);
  });
});

describe('revenueDashboard.js — plan gate works with both shapes', () => {
  it('handleEnhancedDashboard (narrowed wrapper, its actual call-site shape): FREE rejected, ENTERPRISE admitted', async () => {
    expect((await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), WRAP_FREE)).status).toBe(403);
    expect((await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), WRAP_ENTERPRISE)).status).not.toBe(403);
  });

  it('handleEnhancedDashboard: admin (narrowed wrapper role) is admitted', async () => {
    expect((await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), WRAP_OWNER)).status).not.toBe(403);
  });

  it('handleEnhancedDashboard: also works if ever called with a full authCtx instead', async () => {
    expect((await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), FULL_FREE)).status).toBe(403);
    expect((await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), FULL_ENTERPRISE)).status).not.toBe(403);
  });

  it('handleRevenueTrends (narrowed wrapper, its actual call-site shape): FREE rejected, PRO admitted', async () => {
    expect((await handleRevenueTrends(new Request('https://x'), fakeEnv(), WRAP_FREE)).status).toBe(403);
    expect((await handleRevenueTrends(new Request('https://x'), fakeEnv(), WRAP_PRO)).status).not.toBe(403);
  });

  it('handleRevenueTrends: also works if ever called with a full authCtx instead', async () => {
    expect((await handleRevenueTrends(new Request('https://x'), fakeEnv(), FULL_FREE)).status).toBe(403);
    expect((await handleRevenueTrends(new Request('https://x'), fakeEnv(), FULL_PRO)).status).not.toBe(403);
  });
});

describe('defenseMarketplace.js — handleGetSolution purchase-access check works with both shapes', () => {
  function envWithSolution() {
    const env = fakeEnv();
    env.DB.prepare = () => ({
      bind: () => ({
        first: async () => ({ id: 'sol1', title: 'Test Solution', category: 'soar', price_inr: 999, description: 'd', tags: '[]' }),
        run: async () => ({ meta: { changes: 1 } }),
      }),
    });
    return env;
  }

  it('a narrowed-wrapper ENTERPRISE customer (its actual call-site shape) gets the access bypass', async () => {
    const res  = await handleGetSolution(new Request('https://x'), envWithSolution(), { userId: 'u2', plan: 'enterprise', email: 'e@x.com' }, 'sol1');
    const body = await res.json();
    expect(body.has_access).toBe(true);
  });

  it('a narrowed-wrapper FREE customer with no purchase does not get the bypass', async () => {
    const res  = await handleGetSolution(new Request('https://x'), envWithSolution(), { userId: 'u1', plan: 'free', email: 'e@x.com' }, 'sol1');
    const body = await res.json();
    expect(body.has_access).toBe(false);
  });
});
