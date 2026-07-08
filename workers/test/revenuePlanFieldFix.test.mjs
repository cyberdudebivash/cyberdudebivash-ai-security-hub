/* Regression test — revenue.js, revenueDashboard.js, and defenseMarketplace.js
 * gated PRO/ENTERPRISE-only revenue features on `authCtx.plan` and
 * `authCtx.role === 'admin'`. Neither field is ever actually set anywhere in
 * the auth layer (verified: no auth/*.js file assigns `plan` or `role` on any
 * authCtx it returns) — the real fields are `authCtx.tier`
 * ('FREE'/'PRO'/'ENTERPRISE'/etc, uppercase) and `authCtx.isAdmin`.
 *
 * Before this fix: a real, paying ENTERPRISE customer's authCtx.tier ===
 * 'ENTERPRISE' never matched authCtx.plan === undefined, so
 * handleRevenueDashboard, handleChurnRisk, handleFunnelMetrics,
 * handleEnhancedDashboard, and handleRevenueTrends were all unconditionally
 * PLAN_REQUIRED/403 for every real customer AND every admin (the `role !==
 * 'admin'` escape hatch was equally dead). This locks that a real tier now
 * passes the gate, and a FREE-tier caller is still correctly rejected. */
import { describe, it, expect } from 'vitest';
import { handleRevenueDashboard, handleChurnRisk, handleFunnelMetrics } from '../src/handlers/revenue.js';
import { handleEnhancedDashboard, handleRevenueTrends } from '../src/handlers/revenueDashboard.js';

const FREE_USER       = { authenticated: true, userId: 'u1', tier: 'FREE' };
const ENTERPRISE_USER = { authenticated: true, userId: 'u2', tier: 'ENTERPRISE' };
const PRO_USER        = { authenticated: true, userId: 'u3', tier: 'PRO' };
const OWNER           = { authenticated: true, userId: 'admin', isAdmin: true };

function fakeEnv() {
  const noop = { async all(){ return { results: [] }; }, async first(){ return null; }, async run(){ return { meta: { changes: 0 } }; } };
  const stmt = () => ({ bind: () => noop, ...noop });
  return { DB: { prepare: stmt, batch: async () => [] }, SECURITY_HUB_KV: { get: async () => null, put: async () => {} } };
}

describe('revenue.js — plan gate uses the real tier field', () => {
  it('handleRevenueDashboard: FREE tier is rejected (403)', async () => {
    const res = await handleRevenueDashboard(new Request('https://x'), fakeEnv(), FREE_USER);
    expect(res.status).toBe(403);
  });

  it('handleRevenueDashboard: a real ENTERPRISE customer is NOT blocked at the gate', async () => {
    const res = await handleRevenueDashboard(new Request('https://x'), fakeEnv(), ENTERPRISE_USER);
    expect(res.status).not.toBe(403);
  });

  it('handleChurnRisk: FREE tier is rejected (403)', async () => {
    const res = await handleChurnRisk(new Request('https://x'), fakeEnv(), FREE_USER);
    expect(res.status).toBe(403);
  });

  it('handleChurnRisk: a real PRO customer is NOT blocked at the gate', async () => {
    const res = await handleChurnRisk(new Request('https://x'), fakeEnv(), PRO_USER);
    expect(res.status).not.toBe(403);
  });

  it('handleFunnelMetrics: FREE tier is rejected (403)', async () => {
    const res = await handleFunnelMetrics(new Request('https://x'), fakeEnv(), FREE_USER);
    expect(res.status).toBe(403);
  });

  it('handleFunnelMetrics: the platform owner (isAdmin) is NOT blocked at the gate', async () => {
    const res = await handleFunnelMetrics(new Request('https://x'), fakeEnv(), OWNER);
    expect(res.status).not.toBe(403);
  });
});

describe('revenueDashboard.js — plan gate uses the real tier field', () => {
  it('handleEnhancedDashboard: FREE tier is rejected (403)', async () => {
    const res = await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), FREE_USER);
    expect(res.status).toBe(403);
  });

  it('handleEnhancedDashboard: a real ENTERPRISE customer is NOT blocked at the gate', async () => {
    const res = await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), ENTERPRISE_USER);
    expect(res.status).not.toBe(403);
  });

  it('handleEnhancedDashboard: the platform owner (isAdmin) is NOT blocked at the gate', async () => {
    const res = await handleEnhancedDashboard(new Request('https://x'), fakeEnv(), OWNER);
    expect(res.status).not.toBe(403);
  });

  it('handleRevenueTrends: FREE tier is rejected (403)', async () => {
    const res = await handleRevenueTrends(new Request('https://x'), fakeEnv(), FREE_USER);
    expect(res.status).toBe(403);
  });

  it('handleRevenueTrends: a real PRO customer is NOT blocked at the gate', async () => {
    const res = await handleRevenueTrends(new Request('https://x'), fakeEnv(), PRO_USER);
    expect(res.status).not.toBe(403);
  });
});
