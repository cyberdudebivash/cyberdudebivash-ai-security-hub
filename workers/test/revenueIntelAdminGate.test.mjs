/* Revenue Intelligence — admin-only gate (2026-07-14 Production Release Gate
 * Phase II, security sweep finding). GET /api/revenue/intel/history|forecast|
 * waterfall|cohorts|tiermix (handlers/revenueIntelligence.js) previously only
 * required requireAuth() (isRealUser — ANY authenticated user, any tier).
 * Since a non-admin caller can't override org_id, every one of these routes
 * fell back to org_id='default' — this platform's own real business data —
 * meaning any signed-up customer (including the cheapest paid tier) could
 * read the platform's real aggregate MRR/ARR, revenue forecast + churn rate,
 * MRR waterfall, cohort retention, and tier-mix revenue breakdown.
 *
 * This is the same vulnerability class already fixed elsewhere in this
 * codebase (GET /api/revenue/dashboard, PR #233; /v24/ceo/dashboard and
 * /v24/sales/pipeline, PR #239) — missed in this one file, which had zero
 * prior test coverage. Fixed by adding the same requireAdmin() gate this
 * file's own sibling POST /api/revenue/intel/snapshot already used
 * correctly. */
import { describe, it, expect } from 'vitest';
import {
  handleRevenueHistory, handleRevenueForecast, handleRevenueWaterfall,
  handleCohortAnalysis, handleTierMix, handleCreateSnapshot,
} from '../src/handlers/revenueIntelligence.js';

function req(path) {
  return new Request(`https://x${path}`, { method: 'GET' });
}

function fakeDB() {
  const stmt = { bind() { return this; }, async all() { return { results: [] }; }, async first() { return null; }, async run() { return {}; } };
  return { prepare: () => stmt };
}

const ANON       = {};
const FREE_USER  = { authenticated: true, userId: 'u1', tier: 'FREE' };
const STARTER_USER = { authenticated: true, userId: 'u2', tier: 'STARTER' };
const ADMIN      = { authenticated: true, userId: 'admin1', isAdmin: true };

const ENV = { SECURITY_HUB_DB: fakeDB(), SECURITY_HUB_KV: { async get() { return null; }, async put() {} } };

function attach(request, authCtx) {
  request.user = authCtx;
  return request;
}

describe('Revenue Intelligence GET routes — admin-only (was: any authenticated user)', () => {
  const handlers = {
    'history':   handleRevenueHistory,
    'forecast':  handleRevenueForecast,
    'waterfall': handleRevenueWaterfall,
    'cohorts':   handleCohortAnalysis,
    'tiermix':   handleTierMix,
  };

  for (const [name, handler] of Object.entries(handlers)) {
    it(`${name}: an anonymous caller is rejected (401)`, async () => {
      const res = await handler(attach(req(`/api/revenue/intel/${name}`), ANON), ENV);
      expect(res.status).toBe(401);
    });

    it(`${name}: a regular authenticated FREE-tier customer is rejected (403), not shown real revenue data`, async () => {
      const res = await handler(attach(req(`/api/revenue/intel/${name}`), FREE_USER), ENV);
      expect(res.status).toBe(403);
    });

    it(`${name}: a paying STARTER-tier customer is also rejected (403) — paying for a product tier is not staff access`, async () => {
      const res = await handler(attach(req(`/api/revenue/intel/${name}`), STARTER_USER), ENV);
      expect(res.status).toBe(403);
    });

    it(`${name}: admin is admitted`, async () => {
      const res = await handler(attach(req(`/api/revenue/intel/${name}`), ADMIN), ENV);
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
    });
  }

  it('sibling POST /api/revenue/intel/snapshot is unaffected — still admin-gated as before', async () => {
    const res = await handleCreateSnapshot(attach(new Request('https://x/api/revenue/intel/snapshot', { method: 'POST' }), FREE_USER), ENV);
    expect(res.status).toBe(403);
  });
});
