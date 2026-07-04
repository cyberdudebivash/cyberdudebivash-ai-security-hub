/* Phase VIII — advertised entitlements & pricing must match enforced reality.
 *
 * Live-reproduced at scale (HTTP only), three customer-facing contradictions:
 *   1. /api/user/plan told a FREE user ai_analyze:false and reports:false, yet
 *      /api/ai/analyze returned 200 and /api/report/generate returned 201 for
 *      that same FREE user. The free tier was under-sold and the product
 *      contradicted its own plan page ("it says I can't but I can").
 *   2. /api docs `tiers` was a hardcoded copy that had drifted from the enforced
 *      TIER_LIMITS: FREE key_limit 2 (enforced 1) and — worse — STARTER
 *      scan_limit 10 (enforced 600), making STARTER look worse than FREE.
 *   3. The public plans page hardcoded FREE as "3/day" while the limiter enforces
 *      5/day.
 *
 * Fixes: PLAN_FEATURES.FREE reflects what FREE actually ships (analyze + reports);
 * the /api tiers block is DERIVED from TIER_LIMITS so it cannot drift; the plans
 * page states the enforced 5/day. These locks assert advertised == enforced.
 */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';
import { TIER_LIMITS, PLAN_FEATURES, hasAccess } from '../src/auth/apiKeys.js';

function kvStub() { return { get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) }; }
function dbStub() { const s = { bind: () => s, first: async () => null, all: async () => ({ results: [] }), run: async () => ({}) }; return { prepare: () => s, batch: async () => [] }; }
function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }
function baseEnv() { return { DB: dbStub(), KV: kvStub(), SECURITY_HUB_DB: dbStub(), SECURITY_HUB_KV: kvStub() }; }

describe('FREE plan-feature matrix tells the truth about what FREE ships', () => {
  it('advertises the capabilities FREE actually has (analyze + reports)', () => {
    expect(PLAN_FEATURES.FREE.ai_analyze).toBe(true);   // /api/ai/analyze is not PRO-gated
    expect(PLAN_FEATURES.FREE.reports).toBe(true);      // 7-day retention, Phase VII-certified
  });
  it('does NOT over-advertise genuinely paid capabilities', () => {
    expect(PLAN_FEATURES.FREE.ai_simulate).toBe(false); // PRO+ (gated 402)
    expect(PLAN_FEATURES.FREE.ai_forecast).toBe(false); // PRO+ (gated 402)
    expect(PLAN_FEATURES.FREE.api_access).toBe(false);  // /api/v1 premium surface (403 for FREE)
    expect(PLAN_FEATURES.FREE.priority_support).toBe(false);
  });
  it('the real PRO gates still hold via hasAccess (no regression)', () => {
    for (const t of ['FREE', 'STARTER']) {
      expect(hasAccess('ai_simulate', t)).toBe(false);
      expect(hasAccess('ai_forecast', t)).toBe(false);
    }
    for (const t of ['PRO', 'ENTERPRISE', 'MSSP']) {
      expect(hasAccess('ai_simulate', t)).toBe(true);
      expect(hasAccess('ai_forecast', t)).toBe(true);
    }
  });
});

describe('/api docs tiers are derived from enforced TIER_LIMITS (no drift)', () => {
  it('every advertised tier row matches what the platform enforces', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api'), baseEnv(), ctxStub());
    expect(res.status).toBe(200);
    const doc = await res.json();
    const map = { FREEMIUM: 'FREE', STARTER: 'STARTER', PRO: 'PRO', ENTERPRISE: 'ENTERPRISE' };
    for (const [docKey, tier] of Object.entries(map)) {
      const row = doc.tiers[docKey];
      const enforced = TIER_LIMITS[tier];
      expect(row, `${docKey} present`).toBeTruthy();
      expect(row.daily_limit, `${docKey} daily_limit`).toBe(enforced.daily_limit);
      expect(row.scan_limit, `${docKey} scan_limit`).toBe(enforced.scan_limit);
      expect(row.key_limit, `${docKey} key_limit`).toBe(enforced.api_keys);
      expect(row.price_inr, `${docKey} price`).toBe(enforced.price_inr);
    }
    // The specific regressions that started this: FREE keys = 1, STARTER scans = 600.
    expect(doc.tiers.FREEMIUM.key_limit).toBe(1);
    expect(doc.tiers.STARTER.scan_limit).toBe(600);
    expect(doc.tiers.STARTER.scan_limit).toBeGreaterThan(doc.tiers.FREEMIUM.scan_limit);
  });
});

describe('public plans page states the enforced daily allowance', () => {
  it('FREE shows 5/day (matches TIER_LIMITS.FREE.daily_limit), not the stale 3/day', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/subscription/plans'), baseEnv(), ctxStub());
    expect(res.status).toBe(200);
    const body = await res.json();
    const free = body.data.plans.find((p) => p.tier === 'FREE');
    expect(free.scans).toBe('5/day');
    expect(String(TIER_LIMITS.FREE.daily_limit)).toBe('5');
  });
});
