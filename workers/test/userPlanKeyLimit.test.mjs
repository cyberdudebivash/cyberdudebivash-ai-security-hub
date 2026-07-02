// Regression test — GET /api/user/plan never returned a key_limit field, but
// frontend/user-dashboard.html reads d.key_limit to show "of N API keys
// allowed". The daily_limit/key_limit/price_inr were also being read off
// d.plan (a plain tier string, not an object) — a separate frontend fix —
// this test locks in the backend half: the real per-tier key limit is now
// actually present on the response.
import { describe, it, expect } from 'vitest';
import { handleGetUserPlan } from '../src/handlers/subscription.js';
import { TIER_LIMITS } from '../src/auth/apiKeys.js';

function req(headers = {}) {
  return new Request('https://x/api/user/plan', { headers });
}

// The DISPLAYED key limit (TIER_LIMITS[tier].api_keys, shown by /api/user/plan
// and /api/keys tier_limits) MUST equal the ENFORCED limit (MAX_KEYS_BY_TIER in
// handlers/apikeys.js) and the public pricing page. FREE previously advertised
// 2 keys while both enforcement and the pricing page said 1 — /api/keys even
// returned max_keys:1 and tier_limits.api_keys:2 in the same response.
const ENFORCED_MAX_KEYS = { FREE: 1, STARTER: 2, PRO: 5, ENTERPRISE: 20, MSSP: -1 };

describe('key-limit consistency — displayed equals enforced (matches pricing)', () => {
  for (const [tier, enforced] of Object.entries(ENFORCED_MAX_KEYS)) {
    it(`${tier}: TIER_LIMITS.api_keys (${enforced}) matches enforced/pricing`, () => {
      expect(TIER_LIMITS[tier].api_keys).toBe(enforced);
    });
  }
});

describe('handleGetUserPlan — key_limit field', () => {
  it('returns the real per-tier API key limit', async () => {
    const env = { DB: null, KV: null };
    const authCtx = { authenticated: true, method: 'jwt', tier: 'PRO', user_id: 'u_1', email: 'user@example.com' };
    const res  = await handleGetUserPlan(req(), env, authCtx);
    const body = await res.json();
    expect(body.plan).toBe('PRO');
    expect(body.key_limit).toBe(5); // TIER_LIMITS.PRO.api_keys
  });

  it('returns -1 (unlimited) for MSSP, not the FREE-tier default', async () => {
    const env = { DB: null, KV: null };
    const authCtx = { authenticated: true, method: 'jwt', tier: 'MSSP', user_id: 'u_2', email: 'mssp@example.com' };
    const res  = await handleGetUserPlan(req(), env, authCtx);
    const body = await res.json();
    expect(body.key_limit).toBe(-1);
  });
});
