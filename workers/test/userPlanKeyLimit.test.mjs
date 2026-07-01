// Regression test — GET /api/user/plan never returned a key_limit field, but
// frontend/user-dashboard.html reads d.key_limit to show "of N API keys
// allowed". The daily_limit/key_limit/price_inr were also being read off
// d.plan (a plain tier string, not an object) — a separate frontend fix —
// this test locks in the backend half: the real per-tier key limit is now
// actually present on the response.
import { describe, it, expect } from 'vitest';
import { handleGetUserPlan } from '../src/handlers/subscription.js';

function req(headers = {}) {
  return new Request('https://x/api/user/plan', { headers });
}

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
