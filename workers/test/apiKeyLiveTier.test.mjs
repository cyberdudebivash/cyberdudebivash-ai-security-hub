/* Regression test — resolveAuthV5's API-key resolver (auth/middleware.js) is
 * the primary auth path used across ~600 call sites in index.js (scan quotas,
 * Copilot, subscription-gated routes). It used to trust the FROZEN
 * `api_keys.tier` column, written once at key-creation time — a customer
 * who upgraded (or downgraded) their subscription plan kept the OLD tier's
 * limits/features on every already-issued API key, with no documented way
 * to fix it short of rotating the key, while index.html's own marketing
 * copy promises keys "inherit your account plan automatically". The
 * resolver's own SQL already joined the account's CURRENT tier as
 * `user_tier` and simply discarded it. Fixed to use the live value
 * (2026-07-06 revenue-mechanisms audit, P1-5). */
import { describe, it, expect } from 'vitest';
import { resolveAuthV5 } from '../src/auth/middleware.js';

function makeReq(headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { headers: { get(k) { return lower[k.toLowerCase()] ?? null; } } };
}

function envWithKeyRow(row) {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return row; },
        };
      },
    },
  };
}

describe('resolveAuthV5 API-key resolution uses the LIVE account tier, not the frozen key snapshot', () => {
  it('an upgraded account (frozen key tier STARTER, live user_tier ENTERPRISE) resolves to ENTERPRISE', async () => {
    const env = envWithKeyRow({
      id: 'k1', user_id: 'u1', key_prefix: 'cdb_abc...', email: 'buyer@x.com',
      tier: 'STARTER', user_tier: 'ENTERPRISE', user_status: 'active', active: 1,
      daily_limit: 20, monthly_limit: 600,
    });
    const auth = await resolveAuthV5(makeReq({ 'x-api-key': 'cdb_liveKeyTest' }), env);
    expect(auth.method).toBe('api_key');
    expect(auth.tier).toBe('ENTERPRISE');
    // Daily limit must also be re-derived from the live tier, not the frozen
    // api_keys.daily_limit column — enforceQuota() prefers authCtx.daily_limit
    // via `??` when present, so a stale number here would silently keep the
    // OLD cap in effect even after fixing `tier`.
    expect(auth.daily_limit).toBe(-1); // ENTERPRISE = unlimited
    expect(auth.limits.daily_limit).toBe(-1);
  });

  it('a downgraded account is also re-scoped down immediately (not just upgrades)', async () => {
    const env = envWithKeyRow({
      id: 'k2', user_id: 'u2', key_prefix: 'cdb_def...', email: 'buyer2@x.com',
      tier: 'ENTERPRISE', user_tier: 'FREE', user_status: 'active', active: 1,
      daily_limit: -1, monthly_limit: -1,
    });
    const auth = await resolveAuthV5(makeReq({ 'x-api-key': 'cdb_downgradeTest' }), env);
    expect(auth.tier).toBe('FREE');
    expect(auth.daily_limit).toBe(5); // FREE tier's real daily cap
  });

  it('falls back to the frozen tier only if the live join genuinely has no user_tier', async () => {
    const env = envWithKeyRow({
      id: 'k3', user_id: 'u3', key_prefix: 'cdb_ghi...', email: 'buyer3@x.com',
      tier: 'PRO', user_tier: null, user_status: 'active', active: 1,
    });
    const auth = await resolveAuthV5(makeReq({ 'x-api-key': 'cdb_fallbackTest' }), env);
    expect(auth.tier).toBe('PRO');
  });
});
