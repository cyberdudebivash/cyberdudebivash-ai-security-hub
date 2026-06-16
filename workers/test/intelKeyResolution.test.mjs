/* Regression tests — self-serve API keys on the intel API.
 * The intel monetization API resolves x-api-key via middleware/auth.js. It must
 * accept BOTH KV-provisioned keys (legacy/Stripe paid flow) AND D1 self-serve
 * keys generated via POST /api/keys (cdb_*), so a key created in the developer
 * portal authenticates on the paid feeds exactly as the docs promise. */
import { describe, it, expect } from 'vitest';
import { resolveAuth } from '../src/middleware/auth.js';

function makeReq(headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { headers: { get(k) { return lower[k.toLowerCase()] ?? null; } } };
}

describe('intel API key resolution (KV + D1 self-serve)', () => {
  it('resolves a KV-provisioned key to its tier (legacy/paid path)', async () => {
    const env = {
      SECURITY_HUB_KV: { async get(k) { return k === 'apikey:cdb_kvkey' ? JSON.stringify({ tier: 'PRO', active: true, owner_email: 'kv@x.com' }) : null; } },
      DB: null,
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_kvkey' }), env);
    expect(auth.authenticated).toBe(true);
    expect(auth.tier).toBe('PRO');
  });

  it('falls back to D1 for a self-serve cdb_ key and uses the CURRENT account tier', async () => {
    const env = {
      SECURITY_HUB_KV: { async get() { return null; } }, // not in KV
      DB: { prepare() { return { bind() { return this; }, async first() {
        return { id: 7, user_id: 'u1', key_prefix: 'cdb_abc...', label: 'CI', tier: 'STARTER', user_tier: 'ENTERPRISE', user_status: 'active', active: 1 };
      } }; } },
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_selfserve_key_value' }), env);
    expect(auth.authenticated).toBe(true);
    expect(auth.method).toBe('api_key');
    expect(auth.tier).toBe('ENTERPRISE'); // account upgrade applies immediately
  });

  it('rejects an inactive user even with a valid D1 key row', async () => {
    const env = {
      SECURITY_HUB_KV: { async get() { return null; } },
      DB: { prepare() { return { bind() { return this; }, async first() {
        return { id: 8, user_id: 'u2', tier: 'PRO', user_tier: 'PRO', user_status: 'suspended', active: 1 };
      } }; } },
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_suspended_user_key' }), env);
    expect(auth.authenticated).toBe(false);
  });

  it('returns invalid for an unknown cdb_ key (absent from KV and D1)', async () => {
    const env = {
      SECURITY_HUB_KV: { async get() { return null; } },
      DB: { prepare() { return { bind() { return this; }, async first() { return null; } }; } },
    };
    const auth = await resolveAuth(makeReq({ 'x-api-key': 'cdb_does_not_exist' }), env);
    expect(auth.authenticated).toBe(false);
  });

  it('IP fallback to FREE when no key is supplied', async () => {
    const env = { SECURITY_HUB_KV: { async get() { return null; } }, DB: null };
    const auth = await resolveAuth(makeReq({ 'CF-Connecting-IP': '1.2.3.4' }), env);
    expect(auth.tier).toBe('FREE');
    expect(auth.method).toBe('ip_fallback');
  });
});
