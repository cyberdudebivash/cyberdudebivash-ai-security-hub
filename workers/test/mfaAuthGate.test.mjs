/* MFA endpoints must require a REAL logged-in principal.
 *
 * The /api/auth/mfa/* block gated on `authCtx.authenticated`, but resolveAuthV5
 * returns authenticated:true for the anonymous IP-fallback tier (user_id === null).
 * So an unauthenticated caller reached handleMFASetup and minted a TOTP secret
 * bound to a null user (otpauth …:null; KV key `mfa_setup:null` shared across all
 * anonymous callers) — and could reach enable/disable too. The gate now requires
 * a concrete user_id.
 *
 * Drives the real exported worker.fetch() so the actual route/gate wiring is tested.
 */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

function kvStub() {
  const m = new Map();
  return { get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => { m.set(k, v); }, delete: async (k) => { m.delete(k); }, list: async () => ({ keys: [] }) };
}
function dbStub() {
  const stmt = { bind: () => stmt, first: async () => null, all: async () => ({ results: [] }), run: async () => ({}) };
  return { prepare: () => stmt, batch: async () => [] };
}
function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }

function env(extra = {}) {
  return { DB: dbStub(), KV: kvStub(), SECURITY_HUB_DB: dbStub(), SECURITY_HUB_KV: kvStub(), ...extra };
}

describe('/api/auth/mfa/* — requires a real logged-in user', () => {
  it('anonymous POST /api/auth/mfa/setup is rejected (was: 200 minting a :null secret)', async () => {
    const req = new Request('https://cyberdudebivash.in/api/auth/mfa/setup', { method: 'POST' });
    const res = await worker.fetch(req, env(), ctxStub());
    expect(res.status).toBe(401);
    // Critically: no TOTP secret is minted for an anonymous caller
    const body = await res.json().catch(() => ({}));
    expect(body.secret).toBeUndefined();
    expect(body.otpauth_url).toBeUndefined();
  });

  it('anonymous POST /api/auth/mfa/enable is rejected', async () => {
    const req = new Request('https://cyberdudebivash.in/api/auth/mfa/enable', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ totp_code: '123456' }),
    });
    const res = await worker.fetch(req, env(), ctxStub());
    expect(res.status).toBe(401);
  });

  it('anonymous POST /api/auth/mfa/disable is rejected', async () => {
    const req = new Request('https://cyberdudebivash.in/api/auth/mfa/disable', { method: 'POST' });
    const res = await worker.fetch(req, env(), ctxStub());
    expect(res.status).toBe(401);
  });

  it('a real authenticated principal passes the gate (admin key → user_id present)', async () => {
    // ADMIN_KEY path in resolveAuthV5 yields user_id:'admin' → gate must NOT 401.
    const req = new Request('https://cyberdudebivash.in/api/auth/mfa/status', {
      method: 'GET', headers: { 'x-api-key': 'test-admin-key-123' },
    });
    const res = await worker.fetch(req, env({ ADMIN_KEY: 'test-admin-key-123' }), ctxStub());
    expect(res.status).not.toBe(401);
  });
});
