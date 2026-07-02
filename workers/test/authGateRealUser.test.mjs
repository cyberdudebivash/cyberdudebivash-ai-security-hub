/* EH-03 — systemic auth-gate migration to isRealUser().
 *
 * resolveAuthV5 returns authenticated:true for the anonymous IP-fallback tier
 * (user_id === null), so every `if (!authCtx.authenticated)` gate passed all
 * anonymous traffic. All login-required gates now use isRealUser(authCtx):
 * a real principal is a JWT user, a valid API key, or the admin key — never
 * the anonymous IP fallback.
 *
 * Drives the real exported worker.fetch() so the actual route/gate wiring is
 * tested, across one representative route per migrated surface class.
 */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';
import { isRealUser } from '../src/auth/middleware.js';

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
const anon  = (path, init) => worker.fetch(new Request(`https://cyberdudebivash.in${path}`, init), env(), ctxStub());
const admin = (path, init = {}) => worker.fetch(
  new Request(`https://cyberdudebivash.in${path}`, { ...init, headers: { ...(init.headers || {}), 'x-api-key': 'test-admin-key-123' } }),
  env({ ADMIN_KEY: 'test-admin-key-123' }), ctxStub(),
);

describe('isRealUser() — unit contract', () => {
  it('rejects the anonymous IP-fallback context', () => {
    expect(isRealUser({ authenticated: true, method: 'ip_fallback', user_id: null, tier: 'FREE' })).toBe(false);
  });
  it('rejects invalid-key and empty contexts', () => {
    expect(isRealUser({ authenticated: false, method: 'api_key', error: 'invalid_key' })).toBe(false);
    expect(isRealUser(null)).toBe(false);
    expect(isRealUser({})).toBe(false);
  });
  it('accepts JWT, API-key, and admin principals', () => {
    expect(isRealUser({ authenticated: true, method: 'jwt', user_id: 'u_1' })).toBe(true);
    expect(isRealUser({ authenticated: true, method: 'api_key', user_id: 'u_2' })).toBe(true);
    expect(isRealUser({ authenticated: true, method: 'admin_key', user_id: 'admin', isAdmin: true })).toBe(true);
  });
});

describe('migrated route gates — anonymous callers get 401', () => {
  const cases = [
    ['GET',  '/api/keys'],                    // API key management
    ['POST', '/api/scan/async/domain'],       // async scan queue (sync scan stays anonymous)
    ['GET',  '/api/user/reports'],            // user-scoped deliverables
    ['POST', '/api/export/siem'],             // SIEM export (GET is documented-public format info)
    ['GET',  '/api/billing/usage'],           // billing (monetizationV2)
    ['GET',  '/api/soc/cases'],               // SOC case management
    ['POST', '/api/vulns'],                   // vuln CRUD write
    ['GET',  '/api/audit-log'],               // audit trail
    ['GET',  '/api/orgs'],                    // org management
    ['GET',  '/api/monitors'],                // monitoring CRUD
    ['GET',  '/api/ciso/incidents'],          // CISO incidents
    ['GET',  '/api/hunt/sessions'],           // threat hunting sessions
    ['GET',  '/api/zero-trust/anomalies'],    // zero trust
  ];
  for (const [method, path] of cases) {
    it(`anonymous ${method} ${path} → 401`, async () => {
      const res = await anon(path, { method, headers: { 'Content-Type': 'application/json' }, body: method === 'POST' ? '{}' : undefined });
      expect(res.status).toBe(401);
    });
  }

  it('anonymous GET /api/revenue/dashboard is blocked (owner gate, 403)', async () => {
    const res = await anon('/api/revenue/dashboard');
    expect([401, 403]).toContain(res.status);
  });

  it('the anonymous scan funnel is NOT gated (free-tier product entry point)', async () => {
    const res = await anon('/api/scan/domain', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: 'example.com' }),
    });
    // Must never be 401 — anonymous scanning is the deliberate FREE funnel.
    expect(res.status).not.toBe(401);
  });
});

describe('migrated route gates — real principals pass', () => {
  it('admin key passes /api/keys (no 401)', async () => {
    const res = await admin('/api/keys');
    expect(res.status).not.toBe(401);
  });
  it('admin key passes /api/soc/cases (no 401)', async () => {
    const res = await admin('/api/soc/cases');
    expect(res.status).not.toBe(401);
  });
  it('admin key passes /api/billing/usage (no 401)', async () => {
    const res = await admin('/api/billing/usage');
    expect(res.status).not.toBe(401);
  });
});

describe('/api/auth/status — reports REAL login state', () => {
  it('anonymous caller: authenticated:false (was true — key-validation UIs accepted garbage keys)', async () => {
    const res = await anon('/api/auth/status');
    const body = await res.json();
    expect(body.authenticated).toBe(false);
  });
  it('garbage non-cdb key: authenticated:false', async () => {
    const res = await anon('/api/auth/status', { headers: { 'x-api-key': 'not-a-real-key' } });
    const body = await res.json();
    expect(body.authenticated).toBe(false);
  });
  it('admin key: authenticated:true with tier', async () => {
    const res = await admin('/api/auth/status');
    const body = await res.json();
    expect(body.authenticated).toBe(true);
    expect(body.tier).toBe('ENTERPRISE');
  });
});

describe('dead-admin gates — fixed to isAdmin (were: role check that never passed)', () => {
  it('/api/mcp/revenue/performance: admin no longer 403, anonymous still blocked', async () => {
    const adminRes = await admin('/api/mcp/revenue/performance');
    expect(adminRes.status).not.toBe(403);
    const anonRes = await anon('/api/mcp/revenue/performance');
    expect([401, 403]).toContain(anonRes.status);
  });
});
