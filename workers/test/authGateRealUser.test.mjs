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
    ['POST', '/api/agents/run'],              // MASOC — parallel 9-agent orchestration
    ['POST', '/api/agents/stream'],           // MASOC — SSE streaming variant
    ['POST', '/api/agents/dispatch/cve_intel'], // MASOC — single-agent dispatch
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
    // Anonymous callers must be able to obtain a scan token AND complete a scan
    // without ever authenticating — the P1 scan-token gate (runSyncPipeline)
    // must share one env/KV across both calls, exactly like production.
    const sharedEnv = env();
    const tokRes = await worker.fetch(new Request('https://cyberdudebivash.in/api/scan/token', { method: 'POST' }), sharedEnv, ctxStub());
    expect(tokRes.status).toBe(200);
    const { token } = await tokRes.json();
    expect(token).toBeTruthy();

    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/scan/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Scan-Token': token },
      body: JSON.stringify({ domain: 'example.com' }),
    }), sharedEnv, ctxStub());
    // Must never be 401 (auth) or the scan-token 403 — anonymous scanning,
    // now token-gated against abuse, is still the deliberate FREE funnel once
    // a fresh token is presented.
    expect(res.status).not.toBe(401);
    if (res.status === 403) expect((await res.json()).error).not.toBe('scan_token_invalid');
  });

  it('anonymous scan WITHOUT a token is rejected with a clear, actionable error (P1 abuse gate)', async () => {
    const res = await anon('/api/scan/domain', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: 'example.com' }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('scan_token_invalid');
    expect(body.reason).toBe('missing_scan_token');
    expect(body.hint).toMatch(/scan\/token/);
  });

  it('api_key callers are exempt from the scan-token gate (already identified + quota-gated)', async () => {
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/scan/domain', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'test-admin-key-123' }, body: JSON.stringify({ domain: 'example.com' }),
    }), env({ ADMIN_KEY: 'test-admin-key-123' }), ctxStub());
    if (res.status === 403) expect((await res.json()).error).not.toBe('scan_token_invalid');
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
  it('admin key passes /api/agents/run (no 401)', async () => {
    const res = await admin('/api/agents/run', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'assess CVE-2024-3400 risk' }),
    });
    expect(res.status).not.toBe(401);
  });
  it('admin key passes /api/agents/dispatch/cve_intel (no 401)', async () => {
    const res = await admin('/api/agents/dispatch/cve_intel', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'assess CVE-2024-3400 risk' }),
    });
    expect(res.status).not.toBe(401);
  });
});

describe('MASOC (/api/agents/*) — auth-gate fix (P0 finding CAP-MASOC-001)', () => {
  // run/stream/dispatch trigger real parallel AI-agent orchestration and are
  // covered by the shared "anonymous callers get 401" / "real principals pass"
  // blocks above. status is deliberately excluded from those blocks — it must
  // stay open, as asserted here.
  it('anonymous GET /api/agents/status is NOT gated (public read-only widget)', async () => {
    const res = await anon('/api/agents/status');
    expect(res.status).not.toBe(401);
    const body = await res.json();
    expect(body.success).toBe(true);
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
