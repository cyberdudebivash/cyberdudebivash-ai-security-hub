/**
 * Security regression — RevOS (/api/revos/*) access control.
 *
 * RevOS is an internal, single-tenant Revenue Operating System surface: platform
 * MRR/ARR/churn, the full CRM deal pipeline, every customer proposal, platform-wide
 * API analytics, and executive CISO reports (which embed platform financials). It is
 * the owner's private business intelligence — the analogue of the already-guarded
 * /api/proposals and /api/keys/:id/usage surfaces.
 *
 * Regression: these endpoints were open to anonymous callers or any authenticated
 * user (a weak role==='admin' check the real owner login never satisfied), leaking
 * financials and cross-customer PII, plus an attacker-controlled ?key_id BOLA on
 * api-usage. requireOwner() + the key ownership guard close these.
 *
 * These tests exercise the real handleRevOS dispatcher with a mocked env/DB, so the
 * guard logic runs exactly as in production.
 */
import { describe, it, expect } from 'vitest';
import { handleRevOS } from '../src/handlers/revosHandler.js';

// ── Auth-context fixtures mirroring resolveAuthV5 output ──────────────────────
const OWNER_CTX    = { authenticated: true, isAdmin: true, userId: 'admin', email: 'bivash@cyberdudebivash.com', tier: 'ENTERPRISE', keyId: 'k-owner' };
const CUSTOMER_CTX = { authenticated: true, isAdmin: false, userId: 'u-123', email: 'attacker@evil.com', tier: 'PRO', keyId: 'k-victimA' };
const ANON_CTX     = { authenticated: true, isAdmin: false, userId: null, email: null, tier: 'FREE', keyId: null };

function makeDB() {
  const api = {
    bind: () => api,
    all:  async () => ({ results: [] }),
    first: async () => ({}),
    run:  async () => ({}),
  };
  return { prepare: () => api };
}

function makeEnv() {
  return { DB: makeDB(), SECURITY_HUB_KV: { get: async () => null, put: async () => {} } };
}

function req(path, method = 'GET') {
  return new Request(`https://api.cyberdudebivash.test${path}`, { method });
}

// Owner-only endpoints (reads of the owner's private business intelligence).
const OWNER_ONLY = [
  ['/api/revos/dashboard',            'GET'],
  ['/api/revos/mrr',                  'GET'],
  ['/api/revos/crm/pipeline',         'GET'],
  ['/api/revos/crm/proposals',        'GET'],
  ['/api/revos/crm/forecast',         'GET'],
  ['/api/revos/product-pipeline',     'GET'],
  ['/api/revos/cs/dashboard',         'GET'],
  ['/api/revos/api-analytics',        'GET'],
  ['/api/revos/audit-log',            'GET'],
  ['/api/revos/ciso-report/list',     'GET'],
  ['/api/revos/ciso-report/RPT-ABC',  'GET'],
  ['/api/revos/ciso-report',          'POST'],
  ['/api/revos/crm/deal',             'POST'],
  ['/api/revos/crm/propose',          'POST'],
];

describe('RevOS access control — owner-only business intelligence', () => {
  for (const [path, method] of OWNER_ONLY) {
    it(`${method} ${path} → 403 for anonymous`, async () => {
      const res = await handleRevOS(req(path, method), makeEnv(), ANON_CTX, path, method);
      expect(res.status).toBe(403);
    });

    it(`${method} ${path} → 403 for an authenticated non-owner customer`, async () => {
      const res = await handleRevOS(req(path, method), makeEnv(), CUSTOMER_CTX, path, method);
      expect(res.status).toBe(403);
    });

    it(`${method} ${path} → not 403 for the owner`, async () => {
      const res = await handleRevOS(req(path, method), makeEnv(), OWNER_CTX, path, method);
      expect(res.status).not.toBe(403);
    });
  }

  it('anonymous 403 body never leaks MRR/financial fields', async () => {
    const res  = await handleRevOS(req('/api/revos/mrr'), makeEnv(), ANON_CTX, '/api/revos/mrr', 'GET');
    const body = JSON.stringify(await res.json());
    expect(body).not.toMatch(/mrr_inr|arr_inr|breakdown/);
  });
});

// ── api-usage BOLA — a caller may only read usage for a key it owns ───────────
describe('RevOS api-usage — key ownership (BOLA) guard', () => {
  const P = '/api/revos/api-usage';

  it('a customer cannot read another key via ?key_id=…', async () => {
    const res = await handleRevOS(req(`${P}?key_id=k-victimB`), makeEnv(), CUSTOMER_CTX, P, 'GET');
    expect(res.status).toBe(403);
  });

  it('a customer CAN read their own key (no cross-tenant read)', async () => {
    const res = await handleRevOS(req(`${P}?key_id=k-victimA`), makeEnv(), CUSTOMER_CTX, P, 'GET');
    expect(res.status).toBe(200);
  });

  it('the owner may inspect any key', async () => {
    const res = await handleRevOS(req(`${P}?key_id=k-anyone`), makeEnv(), OWNER_CTX, P, 'GET');
    expect(res.status).toBe(200);
  });

  it('anonymous is rejected (401 — not a real principal)', async () => {
    const res = await handleRevOS(req(P), makeEnv(), ANON_CTX, P, 'GET');
    expect(res.status).toBe(401);
  });
});
