/* Regression test — /api/white-label/theme is the one customer-facing piece
 * of the "Partner/White-label" product (a customer's own org branding —
 * logo/colors/domain). Its own doc comment says GET is "any auth" and
 * PUT/DELETE are 'mssp_admin|admin' — but a blanket owner-only regex gate
 * in index.js (`/^\/api\/(...|white-label|...)/`) matched it too, so it
 * returned "This resource is restricted to the platform owner." to every
 * real customer, live in production, contradicting its own source comment.
 * (2026-07-06 revenue-mechanisms audit, P2-9.) */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

function kvStub() {
  return { get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) };
}

function envWithApiKeyRow(row) {
  return {
    DB: {
      prepare(sql) {
        let bound = [];
        const stmt = {
          bind(...a) { bound = a; return stmt; },
          async first() {
            if (/FROM api_keys k\s+JOIN users u/.test(sql)) return row;
            if (/FROM white_label_themes|FROM org_themes/.test(sql)) return null;
            return null;
          },
          async run() { return { success: true }; },
          async all() { return { results: [] }; },
        };
        return stmt;
      },
      batch: async () => [],
    },
    KV: kvStub(),
    SECURITY_HUB_DB: { prepare: () => ({ bind() { return this; }, first: async () => null, all: async () => ({ results: [] }), run: async () => ({ success: true }) }), batch: async () => [] },
    SECURITY_HUB_KV: kvStub(),
  };
}

function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

const OWNER_ONLY_MESSAGE = 'This resource is restricted to the platform owner.';

describe('GET /api/white-label/theme — reachable by a real customer, not owner-only', () => {
  it('a real PRO-tier API key is NOT rejected with the owner-only message', async () => {
    const env = envWithApiKeyRow({
      id: 'k1', user_id: 'u1', key_prefix: 'cdb_abc...', email: 'buyer@x.com',
      tier: 'PRO', user_tier: 'PRO', user_status: 'active', active: 1,
    });
    const req = new Request('https://x/api/white-label/theme', { headers: { 'x-api-key': 'cdb_customerKeyTest' } });
    const res = await worker.fetch(req, env, ctxStub());
    const body = await res.json().catch(() => ({}));
    expect(body.message).not.toBe(OWNER_ONLY_MESSAGE);
  });

  it('an anonymous caller is not blocked by the owner-only gate either (handler applies its own logic)', async () => {
    const env = envWithApiKeyRow(null);
    const req = new Request('https://x/api/white-label/theme');
    const res = await worker.fetch(req, env, ctxStub());
    const body = await res.json().catch(() => ({}));
    expect(body.message).not.toBe(OWNER_ONLY_MESSAGE);
  });
});

describe('PUT /api/white-label/theme — mssp_admin|admin, not owner-only', () => {
  it('a real MSSP-tier customer is NOT rejected with the owner-only message', async () => {
    const env = envWithApiKeyRow({
      id: 'k2', user_id: 'u2', key_prefix: 'cdb_def...', email: 'partner@x.com',
      tier: 'MSSP', user_tier: 'MSSP', user_status: 'active', active: 1,
    });
    const req = new Request('https://x/api/white-label/theme', {
      method: 'PUT', headers: { 'x-api-key': 'cdb_msspKeyTest', 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand_name: 'Acme MSSP' }),
    });
    const res = await worker.fetch(req, env, ctxStub());
    const body = await res.json().catch(() => ({}));
    expect(body.message).not.toBe(OWNER_ONLY_MESSAGE);
  });
});
