/* Regression test — CAP-DASH-001 / CAP-DASH-002 (capability registry,
 * dashboard-personalization domain). GET /api/ciso/metrics and
 * GET /api/executive/dashboard were both gated to 'admin:business:read'
 * (SUPERADMIN-only per workers/src/auth/rbac.js PERMISSIONS), excluding every
 * paying customer these dashboards are built for — confirmed 2026-07-08 by
 * direct registry evidence (docs/capability-registry/domains/
 * dashboard-personalization.json). Fixed to the same tier-inclusive bar as
 * the sibling /api/executive/ prefix block (PRO/ENTERPRISE/MSSP tier OR
 * platform admin, via 'admin:analytics:read'). This locks that both routes
 * now admit a real paying-tier customer and still reject a FREE-tier one. */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

function kvStub() {
  return { get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) };
}

function envWithApiKeyRow(row) {
  return {
    DB: {
      prepare(sql) {
        const stmt = {
          bind() { return stmt; },
          async first() {
            if (/FROM api_keys k\s+JOIN users u/.test(sql)) return row;
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
    SECURITY_HUB_DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
          async run() { return { success: true }; },
        };
      },
      batch: async () => [],
    },
    SECURITY_HUB_KV: kvStub(),
  };
}

function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

const ROUTES = [
  ['/api/ciso/metrics', 'CAP-DASH-001'],
  ['/api/executive/dashboard', 'CAP-DASH-002'],
];

for (const [path, capId] of ROUTES) {
  describe(`GET ${path} (${capId}) — tier-inclusive, not SUPERADMIN-only`, () => {
    it('a real PRO-tier customer is admitted (not 403)', async () => {
      const env = envWithApiKeyRow({
        id: 'k1', user_id: 'u1', key_prefix: 'cdb_abc...', email: 'buyer@x.com',
        tier: 'PRO', user_tier: 'PRO', user_status: 'active', active: 1,
      });
      const req = new Request(`https://x${path}`, { headers: { 'x-api-key': 'cdb_proKeyTest' } });
      const res = await worker.fetch(req, env, ctxStub());
      expect(res.status).not.toBe(403);
    });

    it('a real ENTERPRISE-tier customer is admitted (not 403)', async () => {
      const env = envWithApiKeyRow({
        id: 'k2', user_id: 'u2', key_prefix: 'cdb_def...', email: 'ent@x.com',
        tier: 'ENTERPRISE', user_tier: 'ENTERPRISE', user_status: 'active', active: 1,
      });
      const req = new Request(`https://x${path}`, { headers: { 'x-api-key': 'cdb_entKeyTest' } });
      const res = await worker.fetch(req, env, ctxStub());
      expect(res.status).not.toBe(403);
    });

    it('a real FREE-tier customer is still rejected (403) — not a blanket open-up', async () => {
      const env = envWithApiKeyRow({
        id: 'k3', user_id: 'u3', key_prefix: 'cdb_ghi...', email: 'free@x.com',
        tier: 'FREE', user_tier: 'FREE', user_status: 'active', active: 1,
      });
      const req = new Request(`https://x${path}`, { headers: { 'x-api-key': 'cdb_freeKeyTest' } });
      const res = await worker.fetch(req, env, ctxStub());
      expect(res.status).toBe(403);
    });

    it('an anonymous caller is still rejected (403)', async () => {
      const env = envWithApiKeyRow(null);
      const req = new Request(`https://x${path}`);
      const res = await worker.fetch(req, env, ctxStub());
      expect(res.status).toBe(403);
    });

    it('the ADMIN_KEY bypass is still admitted (not 403)', async () => {
      const env = { ...envWithApiKeyRow(null), ADMIN_KEY: 'test-admin-key' };
      const req = new Request(`https://x${path}`, { headers: { 'x-api-key': 'test-admin-key' } });
      const res = await worker.fetch(req, env, ctxStub());
      expect(res.status).not.toBe(403);
    });
  });
}
