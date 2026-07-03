/* Release blocker RB-2: BOLA/IDOR on GET /api/keys/:id/usage (CWE-639).
 *
 * handleKeyUsage → getKeyUsageSummary queries api_key_usage WHERE key_id = ?
 * ALONE (the userId argument was ignored), so any authenticated tenant could
 * read another tenant's API request volume + per-module breakdown by
 * enumerating key ids — cross-tenant competitor intelligence. The handler now
 * verifies the key belongs to the caller (matching rotate/revoke) and returns
 * 404 otherwise, with no usage query performed.
 */
import { describe, it, expect } from 'vitest';
import { handleKeyUsage } from '../src/handlers/apikeys.js';

function dbWith(ownedKeys, usageByKey = {}) {
  return {
    prepare(sql) {
      let bound = [];
      return {
        bind(...a) { bound = a; return this; },
        async all() {
          if (/FROM api_keys/i.test(sql)) {
            // listUserApiKeys: return only keys owned by the bound user_id
            const uid = bound[0];
            const rows = ownedKeys.filter(k => k.user_id === uid);
            return { results: rows };
          }
          if (/FROM api_key_usage/i.test(sql)) {
            // usage query — should NOT be reached for a non-owned key
            const keyId = bound[0];
            return { results: usageByKey[keyId] || [] };
          }
          return { results: [] };
        },
        async first() {
          if (/FROM api_key_usage/i.test(sql)) {
            const keyId = bound[0];
            return { total: (usageByKey[keyId] || []).reduce((s, r) => s + r.total, 0) };
          }
          return null;
        },
      };
    },
  };
}

const req = new Request('https://x/api/keys/k/usage');

describe('GET /api/keys/:id/usage — tenant isolation', () => {
  const owned = [
    { id: 'key_A', user_id: 'userA', active: 1 },
    { id: 'key_B', user_id: 'userB', active: 1 },
  ];
  const usage = { key_B: [{ total: 4200, module: 'domain' }] }; // victim has real traffic

  it('A CANNOT read B\'s key usage — 404, no volume leaked', async () => {
    const db = dbWith(owned, usage);
    const res = await handleKeyUsage(req, { DB: db }, { user_id: 'userA' }, 'key_B');
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(JSON.stringify(body)).not.toContain('4200'); // no usage volume disclosed
    expect(body.today).toBeUndefined();
  });

  it('A CAN read its own key usage', async () => {
    const db = dbWith(owned, { key_A: [{ total: 7, module: 'ai' }] });
    const res = await handleKeyUsage(req, { DB: db }, { user_id: 'userA' }, 'key_A');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.key_id).toBe('key_A');
    expect(body.today.total).toBe(7);
  });

  it('unauthenticated → 401', async () => {
    const res = await handleKeyUsage(req, { DB: dbWith(owned) }, {}, 'key_A');
    expect(res.status).toBe(401);
  });
});
