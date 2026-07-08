/* Capability Registry Administration-domain pass (2026-07-08) found that
 * PUT /api/ops/flags (handleSetFeatureFlag, opsEngine.js) gated on
 * `['ADMIN','OWNER'].includes((authCtx.tier || '').toUpperCase())`. Nothing
 * in this codebase ever sets authCtx.tier to the literal string 'ADMIN' or
 * 'OWNER' — tier always holds a subscription tier (FREE/STARTER/PRO/
 * ENTERPRISE/MSSP), including for the ADMIN_KEY bypass (resolveAuthV5 sets
 * tier: 'ENTERPRISE' there). The real "is staff" signal used everywhere else
 * in this same file (assertAdmin(), used by handleAdminCustomers and its
 * siblings) is authCtx.isAdmin. handleSetFeatureFlag alone reinvented a
 * broken subset of that check and dropped the isAdmin half, so the write
 * path was unreachable for every caller, including real admins. Now calls
 * the file's own assertAdmin() helper, matching every sibling handler.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleOpsRoute } from '../src/handlers/opsEngine.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE IF NOT EXISTS ops_feature_flags (
    id TEXT PRIMARY KEY, user_id TEXT, flag_name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1, tier_required TEXT DEFAULT 'FREE',
    note TEXT, expires_at TEXT, created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, flag_name)
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { return Promise.all(stmts.map(s => s.run())); },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
    async list({ prefix }) { return { keys: [...store.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) }; },
  };
}

const putReq = (body) => new Request('https://x/api/ops/flags', {
  method: 'PUT', body: JSON.stringify(body), headers: { 'content-type': 'application/json' },
});

describe('PUT /api/ops/flags (handleSetFeatureFlag) — admin gate', () => {
  it('rejects a real paying customer whose tier is a subscription plan, not staff', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await handleOpsRoute(putReq({ flag_name: 'x', enabled: true }), env, { isAdmin: false, tier: 'ENTERPRISE', userId: 'u1' }, '/api/ops/flags', 'PUT');
    expect(res.status).toBe(403);
  });

  it('rejects the ADMIN_KEY bypass caller too, since it authenticates with tier: ENTERPRISE, not isAdmin', async () => {
    // Documents current behavior: the raw ADMIN_KEY bypass (resolveAuthV5) sets
    // { tier: 'ENTERPRISE' } with no isAdmin flag, so it does NOT satisfy
    // assertAdmin() either. Real admin access to this route requires a staff
    // account with isAdmin: true (user_roles), consistent with every sibling
    // handleAdmin* in this file.
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await handleOpsRoute(putReq({ flag_name: 'x', enabled: true }), env, { authenticated: true, method: 'admin_key', tier: 'ENTERPRISE' }, '/api/ops/flags', 'PUT');
    expect(res.status).toBe(403);
  });

  it('allows a real staff admin (isAdmin: true) to set a flag — previously impossible for anyone', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await handleOpsRoute(
      putReq({ user_id: 'u1', flag_name: 'beta_feature', enabled: true, tier_required: 'PRO' }),
      env, { isAdmin: true, tier: 'ENTERPRISE', userId: 'admin_1' }, '/api/ops/flags', 'PUT'
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true, flag_name: 'beta_feature', enabled: true });

    const row = env.DB._sqlite.prepare(`SELECT * FROM ops_feature_flags WHERE flag_name = ?`).get('beta_feature');
    expect(row.user_id).toBe('u1');
    expect(row.enabled).toBe(1);
    expect(row.tier_required).toBe('PRO');
  });

  it('still requires flag_name for an authorized admin caller', async () => {
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    const res = await handleOpsRoute(putReq({ enabled: true }), env, { isAdmin: true, tier: 'ENTERPRISE', userId: 'admin_1' }, '/api/ops/flags', 'PUT');
    expect(res.status).toBe(400);
  });
});
