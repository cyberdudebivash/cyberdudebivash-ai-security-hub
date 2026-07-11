/* P1 — a revoked API key stayed permanently visible (and permanently counted)
 * in GET /api/keys, the endpoint the dashboard's "My API Keys" table and
 * stat-count badge render directly.
 *
 * ROOT CAUSE: listUserApiKeys() intentionally returns every key regardless of
 * `active` status — handleRotateKey and handleKeyUsage need that to make
 * their own active/ownership decisions (e.g. "key already revoked" vs "key
 * not found"). handleListKeys returned that same unfiltered list straight to
 * the client with no revoked-state UI at all: renderKeys() in
 * frontend/user-dashboard.html always renders a live "Revoke" button
 * regardless of the key's active flag, and the count badge is just
 * `keys.length`. handleCreateKey already filters to `active` keys for its own
 * per-tier limit check (`existing.filter(k => k.active)`), so the two
 * endpoints disagreed: after revoking your only key, GET /api/keys still
 * reported count:1 forever, while POST /api/keys' limit check correctly saw
 * zero active keys.
 *
 * Confirmed live via Playwright against production (real signup, real
 * DELETE /api/keys/:id — 200, "Key revoked", key correctly set active=0 in
 * D1 — followed by a real GET /api/keys): the revoked key was still present
 * in `keys` and `count` was still 1, even though the account had zero usable
 * keys left.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleListKeys, handleCreateKey, handleRevokeKey } from '../src/handlers/apikeys.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

const authCtx = { user_id: 'u1', tier: 'FREE' };
const listReq = () => new Request('https://x/api/keys');
const createReq = (body) => new Request('https://x/api/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const delReq = () => new Request('https://x/api/keys/x', { method: 'DELETE' });

describe('GET /api/keys only lists active keys (P1)', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE api_keys (id TEXT PRIMARY KEY, user_id TEXT, key_hash TEXT, key_prefix TEXT, label TEXT, tier TEXT, daily_limit INTEGER, monthly_limit INTEGER, active INTEGER DEFAULT 1, created_at INTEGER, last_used_at TEXT, expires_at TEXT)`);
  });

  it('a freshly created key is listed and counted', async () => {
    await handleCreateKey(createReq({ name: 'My Key' }), env, authCtx);
    const res = await handleListKeys(listReq(), env, authCtx);
    const body = await res.json();
    expect(body.count).toBe(1);
    expect(body.keys).toHaveLength(1);
  });

  it('revoking the only key drops it from the list AND the count — the actual bug', async () => {
    await handleCreateKey(createReq({ name: 'My Key' }), env, authCtx);
    const listed = await (await handleListKeys(listReq(), env, authCtx)).json();
    const keyId = listed.keys[0].id;

    const revokeRes = await handleRevokeKey(delReq(), env, authCtx, keyId);
    expect(revokeRes.status).toBe(200);
    // Confirm the DB row really is soft-revoked (active=0), not deleted —
    // matches revokeApiKey()'s UPDATE ... SET active = 0 semantics.
    expect(db.prepare(`SELECT active FROM api_keys WHERE id = ?`).get(keyId).active).toBe(0);

    const after = await (await handleListKeys(listReq(), env, authCtx)).json();
    expect(after.count).toBe(0);
    expect(after.keys).toHaveLength(0);
  });

  it('a revoked key does not count against the per-tier limit for a new create (handleCreateKey was already correct — this just confirms both endpoints now agree)', async () => {
    const first = await handleCreateKey(createReq({ name: 'First' }), env, authCtx);
    expect(first.status).toBe(201);
    const listed = await (await handleListKeys(listReq(), env, authCtx)).json();
    await handleRevokeKey(delReq(), env, authCtx, listed.keys[0].id);

    const second = await handleCreateKey(createReq({ name: 'Second' }), env, authCtx);
    expect(second.status).toBe(201); // FREE tier's limit is 1 active key — this only works because the first is truly gone from the active count

    const finalList = await (await handleListKeys(listReq(), env, authCtx)).json();
    expect(finalList.count).toBe(1);
    expect(finalList.keys[0].label).toBe('Second');
  });
});
