/* Phase X GA gap lock: credential recovery.
 *
 * Found by the GA Board (Phase X): the platform had NO password recovery —
 * every standard reset path 404'd in production and the login UI offered no
 * affordance. A customer who forgot their password permanently lost their
 * account, organization, and subscription, and single-operator support had
 * no reset tool. GA-blocking for customer operations.
 *
 * Locks the new flow: POST /api/auth/forgot-password (enumeration-safe,
 * rate-limited, KV-stored single-use token hashed with SHA-256, 30-min TTL)
 * and POST /api/auth/reset-password (strength-validated, single-use,
 * revokes all prior sessions).
 *
 * Runs the real handlers against a real SQL engine (node:sqlite) + a KV mock.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

vi.mock('../src/services/emailEngine.js', () => ({
  sendEmail: vi.fn(async () => ({ success: true, provider: 'mock' })),
}));

import { handleForgotPassword, handleResetPassword } from '../src/handlers/auth.js';
import { hashPassword, verifyPassword } from '../src/auth/password.js';
import { sendEmail } from '../src/services/emailEngine.js';

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

function makeKV() {
  const store = new Map();
  return {
    _store: store,
    async get(k, opts) {
      const v = store.get(k);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(k, v) { store.set(k, String(v)); },
    async delete(k) { store.delete(k); },
  };
}

const post = (path, body) => new Request(`https://x${path}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

describe('Phase X: credential recovery (was a total GA gap — all paths 404)', () => {
  let env, db;
  beforeEach(async () => {
    env = { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() };
    db = env.DB._sqlite;
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, password_salt TEXT, status TEXT DEFAULT 'active')`);
    db.exec(`CREATE TABLE refresh_tokens (user_id TEXT, token_hash TEXT, revoked INTEGER DEFAULT 0)`);
    const { hash, salt } = await hashPassword('OldPassw0rd!x');
    db.prepare(`INSERT INTO users (id, email, password_hash, password_salt) VALUES ('u1','alice@acme.com',?,?)`).run(hash, salt);
    db.prepare(`INSERT INTO refresh_tokens (user_id, token_hash) VALUES ('u1','oldsession')`).run();
    vi.mocked(sendEmail).mockClear();
  });

  async function requestTokenFor(email) {
    const res = await handleForgotPassword(post('/api/auth/forgot-password', { email }), env);
    const kvKeys = [...env.SECURITY_HUB_KV._store.keys()].filter(k => k.startsWith('pwreset:') && !k.startsWith('pwreset-rl:'));
    // Recover the plaintext token from the mocked email body (as a customer would from their inbox)
    const call = vi.mocked(sendEmail).mock.calls.at(-1);
    const token = call ? call[1].text.match(/reset_token=([a-f0-9]{64})/)?.[1] : null;
    return { res, kvKeys, token };
  }

  it('existing account: 200 generic, single-use token stored hashed, email sent with link', async () => {
    const { res, kvKeys, token } = await requestTokenFor('alice@acme.com');
    expect(res.status).toBe(200);
    expect(kvKeys.length).toBe(1);
    expect(token).toMatch(/^[a-f0-9]{64}$/);
    expect(kvKeys[0]).not.toContain(token); // stored by hash, not plaintext
  });

  it('unknown account: byte-identical generic response, no token, no email (no enumeration oracle)', async () => {
    const known   = await handleForgotPassword(post('/api/auth/forgot-password', { email: 'alice@acme.com' }), env);
    const unknown = await handleForgotPassword(post('/api/auth/forgot-password', { email: 'ghost@acme.com' }), env);
    expect(unknown.status).toBe(200);
    expect(await unknown.text()).toBe(await known.clone().text());
    expect(vi.mocked(sendEmail).mock.calls.every(c => c[1].to === 'alice@acme.com')).toBe(true);
  });

  it('reset with a valid token: password changes, old sessions revoked', async () => {
    const { token } = await requestTokenFor('alice@acme.com');
    const res = await handleResetPassword(post('/api/auth/reset-password', { token, new_password: 'NewPassw0rd!y' }), env);
    expect(res.status).toBe(200);
    const u = db.prepare(`SELECT password_hash, password_salt FROM users WHERE id='u1'`).get();
    expect(await verifyPassword('NewPassw0rd!y', u.password_hash, u.password_salt)).toBe(true);
    expect(await verifyPassword('OldPassw0rd!x', u.password_hash, u.password_salt)).toBe(false);
    expect(db.prepare(`SELECT revoked FROM refresh_tokens WHERE user_id='u1'`).get().revoked).toBe(1);
  });

  it('a token is single-use: second attempt fails 400', async () => {
    const { token } = await requestTokenFor('alice@acme.com');
    await handleResetPassword(post('/api/auth/reset-password', { token, new_password: 'NewPassw0rd!y' }), env);
    const again = await handleResetPassword(post('/api/auth/reset-password', { token, new_password: 'Another0ne!z' }), env);
    expect(again.status).toBe(400);
  });

  it('garbage token → 400; weak password → 400 (password unchanged)', async () => {
    const bad = await handleResetPassword(post('/api/auth/reset-password', { token: 'f'.repeat(64), new_password: 'NewPassw0rd!y' }), env);
    expect(bad.status).toBe(400);
    const { token } = await requestTokenFor('alice@acme.com');
    const weak = await handleResetPassword(post('/api/auth/reset-password', { token, new_password: 'short' }), env);
    expect(weak.status).toBe(400);
    const u = db.prepare(`SELECT password_hash, password_salt FROM users WHERE id='u1'`).get();
    expect(await verifyPassword('OldPassw0rd!x', u.password_hash, u.password_salt)).toBe(true);
  });

  it('per-email rate limit: 4th request mints no new token but stays generic 200', async () => {
    for (let i = 0; i < 3; i++) await requestTokenFor('alice@acme.com');
    const before = [...env.SECURITY_HUB_KV._store.keys()].filter(k => k.startsWith('pwreset:')).length;
    const { res } = await requestTokenFor('alice@acme.com');
    const after = [...env.SECURITY_HUB_KV._store.keys()].filter(k => k.startsWith('pwreset:')).length;
    expect(res.status).toBe(200);
    expect(after).toBe(before);
  });
});
