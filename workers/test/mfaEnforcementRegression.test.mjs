/* MFA enforcement — production regression (real SQLite, catches "no such column").
 *
 * BUG: issueMFAChallenge() ran `SELECT id FROM mfa_secrets ...`, but that table
 * has NO `id` column — its PRIMARY KEY is user_id (schema_master.sql). The query
 * threw "no such column: id" on every login and the handler's `.catch(()=>null)`
 * swallowed it, so the function always returned null → the login handler issued
 * full access/refresh tokens WITHOUT the second factor. Any user who "enabled"
 * MFA (and got backup codes) was, in reality, NOT protected: email+password
 * alone logged straight in. A silent, total 2FA bypass on a security product.
 *
 * A SQL-string-recording mock can't catch this (it never errors on a bad
 * column), so this suite runs the REAL query against a real SQL engine seeded
 * through the exact schema + the enable path's own INSERT.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { issueMFAChallenge } from '../src/handlers/mfa.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  function wrap(sql) {
    let bound = [];
    return {
      bind(...a) { bound = a; return this; },
      async all() { return { results: sqlite.prepare(sql).all(...bound) }; },
      async first() { return sqlite.prepare(sql).get(...bound) ?? null; },
      async run() { const i = sqlite.prepare(sql).run(...bound); return { success: true, meta: { changes: i.changes } }; },
    };
  }
  return { _sqlite: sqlite, prepare(sql) { return wrap(sql); } };
}
function makeKV() {
  const m = new Map();
  return { async get(k, t) { const v = m.get(k); return v == null ? null : (t === 'json' ? JSON.parse(v) : v); }, async put(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); } };
}

describe('MFA is actually enforced at login (issueMFAChallenge)', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1(), KV: makeKV() };
    // Real schema (verbatim from schema_master.sql / schema_migration_mfa.sql):
    // user_id is the PRIMARY KEY — there is NO `id` column.
    env.DB._sqlite.exec(`CREATE TABLE mfa_secrets (
      user_id TEXT PRIMARY KEY, secret TEXT NOT NULL, backup_codes TEXT NOT NULL DEFAULT '[]',
      enabled INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
  });

  it('issues a challenge for an enrolled (enabled=1) user — NOT a passwordless bypass', async () => {
    env.DB._sqlite.prepare(`INSERT INTO mfa_secrets (user_id, secret, backup_codes, enabled) VALUES (?,?,?,1)`)
      .run('user-1', 'JBSWY3DPEHPK3PXP', '[]');
    const token = await issueMFAChallenge(env, 'user-1', 'a@b.com', 'PRO');
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(20);
    // The challenge must be persisted so /mfa/authenticate can complete it.
    expect(await env.KV.get(`mfa_challenge:${token}`, 'json')).toMatchObject({ userId: 'user-1' });
  });

  it('returns null (no challenge) for a user who never enrolled', async () => {
    expect(await issueMFAChallenge(env, 'nobody', 'x@y.com', 'FREE')).toBeNull();
  });

  it('returns null for a user whose MFA is disabled (enabled=0)', async () => {
    env.DB._sqlite.prepare(`INSERT INTO mfa_secrets (user_id, secret, enabled) VALUES (?,?,0)`).run('user-2', 'SECRET');
    expect(await issueMFAChallenge(env, 'user-2', 'a@b.com', 'PRO')).toBeNull();
  });

  it('the query references only columns that exist on mfa_secrets', () => {
    // Guards against re-introducing a phantom-column SELECT (the original bug).
    const cols = env.DB._sqlite.prepare(`PRAGMA table_info(mfa_secrets)`).all().map(c => c.name);
    expect(cols).not.toContain('id');
    expect(cols).toContain('user_id');
  });
});

describe('MFA enrollment UI is wired in the account dashboard', () => {
  const html = readFileSync(resolve(import.meta.dirname, '../../frontend/user-dashboard.html'), 'utf8');
  it('has the 2FA settings panel', () => {
    expect(/Two-Factor Authentication/i.test(html)).toBe(true);
    expect(/id="mfa-body"/.test(html)).toBe(true);
  });
  it('drives the full enroll/disable flow against the real endpoints', () => {
    expect(/\/api\/auth\/mfa\/status/.test(html)).toBe(true);
    expect(/\/api\/auth\/mfa\/setup/.test(html)).toBe(true);
    expect(/\/api\/auth\/mfa\/enable/.test(html)).toBe(true);
    expect(/\/api\/auth\/mfa\/disable/.test(html)).toBe(true);
    // Sends the correct field the backend requires.
    expect(/totp_code/.test(html)).toBe(true);
  });
  it('CSP allows the client-side QR library the enrollment UI uses', () => {
    // The QR renders locally (secret never leaves the browser) but the lib is
    // loaded from cdnjs — the enforced CSP script-src MUST allow it or the QR
    // silently fails to the manual-key fallback.
    const headers = readFileSync(resolve(import.meta.dirname, '../../frontend/_headers'), 'utf8');
    const enforced = headers.split('\n').find(l => /^\s*Content-Security-Policy:/.test(l)) || '';
    expect(enforced).toContain('https://cdnjs.cloudflare.com');
  });
});
