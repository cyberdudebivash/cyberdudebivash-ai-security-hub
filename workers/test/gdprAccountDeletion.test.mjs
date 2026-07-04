/* GDPR account deletion / right-to-erasure (Journey 9).
 *
 * DEFECT: DELETE /api/auth/delete-account anonymized the users row and removed
 * API keys + tokens, but LEFT the user's personal data keyed by user_id —
 * scan history (targets/findings), async job records, generated reports, and
 * (most sensitively) their MFA/TOTP secret. Incomplete erasure for a Fortune
 * 500 / GDPR posture. Fix purges those tables, scoped to the deleting user,
 * while retaining payment/GST records (statutory tax retention).
 *
 * Verified against a real SQL engine (node:sqlite).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleDeleteAccount } from '../src/handlers/auth.js';

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

describe('GDPR account deletion erases the user\'s personal data', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, password_hash TEXT, password_salt TEXT, full_name TEXT, company TEXT, telegram_chat_id TEXT, alert_email TEXT, status TEXT, updated_at TEXT)`);
    db.exec(`CREATE TABLE api_keys (id TEXT, user_id TEXT, active INTEGER)`);
    db.exec(`CREATE TABLE scan_history (id TEXT, user_id TEXT, target TEXT)`);
    db.exec(`CREATE TABLE scan_jobs (id TEXT, user_id TEXT)`);
    db.exec(`CREATE TABLE report_jobs (id TEXT, user_id TEXT)`);
    db.exec(`CREATE TABLE mfa_secrets (user_id TEXT PRIMARY KEY, secret TEXT, enabled INTEGER)`);
    db.exec(`CREATE TABLE payments (id TEXT, email TEXT, amount INTEGER)`);
    // Alice (to be deleted) with data across every table + a bob who must survive.
    for (const uid of ['alice', 'bob']) {
      db.prepare(`INSERT INTO users (id,email,password_hash,password_salt,full_name,status) VALUES (?,?,?,?,?,'active')`).run(uid, uid+'@x.com', 'h', 's', uid.toUpperCase());
      db.prepare(`INSERT INTO api_keys (id,user_id,active) VALUES (?,?,1)`).run('k_'+uid, uid);
      db.prepare(`INSERT INTO scan_history (id,user_id,target) VALUES (?,?,?)`).run('sh_'+uid, uid, 'secret-target.com');
      db.prepare(`INSERT INTO scan_jobs (id,user_id) VALUES (?,?)`).run('sj_'+uid, uid);
      db.prepare(`INSERT INTO report_jobs (id,user_id) VALUES (?,?)`).run('rj_'+uid, uid);
      db.prepare(`INSERT INTO mfa_secrets (user_id,secret,enabled) VALUES (?,?,1)`).run(uid, 'TOTPSEED');
      db.prepare(`INSERT INTO payments (id,email,amount) VALUES (?,?,149900)`).run('pay_'+uid, uid+'@x.com');
    }
  });

  const del = async (uid) => handleDeleteAccount(new Request('https://x/api/auth/delete-account', { method: 'DELETE' }), env, { user_id: uid });
  const count = (t, uid) => db.prepare(`SELECT COUNT(*) c FROM ${t} WHERE user_id=?`).get(uid).c;

  it('purges all personal-data tables for the deleted user', async () => {
    const res = await del('alice');
    expect(res.status).toBe(200);
    for (const t of ['api_keys', 'scan_history', 'scan_jobs', 'report_jobs', 'mfa_secrets']) {
      expect(count(t, 'alice')).toBe(0);
    }
  });

  it('anonymizes the users row (email/name cleared, suspended)', async () => {
    await del('alice');
    const u = db.prepare(`SELECT * FROM users WHERE id='alice'`).get();
    expect(u.email).not.toBe('alice@x.com');
    expect(u.full_name).toBeNull();
    expect(u.status).toBe('suspended');
    expect(u.password_hash).toBe('DELETED');
  });

  it('retains payment/GST records (statutory retention)', async () => {
    await del('alice');
    expect(db.prepare(`SELECT COUNT(*) c FROM payments WHERE email='alice@x.com'`).get().c).toBe(1);
  });

  it('does NOT touch another user\'s data', async () => {
    await del('alice');
    for (const t of ['api_keys', 'scan_history', 'scan_jobs', 'report_jobs', 'mfa_secrets']) {
      expect(count(t, 'bob')).toBe(1);
    }
    expect(db.prepare(`SELECT status FROM users WHERE id='bob'`).get().status).toBe('active');
  });
});
