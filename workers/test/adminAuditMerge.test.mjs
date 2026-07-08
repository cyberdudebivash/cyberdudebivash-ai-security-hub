/* SaaS productization audit (2026-07-08), quick win #4: the admin "Audit Log"
 * tab (GET /api/admin/audit -> handleAdminAudit) only ever read the KV trail
 * written by writeOpsAudit(). Enterprise SSO logins/config changes
 * (handlers/enterpriseSsoHandler.js) and AI copilot sessions
 * (handlers/aiSecurityCopilot.js) write straight to the D1 audit_log table
 * instead and were completely invisible to an admin reviewing this tab.
 *
 * handleAdminAudit() now merges both trails. These tests cover: KV-only
 * (unchanged), D1-only (the previously-missing case), merged + sorted
 * together, date-window filtering, type filtering across both sources, and
 * that a missing DB/KV binding degrades gracefully rather than throwing.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAdminAudit } from '../src/handlers/opsEngine.js';

const ADMIN = { isAdmin: true, tier: 'ENTERPRISE' };

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL, resource TEXT,
    resource_id TEXT, status TEXT DEFAULT 'ok', metadata TEXT DEFAULT '{}',
    details TEXT DEFAULT '{}', created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeKV(entries = {}) {
  const store = new Map(Object.entries(entries));
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
    async list({ prefix }) { return { keys: [...store.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) }; },
  };
}

function kvEntry(overrides = {}) {
  return JSON.stringify({
    id: 'audit_kv1', type: 'auth.login', actor: 'user_1', actor_tier: 'PRO',
    ip: '1.2.3.4', resource: 'session', action: 'login', outcome: 'success',
    details: {}, org_id: null, timestamp: '2026-07-08T09:00:00.000Z',
    ...overrides,
  });
}

const req = (qs = '') => new Request(`https://x/api/admin/audit${qs}`);

describe('handleAdminAudit — merges KV ops-audit trail with D1 audit_log', () => {
  it('rejects a non-admin caller', async () => {
    const res = await handleAdminAudit(req(), { DB: makeRealD1(), SECURITY_HUB_KV: makeKV() }, { isAdmin: false, tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('returns KV entries as before when D1 has nothing for that date', async () => {
    const kv = makeKV({ 'audit:2026-07-08:audit_kv1': kvEntry() });
    const env = { DB: makeRealD1(), SECURITY_HUB_KV: kv };
    const res = await handleAdminAudit(req('?date=2026-07-08'), env, ADMIN);
    const body = await res.json();
    expect(body.total).toBe(1);
    expect(body.entries[0].source).toBe('kv');
    expect(body.entries[0].type).toBe('auth.login');
  });

  it('surfaces D1 audit_log rows that were previously invisible (SSO login, copilot session)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, resource, resource_id, status, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run('d1_sso', 'user_42', 'sso.login', 'session', null, 'ok', JSON.stringify({ idp: 'okta', org: 'acme' }), '2026-07-08 09:15:00');
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, resource, resource_id, status, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run('d1_copilot', 'user_7', 'copilot_chat', 'copilot_session', 'sess_123', 'ok', JSON.stringify({ tier: 'ENTERPRISE' }), '2026-07-08 09:20:00');

    const env = { DB: db, SECURITY_HUB_KV: makeKV() };
    const res = await handleAdminAudit(req('?date=2026-07-08'), env, ADMIN);
    const body = await res.json();
    expect(body.total).toBe(2);
    expect(body.entries.every(e => e.source === 'd1')).toBe(true);
    const ssoEntry = body.entries.find(e => e.type === 'sso.login');
    expect(ssoEntry.actor).toBe('user_42');
    expect(ssoEntry.details).toEqual({ idp: 'okta', org: 'acme' });
    const copilotEntry = body.entries.find(e => e.type === 'copilot_chat');
    expect(copilotEntry.actor).toBe('user_7');
  });

  it('merges and sorts both sources together, newest first', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, status, created_at) VALUES (?, ?, ?, ?, ?)`
    ).run('d1_1', 'user_9', 'sso.login', 'ok', '2026-07-08 09:30:00');
    const kv = makeKV({
      'audit:2026-07-08:audit_kv1': kvEntry({ id: 'audit_kv1', timestamp: '2026-07-08T09:00:00.000Z' }),
      'audit:2026-07-08:audit_kv2': kvEntry({ id: 'audit_kv2', timestamp: '2026-07-08T09:45:00.000Z' }),
    });
    const env = { DB: db, SECURITY_HUB_KV: kv };
    const res = await handleAdminAudit(req('?date=2026-07-08'), env, ADMIN);
    const body = await res.json();
    expect(body.total).toBe(3);
    // Newest first: kv2 (09:45) > d1_1 (09:30) > kv1 (09:00)
    expect(body.entries.map(e => e.id)).toEqual(['audit_kv2', 'd1_1', 'audit_kv1']);
  });

  it('excludes D1 rows outside the requested date window', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, status, created_at) VALUES (?, ?, ?, ?, ?)`
    ).run('d1_yesterday', 'user_1', 'sso.login', 'ok', '2026-07-07 23:59:00');
    const env = { DB: db, SECURITY_HUB_KV: makeKV() };
    const res = await handleAdminAudit(req('?date=2026-07-08'), env, ADMIN);
    const body = await res.json();
    expect(body.total).toBe(0);
  });

  it('applies the type filter across both sources', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, status, created_at) VALUES (?, ?, ?, ?, ?)`
    ).run('d1_sso', 'user_1', 'sso.login', 'ok', '2026-07-08 09:15:00');
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, status, created_at) VALUES (?, ?, ?, ?, ?)`
    ).run('d1_copilot', 'user_2', 'copilot_chat', 'ok', '2026-07-08 09:16:00');
    const kv = makeKV({ 'audit:2026-07-08:audit_kv1': kvEntry({ type: 'auth.login' }) });
    const env = { DB: db, SECURITY_HUB_KV: kv };
    const res = await handleAdminAudit(req('?date=2026-07-08&type=sso'), env, ADMIN);
    const body = await res.json();
    expect(body.total).toBe(1);
    expect(body.entries[0].type).toBe('sso.login');
  });

  it('degrades gracefully with no DB binding at all (KV-only, no throw)', async () => {
    const kv = makeKV({ 'audit:2026-07-08:audit_kv1': kvEntry() });
    const res = await handleAdminAudit(req('?date=2026-07-08'), { SECURITY_HUB_KV: kv }, ADMIN);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBe(1);
  });

  it('degrades gracefully with no KV binding at all (D1-only, no throw)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO audit_log (id, user_id, action, status, created_at) VALUES (?, ?, ?, ?, ?)`
    ).run('d1_only', 'user_1', 'sso.login', 'ok', '2026-07-08 09:15:00');
    const res = await handleAdminAudit(req('?date=2026-07-08'), { DB: db }, ADMIN);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBe(1);
    expect(body.entries[0].source).toBe('d1');
  });
});
