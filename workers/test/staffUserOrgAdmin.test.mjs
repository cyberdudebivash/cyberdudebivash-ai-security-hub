/* Regression test for CAP-ADMIN-004 (Users + Organizations slice) —
 * handlers/staffUserOrgAdmin.js. Locks in: RBAC gating matches the intended
 * trust tiers (admin:users:manage is Super-Admin only because it exposes
 * customer PII and can suspend an account; admin:orgs:read is the lower
 * Platform-Admin bar since it's view-only oversight), that suspending a user
 * both flips users.status AND revokes outstanding refresh tokens (otherwise
 * a suspension would only take effect once an existing session naturally
 * expired), and that an audit entry is actually written (not silently
 * swallowed the way workers/src/handlers/enterpriseSsoHandler.js's
 * audit_log INSERT is). */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  handleListUsers,
  handleGetUserAdmin,
  handleUpdateUserStatus,
  handleListOrgsAdmin,
  handleGetOrgAdmin,
} from '../src/handlers/staffUserOrgAdmin.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap, async batch(stmts) { return Promise.all(stmts.map(s => s.run())); } };
}

function makeFakeKV() {
  const store = new Map();
  return {
    _store: store,
    async put(k, v) { store.set(k, v); },
    async get(k) { return store.get(k) ?? null; },
    async delete(k) { store.delete(k); },
  };
}

const ANON        = { authenticated: false };
const FREE_USER    = { authenticated: true, userId: 'u1', tier: 'FREE' };
const STAFF_ADMIN  = { authenticated: true, userId: 'staff1', email: 'admin@cyberdudebivash.com', platformRoles: ['ADMIN'] };
const STAFF_SUPER  = { authenticated: true, userId: 'staff2', email: 'super@cyberdudebivash.com', platformRoles: ['SUPERADMIN'] };
const OWNER        = { authenticated: true, userId: 'owner1', isAdmin: true };

describe('staffUserOrgAdmin.js — Users oversight (admin:users:manage, Super Admin only)', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1(), KV: makeFakeKV() };
    env.DB._sqlite.exec(`CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT, full_name TEXT, company TEXT, tier TEXT,
      status TEXT DEFAULT 'active', email_verified INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')),
      last_login_at TEXT, login_count INTEGER DEFAULT 0
    )`);
    env.DB._sqlite.exec(`CREATE TABLE organizations (
      id TEXT PRIMARY KEY, name TEXT, slug TEXT, plan TEXT, owner_id TEXT,
      max_members INTEGER DEFAULT 5, max_daily_scans INTEGER DEFAULT 100,
      domain TEXT, industry TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
    )`);
    env.DB._sqlite.exec(`CREATE TABLE org_members (
      id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, role TEXT DEFAULT 'MEMBER',
      status TEXT DEFAULT 'active', joined_at TEXT DEFAULT (datetime('now'))
    )`);
    env.DB._sqlite.exec(`CREATE TABLE refresh_tokens (id TEXT PRIMARY KEY, user_id TEXT, revoked INTEGER DEFAULT 0)`);

    env.DB._sqlite.prepare(`INSERT INTO users (id, email, full_name, company, tier, status) VALUES (?,?,?,?,?,?)`)
      .run('cust1', 'alice@example.com', 'Alice Smith', 'Acme Co', 'PRO', 'active');
    env.DB._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES (?,?,?,?,?)`)
      .run('org1', 'Acme Corp', 'acme-corp', 'PRO', 'cust1');
    env.DB._sqlite.prepare(`INSERT INTO org_members (id, org_id, user_id, role) VALUES (?,?,?,?)`)
      .run('m1', 'org1', 'cust1', 'OWNER');
    env.DB._sqlite.prepare(`INSERT INTO refresh_tokens (id, user_id, revoked) VALUES (?,?,0)`).run('rt1', 'cust1');
  });

  it('anonymous caller is rejected (403)', async () => {
    const res = await handleListUsers(new Request('https://x/api/admin/users'), env, ANON);
    expect(res.status).toBe(403);
  });

  it('a FREE-tier authenticated user is rejected (403)', async () => {
    const res = await handleListUsers(new Request('https://x/api/admin/users'), env, FREE_USER);
    expect(res.status).toBe(403);
  });

  it('a plain ADMIN-tier staffer is rejected — users:manage is Super-Admin only', async () => {
    const res = await handleListUsers(new Request('https://x/api/admin/users'), env, STAFF_ADMIN);
    expect(res.status).toBe(403);
  });

  it('a SUPERADMIN staffer can list users', async () => {
    const res = await handleListUsers(new Request('https://x/api/admin/users'), env, STAFF_SUPER);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.users.length).toBe(1);
    expect(data.users[0].email).toBe('alice@example.com');
  });

  it('the ADMIN_KEY/owner bypass can list users', async () => {
    const res = await handleListUsers(new Request('https://x/api/admin/users'), env, OWNER);
    expect(res.status).toBe(200);
  });

  it('search query filters by email/name/company, and non-matches return empty', async () => {
    const res = await handleListUsers(new Request('https://x/api/admin/users?q=alice'), env, STAFF_SUPER);
    const data = await res.json();
    expect(data.users.length).toBe(1);

    const res2 = await handleListUsers(new Request('https://x/api/admin/users?q=nomatch'), env, STAFF_SUPER);
    const data2 = await res2.json();
    expect(data2.users.length).toBe(0);
  });

  it('handleGetUserAdmin returns 404 for an unknown user', async () => {
    const res = await handleGetUserAdmin(new Request('https://x'), env, STAFF_SUPER, 'nope');
    expect(res.status).toBe(404);
  });

  it('handleGetUserAdmin returns the user plus their org memberships', async () => {
    const res = await handleGetUserAdmin(new Request('https://x'), env, STAFF_SUPER, 'cust1');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.user.email).toBe('alice@example.com');
    expect(data.organizations.length).toBe(1);
    expect(data.organizations[0].role).toBe('OWNER');
  });

  it('handleUpdateUserStatus rejects an invalid status value', async () => {
    const req = new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'banned' }) });
    const res = await handleUpdateUserStatus(req, env, STAFF_SUPER, 'cust1');
    expect(res.status).toBe(400);
  });

  it('handleUpdateUserStatus returns 404 for an unknown user', async () => {
    const req = new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'suspended' }) });
    const res = await handleUpdateUserStatus(req, env, STAFF_SUPER, 'nope');
    expect(res.status).toBe(404);
  });

  it('a plain ADMIN-tier staffer cannot suspend a user — Super-Admin only', async () => {
    const req = new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'suspended' }) });
    const res = await handleUpdateUserStatus(req, env, STAFF_ADMIN, 'cust1');
    expect(res.status).toBe(403);
  });

  it('suspending a user updates status, revokes outstanding refresh tokens, and writes an audit entry', async () => {
    const req = new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'suspended' }) });
    const res = await handleUpdateUserStatus(req, env, STAFF_SUPER, 'cust1');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('suspended');

    const row = env.DB._sqlite.prepare('SELECT status FROM users WHERE id = ?').get('cust1');
    expect(row.status).toBe('suspended');

    const token = env.DB._sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE id = ?').get('rt1');
    expect(token.revoked).toBe(1);

    expect(env.KV._store.size).toBe(1);
  });

  it('reactivating a user does not touch refresh tokens — only suspend revokes', async () => {
    env.DB._sqlite.prepare('UPDATE users SET status = ? WHERE id = ?').run('suspended', 'cust1');
    const req = new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'active' }) });
    const res = await handleUpdateUserStatus(req, env, STAFF_SUPER, 'cust1');
    expect(res.status).toBe(200);
    const token = env.DB._sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE id = ?').get('rt1');
    expect(token.revoked).toBe(0);
  });

  it('setting the same status returns unchanged:true without rewriting or revoking', async () => {
    const req = new Request('https://x', { method: 'PATCH', body: JSON.stringify({ status: 'active' }) });
    const res = await handleUpdateUserStatus(req, env, STAFF_SUPER, 'cust1');
    const data = await res.json();
    expect(data.unchanged).toBe(true);
    const token = env.DB._sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE id = ?').get('rt1');
    expect(token.revoked).toBe(0);
  });
});

describe('staffUserOrgAdmin.js — Organizations oversight (admin:orgs:read, Admin+)', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1(), KV: makeFakeKV() };
    env.DB._sqlite.exec(`CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT, full_name TEXT, tier TEXT, status TEXT DEFAULT 'active'
    )`);
    env.DB._sqlite.exec(`CREATE TABLE organizations (
      id TEXT PRIMARY KEY, name TEXT, slug TEXT, plan TEXT, owner_id TEXT,
      max_members INTEGER DEFAULT 5, max_daily_scans INTEGER DEFAULT 100,
      domain TEXT, industry TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
    )`);
    env.DB._sqlite.exec(`CREATE TABLE org_members (
      id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, role TEXT DEFAULT 'MEMBER',
      status TEXT DEFAULT 'active', joined_at TEXT DEFAULT (datetime('now'))
    )`);

    env.DB._sqlite.prepare(`INSERT INTO users (id, email, full_name, tier, status) VALUES (?,?,?,?,?)`)
      .run('owner1', 'owner@acme.com', 'Owner Person', 'PRO', 'active');
    env.DB._sqlite.prepare(`INSERT INTO users (id, email, full_name, tier, status) VALUES (?,?,?,?,?)`)
      .run('member1', 'member@acme.com', 'Member Person', 'PRO', 'active');
    env.DB._sqlite.prepare(`INSERT INTO organizations (id, name, slug, plan, owner_id) VALUES (?,?,?,?,?)`)
      .run('org1', 'Acme Corp', 'acme-corp', 'PRO', 'owner1');
    env.DB._sqlite.prepare(`INSERT INTO org_members (id, org_id, user_id, role) VALUES (?,?,?,?)`).run('m1', 'org1', 'owner1', 'OWNER');
    env.DB._sqlite.prepare(`INSERT INTO org_members (id, org_id, user_id, role) VALUES (?,?,?,?)`).run('m2', 'org1', 'member1', 'MEMBER');
  });

  it('anonymous caller is rejected (403)', async () => {
    const res = await handleListOrgsAdmin(new Request('https://x'), env, ANON);
    expect(res.status).toBe(403);
  });

  it('a plain ADMIN-tier staffer CAN read org oversight — lower bar than users:manage', async () => {
    const res = await handleListOrgsAdmin(new Request('https://x'), env, STAFF_ADMIN);
    expect(res.status).toBe(200);
  });

  it('lists organizations with owner email and member_count computed', async () => {
    const res = await handleListOrgsAdmin(new Request('https://x'), env, STAFF_ADMIN);
    const data = await res.json();
    expect(data.organizations.length).toBe(1);
    expect(data.organizations[0].owner_email).toBe('owner@acme.com');
    expect(data.organizations[0].member_count).toBe(2);
  });

  it('search query filters by name/slug, and non-matches return empty', async () => {
    const res = await handleListOrgsAdmin(new Request('https://x?q=acme'), env, STAFF_ADMIN);
    const data = await res.json();
    expect(data.organizations.length).toBe(1);

    const res2 = await handleListOrgsAdmin(new Request('https://x?q=nomatch'), env, STAFF_ADMIN);
    const data2 = await res2.json();
    expect(data2.organizations.length).toBe(0);
  });

  it('handleGetOrgAdmin returns 404 for an unknown org', async () => {
    const res = await handleGetOrgAdmin(new Request('https://x'), env, STAFF_ADMIN, 'nope');
    expect(res.status).toBe(404);
  });

  it('handleGetOrgAdmin returns the organization plus its full member list', async () => {
    const res = await handleGetOrgAdmin(new Request('https://x'), env, STAFF_ADMIN, 'org1');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.organization.name).toBe('Acme Corp');
    expect(data.organization.owner_email).toBe('owner@acme.com');
    expect(data.members.length).toBe(2);
    expect(data.members.map((m) => m.role).sort()).toEqual(['MEMBER', 'OWNER']);
  });
});
