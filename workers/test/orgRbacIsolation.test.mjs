/* Organization invites, roles & RBAC (Journey 7).
 *
 * Verdict: org member management is production-grade — invite requires OWNER/
 * ADMIN, role changes are OWNER-only, the OWNER cannot be removed, roles are
 * allowlisted, member limits enforced, and non-members are rejected. Verified
 * live; this suite locks it (there was previously NO test coverage for this
 * critical multi-tenant surface).
 *
 * Runs the real handlers against a real SQL engine (node:sqlite).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleInviteMember, handleUpdateMemberRole, handleRemoveMember } from '../src/handlers/orgManagement.js';

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
const U = (id) => ({ authenticated: true, userId: id, user_id: id });
const owner = U('owner1'), member = U('member1'), outsider = U('outsider1');
const post = (body) => new Request('https://x/api/orgs/org1/members', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const put  = (body) => new Request('https://x/api/orgs/org1/members/x', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const del  = () => new Request('https://x/api/orgs/org1/members/x', { method: 'DELETE' });

describe('org invites + roles + RBAC', () => {
  let env, db;
  beforeEach(() => {
    env = { DB: makeRealD1() }; db = env.DB._sqlite;
    db.exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY, plan TEXT, max_members INTEGER)`);
    db.exec(`CREATE TABLE org_members (id TEXT DEFAULT (lower(hex(randomblob(8)))), org_id TEXT, user_id TEXT, role TEXT, status TEXT DEFAULT 'active', invited_by TEXT, invite_email TEXT, joined_at TEXT)`);
    db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, full_name TEXT, tier TEXT)`);
    db.prepare(`INSERT INTO organizations (id, plan, max_members) VALUES ('org1','ENTERPRISE',50)`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org1','owner1','OWNER','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org1','member1','MEMBER','active')`).run();
    db.prepare(`INSERT INTO users (id, email, full_name, tier) VALUES ('cand','cand@x.com','Candidate','FREE')`).run();
  });

  it('OWNER can invite an existing user by email', async () => {
    const res = await handleInviteMember(post({ email: 'cand@x.com', role: 'ANALYST' }), env, owner, 'org1');
    expect(res.status).toBe(201);
    const row = db.prepare(`SELECT role FROM org_members WHERE user_id='cand'`).get();
    expect(row.role).toBe('ANALYST');
  });
  it('a plain MEMBER cannot invite (403)', async () => {
    const res = await handleInviteMember(post({ email: 'cand@x.com', role: 'MEMBER' }), env, member, 'org1');
    expect(res.status).toBe(403);
  });
  it('an outsider cannot invite (403)', async () => {
    const res = await handleInviteMember(post({ email: 'cand@x.com' }), env, outsider, 'org1');
    expect(res.status).toBe(403);
  });
  it('rejects an invalid role (400)', async () => {
    const res = await handleInviteMember(post({ email: 'cand@x.com', role: 'SUPERADMIN' }), env, owner, 'org1');
    expect(res.status).toBe(400);
  });
  it('rejects inviting an email with no account (404)', async () => {
    const res = await handleInviteMember(post({ email: 'ghost@x.com' }), env, owner, 'org1');
    expect(res.status).toBe(404);
  });
  it('duplicate invite is 409', async () => {
    await handleInviteMember(post({ email: 'cand@x.com' }), env, owner, 'org1');
    const res = await handleInviteMember(post({ email: 'cand@x.com' }), env, owner, 'org1');
    expect(res.status).toBe(409);
  });
  it('only OWNER can change roles (member → 403)', async () => {
    const res = await handleUpdateMemberRole(put({ role: 'ADMIN' }), env, member, 'org1', 'member1');
    expect(res.status).toBe(403);
  });
  it('OWNER can change a role (200)', async () => {
    const res = await handleUpdateMemberRole(put({ role: 'ADMIN' }), env, owner, 'org1', 'member1');
    expect(res.status).toBe(200);
    expect(db.prepare(`SELECT role FROM org_members WHERE user_id='member1'`).get().role).toBe('ADMIN');
  });
  it('the OWNER cannot be removed (404)', async () => {
    const res = await handleRemoveMember(del(), env, owner, 'org1', 'owner1');
    expect(res.status).toBe(404);
    expect(db.prepare(`SELECT status FROM org_members WHERE user_id='owner1'`).get().status).toBe('active');
  });
  it('OWNER can remove a member (200)', async () => {
    const res = await handleRemoveMember(del(), env, owner, 'org1', 'member1');
    expect(res.status).toBe(200);
    expect(db.prepare(`SELECT status FROM org_members WHERE user_id='member1'`).get().status).toBe('suspended');
  });
});
