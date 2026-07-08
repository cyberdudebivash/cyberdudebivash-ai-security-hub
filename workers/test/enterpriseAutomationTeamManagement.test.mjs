/* Regression test — POST /api/auto/team and DELETE /api/auto/team/:id gated
 * on `authCtx.role` being the uppercase 'OWNER'/'ADMIN' strings from this
 * file's own ROLES vocabulary. authCtx.role is derived by withAuthAliases()
 * and only ever holds lowercase 'admin'/'mssp_admin'/'partner'/undefined —
 * it can never equal 'OWNER' or 'ADMIN'. Nothing else in the codebase ever
 * seeds an org_team_members row with role OWNER either, so this was a
 * permanent 403 for every caller, including the platform's real admin: team
 * management was completely unusable since it shipped.
 *
 * Fix (2026-07-08): every query in handleAddTeamMember/handleRemoveTeamMember
 * is already scoped to orgId(authCtx) — the caller's own org, derived from
 * their own authCtx and never a request parameter — so there is no
 * cross-tenant path through this endpoint. Removed the unreachable role gate
 * so any authenticated caller can manage their own org's team, matching
 * handleListTeamMembers (same file) which never had a role gate at all. */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAutoRoute } from '../src/handlers/enterpriseAutomation.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { return Promise.all(stmts.map(s => s.run())); },
  };
}

const FREE_USER = { authenticated: true, userId: 'u1', tier: 'FREE' };
const OTHER_USER = { authenticated: true, userId: 'u2', tier: 'PRO' };
const OWNER = { authenticated: true, userId: 'admin', isAdmin: true };
const ANON = { authenticated: false };

describe('enterpriseAutomation.js — team management is usable by a real customer for their own org', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE org_team_members (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, email TEXT,
      role TEXT NOT NULL DEFAULT 'VIEWER', invited_by TEXT, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now'))
    )`);
  });

  function addReq(body) {
    return new Request('https://x/api/auto/team', { method: 'POST', body: JSON.stringify(body) });
  }

  it('an unauthenticated caller is still rejected', async () => {
    const res = await handleAutoRoute(addReq({ user_id: 'teammate1' }), env, ANON, '/api/auto/team', 'POST');
    expect(res.status).toBe(401);
  });

  it('a real authenticated customer (FREE tier, no isAdmin, no special role) can add a team member to their own org', async () => {
    const res = await handleAutoRoute(addReq({ user_id: 'teammate1', email: 't1@x.com' }), env, FREE_USER, '/api/auto/team', 'POST');
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.user_id).toBe('teammate1');
  });

  it('the platform admin (isAdmin bypass) can also add a team member', async () => {
    const res = await handleAutoRoute(addReq({ user_id: 'teammate2' }), env, OWNER, '/api/auto/team', 'POST');
    expect(res.status).toBe(201);
  });

  it('added members are scoped to the caller\'s own org — a different user does not see them', async () => {
    await handleAutoRoute(addReq({ user_id: 'teammate1' }), env, FREE_USER, '/api/auto/team', 'POST');
    const res  = await handleAutoRoute(new Request('https://x/api/auto/team'), env, OTHER_USER, '/api/auto/team', 'GET');
    const body = await res.json();
    expect(body.members).toHaveLength(0);

    const ownRes  = await handleAutoRoute(new Request('https://x/api/auto/team'), env, FREE_USER, '/api/auto/team', 'GET');
    const ownBody = await ownRes.json();
    expect(ownBody.members).toHaveLength(1);
  });

  it('a real customer can remove a team member from their own org', async () => {
    const created = await (await handleAutoRoute(addReq({ user_id: 'teammate1' }), env, FREE_USER, '/api/auto/team', 'POST')).json();
    const res = await handleAutoRoute(new Request('https://x/api/auto/team/' + created.id, { method: 'DELETE' }), env, FREE_USER, '/api/auto/team/' + created.id, 'DELETE');
    expect(res.status).toBe(200);
  });

  it('a customer cannot remove a team member belonging to a different org', async () => {
    const created = await (await handleAutoRoute(addReq({ user_id: 'teammate1' }), env, FREE_USER, '/api/auto/team', 'POST')).json();
    const res = await handleAutoRoute(new Request('https://x/api/auto/team/' + created.id, { method: 'DELETE' }), env, OTHER_USER, '/api/auto/team/' + created.id, 'DELETE');
    expect(res.status).toBe(404);
  });
});
