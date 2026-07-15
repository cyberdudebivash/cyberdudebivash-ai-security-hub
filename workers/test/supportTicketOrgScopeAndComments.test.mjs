/* CAP-PORTAL-004: Customer Support Ticket UI — org scoping, comment thread,
 * and status-transition RBAC added to workers/src/handlers/support.js.
 *
 * Drives everything through the real handleSupport(request, env, authCtx,
 * path, method) dispatcher — the same entry point index.js uses — against a
 * real SQL engine (node:sqlite), following this repo's aiMaturityHandler.test.mjs
 * / orgRbacIsolation.test.mjs conventions. deliverNotification is mocked: this
 * file verifies it's *called* with the right shape, not that a webhook is
 * actually delivered (that's notificationPlatform.js's own test coverage).
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

vi.mock('../src/handlers/notificationPlatform.js', () => ({
  deliverNotification: vi.fn(async () => ({ INAPP: 'SENT' })),
}));

import { deliverNotification } from '../src/handlers/notificationPlatform.js';
import { handleSupport } from '../src/handlers/support.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
}

const U = (id, extra = {}) => ({ authenticated: true, userId: id, user_id: id, tier: 'PRO', ...extra });
const ANON  = { authenticated: false, tier: 'FREE' };
const STAFF = U('staff-1', { isAdmin: true });

const ownerA = U('owner-a'), analystA = U('analyst-a'), outsider = U('outsider'), soloUser = U('solo-user');

function req(path, method, body) {
  return new Request(`https://x${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

describe('Support Ticket System — org scoping, comments, status RBAC (CAP-PORTAL-004)', () => {
  let env, db;
  const call = (path, method, authCtx, body) =>
    handleSupport(req(path, method, body), env, authCtx, path.split('?')[0], method);

  beforeEach(() => {
    vi.clearAllMocks();
    env = { DB: makeRealD1() };
    db = env.DB._sqlite;

    db.exec(`CREATE TABLE support_tickets (
      id TEXT PRIMARY KEY, user_id TEXT, tier TEXT, subject TEXT, description TEXT,
      category TEXT, priority TEXT, status TEXT NOT NULL DEFAULT 'open',
      organization_id TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT
    )`);
    db.exec(`CREATE TABLE support_ticket_comments (
      id TEXT PRIMARY KEY, ticket_id TEXT NOT NULL, author_user_id TEXT NOT NULL,
      is_staff INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
    db.exec(`CREATE TABLE org_members (id TEXT DEFAULT (lower(hex(randomblob(8)))), org_id TEXT, user_id TEXT, role TEXT, status TEXT DEFAULT 'active')`);
    db.exec(`CREATE TABLE system_errors (id TEXT PRIMARY KEY, area TEXT, message TEXT, context TEXT, created_at TEXT DEFAULT (datetime('now')))`);

    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-a','owner-a','OWNER','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-a','analyst-a','ANALYST','active')`).run();
    db.prepare(`INSERT INTO org_members (org_id, user_id, role, status) VALUES ('org-b','owner-b','OWNER','active')`).run();
  });

  // ── Ticket creation ──────────────────────────────────────────────────────
  describe('POST /api/support/ticket', () => {
    it('rejects an unauthenticated caller with 401, and writes no row', async () => {
      const res = await call('/api/support/ticket', 'POST', ANON, { subject: 'Help', description: 'Cannot log in' });
      expect(res.status).toBe(401);
      expect(db.prepare('SELECT COUNT(*) n FROM support_tickets').get().n).toBe(0);
    });

    it('a logged-in user with no org_id gets a personal ticket (organization_id NULL)', async () => {
      const res = await call('/api/support/ticket', 'POST', soloUser, { subject: 'Billing', description: 'Double charged' });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      const row = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(body.ticket_id);
      expect(row.user_id).toBe('solo-user');
      expect(row.organization_id).toBeNull();
    });

    it('an active org member can create a ticket scoped to their org', async () => {
      const res = await call('/api/support/ticket', 'POST', analystA, { subject: 'SIEM setup', description: 'Need help', org_id: 'org-a' });
      expect(res.status).toBe(200);
      const body = await res.json();
      const row = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(body.ticket_id);
      expect(row.organization_id).toBe('org-a');
    });

    it('rejects filing a ticket "as" an org the caller does not belong to (403), and writes no row', async () => {
      const res = await call('/api/support/ticket', 'POST', outsider, { subject: 'x', description: 'y', org_id: 'org-a' });
      expect(res.status).toBe(403);
      expect(db.prepare('SELECT COUNT(*) n FROM support_tickets').get().n).toBe(0);
    });

    it('fires an in-app confirmation notification on successful creation', async () => {
      await call('/api/support/ticket', 'POST', soloUser, { subject: 'x', description: 'y' });
      expect(deliverNotification).toHaveBeenCalledTimes(1);
      const [payload] = deliverNotification.mock.calls[0];
      expect(payload.userId).toBe('solo-user');
      expect(payload.channels).toEqual(['INAPP']);
    });
  });

  // ── My tickets list ──────────────────────────────────────────────────────
  describe('GET /api/support/tickets/mine', () => {
    it('unauthenticated caller gets 401', async () => {
      const res = await call('/api/support/tickets/mine', 'GET', ANON);
      expect(res.status).toBe(401);
    });

    it('personal-scope list only ever returns the caller\'s own org-less tickets', async () => {
      await call('/api/support/ticket', 'POST', soloUser, { subject: 'mine', description: 'd' });
      await call('/api/support/ticket', 'POST', outsider, { subject: 'not mine', description: 'd' });

      const res = await call('/api/support/tickets/mine', 'GET', soloUser);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.length).toBe(1);
      expect(body.data[0].subject).toBe('mine');
    });

    it('org-scoped list (?org_id=) is visible to any active member of that org', async () => {
      await call('/api/support/ticket', 'POST', analystA, { subject: 'org ticket', description: 'd', org_id: 'org-a' });

      const res = await call('/api/support/tickets/mine?org_id=org-a', 'GET', ownerA);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.length).toBe(1);
      expect(body.meta.pagination.total).toBe(1);
    });

    it('a non-member requesting another org\'s scope gets 403, not the org\'s tickets', async () => {
      await call('/api/support/ticket', 'POST', analystA, { subject: 'org ticket', description: 'd', org_id: 'org-a' });
      const res = await call('/api/support/tickets/mine?org_id=org-a', 'GET', outsider);
      expect(res.status).toBe(403);
    });
  });

  // ── Ticket detail + cross-org isolation ──────────────────────────────────
  describe('GET /api/support/ticket/:id', () => {
    it('the ticket owner can view their own personal ticket', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}`, 'GET', soloUser);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.ticket.id).toBe(create.ticket_id);
      expect(body.data.comments).toEqual([]);
    });

    it('a member of a DIFFERENT org gets 404, not the other org\'s ticket (cross-org isolation, no existence leak)', async () => {
      const create = await (await call('/api/support/ticket', 'POST', analystA, { subject: 's', description: 'd', org_id: 'org-a' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}`, 'GET', U('owner-b'));
      expect(res.status).toBe(404);
    });

    it('a stranger cannot view another user\'s personal ticket (404)', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}`, 'GET', outsider);
      expect(res.status).toBe(404);
    });

    it('platform staff (isAdmin) can view any ticket', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}`, 'GET', STAFF);
      expect(res.status).toBe(200);
    });

    it('a nonexistent ticket id is 404', async () => {
      const res = await call('/api/support/ticket/nope', 'GET', soloUser);
      expect(res.status).toBe(404);
    });
  });

  // ── Comments ─────────────────────────────────────────────────────────────
  describe('POST /api/support/ticket/:id/comment', () => {
    it('the ticket owner can comment on their own ticket', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/comment`, 'POST', soloUser, { body: 'any update?' });
      expect(res.status).toBe(201);
      const row = db.prepare('SELECT * FROM support_ticket_comments WHERE ticket_id = ?').get(create.ticket_id);
      expect(row.author_user_id).toBe('solo-user');
      expect(row.is_staff).toBe(0);
    });

    it('a same-org member can comment on the org\'s ticket', async () => {
      const create = await (await call('/api/support/ticket', 'POST', analystA, { subject: 's', description: 'd', org_id: 'org-a' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/comment`, 'POST', ownerA, { body: 'checking on this' });
      expect(res.status).toBe(201);
    });

    it('a stranger cannot comment on someone else\'s ticket (404, not leaked)', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/comment`, 'POST', outsider, { body: 'hi' });
      expect(res.status).toBe(404);
      expect(db.prepare('SELECT COUNT(*) n FROM support_ticket_comments').get().n).toBe(0);
    });

    it('an empty comment body is rejected with 400', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/comment`, 'POST', soloUser, { body: '   ' });
      expect(res.status).toBe(400);
    });

    it('a staff reply is marked is_staff and notifies the ticket owner', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      vi.clearAllMocks(); // drop the ticket-creation confirmation notification
      const res = await call(`/api/support/ticket/${create.ticket_id}/comment`, 'POST', STAFF, { body: 'We are looking into it.' });
      expect(res.status).toBe(201);
      const row = db.prepare('SELECT * FROM support_ticket_comments WHERE ticket_id = ?').get(create.ticket_id);
      expect(row.is_staff).toBe(1);
      expect(deliverNotification).toHaveBeenCalledTimes(1);
      expect(deliverNotification.mock.calls[0][0].userId).toBe('solo-user');
    });

    it('a customer reply does NOT fire an in-app notification (no fixed staff recipient exists yet)', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      vi.clearAllMocks();
      await call(`/api/support/ticket/${create.ticket_id}/comment`, 'POST', soloUser, { body: 'any update?' });
      expect(deliverNotification).not.toHaveBeenCalled();
    });
  });

  // ── Status transitions ───────────────────────────────────────────────────
  describe('POST /api/support/ticket/:id/status', () => {
    it('the ticket owner can mark their own open ticket resolved', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/status`, 'POST', soloUser, { status: 'resolved' });
      expect(res.status).toBe(200);
      expect(db.prepare('SELECT status FROM support_tickets WHERE id = ?').get(create.ticket_id).status).toBe('resolved');
    });

    it('a customer cannot set status to "closed" — staff-only terminal state', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/status`, 'POST', soloUser, { status: 'closed' });
      expect(res.status).toBe(403);
      expect(db.prepare('SELECT status FROM support_tickets WHERE id = ?').get(create.ticket_id).status).toBe('open');
    });

    it('staff can set status to "closed"', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/status`, 'POST', STAFF, { status: 'closed' });
      expect(res.status).toBe(200);
      expect(db.prepare('SELECT status FROM support_tickets WHERE id = ?').get(create.ticket_id).status).toBe('closed');
    });

    it('a stranger cannot change another user\'s ticket status (404)', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      const res = await call(`/api/support/ticket/${create.ticket_id}/status`, 'POST', outsider, { status: 'resolved' });
      expect(res.status).toBe(404);
    });

    it('reopening a resolved ticket back to "open" is allowed for the owner', async () => {
      const create = await (await call('/api/support/ticket', 'POST', soloUser, { subject: 's', description: 'd' })).json();
      await call(`/api/support/ticket/${create.ticket_id}/status`, 'POST', soloUser, { status: 'resolved' });
      const res = await call(`/api/support/ticket/${create.ticket_id}/status`, 'POST', soloUser, { status: 'open' });
      expect(res.status).toBe(200);
      expect(db.prepare('SELECT status FROM support_tickets WHERE id = ?').get(create.ticket_id).status).toBe('open');
    });
  });
});
