/* v24Handler.js authorization hardening (2026-07-14 commercial-integrity
 * audit / Enterprise Commercial Product Registry follow-up).
 *
 * A full read of this file (prompted by two originally-scoped findings —
 * scanner/fulfill's missing payment verification and billing/invoice/create's
 * missing payment check) found the same root cause in 7 more routes: this
 * file already establishes isAdmin()/isOwner() conventions correctly for
 * some routes (license/issue, refund/process, recovery/run, ...) but applies
 * them inconsistently — several routes that touch real internal business
 * data or write real records had either no auth check, or only
 * `authCtx?.userId` (any logged-in customer, any tier) where the sibling
 * routes for the exact same resource correctly require isAdmin/isOwner.
 *
 * Fixed this pass, each verified below:
 *   1. billing/invoice/create — any user -> isAdmin (was: mints a "paid"
 *      invoice with no payment check at all)
 *   2. billing/invoice/:id    — no ownership check -> owner-or-admin
 *      (known IDOR flagged in PR #230's own notes, never fixed until now)
 *   3. sales/score (deal_id branch) — no auth -> isAdmin
 *   4. scanner/fulfill — no verification at all -> real Razorpay signature
 *      required (the most severe finding: free access to paid reports)
 *   5. sales/pipeline — any user -> isAdmin
 *   6. proposals (list) — any user -> isAdmin
 *   7. proposals/:id/send — no auth -> isAdmin
 *   8. ceo/dashboard — any user -> isOwner (same class as already-fixed C1)
 *   9. ceo/revenue-streams — any user -> isOwner
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleV24 } from '../src/handlers/v24Handler.js';

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

function fakeD1() {
  const noop = { async all() { return { results: [] }; }, async first() { return null; }, async run() { return { meta: { changes: 0 } }; } };
  return { prepare: () => ({ bind: () => noop, ...noop }) };
}

const SECRET = 'test_razorpay_secret';
async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

const ANON       = { authenticated: false };
const FREE_USER  = { authenticated: true, userId: 'u1', tier: 'FREE' };
const OTHER_USER = { authenticated: true, userId: 'u2', tier: 'ENTERPRISE' };
const ADMIN      = { authenticated: true, userId: 'admin', isAdmin: true };

function req(body) {
  return new Request('https://x/v24', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) });
}
function getReq() {
  return new Request('https://x/v24', { method: 'GET' });
}

describe('1. billing/invoice/create — requires isAdmin, not just any logged-in user', () => {
  it('a regular authenticated customer is rejected', async () => {
    const res = await handleV24(req({ line_items: [{ description: 'x', amount_inr: 999999 }] }), { DB: fakeD1() }, FREE_USER, '/api/v24/billing/invoice/create', 'POST');
    expect(res.status).toBe(403);
  });

  it('admin is admitted', async () => {
    const res = await handleV24(req({ line_items: [{ description: 'x', amount_inr: 999 }] }), { DB: fakeD1() }, ADMIN, '/api/v24/billing/invoice/create', 'POST');
    expect(res.status).not.toBe(403);
  });
});

describe('2. billing/invoice/:id — owner-or-admin only (PR #230\'s known IDOR)', () => {
  function seedDb() {
    const db = makeRealD1();
    db._sqlite.exec(`CREATE TABLE invoices (id TEXT PRIMARY KEY, user_id TEXT, total_inr INTEGER, status TEXT)`);
    db._sqlite.exec(`INSERT INTO invoices (id, user_id, total_inr, status) VALUES ('inv1', 'u1', 999, 'paid')`);
    return db;
  }

  it('anonymous caller is rejected', async () => {
    const res = await handleV24(getReq(), { DB: seedDb() }, ANON, '/api/v24/billing/invoice/inv1', 'GET');
    expect(res.status).toBe(401);
  });

  it('a different authenticated user cannot fetch someone else\'s invoice', async () => {
    const res = await handleV24(getReq(), { DB: seedDb() }, OTHER_USER, '/api/v24/billing/invoice/inv1', 'GET');
    expect(res.status).toBe(403);
  });

  it('the owning customer can fetch their own invoice', async () => {
    const res = await handleV24(getReq(), { DB: seedDb() }, FREE_USER, '/api/v24/billing/invoice/inv1', 'GET');
    expect(res.status).toBe(200);
    const d = await res.json();
    expect(d.invoice.id).toBe('inv1');
  });

  it('admin can fetch any invoice', async () => {
    const res = await handleV24(getReq(), { DB: seedDb() }, ADMIN, '/api/v24/billing/invoice/inv1', 'GET');
    expect(res.status).toBe(200);
  });
});

describe('3. sales/score — deal_id write branch requires isAdmin; pure scoring stays open', () => {
  it('scoring with no deal_id requires no auth (no side effects)', async () => {
    const res = await handleV24(req({ security_budget_inr: 500000 }), { DB: fakeD1() }, ANON, '/api/v24/sales/score', 'POST');
    expect(res.status).toBe(200);
  });

  it('a non-admin caller cannot write to a real deal via deal_id', async () => {
    const res = await handleV24(req({ deal_id: 'deal1', security_budget_inr: 500000 }), { DB: fakeD1() }, FREE_USER, '/api/v24/sales/score', 'POST');
    expect(res.status).toBe(403);
  });

  it('admin can write to a deal via deal_id', async () => {
    const res = await handleV24(req({ deal_id: 'deal1', security_budget_inr: 500000 }), { DB: fakeD1() }, ADMIN, '/api/v24/sales/score', 'POST');
    expect(res.status).toBe(200);
  });
});

describe('4. scanner/fulfill — requires a real Razorpay signature (was: none at all)', () => {
  it('rejects a request missing razorpay_order_id/razorpay_signature (the original free-access gap)', async () => {
    const res = await handleV24(req({ order_id: 'so-1', payment_id: 'pay_1' }), { DB: fakeD1() }, ANON, '/api/v24/scanner/fulfill', 'POST');
    expect(res.status).toBe(400);
  });

  it('rejects a tampered signature', async () => {
    const res = await handleV24(req({
      order_id: 'so-1', payment_id: 'pay_1', razorpay_order_id: 'order_1', razorpay_signature: 'wrong',
    }), { DB: fakeD1(), RAZORPAY_KEY_SECRET: SECRET }, ANON, '/api/v24/scanner/fulfill', 'POST');
    const d = await res.json();
    expect(d.success).toBe(false);
    expect(d.code).toBe('INVALID_SIGNATURE');
  });

  it('accepts a genuine signature and proceeds to fulfillment', async () => {
    const sig = await hmac(SECRET, 'order_2|pay_2');
    const res = await handleV24(req({
      order_id: 'so-2', payment_id: 'pay_2', razorpay_order_id: 'order_2', razorpay_signature: sig,
    }), { DB: fakeD1(), RAZORPAY_KEY_SECRET: SECRET }, ANON, '/api/v24/scanner/fulfill', 'POST');
    const d = await res.json();
    expect(d.code).not.toBe('INVALID_SIGNATURE');
  });
});

describe('5-7. sales/pipeline, proposals (list), proposals/:id/send — isAdmin required', () => {
  it('sales/pipeline: a regular customer is rejected', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, FREE_USER, '/api/v24/sales/pipeline', 'GET');
    expect(res.status).toBe(403);
  });
  it('sales/pipeline: admin is admitted', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, ADMIN, '/api/v24/sales/pipeline', 'GET');
    expect(res.status).toBe(200);
  });

  it('proposals list: a regular customer is rejected', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, FREE_USER, '/api/v24/proposals', 'GET');
    expect(res.status).toBe(403);
  });
  it('proposals list: admin is admitted', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, ADMIN, '/api/v24/proposals', 'GET');
    expect(res.status).toBe(200);
  });

  it('proposals/:id/send: an unauthenticated caller is rejected', async () => {
    const res = await handleV24(req({}), { DB: fakeD1() }, ANON, '/api/v24/proposals/prop1/send', 'POST');
    expect(res.status).toBe(403);
  });
  it('proposals/:id/send: admin is admitted', async () => {
    const res = await handleV24(req({}), { DB: fakeD1() }, ADMIN, '/api/v24/proposals/prop1/send', 'POST');
    expect(res.status).toBe(200);
  });
});

describe('8-9. ceo/dashboard, ceo/revenue-streams — isOwner required (same class as already-fixed C1)', () => {
  it('ceo/dashboard: a regular ENTERPRISE-tier customer is rejected', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, OTHER_USER, '/api/v24/ceo/dashboard', 'GET');
    expect(res.status).toBe(403);
  });
  it('ceo/dashboard: admin (isOwner via isAdmin) is admitted', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, ADMIN, '/api/v24/ceo/dashboard', 'GET');
    expect(res.status).not.toBe(403);
  });

  it('ceo/revenue-streams: a regular ENTERPRISE-tier customer is rejected', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, OTHER_USER, '/api/v24/ceo/revenue-streams', 'GET');
    expect(res.status).toBe(403);
  });
  it('ceo/revenue-streams: admin is admitted', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1() }, ADMIN, '/api/v24/ceo/revenue-streams', 'GET');
    expect(res.status).toBe(200);
  });
});
