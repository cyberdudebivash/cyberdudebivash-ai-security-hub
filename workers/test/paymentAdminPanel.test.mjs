/* Regression tests — admin-payments.html wiring fix.
 * Three bugs, one change: (1) GET /api/payments/admin only checked
 * `authCtx.authenticated`, which is true even for anonymous IP-fallback callers
 * — anyone could list every manual payment record (PII + revenue data).
 * (2) POST /api/payments/verify was registered twice — the legitimate Razorpay
 * handler (line ~1589) and a dead, unreachable manual-payment handler (former
 * line ~4801) shared the same path+method, so the second registration could
 * never run. (3) The already-deployed admin-payments.html dashboard calls
 * /api/payment/admin/{list,stats,approve/:id,reject/:id} with an
 * `x-admin-secret` header — none of those existed server-side, so the panel
 * was 100% non-functional in production despite looking complete.
 * Fixed by: owner-gating /api/payments/admin, deleting the dead duplicate,
 * accepting x-admin-secret as an ADMIN_KEY alias, and adding the four routes
 * the dashboard already expects. */
import { describe, it, expect } from 'vitest';
import { resolveAuthV5 } from '../src/auth/middleware.js';
import {
  handleAdminPaymentList, handleAdminPaymentStats, handleAdminPaymentAction,
} from '../src/handlers/manualPayments.js';
import worker from '../src/index.js';

function makeKV(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
    _store: store,
  };
}

function seedRecord(overrides = {}) {
  return {
    payment_id: 'pay_1', user_id: 'u1', product_id: 'PRO', amount_inr: 1499,
    payment_method: 'upi', transaction_id: 'TXN123456', payer_email: 'a@b.com',
    status: 'pending', created_at: '2026-01-01T00:00:00.000Z',
    verified_at: null, admin_note: '',
    ...overrides,
  };
}

function seedKvWithRecords(records) {
  const seed = {
    'payment:index': JSON.stringify(records.map(r => (
      { payment_id: r.payment_id, status: r.status, amount_inr: r.amount_inr, payer_email: r.payer_email, created_at: r.created_at, product_id: r.product_id }
    ))),
  };
  for (const r of records) {
    seed[`payment:record:${r.payment_id}`] = JSON.stringify(r);
    seed[`payment:user:${r.payer_email}`] = JSON.stringify([
      { payment_id: r.payment_id, status: r.status, amount_inr: r.amount_inr, product_id: r.product_id, created_at: r.created_at },
    ]);
  }
  return makeKV(seed);
}

// ── resolveAuthV5 — x-admin-secret as an ADMIN_KEY alias ─────────────────────
describe('resolveAuthV5 — x-admin-secret header', () => {
  it('grants the admin context when x-admin-secret matches env.ADMIN_KEY', async () => {
    const req = new Request('https://x/api/payment/admin/list', { headers: { 'x-admin-secret': 'SECRET' } });
    const ctx = await resolveAuthV5(req, { ADMIN_KEY: 'SECRET' });
    expect(ctx.isAdmin).toBe(true);
    expect(ctx.tier).toBe('ENTERPRISE');
  });

  it('rejects a wrong x-admin-secret (falls through to IP fallback, not admin)', async () => {
    const req = new Request('https://x/api/payment/admin/list', { headers: { 'x-admin-secret': 'WRONG' } });
    const ctx = await resolveAuthV5(req, { ADMIN_KEY: 'SECRET' });
    expect(ctx.isAdmin).toBeUndefined();
    expect(ctx.method).toBe('ip_fallback');
  });

  it('still accepts the original x-api-key / Bearer admin paths (no regression)', async () => {
    const req1 = await resolveAuthV5(new Request('https://x/', { headers: { 'x-api-key': 'SECRET' } }), { ADMIN_KEY: 'SECRET' });
    expect(req1.isAdmin).toBe(true);
    const req2 = await resolveAuthV5(new Request('https://x/', { headers: { Authorization: 'Bearer SECRET' } }), { ADMIN_KEY: 'SECRET' });
    expect(req2.isAdmin).toBe(true);
  });
});

// ── handleAdminPaymentList / handleAdminPaymentStats / handleAdminPaymentAction ──
describe('handleAdminPaymentList', () => {
  it('translates KV records into the dashboard flat shape', async () => {
    const env = { SECURITY_HUB_KV: seedKvWithRecords([seedRecord()]) };
    const res = await handleAdminPaymentList(new Request('https://x/api/payment/admin/list'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.payments).toEqual([{
      record_id: 'pay_1', status: 'pending', method: 'UPI', product: 'Pro Plan',
      user: 'a@b.com', txnId: 'TXN123456', amount: 1499, currency: 'INR',
      created_at: '2026-01-01T00:00:00.000Z', admin_notes: '',
    }]);
  });

  it('maps verified -> approved for the dashboard status badge', async () => {
    const env = { SECURITY_HUB_KV: seedKvWithRecords([seedRecord({ status: 'verified' })]) };
    const body = await (await handleAdminPaymentList(new Request('https://x/api/payment/admin/list'), env)).json();
    expect(body.payments[0].status).toBe('approved');
  });

  it('filters by ?status=', async () => {
    const env = {
      SECURITY_HUB_KV: seedKvWithRecords([
        seedRecord({ payment_id: 'pay_1', status: 'pending' }),
        seedRecord({ payment_id: 'pay_2', status: 'verified', payer_email: 'x@y.com' }),
      ]),
    };
    const body = await (await handleAdminPaymentList(new Request('https://x/api/payment/admin/list?status=pending'), env)).json();
    expect(body.payments.map(p => p.record_id)).toEqual(['pay_1']);
  });

  it('returns an empty list, not an error, when no payments exist', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const res = await handleAdminPaymentList(new Request('https://x/api/payment/admin/list'), env);
    expect(res.status).toBe(200);
    expect((await res.json()).payments).toEqual([]);
  });
});

describe('handleAdminPaymentStats', () => {
  it('aggregates totals and by_method counts across mixed methods', async () => {
    const env = {
      SECURITY_HUB_KV: seedKvWithRecords([
        seedRecord({ payment_id: 'p1', status: 'pending',  payment_method: 'upi',    payer_email: 'p1@x.com' }),
        seedRecord({ payment_id: 'p2', status: 'verified', payment_method: 'bank',   payer_email: 'p2@x.com' }),
        seedRecord({ payment_id: 'p3', status: 'rejected', payment_method: 'paypal', payer_email: 'p3@x.com' }),
        seedRecord({ payment_id: 'p4', status: 'verified', payment_method: 'crypto', payer_email: 'p4@x.com' }),
      ]),
    };
    const stats = await (await handleAdminPaymentStats(new Request('https://x/api/payment/admin/stats'), env)).json();
    expect(stats).toEqual({
      total: 4, pending: 1, approved: 2, rejected: 1,
      by_method: { UPI: 1, BANK: 1, PAYPAL: 1, CRYPTO: 1 },
    });
  });

  it('reports honest zeros for an empty KV instead of fabricated numbers', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const stats = await (await handleAdminPaymentStats(new Request('https://x/api/payment/admin/stats'), env)).json();
    expect(stats).toEqual({ total: 0, pending: 0, approved: 0, rejected: 0, by_method: { UPI: 0, BANK: 0, PAYPAL: 0, CRYPTO: 0 } });
  });
});

describe('handleAdminPaymentAction', () => {
  it('approve activates the plan and flips status to verified/approved', async () => {
    const kv = seedKvWithRecords([seedRecord()]);
    const env = { SECURITY_HUB_KV: kv };
    const req = new Request('https://x/api/payment/admin/approve/pay_1', {
      method: 'POST', body: JSON.stringify({ notes: 'looks good' }),
    });
    const res = await handleAdminPaymentAction(req, env, 'pay_1', 'approve');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true, record_id: 'pay_1', status: 'approved' });

    const stored = JSON.parse(await kv.get('payment:record:pay_1'));
    expect(stored.status).toBe('verified');
    expect(stored.admin_note).toBe('looks good');
    const plan = JSON.parse(await kv.get('user:plan:u1'));
    expect(plan.plan).toBe('PRO');
  });

  it('reject flips status to rejected without activating a plan', async () => {
    const kv = seedKvWithRecords([seedRecord({ payment_id: 'pay_2', payer_email: 'r@x.com', user_id: 'u2' })]);
    const env = { SECURITY_HUB_KV: kv };
    const res = await handleAdminPaymentAction(new Request('https://x/y', { method: 'POST' }), env, 'pay_2', 'reject');
    expect(await res.json()).toEqual({ success: true, record_id: 'pay_2', status: 'rejected' });
    expect(await kv.get('user:plan:u2')).toBeNull();
  });

  it('returns a 404-shaped { detail } error for an unknown record_id', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const res = await handleAdminPaymentAction(new Request('https://x/y', { method: 'POST' }), env, 'does-not-exist', 'approve');
    expect(res.status).toBe(404);
    expect((await res.json()).detail).toBe('Payment not found');
  });

  it('rejects an invalid action with 400', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const res = await handleAdminPaymentAction(new Request('https://x/y', { method: 'POST' }), env, 'pay_1', 'delete');
    expect(res.status).toBe(400);
  });

  it('tolerates a missing/empty JSON body (notes optional)', async () => {
    const kv = seedKvWithRecords([seedRecord()]);
    const env = { SECURITY_HUB_KV: kv };
    const res = await handleAdminPaymentAction(new Request('https://x/y', { method: 'POST' }), env, 'pay_1', 'approve');
    expect(res.status).toBe(200);
  });
});

// ── Full router wiring — proves the gate + dead-route removal + new routes ───
// are actually reachable end-to-end, not just correct in isolation.
describe('router wiring — /api/payment(s)/admin/* end-to-end', () => {
  const ctxStub = { waitUntil: () => {}, passThroughOnException: () => {} };
  const dbStub  = {}; // truthy placeholder — these routes never touch D1

  it('GET /api/payment/admin/list 403s an anonymous (IP-fallback) caller', async () => {
    const env = { DB: dbStub, SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/payment/admin/list'), env, ctxStub);
    expect(res.status).toBe(403);
  });

  it('GET /api/payments/admin (legacy path) is now also owner-gated, not just authenticated-gated', async () => {
    const env = { DB: dbStub, SECURITY_HUB_KV: makeKV() };
    const res = await worker.fetch(new Request('https://x/api/payments/admin'), env, ctxStub);
    expect(res.status).toBe(403);
  });

  it('GET /api/payment/admin/list 200s for the admin secret and returns the dashboard shape', async () => {
    const env = { DB: dbStub, SECURITY_HUB_KV: seedKvWithRecords([seedRecord()]), ADMIN_KEY: 'SECRET' };
    const req = new Request('https://x/api/payment/admin/list', { headers: { 'x-admin-secret': 'SECRET' } });
    const res = await worker.fetch(req, env, ctxStub);
    expect(res.status).toBe(200);
    expect((await res.json()).payments[0].record_id).toBe('pay_1');
  });

  it('POST /api/payment/admin/approve/:id mutates KV through the real router', async () => {
    const kv = seedKvWithRecords([seedRecord({ payment_id: 'pay_9', payer_email: 'z@z.com' })]);
    const env = { DB: dbStub, SECURITY_HUB_KV: kv, ADMIN_KEY: 'SECRET' };
    const req = new Request('https://x/api/payment/admin/approve/pay_9', {
      method: 'POST', headers: { 'x-admin-secret': 'SECRET', 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    });
    const res = await worker.fetch(req, env, ctxStub);
    expect(res.status).toBe(200);
    expect(JSON.parse(await kv.get('payment:record:pay_9')).status).toBe('verified');
  });

  it('the former duplicate: POSTing the old manual-verify body shape to /api/payments/verify no longer verifies anything', async () => {
    const kv = seedKvWithRecords([seedRecord({ payment_id: 'pay_legacy' })]);
    const env = { DB: dbStub, SECURITY_HUB_KV: kv };
    const req = new Request('https://x/api/payments/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payment_id: 'pay_legacy', action: 'approve' }),
    });
    await worker.fetch(req, env, ctxStub);
    // The Razorpay handler now exclusively owns this path+method and doesn't
    // recognize {payment_id, action} — the record must be left untouched.
    expect(JSON.parse(await kv.get('payment:record:pay_legacy')).status).toBe('pending');
  });
});
