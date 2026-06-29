/* Tests — Razorpay webhook must apply the subscription tier upgrade when an
 * order's notes carry tenant_id+plan (the path used by
 * /api/subscription/checkout). Regression coverage for the bug where a
 * captured subscription payment never updated users.tier because the
 * webhook only knew about the per-report `payments` table. */
import { describe, it, expect } from 'vitest';
import { handleRazorpayWebhook } from '../src/handlers/payments.js';

const WEBHOOK_SECRET = 'whsec_test_12345';

async function sign(secret, body) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(body));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function memDB({ paymentsRow = null, userRow = null } = {}) {
  const tierUpdates = [];
  const usersCreated = [];
  return {
    tierUpdates, usersCreated,
    prepare(sql) {
      return {
        _sql: sql, _b: [],
        bind(...a) { this._b = a; return this; },
        async first() {
          if (/FROM payments WHERE razorpay_order_id/i.test(this._sql)) return paymentsRow;
          if (/FROM users WHERE email/i.test(this._sql))               return userRow;
          return null;
        },
        async run() {
          if (/UPDATE users SET tier/i.test(this._sql)) {
            tierUpdates.push({ tier: this._b[0], userId: this._b[1] });
          }
          if (/INSERT INTO users/i.test(this._sql)) {
            usersCreated.push({ email: this._b[1], tier: this._b[4] });
          }
          return { success: true };
        },
      };
    },
  };
}

async function webhookRequest(eventObj) {
  const rawBody = JSON.stringify(eventObj);
  const sig     = await sign(WEBHOOK_SECRET, rawBody);
  return new Request('https://x.test/api/webhooks/razorpay', {
    method: 'POST', headers: { 'x-razorpay-signature': sig }, body: rawBody,
  });
}

describe('handleRazorpayWebhook — subscription tier upgrade', () => {
  it('applies UPDATE users SET tier when notes carry tenant_id + a paid plan', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_1', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_1', order_id: 'order_1', notes: { tenant_id: 'user_123', plan: 'PRO' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toEqual([{ tier: 'PROFESSIONAL', userId: 'user_123' }]);
  });

  it('does not touch users.tier for a regular per-report payment (no plan/tenant_id in notes)', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_2', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_2', order_id: 'order_2', notes: { module: 'domain' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
  });

  it('does not apply a tier upgrade for a free/invalid plan value', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_3', event: 'order.paid',
      payload: { payment: { entity: {
        id: 'pay_3', order_id: 'order_3', notes: { tenant_id: 'user_456', plan: 'COMMUNITY' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
  });

  it('rejects a payload with an invalid webhook signature', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const rawBody = JSON.stringify({
      id: 'evt_4', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_4', order_id: 'order_4', notes: { tenant_id: 'user_789', plan: 'PRO' } } } },
    });
    const request = new Request('https://x.test/api/webhooks/razorpay', {
      method: 'POST', headers: { 'x-razorpay-signature': 'deadbeef' }, body: rawBody,
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(401);
    expect(db.tierUpdates).toHaveLength(0);
  });
});

/* Regression coverage — the REAL live checkout (/api/payment/create-order
 * with module='subscription') never puts tenant_id/plan in the Razorpay
 * order notes, only {module, target: email}. The plan is only ever
 * persisted to the `payments` D1 row at order-creation time. Before this
 * fix, the webhook's only subscription-tier-grant branch required
 * notes.tenant_id + notes.plan — dead code for this flow — so a customer
 * whose browser closed right after paying (before the synchronous
 * /api/payment/verify call completed) was charged and never upgraded, with
 * no automatic recovery. */
describe('handleRazorpayWebhook — fallback subscription grant (real checkout flow)', () => {
  it('upgrades an existing user from the payments row when notes carry no plan', async () => {
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'ENTERPRISE', email: 'buyer@example.com', status: 'pending' },
      userRow:     { id: 'usr_1', tier: 'FREE' },
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_5', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_5', order_id: 'order_5', notes: { module: 'subscription', target: 'buyer@example.com' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toEqual([{ tier: 'ENTERPRISE', userId: 'usr_1' }]);
  });

  it('creates a new account at the paid tier if no account exists yet for that email', async () => {
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'MSSP', email: 'newbuyer@example.com', status: 'pending' },
      userRow:     null,
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_6', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_6', order_id: 'order_6', notes: { module: 'subscription', target: 'newbuyer@example.com' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.usersCreated).toEqual([{ email: 'newbuyer@example.com', tier: 'MSSP' }]);
  });

  it('does nothing extra for a non-subscription (per-report) payments row', async () => {
    const db = memDB({
      paymentsRow: { module: 'domain', plan: 'pay_per_report', email: 'reportbuyer@example.com', status: 'pending' },
      userRow:     { id: 'usr_2', tier: 'FREE' },
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_7', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_7', order_id: 'order_7', notes: { module: 'domain' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
    expect(db.usersCreated).toHaveLength(0);
  });
});
