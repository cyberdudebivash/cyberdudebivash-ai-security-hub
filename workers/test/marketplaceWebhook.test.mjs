/* Regression tests — Fix #4: close the purchase→delivery chain.
 * The marketplace webhook confirms payment, flips marketplace_orders to 'paid'
 * (the gate secureDownload.js enforces) and activates the entitlement. Tested
 * via the exported dispatcher: admin confirmation, idempotency, 404/400/403. */
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMarketplace } from '../src/handlers/sentinelApexMarketplace.js';

function makeEnv(seedOrders = []) {
  const orders = new Map(seedOrders.map(o => [o.id, { ...o }]));
  const entitlements = [];
  const env = {
    // No RAZORPAY_WEBHOOK_SECRET ⇒ signature path can't authorize (admin only).
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async first() {
            if (/SELECT id, status FROM marketplace_orders/.test(sql)) {
              const o = orders.get(b[0]);
              return o ? { id: o.id, status: o.status } : null;
            }
            return null;
          },
          async run() {
            if (/UPDATE marketplace_orders SET status = 'paid'/.test(sql)) {
              const o = orders.get(b[0]); if (o) o.status = 'paid';
            }
            if (/UPDATE marketplace_entitlements SET status = 'active'/.test(sql)) {
              entitlements.push({ order_id: b[0], status: 'active' });
            }
            return { success: true };
          },
        };
      },
    },
  };
  return { env, orders, entitlements };
}

function webhookReq(body) {
  return new Request('https://x/api/marketplace/webhook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const admin = { authenticated: true, isAdmin: true, userId: 'admin' };
const normalUser = { authenticated: true, userId: 'u1' };
const call = (env, req, ctx) =>
  handleMarketplace(req, env, ctx, '/api/marketplace/webhook', 'POST');

describe('marketplace webhook — purchase→delivery chain', () => {
  let ctx;
  beforeEach(() => { ctx = makeEnv([{ id: 'order-1', status: 'pending' }]); });

  it('rejects a non-admin, unsigned confirmation (403)', async () => {
    const res = await call(ctx.env, webhookReq({ order_id: 'order-1' }), normalUser);
    expect(res.status).toBe(403);
    expect(ctx.orders.get('order-1').status).toBe('pending'); // unchanged
  });

  it('admin confirmation flips pending → paid and provisions', async () => {
    const res = await call(ctx.env, webhookReq({ order_id: 'order-1' }), admin);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('paid');
    expect(body.via).toBe('admin_confirmation');
    expect(ctx.orders.get('order-1').status).toBe('paid');
    expect(ctx.entitlements.some(e => e.order_id === 'order-1' && e.status === 'active')).toBe(true);
  });

  it('is idempotent — re-confirming an already-paid order is a no-op', async () => {
    await call(ctx.env, webhookReq({ order_id: 'order-1' }), admin);
    const res2 = await call(ctx.env, webhookReq({ order_id: 'order-1' }), admin);
    const body = await res2.json();
    expect(body.status).toBe('already_paid');
    expect(body.idempotent).toBe(true);
  });

  it('returns 404 for an unknown order', async () => {
    const res = await call(ctx.env, webhookReq({ order_id: 'does-not-exist' }), admin);
    expect(res.status).toBe(404);
  });

  it('returns 400 when order_id is missing', async () => {
    const res = await call(ctx.env, webhookReq({}), admin);
    expect(res.status).toBe(400);
  });
});
