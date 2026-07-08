/* Discount coupon system (lib/coupons.js) — new for the 2026-07-08
 * revenue-focused audit. The live checkout flow (payments.js
 * handleCreateOrder) had zero discount-code support at all; a `coupon`
 * field existed in one unrelated, effectively-dead checkout path
 * (subscriptionPaywallEngine.js handleSubscriptionCheckout, unreferenced by
 * any live frontend caller) but was destructured and never used.
 *
 * These tests cover: coupon validation rules, discount math, idempotent
 * redemption-counting (must not double-count if both the synchronous
 * /verify call and the async webhook both confirm the same payment), the
 * admin CRUD endpoints, and that handleCreateOrder actually charges the
 * discounted amount (verified via a stubbed Razorpay order-create call). */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import {
  validateCoupon, applyDiscount, recordCouponUsage, finalizeCouponRedemption,
  handleAdminListCoupons, handleAdminCreateCoupon, handleAdminDeactivateCoupon,
} from '../src/lib/coupons.js';
import { handleCreateOrder } from '../src/handlers/payments.js';

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

const ADMIN     = { isAdmin: true, email: 'admin@x.com' };
const NON_ADMIN = { userId: 'u1', tier: 'FREE' };

describe('validateCoupon', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });

  async function seed(overrides = {}) {
    const c = {
      code: 'LAUNCH20', discount_pct: 20, applies_to: 'all',
      max_redemptions: null, expires_at: null, active: 1,
      ...overrides,
    };
    await handleAdminCreateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify(c),
    }), env, ADMIN);
    // handleAdminCreateCoupon always sets active=1; deactivate afterwards if needed
    if (c.active === 0) {
      await env.DB.prepare(`UPDATE discount_coupons SET active=0 WHERE code=?`).bind(c.code).run();
    }
    if (c.max_redemptions != null) {
      await env.DB.prepare(`UPDATE discount_coupons SET max_redemptions=? WHERE code=?`).bind(c.max_redemptions, c.code).run();
    }
    if (c.expires_at) {
      await env.DB.prepare(`UPDATE discount_coupons SET expires_at=? WHERE code=?`).bind(c.expires_at, c.code).run();
    }
  }

  it('rejects an unknown code', async () => {
    const r = await validateCoupon(env, 'NOPE', 'domain', null);
    expect(r.valid).toBe(false);
  });

  it('accepts a valid, active, unrestricted coupon', async () => {
    await seed();
    const r = await validateCoupon(env, 'launch20', 'domain', null); // lowercase input, still matches
    expect(r.valid).toBe(true);
    expect(r.discount_pct).toBe(20);
  });

  it('rejects a deactivated coupon', async () => {
    await seed({ active: 0 });
    const r = await validateCoupon(env, 'LAUNCH20', 'domain', null);
    expect(r.valid).toBe(false);
  });

  it('rejects an expired coupon', async () => {
    await seed({ expires_at: '2020-01-01T00:00:00.000Z' });
    const r = await validateCoupon(env, 'LAUNCH20', 'domain', null);
    expect(r.valid).toBe(false);
  });

  it('rejects a coupon that has hit its redemption cap', async () => {
    await seed({ max_redemptions: 1 });
    await env.DB.prepare(`UPDATE discount_coupons SET redeemed_count=1 WHERE code='LAUNCH20'`).run();
    const r = await validateCoupon(env, 'LAUNCH20', 'domain', null);
    expect(r.valid).toBe(false);
  });

  it('rejects a coupon restricted to a different module/plan', async () => {
    await seed({ code: 'PROONLY', applies_to: 'PRO,ENTERPRISE' });
    const wrong = await validateCoupon(env, 'PROONLY', 'domain', null);
    expect(wrong.valid).toBe(false);
    const right = await validateCoupon(env, 'PROONLY', 'subscription', 'PRO');
    expect(right.valid).toBe(true);
  });
});

describe('applyDiscount', () => {
  it('computes percentage discounts correctly and clamps out-of-range values', () => {
    expect(applyDiscount(100000, 20)).toBe(80000);
    expect(applyDiscount(100000, 0)).toBe(100000);
    expect(applyDiscount(100000, 100)).toBe(0);
    expect(applyDiscount(100000, 150)).toBe(0);   // clamped to 100%
    expect(applyDiscount(100000, -10)).toBe(100000); // clamped to 0%
  });
});

describe('redemption counting is idempotent', () => {
  let env;
  beforeEach(async () => {
    env = { DB: makeRealD1() };
    await handleAdminCreateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ code: 'ONECODE', discount_pct: 10 }),
    }), env, ADMIN);
    await recordCouponUsage(env, {
      razorpayOrderId: 'order_1', code: 'ONECODE', module: 'domain',
      originalAmount: 99900, discountedAmount: 89910,
    });
  });

  it('increments redeemed_count exactly once even if finalize is called twice (verify + webhook both firing)', async () => {
    await finalizeCouponRedemption(env, 'order_1');
    await finalizeCouponRedemption(env, 'order_1');
    const coupon = await env.DB.prepare(`SELECT redeemed_count FROM discount_coupons WHERE code='ONECODE'`).first();
    expect(coupon.redeemed_count).toBe(1);
  });

  it('does nothing for an order with no coupon redemption row', async () => {
    await finalizeCouponRedemption(env, 'order_never_had_a_coupon');
    const coupon = await env.DB.prepare(`SELECT redeemed_count FROM discount_coupons WHERE code='ONECODE'`).first();
    expect(coupon.redeemed_count).toBe(0);
  });
});

describe('admin coupon endpoints', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });

  it('rejects a non-admin caller on all three endpoints', async () => {
    const create = await handleAdminCreateCoupon(new Request('https://x', { method: 'POST', body: JSON.stringify({ code: 'X', discount_pct: 10 }) }), env, NON_ADMIN);
    expect(create.status).toBe(403);
    const list = await handleAdminListCoupons(new Request('https://x'), env, NON_ADMIN);
    expect(list.status).toBe(403);
    const deact = await handleAdminDeactivateCoupon(new Request('https://x', { method: 'DELETE' }), env, NON_ADMIN, 'X');
    expect(deact.status).toBe(403);
  });

  it('an admin can create, list, and deactivate a coupon', async () => {
    const create = await handleAdminCreateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ code: 'WELCOME10', discount_pct: 10 }),
    }), env, ADMIN);
    expect(create.status).toBe(200);

    const list = await handleAdminListCoupons(new Request('https://x'), env, ADMIN);
    const listBody = await list.json();
    expect(listBody.data.coupons.some(c => c.code === 'WELCOME10')).toBe(true);

    const deact = await handleAdminDeactivateCoupon(new Request('https://x', { method: 'DELETE' }), env, ADMIN, 'welcome10');
    expect(deact.status).toBe(200);

    const check = await validateCoupon(env, 'WELCOME10', 'domain', null);
    expect(check.valid).toBe(false);
  });

  it('rejects a malformed code or out-of-range discount_pct', async () => {
    const badCode = await handleAdminCreateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ code: 'a b!', discount_pct: 10 }),
    }), env, ADMIN);
    expect(badCode.status).toBe(400);

    const badPct = await handleAdminCreateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ code: 'VALIDCODE', discount_pct: 150 }),
    }), env, ADMIN);
    expect(badPct.status).toBe(400);
  });
});

describe('handleCreateOrder actually charges the discounted amount', () => {
  const realFetch = globalThis.fetch;
  let lastRazorpayRequestBody = null;

  beforeEach(() => {
    lastRazorpayRequestBody = null;
    globalThis.fetch = async (url, opts) => {
      if (String(url).includes('api.razorpay.com')) {
        lastRazorpayRequestBody = JSON.parse(opts.body);
        return new Response(JSON.stringify({
          id: 'order_stub_1', entity: 'order', amount: lastRazorpayRequestBody.amount,
          currency: 'INR', receipt: lastRazorpayRequestBody.receipt, status: 'created',
        }), { status: 200 });
      }
      return realFetch(url, opts);
    };
  });
  afterAll(() => { globalThis.fetch = realFetch; });

  // Real SQLite-backed DB (not a dumb stub): a coupon created via the admin
  // endpoint must actually be visible to validateCoupon() inside the
  // subsequent handleCreateOrder call. handleCreateOrder's own payments-table
  // reads/writes are all .catch()-wrapped and degrade gracefully without that
  // table existing, so only discount_coupons/coupon_redemptions need to be real.
  function fakeEnv() {
    return { RAZORPAY_KEY_ID: 'rzp_test_x', RAZORPAY_KEY_SECRET: 'secret', DB: makeRealD1() };
  }

  function orderReq(body) {
    return new Request('https://x/api/payment/create-order', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
  }

  it('with no coupon: charges the full module price, unchanged from before this feature', async () => {
    const res = await handleCreateOrder(orderReq({ module: 'domain', target: 'example.com' }), fakeEnv(), {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.amount).toBe(99900); // ₹999 domain report — MODULE_PRICES['domain']
    expect(lastRazorpayRequestBody.amount).toBe(99900);
    expect(body.coupon).toBeNull();
  });

  it('rejects an unknown coupon code before ever calling Razorpay', async () => {
    const res = await handleCreateOrder(orderReq({ module: 'domain', target: 'example.com', coupon_code: 'NOPE' }), fakeEnv(), {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.code).toBe('INVALID_COUPON');
    expect(lastRazorpayRequestBody).toBeNull();
  });

  it('with a valid coupon: Razorpay order + response both reflect the discounted amount', async () => {
    const env = fakeEnv();
    await handleAdminCreateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ code: 'LAUNCH20', discount_pct: 20 }),
    }), env, ADMIN);

    const res  = await handleCreateOrder(orderReq({ module: 'domain', target: 'example.com', coupon_code: 'LAUNCH20' }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.amount).toBe(79920); // 99900 * 0.8
    expect(lastRazorpayRequestBody.amount).toBe(79920);
    expect(body.coupon).toEqual({ code: 'LAUNCH20', discount_pct: 20 });
  });
});
