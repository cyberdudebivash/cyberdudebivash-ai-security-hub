/* Enterprise discount coupon system (lib/coupons.js) — 2026-07-08 revenue
 * audit, extended to the full enterprise field set (mission-brief Task 2).
 *
 * The live checkout flow (payments.js handleCreateOrder) had zero discount-
 * code support before this work; a `coupon` field existed in one unrelated,
 * effectively-dead checkout path (subscriptionPaywallEngine.js
 * handleSubscriptionCheckout, unreferenced by any live frontend caller) but
 * was destructured and never used.
 *
 * v1 shipped: percentage discounts, expiry, redemption caps, module/plan
 * eligibility, idempotent redemption counting, and admin list/create/disable.
 * v2 (this file) adds: full CRUD (get/update/delete/enable/disable),
 * discountType (percentage/fixed), currency, applicablePlans/Products/Apis,
 * enterpriseOnly, firstPurchaseOnly, maxUsesPerUser, startDate, stackable,
 * minimumPurchase, metadata, a validate-without-checkout endpoint, a
 * redemption audit trail + revocation, and IP-based abuse detection against
 * invalid-coupon guessing. */
import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

// finalizeCouponRedemption fires a (non-awaited) coupon-redeemed confirmation
// email (Task 3 Phase 1) whenever a redemption row has an email — several
// tests below use one. Mock it out so this file never makes a real network
// call to Resend/MailChannels.
vi.mock('../src/services/emailEngine.js', () => ({
  sendCouponRedeemedEmail: vi.fn(async () => ({ success: true, provider: 'mock' })),
}));

import {
  validateCoupon, applyDiscount, computeDiscountedAmount, recordCouponUsage,
  finalizeCouponRedemption, revokeRedemption,
  handleAdminListCoupons, handleAdminGetCoupon, handleAdminCreateCoupon,
  handleAdminUpdateCoupon, handleAdminDeleteCoupon, handleAdminSetCouponActive,
  handleAdminValidateCoupon, handleAdminListRedemptions, handleAdminRevokeRedemption,
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

async function createCoupon(env, overrides = {}) {
  const body = { code: 'TESTCODE', discountType: 'percentage', discountValue: 20, ...overrides };
  const res = await handleAdminCreateCoupon(new Request('https://x', { method: 'POST', body: JSON.stringify(body) }), env, ADMIN);
  return res;
}

describe('validateCoupon', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });

  it('rejects an unknown code', async () => {
    const r = await validateCoupon(env, 'NOPE', { module: 'domain' });
    expect(r.valid).toBe(false);
    expect(r.code).toBe('NOT_FOUND');
  });

  it('accepts a valid, active, unrestricted coupon (lowercase input still matches)', async () => {
    await createCoupon(env, { code: 'LAUNCH20', discountValue: 20 });
    const r = await validateCoupon(env, 'launch20', { module: 'domain' });
    expect(r.valid).toBe(true);
    expect(r.discountValue).toBe(20);
  });

  it('rejects a deactivated coupon', async () => {
    await createCoupon(env, { code: 'OFFCODE' });
    await handleAdminSetCouponActive(new Request('https://x', { method: 'POST' }), env, ADMIN, 'OFFCODE', false);
    const r = await validateCoupon(env, 'OFFCODE', { module: 'domain' });
    expect(r.valid).toBe(false);
    expect(r.code).toBe('INACTIVE');
  });

  it('rejects a coupon that has not started yet', async () => {
    const future = new Date(Date.now() + 86400000).toISOString();
    await createCoupon(env, { code: 'FUTURE', startDate: future });
    const r = await validateCoupon(env, 'FUTURE', { module: 'domain' });
    expect(r.valid).toBe(false);
    expect(r.code).toBe('NOT_STARTED');
  });

  it('rejects an expired coupon', async () => {
    await createCoupon(env, { code: 'OLD', expiryDate: '2020-01-01T00:00:00.000Z' });
    const r = await validateCoupon(env, 'OLD', { module: 'domain' });
    expect(r.valid).toBe(false);
    expect(r.code).toBe('EXPIRED');
  });

  it('rejects a coupon that has hit its total redemption cap', async () => {
    await createCoupon(env, { code: 'CAPPED', maxUses: 1 });
    await env.DB.prepare(`UPDATE discount_coupons SET redeemed_count=1 WHERE code='CAPPED'`).run();
    const r = await validateCoupon(env, 'CAPPED', { module: 'domain' });
    expect(r.valid).toBe(false);
    expect(r.code).toBe('MAX_USES_REACHED');
  });

  it('rejects a coupon restricted to different applicablePlans', async () => {
    await createCoupon(env, { code: 'PROONLY', applicablePlans: ['PRO', 'ENTERPRISE'] });
    const wrong = await validateCoupon(env, 'PROONLY', { module: 'domain' });
    expect(wrong.valid).toBe(false);
    expect(wrong.code).toBe('NOT_APPLICABLE');
    const right = await validateCoupon(env, 'PROONLY', { module: 'subscription', planKey: 'PRO' });
    expect(right.valid).toBe(true);
  });

  it('rejects a coupon restricted to different applicableProducts', async () => {
    await createCoupon(env, { code: 'DOMAINONLY', applicableProducts: ['domain'] });
    expect((await validateCoupon(env, 'DOMAINONLY', { module: 'ai' })).valid).toBe(false);
    expect((await validateCoupon(env, 'DOMAINONLY', { module: 'domain' })).valid).toBe(true);
  });

  it('legacy applies_to field still works for backward compatibility', async () => {
    await createCoupon(env, { code: 'LEGACY', applies_to: 'PRO,ENTERPRISE' });
    expect((await validateCoupon(env, 'LEGACY', { module: 'domain' })).valid).toBe(false);
    expect((await validateCoupon(env, 'LEGACY', { module: 'subscription', planKey: 'ENTERPRISE' })).valid).toBe(true);
  });

  it('enterpriseOnly: rejects non-enterprise context, accepts an Enterprise plan purchase or Enterprise-tier customer', async () => {
    await createCoupon(env, { code: 'ENTONLY', enterpriseOnly: true });
    expect((await validateCoupon(env, 'ENTONLY', { module: 'subscription', planKey: 'PRO' })).valid).toBe(false);
    expect((await validateCoupon(env, 'ENTONLY', { module: 'subscription', planKey: 'ENTERPRISE' })).valid).toBe(true);
    expect((await validateCoupon(env, 'ENTONLY', { module: 'domain', authCtx: { tier: 'ENTERPRISE' } })).valid).toBe(true);
  });

  it('minimumPurchase: rejects a purchase below the threshold', async () => {
    await createCoupon(env, { code: 'MIN500', minimumPurchase: 50000 });
    expect((await validateCoupon(env, 'MIN500', { module: 'domain', amountPaise: 10000 })).valid).toBe(false);
    expect((await validateCoupon(env, 'MIN500', { module: 'domain', amountPaise: 99900 })).valid).toBe(true);
  });

  it('firstPurchaseOnly: rejects an email with a prior paid order', async () => {
    await env.DB.prepare(`CREATE TABLE payments (id TEXT PRIMARY KEY, email TEXT, status TEXT)`).run();
    await env.DB.prepare(`INSERT INTO payments (id, email, status) VALUES ('p1','repeat@x.com','paid')`).run();
    await createCoupon(env, { code: 'NEWONLY', firstPurchaseOnly: true });
    expect((await validateCoupon(env, 'NEWONLY', { module: 'domain', email: 'repeat@x.com' })).valid).toBe(false);
    expect((await validateCoupon(env, 'NEWONLY', { module: 'domain', email: 'fresh@x.com' })).valid).toBe(true);
  });

  it('maxUsesPerUser: rejects once an email has redeemed the cap, allows a different email', async () => {
    await createCoupon(env, { code: 'ONCE', maxUsesPerUser: 1 });
    await recordCouponUsage(env, { razorpayOrderId: 'o1', code: 'ONCE', email: 'a@x.com', originalAmount: 1000, discountedAmount: 800 });
    await finalizeCouponRedemption(env, 'o1');
    expect((await validateCoupon(env, 'ONCE', { module: 'domain', email: 'a@x.com' })).valid).toBe(false);
    expect((await validateCoupon(env, 'ONCE', { module: 'domain', email: 'b@x.com' })).valid).toBe(true);
  });

  it('finalizeCouponRedemption sends a redemption confirmation email when the redemption has an email on file (Task 3 Phase 1)', async () => {
    const { sendCouponRedeemedEmail } = await import('../src/services/emailEngine.js');
    vi.mocked(sendCouponRedeemedEmail).mockClear();
    await createCoupon(env, { code: 'MAILME', discountType: 'percentage', discountValue: 30 });
    await recordCouponUsage(env, { razorpayOrderId: 'o_mail', code: 'MAILME', email: 'mailme@x.com', module: 'subscription', originalAmount: 1000, discountedAmount: 700 });
    await finalizeCouponRedemption(env, 'o_mail');
    expect(sendCouponRedeemedEmail).toHaveBeenCalledTimes(1);
    const [, args] = sendCouponRedeemedEmail.mock.calls[0];
    expect(args.to).toBe('mailme@x.com');
    expect(args.code).toBe('MAILME');
    expect(args.discountLabel).toBe('30% off');
    expect(args.finalAmountInr).toBe(7);
  });

  it('finalizeCouponRedemption does not attempt to email when the redemption has no email on file', async () => {
    const { sendCouponRedeemedEmail } = await import('../src/services/emailEngine.js');
    vi.mocked(sendCouponRedeemedEmail).mockClear();
    await createCoupon(env, { code: 'NOMAIL' });
    await recordCouponUsage(env, { razorpayOrderId: 'o_nomail', code: 'NOMAIL', originalAmount: 1000, discountedAmount: 800 });
    await finalizeCouponRedemption(env, 'o_nomail');
    expect(sendCouponRedeemedEmail).not.toHaveBeenCalled();
  });

  it('IP abuse detection: blocks after repeated invalid-coupon attempts from the same IP', async () => {
    const kv = new Map();
    env.SECURITY_HUB_KV = {
      get: async (k) => kv.get(k) ?? null,
      put: async (k, v) => { kv.set(k, v); },
    };
    for (let i = 0; i < 10; i++) {
      await validateCoupon(env, 'GUESS' + i, { module: 'domain', ip: '1.2.3.4' });
    }
    const blocked = await validateCoupon(env, 'ANOTHERGUESS', { module: 'domain', ip: '1.2.3.4' });
    expect(blocked.valid).toBe(false);
    expect(blocked.code).toBe('RATE_LIMITED');
    // A different IP is unaffected
    const other = await validateCoupon(env, 'GUESS0', { module: 'domain', ip: '5.6.7.8' });
    expect(other.code).toBe('NOT_FOUND'); // still invalid (code doesn't exist) but NOT rate-limited
  });
});

describe('discount math', () => {
  it('applyDiscount computes percentage discounts and clamps out-of-range values', () => {
    expect(applyDiscount(100000, 20)).toBe(80000);
    expect(applyDiscount(100000, 0)).toBe(100000);
    expect(applyDiscount(100000, 100)).toBe(0);
    expect(applyDiscount(100000, 150)).toBe(0);
    expect(applyDiscount(100000, -10)).toBe(100000);
  });

  it('computeDiscountedAmount handles percentage type', () => {
    expect(computeDiscountedAmount(100000, { discountType: 'percentage', discountValue: 25 })).toBe(75000);
  });

  it('computeDiscountedAmount handles fixed type (paise off, floored at zero)', () => {
    expect(computeDiscountedAmount(100000, { discountType: 'fixed', discountValue: 30000 })).toBe(70000);
    expect(computeDiscountedAmount(10000, { discountType: 'fixed', discountValue: 50000 })).toBe(0);
  });
});

describe('redemption counting is idempotent and supports revocation', () => {
  let env;
  beforeEach(async () => {
    env = { DB: makeRealD1() };
    await createCoupon(env, { code: 'ONECODE', discountValue: 10 });
    await recordCouponUsage(env, {
      razorpayOrderId: 'order_1', code: 'ONECODE', module: 'domain',
      originalAmount: 99900, discountedAmount: 89910, email: 'x@y.com',
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

  it('revoking a redemption (e.g. after a refund) decrements the counter and cannot be revoked twice', async () => {
    await finalizeCouponRedemption(env, 'order_1');
    const r1 = await revokeRedemption(env, 'order_1', 'refunded');
    expect(r1.revoked).toBe(true);
    const coupon = await env.DB.prepare(`SELECT redeemed_count FROM discount_coupons WHERE code='ONECODE'`).first();
    expect(coupon.redeemed_count).toBe(0);
    const r2 = await revokeRedemption(env, 'order_1', 'refunded again');
    expect(r2.revoked).toBe(false);
  });

  it('a revoked redemption no longer counts toward maxUsesPerUser', async () => {
    await createCoupon(env, { code: 'PERUSER', maxUsesPerUser: 1 });
    await recordCouponUsage(env, { razorpayOrderId: 'order_2', code: 'PERUSER', email: 'z@x.com', originalAmount: 1000, discountedAmount: 800 });
    await finalizeCouponRedemption(env, 'order_2');
    expect((await validateCoupon(env, 'PERUSER', { module: 'domain', email: 'z@x.com' })).valid).toBe(false);
    await revokeRedemption(env, 'order_2', 'refunded');
    expect((await validateCoupon(env, 'PERUSER', { module: 'domain', email: 'z@x.com' })).valid).toBe(true);
  });
});

describe('admin coupon endpoints — full CRUD', () => {
  let env;
  beforeEach(() => { env = { DB: makeRealD1() }; });

  it('rejects a non-admin caller on every endpoint', async () => {
    expect((await handleAdminCreateCoupon(new Request('https://x', { method: 'POST', body: '{}' }), env, NON_ADMIN)).status).toBe(403);
    expect((await handleAdminListCoupons(new Request('https://x'), env, NON_ADMIN)).status).toBe(403);
    expect((await handleAdminGetCoupon(new Request('https://x'), env, NON_ADMIN, 'X')).status).toBe(403);
    expect((await handleAdminUpdateCoupon(new Request('https://x', { method: 'PUT', body: '{}' }), env, NON_ADMIN, 'X')).status).toBe(403);
    expect((await handleAdminDeleteCoupon(new Request('https://x', { method: 'DELETE' }), env, NON_ADMIN, 'X')).status).toBe(403);
    expect((await handleAdminSetCouponActive(new Request('https://x', { method: 'POST' }), env, NON_ADMIN, 'X', false)).status).toBe(403);
    expect((await handleAdminListRedemptions(new Request('https://x'), env, NON_ADMIN, 'X')).status).toBe(403);
    expect((await handleAdminRevokeRedemption(new Request('https://x', { method: 'POST', body: '{}' }), env, NON_ADMIN, 'o1')).status).toBe(403);
  });

  it('create -> get -> list -> update -> disable -> enable -> delete round-trip', async () => {
    const create = await createCoupon(env, { code: 'ROUNDTRIP', description: 'Test coupon', discountValue: 15 });
    expect(create.status).toBe(200);
    const created = (await create.json()).data.coupon;
    expect(created.id).toBe('ROUNDTRIP');
    expect(created.code).toBe('ROUNDTRIP');
    expect(created.discountValue).toBe(15);

    const got = await handleAdminGetCoupon(new Request('https://x'), env, ADMIN, 'roundtrip');
    expect(got.status).toBe(200);

    const list = await handleAdminListCoupons(new Request('https://x'), env, ADMIN);
    const listBody = await list.json();
    expect(listBody.data.coupons.some(c => c.code === 'ROUNDTRIP')).toBe(true);

    const updated = await handleAdminUpdateCoupon(new Request('https://x', {
      method: 'PUT', body: JSON.stringify({ discountValue: 30, description: 'Updated' }),
    }), env, ADMIN, 'ROUNDTRIP');
    expect(updated.status).toBe(200);
    const updatedBody = (await updated.json()).data.coupon;
    expect(updatedBody.discountValue).toBe(30);
    expect(updatedBody.description).toBe('Updated');

    const disabled = await handleAdminSetCouponActive(new Request('https://x', { method: 'POST' }), env, ADMIN, 'ROUNDTRIP', false);
    expect(disabled.status).toBe(200);
    expect((await validateCoupon(env, 'ROUNDTRIP', { module: 'domain' })).valid).toBe(false);

    const enabled = await handleAdminSetCouponActive(new Request('https://x', { method: 'POST' }), env, ADMIN, 'ROUNDTRIP', true);
    expect(enabled.status).toBe(200);
    expect((await validateCoupon(env, 'ROUNDTRIP', { module: 'domain' })).valid).toBe(true);

    const deleted = await handleAdminDeleteCoupon(new Request('https://x', { method: 'DELETE' }), env, ADMIN, 'ROUNDTRIP');
    expect(deleted.status).toBe(200);
    expect((await handleAdminGetCoupon(new Request('https://x'), env, ADMIN, 'ROUNDTRIP')).status).toBe(404);
  });

  it('refuses to delete a coupon with redemption history (use disable instead)', async () => {
    await createCoupon(env, { code: 'USED' });
    await recordCouponUsage(env, { razorpayOrderId: 'o1', code: 'USED', originalAmount: 1000, discountedAmount: 800 });
    await finalizeCouponRedemption(env, 'o1');
    const del = await handleAdminDeleteCoupon(new Request('https://x', { method: 'DELETE' }), env, ADMIN, 'USED');
    expect(del.status).toBe(409);
    // Disable still works as the reversible alternative
    expect((await handleAdminSetCouponActive(new Request('https://x', { method: 'POST' }), env, ADMIN, 'USED', false)).status).toBe(200);
  });

  it('rejects a malformed code or out-of-range discountValue', async () => {
    expect((await createCoupon(env, { code: 'a b!' })).status).toBe(400);
    expect((await createCoupon(env, { code: 'VALIDCODE', discountValue: 150 })).status).toBe(400);
    expect((await createCoupon(env, { code: 'BADTYPE', discountType: 'not-a-real-type' })).status).toBe(400);
  });

  it('GET/PUT/DELETE on a nonexistent coupon return 404', async () => {
    expect((await handleAdminGetCoupon(new Request('https://x'), env, ADMIN, 'GHOST')).status).toBe(404);
    expect((await handleAdminUpdateCoupon(new Request('https://x', { method: 'PUT', body: '{}' }), env, ADMIN, 'GHOST')).status).toBe(404);
    expect((await handleAdminDeleteCoupon(new Request('https://x', { method: 'DELETE' }), env, ADMIN, 'GHOST')).status).toBe(404);
    expect((await handleAdminSetCouponActive(new Request('https://x', { method: 'POST' }), env, ADMIN, 'GHOST', false)).status).toBe(404);
  });

  it('validate endpoint previews a coupon without creating a real order', async () => {
    await createCoupon(env, { code: 'PREVIEW', discountValue: 40 });
    const res = await handleAdminValidateCoupon(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ code: 'PREVIEW', module: 'domain' }),
    }), env, {});
    const body = await res.json();
    expect(body.data.valid).toBe(true);
    expect(body.data.discountValue).toBe(40);
  });

  it('redemption history + revoke are reachable via the admin API', async () => {
    await createCoupon(env, { code: 'AUDITME' });
    await recordCouponUsage(env, { razorpayOrderId: 'o1', code: 'AUDITME', email: 'aud@x.com', originalAmount: 1000, discountedAmount: 800 });
    await finalizeCouponRedemption(env, 'o1');

    const list = await handleAdminListRedemptions(new Request('https://x'), env, ADMIN, 'AUDITME');
    const listBody = await list.json();
    expect(listBody.data.redemptions).toHaveLength(1);
    expect(listBody.data.redemptions[0].email).toBe('aud@x.com');

    const revoke = await handleAdminRevokeRedemption(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ reason: 'customer refund' }),
    }), env, ADMIN, 'o1');
    expect(revoke.status).toBe(200);
    const coupon = await env.DB.prepare(`SELECT redeemed_count FROM discount_coupons WHERE code='AUDITME'`).first();
    expect(coupon.redeemed_count).toBe(0);
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

  // Real SQLite-backed DB: a coupon created via the admin endpoint must
  // actually be visible to validateCoupon() inside the subsequent
  // handleCreateOrder call. handleCreateOrder's own payments-table
  // reads/writes are all .catch()-wrapped and degrade gracefully without
  // that table existing, so only discount_coupons/coupon_redemptions need
  // to be real for these tests.
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

  it('with a valid percentage coupon: Razorpay order + response both reflect the discounted amount', async () => {
    const env = fakeEnv();
    await createCoupon(env, { code: 'LAUNCH20', discountType: 'percentage', discountValue: 20 });

    const res  = await handleCreateOrder(orderReq({ module: 'domain', target: 'example.com', coupon_code: 'LAUNCH20' }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.amount).toBe(79920); // 99900 * 0.8
    expect(lastRazorpayRequestBody.amount).toBe(79920);
    expect(body.coupon).toEqual({ code: 'LAUNCH20', discount_type: 'percentage', discount_pct: 20 });
  });

  it('with a valid fixed-amount coupon: charges original price minus the fixed amount', async () => {
    const env = fakeEnv();
    await createCoupon(env, { code: 'FLAT200', discountType: 'fixed', discountValue: 20000 }); // ₹200 off

    const res = await handleCreateOrder(orderReq({ module: 'domain', target: 'example.com', coupon_code: 'FLAT200' }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.amount).toBe(79900); // 99900 - 20000
  });

  it('enterpriseOnly coupon is rejected for a non-enterprise subscription purchase', async () => {
    const env = fakeEnv();
    await createCoupon(env, { code: 'ENTONLY', enterpriseOnly: true, applicablePlans: ['ENTERPRISE'] });
    const res = await handleCreateOrder(orderReq({ module: 'subscription', plan: 'PRO', target: 'pro', coupon_code: 'ENTONLY' }), env, {});
    expect(res.status).toBe(400);
  });

  it('minimumPurchase coupon is rejected below the threshold', async () => {
    const env = fakeEnv();
    await createCoupon(env, { code: 'MIN2000', minimumPurchase: 200000 }); // needs a >=₹2000 base order
    const res = await handleCreateOrder(orderReq({ module: 'domain', target: 'example.com', coupon_code: 'MIN2000' }), env, {}); // domain is ₹999
    expect(res.status).toBe(400);
  });
});
