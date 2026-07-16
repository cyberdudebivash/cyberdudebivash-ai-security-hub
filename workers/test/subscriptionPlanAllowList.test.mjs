/* H8 — Subscription Plan Validation (2026-07-14 Production Release Gate Phase II).
 *
 * handleCreateOrder's module:'subscription' branch computed price as
 * `SUBSCRIPTION_PRICES[planKey] || SUBSCRIPTION_PRICES['STARTER']` — an
 * unrecognized or missing plan silently fell back to STARTER pricing while
 * the RAW (unvalidated) plan string was still stored on the payments row
 * (`plan` column). That stored value is later read back as authoritative by
 * handleVerifyPayment (payment/plan-tampering fix) and checked against an
 * exact-match allow-list — GRANTABLE_SUBSCRIPTION_PLANS, previously an
 * inline literal duplicated in three places — before granting a tier. Any
 * plan string outside that allow-list (a typo, a stale/renamed frontend
 * value, or direct API abuse) meant: Razorpay genuinely charges the
 * customer, `payments.status` gets marked 'paid', a `subscriptions` row is
 * created — but users.tier is never updated and no access token is ever
 * issued. Charged, zero entitlement, no error surfaced anywhere.
 *
 * Root cause chain (confirmed by direct code trace):
 *   1. handleCreateOrder: `(body.plan || target || 'STARTER').toUpperCase()`
 *      + `SUBSCRIPTION_PRICES[planKey] || SUBSCRIPTION_PRICES['STARTER']`
 *      — silent coercion to STARTER pricing for any unrecognized plan.
 *   2. The raw (uncorrected) plan string is what gets stored as
 *      `payments.plan` (`planLabel`), not the corrected/fallback price key.
 *   3. handleVerifyPayment's tier-grant step and the Razorpay webhook's
 *      fallback grant both gate on an EXACT match against
 *      ['STARTER','PRO','ENTERPRISE','MSSP'] — any other stored value
 *      silently skips the entire grant block while the payment is still
 *      marked 'paid'.
 *
 * Fix: handleCreateOrder now rejects any module:'subscription' request
 * whose plan isn't in GRANTABLE_SUBSCRIPTION_PLANS *before* creating any
 * Razorpay order — no silent coercion, no unfulfillable charge.
 * ENTERPRISE_SOC (a real SUBSCRIPTION_PRICES entry, priced but never
 * actually granted a tier anywhere — see mssPartnerSkuRemoved.test.mjs) is
 * deliberately excluded from what self-serve checkout can charge for, since
 * self-serve checkout has no way to fulfill it today.
 *
 * handleVerifyPayment also gets a defense-in-depth guard for the same
 * allow-list, covering the edge case where no D1 payments row exists for a
 * given order_id (the authoritative-order-lookup only overrides
 * client-resent values when a row is found).
 */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleCreateOrder, handleVerifyPayment } from '../src/handlers/payments.js';
import { SUBSCRIPTION_PRICES } from '../src/lib/razorpay.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all() { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run() { const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return {
    _sqlite: sqlite,
    prepare: wrap,
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
}

function makeEnv() {
  const db = makeRealD1();
  db._sqlite.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'FREE',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE payments (
      id TEXT PRIMARY KEY, user_id TEXT, scan_id TEXT, module TEXT NOT NULL, target TEXT NOT NULL,
      amount INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT 'INR',
      razorpay_order_id TEXT UNIQUE, razorpay_payment_id TEXT, razorpay_signature TEXT,
      status TEXT NOT NULL DEFAULT 'pending', plan TEXT NOT NULL DEFAULT 'pay_per_report',
      report_token TEXT, ip TEXT, email TEXT, partner_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), paid_at TEXT
    );
    CREATE TABLE subscriptions (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'FREE', status TEXT NOT NULL DEFAULT 'active',
      price_inr INTEGER NOT NULL DEFAULT 0, billing_cycle TEXT NOT NULL DEFAULT 'monthly',
      current_period_start TEXT NOT NULL DEFAULT (datetime('now')),
      current_period_end TEXT NOT NULL DEFAULT (datetime('now')),
      razorpay_sub_id TEXT, payment_method TEXT DEFAULT 'razorpay',
      utm_source TEXT, utm_campaign TEXT, created_at TEXT, updated_at TEXT
    );
    CREATE TABLE refresh_tokens (
      id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), revoked INTEGER NOT NULL DEFAULT 0,
      ip_address TEXT, user_agent TEXT
    );
  `);
  return {
    RAZORPAY_KEY_ID: 'rzp_test_key',
    RAZORPAY_KEY_SECRET,
    JWT_SECRET: 'jwt_test_secret',
    DB: db,
    SECURITY_HUB_KV: { async put() {}, async get() { return null; } },
  };
}

function createReq(body) {
  return new Request('https://x/api/payments/create-order', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}
function verifyReq(body) {
  return new Request('https://x/api/payments/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

const realFetch = globalThis.fetch;
let lastRazorpayBody = null;
beforeEach(() => {
  lastRazorpayBody = null;
  globalThis.fetch = async (url, opts) => {
    if (new URL(String(url)).hostname === 'api.razorpay.com') {
      lastRazorpayBody = JSON.parse(opts.body);
      return new Response(JSON.stringify({ id: 'order_stub_123', amount: lastRazorpayBody.amount, currency: 'INR', status: 'created' }), { status: 200 });
    }
    return realFetch(url, opts);
  };
});
afterAll(() => { globalThis.fetch = realFetch; });

describe('handleCreateOrder — subscription plan allow-list (H8)', () => {
  it('accepts a valid plan and charges exactly the catalog price', async () => {
    const env = makeEnv();
    const res = await handleCreateOrder(createReq({ module: 'subscription', plan: 'PRO', target: 'buyer@corp.com', email: 'buyer@corp.com' }), env, {});
    expect(res.status).toBe(200);
    expect(lastRazorpayBody.amount).toBe(SUBSCRIPTION_PRICES.PRO.amount);
    const row = env.DB._sqlite.prepare(`SELECT plan, amount FROM payments WHERE razorpay_order_id = 'order_stub_123'`).get();
    expect(row.plan).toBe('PRO');
    expect(row.amount).toBe(SUBSCRIPTION_PRICES.PRO.amount);
  });

  it('rejects an unrecognized plan with 400, no Razorpay order created, no payments row written', async () => {
    const env = makeEnv();
    const res = await handleCreateOrder(createReq({ module: 'subscription', plan: 'GARBAGE_TIER', target: 'buyer@corp.com' }), env, {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/Invalid plan/i);
    expect(lastRazorpayBody).toBeNull();
    const rows = env.DB._sqlite.prepare(`SELECT * FROM payments`).all();
    expect(rows.length).toBe(0);
  });

  it('rejects a missing plan — no silent default to STARTER', async () => {
    const env = makeEnv();
    const res = await handleCreateOrder(createReq({ module: 'subscription', target: 'buyer@corp.com' }), env, {});
    expect(res.status).toBe(400);
    expect(lastRazorpayBody).toBeNull();
  });

  it('rejects ENTERPRISE_SOC — priced in the catalog but not fulfillable by self-serve checkout', async () => {
    const env = makeEnv();
    expect(SUBSCRIPTION_PRICES.ENTERPRISE_SOC).toBeDefined(); // still a real catalog entry
    const res = await handleCreateOrder(createReq({ module: 'subscription', plan: 'ENTERPRISE_SOC', target: 'buyer@corp.com' }), env, {});
    expect(res.status).toBe(400);
    expect(lastRazorpayBody).toBeNull();
  });

  it('is case-insensitive for a valid plan (lowercase still matches)', async () => {
    const env = makeEnv();
    const res = await handleCreateOrder(createReq({ module: 'subscription', plan: 'starter', target: 'buyer@corp.com' }), env, {});
    expect(res.status).toBe(200);
    expect(lastRazorpayBody.amount).toBe(SUBSCRIPTION_PRICES.STARTER.amount);
  });

  it('rejects a coupon-carrying request for an invalid plan before any coupon lookup happens', async () => {
    const env = makeEnv();
    const res = await handleCreateOrder(createReq({ module: 'subscription', plan: 'NOT_A_PLAN', target: 'buyer@corp.com', coupon_code: 'ANY' }), env, {});
    expect(res.status).toBe(400);
    expect(lastRazorpayBody).toBeNull();
  });
});

describe('handleVerifyPayment — subscription plan allow-list defense in depth', () => {
  it('rejects verify for an invalid plan when no matching payments row exists (order not created via the now-fixed handleCreateOrder)', async () => {
    const env = makeEnv();
    const orderId = 'order_orphan001', paymentId = 'pay_orphan001';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(verifyReq({
      razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature,
      module: 'subscription', plan: 'GARBAGE_TIER', target: 'x@corp.com', email: 'x@corp.com',
    }), env, {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.code).toBe('INVALID_PLAN');
    const user = env.DB._sqlite.prepare(`SELECT * FROM users WHERE email = 'x@corp.com'`).get();
    expect(user).toBeUndefined(); // no account created, no entitlement granted
  });

  it('a genuinely valid plan still verifies and grants normally (no regression)', async () => {
    const env = makeEnv();
    const orderId = 'order_valid001', paymentId = 'pay_valid001';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(verifyReq({
      razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature,
      module: 'subscription', plan: 'ENTERPRISE', target: 'y@corp.com', email: 'y@corp.com',
    }), env, {});
    expect(res.status).toBe(200);
    const user = env.DB._sqlite.prepare(`SELECT tier FROM users WHERE email = 'y@corp.com'`).get();
    expect(user.tier).toBe('ENTERPRISE');
  });
});

describe('handleVerifyPayment — invalid user_id fallback (subscriptions.user_id NOT NULL, previously fell back to email/\'anon\')', () => {
  it('does not write a subscriptions row at all when no email is resolvable — payment still verifies, no bogus user_id row', async () => {
    // Root cause of the original bug: when confirmedEmail is null the tier
    // grant step never runs, so issuedUserId stays null. The old code then
    // fell back to `issuedUserId || confirmedEmail || 'anon'` for
    // subscriptions.user_id — writing a value that can never match a real
    // users.id, so enforceSubscriptionExpiry's later downgrade silently
    // matched zero rows against it forever. The fix: skip the subscriptions
    // INSERT entirely (loud gap, not a silently-corrupt row) whenever
    // issuedUserId couldn't be resolved.
    const env = makeEnv();
    const orderId = 'order_noemail001', paymentId = 'pay_noemail001';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(verifyReq({
      razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature,
      module: 'subscription', plan: 'PRO', target: 'anon-checkout',
      // deliberately no `email`, and authCtx below has none either
    }), env, {});
    expect(res.status).toBe(200);

    const subs = env.DB._sqlite.prepare(`SELECT * FROM subscriptions`).all();
    for (const row of subs) {
      expect(row.user_id).not.toBe('anon');
      expect(row.user_id).not.toBe('');
    }
    expect(subs.length).toBe(0); // no unresolvable-user_id row written at all
  });

  it('a resolvable user still gets a real user_id on the subscriptions row (no regression)', async () => {
    const env = makeEnv();
    const orderId = 'order_realid001', paymentId = 'pay_realid001';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(verifyReq({
      razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature,
      module: 'subscription', plan: 'PRO', target: 'realuser@corp.com', email: 'realuser@corp.com',
    }), env, {});
    expect(res.status).toBe(200);

    const user = env.DB._sqlite.prepare(`SELECT id, tier FROM users WHERE email = 'realuser@corp.com'`).get();
    expect(user.tier).toBe('PRO');
    const sub = env.DB._sqlite.prepare(`SELECT user_id FROM subscriptions WHERE email = 'realuser@corp.com'`).get();
    expect(sub.user_id).toBe(user.id);
  });
});
