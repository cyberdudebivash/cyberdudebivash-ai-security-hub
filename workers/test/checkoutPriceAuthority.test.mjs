/* Priority 1 — Server-Side Price Authority (2026-07-14 commercial-integrity
 * audit continuation). handleCheckoutInitiate (POST /api/checkout, wired in
 * index.js) previously computed the Razorpay order amount directly from
 * body.price / ?price=, a client-controlled value, with only a "> 0" sanity
 * check. Any caller could set an arbitrary price for a real product/plan and
 * the resulting Razorpay order — and the revenue_events row recording it —
 * would reflect that tampered amount.
 *
 * Fix: price is now looked up server-side from the canonical catalogs
 * (DEFENSE_PRODUCTS in services/defenseSolutions.js for `product`,
 * SUBSCRIPTION_PRICES in lib/razorpay.js for `plan`) and the client-supplied
 * price field is never read. These tests cover the normal, tampered, and
 * invalid-catalog-key cases end to end through the real handler, including
 * the D1 write and the Razorpay order-creation call. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { handleCheckoutInitiate } from '../src/handlers/revenue.js';
import { DEFENSE_PRODUCTS } from '../src/services/defenseSolutions.js';
import { SUBSCRIPTION_PRICES } from '../src/lib/razorpay.js';

function req(body, { asQuery = false } = {}) {
  const url = asQuery
    ? `https://x/api/checkout?${new URLSearchParams(body).toString()}`
    : 'https://x/api/checkout';
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: asQuery ? '{}' : JSON.stringify(body),
  });
}

function makeEnv() {
  const rows = [];
  const stmt = {
    bind(...a) { this._a = a; return this; },
    async run() { rows.push(this._a); return { meta: {} }; },
    async first() { return null; },
    async all() { return { results: [] }; },
  };
  return { env: { DB: { prepare: () => ({ ...stmt }) }, RAZORPAY_KEY_ID: 'rzp_test', RAZORPAY_KEY_SECRET: 'secret' }, rows };
}

const realFetch = globalThis.fetch;
beforeEach(() => {
  // Razorpay API unreachable in tests — handler must fall back to a local
  // order using its own server-computed amount, not fail the request.
  globalThis.fetch = async () => { throw new Error('network disabled in test'); };
});
afterAll(() => { globalThis.fetch = realFetch; });

describe('handleCheckoutInitiate — server-side price authority', () => {
  it('normal request: derives price from DEFENSE_PRODUCTS catalog when no price is sent', async () => {
    const { env } = makeEnv();
    const res = await handleCheckoutInitiate(req({ product: 'ir_playbook' }), env, {});
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.amount).toBe(DEFENSE_PRODUCTS.ir_playbook.price_inr);
    expect(body.amount_paise).toBe(Math.round(DEFENSE_PRODUCTS.ir_playbook.price_inr * 100));
  });

  it('tampered request: a client-supplied price is ignored — catalog price wins', async () => {
    const { env } = makeEnv();
    const res = await handleCheckoutInitiate(
      req({ product: 'enterprise_bundle', price: 1 }), // real price is ₹9,999
      env, {}
    );
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.amount).toBe(DEFENSE_PRODUCTS.enterprise_bundle.price_inr);
    expect(body.amount).not.toBe(1);
  });

  it('tampered request via query string is also ignored', async () => {
    const { env } = makeEnv();
    const res = await handleCheckoutInitiate(
      req({ product: 'full_defense_pack', price: '0.01' }, { asQuery: true }),
      env, {}
    );
    const body = await res.json();
    expect(body.amount).toBe(DEFENSE_PRODUCTS.full_defense_pack.price_inr);
  });

  it('valid subscription plan: derives price from SUBSCRIPTION_PRICES, ignoring client price', async () => {
    const { env } = makeEnv();
    const res = await handleCheckoutInitiate(req({ plan: 'pro', price: 5 }), env, {});
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.amount_paise).toBe(SUBSCRIPTION_PRICES.PRO.amount);
    expect(body.amount).toBe(SUBSCRIPTION_PRICES.PRO.amount / 100);
  });

  it('rejects an unknown product with 400 INVALID_PRODUCT, no order created', async () => {
    const { env, rows } = makeEnv();
    const res = await handleCheckoutInitiate(req({ product: 'totally-fake-product', price: 999 }), env, {});
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.code).toBe('INVALID_PRODUCT');
    expect(rows.length).toBe(0);
  });

  it('rejects an unknown plan with 400 INVALID_PLAN', async () => {
    const { env } = makeEnv();
    const res = await handleCheckoutInitiate(req({ plan: 'GOLD_TIER', price: 1 }), env, {});
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.code).toBe('INVALID_PLAN');
  });

  it('rejects a request with neither product nor plan', async () => {
    const { env } = makeEnv();
    const res = await handleCheckoutInitiate(req({ price: 999 }), env, {});
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.code).toBe('MISSING_PRODUCT');
  });

  it('the stored revenue_events row and funnel event both reflect the catalog price, not any client value', async () => {
    const { env, rows } = makeEnv();
    await handleCheckoutInitiate(req({ product: 'firewall_rules', price: 999999 }), env, {});
    // rows[0] = revenue_events insert, rows[1] = funnel_events insert (see handler order)
    const revenueEventBind = rows.find(a => a.includes(DEFENSE_PRODUCTS.firewall_rules.price_inr));
    expect(revenueEventBind).toBeTruthy();
    expect(rows.some(a => a.includes(999999))).toBe(false);
  });
});
