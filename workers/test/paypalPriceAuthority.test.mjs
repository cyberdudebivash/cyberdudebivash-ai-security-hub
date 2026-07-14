/* Priority 4 — PayPal price validation (2026-07-14 commercial-integrity audit
 * continuation). POST /api/v24/billing/paypal/create (v24Handler.js) computed
 * the PayPal order amount directly from body.amount_usd, a client-controlled
 * value — body.plan_id was accepted but never looked up against any pricing
 * catalog, so a caller could request any plan label while paying (and being
 * charged) whatever amount they chose.
 *
 * Fix: amountUSD is now derived exclusively from SUBSCRIPTION_TIERS
 * (handlers/subscriptionPaywallEngine.js — the same canonical tier catalog
 * used for Razorpay subscription checkout) via plan_id, ignoring
 * body.amount_usd entirely. These tests drive the real handler end to end,
 * stubbing only the outbound PayPal HTTP calls. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { handleV24 } from '../src/handlers/v24Handler.js';
import { SUBSCRIPTION_TIERS } from '../src/handlers/subscriptionPaywallEngine.js';

function req(body) {
  return new Request('https://x/api/v24/billing/paypal/create', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

const ENV = { PAYPAL_CLIENT_ID: 'client_test', PAYPAL_CLIENT_SECRET: 'secret_test', DB: null };

const realFetch = globalThis.fetch;
let capturedOrderBody = null;

beforeEach(() => {
  capturedOrderBody = null;
  globalThis.fetch = async (url, opts) => {
    if (String(url).includes('/v1/oauth2/token')) {
      return new Response(JSON.stringify({ access_token: 'tok_test' }), { status: 200 });
    }
    if (String(url).includes('/v2/checkout/orders')) {
      capturedOrderBody = JSON.parse(opts.body);
      return new Response(JSON.stringify({
        id: 'order_abc',
        links: [{ rel: 'approve', href: 'https://paypal.test/approve/order_abc' }],
      }), { status: 200 });
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
});
afterAll(() => { globalThis.fetch = realFetch; });

describe('POST /api/v24/billing/paypal/create — server-side price authority', () => {
  it('derives the PayPal order amount from SUBSCRIPTION_TIERS, ignoring a tampered amount_usd', async () => {
    const res = await handleV24(
      req({ plan_id: 'PROFESSIONAL', amount_usd: 0.01, email: 'buyer@example.com' }),
      ENV, {}, '/api/v24/billing/paypal/create', 'POST'
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(capturedOrderBody.purchase_units[0].amount.value).toBe(SUBSCRIPTION_TIERS.PROFESSIONAL.price_usd.toFixed(2));
    expect(capturedOrderBody.purchase_units[0].amount.value).not.toBe('0.01');
  });

  it('resolves a legacy plan alias (STARTER -> PROFESSIONAL) to the same catalog price', async () => {
    const res = await handleV24(
      req({ plan_id: 'STARTER', amount_usd: 999999 }),
      ENV, {}, '/api/v24/billing/paypal/create', 'POST'
    );
    expect(res.status).toBe(200);
    expect(capturedOrderBody.purchase_units[0].amount.value).toBe(SUBSCRIPTION_TIERS.PROFESSIONAL.price_usd.toFixed(2));
  });

  it('rejects a free/community plan_id — no PayPal order is created', async () => {
    const res = await handleV24(
      req({ plan_id: 'COMMUNITY', amount_usd: 50 }),
      ENV, {}, '/api/v24/billing/paypal/create', 'POST'
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.code).toBe('INVALID_PLAN');
    expect(capturedOrderBody).toBeNull();
  });

  it('rejects a request with no plan_id at all', async () => {
    const res = await handleV24(req({ amount_usd: 60 }), ENV, {}, '/api/v24/billing/paypal/create', 'POST');
    expect(res.status).toBe(400);
    expect(capturedOrderBody).toBeNull();
  });

  it('a higher tier (ENTERPRISE) resolves to its own distinct catalog price', async () => {
    const res = await handleV24(
      req({ plan_id: 'ENTERPRISE', amount_usd: 1 }),
      ENV, {}, '/api/v24/billing/paypal/create', 'POST'
    );
    expect(res.status).toBe(200);
    expect(capturedOrderBody.purchase_units[0].amount.value).toBe(SUBSCRIPTION_TIERS.ENTERPRISE.price_usd.toFixed(2));
    expect(capturedOrderBody.purchase_units[0].amount.value).not.toBe('1.00');
  });
});
