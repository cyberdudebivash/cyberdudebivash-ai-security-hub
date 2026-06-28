/* Regression tests — P21.0 Marketplace Checkout Engine had zero test coverage
 * despite handling real money. Covers the two things that matter most for a
 * revenue path: (1) server-side pricing can't be overridden by the client,
 * and (2) payment verification only provisions access on a valid signature,
 * and is idempotent on retry. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import {
  handleMarketplaceCatalog,
  handleMarketplaceProduct,
  handleMarketplaceCheckout,
  handleMarketplaceVerify,
  handleMyMarketplacePurchases,
  MARKETPLACE_CATALOG,
} from '../src/handlers/marketplaceCheckoutHandler.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv(seedPurchases = []) {
  const purchases = new Map(seedPurchases.map(p => [p.razorpay_order_id, { ...p }]));
  const kvStore = new Map();
  const env = {
    RAZORPAY_KEY_ID: 'rzp_test_key',
    RAZORPAY_KEY_SECRET,
    DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async first() {
            if (/SELECT id, razorpay_order_id FROM marketplace_purchases/.test(sql)) {
              return null; // no existing pending order by default
            }
            if (/SELECT \* FROM marketplace_purchases WHERE razorpay_order_id/.test(sql)) {
              return purchases.get(bound[0]) || null;
            }
            return null;
          },
          async run() {
            if (/CREATE TABLE/.test(sql)) return { success: true };
            if (/INSERT INTO marketplace_purchases/.test(sql)) {
              const [id, user_id, product_id, product_name, category, amount, currency, razorpay_order_id, buyer_email, buyer_name] = bound;
              purchases.set(razorpay_order_id, {
                id, user_id, product_id, product_name, category, amount, currency,
                razorpay_order_id, buyer_email, buyer_name, status: 'pending',
              });
              return { success: true };
            }
            if (/UPDATE marketplace_purchases[\s\S]*status='paid'/.test(sql)) {
              const [razorpay_payment_id, access_token, access_expires_at, id] = bound;
              for (const p of purchases.values()) {
                if (p.id === id) {
                  p.status = 'paid'; p.razorpay_payment_id = razorpay_payment_id;
                  p.access_token = access_token; p.access_expires_at = access_expires_at;
                }
              }
              return { success: true };
            }
            return { success: true };
          },
          async all() { return { results: [] }; },
        };
      },
    },
    KV: {
      async put(k, v, opts) { kvStore.set(k, v); return true; },
      async get(k) { return kvStore.get(k) ?? null; },
    },
  };
  return { env, purchases, kvStore };
}

function req(body) {
  return new Request('https://x/api/marketplace/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// createRazorpayOrder() calls out to api.razorpay.com via resilientFetch — stub
// global fetch so checkout tests never make a real network call.
const realFetch = globalThis.fetch;
function stubRazorpayOrderCreate(orderId = 'order_stub_123') {
  globalThis.fetch = async () => new Response(JSON.stringify({
    id: orderId, entity: 'order', amount: 0, currency: 'INR', receipt: 'r', status: 'created',
  }), { status: 200 });
}

describe('marketplace catalog — server-side pricing source of truth', () => {
  it('serves prices from MARKETPLACE_CATALOG, never accepts client overrides', async () => {
    const { env } = makeEnv();
    const res = await handleMarketplaceCatalog(new Request('https://x/api/marketplace/catalog'), env);
    const body = await res.json();
    const flat = Object.values(body.catalog).flatMap(g => g.items);
    for (const item of flat) {
      expect(item.amount).toBe(MARKETPLACE_CATALOG[item.id].amount);
    }
  });

  it('404s an unknown product id', async () => {
    const { env } = makeEnv();
    const res = await handleMarketplaceProduct(new Request('https://x/api/marketplace/catalog/does-not-exist'), env, 'does-not-exist');
    expect(res.status).toBe(404);
  });
});

describe('marketplace checkout — price tamper resistance', () => {
  beforeEach(() => { stubRazorpayOrderCreate(); });
  afterAll(() => { globalThis.fetch = realFetch; });

  it('ignores a client-supplied amount and charges the real catalog price', async () => {
    const { env } = makeEnv();
    const product = MARKETPLACE_CATALOG['pb-ransomware-ir']; // ₹999
    const res = await handleMarketplaceCheckout(
      req({ product_id: 'pb-ransomware-ir', email: 'buyer@example.com', name: 'Buyer', amount: 100 /* tamper attempt: ₹1 */ }),
      env, {}
    );
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.product.amount).toBe(product.amount);
    expect(body.product.amount).not.toBe(100);
  });

  it('rejects an unknown product id with 404, no order created', async () => {
    const { env } = makeEnv();
    const res = await handleMarketplaceCheckout(req({ product_id: 'totally-fake-product', email: 'buyer@example.com' }), env, {});
    expect(res.status).toBe(404);
  });

  it('rejects checkout with no valid email', async () => {
    const { env } = makeEnv();
    const res = await handleMarketplaceCheckout(req({ product_id: 'pb-ransomware-ir', email: 'not-an-email' }), env, {});
    expect(res.status).toBe(400);
  });

  it('rejects malformed JSON bodies', async () => {
    const { env } = makeEnv();
    const badReq = new Request('https://x/api/marketplace/checkout', { method: 'POST', body: '{not json' });
    const res = await handleMarketplaceCheckout(badReq, env, {});
    expect(res.status).toBe(400);
  });
});

describe('marketplace payment verification — signature gate + idempotency', () => {
  it('rejects verification with an invalid signature and does not provision access', async () => {
    const { env, purchases } = makeEnv([
      { id: 'mp_1', razorpay_order_id: 'order_1', product_id: 'pb-ransomware-ir', product_name: 'x', category: 'playbook', status: 'pending', buyer_email: 'b@x.com' },
    ]);
    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1', razorpay_signature: 'totally-wrong-signature',
    }), env, {});
    expect(res.status).toBe(400);
    expect(purchases.get('order_1').status).toBe('pending');
  });

  it('accepts a valid HMAC signature, marks paid, and provisions an access token', async () => {
    const { env, purchases, kvStore } = makeEnv([
      { id: 'mp_2', razorpay_order_id: 'order_2', product_id: 'pb-ransomware-ir', product_name: 'x', category: 'playbook', status: 'pending', buyer_email: 'b@x.com' },
    ]);
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_2|pay_2');
    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_2', razorpay_payment_id: 'pay_2', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.access_token).toBeTruthy();
    expect(purchases.get('order_2').status).toBe('paid');
    expect(kvStore.has(`marketplace:access:${body.access_token}`)).toBe(true);
  });

  it('is idempotent — re-verifying an already-paid order returns the same access token without re-charging', async () => {
    const { env } = makeEnv([
      { id: 'mp_3', razorpay_order_id: 'order_3', product_id: 'pb-ransomware-ir', product_name: 'x', category: 'playbook', status: 'paid', access_token: 'existing-token-abc', buyer_email: 'b@x.com' },
    ]);
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_3|pay_3');
    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_3', razorpay_payment_id: 'pay_3', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBe('existing-token-abc');
  });

  it('404s verification for an order with no matching purchase record', async () => {
    const { env } = makeEnv();
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_missing|pay_x');
    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_missing', razorpay_payment_id: 'pay_x', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(404);
  });
});

describe('marketplace purchase history — requires authentication', () => {
  it('rejects unauthenticated access', async () => {
    const { env } = makeEnv();
    const res = await handleMyMarketplacePurchases(new Request('https://x/api/marketplace/my-purchases'), env, {});
    expect(res.status).toBe(401);
  });
});
