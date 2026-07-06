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
  handleMarketplaceDownload,
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

function makeEnv(seedPurchases = [], seedUsers = []) {
  const purchases = new Map(seedPurchases.map(p => [p.razorpay_order_id, { ...p }]));
  const users = new Map(seedUsers.map(u => [u.email, { ...u }]));
  const apiKeys = new Map();
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
            if (/SELECT \* FROM marketplace_purchases WHERE access_token/.test(sql)) {
              return [...purchases.values()].find(p => p.access_token === bound[0]) || null;
            }
            if (/SELECT id FROM users WHERE email/.test(sql)) {
              const u = users.get(bound[0]);
              return u ? { id: u.id } : null;
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
            if (/INSERT INTO users/.test(sql)) {
              const [id, email] = bound;
              users.set(email, { id, email });
              return { success: true };
            }
            if (/INSERT INTO api_keys/.test(sql)) {
              const [id, user_id, key_hash, key_prefix, label, tier] = bound;
              apiKeys.set(id, { id, user_id, key_hash, key_prefix, label, tier, expires_at: null });
              return { success: true };
            }
            if (/UPDATE api_keys SET expires_at/.test(sql)) {
              const [expires_at, id] = bound;
              const k = apiKeys.get(id);
              if (k) k.expires_at = expires_at;
              return { success: true };
            }
            return { success: true };
          },
          async all() { return { results: [] }; },
        };
      },
    },
    SECURITY_HUB_KV: {
      async put(k, v, opts) { kvStore.set(k, v); return true; },
      async get(k) { return kvStore.get(k) ?? null; },
    },
  };
  return { env, purchases, users, apiKeys, kvStore };
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

describe('marketplace download — the route that never existed (2026-07-06 audit)', () => {
  // handleMarketplaceVerify has always returned
  // `download_url: /api/marketplace/download/${accessToken}`, but no route
  // for it existed anywhere — every verified purchase across all 12 catalog
  // products dead-ended on a live 404. These lock the real fix per category.

  it('400s a too-short token', async () => {
    const { env } = makeEnv();
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/short'), env, 'short');
    expect(res.status).toBe(400);
  });

  it('404s a well-formed but unknown access token', async () => {
    const { env } = makeEnv();
    const token = '0'.repeat(32);
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + token), env, token);
    expect(res.status).toBe(404);
  });

  it('410s an expired access token', async () => {
    const { env } = makeEnv([{
      id: 'mp_exp', razorpay_order_id: 'order_exp', product_id: 'pb-ransomware-ir',
      product_name: 'x', category: 'playbook', status: 'paid',
      access_token: 'a'.repeat(32), access_expires_at: new Date(Date.now() - 86400000).toISOString(),
      buyer_email: 'b@x.com',
    }]);
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'a'.repeat(32)), env, 'a'.repeat(32));
    expect(res.status).toBe(410);
  });

  it('403s if the order was never actually paid', async () => {
    const { env } = makeEnv([{
      id: 'mp_unpaid', razorpay_order_id: 'order_unpaid', product_id: 'pb-ransomware-ir',
      product_name: 'x', category: 'playbook', status: 'pending',
      access_token: 'b'.repeat(32), buyer_email: 'b@x.com',
    }]);
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'b'.repeat(32)), env, 'b'.repeat(32));
    expect(res.status).toBe(403);
  });

  it('detection_pack/playbook: honestly confirms the paid order for manual fulfillment (no fabricated rule content)', async () => {
    const { env } = makeEnv([{
      id: 'mp_pb', razorpay_order_id: 'order_pb', product_id: 'pb-ransomware-ir',
      product_name: 'Ransomware IR Playbook', category: 'playbook', status: 'paid',
      access_token: 'c'.repeat(32), access_expires_at: new Date(Date.now() + 86400000).toISOString(),
      buyer_email: 'buyer@x.com',
    }]);
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'c'.repeat(32)), env, 'c'.repeat(32));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.delivery).toBe('manual_pending');
    expect(body.message).toContain('buyer@x.com');
  });

  it('intelligence_report: generates real content via the live CTI engine, not a static file', async () => {
    const { env } = makeEnv([{
      id: 'mp_ir', razorpay_order_id: 'order_ir', product_id: 'ir-q2-2025-threat',
      product_name: 'Q2 2025 Threat Report', category: 'intelligence_report', status: 'paid',
      access_token: 'd'.repeat(32), access_expires_at: new Date(Date.now() + 86400000).toISOString(),
      buyer_email: 'buyer@x.com',
    }]);
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'd'.repeat(32)), env, 'd'.repeat(32));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.delivery).toBe('report');
    expect(body.report).toBeTruthy();
  });

  it('compliance_pack: generates real gap-analysis content via the live compliance engine', async () => {
    const { env } = makeEnv([{
      id: 'mp_cp', razorpay_order_id: 'order_cp', product_id: 'cp-nist-csf-2',
      product_name: 'NIST CSF Starter Pack', category: 'compliance_pack', status: 'paid',
      access_token: 'e'.repeat(32), access_expires_at: new Date(Date.now() + 86400000).toISOString(),
      buyer_email: 'buyer@x.com',
    }]);
    const res = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'e'.repeat(32)), env, 'e'.repeat(32));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.delivery).toBe('report');
    expect(body.report).toBeTruthy();
  });

  it('api_key: mints a real functional API key for a new buyer and is idempotent on retry', async () => {
    const { env, apiKeys, kvStore } = makeEnv([{
      id: 'mp_key', razorpay_order_id: 'order_key', product_id: 'aa-threat-hunter',
      product_name: 'AI Threat Hunting Agent', category: 'ai_agent', status: 'paid',
      access_token: 'f'.repeat(32), access_expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
      buyer_email: 'newbuyer@x.com', user_id: null,
    }]);
    const res1 = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'f'.repeat(32)), env, 'f'.repeat(32));
    expect(res1.status).toBe(200);
    const body1 = await res1.json();
    expect(body1.success).toBe(true);
    expect(body1.delivery).toBe('api_key');
    expect(body1.api_key).toBeTruthy();
    expect(body1.already_issued).toBeFalsy();
    expect(apiKeys.size).toBe(1);
    expect(kvStore.has(`marketplace:apikey_issued:${'f'.repeat(32)}`)).toBe(true);

    // Retry must NOT mint a second key — the raw key is only ever shown once.
    const res2 = await handleMarketplaceDownload(new Request('https://x/api/marketplace/download/' + 'f'.repeat(32)), env, 'f'.repeat(32));
    expect(res2.status).toBe(200);
    const body2 = await res2.json();
    expect(body2.already_issued).toBe(true);
    expect(apiKeys.size).toBe(1);
  });
});
