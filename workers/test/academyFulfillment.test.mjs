/* Regression tests — Academy had ZERO test coverage despite handling real
 * money (2026-07-06 revenue-mechanisms audit found "0 references to academy
 * in tests/, ceap-sweep, or any CI workflow"). Locks:
 *  1. The checkout itself (already correct — own real order-create + verify,
 *     not the shared checkout-modal legacy-bypass path).
 *  2. The real bug: the KV access grant handleVerifyAcademy wrote was never
 *     read back by anything, and a paid order left no durable trace if the
 *     founder-alert email silently failed. Now every paid order is recorded
 *     in academy_orders regardless of email outcome, and can be checked via
 *     /api/academy/access and closed out via the new admin endpoints. */
import { describe, it, expect } from 'vitest';
import {
  handlePurchaseAcademy,
  handleVerifyAcademy,
  handleAcademyAccessStatus,
  handleListAcademyOrders,
  handleMarkAcademyDelivered,
  ACADEMY_CATALOG,
} from '../src/handlers/academyMarketplace.js';

const RAZORPAY_KEY_SECRET = 'test_secret';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv() {
  const payments = new Map();
  const orders = new Map();
  const kvStore = new Map();
  return {
    RAZORPAY_KEY_SECRET,
    DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async first() {
            if (/SELECT id FROM payments WHERE razorpay_order_id/.test(sql)) {
              return payments.get(bound[0]) || null;
            }
            if (/SELECT status, created_at, delivered_at FROM academy_orders/.test(sql)) {
              const [productId, email] = bound;
              const rows = [...orders.values()]
                .filter(o => o.product_id === productId && o.email === email)
                .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
              return rows[0] || null;
            }
            return null;
          },
          async run() {
            if (/CREATE TABLE/.test(sql)) return { success: true };
            if (/INSERT OR IGNORE INTO payments/.test(sql)) {
              const [id, user_id, module, target, amount, currency, order_id] = bound;
              payments.set(order_id, { id });
              return { success: true };
            }
            if (/INSERT OR IGNORE INTO academy_orders/.test(sql)) {
              const [id, product_id, product_name, email, payment_id, order_id] = bound;
              orders.set(id, {
                id, product_id, product_name, email, payment_id, order_id,
                status: 'pending_delivery', created_at: new Date().toISOString(), delivered_at: null,
              });
              return { success: true };
            }
            if (/UPDATE academy_orders SET status = 'delivered'/.test(sql)) {
              const [id] = bound;
              const o = orders.get(id);
              if (!o || o.status === 'delivered') return { meta: { changes: 0 } };
              o.status = 'delivered'; o.delivered_at = new Date().toISOString();
              return { meta: { changes: 1 } };
            }
            return { success: true };
          },
          async all() {
            if (/FROM academy_orders WHERE status/.test(sql)) {
              const [status] = bound;
              return { results: [...orders.values()].filter(o => o.status === status) };
            }
            return { results: [] };
          },
        };
      },
    },
    SECURITY_HUB_KV: {
      async put(k, v) { kvStore.set(k, v); },
      async get(k) { return kvStore.get(k) ?? null; },
    },
    _orders: orders,
    _kvStore: kvStore,
  };
}

function req(url, body) {
  return new Request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

describe('Academy checkout — real order flow, no legacy bypass', () => {
  it('rejects an unknown course', async () => {
    const res = await handlePurchaseAcademy(req('https://x/api/academy/purchase', { product_id: 'NOT_REAL', email: 'a@b.com' }), makeEnv());
    expect((await res.json()).success).toBe(false);
    expect(res.status).toBe(404);
  });

  it('rejects an invalid email', async () => {
    const res = await handlePurchaseAcademy(req('https://x/api/academy/purchase', { product_id: 'SOC_PLAYBOOK_2026', email: 'not-an-email' }), makeEnv());
    expect(res.status).toBe(400);
  });
});

describe('Academy verify — payment confirmation is now durably tracked', () => {
  it('rejects an invalid HMAC signature', async () => {
    const env = makeEnv();
    const res = await handleVerifyAcademy(req('https://x/api/academy/verify', {
      razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1', razorpay_signature: 'wrong',
      product_id: 'SOC_PLAYBOOK_2026', email: 'buyer@x.com',
    }), env);
    expect((await res.json()).success).toBe(false);
    expect(env._orders.size).toBe(0);
  });

  it('a real signature records a durable academy_orders row (pending_delivery)', async () => {
    const env = makeEnv();
    const sig = await hmac(RAZORPAY_KEY_SECRET, 'order_2|pay_2');
    const res = await handleVerifyAcademy(req('https://x/api/academy/verify', {
      razorpay_order_id: 'order_2', razorpay_payment_id: 'pay_2', razorpay_signature: sig,
      product_id: 'SOC_PLAYBOOK_2026', email: 'buyer@x.com',
    }), env);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.access_granted).toBe(true);
    expect(env._orders.size).toBe(1);
    const order = [...env._orders.values()][0];
    expect(order.status).toBe('pending_delivery');
    expect(order.email).toBe('buyer@x.com');
    // the previously-dead KV write now has a real reader (handleAcademyAccessStatus)
    expect(env._kvStore.has('access:academy:SOC_PLAYBOOK_2026:buyer@x.com')).toBe(true);
  });
});

describe('GET /api/academy/access — the buyer can now check their own fulfillment status', () => {
  it('404s when no purchase exists for that email/course', async () => {
    const env = makeEnv();
    const res = await handleAcademyAccessStatus(new Request('https://x/api/academy/access?email=nobody@x.com&product_id=SOC_PLAYBOOK_2026'), env);
    expect(res.status).toBe(404);
  });

  it('reports pending_delivery right after a verified purchase', async () => {
    const env = makeEnv();
    const sig = await hmac(RAZORPAY_KEY_SECRET, 'order_3|pay_3');
    await handleVerifyAcademy(req('https://x/api/academy/verify', {
      razorpay_order_id: 'order_3', razorpay_payment_id: 'pay_3', razorpay_signature: sig,
      product_id: 'OSINT_STARTER_BUNDLE', email: 'buyer3@x.com',
    }), env);
    const res = await handleAcademyAccessStatus(new Request('https://x/api/academy/access?email=buyer3@x.com&product_id=OSINT_STARTER_BUNDLE'), env);
    const body = await res.json();
    expect(body.access_granted).toBe(true);
    expect(body.status).toBe('pending_delivery');
  });
});

describe('Admin fulfillment queue — nothing can silently vanish', () => {
  it('non-admins are rejected from both admin endpoints', async () => {
    const env = makeEnv();
    const listRes = await handleListAcademyOrders(new Request('https://x/api/academy/orders'), env, {});
    expect(listRes.status).toBe(403);
    const markRes = await handleMarkAcademyDelivered(new Request('https://x'), env, {}, 'ac_1');
    expect(markRes.status).toBe(403);
  });

  it('an admin sees the pending order and can mark it delivered', async () => {
    const env = makeEnv();
    const sig = await hmac(RAZORPAY_KEY_SECRET, 'order_4|pay_4');
    await handleVerifyAcademy(req('https://x/api/academy/verify', {
      razorpay_order_id: 'order_4', razorpay_payment_id: 'pay_4', razorpay_signature: sig,
      product_id: 'PYTHON_JAVA_AUTOMATION_PACK', email: 'buyer4@x.com',
    }), env);

    const listRes = await handleListAcademyOrders(new Request('https://x/api/academy/orders'), env, { isAdmin: true });
    const listBody = await listRes.json();
    expect(listBody.count).toBe(1);
    const orderId = listBody.orders[0].id;

    const markRes = await handleMarkAcademyDelivered(new Request('https://x', { method: 'POST' }), env, { isAdmin: true }, orderId);
    expect((await markRes.json()).status).toBe('delivered');

    const statusRes = await handleAcademyAccessStatus(new Request('https://x/api/academy/access?email=buyer4@x.com&product_id=PYTHON_JAVA_AUTOMATION_PACK'), env);
    expect((await statusRes.json()).status).toBe('delivered');
  });

  it('marking an already-delivered order again fails cleanly', async () => {
    const env = makeEnv();
    const sig = await hmac(RAZORPAY_KEY_SECRET, 'order_5|pay_5');
    await handleVerifyAcademy(req('https://x/api/academy/verify', {
      razorpay_order_id: 'order_5', razorpay_payment_id: 'pay_5', razorpay_signature: sig,
      product_id: 'CYBER_MEGA_PART1', email: 'buyer5@x.com',
    }), env);
    const orderId = [...env._orders.values()][0].id;
    await handleMarkAcademyDelivered(new Request('https://x', { method: 'POST' }), env, { isAdmin: true }, orderId);
    const secondRes = await handleMarkAcademyDelivered(new Request('https://x', { method: 'POST' }), env, { isAdmin: true }, orderId);
    expect(secondRes.status).toBe(404);
  });
});

describe('ACADEMY_CATALOG sanity', () => {
  it('every product has a positive price and a name', () => {
    for (const course of Object.values(ACADEMY_CATALOG)) {
      expect(course.price_inr).toBeGreaterThan(0);
      expect(course.name).toBeTruthy();
    }
  });
});
