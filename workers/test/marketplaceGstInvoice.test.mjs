/* Priority 2 — Marketplace GST Invoice Flow (2026-07-14 commercial-integrity
 * audit continuation). handleMarketplaceVerify (marketplaceCheckoutHandler.js)
 * marked purchases paid, provisioned access, and emailed a confirmation — but
 * never called the consolidated GST invoice authority (createInvoice, in
 * services/v24/billingEngine.js), unlike every other purchase path in this
 * codebase (payments.js, defenseMarketplace.js, toolsMarketplace.js,
 * sentinelMarketplace.js, academyMarketplace.js all call it). A paid
 * marketplace order produced no invoice record at all.
 *
 * Fix: handleMarketplaceVerify now calls the same createInvoice() authority,
 * both on first verification and (as a payment_id-idempotent backfill) on a
 * repeat verify of an already-paid order — covering purchases verified
 * before this fix existed. These tests drive the real handler end to end
 * against a D1 mock that also models the `invoices` table, so they fail if
 * the invoice call is ever removed or made non-idempotent. */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { handleMarketplaceCheckout, handleMarketplaceVerify, MARKETPLACE_CATALOG } from '../src/handlers/marketplaceCheckoutHandler.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv(seedPurchases = []) {
  const purchases = new Map(seedPurchases.map(p => [p.razorpay_order_id, { ...p }]));
  const invoices = new Map(); // keyed by payment_id
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
            if (/SELECT \* FROM marketplace_purchases WHERE razorpay_order_id/.test(sql)) {
              return purchases.get(bound[0]) || null;
            }
            if (/SELECT \* FROM invoices WHERE payment_id/.test(sql)) {
              return invoices.get(bound[0]) || null;
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
            if (/INSERT INTO invoices/.test(sql)) {
              const [invId, invoiceNumber, customerId, userId, email, company, gstin, billingAddress, lineItems, subtotal, gstRate, gstAmount, total, paymentId, paymentMethod] = bound;
              if (paymentId && [...invoices.values()].some(i => i.payment_id === paymentId)) {
                throw new Error('UNIQUE constraint failed: invoices.payment_id');
              }
              invoices.set(paymentId, {
                id: invId, invoice_number: invoiceNumber, customer_id: customerId, user_id: userId,
                email, company, gstin, line_items: lineItems, subtotal_inr: subtotal,
                gst_amount_inr: gstAmount, total_inr: total, payment_id: paymentId, payment_method: paymentMethod,
              });
              return { success: true };
            }
            if (/INSERT INTO revenue_streams/.test(sql)) return { success: true };
            return { success: true };
          },
          async all() {
            if (/SELECT invoice_number FROM invoices/.test(sql)) {
              return { results: [...invoices.values()].map(i => ({ invoice_number: i.invoice_number })) };
            }
            return { results: [] };
          },
        };
      },
    },
    SECURITY_HUB_KV: {
      async put(k, v) { kvStore.set(k, v); return true; },
      async get(k) { return kvStore.get(k) ?? null; },
    },
  };
  return { env, purchases, invoices, kvStore };
}

function req(body) {
  return new Request('https://x/api/marketplace/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

const realFetch = globalThis.fetch;
beforeEach(() => {
  globalThis.fetch = async () => new Response(JSON.stringify({
    id: 'order_stub', entity: 'order', amount: 0, currency: 'INR', receipt: 'r', status: 'created',
  }), { status: 200 });
});
afterAll(() => { globalThis.fetch = realFetch; });

describe('handleMarketplaceVerify — GST invoice is generated on successful payment', () => {
  it('creates an invoice with the correct catalog amount (in rupees) on first verify', async () => {
    const product = MARKETPLACE_CATALOG['pb-ransomware-ir']; // ₹999 (amount: 99900 paise)
    const { env, invoices } = makeEnv([
      { id: 'mp_1', razorpay_order_id: 'order_1', product_id: 'pb-ransomware-ir', product_name: product.name, category: 'playbook', amount: product.amount, status: 'pending', buyer_email: 'buyer@example.com' },
    ]);
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_1|pay_1');
    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);

    expect(invoices.size).toBe(1);
    const invoice = invoices.get('pay_1');
    expect(invoice).toBeTruthy();
    expect(invoice.subtotal_inr).toBe(999); // rupees, not paise
    expect(invoice.email).toBe('buyer@example.com');
    expect(invoice.invoice_number).toMatch(/^CBD-\d{6}-\d{4}$/);
  });

  it('is idempotent — re-verifying an already-paid order does not create a second invoice', async () => {
    const product = MARKETPLACE_CATALOG['pb-ransomware-ir'];
    const { env, invoices } = makeEnv([
      { id: 'mp_2', razorpay_order_id: 'order_2', product_id: 'pb-ransomware-ir', product_name: product.name, category: 'playbook', amount: product.amount, status: 'paid', access_token: 'existing-token', razorpay_payment_id: 'pay_2', buyer_email: 'buyer2@example.com' },
    ]);
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_2|pay_2');

    // Simulate this purchase having already been invoiced once (post-fix behavior).
    invoices.set('pay_2', { id: 'inv_pre', invoice_number: 'CBD-202607-0001', payment_id: 'pay_2', subtotal_inr: 999 });

    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_2', razorpay_payment_id: 'pay_2', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(200);
    expect(invoices.size).toBe(1); // no duplicate created
  });

  it('backfills an invoice for a purchase that was marked paid before this fix existed (no prior invoice)', async () => {
    const product = MARKETPLACE_CATALOG['ir-q2-2025-threat'];
    const { env, invoices } = makeEnv([
      { id: 'mp_3', razorpay_order_id: 'order_3', product_id: 'ir-q2-2025-threat', product_name: product.name, category: 'intelligence_report', amount: product.amount, status: 'paid', access_token: 'legacy-token', razorpay_payment_id: 'pay_3', buyer_email: 'buyer3@example.com' },
    ]);
    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_3|pay_3');

    expect(invoices.size).toBe(0); // legacy paid purchase, no invoice yet

    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_3', razorpay_payment_id: 'pay_3', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.message).toMatch(/already verified/i);

    expect(invoices.size).toBe(1);
    expect(invoices.get('pay_3').subtotal_inr).toBe(1999);
  });

  it('a downstream invoice-engine failure does not fail the payment verification response', async () => {
    const product = MARKETPLACE_CATALOG['pb-ransomware-ir'];
    const { env } = makeEnv([
      { id: 'mp_4', razorpay_order_id: 'order_4', product_id: 'pb-ransomware-ir', product_name: product.name, category: 'playbook', amount: product.amount, status: 'pending', buyer_email: 'buyer4@example.com' },
    ]);
    // Break invoice creation specifically, leaving everything else working.
    const realPrepare = env.DB.prepare.bind(env.DB);
    env.DB.prepare = (sql) => {
      if (/INSERT INTO invoices/.test(sql)) {
        return { bind() { return this; }, async run() { throw new Error('DB unavailable'); }, async first() { return null; }, async all() { return { results: [] }; } };
      }
      return realPrepare(sql);
    };

    const signature = await hmac(RAZORPAY_KEY_SECRET, 'order_4|pay_4');
    const res = await handleMarketplaceVerify(req({
      razorpay_order_id: 'order_4', razorpay_payment_id: 'pay_4', razorpay_signature: signature,
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.access_token).toBeTruthy();
  });
});
