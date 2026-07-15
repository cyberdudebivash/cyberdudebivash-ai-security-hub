/* Customer-lifecycle audit (2026-07-15) — compliance-pack price-tampering fix.
 *
 * handleVerifyCompliancePack (workers/src/services/globalScale.js) used to
 * trust the client-resent pack_id at verify time. The Razorpay signature only
 * proves razorpay_order_id + razorpay_payment_id are a genuine, linked pair —
 * it says nothing about WHICH pack that order was actually priced for. That
 * meant a customer could create+pay for the cheapest pack and then call
 * verify a second time with a pricier pack_id, reusing the same signed
 * order/payment pair, and receive the expensive pack's entitlement. Same
 * vulnerability class as handlers/payments.js's handleVerifyPayment
 * (2026-07-14 commercial-integrity audit, H8; see
 * paymentVerifyOrderIntegrity.test.mjs), just never applied to this flow.
 *
 * Fix: handlePurchaseCompliancePack now writes an authoritative 'pending'
 * payments row at order-creation time; handleVerifyCompliancePack looks up
 * ITS pack_id, never the client's, and fails closed (400, not a fallback to
 * client input) if no matching row exists — unlike handleVerifyPayment's
 * fail-open posture, this handler's entitlement grant (the KV write) doesn't
 * itself depend on D1, so a fail-open fallback would still be exploitable.
 *
 * Runs the real handlers against a real SQL engine (node:sqlite) with the
 * live payments schema, same convention as paymentVerifyOrderIntegrity.test.mjs.
 */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handlePurchaseCompliancePack, handleVerifyCompliancePack } from '../src/services/globalScale.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

// handlePurchaseCompliancePack calls the real Razorpay order-creation API —
// stub it to return a successful, uniquely-IDed order, matching the
// beforeEach/afterAll stub convention already used in this test suite
// (partnerAuth.test.mjs, whiteLabelPartnerScoping.test.mjs).
const realFetch = globalThis.fetch;
beforeEach(() => {
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ id: 'order_' + Math.random().toString(36).slice(2, 10) }), { status: 200 });
});
afterAll(() => { globalThis.fetch = realFetch; });

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

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
    async batch(stmts) {
      const out = [];
      for (const s of stmts) out.push(await s.run());
      return out;
    },
  };
}

function makeEnv() {
  const db = makeRealD1();
  db._sqlite.exec(`
    CREATE TABLE payments (
      id TEXT PRIMARY KEY, user_id TEXT, scan_id TEXT, module TEXT NOT NULL, target TEXT NOT NULL,
      amount INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT 'INR',
      razorpay_order_id TEXT UNIQUE, razorpay_payment_id TEXT, razorpay_signature TEXT,
      status TEXT NOT NULL DEFAULT 'pending', plan TEXT NOT NULL DEFAULT 'pay_per_report',
      report_token TEXT, ip TEXT, email TEXT, partner_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), paid_at TEXT
    );
  `);
  const kvStore = new Map();
  return {
    RAZORPAY_KEY_ID: 'rzp_test_key',
    RAZORPAY_KEY_SECRET,
    DB: db,
    SECURITY_HUB_KV: {
      async put(key, value) { kvStore.set(key, value); },
      async get(key) { return kvStore.get(key) ?? null; },
    },
    _kvStore: kvStore,
  };
}

function seedOrder(env, { orderId, packId, amount = 499900, email = 'buyer@corp.com', status = 'pending' }) {
  env.DB._sqlite.prepare(
    `INSERT INTO payments (id, module, target, amount, razorpay_order_id, status, email)
     VALUES (?, 'compliance_pack', ?, ?, ?, ?, ?)`
  ).run('cp_' + orderId, packId, amount, orderId, status, email);
}

function verifyReq(body) {
  return new Request('https://x.test/api/global/compliance-packs/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

function purchaseReq(body) {
  return new Request('https://x.test/api/global/compliance-packs/purchase', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

// Real keys from globalScale.js's exported COMPLIANCE_PACKS catalog:
// dpdp (₹2999) is the cheapest pack; iso27001 (₹4999) is the pack
// CAP-COMP-001's own registry notes cite for the 3-way price fragmentation
// finding.
const CHEAP_PACK = 'dpdp';
const EXPENSIVE_PACK = 'iso27001';

describe('handleVerifyCompliancePack — order-integrity (pack_id/price tampering)', () => {
  it('a genuinely-paid cheap pack cannot be verified as an expensive one by resending a different pack_id', async () => {
    const env = makeEnv();
    const orderId = 'order_cheap0001', paymentId = 'pay_cheap0001';
    seedOrder(env, { orderId, packId: CHEAP_PACK, amount: 49900 });
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyCompliancePack(verifyReq({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      pack_id: EXPENSIVE_PACK,        // tampered — real order was CHEAP_PACK
      email: 'buyer@corp.com',
    }), env);
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.pack_name).not.toMatch(/ISO/i);

    // The KV entitlement grant must be keyed to the AUTHORITATIVE pack, not
    // the tampered one — this is the actual exploitable surface.
    const grantedKeys = [...env._kvStore.keys()];
    expect(grantedKeys.some(k => k.includes(`access:compliance:${CHEAP_PACK}:`))).toBe(true);
    expect(grantedKeys.some(k => k.includes(`access:compliance:${EXPENSIVE_PACK}:`))).toBe(false);
  });

  it('legitimate flow: purchase then verify with matching pack_id succeeds and grants the correct pack', async () => {
    const env = makeEnv();

    const purchaseRes = await handlePurchaseCompliancePack(purchaseReq({
      pack_id: CHEAP_PACK, email: 'real@corp.com', currency: 'INR',
    }), env, {});
    const purchaseData = await purchaseRes.json();
    expect(purchaseRes.status).toBe(200);
    expect(purchaseData.success).toBe(true);
    const orderId = purchaseData.order.razorpay_order_id;
    expect(orderId).toBeTruthy();

    // Purchase must have written the authoritative row itself.
    const row = env.DB._sqlite.prepare(`SELECT module, target, status FROM payments WHERE razorpay_order_id = ?`).get(orderId);
    expect(row).toBeTruthy();
    expect(row.module).toBe('compliance_pack');
    expect(row.target).toBe(CHEAP_PACK);
    expect(row.status).toBe('pending');

    const paymentId = 'pay_real0001';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
    const verifyRes = await handleVerifyCompliancePack(verifyReq({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      pack_id: CHEAP_PACK,
      email: 'real@corp.com',
    }), env);
    const verifyData = await verifyRes.json();

    expect(verifyRes.status).toBe(200);
    expect(verifyData.success).toBe(true);
    expect(verifyData.access_granted).toBe(true);

    const updated = env.DB._sqlite.prepare(`SELECT status FROM payments WHERE razorpay_order_id = ?`).get(orderId);
    expect(updated.status).toBe('paid');

    const grantedKeys = [...env._kvStore.keys()];
    expect(grantedKeys.some(k => k.includes(`access:compliance:${CHEAP_PACK}:`))).toBe(true);
  });

  it('fails closed (does not fall back to client input) when no matching D1 order row exists', async () => {
    const env = makeEnv();
    const orderId = 'order_unknown001', paymentId = 'pay_unknown001';
    // No seedOrder() call — this order_id has no payments row at all.
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyCompliancePack(verifyReq({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      pack_id: EXPENSIVE_PACK,
      email: 'noorder@corp.com',
    }), env);
    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data.success).toBe(false);
    expect([...env._kvStore.keys()].length).toBe(0);
  });

  it('replaying the same order twice is idempotent and does not re-grant or error', async () => {
    const env = makeEnv();
    const orderId = 'order_dup0001', paymentId = 'pay_dup0001';
    seedOrder(env, { orderId, packId: CHEAP_PACK, amount: 49900 });
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
    const body = {
      razorpay_order_id: orderId, razorpay_payment_id: paymentId,
      razorpay_signature: signature, pack_id: CHEAP_PACK, email: 'buyer@corp.com',
    };

    const first = await (await handleVerifyCompliancePack(verifyReq(body), env)).json();
    expect(first.duplicate).toBeFalsy();

    const second = await (await handleVerifyCompliancePack(verifyReq(body), env)).json();
    expect(second.success).toBe(true);
    expect(second.duplicate).toBe(true);
  });
});
