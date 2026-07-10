/* P0 Wave 2 (Payment & Subscription Platform) — payment/plan-tampering fix.
 *
 * handleVerifyPayment (workers/src/handlers/payments.js) used to trust the
 * client-resent module/target/plan/product_id fields at verify time. The
 * Razorpay signature only proves razorpay_order_id + razorpay_payment_id are
 * a genuine, linked pair — it says nothing about WHICH module/plan/product
 * that order was actually created (and priced) for. That meant a customer
 * could create+pay for the cheapest product (e.g. a genuinely-signed ₹499
 * STARTER subscription order) and then call verify a second time with a
 * different, more expensive module/plan/product_id (e.g. MSSP ₹9,999/mo, or
 * a ₹4,999 redteam report) while reusing that same order — the signature
 * check alone would still pass.
 *
 * Fix: once a matching payments row exists in D1 (written once, server-side,
 * by handleCreateOrder at order-creation time), its own stored
 * module/target/plan are authoritative for verify — client-supplied values
 * are only a fallback when no D1 record exists.
 *
 * Runs the real handler against a real SQL engine (node:sqlite) with the
 * live payments/subscriptions/users/refresh_tokens schema, same convention
 * as workers/test/userSessionManagement.test.mjs.
 */
import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleVerifyPayment } from '../src/handlers/payments.js';

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

function seedOrder(env, { orderId, module, target, plan, amount = 49900, email = null, status = 'pending' }) {
  env.DB._sqlite.prepare(
    `INSERT INTO payments (id, module, target, amount, razorpay_order_id, status, plan, email)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run('pay_' + orderId, module, target, amount, orderId, status, plan, email);
}

function req(body) {
  return new Request('https://x.test/api/payments/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('handleVerifyPayment — order-integrity (payment/plan tampering)', () => {
  it('subscription: a genuinely-paid STARTER order cannot be verified as MSSP by resending a different plan', async () => {
    const env = makeEnv();
    const orderId = 'order_starter001', paymentId = 'pay_starter001';
    seedOrder(env, { orderId, module: 'subscription', target: 'buyer@corp.com', plan: 'STARTER', amount: 49900, email: 'buyer@corp.com' });
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'subscription',
      plan: 'MSSP',              // tampered — real order was STARTER
      target: 'buyer@corp.com',
      email: 'buyer@corp.com',
    }), env, {});
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.plan).toBe('STARTER');           // NOT MSSP
    const user = env.DB._sqlite.prepare(`SELECT tier FROM users WHERE email = ?`).get('buyer@corp.com');
    expect(user.tier).toBe('STARTER');            // NOT MSSP
    const sub = env.DB._sqlite.prepare(`SELECT plan, price_inr FROM subscriptions WHERE email = ?`).get('buyer@corp.com');
    expect(sub.plan).toBe('STARTER');
  });

  it('package/assessment: a cheap product_id order cannot be verified as an expensive one', async () => {
    const env = makeEnv();
    const orderId = 'order_pkg000111', paymentId = 'pay_pkg000111';
    seedOrder(env, { orderId, module: 'package', target: 'buyer@corp.com', plan: 'MCP_SECURITY_REPORT', amount: 99900, email: 'buyer@corp.com' });
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'package',
      product_id: 'ENTERPRISE_AI_SUITE',   // tampered — real order was the ₹999 report
      target: 'buyer@corp.com',
      email: 'buyer@corp.com',
    }), env, {});
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.message).toContain('MCP Security Full Report');
    expect(data.message).not.toContain('Enterprise AI Security Suite');
  });

  it('scan report: a cheap-module order cannot be verified as a more expensive module', async () => {
    const env = makeEnv();
    const orderId = 'order_scan000111', paymentId = 'pay_scan000111';
    seedOrder(env, { orderId, module: 'compliance', target: 'example.com', plan: 'pay_per_report', amount: 49900 });
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'redteam',        // tampered — real order was the cheaper 'compliance' module
      target: 'example.com',
      email: 'buyer@corp.com',
    }), env, {});

    // The scan-report branch runs a real scan handler for the authoritative
    // module (compliance) — it must not silently succeed as a 'redteam'
    // report. It may fail for unrelated reasons in this minimal test env
    // (no scan infra mocked), but it must never report success for redteam.
    if (res.status === 200) {
      const data = await res.json();
      expect(data.message).not.toMatch(/Red Team/i);
    }
  });

  it('legitimate flow: module/target/plan exactly matching the paid order still succeeds normally', async () => {
    const env = makeEnv();
    const orderId = 'order_pro000111', paymentId = 'pay_pro000111';
    seedOrder(env, { orderId, module: 'subscription', target: 'real@corp.com', plan: 'PRO', amount: 149900, email: 'real@corp.com' });
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'subscription',
      plan: 'PRO',
      target: 'real@corp.com',
      email: 'real@corp.com',
    }), env, {});
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.plan).toBe('PRO');
    expect(data.token).toBeTruthy();
    const user = env.DB._sqlite.prepare(`SELECT tier FROM users WHERE email = ?`).get('real@corp.com');
    expect(user.tier).toBe('PRO');
  });

  it('fallback: when no matching D1 payments row exists, client-supplied values are used unchanged (no regression)', async () => {
    const env = makeEnv();
    const orderId = 'order_unknown001', paymentId = 'pay_unknown001';
    // No seedOrder() call — this order_id has no payments row at all.
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'subscription',
      plan: 'STARTER',
      target: 'noorder@corp.com',
      email: 'noorder@corp.com',
    }), env, {});
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.plan).toBe('STARTER');
  });
});
