/* P0 Wave 2 (Payment & Subscription Platform) — legacy route consolidation.
 *
 * POST /api/subscription/create and POST /api/subscription/activate
 * (workers/src/handlers/subscription.js handleCreateSubscription /
 * handleActivateSubscription) used to run their own parallel Razorpay
 * order-creation/verification logic. handleActivateSubscription's D1 writes
 * used column names that don't exist in the live schema (order_id/payment_id
 * vs. the real razorpay_order_id/razorpay_payment_id; processor/external_id
 * vs. the real schema) — silently swallowed by .catch(), so every activation
 * was charged and never actually activated, and users.tier was never touched
 * at all (see PR #142's incident writeup). PR #142 fixed the one known
 * frontend caller (the dashboard's "Upgrade to Pro" button) by pointing it
 * at the canonical path directly, but left these routes themselves live and
 * still broken for any other caller.
 *
 * This wave replaces both functions' internals with thin delegating wrappers
 * over the canonical, now-hardened handlers/payments.js handleCreateOrder /
 * handleVerifyPayment, keeping the routes and response shape backward
 * compatible. These tests prove the delegation actually produces correct,
 * schema-valid D1 writes and a real tier grant — not just that it returns
 * 200.
 *
 * Runs the real handlers against a real SQL engine (node:sqlite) with the
 * live payments/subscriptions/users/refresh_tokens schema.
 */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import { handleCreateSubscription, handleActivateSubscription } from '../src/handlers/subscription.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

// handleCreateOrder (the delegation target) calls the real Razorpay Orders
// API via a bare fetch() — stub it exactly like
// workers/test/couponSystem.test.mjs does, so order creation succeeds
// deterministically without a live network call.
const realFetch = globalThis.fetch;
beforeEach(() => {
  globalThis.fetch = async (url, opts) => {
    if (String(url).includes('api.razorpay.com')) {
      const reqBody = JSON.parse(opts.body);
      return new Response(JSON.stringify({
        id: 'order_' + Math.random().toString(36).slice(2, 14),
        entity: 'order', amount: reqBody.amount, currency: 'INR',
        receipt: reqBody.receipt, status: 'created',
      }), { status: 200 });
    }
    return realFetch(url, opts);
  };
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

function post(path, body) {
  return new Request(`https://x.test${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('handleCreateSubscription — delegates to the canonical order-creation path', () => {
  it('rejects an unknown plan (400, before touching Razorpay)', async () => {
    const env = makeEnv();
    const res = await handleCreateSubscription(post('/api/subscription/create', { plan: 'GOLD', email: 'a@b.com' }), env, {});
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/Invalid plan/i);
  });

  it('rejects a missing/invalid email (400)', async () => {
    const env = makeEnv();
    const res = await handleCreateSubscription(post('/api/subscription/create', { plan: 'PRO' }), env, {});
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/email/i);
  });

  it('creates a real, correctly-recorded payments row via handleCreateOrder — not a KV-only intent invisible to billing/admin', async () => {
    const env = makeEnv();
    const res = await handleCreateSubscription(
      post('/api/subscription/create', { plan: 'pro', email: 'buyer@corp.com', name: 'Buyer' }),
      env, {},
    );
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.order_id).toBeTruthy();
    // Old response shape preserved
    expect(data.plan).toBe('PRO');
    expect(data.plan_name).toBe('Pro');
    expect(data.amount).toBe(149900);

    const row = env.DB._sqlite.prepare(`SELECT module, target, plan, amount, email FROM payments WHERE razorpay_order_id = ?`).get(data.order_id);
    expect(row).toBeTruthy();
    expect(row.module).toBe('subscription');
    expect(row.plan).toBe('PRO');
    expect(row.amount).toBe(149900);
    expect(row.email).toBe('buyer@corp.com');
  });
});

describe('handleActivateSubscription — delegates to the canonical verify path', () => {
  it('rejects missing payment verification fields (400)', async () => {
    const env = makeEnv();
    const res = await handleActivateSubscription(post('/api/subscription/activate', {}), env, {});
    expect(res.status).toBe(400);
  });

  it('a full create→pay→activate round trip grants real users.tier and a usable JWT — the exact bug PR #142 found and this wave closes at the route level', async () => {
    const env = makeEnv();

    const createRes = await handleCreateSubscription(
      post('/api/subscription/create', { plan: 'STARTER', email: 'newcustomer@corp.com' }),
      env, {},
    );
    const created = await createRes.json();
    expect(createRes.status).toBe(200);

    const paymentId = 'pay_activatetest01';
    const signature  = await hmac(RAZORPAY_KEY_SECRET, `${created.order_id}|${paymentId}`);

    const activateRes = await handleActivateSubscription(
      post('/api/subscription/activate', {
        razorpay_order_id:   created.order_id,
        razorpay_payment_id: paymentId,
        razorpay_signature:  signature,
        email:               'newcustomer@corp.com',
      }),
      env, {},
    );
    const activated = await activateRes.json();

    expect(activateRes.status).toBe(200);
    expect(activated.success).toBe(true);
    // Old response shape preserved
    expect(activated.plan).toBe('STARTER');
    expect(activated.session_token).toBeTruthy();
    expect(activated.features).toBeTruthy();
    // New: the actual tier grant PR #142 found missing entirely
    expect(activated.token).toBeTruthy();
    expect(activated.refresh_token).toBeTruthy();
    expect(activated.user_id).toBeTruthy();

    const user = env.DB._sqlite.prepare(`SELECT tier FROM users WHERE email = ?`).get('newcustomer@corp.com');
    expect(user.tier).toBe('STARTER');

    const sub = env.DB._sqlite.prepare(`SELECT plan, status FROM subscriptions WHERE email = ?`).get('newcustomer@corp.com');
    expect(sub.plan).toBe('STARTER');
    expect(sub.status).toBe('active');

    const payRow = env.DB._sqlite.prepare(`SELECT status FROM payments WHERE razorpay_order_id = ?`).get(created.order_id);
    expect(payRow.status).toBe('paid');
  });

  it('a tampered plan at activate time cannot grant a higher tier than what was actually paid for (inherits the order-integrity fix)', async () => {
    const env = makeEnv();
    const createRes = await handleCreateSubscription(
      post('/api/subscription/create', { plan: 'STARTER', email: 'cheapskate@corp.com' }),
      env, {},
    );
    const created = await createRes.json();

    const paymentId = 'pay_tampertest01';
    const signature  = await hmac(RAZORPAY_KEY_SECRET, `${created.order_id}|${paymentId}`);

    // Bypasses this shim's own request shape and hits the endpoint as if an
    // attacker crafted the body directly — plan isn't even accepted as a
    // field by handleActivateSubscription's real signature, but prove the
    // underlying delegation is what actually protects this, not luck.
    const activateRes = await handleActivateSubscription(
      post('/api/subscription/activate', {
        razorpay_order_id:   created.order_id,
        razorpay_payment_id: paymentId,
        razorpay_signature:  signature,
        email:               'cheapskate@corp.com',
        plan:                'MSSP',
      }),
      env, {},
    );
    const activated = await activateRes.json();

    expect(activateRes.status).toBe(200);
    expect(activated.plan).toBe('STARTER');
    const user = env.DB._sqlite.prepare(`SELECT tier FROM users WHERE email = ?`).get('cheapskate@corp.com');
    expect(user.tier).toBe('STARTER');
  });
});

describe('route wiring contract (workers/src/index.js)', () => {
  const indexSrc = fs.readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');

  it('both routes are registered and pass authCtx to their handlers', () => {
    expect(indexSrc).toMatch(/handleGetUserPlan, handleCreateSubscription, handleActivateSubscription, handleGetPlans/);
    expect(indexSrc).toMatch(/path === '\/api\/subscription\/create' && method === 'POST'/);
    expect(indexSrc).toMatch(/await handleCreateSubscription\(request, env, authCtx\)/);
    expect(indexSrc).toMatch(/path === '\/api\/subscription\/activate' && method === 'POST'/);
    expect(indexSrc).toMatch(/await handleActivateSubscription\(request, env, authCtx\)/);
  });
});
