/* Payment → entitlement E2E — the full customer money path, driven through
 * the real exported worker.fetch():
 *
 *   1. FREE caller hits the PRO-gated /api/ai/simulate → 402 ERR_PLAN_REQUIRED
 *   2. POST /api/payments/verify with a genuinely HMAC-SHA256-signed Razorpay
 *      payload (module:'subscription', plan:'PRO') → users.tier written,
 *      subscriptions row persisted, real JWT minted with tier:PRO
 *   3. The SAME endpoint called with that JWT → 200 (feature unlocked)
 *   4. A tampered signature → 400, and NO tier is granted
 *
 * This is the acceptance-board blocker "payment→entitlement never demonstrated
 * end-to-end": every hop (signature crypto, D1 writes, JWT mint, resolveAuthV5
 * verification, plan matrix gate) is the production code path — only the D1/KV
 * bindings are in-memory stubs.
 */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';
const JWT_SECRET = 'jwt_e2e_test_secret';

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv() {
  const kvStore = new Map();
  const writes = { users: [], tierUpdates: [], subscriptions: [], refreshTokens: [] };
  const env = {
    RAZORPAY_KEY_ID: 'rzp_test_key',
    RAZORPAY_KEY_SECRET,
    JWT_SECRET,
    __writes: writes,
    SECURITY_HUB_KV: {
      async put(k, v) { kvStore.set(k, v); },
      async get(k) { return kvStore.has(k) ? kvStore.get(k) : null; },
      async delete(k) { kvStore.delete(k); },
      async list() { return { keys: [] }; },
    },
    DB: {
      prepare(sql) {
        let bound = [];
        const stmt = {
          bind(...a) { bound = a; return stmt; },
          async first() {
            if (/SELECT report_token FROM payments/.test(sql)) return null;
            if (/SELECT id FROM users WHERE email/.test(sql)) return null; // new buyer
            return null;
          },
          async run() {
            if (/INSERT INTO users/.test(sql)) writes.users.push({ id: bound[0], email: bound[1], tier: bound[4] });
            if (/UPDATE users SET tier/.test(sql)) writes.tierUpdates.push({ tier: bound[0], userId: bound[1] });
            if (/INSERT OR IGNORE INTO subscriptions/.test(sql)) writes.subscriptions.push({ plan: bound[3] });
            if (/refresh_tokens/.test(sql)) writes.refreshTokens.push(bound);
            return { success: true, meta: { changes: 1 } };
          },
          async all() { return { results: [] }; },
        };
        return stmt;
      },
      async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
    },
  };
  env.KV = env.SECURITY_HUB_KV;
  env.SECURITY_HUB_DB = env.DB;
  return env;
}
function ctxStub() { return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } }; }

const SIM_BODY = JSON.stringify({
  scan_result: { risk_score: 72, findings: [{ severity: 'HIGH', title: 'SPF missing' }] },
  module: 'domain',
  target: 'example.com',
});

describe('payment → entitlement E2E (real worker.fetch, real crypto)', () => {
  it('FREE→402, signed PRO purchase→JWT, JWT→200 on the same gated endpoint', async () => {
    const env = makeEnv();

    // 1) Before purchase: anonymous FREE caller is blocked by the plan gate.
    const before = await worker.fetch(new Request('https://cyberdudebivash.in/api/ai/simulate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: SIM_BODY,
    }), env, ctxStub());
    expect(before.status).toBe(402);
    const beforeBody = await before.json();
    expect(beforeBody.required_plan).toBe('PRO');

    // 2) Purchase: correctly signed Razorpay verification for a PRO subscription.
    const orderId = 'order_e2e12345', paymentId = 'pay_e2e12345';
    const signature = await hmacHex(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
    const verify = await worker.fetch(new Request('https://cyberdudebivash.in/api/payments/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature,
        module: 'subscription', plan: 'PRO', target: 'pro', email: 'buyer@enterprise-corp.com',
      }),
    }), env, ctxStub());
    expect(verify.status).toBe(200);
    const vBody = await verify.json();
    expect(vBody.success).toBe(true);
    expect(vBody.token).toBeTruthy();          // real JWT, minted with tier:PRO
    expect(vBody.refresh_token).toBeTruthy();  // session survives the 15-min access TTL

    // Persistence: account created at PRO + subscriptions row written.
    expect(env.__writes.users).toEqual([expect.objectContaining({ email: 'buyer@enterprise-corp.com', tier: 'PRO' })]);
    expect(env.__writes.subscriptions).toEqual([{ plan: 'PRO' }]);
    expect(env.__writes.refreshTokens.length).toBeGreaterThan(0);

    // 3) After purchase: the SAME endpoint with the minted JWT is unlocked.
    const after = await worker.fetch(new Request('https://cyberdudebivash.in/api/ai/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${vBody.token}` },
      body: SIM_BODY,
    }), env, ctxStub());
    expect(after.status).toBe(200);
    const simBody = await after.json();
    expect(simBody.simulation_id || simBody.data?.simulation_id || simBody.attack_paths || simBody.data).toBeTruthy();
  });

  it('a tampered signature is rejected and grants nothing', async () => {
    const env = makeEnv();
    const badSig = await hmacHex('wrong_secret', 'order_evil12345|pay_evil12345');
    const res = await worker.fetch(new Request('https://cyberdudebivash.in/api/payments/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        razorpay_order_id: 'order_evil12345', razorpay_payment_id: 'pay_evil12345', razorpay_signature: badSig,
        module: 'subscription', plan: 'ENTERPRISE', target: 'enterprise', email: 'attacker@evil.com',
      }),
    }), env, ctxStub());
    expect(res.status).toBe(400);
    expect(env.__writes.users).toEqual([]);
    expect(env.__writes.tierUpdates).toEqual([]);
    expect(env.__writes.subscriptions).toEqual([]);
  });

  it('STARTER purchase does NOT unlock the PRO-gated endpoint (no over-grant)', async () => {
    const env = makeEnv();
    const orderId = 'order_starter123', paymentId = 'pay_starter123';
    const signature = await hmacHex(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
    const verify = await worker.fetch(new Request('https://cyberdudebivash.in/api/payments/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature,
        module: 'subscription', plan: 'STARTER', target: 'starter', email: 'starter@corp.com',
      }),
    }), env, ctxStub());
    const vBody = await verify.json();
    expect(vBody.token).toBeTruthy();

    const after = await worker.fetch(new Request('https://cyberdudebivash.in/api/ai/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${vBody.token}` },
      body: SIM_BODY,
    }), env, ctxStub());
    expect(after.status).toBe(402); // STARTER stays below the PRO gate
  });
});
