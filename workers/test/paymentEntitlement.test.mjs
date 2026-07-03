/**
 * Integration test — Razorpay capture → entitlement grant.
 *
 * Drives the REAL handleRazorpayWebhook with a REAL HMAC-signed `payment.captured`
 * event and asserts the full capture→entitlement chain:
 *   • signature verification (real crypto.subtle path, not mocked),
 *   • payment row flips to 'paid',
 *   • users.tier is upgraded to the purchased plan (the entitlement),
 *   • invalid signature is rejected 401,
 *   • replayed event is idempotent (D1 dedup) — no double grant.
 *
 * Only network/side-effect deps (email, lifecycle, invoice, revenue-share, scans)
 * are mocked; the signature, tier-normalization, and grant logic run for real.
 * This converts "code complete, not exercised end-to-end" into "capture→entitlement
 * proven at the integration boundary". The one remaining unproven hop is Razorpay's
 * network delivery of the webhook itself (see scripts/verify-external-integrations.sh).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mock only heavy / side-effecting deps (keep razorpay.js + tier logic REAL) ──
vi.mock('../src/lib/htmlReport.js',   () => ({ generateHTMLReport: vi.fn() }));
vi.mock('../src/lib/reportEngine.js', () => ({ buildReport: vi.fn() }));
vi.mock('../src/handlers/analytics.js', () => ({ trackEvent: vi.fn(async () => {}) }));
vi.mock('../src/services/emailEngine.js', () => ({ sendPurchaseConfirmation: vi.fn(async () => {}) }));
vi.mock('../src/services/v24/billingEngine.js', () => ({ createInvoice: vi.fn(async () => {}) }));
vi.mock('../src/services/lifecycleEngine.js', () => ({ triggerPostPurchase: vi.fn(async () => {}), normalizeRevenueSource: vi.fn(s => s) }));
vi.mock('../src/handlers/msspRevenue.js', () => ({ resolvePartnerIdForEmail: vi.fn(async () => null), recordRevenueShare: vi.fn(async () => {}) }));
vi.mock('../src/handlers/domain.js',     () => ({ handleDomainScan: vi.fn() }));
vi.mock('../src/handlers/ai.js',         () => ({ handleAIScan: vi.fn() }));
vi.mock('../src/handlers/redteam.js',    () => ({ handleRedteamScan: vi.fn() }));
vi.mock('../src/handlers/identity.js',   () => ({ handleIdentityScan: vi.fn() }));
vi.mock('../src/handlers/compliance.js', () => ({ handleCompliance: vi.fn() }));

import { handleRazorpayWebhook } from '../src/handlers/payments.js';

const SECRET = 'whsec_test_cdb_123';

// Compute a real Razorpay-style webhook signature: HMAC-SHA256(rawBody) hex.
async function sign(rawBody, secret = SECRET) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(rawBody));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Stateful mock D1 that models the exact rows the webhook reads/writes.
function makeDB(initial) {
  const state = {
    webhookEvents: new Set(),
    payment: initial.payment,           // { id, status, email, module, amount, partner_id, plan }
    user:    initial.user,              // { id, tier } | null
    granted: [],                        // records of UPDATE users SET tier
    createdUser: null,
  };
  function prepare(sql) {
    const stmt = {
      _b: [],
      bind(...a) { this._b = a; return this; },
      async run() {
        const binds = this._b;
        if (/INSERT OR IGNORE INTO webhook_events/i.test(sql)) {
          const id = binds[0];
          if (state.webhookEvents.has(id)) return { meta: { changes: 0 } };
          state.webhookEvents.add(id);
          return { meta: { changes: 1 } };
        }
        if (/UPDATE payments SET/i.test(sql)) { if (state.payment) state.payment.status = 'paid'; return { meta: { changes: 1 } }; }
        if (/UPDATE users SET tier/i.test(sql)) { const tier = binds[0]; if (state.user) state.user.tier = tier; state.granted.push(tier); return { meta: { changes: 1 } }; }
        if (/INSERT INTO users/i.test(sql)) { state.createdUser = { id: binds[0], email: binds[1], tier: binds[4] }; state.granted.push(binds[4]); return { meta: { changes: 1 } }; }
        return { meta: { changes: 0 } };
      },
      async first() {
        if (/FROM payments WHERE razorpay_order_id/i.test(sql)) return state.payment;
        if (/FROM users WHERE email/i.test(sql))                return state.user;
        return null;
      },
    };
    return stmt;
  }
  return { prepare, _state: state };
}

function makeEnv(db) {
  return {
    RAZORPAY_WEBHOOK_SECRET: SECRET,
    DB: db,
    SECURITY_HUB_KV: { get: async () => null, put: async () => {} },
  };
}

function captureEvent({ orderId = 'order_ABC', paymentId = 'pay_XYZ', email = 'buyer@corp.com', amount = 149900 } = {}) {
  return {
    event: 'payment.captured',
    id: `evt_${orderId}_${paymentId}`,
    payload: { payment: { entity: { id: paymentId, order_id: orderId, email, amount, contact: null, notes: {} } } },
  };
}

async function post(env, event, sigOverride) {
  const raw = JSON.stringify(event);
  const sig = sigOverride ?? await sign(raw);
  const req = new Request('https://api.cyberdudebivash.test/api/webhooks/razorpay', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-razorpay-signature': sig }, body: raw,
  });
  return handleRazorpayWebhook(req, env);
}

describe('Razorpay capture → entitlement (integration)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('a valid payment.captured upgrades users.tier to the purchased plan', async () => {
    const db = makeDB({
      payment: { id: 'p1', status: 'pending', email: 'buyer@corp.com', module: 'subscription', amount: 149900, partner_id: null, plan: 'PRO' },
      user:    { id: 'user-1', tier: 'FREE' },
    });
    const res  = await post(makeEnv(db), captureEvent());
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.received).toBe(true);
    expect(body.duplicate).toBeUndefined();
    expect(db._state.payment.status).toBe('paid');      // payment captured
    expect(db._state.user.tier).toBe('PRO');            // ENTITLEMENT granted
    expect(db._state.granted).toContain('PRO');
  });

  it('rejects an INVALID signature with 401 and grants nothing', async () => {
    const db = makeDB({
      payment: { id: 'p1', status: 'pending', email: 'buyer@corp.com', module: 'subscription', amount: 149900, partner_id: null, plan: 'PRO' },
      user:    { id: 'user-1', tier: 'FREE' },
    });
    const res = await post(makeEnv(db), captureEvent(), 'deadbeef_not_a_real_signature');
    expect(res.status).toBe(401);
    expect(db._state.user.tier).toBe('FREE');           // no grant on bad signature
    expect(db._state.granted).toHaveLength(0);
  });

  it('is idempotent on replay — a duplicated event never double-grants', async () => {
    const db = makeDB({
      payment: { id: 'p1', status: 'pending', email: 'buyer@corp.com', module: 'subscription', amount: 149900, partner_id: null, plan: 'PRO' },
      user:    { id: 'user-1', tier: 'FREE' },
    });
    const env = makeEnv(db);
    const first  = await (await post(env, captureEvent())).json();
    const second = await (await post(env, captureEvent())).json();

    expect(first.received).toBe(true);
    expect(second.duplicate).toBe(true);               // D1 dedup caught the replay
    expect(db._state.granted).toEqual(['PRO']);        // exactly one grant, not two
  });

  it('safety-net: creates the account + grants tier when the buyer had no user row', async () => {
    const db = makeDB({
      payment: { id: 'p1', status: 'pending', email: 'new@corp.com', module: 'subscription', amount: 499900, partner_id: null, plan: 'ENTERPRISE' },
      user:    null,   // browser callback never created the account
    });
    const res = await post(makeEnv(db), captureEvent({ email: 'new@corp.com', amount: 499900 }));
    expect(res.status).toBe(200);
    expect(db._state.createdUser).toBeTruthy();
    expect(db._state.createdUser.tier).toBe('ENTERPRISE');   // charged customer is never left un-provisioned
  });
});
