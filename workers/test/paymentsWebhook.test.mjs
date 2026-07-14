/* Tests — Razorpay webhook must apply the subscription tier upgrade when an
 * order's notes carry tenant_id+plan (the path used by
 * /api/subscription/checkout). Regression coverage for the bug where a
 * captured subscription payment never updated users.tier because the
 * webhook only knew about the per-report `payments` table. */
import { describe, it, expect, vi } from 'vitest';
import { handleRazorpayWebhook } from '../src/handlers/payments.js';
import { handleForgotPassword } from '../src/handlers/auth.js';

// vi.mock factories are hoisted above imports and can't close over top-level
// test-file variables — vi.hoisted() is the sanctioned way to share a mutable
// record between the factory and the assertions below.
const forgotPasswordCalls = vi.hoisted(() => ({ lastEmail: null }));

vi.mock('../src/handlers/auth.js', () => ({
  handleForgotPassword: vi.fn(async (request) => {
    // Request bodies are single-read streams — capture the parsed email here
    // rather than re-reading `request` from the assertion afterward.
    const body = await request.json();
    forgotPasswordCalls.lastEmail = body.email;
    return Response.json({ success: true });
  }),
}));

// The dispatch is a detached (unawaited) promise chain — give its microtasks
// a turn to run before asserting on the mock.
const flush = () => new Promise((r) => setTimeout(r, 0));

const WEBHOOK_SECRET = 'whsec_test_12345';

async function sign(secret, body) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(body));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function memDB({ paymentsRow = null, userRow = null } = {}) {
  const tierUpdates = [];
  const usersCreated = [];
  const paymentsEmailBackfills = [];
  return {
    tierUpdates, usersCreated, paymentsEmailBackfills,
    prepare(sql) {
      return {
        _sql: sql, _b: [],
        bind(...a) { this._b = a; return this; },
        async first() {
          if (/FROM payments WHERE razorpay_order_id/i.test(this._sql)) return paymentsRow;
          if (/FROM users WHERE email/i.test(this._sql))               return userRow;
          return null;
        },
        async run() {
          if (/UPDATE users SET tier/i.test(this._sql)) {
            tierUpdates.push({ tier: this._b[0], userId: this._b[1] });
          }
          if (/INSERT INTO users/i.test(this._sql)) {
            usersCreated.push({ email: this._b[1], tier: this._b[4] });
          }
          if (/UPDATE payments SET email/i.test(this._sql)) {
            paymentsEmailBackfills.push({ email: this._b[0], orderId: this._b[1] });
          }
          return { success: true };
        },
      };
    },
  };
}

async function webhookRequest(eventObj) {
  const rawBody = JSON.stringify(eventObj);
  const sig     = await sign(WEBHOOK_SECRET, rawBody);
  return new Request('https://x.test/api/webhooks/razorpay', {
    method: 'POST', headers: { 'x-razorpay-signature': sig }, body: rawBody,
  });
}

describe('handleRazorpayWebhook — subscription tier upgrade', () => {
  it('applies UPDATE users SET tier when notes carry tenant_id + a paid, grantable plan', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_1', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_1', order_id: 'order_1', notes: { tenant_id: 'user_123', plan: 'ENTERPRISE' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toEqual([{ tier: 'ENTERPRISE', userId: 'user_123' }]);
  });

  // 2026-07-14 Production Release Gate Phase II (H5): 'PRO' normalizes to
  // 'PROFESSIONAL' (subscriptionPaywallEngine.js's SUBSCRIPTION_TIERS
  // vocabulary), which auth/apiKeys.js's TIER_LIMITS (every real
  // quota/feature check) and the live users.tier schema CHECK constraint
  // don't recognize. Previously this write was still attempted — either
  // silently failing the CHECK constraint or, if it somehow succeeded,
  // leaving the customer's real entitlement unresolvable (TIER_LIMITS.PRO
  // vs TIER_LIMITS.PROFESSIONAL === undefined). Now skipped outright rather
  // than attempting a write to an entitlement that can't be resolved.
  it('does NOT apply a tier upgrade when the normalized tier has no TIER_LIMITS/schema-compatible entry (PRO -> PROFESSIONAL)', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_1b', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_1b', order_id: 'order_1b', notes: { tenant_id: 'user_123', plan: 'PRO' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
  });

  it('does not touch users.tier for a regular per-report payment (no plan/tenant_id in notes)', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_2', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_2', order_id: 'order_2', notes: { module: 'domain' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
  });

  it('does not apply a tier upgrade for a free/invalid plan value', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_3', event: 'order.paid',
      payload: { payment: { entity: {
        id: 'pay_3', order_id: 'order_3', notes: { tenant_id: 'user_456', plan: 'COMMUNITY' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
  });

  it('rejects a payload with an invalid webhook signature', async () => {
    const db  = memDB();
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const rawBody = JSON.stringify({
      id: 'evt_4', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_4', order_id: 'order_4', notes: { tenant_id: 'user_789', plan: 'PRO' } } } },
    });
    const request = new Request('https://x.test/api/webhooks/razorpay', {
      method: 'POST', headers: { 'x-razorpay-signature': 'deadbeef' }, body: rawBody,
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(401);
    expect(db.tierUpdates).toHaveLength(0);
  });
});

/* Regression coverage — the REAL live checkout (/api/payment/create-order
 * with module='subscription') never puts tenant_id/plan in the Razorpay
 * order notes, only {module, target: email}. The plan is only ever
 * persisted to the `payments` D1 row at order-creation time. Before this
 * fix, the webhook's only subscription-tier-grant branch required
 * notes.tenant_id + notes.plan — dead code for this flow — so a customer
 * whose browser closed right after paying (before the synchronous
 * /api/payment/verify call completed) was charged and never upgraded, with
 * no automatic recovery. */
describe('handleRazorpayWebhook — fallback subscription grant (real checkout flow)', () => {
  it('upgrades an existing user from the payments row when notes carry no plan', async () => {
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'ENTERPRISE', email: 'buyer@example.com', status: 'pending' },
      userRow:     { id: 'usr_1', tier: 'FREE' },
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_5', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_5', order_id: 'order_5', notes: { module: 'subscription', target: 'buyer@example.com' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toEqual([{ tier: 'ENTERPRISE', userId: 'usr_1' }]);
  });

  it('creates a new account at the paid tier if no account exists yet for that email', async () => {
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'MSSP', email: 'newbuyer@example.com', status: 'pending' },
      userRow:     null,
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_6', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_6', order_id: 'order_6', notes: { module: 'subscription', target: 'newbuyer@example.com' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.usersCreated).toEqual([{ email: 'newbuyer@example.com', tier: 'MSSP' }]);
  });

  it('does nothing extra for a non-subscription (per-report) payments row', async () => {
    const db = memDB({
      paymentsRow: { module: 'domain', plan: 'pay_per_report', email: 'reportbuyer@example.com', status: 'pending' },
      userRow:     { id: 'usr_2', tier: 'FREE' },
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_7', event: 'payment.captured',
      payload: { payment: { entity: { id: 'pay_7', order_id: 'order_7', notes: { module: 'domain' } } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toHaveLength(0);
    expect(db.usersCreated).toHaveLength(0);
  });
});

/* Regression coverage — 2026-07-10 production incident (pay_TBVXv75Tgm2Gla,
 * order paid via UPI QR scan, ₹499 Starter). Root cause: a visitor who lands
 * straight on pricing (no prior free-scan lead-capture, not logged in) has no
 * cdb_email in localStorage, so /api/payment/create-order writes the pending
 * `payments` row with email=NULL. The synchronous /api/payments/verify call
 * never ran (browser closed before Razorpay's success handler fired), so this
 * webhook fallback was the only remaining path to grant the tier — and it
 * required payRow.email, which was NULL, so it silently no-opped. The captured
 * payment settled to the merchant normally; the customer was simply never
 * upgraded, with no error anywhere in the logs. Razorpay's own checkout form
 * still collects the payer's email regardless of login state, so it is always
 * present on the webhook's payment.entity payload — this is what the fix reads
 * instead of assuming payments.email is populated. */
describe('handleRazorpayWebhook — fallback grant when payments.email is NULL (guest checkout)', () => {
  it('grants the tier using the Razorpay payload email and backfills payments.email', async () => {
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'STARTER', email: null, status: 'pending' },
      userRow:     null,
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_8', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_8', order_id: 'order_8',
        email: 'guest@example.com', contact: '+919999999999',
        notes: { module: 'subscription', target: 'starter' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.usersCreated).toEqual([{ email: 'guest@example.com', tier: 'STARTER' }]);
    expect(db.paymentsEmailBackfills).toEqual([{ email: 'guest@example.com', orderId: 'order_8' }]);
  });

  it('dispatches a real set-your-password link for a freshly-created account — not just a generic "log in" email that dead-ends', async () => {
    vi.mocked(handleForgotPassword).mockClear();
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'STARTER', email: null, status: 'pending' },
      userRow:     null,
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_8b', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_8b', order_id: 'order_8b', email: 'freshbuyer@example.com',
        notes: { module: 'subscription', target: 'starter' },
      } } },
    });

    await handleRazorpayWebhook(request, env);
    await flush();
    expect(handleForgotPassword).toHaveBeenCalledTimes(1);
    expect(forgotPasswordCalls.lastEmail).toBe('freshbuyer@example.com');
  });

  it('upgrades an existing account by the payload email when payments.email is NULL', async () => {
    vi.mocked(handleForgotPassword).mockClear();
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'PRO', email: null, status: 'pending' },
      userRow:     { id: 'usr_3', tier: 'FREE' },
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_9', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_9', order_id: 'order_9', email: 'returning@example.com',
        notes: { module: 'subscription', target: 'pro' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    await flush();
    expect(res.status).toBe(200);
    expect(db.tierUpdates).toEqual([{ tier: 'PRO', userId: 'usr_3' }]);
    // An existing account already has real credentials — must NOT get a
    // "reset your password" email just for being upgraded.
    expect(handleForgotPassword).not.toHaveBeenCalled();
  });

  it('still does not grant anything if neither payments.email nor the payload carries an email', async () => {
    const db = memDB({
      paymentsRow: { module: 'subscription', plan: 'STARTER', email: null, status: 'pending' },
      userRow:     null,
    });
    const env = { RAZORPAY_WEBHOOK_SECRET: WEBHOOK_SECRET, DB: db };
    const request = await webhookRequest({
      id: 'evt_10', event: 'payment.captured',
      payload: { payment: { entity: {
        id: 'pay_10', order_id: 'order_10', notes: { module: 'subscription', target: 'starter' },
      } } },
    });

    const res = await handleRazorpayWebhook(request, env);
    expect(res.status).toBe(200);
    expect(db.usersCreated).toHaveLength(0);
    expect(db.tierUpdates).toHaveLength(0);
  });
});
