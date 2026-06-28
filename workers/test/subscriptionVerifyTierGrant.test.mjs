/* Regression coverage — POST /api/payments/verify with module:'subscription'
 * (the path actually wired to the homepage's "Upgrade" buttons via
 * cdbStartSubscriptionAuto -> /api/payments/create-order + /verify) used to
 * write a `subscriptions` table row and a KV `sub_session:` token but NEVER
 * upgraded users.tier and never issued a JWT. Every PRO/ENTERPRISE-gated
 * endpoint (e.g. /api/scan/threat-intel-report) checks authCtx.tier, which
 * resolveAuthV5() derives only from a JWT or DB-backed API key — never from
 * that KV session. Customers paying for PRO/ENTERPRISE got "payment
 * successful" but stayed 403'd on the feature they bought. Found during the
 * EY/Accenture AI Threat Intel Report pre-subscription audit. */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { handleVerifyPayment } from '../src/handlers/payments.js';

const RAZORPAY_KEY_SECRET = 'test_secret_key_for_hmac';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeEnv({ existingUser = null } = {}) {
  const kvStore = new Map();
  const refreshTokens = [];
  const env = {
    RAZORPAY_KEY_ID: 'rzp_test_key',
    RAZORPAY_KEY_SECRET,
    JWT_SECRET: 'jwt_test_secret',
    SECURITY_HUB_KV: {
      async put(k, v, opts) { kvStore.set(k, v); },
      async get(k) { return kvStore.get(k) || null; },
    },
    DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async first() {
            if (/SELECT report_token FROM payments/.test(sql)) return null;
            if (/SELECT id FROM users WHERE email/.test(sql)) return existingUser;
            return null;
          },
          async run() {
            if (/UPDATE payments SET status='paid'/.test(sql)) return { success: true };
            if (/INSERT OR IGNORE INTO subscriptions/.test(sql)) return { success: true };
            if (/UPDATE users SET tier/.test(sql)) {
              env.__tierUpdate = { tier: bound[0], userId: bound[1] };
              return { success: true };
            }
            if (/INSERT INTO users/.test(sql)) {
              env.__userInsert = { id: bound[0], email: bound[1], tier: bound[4] };
              return { success: true };
            }
            if (/INSERT INTO refresh_tokens|INSERT OR REPLACE INTO refresh_tokens/.test(sql)) {
              refreshTokens.push(bound);
              return { success: true };
            }
            return { success: true };
          },
          async all() { return { results: [] }; },
        };
      },
    },
  };
  return env;
}

function req(body) {
  return new Request('https://x.test/api/payments/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('handleVerifyPayment — subscription tier grant', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('grants real users.tier and issues a usable JWT for a PRO subscription', async () => {
    const orderId   = 'order_abc123';
    const paymentId = 'pay_abc123';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
    const env = makeEnv({ existingUser: null });

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'subscription',
      plan: 'PRO',
      target: 'pro',
      email: 'buyer@example.com',
    }), env, {});

    expect(res.status).toBe(200);
    const body = await res.json();

    // The bug: this used to be undefined, so the frontend's
    // `if (vData.token)` branch never ran and the tier was never persisted.
    expect(body.token).toBeTruthy();
    expect(body.user_id).toBeTruthy();

    // users.tier must actually be written for a brand-new account.
    expect(env.__userInsert).toBeTruthy();
    expect(env.__userInsert.tier).toBe('PRO');
    expect(env.__userInsert.email).toBe('buyer@example.com');
  });

  it('upgrades an existing user row instead of creating a duplicate', async () => {
    const orderId   = 'order_def456';
    const paymentId = 'pay_def456';
    const signature = await hmac(RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
    const env = makeEnv({ existingUser: { id: 'usr_existing_1' } });

    const res = await handleVerifyPayment(req({
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      razorpay_signature: signature,
      module: 'subscription',
      plan: 'ENTERPRISE',
      target: 'enterprise',
      email: 'existing@example.com',
    }), env, {});

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token).toBeTruthy();
    expect(body.user_id).toBe('usr_existing_1');

    expect(env.__userInsert).toBeFalsy();
    expect(env.__tierUpdate).toEqual({ tier: 'ENTERPRISE', userId: 'usr_existing_1' });
  });
});
