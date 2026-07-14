/* Payment-signature verification hardening (2026-07-14 commercial-integrity
 * audit / Enterprise Commercial Product Registry pass).
 *
 * lib/razorpay.js's canonical verifyPaymentSignature() has used a
 * constant-time comparison (constantTimeEqual) since it was written. Seven
 * other payment-verification handlers reimplemented the same HMAC check
 * inline but compared with a plain !==/===, never adopting the canonical
 * helper. This file locks in two things per handler:
 *   1. constantTimeEqual is now exported from lib/razorpay.js and reused —
 *      valid signatures still pass, invalid ones still fail.
 *   2. Two of the seven (growth.js handleBillingCallback,
 *      revenue.js handleCheckoutVerify) had a structural gap beyond the
 *      comparison method: verification could be skipped outright (missing
 *      webhook secret, or simply omitting razorpay_order_id/razorpay_signature
 *      from the request body) and the call would still proceed to grant a
 *      plan/product. Both now fail closed instead.
 *
 * None of these 7 handlers had prior test coverage except academyMarketplace
 * (workers/test/academyFulfillment.test.mjs, unaffected by this change and
 * not duplicated here).
 */
import { describe, it, expect } from 'vitest';
import { constantTimeEqual } from '../src/lib/razorpay.js';
import { handleVerifyTool } from '../src/handlers/toolsMarketplace.js';
import { handleSentinelVerify } from '../src/handlers/sentinelMarketplace.js';
import { handleVerifyPurchase } from '../src/handlers/defenseMarketplace.js';
import { handleVerifyEnterprisePayment } from '../src/handlers/enterpriseLayer.js';
import { handleBillingCallback } from '../src/handlers/growth.js';
import { handleCheckoutVerify } from '../src/handlers/revenue.js';

const SECRET = 'test_razorpay_secret';

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function req(body) {
  return new Request('https://x/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}),
  });
}

function nullDB() {
  const stmt = { bind() { return this; }, async first() { return null; }, async run() { return { meta: {} }; } };
  return { prepare: () => stmt };
}

describe('constantTimeEqual (lib/razorpay.js)', () => {
  it('is exported and behaves like string equality for equal-length inputs', () => {
    expect(constantTimeEqual('abc123', 'abc123')).toBe(true);
    expect(constantTimeEqual('abc123', 'abc124')).toBe(false);
  });
  it('returns false (not a throw) for mismatched lengths', () => {
    expect(constantTimeEqual('short', 'muchlonger')).toBe(false);
  });
});

describe('toolsMarketplace.js handleVerifyTool — adopts constant-time comparison', () => {
  it('rejects a tampered signature', async () => {
    const r = await handleVerifyTool(req({
      razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1', razorpay_signature: 'wrong', product_id: 'domain_scanner',
    }), { RAZORPAY_KEY_SECRET: SECRET });
    const d = await r.json();
    expect(d.success).toBe(false);
    expect(d.error).toMatch(/signature/i);
  });

  it('accepts a genuine signature and proceeds past the signature check', async () => {
    const sig = await hmac(SECRET, 'order_2|pay_2');
    const r = await handleVerifyTool(req({
      razorpay_order_id: 'order_2', razorpay_payment_id: 'pay_2', razorpay_signature: sig, product_id: 'domain_scanner',
    }), { RAZORPAY_KEY_SECRET: SECRET });
    const d = await r.json();
    expect(d.success).toBe(true);
  });
});

describe('sentinelMarketplace.js handleSentinelVerify — adopts constant-time comparison', () => {
  it('rejects a tampered signature', async () => {
    const r = await handleSentinelVerify(req({
      razorpay_order_id: 'order_3', razorpay_payment_id: 'pay_3', razorpay_signature: 'wrong', product_type: 'cve_report',
    }), { RAZORPAY_KEY_SECRET: SECRET });
    const d = await r.json();
    expect(d.success).toBe(false);
    expect(d.error).toMatch(/signature/i);
  });

  it('accepts a genuine signature and proceeds past the signature check', async () => {
    const sig = await hmac(SECRET, 'order_4|pay_4');
    const r = await handleSentinelVerify(req({
      razorpay_order_id: 'order_4', razorpay_payment_id: 'pay_4', razorpay_signature: sig, product_type: 'cve_report',
    }), { RAZORPAY_KEY_SECRET: SECRET });
    const d = await r.json();
    expect(d.success).toBe(true);
  });
});

describe('defenseMarketplace.js handleVerifyPurchase — adopts constant-time comparison', () => {
  it('rejects a tampered signature', async () => {
    const r = await handleVerifyPurchase(req({
      razorpay_order_id: 'order_5', razorpay_payment_id: 'pay_5', razorpay_signature: 'wrong',
    }), { RAZORPAY_KEY_SECRET: SECRET, DB: nullDB() }, {}, 'sol_1');
    const d = await r.json();
    expect(d.success).toBe(false);
    expect(d.error).toMatch(/signature/i);
  });

  it('accepts a genuine signature and proceeds past the signature check', async () => {
    const sig = await hmac(SECRET, 'order_6|pay_6');
    const r = await handleVerifyPurchase(req({
      razorpay_order_id: 'order_6', razorpay_payment_id: 'pay_6', razorpay_signature: sig,
    }), { RAZORPAY_KEY_SECRET: SECRET, DB: nullDB() }, {}, 'sol_1');
    const d = await r.json();
    // Proceeds to the (unmocked) solution lookup, which correctly 404s — the
    // point here is it's no longer rejected for "signature mismatch".
    expect(d.error).not.toMatch(/signature/i);
  });
});

describe('enterpriseLayer.js handleVerifyEnterprisePayment — adopts constant-time comparison', () => {
  it('rejects a tampered signature', async () => {
    const r = await handleVerifyEnterprisePayment(req({
      razorpay_order_id: 'order_7', razorpay_payment_id: 'pay_7', razorpay_signature: 'wrong',
    }), { RAZORPAY_KEY_SECRET: SECRET }, {});
    const d = await r.json();
    expect(d.success).toBe(false);
    expect(d.error).toMatch(/signature|mismatch/i);
  });

  it('accepts a genuine signature and proceeds past the signature check', async () => {
    const sig = await hmac(SECRET, 'order_8|pay_8');
    const r = await handleVerifyEnterprisePayment(req({
      razorpay_order_id: 'order_8', razorpay_payment_id: 'pay_8', razorpay_signature: sig,
      // enterprise_order_id omitted deliberately — skips the unguarded env.DB.prepare() branch
    }), { RAZORPAY_KEY_SECRET: SECRET }, {});
    const d = await r.json();
    expect(d.success).toBe(true);
  });
});

describe('growth.js handleBillingCallback — fails closed instead of skipping verification', () => {
  it('previously: no RAZORPAY_WEBHOOK_SECRET logged a warning and continued anyway; now: rejects', async () => {
    const r = await handleBillingCallback(req({
      event: 'payment.captured', email: 'x@example.com', plan: 'ENTERPRISE',
      razorpay_payment_id: 'pay_9', razorpay_order_id: 'order_9', razorpay_signature: 'anything',
    }), {});
    expect(r.status).toBe(401);
    const d = await r.json();
    expect(d.error).toBe('webhook_not_configured');
  });

  it('rejects when razorpay_signature is omitted even though a secret is configured', async () => {
    const r = await handleBillingCallback(req({
      event: 'payment.captured', email: 'x@example.com', plan: 'ENTERPRISE',
      razorpay_payment_id: 'pay_10', razorpay_order_id: 'order_10',
    }), { RAZORPAY_WEBHOOK_SECRET: SECRET });
    expect(r.status).toBe(401);
  });

  it('rejects a tampered signature', async () => {
    const r = await handleBillingCallback(req({
      event: 'payment.captured', email: 'x@example.com', plan: 'ENTERPRISE',
      razorpay_payment_id: 'pay_11', razorpay_order_id: 'order_11', razorpay_signature: 'wrong',
    }), { RAZORPAY_WEBHOOK_SECRET: SECRET });
    expect(r.status).toBe(401);
  });

  it('documents a separate, pre-existing design gap: no request can ever pass this check, since the HMAC is computed over the whole raw body INCLUDING the razorpay_signature field itself — not fixed here, out of scope for this pass', async () => {
    const body = { event: 'payment.captured', email: 'x@example.com', plan: 'ENTERPRISE', razorpay_payment_id: 'pay_12', razorpay_order_id: 'order_12' };
    const sig = await hmac(SECRET, JSON.stringify({ ...body, razorpay_signature: 'placeholder' }));
    const r = await handleBillingCallback(new Request('https://x/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, razorpay_signature: sig }),
    }), { RAZORPAY_WEBHOOK_SECRET: SECRET });
    // Substituting the real signature into the body changes the raw bytes from
    // whatever was signed, so this can never match — confirmed still fails
    // closed (401) rather than silently succeeding, but this endpoint's
    // verification design appears unable to ever accept a legitimate call as
    // currently written. Flagged in the registry as its own finding.
    expect(r.status).toBe(401);
  });
});

describe('revenue.js handleCheckoutVerify — signature check is no longer skippable', () => {
  it('previously: omitting razorpay_order_id/razorpay_signature skipped verification entirely and granted a plan; now: rejects', async () => {
    const r = await handleCheckoutVerify(req({
      razorpay_payment_id: 'pay_13', plan: 'ENTERPRISE', email: 'x@example.com',
    }), { RAZORPAY_KEY_SECRET: SECRET }, {});
    const d = await r.json();
    expect(d.success).toBe(false);
    expect(d.code).toBe('MISSING_PAYMENT_ID');
  });

  it('rejects a tampered signature', async () => {
    const r = await handleCheckoutVerify(req({
      razorpay_payment_id: 'pay_14', razorpay_order_id: 'order_14', razorpay_signature: 'wrong', plan: 'ENTERPRISE',
    }), { RAZORPAY_KEY_SECRET: SECRET }, {});
    const d = await r.json();
    expect(d.success).toBe(false);
    expect(d.code).toBe('INVALID_SIGNATURE');
  });

  it('accepts a genuine signature and proceeds past the signature check', async () => {
    const sig = await (async () => {
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const buf = await crypto.subtle.sign('HMAC', key, enc.encode('order_15|pay_15'));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    })();
    const r = await handleCheckoutVerify(req({
      razorpay_payment_id: 'pay_15', razorpay_order_id: 'order_15', razorpay_signature: sig,
      product: 'defense_pack_1', email: 'x@example.com',
    }), { RAZORPAY_KEY_SECRET: SECRET, DB: nullDB(), SECURITY_HUB_KV: { put: async () => {} } }, {});
    const d = await r.json();
    expect(d.code).not.toBe('INVALID_SIGNATURE');
    expect(d.success).toBe(true);
  });
});
