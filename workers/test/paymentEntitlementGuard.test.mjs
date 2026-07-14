/* Payment → entitlement security guard.
 *
 * Journey-2 audit verdict: the revenue path is sound — order → Razorpay HMAC
 * signature verification (constant-time, fail-closed) → idempotency → tier
 * upgrade (whitelisted plans) → entitlement enforcement via authCtx.tier.
 *
 * These are the load-bearing security properties of the whole business: if a
 * refactor ever drops the signature gate or lets an arbitrary tier through,
 * anyone could self-upgrade to PRO/ENTERPRISE for free. This guard fails CI if
 * that protection is weakened.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');

describe('payment signature verification (lib/razorpay.js)', () => {
  const src = read('src/lib/razorpay.js');
  it('is a real HMAC-SHA256 over orderId|paymentId, not a stub', () => {
    expect(src).toMatch(/name:\s*'HMAC'[\s\S]*hash:\s*'SHA-256'/);
    expect(src).toMatch(/\$\{orderId\}\|\$\{paymentId\}/);
  });
  it('fails closed when the secret is absent', () => {
    expect(/if\s*\(!env\.RAZORPAY_KEY_SECRET\)\s*return false/.test(src)).toBe(true);
  });
  it('uses a constant-time comparison (no timing oracle)', () => {
    expect(/constantTimeEqual\(computed,\s*signature\)/.test(src)).toBe(true);
  });
});

describe('verify handler gates entitlement behind a valid signature', () => {
  const src = read('src/handlers/payments.js');
  it('verifies the signature and rejects before any fulfillment', () => {
    const sigIdx = src.indexOf('verifyPaymentSignature(env');
    const rejectIdx = src.indexOf("Payment signature invalid");
    const firstTierUpdate = src.indexOf('UPDATE users SET tier');
    expect(sigIdx).toBeGreaterThan(-1);
    expect(rejectIdx).toBeGreaterThan(sigIdx);        // reject path exists after the check
    expect(firstTierUpdate).toBeGreaterThan(rejectIdx); // tier upgrade happens only afterwards
  });
  it('only upgrades to a whitelisted tier (no arbitrary tier injection)', () => {
    // Consolidated into a shared GRANTABLE_SUBSCRIPTION_PLANS constant
    // (2026-07-14 commercial-integrity audit, H8/H5) — same four literal
    // values, now reused by handleCreateOrder's up-front plan validation too.
    expect(src).toMatch(/const GRANTABLE_SUBSCRIPTION_PLANS\s*=\s*\['STARTER',\s*'PRO',\s*'ENTERPRISE',\s*'MSSP'\]/);
    expect(src).toMatch(/GRANTABLE_SUBSCRIPTION_PLANS\.includes\(plan\)/);
  });
});
