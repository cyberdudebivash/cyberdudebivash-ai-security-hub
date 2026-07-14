/* Tests — /api/subscription/checkout must require an authenticated tenant
 * (so a captured payment always has a real users.id row to upgrade) and must
 * forward tenant_id in the Razorpay order notes so the payment.captured
 * webhook can apply the tier upgrade. Regression coverage for the bug where
 * checkout took payment but never granted the paid tier.
 *
 * 2026-07-14 Production Release Gate Phase II (H5): PRO/TEAM/BUSINESS all
 * normalize to a SUBSCRIPTION_TIERS tier (PROFESSIONAL/TEAM/BUSINESS) that
 * auth/apiKeys.js's TIER_LIMITS (the table every real quota/feature check
 * actually consults) and the live users.tier schema CHECK constraint don't
 * recognize — the webhook grant would either violate the CHECK constraint or
 * silently degrade the customer to FREE-tier limits. handleSubscriptionCheckout
 * now refuses checkout for any such tier rather than take payment for one
 * that can't be granted. Only ENTERPRISE (the one paid SUBSCRIPTION_TIERS
 * name TIER_LIMITS also defines) still completes checkout via this endpoint —
 * used below in place of the original tests' 'PRO' so the auth/free-plan
 * assertions aren't conflated with this separate provisionability gate. */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { handleSubscriptionCheckout } from '../src/handlers/subscriptionPaywallEngine.js';

function req(body) {
  return new Request('https://x.test/api/subscription/checkout', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

describe('handleSubscriptionCheckout', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('rejects checkout with no authenticated tenant (401)', async () => {
    const res = await handleSubscriptionCheckout(
      req({ plan: 'ENTERPRISE', email: 'a@b.com' }),
      { RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's' },
      {},
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toMatch(/Login required/i);
  });

  it('rejects a free/invalid plan regardless of auth (400, before touching Razorpay)', async () => {
    const res = await handleSubscriptionCheckout(
      req({ plan: 'COMMUNITY' }), {}, { userId: 'user_123' },
    );
    expect(res.status).toBe(400);
  });

  it('forwards tenant_id in the Razorpay order notes for an authenticated checkout', async () => {
    let capturedBody;
    vi.stubGlobal('fetch', vi.fn(async (_url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return { ok: true, json: async () => ({ id: 'order_abc', amount: 4999900 }) };
    }));

    const env     = { RAZORPAY_KEY_ID: 'key_test', RAZORPAY_KEY_SECRET: 'secret_test' };
    const authCtx = { userId: 'user_123' };
    const res = await handleSubscriptionCheckout(req({ plan: 'ENTERPRISE', email: 'a@b.com' }), env, authCtx);

    expect(res.status).toBe(200);
    expect(capturedBody.notes).toEqual({
      plan: 'ENTERPRISE', email: 'a@b.com', tenant_id: 'user_123', platform: 'cyberdudebivash.in',
    });

    const body = await res.json();
    expect(body.order_id).toBe('order_abc');
    expect(body.plan).toBe('ENTERPRISE');
  });

  describe('H5 — refuses checkout for a tier this platform cannot actually grant', () => {
    it('rejects PRO (normalizes to PROFESSIONAL) with 409, never reaching Razorpay', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      const res = await handleSubscriptionCheckout(
        req({ plan: 'PRO', email: 'a@b.com' }),
        { RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's' },
        { userId: 'user_123' },
      );
      expect(res.status).toBe(409);
      const body = await res.json();
      expect(body.code).toBe('PLAN_NOT_PROVISIONABLE');
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('rejects TEAM with 409', async () => {
      const res = await handleSubscriptionCheckout(
        req({ plan: 'TEAM' }), { RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's' }, { userId: 'user_123' },
      );
      expect(res.status).toBe(409);
    });

    it('rejects BUSINESS with 409', async () => {
      const res = await handleSubscriptionCheckout(
        req({ plan: 'BUSINESS' }), { RAZORPAY_KEY_ID: 'k', RAZORPAY_KEY_SECRET: 's' }, { userId: 'user_123' },
      );
      expect(res.status).toBe(409);
    });
  });
});
