/* Tests — /api/subscription/checkout must require an authenticated tenant
 * (so a captured payment always has a real users.id row to upgrade) and must
 * forward tenant_id in the Razorpay order notes so the payment.captured
 * webhook can apply the tier upgrade. Regression coverage for the bug where
 * checkout took payment but never granted the paid tier. */
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
      req({ plan: 'PRO', email: 'a@b.com' }),
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
      return { ok: true, json: async () => ({ id: 'order_abc', amount: 149900 }) };
    }));

    const env     = { RAZORPAY_KEY_ID: 'key_test', RAZORPAY_KEY_SECRET: 'secret_test' };
    const authCtx = { userId: 'user_123' };
    const res = await handleSubscriptionCheckout(req({ plan: 'PRO', email: 'a@b.com' }), env, authCtx);

    expect(res.status).toBe(200);
    expect(capturedBody.notes).toEqual({
      plan: 'PROFESSIONAL', email: 'a@b.com', tenant_id: 'user_123', platform: 'cyberdudebivash.in',
    });

    const body = await res.json();
    expect(body.order_id).toBe('order_abc');
    expect(body.plan).toBe('PROFESSIONAL');
  });
});
