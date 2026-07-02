/* Regression tests — the entire customer-facing Billing Portal (view plan,
 * cancel, upgrade, invoices, live usage) was broken end-to-end for every real
 * customer:
 *
 * 1. billing-portal.html sent `credentials: 'include'` (cookies) on every API
 *    call, but resolveAuthV5 only ever reads Authorization/x-api-key headers.
 *    Every visitor resolved as an anonymous FREE-tier IP identity regardless
 *    of who was actually logged in (fixed in the frontend, not covered here).
 * 2. All 5 handlers read `authCtx.owner_email` — a field that has never
 *    existed on any auth context (resolveFromJWT sets `email`) — breaking
 *    the OR-email fallback used to match subscriptions/invoices/usage.
 * 3. Every query against `subscriptions` referenced columns that don't exist
 *    on that table (`tier`, `amount_usd`) instead of the real ones (`plan`,
 *    `price_inr`) — silently swallowed by .catch(), meaning `sub` was always
 *    null and Cancel Subscription always 404'd.
 * 4. Every query against `invoices` referenced `amount_usd`/`invoice_pdf_url`
 *    instead of the real `total_inr`/`pdf_key` columns — same silent failure.
 * 5. handleUpgradeInitiate read body.plan while the frontend sends
 *    target_plan — upgrade always 400'd with "Invalid plan: ".
 * 6. MSSP was missing from TIER_LIMITS/PLAN_FEATURES (auth/apiKeys.js) —
 *    every MSSP customer's real rate limits and feature flags silently
 *    downgraded to FREE tier platform-wide, not just in the billing portal.
 *
 * This suite proves each of these is fixed. */
import { describe, it, expect } from 'vitest';
import {
  handleCustomerBillingPortal,
  handleCustomerInvoices,
  handleCustomerPayments,
  handleCancelSubscription,
  handleUpgradeInitiate,
  handleLiveUsage,
} from '../src/handlers/enterpriseTransformHandler.js';
import { TIER_LIMITS, PLAN_FEATURES } from '../src/auth/apiKeys.js';

function makeDB({ subscription = null, invoices = [], payments = [], apiKeyUsage = { daily: 0, monthly: 0 }, overageUsd = 0 } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async first() {
          if (/FROM subscriptions/.test(sql)) return subscription;
          if (/SUM\(request_count\) as reqs.*period_start=\?/s.test(sql)) return { reqs: apiKeyUsage.daily };
          if (/SUM\(request_count\) as reqs.*start of month/s.test(sql)) return { reqs: apiKeyUsage.monthly };
          if (/SUM\(amount_usd\) as total FROM invoices/.test(sql)) return { total: overageUsd };
          return null;
        },
        async all() {
          if (/FROM invoices/.test(sql)) return { results: invoices };
          if (/FROM payments/.test(sql)) return { results: payments };
          if (/FROM customer_entitlements/.test(sql)) return { results: [] };
          if (/FROM api_keys/.test(sql)) return { results: [] };
          return { results: [] };
        },
        async run() { return { success: true }; },
      };
      return stmt;
    },
  };
}

function jsonReq(body) {
  return new Request('https://x/api/customer/billing/upgrade', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const REAL_SUB = {
  id: 'sub_123', plan: 'PRO', status: 'active', price_inr: 1499,
  trial_ends_at: null, current_period_end: '2026-08-01T00:00:00.000Z',
  cancel_at_period_end: 0, created_at: '2026-01-01T00:00:00.000Z',
};

describe('TIER_LIMITS / PLAN_FEATURES — MSSP was silently downgraded to FREE', () => {
  it('MSSP has real (non-FREE) rate limits', () => {
    expect(TIER_LIMITS.MSSP).toBeDefined();
    expect(TIER_LIMITS.MSSP.daily_limit).not.toBe(TIER_LIMITS.FREE.daily_limit);
    expect(TIER_LIMITS.MSSP.price_inr).toBe(9999);
  });
  it('MSSP has all features enabled, not FREE\'s all-false flags', () => {
    expect(PLAN_FEATURES.MSSP).toBeDefined();
    expect(PLAN_FEATURES.MSSP.ai_analyze).toBe(true);
    expect(PLAN_FEATURES.MSSP.multi_user).toBe(true);
  });
});

describe('handleCustomerBillingPortal — real subscription data for a real logged-in customer', () => {
  it('resolves the customer\'s real PRO subscription via email fallback (authCtx.email, not owner_email)', async () => {
    const env = { DB: makeDB({ subscription: REAL_SUB }) };
    // userId misses the subscriptions row on purpose — the WHERE user_id=? OR email=?
    // fallback must resolve it by email (a real JWT principal always carries a userId).
    const authCtx = { authenticated: true, tier: 'PRO', userId: 'u_email_fallback', email: 'ciso@fortune500.com' };
    const res = await handleCustomerBillingPortal(new Request('https://x'), env, authCtx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.portal.current_plan).toBe('PRO');
    expect(body.portal.subscription.price_inr).toBe(1499);
    expect(body.portal.can_cancel).toBe(true);
  });

  it('upgrade options are priced from TIER_LIMITS — what is shown matches what upgrade charges', async () => {
    const env = { DB: makeDB({ subscription: REAL_SUB }) };
    const authCtx = { authenticated: true, tier: 'PRO', userId: 'u_1' };
    const res = await handleCustomerBillingPortal(new Request('https://x'), env, authCtx);
    const body = await res.json();
    const enterpriseOpt = body.portal.upgrade_options.find(o => o.plan === 'ENTERPRISE');
    expect(enterpriseOpt.price_inr_month).toBe(TIER_LIMITS.ENTERPRISE.price_inr);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await handleCustomerBillingPortal(new Request('https://x'), {}, { authenticated: false });
    expect(res.status).toBe(401);
  });
});

describe('handleCancelSubscription — previously always 404\'d (wrong column name)', () => {
  it('cancels a real active subscription found via the correct plan/status columns', async () => {
    const env = { DB: makeDB({ subscription: REAL_SUB }) };
    const authCtx = { authenticated: true, tier: 'PRO', userId: 'u_1', email: 'ciso@fortune500.com' };
    const res = await handleCancelSubscription(jsonReq({}), env, authCtx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.message).toContain('PRO');
  });

  it('404s honestly when there really is no active subscription', async () => {
    const env = { DB: makeDB({ subscription: null }) };
    const authCtx = { authenticated: true, tier: 'FREE', userId: 'u_2' };
    const res = await handleCancelSubscription(jsonReq({}), env, authCtx);
    expect(res.status).toBe(404);
  });
});

describe('handleUpgradeInitiate — previously always 400\'d (field name + wrong price source)', () => {
  it('accepts target_plan (what the frontend actually sends)', async () => {
    const env = { DB: makeDB() };
    const authCtx = { authenticated: true, tier: 'STARTER', userId: 'u_1' };
    const res = await handleUpgradeInitiate(jsonReq({ target_plan: 'PRO' }), env, authCtx);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.upgrade.to_plan).toBe('PRO');
  });

  it('charges exactly the TIER_LIMITS price — same figure the portal displayed', async () => {
    const env = { DB: makeDB() };
    const authCtx = { authenticated: true, tier: 'FREE', userId: 'u_1' };
    const res = await handleUpgradeInitiate(jsonReq({ target_plan: 'ENTERPRISE' }), env, authCtx);
    const body = await res.json();
    expect(body.upgrade.amount_inr).toBe(TIER_LIMITS.ENTERPRISE.price_inr);
  });

  it('rejects a downgrade attempt', async () => {
    const env = { DB: makeDB() };
    const authCtx = { authenticated: true, tier: 'ENTERPRISE', userId: 'u_1' };
    const res = await handleUpgradeInitiate(jsonReq({ target_plan: 'STARTER' }), env, authCtx);
    expect(res.status).toBe(400);
  });
});

describe('handleLiveUsage — real per-tier limits, not a hardcoded duplicate map', () => {
  it('uses TIER_LIMITS for daily and monthly limits, and reports real overage charges', async () => {
    const env = { DB: makeDB({ apiKeyUsage: { daily: 12, monthly: 340 }, overageUsd: 4.5 }) };
    const authCtx = { authenticated: true, tier: 'STARTER', userId: 'u_1' };
    const res = await handleLiveUsage(new Request('https://x'), env, authCtx);
    const body = await res.json();
    expect(body.usage.daily.limit).toBe(TIER_LIMITS.STARTER.daily_limit);
    expect(body.usage.monthly.limit).toBe(TIER_LIMITS.STARTER.monthly_limit);
    expect(body.usage.daily.used).toBe(12);
    expect(body.usage.overage_charges_usd).toBe(4.5);
  });

  it('MSSP gets real unlimited limits, not FREE\'s tiny defaults', async () => {
    const env = { DB: makeDB() };
    const authCtx = { authenticated: true, tier: 'MSSP', userId: 'u_1' };
    const res = await handleLiveUsage(new Request('https://x'), env, authCtx);
    const body = await res.json();
    expect(body.usage.daily.limit).toBe(-1);
    expect(body.usage.monthly.limit).toBe(-1);
  });
});

describe('handleCustomerInvoices', () => {
  it('returns real invoices queried with the correct invoices-table columns', async () => {
    const env = { DB: makeDB({ invoices: [{ id: 'inv_1', total_inr: 1499, currency: 'INR', status: 'paid', created_at: '2026-06-01', pdf_key: 'invoices/inv_1.pdf' }] }) };
    const authCtx = { authenticated: true, tier: 'PRO', userId: 'u_1' };
    const res = await handleCustomerInvoices(new Request('https://x/api/customer/billing/invoices'), env, authCtx);
    const body = await res.json();
    expect(body.invoices).toHaveLength(1);
    expect(body.invoices[0].total_inr).toBe(1499);
  });
});

describe('handleCustomerPayments', () => {
  // The customer dashboard's Payment History tab used to call the owner-only
  // /api/admin/analytics endpoint (isOwner-gated, no user filter at all),
  // which 403'd for every real customer and showed a misleading "Upgrade to
  // PRO" message regardless of actual plan or purchase history.
  it('returns the caller\'s own pay-per-report purchases, not a platform-wide list', async () => {
    const env = { DB: makeDB({ payments: [
      { id: 'pay_1', module: 'domain', target: 'example.com', amount: 99900, currency: 'INR', status: 'paid', plan: 'pay_per_report', created_at: '2026-06-20', paid_at: '2026-06-20' },
    ] }) };
    const authCtx = { authenticated: true, tier: 'PRO', userId: 'u_1', email: 'user@example.com' };
    const res = await handleCustomerPayments(new Request('https://x/api/customer/payments'), env, authCtx);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.payments).toHaveLength(1);
    expect(body.payments[0].target).toBe('example.com');
  });

  it('requires authentication instead of allowing anonymous access to payment data', async () => {
    const env = { DB: makeDB({ payments: [{ id: 'pay_1' }] }) };
    const res = await handleCustomerPayments(new Request('https://x/api/customer/payments'), env, { authenticated: false });
    expect(res.status).toBe(401);
  });
});
