/* Regression test — lib/razorpay.js SUBSCRIPTION_PRICES.MSSP_PARTNER removed
 * (H1 follow-up, COMMERCIAL_RISK_AUDIT_2026-07-14.md).
 *
 * MSSP_PARTNER (₹1,999/mo, "Multi-Tenant MSSP Workspace") had no frontend
 * caller anywhere in the codebase, but was not simply inert: handleCreateOrder
 * looks up module:'subscription' plans by an unvalidated client-supplied key
 * (`SUBSCRIPTION_PRICES[planKey] || SUBSCRIPTION_PRICES['STARTER']`), so a
 * direct API call with plan:'MSSP_PARTNER' could create a real, payable
 * ₹1,999 Razorpay order. handleVerifyPayment's tier-grant step only activates
 * a user/subscription record for plan values in
 * ['STARTER','PRO','ENTERPRISE','MSSP'] — 'MSSP_PARTNER' was never in that
 * list, so a customer who somehow found and used this plan value could pay
 * and receive no tier/entitlement at all. Removing the entry closes this one
 * specific dead-end (an unrecognized plan key now falls back to STARTER
 * pricing/behavior, same as any other typo). The broader gap it's an
 * instance of — module:'subscription' accepts any plan string with no
 * allow-list, unlike module:'package', which validates product_id and 400s
 * on an unknown one — is a separate, pre-existing finding tracked in the
 * audit doc, not fixed here.
 */
import { describe, it, expect } from 'vitest';
import { SUBSCRIPTION_PRICES } from '../src/lib/razorpay.js';

describe('SUBSCRIPTION_PRICES no longer defines the dead MSSP_PARTNER SKU', () => {
  it('MSSP_PARTNER is not a key in SUBSCRIPTION_PRICES', () => {
    expect(SUBSCRIPTION_PRICES.MSSP_PARTNER).toBeUndefined();
  });

  it('the real MSSP plan (₹9,999) is unaffected by removing MSSP_PARTNER', () => {
    expect(SUBSCRIPTION_PRICES.MSSP.amount).toBe(999900);
    expect(SUBSCRIPTION_PRICES.MSSP.label).toBe('₹9,999');
  });

  it('every remaining subscription plan key is one handleVerifyPayment actually grants a tier for', () => {
    // Documents the allow-list in handlers/payments.js handleVerifyPayment
    // (['STARTER','PRO','ENTERPRISE','MSSP']) — ENTERPRISE_SOC is priced here
    // but intentionally not in that grant list (a separate, pre-existing
    // product not gated by this table); MSSP_PARTNER used to be the one
    // plan that was both priced AND silently un-grantable.
    const grantable = ['STARTER', 'PRO', 'ENTERPRISE', 'MSSP'];
    const nonGrantablePricedPlans = Object.keys(SUBSCRIPTION_PRICES).filter(k => !grantable.includes(k));
    expect(nonGrantablePricedPlans).toEqual(['ENTERPRISE_SOC']);
  });
});
