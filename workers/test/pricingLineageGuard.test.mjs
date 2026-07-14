/* Pricing lineage guard — enforces ONE canonical price across every source.
 *
 * FINDING (was PL-1, prior sessions mis-severitized as a CRITICAL overcharge):
 * a forensic trace of every checkout path shows the price a customer is ACTUALLY
 * charged is ₹1,499 (PRO) / ₹4,999 (ENTERPRISE), everywhere:
 *   • public marketing checkout  → /api/payments/create-order → SUBSCRIPTION_PRICES
 *   • in-app billing portal       → /api/customer/billing/upgrade → TIER_LIMITS
 *   • pricing page                → /api/pricing → pricingConfig
 *   • frontend buttons + SEO JSON-LD (index.html)
 * The ONLY source that diverged (₹2,999 / ₹24,999) was handlers/monetizationV2.js
 * PLANS, served by /api/billing/* — routes NOT wired to any customer UI (an
 * orphaned/legacy billing surface). That stray value had leaked into feature-gate
 * upsells (entitlementCheck buildUpgradePayload). All strays are now aligned to
 * the charged price. This guard fails CI if any of them drifts apart again.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');

// Grab a named tier block's price_inr (first numeric after `TIER: {... price_inr:`).
// Tolerates `TIER: {` and `TIER: Object.freeze({`.
function tierPriceInr(src, tier) {
  const m = src.match(new RegExp(`\\b${tier}:\\s*(?:Object\\.freeze\\()?\\{[^}]*?price_inr:\\s*(\\d+)`, 's'));
  return m ? Number(m[1]) : null;
}
const proPriceInr = (src) => tierPriceInr(src, 'PRO');

const CANONICAL_PRO = 1499;
// Only STARTER/ENTERPRISE/MSSP are covered here (not FREE, which is always 0) —
// this is the exact gap that let TIER_LIMITS.STARTER drift to 499 while every
// other source said 999, undetected until a dedicated audit found it.
const CANONICAL_PRICE_INR = { STARTER: 999, ENTERPRISE: 4999, MSSP: 9999 };

// Extracts a named key's numeric value from a `reports: Object.freeze({ name: N, ... })` block.
function reportPriceRupees(src, name) {
  const m = src.match(new RegExp(`reports:\\s*Object\\.freeze\\(\\{[^}]*?\\b${name}:\\s*(\\d+)`, 's'));
  return m ? Number(m[1]) : null;
}

// Extracts MODULE_PRICES[name].amount (paise) from razorpay.js, converted to rupees.
function modulePriceRupees(src, name) {
  const m = src.match(new RegExp(`\\b${name}:\\s*\\{\\s*amount:\\s*(\\d+)`, 's'));
  return m ? Number(m[1]) / 100 : null;
}

describe('pricing lineage — one canonical PRO price across all sources', () => {
  it('checkout source of truth (auth/apiKeys.js TIER_LIMITS) is ₹1,499', () => {
    expect(proPriceInr(read('src/auth/apiKeys.js'))).toBe(CANONICAL_PRO);
  });

  it('marketing checkout table (lib/razorpay.js SUBSCRIPTION_PRICES) charges ₹1,499', () => {
    // SUBSCRIPTION_PRICES.PRO.amount is in paise.
    const src = read('src/lib/razorpay.js');
    const m = src.match(/PRO:\s*\{\s*amount:\s*(\d+)/);
    expect(m && Number(m[1])).toBe(CANONICAL_PRO * 100);
  });

  it('pricing page config (config/pricingConfig.js) advertises ₹1,499', () => {
    expect(proPriceInr(read('src/config/pricingConfig.js'))).toBe(CANONICAL_PRO);
  });

  it('billing PLANS (handlers/monetizationV2.js) matches the charged price', () => {
    expect(proPriceInr(read('src/handlers/monetizationV2.js'))).toBe(CANONICAL_PRO);
  });

  it('feature-gate upsell (entitlementCheck buildUpgradePayload) quotes ₹1,499', () => {
    const src = read('src/middleware/entitlementCheck.js');
    // PRO CTA line: price_inr: '₹1,499/mo'
    const m = src.match(/required_tier:\s*'PRO'[^}]*?price_inr:\s*'([^']+)'/s);
    expect(m && m[1]).toBe('₹1,499/mo');
  });
});

/* FINDING (2026-07-14 commercial risk audit): this guard only ever covered PRO.
 * TIER_LIMITS.STARTER.price_inr drifted to 499 — while razorpay.js, pricingConfig.js,
 * subscription.js, revenueGate.js, and commercialPlatformHandler.js all agreed on
 * 999 — and shipped undetected because nothing checked STARTER (or ENTERPRISE/MSSP)
 * the way this file already checked PRO. A real customer upgrading Starter through
 * the billing portal (which charges off TIER_LIMITS) was charged 499 while a
 * customer signing up through the main pricing checkout was charged 999 for the
 * same plan. Fixed in auth/apiKeys.js; this closes the coverage gap that let it
 * happen. */
describe('pricing lineage — STARTER/ENTERPRISE/MSSP prices also agree everywhere', () => {
  for (const tier of Object.keys(CANONICAL_PRICE_INR)) {
    const expected = CANONICAL_PRICE_INR[tier];

    it(`checkout source of truth (auth/apiKeys.js TIER_LIMITS.${tier}) is ₹${expected}`, () => {
      expect(tierPriceInr(read('src/auth/apiKeys.js'), tier)).toBe(expected);
    });

    it(`marketing checkout table (lib/razorpay.js SUBSCRIPTION_PRICES.${tier}) charges ₹${expected}`, () => {
      const src = read('src/lib/razorpay.js');
      const m = src.match(new RegExp(`SUBSCRIPTION_PRICES[\\s\\S]*?\\b${tier}:\\s*\\{\\s*amount:\\s*(\\d+)`));
      expect(m && Number(m[1])).toBe(expected * 100);
    });

    it(`pricing page config (config/pricingConfig.js plans.${tier}) advertises ₹${expected}`, () => {
      expect(tierPriceInr(read('src/config/pricingConfig.js'), tier)).toBe(expected);
    });
  }
});

/* FINDING (2026-07-06 revenue-mechanisms audit): frontend/assets/geo-currency-
 * router.js's report prices (shown on every "Unlock Full Report" button pre-
 * checkout, and used by checkout-modal.js to build the Razorpay charge) had
 * drifted from workers/src/lib/razorpay.js MODULE_PRICES — the actual amount
 * charged. Domain matched (₹999) by coincidence; ai showed ₹999 but charged
 * ₹2,499, redteam showed ₹999 but charged ₹4,999, identity/compliance showed
 * ₹999 but charged ₹799/₹499. A customer could be shown one price and
 * charged another on the highest-intent screen in the funnel — fixed by
 * aligning the displayed matrix to MODULE_PRICES. This guard fails CI if
 * they drift apart again. */
describe('pricing lineage — report prices shown pre-checkout match what Razorpay actually charges', () => {
  const razorpaySrc = read('src/lib/razorpay.js');
  const geoRouterSrc = readFileSync(resolve(root, '../frontend/assets/geo-currency-router.js'), 'utf8');

  for (const reportModule of ['domain', 'ai', 'redteam', 'identity', 'compliance']) {
    it(`${reportModule} report: displayed INR price equals the charged price`, () => {
      const charged   = modulePriceRupees(razorpaySrc, reportModule);
      const displayed = reportPriceRupees(geoRouterSrc, reportModule);
      expect(charged, `MODULE_PRICES.${reportModule} not found in razorpay.js`).not.toBe(null);
      expect(displayed, `reports.${reportModule} not found in geo-currency-router.js`).not.toBe(null);
      expect(displayed).toBe(charged);
    });
  }
});
