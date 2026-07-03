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

// Grab the PRO block's price_inr (first numeric after `PRO: {... price_inr:`).
function proPriceInr(src) {
  // Tolerates `PRO: {` and `PRO: Object.freeze({`.
  const m = src.match(/PRO:\s*(?:Object\.freeze\()?\{[^}]*?price_inr:\s*(\d+)/s);
  return m ? Number(m[1]) : null;
}

const CANONICAL_PRO = 1499;

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
