/* Customer-truth: every premium-feature upgrade CTA must point to a tier the
 * customer can actually PURCHASE, at the price billing actually charges.
 *
 * Found during the enterprise customer simulation: SIEM export / kill-chain
 * mapping told the customer "required_tier: TEAM (₹7,999/mo)" — but billing
 * (/api/billing/plans) sells only FREE / PRO / ENTERPRISE. A customer wanting
 * SIEM integration hit a dead-end upgrade path. Separately, every CTA misquoted
 * the price. The CTA price MUST equal the price the customer is actually charged
 * at checkout — the canonical source is TIER_LIMITS (auth/apiKeys.js) /
 * SUBSCRIPTION_PRICES (lib/razorpay.js): PRO ₹1,499, ENTERPRISE ₹4,999. (A prior
 * pass wrongly aligned these to the orphaned monetizationV2 ₹2,999/₹24,999, which
 * no checkout path uses — that made the gate quote ₹2,999 while checkout charged
 * ₹1,499. Corrected to the charged price.)
 */
import { describe, it, expect } from 'vitest';
import { buildUpgradePayload } from '../src/middleware/entitlementCheck.js';
import { FEATURES } from '../src/middleware/entitlementCheck.js';

// Tiers a customer can actually buy.
const PURCHASABLE = new Set(['PRO', 'ENTERPRISE']);
// The price the customer is actually charged at checkout (canonical: TIER_LIMITS).
const BILLING = {
  PRO:        '₹1,499/mo',
  ENTERPRISE: '₹4,999/mo',
};

const ALL_FEATURES = Object.values(FEATURES);

describe('upgrade CTA truth', () => {
  it('every feature gate points to a PURCHASABLE tier (no phantom TEAM)', () => {
    for (const f of ALL_FEATURES) {
      const p = buildUpgradePayload(f, 'FREE');
      expect(PURCHASABLE.has(p.required_tier), `feature ${f} → non-purchasable tier ${p.required_tier}`).toBe(true);
    }
  });

  it('SIEM export + kill-chain now direct to ENTERPRISE (was the unbuyable TEAM)', () => {
    expect(buildUpgradePayload(FEATURES.SIEM_WEBHOOK, 'FREE').required_tier).toBe('ENTERPRISE');
    expect(buildUpgradePayload(FEATURES.KILL_CHAIN_MAPPING, 'FREE').required_tier).toBe('ENTERPRISE');
  });

  it('quoted price matches what billing actually charges for that tier', () => {
    for (const f of ALL_FEATURES) {
      const p = buildUpgradePayload(f, 'FREE');
      expect(p.price_inr, `feature ${f} price mismatch for ${p.required_tier}`).toBe(BILLING[p.required_tier]);
    }
  });

  it('never quotes a non-canonical price (₹3,999 / ₹39,999 / ₹7,999 / ₹2,999 / ₹24,999)', () => {
    const wrong = ['₹3,999/mo', '₹39,999/mo', '₹7,999/mo', '₹2,999/mo', '₹24,999/mo'];
    for (const f of ALL_FEATURES) {
      const p = buildUpgradePayload(f, 'FREE');
      expect(wrong).not.toContain(p.price_inr);
    }
  });
});
