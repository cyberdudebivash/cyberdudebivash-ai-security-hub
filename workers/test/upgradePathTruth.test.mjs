/* Customer-truth: every premium-feature upgrade CTA must point to a tier the
 * customer can actually PURCHASE, at the price billing actually charges.
 *
 * Found during the enterprise customer simulation: SIEM export / kill-chain
 * mapping told the customer "required_tier: TEAM (₹7,999/mo)" — but billing
 * (/api/billing/plans) sells only FREE / PRO / ENTERPRISE. A customer wanting
 * SIEM integration hit a dead-end upgrade path. Separately, every CTA misquoted
 * the price (PRO ₹3,999 vs billed ₹2,999; ENTERPRISE ₹39,999 vs billed ₹24,999).
 */
import { describe, it, expect } from 'vitest';
import { buildUpgradePayload } from '../src/middleware/entitlementCheck.js';
import { FEATURES } from '../src/middleware/entitlementCheck.js';

// Tiers a customer can actually buy (matches /api/billing/plans → monetizationV2 PLANS).
const PURCHASABLE = new Set(['PRO', 'ENTERPRISE']);
// Authoritative customer-facing prices (monetizationV2 PLANS).
const BILLING = {
  PRO:        '₹2,999/mo',
  ENTERPRISE: '₹24,999/mo',
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

  it('never quotes the old wrong prices (₹3,999 / ₹39,999 / ₹7,999)', () => {
    const wrong = ['₹3,999/mo', '₹39,999/mo', '₹7,999/mo'];
    for (const f of ALL_FEATURES) {
      const p = buildUpgradePayload(f, 'FREE');
      expect(wrong).not.toContain(p.price_inr);
    }
  });
});
