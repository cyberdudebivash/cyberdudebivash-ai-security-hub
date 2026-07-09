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
import { buildUpgradePayload, checkEntitlement } from '../src/middleware/entitlementCheck.js';
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

  it('kill-chain directs to ENTERPRISE (was the unbuyable TEAM)', () => {
    expect(buildUpgradePayload(FEATURES.KILL_CHAIN_MAPPING, 'FREE').required_tier).toBe('ENTERPRISE');
  });

  // A later API-surface audit found this ENTERPRISE redirect itself was wrong for
  // SIEM specifically: the pricing page's own feature-comparison table and the
  // public API docs (POST /api/export/siem) both advertise SIEM Integration as
  // included at PRO. A PRO customer following the docs got a 403 telling them to
  // upgrade to a tier they'd already paid for the equivalent of. Fixed at the
  // source — SIEM_WEBHOOK added to TIER_IMPLICIT_FEATURES.PRO — so the CTA (and
  // an actual PRO caller of POST /api/export/siem) now match what was sold.
  it('SIEM export directs to PRO — matches what the pricing page and API docs sell', () => {
    expect(buildUpgradePayload(FEATURES.SIEM_WEBHOOK, 'FREE').required_tier).toBe('PRO');
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

describe('SIEM export entitlement matches what PRO customers were sold', () => {
  it('a PRO caller is actually granted SIEM_WEBHOOK (not just told PRO would unlock it)', async () => {
    const result = await checkEntitlement(null, null, FEATURES.SIEM_WEBHOOK, 'PRO');
    expect(result.granted).toBe(true);
  });

  it('FREE and STARTER are still correctly denied', async () => {
    expect((await checkEntitlement(null, null, FEATURES.SIEM_WEBHOOK, 'FREE')).granted).toBe(false);
    expect((await checkEntitlement(null, null, FEATURES.SIEM_WEBHOOK, 'STARTER')).granted).toBe(false);
  });

  it('ENTERPRISE and MSSP remain granted', async () => {
    expect((await checkEntitlement(null, null, FEATURES.SIEM_WEBHOOK, 'ENTERPRISE')).granted).toBe(true);
    expect((await checkEntitlement(null, null, FEATURES.SIEM_WEBHOOK, 'MSSP')).granted).toBe(true);
  });
});
