/* Regression test — handleEnterpriseWelcome's "pricing" block was a
 * hand-typed copy that had drifted from config/pricingConfig.js (the
 * platform's declared "immutable source of truth"): starter showed ₹999/mo
 * (real: ₹499), pro ₹2,999/mo (real: ₹1,499), enterprise ₹25,000/mo (real:
 * ₹4,999), mssp ₹75,000/mo (real: ₹9,999) — a customer comparing this
 * endpoint against an actual checkout would see contradictory prices. Now
 * sourced directly from pricingConfig.js so the two can't drift again. */
import { describe, it, expect } from 'vitest';
import { handleEnterpriseWelcome } from '../src/handlers/enterpriseOnboarding.js';
import { PRICING_CONFIG } from '../src/config/pricingConfig.js';

describe('handleEnterpriseWelcome — pricing matches config/pricingConfig.js', () => {
  it('every paid tier price string comes from the canonical config, not a stale copy', async () => {
    const resp = await handleEnterpriseWelcome(new Request('https://x/api/enterprise/welcome'), {});
    const body = await resp.json();
    const pricing = body.data.pricing;

    expect(pricing.starter).toContain(PRICING_CONFIG.plans.STARTER.label);
    expect(pricing.pro).toContain(PRICING_CONFIG.plans.PRO.label);
    expect(pricing.enterprise).toContain(PRICING_CONFIG.plans.ENTERPRISE.label);
    expect(pricing.mssp).toContain(PRICING_CONFIG.plans.MSSP.label);

    // Guard against the specific stale figures this endpoint used to show.
    expect(pricing.starter).not.toContain('₹999/mo');
    expect(pricing.pro).not.toContain('₹2,999/mo');
    expect(pricing.enterprise).not.toContain('₹25,000');
    expect(pricing.mssp).not.toContain('₹75,000');
  });
});
