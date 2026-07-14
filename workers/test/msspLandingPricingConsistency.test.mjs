/* Regression test — frontend/mssp.html pricing cards vs. what their own
 * buttons actually charge (H1 follow-up, COMMERCIAL_RISK_AUDIT_2026-07-14.md).
 *
 * mssp.html's "MSSP Pricing" section showed ₹25,000 for "ENTERPRISE" (its own
 * "Get Enterprise" button links to /upgrade, whose real price is ₹4,999 —
 * config/pricingConfig.js plans.ENTERPRISE) and ₹75,000 for "MSSP PARTNER"
 * (its own "Become MSSP Partner" button links to /mssp-onboarding, whose
 * checkout — handlers/msspOnboardingHandler.js, backed by
 * services/globalScale.js MSSP_TIERS — only ever offers Reseller/Silver/Gold
 * at ₹14,999/₹29,999/₹49,999; there is no ₹75,000 tier anywhere). Both
 * numbers were stale content, contradicted by the pages the same buttons
 * route to one click later. This guard fails if either drifts back.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { MSSP_TIERS } from '../src/services/globalScale.js';

const root = resolve(import.meta.dirname, '..');
const mssp = readFileSync(resolve(root, '../frontend/mssp.html'), 'utf8');

describe('mssp.html pricing cards match what their own buttons actually charge', () => {
  it('Enterprise card price matches /upgrade\'s real Enterprise price (₹4,999)', () => {
    const cardMatch = mssp.match(/ENTERPRISE<\/h3>\s*<div class="price">₹([\d,]+)<\/div>/);
    expect(cardMatch, 'Enterprise pricing card must be present').not.toBeNull();
    expect(cardMatch[1]).toBe('4,999');
  });

  it('Enterprise card links to /upgrade (the real charge path)', () => {
    const section = mssp.slice(mssp.indexOf('ENTERPRISE</h3>'), mssp.indexOf('MSSP PARTNER'));
    expect(section).toContain('href="/upgrade"');
  });

  it('MSSP Partner card price matches the real Gold tier (₹49,999) it links to', () => {
    const cardMatch = mssp.match(/MSSP PARTNER[^<]*<\/h3>\s*<div class="price">₹([\d,]+)<\/div>/);
    expect(cardMatch, 'MSSP Partner pricing card must be present').not.toBeNull();
    const shownPrice = Number(cardMatch[1].replace(/,/g, ''));
    expect(shownPrice).toBe(MSSP_TIERS.gold.price_inr);
  });

  it('MSSP Partner card links to /mssp-onboarding (the real checkout it must match)', () => {
    const section = mssp.slice(mssp.indexOf('MSSP PARTNER'), mssp.indexOf('Custom pricing available'));
    expect(section).toContain('href="/mssp-onboarding"');
  });

  it('does not show the old orphaned prices (₹25,000 / ₹75,000)', () => {
    expect(mssp).not.toContain('₹25,000');
    expect(mssp).not.toContain('₹75,000');
  });

  it('mentions the lower-volume Reseller/Silver tiers so the page is not silently narrower than reality', () => {
    expect(mssp).toContain(`₹${MSSP_TIERS.reseller.price_inr.toLocaleString('en-IN')}`);
    expect(mssp).toContain(`₹${MSSP_TIERS.silver.price_inr.toLocaleString('en-IN')}`);
  });
});
