// Billing contract: prices are the immutable source of truth. These tests fail
// loudly if a price, the paise conversion, or the GST rate silently changes.
import { describe, it, expect } from 'vitest';
import { PRICING_CONFIG, getPlanPrice, getPriceWithGST, getPlansArray } from '../src/config/pricingConfig.js';

describe('pricing config — paise integrity (Razorpay charges in paise)', () => {
  it('every plan/package price_paise == price_inr * 100', () => {
    const groups = [PRICING_CONFIG.plans, PRICING_CONFIG.packages];
    for (const group of groups) {
      for (const [id, item] of Object.entries(group)) {
        if (item.price_paise !== undefined) {
          expect(item.price_paise, `${id} paise mismatch`).toBe(item.price_inr * 100);
        }
      }
    }
  });
});

describe('pricing config — known plan prices (regression lock)', () => {
  it('matches the published tier prices', () => {
    expect(getPlanPrice('FREE')).toBe(0);
    expect(getPlanPrice('STARTER')).toBe(999);
    expect(getPlanPrice('PRO')).toBe(1499);
    expect(getPlanPrice('ENTERPRISE')).toBe(4999);
  });

  it('returns null for an unknown plan id', () => {
    expect(getPlanPrice('NON_EXISTENT')).toBeNull();
  });
});

describe('pricing config — GST', () => {
  it('applies an 18% GST rate, rounded', () => {
    expect(PRICING_CONFIG.gst_rate).toBe(0.18);
    expect(getPriceWithGST(1000)).toBe(1180);
    expect(getPriceWithGST(499)).toBe(Math.round(499 * 1.18));
  });
});

describe('pricing config — immutability', () => {
  it('is frozen and cannot be mutated at runtime', () => {
    expect(Object.isFrozen(PRICING_CONFIG)).toBe(true);
    expect(Object.isFrozen(PRICING_CONFIG.plans)).toBe(true);
    expect(() => { PRICING_CONFIG.plans.PRO.price_inr = 1; }).toThrow();
  });

  it('exposes plans as an array for rendering', () => {
    const arr = getPlansArray();
    expect(Array.isArray(arr)).toBe(true);
    expect(arr.find(p => p.id === 'PRO')).toBeTruthy();
  });
});
