/* Regression test — billing-portal.html displayed a real USD figure with a
 * ₹ (Rupee) symbol, and a real INR figure's static placeholder used a $
 * (Dollar) symbol (Tier 3 backlog item #1; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * The overage-charges tile read u.overage_charges_usd — a field the backend
 * (workers/src/handlers/enterpriseTransformHandler.js:441) computes from a
 * real `SUM(amount_usd) ... FROM invoices` query, genuinely US-dollar
 * denominated (its own name says so) — through fmtINR(), which prepends
 * '₹' and formats with the en-IN locale. A customer with, say, $45.50 in
 * real overage charges would have seen "₹45.50" — the wrong currency
 * entirely, not just wrong formatting.
 *
 * Separately, the plan-price tile's static HTML placeholder read "$0", but
 * the real field it gets replaced with (sub.price_inr) is genuinely INR —
 * every other use of *_inr fields on this exact page correctly goes through
 * fmtINR(). The placeholder used the wrong symbol for what real data would
 * eventually show.
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/billing-portal.html'), 'utf8');

describe('overage charges (a real USD figure) are formatted as USD, not INR', () => {
  it('defines a real USD formatter', () => {
    expect(fe).toMatch(/function fmtUSD\(n\)\s*\{\s*return\s*'\$'/);
  });

  it("overage-charges' textContent is set via fmtUSD, not fmtINR", () => {
    const idx = fe.indexOf("getElementById('overage-charges').textContent");
    expect(idx, 'the overage-charges assignment must exist').toBeGreaterThan(-1);
    const line = fe.slice(idx, idx + 120);
    expect(line).toContain('fmtUSD(u.overage_charges_usd)');
    expect(line).not.toContain('fmtINR(u.overage_charges_usd)');
  });

  it("the static HTML placeholder for overage-charges already correctly used '$' (was never the bug)", () => {
    expect(fe).toContain('id="overage-charges">$0.00</div>');
  });
});

describe('the plan-price placeholder (a real INR figure once loaded) uses the correct ₹ symbol', () => {
  it('the static HTML placeholder now reads ₹0, not $0', () => {
    expect(fe).toContain('id="plan-price">₹0</span>');
    expect(fe).not.toContain('id="plan-price">$0</span>');
  });

  it('plan-price is still populated via fmtINR(sub.price_inr) once real data loads (unchanged)', () => {
    const idx = fe.indexOf("getElementById('plan-price').textContent");
    expect(idx, 'the plan-price assignment must exist').toBeGreaterThan(-1);
    const line = fe.slice(idx, idx + 80);
    expect(line).toContain('fmtINR(sub.price_inr)');
  });
});

describe('other real-INR fields on this page are untouched (still correctly use fmtINR)', () => {
  it('monthly-spend, the upgrade plan list, and invoice rows still read *_inr fields', () => {
    expect(fe).toContain('fmtINR(sub.price_inr)');
    expect(fe).toContain('fmtINR(p.price_inr_month)');
  });
});
