/* No fabricated fallback numbers in the homepage stat tiles.
 *
 * The scroll-triggered Global-Threat-Map / Vuln-Management / Zero-Day tiles used
 * to fall back to hardcoded figures (1626, 42, 285, 4/9/17/5, 5/3/14) when the
 * API returned nothing or errored — indistinguishable from real data to a
 * customer. They now show an em-dash empty state via statOrDash(). This guard
 * fails if a fabricated fallback creeps back.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const html = readFileSync(resolve(import.meta.dirname, '../../frontend/index.html'), 'utf8');

describe('homepage stat tiles never show fabricated fallback numbers', () => {
  it('uses the statOrDash empty-state helper', () => {
    expect(html.includes('function statOrDash')).toBe(true);
  });
  it('no cntUp() call passes a hardcoded multi-digit literal', () => {
    const m = html.match(/cntUp\('[a-z0-9-]+',\s*\d{2,}\)/g) || [];
    expect(m).toEqual([]);
  });
  it('the specific old fabricated figures are gone from the tile logic', () => {
    // 1626 was the signature fake "attacks" number.
    expect(/cntUp\('gtm-attacks',\s*1626\)/.test(html)).toBe(false);
  });
  it('stat tiles initialize to an em-dash, not a hardcoded number', () => {
    for (const id of ['vm-critical', 'zd-active', 'zd-pocs']) {
      expect(new RegExp(`id="${id}"[^>]*>\\d`).test(html)).toBe(false);
    }
  });
});
