/* Build/deploy sync badge — guards the dashboard's FE↔BE commit visibility.
 * The badge fetches both version sources and compares commits so an operator
 * can see at a glance whether the frontend and backend are on the same deploy
 * (the "did my change land?" signal).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const html = readFileSync(resolve(import.meta.dirname, '../../frontend/user-dashboard.html'), 'utf8');

describe('dashboard build-sync badge', () => {
  it('renders a badge element', () => {
    expect(html.includes('id="cdb-build-badge"')).toBe(true);
    expect(html.includes('id="cdb-build-dot"')).toBe(true);
  });
  it('compares the frontend and backend commit sources', () => {
    expect(html.includes('/version.json')).toBe(true);
    expect(html.includes('/api/version')).toBe(true);
    // Compares the two commits to derive synced vs skew.
    expect(/feC\s*===\s*beC/.test(html)).toBe(true);
  });
  it('surfaces a skew (deploying) state, not just synced', () => {
    expect(/deploying/.test(html)).toBe(true);
    expect(/synced/.test(html)).toBe(true);
  });
});
