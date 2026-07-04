/* Enterprise-portal API documentation must reflect REAL backend routes.
 *
 * enterprise-portal.html advertises the platform's API surface as labels + an
 * endpoint catalog. A route-reconciliation (FE↔BE) pass found it displayed
 * stale paths that never existed on the router (e.g. /api/audit/log when the
 * real route is /api/audit-log), which misleads enterprise evaluators reading
 * the capabilities page. These are display strings (no functional break) but
 * must stay accurate. This guard fails if a known-stale path reappears.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const html = readFileSync(resolve(import.meta.dirname, '../../frontend/enterprise-portal.html'), 'utf8');

describe('enterprise-portal advertised API paths are real', () => {
  const stale = ['/api/audit/log', '/api/audit/export', '/api/hunt/history', '/api/mssp/workspace', '/api/mssp/tenant/provision'];
  for (const p of stale) {
    it(`does not advertise the stale path ${p}`, () => {
      expect(html.includes(`${p}<`) || html.includes(`${p}'`) || html.includes(`${p} `)).toBe(false);
    });
  }
  it('advertises the corrected real paths', () => {
    for (const real of ['/api/audit-log', '/api/hunt/sessions', '/api/mssp/overview']) {
      expect(html.includes(real)).toBe(true);
    }
  });
});
