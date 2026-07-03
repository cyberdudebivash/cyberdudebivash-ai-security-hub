/* Forensic lineage protection: the router must have NO duplicate (path+method)
 * definitions. In the linear if-chain router, a second definition of the same
 * path+method is DEAD (unreachable — the first match returns), which silently
 * strands whatever handler/auth the duplicate wired up. The forensic audit found
 * three such dead duplicates:
 *   • GET /api/billing/invoices  (dead → handleGetInvoices; live → handleListInvoices)
 *   • GET /api/revenue/metrics   (dead → isRealUser+revenue.js; live → owner-gated)
 *   • GET /api/threat-intel/live (identical dead copy)
 * This guard fails CI if any duplicate is reintroduced.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const INDEX = resolve(import.meta.dirname, '../src/index.js');
const src = readFileSync(INDEX, 'utf8');

// Match explicit `path === '<literal>' && method === '<VERB>'` route predicates.
const RE = /path === '([^']+)'\s*&&\s*method === '([A-Z]+)'/g;

function collectRoutes() {
  const seen = new Map(); // "METHOD path" -> count
  let m;
  while ((m = RE.exec(src)) !== null) {
    const key = `${m[2]} ${m[1]}`;
    seen.set(key, (seen.get(key) || 0) + 1);
  }
  return seen;
}

describe('router lineage — one definition per (path, method)', () => {
  it('has no duplicate path+method route definitions', () => {
    const routes = collectRoutes();
    const dupes = [...routes.entries()].filter(([, n]) => n > 1).map(([k, n]) => `${k} ×${n}`);
    expect(dupes, `Duplicate (dead) route definitions found:\n${dupes.join('\n')}`).toEqual([]);
  });

  it('still defines a healthy number of routes (sanity: parser not broken)', () => {
    const routes = collectRoutes();
    // Guards against the regex silently matching nothing (which would make the
    // dup check vacuously pass).
    expect(routes.size).toBeGreaterThan(200);
  });
});
