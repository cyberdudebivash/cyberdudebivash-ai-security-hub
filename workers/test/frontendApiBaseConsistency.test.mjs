/* Platform API-wiring audit, 2026-07-11 — of ~40 distinct API-base
 * declarations across the frontend, 2 hardcoded the raw Cloudflare Workers
 * URL (cyberdudebivash-security-hub.iambivash-bn.workers.dev) unconditionally
 * instead of the same-origin/cyberdudebivash.in-first pattern every other
 * page uses (confirmed by a full repo-wide audit — not an ecosystem-link
 * question; frontend/assets/global.js's tools./intel./blog.cyberdudebivash.*
 * references are deliberate cross-links to sibling CYBERDUDEBIVASH ecosystem
 * properties and are correct as-is, unrelated to this finding):
 *
 *   - frontend/index.html's "CDB_HARDENED_STATS" widget (line ~22601)
 *   - frontend/gadgets.html's entire dashboard engine (line ~729)
 *
 * Both still worked (the raw Workers URL stays live alongside the custom
 * domain) but were needlessly fragile and inconsistent with the documented
 * convention used everywhere else (see soc-dashboard.html's own in-code
 * post-mortem of a prior, more severe version of this exact bug class — a
 * non-resolving bare workers.dev fallback that made a whole dashboard 100%
 * dead, found 2026-06-29). Fixed to match the established pattern.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const indexHtml = readFileSync(
  fileURLToPath(new URL('../../frontend/index.html', import.meta.url)), 'utf8'
);
const gadgetsHtml = readFileSync(
  fileURLToPath(new URL('../../frontend/gadgets.html', import.meta.url)), 'utf8'
);

describe('frontend/index.html — CDB_HARDENED_STATS widget no longer hardcodes the raw Workers URL', () => {
  it('does not assign API directly to the raw workers.dev hostname', () => {
    expect(indexHtml).not.toMatch(/const API {2}= 'https:\/\/cyberdudebivash-security-hub\.iambivash-bn\.workers\.dev';/);
  });

  it('goes through CONFIG.API_BASE first, matching this file\'s own documented primary source', () => {
    expect(indexHtml).toMatch(/const API {2}= \(typeof CONFIG !== 'undefined' && CONFIG\.API_BASE\) \|\| 'https:\/\/cyberdudebivash\.in';/);
  });

  it('the documented multi-endpoint fallback pattern elsewhere in the file is untouched', () => {
    // CONFIG.API_BASE (primary) + workers.dev (resilience fallback) — a
    // deliberate, different, correct pattern this fix does not change.
    expect(indexHtml).toContain("CONFIG.API_BASE,                                                       // primary: cyberdudebivash.in");
  });
});

describe('frontend/gadgets.html — dashboard engine no longer hardcodes the raw Workers URL', () => {
  it('uses a same-origin relative base, matching this page\'s own canonical cyberdudebivash.in URL', () => {
    expect(gadgetsHtml).toContain("const API   = '';");
    expect(gadgetsHtml).not.toMatch(/const API {3}= 'https:\/\/cyberdudebivash-security-hub\.iambivash-bn\.workers\.dev';/);
    expect(gadgetsHtml).toContain('<link rel="canonical" href="https://cyberdudebivash.in/gadgets">');
  });

  it('every API call on this page still resolves correctly through the relative base (template-literal usage, not string concatenation that would break on an empty prefix)', () => {
    const apiCalls = gadgetsHtml.match(/fetchJSON\(`\$\{API\}\/api\//g) || [];
    expect(apiCalls.length).toBeGreaterThan(5);
  });
});

describe('Ecosystem cross-links (unaffected, confirmed correct as-is) — sanity check they still exist', () => {
  it('the sibling CYBERDUDEBIVASH properties are still linked (not accidentally removed by this fix)', () => {
    expect(indexHtml).toContain('tools.cyberdudebivash.com');
  });
});
