/* Regression test — tools.html Tools/AI/Marketplace grids (full-frontend-audit
 * follow-up, Tier 1 item #10; see docs/capability-registry/PROGRAM_BOARD.md
 * session log).
 *
 * Three independent bugs, all rooted in the same three render functions:
 *
 * 1. renderOfficialTools()/renderAITools()/renderMarketplace() all built their
 *    "Buy" button's price argument via `price.match(/\\d+/)[0]` — a regex
 *    LITERAL with a doubled backslash, which matches a literal backslash
 *    character followed by digits (never present in a "₹999"-style string).
 *    `.match()` therefore always returned null, and `null[0]` threw a
 *    TypeError inside the Array#map callback — aborting the *entire* map()
 *    call, so grid.innerHTML was never assigned. All three grids
 *    (officialToolsGrid, aiToolsGrid, marketplaceGrid) silently rendered
 *    nothing at all, for every visitor, whenever a priced item was present.
 *
 * 2. renderOfficialTools()'s live /api/tools/catalog path mapped API tools
 *    without carrying through category/description — even after fixing the
 *    regex crash, every API-sourced card would have rendered the literal
 *    text "undefined" for its category badge and description paragraph.
 *
 * 3. renderMarketplace() read item.demand/item.cve/item.price, but the real
 *    /api/defense/solutions response (enrichSolution() in
 *    workers/src/handlers/defenseMarketplace.js) returns
 *    demand_score/cve_id/price_inr — so every live listing silently showed
 *    the hardcoded fallback demand (75%), CVE ('N/A') and price (₹999)
 *    instead of its real values. Worse, "Buy Now" on a live item called
 *    cdbToolBuy() -> POST /api/tools/purchase, which only recognizes the
 *    static TOOLS_CATALOG dict (workers/src/handlers/toolsMarketplace.js);
 *    dynamic defense_solutions IDs are never in it, so the purchase always
 *    404'd ("Product not found") and silently fell back to a WhatsApp
 *    message quoting the wrong (hardcoded ₹999) price computed above.
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/tools.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n        }', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

describe('the doubled-backslash regex that crashed all three grids is gone', () => {
  it('tools.html contains no `match(/\\\\d+/)` (double-backslash) regex literal', () => {
    // This JS source string decodes to the 14-char literal  match(/\\d+/)
    // i.e. two backslash characters in the file — the bug being asserted gone.
    expect(fe).not.toContain('match(/\\\\d+/)');
  });

  it('renderOfficialTools, renderAITools and renderMarketplace all use the single-backslash \\d+ literal', () => {
    expect(fnBody('renderOfficialTools')).toContain('match(/\\d+/)');
    expect(fnBody('renderAITools')).toContain('match(/\\d+/)');
    expect(fnBody('renderMarketplace')).toContain('match(/\\d+/)');
  });
});

describe('renderOfficialTools — API-sourced tools carry category/description through', () => {
  it('maps t.category and t.description onto the rendered tool object', () => {
    const body = fnBody('renderOfficialTools');
    const mapIdx = body.indexOf('apiTools.map(function(t)');
    expect(mapIdx).toBeGreaterThan(-1);
    const mapSection = body.slice(mapIdx, mapIdx + 400);
    expect(mapSection).toContain('category: t.category');
    expect(mapSection).toContain('description: t.description');
  });
});

describe('renderMarketplace — reads the real /api/defense/solutions field names', () => {
  it('reads item.demand_score (not just item.demand) for the demand meter', () => {
    expect(fnBody('renderMarketplace')).toContain('item.demand_score');
  });

  it('reads item.cve_id (not just item.cve) for the CVE badge', () => {
    expect(fnBody('renderMarketplace')).toContain('item.cve_id');
  });

  it('builds the price/priceNum from item.price_inr as a number, with the fallback string as a secondary path', () => {
    const body = fnBody('renderMarketplace');
    expect(body).toContain('item.price_inr');
    expect(body).toMatch(/item\.price_inr\s*!=\s*null\s*\?\s*Number\(item\.price_inr\)/);
  });
});

describe('renderMarketplace — routes live-sourced items to the correct purchase endpoint', () => {
  it('tracks whether the rendered items came from the live API', () => {
    const body = fnBody('renderMarketplace');
    expect(body).toContain('liveSource');
    expect(body).toMatch(/liveSource\s*=\s*true/);
  });

  it('live items call window.cdbBuySolution, not window.CDB_PAY.open', () => {
    const body = fnBody('renderMarketplace');
    expect(body).toMatch(/liveSource\s*\n?\s*\?\s*`window\.cdbBuySolution && window\.cdbBuySolution\(/);
  });

  it('fallback (static-catalog) items still call window.CDB_PAY.open', () => {
    const body = fnBody('renderMarketplace');
    expect(body).toContain("window.CDB_PAY && window.CDB_PAY.open('${item.id}'");
  });
});

describe('cdbBuySolution — new purchase flow for dynamic defense_solutions items', () => {
  function cdbBuySolutionBody() {
    const start = fe.indexOf('async function cdbBuySolution(solutionId, priceInr, label)');
    expect(start, 'cdbBuySolution must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('window.cdbBuySolution = cdbBuySolution;', start);
    expect(end, 'cdbBuySolution export must be found').toBeGreaterThan(-1);
    return fe.slice(start, end);
  }

  it('is defined and exposed on window', () => {
    expect(fe).toContain('async function cdbBuySolution(solutionId, priceInr, label)');
    expect(fe).toContain('window.cdbBuySolution = cdbBuySolution;');
  });

  it('creates the order against /api/defense/purchase/:id, never /api/tools/purchase', () => {
    const body = cdbBuySolutionBody();
    expect(body).toContain("fetch('/api/defense/purchase/' + encodeURIComponent(solutionId)");
    expect(body).not.toContain('/api/tools/purchase');
  });

  it('verifies payment against /api/defense/verify/:id, never /api/tools/verify', () => {
    const body = cdbBuySolutionBody();
    expect(body).toContain("fetch('/api/defense/verify/' + encodeURIComponent(solutionId)");
    expect(body).not.toContain('/api/tools/verify');
  });

  it("checks order.order_id (the defense-purchase response field), not order.razorpay_order_id (the tools-purchase field)", () => {
    const body = cdbBuySolutionBody();
    expect(body).toMatch(/String\(order\.order_id\)\.indexOf\('order_'\)\s*!==\s*0/);
    expect(body).not.toContain('order.razorpay_order_id');
  });

  it('falls back to the manual/WhatsApp flow when the order lacks a real Razorpay order_id', () => {
    const body = cdbBuySolutionBody();
    expect(body).toMatch(/if \(!oRes\.ok \|\| !order \|\| !order\.razorpay_key \|\| !order\.order_id \|\|/);
    expect(body).toContain('manualFallback(); return;');
  });
});
