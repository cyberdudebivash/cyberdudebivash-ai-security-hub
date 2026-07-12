/* Regression test — ops-dashboard.html referenced a DOM element id that
 * doesn't exist, silently breaking the Top Endpoints table (Tier 3 backlog
 * item #2; see docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * loadMetrics() ran, in order within a single try block:
 *   1. document.getElementById('wh-bar').style.width = ratio + '%';
 *   2. const tbody = document.querySelector('#top-endpoints tbody');
 *      tbody.innerHTML = (d.d1.top_endpoints || []).map(...)...
 *
 * The real element's id is 'wh-kv-bar' (confirmed against the HTML markup)
 * — 'wh-bar' does not exist anywhere on the page. getElementById('wh-bar')
 * therefore always returned null, and null.style threw a TypeError,
 * silently swallowed by the function's empty `catch {}`. Because that throw
 * happened on the line immediately before the Top Endpoints table
 * population *in the same try block*, execution never reached it — the
 * table's real, correctly-wired data (verified separately: both the DOM id
 * (#top-endpoints) and the backend field path (d.d1.top_endpoints) were
 * already correct) never had a chance to render, for any visitor, ever.
 *
 * Pure static parse — no browser/network. Generalizes beyond the one
 * instance: asserts every literal getElementById/querySelector('#...') id
 * reference in this file's inline script has a matching id="..." somewhere
 * in the page, catching this entire bug class, not just this one line.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/ops-dashboard.html'), 'utf8');

function extractIds(re) {
  return new Set([...fe.matchAll(re)].map(m => m[1]));
}

describe('every literal getElementById/querySelector id reference resolves to a real element', () => {
  const referenced = new Set([
    ...extractIds(/getElementById\('([a-zA-Z0-9_-]+)'\)/g),
    ...extractIds(/querySelector\('#([a-zA-Z0-9_-]+)/g),
  ]);
  const defined = extractIds(/\bid="([a-zA-Z0-9_-]+)"/g);

  it('found at least one referenced id and one defined id (sanity check on the extraction itself)', () => {
    expect(referenced.size).toBeGreaterThan(10);
    expect(defined.size).toBeGreaterThan(10);
  });

  it('every referenced id has a matching id="..." in the HTML — no orphan references', () => {
    const orphans = [...referenced].filter(id => !defined.has(id));
    expect(orphans, `orphan id reference(s) with no matching element: ${orphans.join(', ')}`).toEqual([]);
  });
});

describe('the specific fix: the KV health bar width update targets the real element', () => {
  it("no longer references the nonexistent 'wh-bar' id", () => {
    expect(fe).not.toContain("getElementById('wh-bar')");
  });

  it("sets .style.width on the real 'wh-kv-bar' element", () => {
    expect(fe).toContain("getElementById('wh-kv-bar').style.width");
  });

  it('the wh-kv-bar element genuinely exists in the markup', () => {
    expect(fe).toContain('id="wh-kv-bar"');
  });
});

describe('the Top Endpoints table itself was always correctly wired (the id 2 lines below wh-bar was fine)', () => {
  it('#top-endpoints exists and is targeted by the metrics loader', () => {
    expect(fe).toContain('id="top-endpoints"');
    expect(fe).toContain("querySelector('#top-endpoints tbody')");
  });

  it('reads the real nested backend field path d.d1.top_endpoints', () => {
    expect(fe).toContain('d.d1.top_endpoints');
  });
});
