/* Regression test — academy.html's "attention strip" CVE/scan counters read
 * the wrong field paths and one was permanently invisible (Tier 2 backlog
 * item #8, the last Tier-2 item; see docs/capability-registry/PROGRAM_BOARD.md
 * session log).
 *
 * liveCounters() read d.cves_tracked and d.total_scans directly off
 * GET /api/health's top-level response. Neither field exists there:
 *   - /api/health has no cves_tracked field anywhere (it tracks D1/KV/cache
 *     health and scan counts, not CVE counts).
 *   - /api/health's scan count is real but nested at `stats.total_scans`,
 *     never a top-level `total_scans`.
 * Both reads always evaluated to undefined, so #acy-cve silently kept its
 * static "3" fallback forever, and #acy-scan — which has no static text of
 * its own and starts `display:none` in the markup, meant to be revealed by
 * this same script once real data loads — never appeared at all, for any
 * visitor, ever.
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/academy.html'), 'utf8');

function liveCountersBody() {
  const start = fe.indexOf('function liveCounters()');
  expect(start, 'liveCounters must exist').toBeGreaterThan(-1);
  const end = fe.indexOf('\n})();', start);
  expect(end, "liveCounters's closing \"})();\" must be found").toBeGreaterThan(-1);
  return fe.slice(start, end);
}

describe('liveCounters() reads the real, nested response field paths', () => {
  it('no longer reads the nonexistent top-level d.cves_tracked / d.total_scans', () => {
    const body = liveCountersBody();
    expect(body).not.toContain('.cves_tracked');
    expect(body).not.toContain('d.total_scans');
  });

  it('reads the real nested scan count from /api/health\'s stats.total_scans', () => {
    const body = liveCountersBody();
    expect(body).toContain('/api/health');
    expect(body).toMatch(/health\s*&&\s*health\.stats\s*&&\s*health\.stats\.total_scans/);
  });

  it('fetches the real CVE count from /api/threat-intel/stats\'s stats.critical', () => {
    const body = liveCountersBody();
    expect(body).toContain('/api/threat-intel/stats');
    expect(body).toMatch(/intel\s*&&\s*intel\.stats\s*&&\s*intel\.stats\.critical/);
  });
});

describe('the scan counter is actually revealed once real data loads', () => {
  it('clears the inline display:none on #acy-scan when a real count is available', () => {
    const body = liveCountersBody();
    expect(body).toMatch(/scanEl\.style\.display\s*=\s*''/);
  });

  it('sets descriptive text, not a bare number, since the span has no surrounding label in the HTML', () => {
    const body = liveCountersBody();
    expect(body).toMatch(/scanEl\.textContent\s*=\s*scans\.toLocaleString\(\)\s*\+\s*'[^']*scan/);
  });

  it('the #acy-scan span in the markup still starts hidden with no static text (JS is solely responsible for revealing it)', () => {
    expect(fe).toContain('<span id="acy-scan" style="display:none"></span>');
  });
});

describe('the CVE counter\'s copy no longer claims a "today" figure it cannot honestly show', () => {
  it('the static fallback label reads "tracked", not "today" (stats.critical is a live total, not time-boxed)', () => {
    expect(fe).toContain('critical CVEs tracked');
    expect(fe).not.toContain('critical CVEs today');
  });
});
