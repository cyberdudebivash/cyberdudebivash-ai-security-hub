// EPCAA independent acceptance review — static guard against fabricated
// "measured result" metrics reappearing on the homepage.
//
// Found live: the Trust Center's uptime counter had an `IntersectionObserver`
// animation with a HARDCODED `target: 99.9` that fired unconditionally on
// scroll, directly contradicting the comment immediately above it ("do NOT
// hardcode targets here"). On any /api/trust/metrics failure/timeout, this
// hardcoded number was the ONLY thing ever shown, with just a console.warn.
// A prior, independent fix (commit 87781f2) corrected the initial HTML markup
// to "—" but did not touch this animation bug, so the fake 99.9% still fired
// the moment the section scrolled into view.
//
// Separately, `p4-cnt-uptime` was hardcoded to a static percentage in markup
// and NEVER referenced by any JS anywhere in the file — a permanently fake
// "measured" stat sitting beside three honestly live-hydrated sibling
// counters (p4-cnt-scans/threats/orgs). And the training-academy bundle card
// had a static "N enrolled today" fake-urgency counter with zero backing
// data source anywhere in the codebase.
//
// This does not re-litigate legitimate SLA COMMITMENT labels (e.g. "Uptime
// SLA Target: 99.9%", "CVE Alert SLA: <2h") — those are policy statements,
// not claims of measured historical performance, and are unaffected.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(resolve(__dirname, '../../frontend/index.html'), 'utf8');

describe('Trust Center uptime — no hardcoded measured-result target', () => {
  it('the animateCounter METRICS array does not carry a hardcoded uptime target', () => {
    const metricsBlock = HTML.match(/var METRICS = \[[\s\S]*?\];/)?.[0] || '';
    expect(metricsBlock).not.toMatch(/id:\s*'tm-uptime'/);
  });

  it('tm-uptime starts as an honest placeholder, not a fabricated percentage', () => {
    const markup = HTML.match(/<div class="trust-metric-num" id="tm-uptime">([^<]*)<\/div>/);
    expect(markup).toBeTruthy();
    expect(markup[1]).toBe('—');
  });

  it('tm-uptime is only ever set from the real /api/trust/metrics response, using a null-check (not truthiness)', () => {
    expect(HTML).toMatch(/if\s*\(\s*eu\s*&&\s*m\.uptime_pct\s*!=\s*null\s*\)/);
    // Must NOT use the old truthy check, which silently skips a real 0% (outage).
    expect(HTML).not.toMatch(/if\s*\(\s*m\.uptime_pct\s*\)\s*\{\s*\n\s*var eu/);
  });
});

describe('Authority-pill counter row — no orphaned fabricated stat', () => {
  it('p4-cnt-uptime is an honest placeholder like its live-hydrated siblings, not a frozen fake percentage', () => {
    const markup = HTML.match(/<div id="p4-cnt-uptime"[^>]*>([^<]*)<\/div>/);
    expect(markup).toBeTruthy();
    expect(markup[1]).toBe('—');
  });

  it('the real, JS-hydrated siblings are untouched (regression guard)', () => {
    expect(HTML).toMatch(/<div id="p4-cnt-scans"[^>]*>—<\/div>/);
    expect(HTML).toMatch(/<div id="p4-cnt-threats"[^>]*>—<\/div>/);
    expect(HTML).toMatch(/<div id="p4-cnt-orgs"[^>]*>—<\/div>/);
  });
});

describe('Training academy — no fake urgency counter', () => {
  it('does not claim a specific "N enrolled today" with no backing data source', () => {
    expect(HTML).not.toMatch(/id="acs-bundle-today"/);
    expect(HTML).not.toMatch(/\d+\s*<\/span>\s*enrolled today/);
  });
});

describe('Legitimate SLA commitment labels are preserved (not falsely flagged)', () => {
  it('still advertises the Enterprise Uptime SLA TARGET (a policy commitment, not a measured claim)', () => {
    expect(HTML).toContain('Uptime SLA Target');
  });
});
