/* The homepage's "Command Centers" widget used an exclusive single-tab
 * pattern across all 5 sections (Executive/SOC Operations/Sentinel APEX
 * Intel/AI SecOps/MSSP Operations) — only the Executive tab was visible by
 * default, and the other 4 were `display:none` until clicked. A page-text
 * dump tool (or a skimming visitor) never sees `display:none` content, so
 * the live incident/CVE intelligence (SOC Operations, Sentinel APEX Intel —
 * both genuinely public, no customer or revenue data) looked entirely
 * missing from the dashboard even though dashboard-live.js was already
 * fetching and rendering real data into them on page load.
 *
 * Fix: Executive, SOC Operations, and Sentinel APEX Intel are now visible by
 * default (stacked, not hidden behind a click). AI SecOps (each account's
 * own AI asset inventory) and MSSP Operations (managed client counts,
 * partner revenue-share terms) are customer/revenue sections and
 * deliberately stay tab-gated, unchanged.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');
const js = readFileSync(resolve(root, '../frontend/dashboard-live.js'), 'utf8');

function panelClassAttr(id) {
  const m = fe.match(new RegExp(`<div[^>]*id="${id}"[^>]*>`));
  expect(m, `panel #${id} must exist`).toBeTruthy();
  const classMatch = m[0].match(/class="([^"]*)"/);
  return classMatch ? classMatch[1] : '';
}

describe('Command Centers — public sections visible by default (CAP dashboard-intel-visibility)', () => {
  it('Executive, SOC Operations, and Sentinel APEX Intel panels are active (visible) by default', () => {
    expect(panelClassAttr('cdb-panel-exec')).toContain('active');
    expect(panelClassAttr('cdb-panel-soc')).toContain('active');
    expect(panelClassAttr('cdb-panel-sentinel')).toContain('active');
  });

  it('AI SecOps and MSSP Operations (customer/revenue sections) remain hidden by default', () => {
    expect(panelClassAttr('cdb-panel-ai')).not.toContain('active');
    expect(panelClassAttr('cdb-panel-mssp')).not.toContain('active');
  });

  it('the public panels are marked as jump-links, not exclusive show/hide tabs', () => {
    const start = fe.indexOf('Command center sections');
    expect(start).toBeGreaterThan(-1);
    const nav = fe.slice(start, start + 900);
    expect(nav).toMatch(/data-scrollto="cdb-panel-exec"[^>]*data-cc-jump="true"|data-cc-jump="true"[^>]*data-scrollto="cdb-panel-exec"/);
    expect(nav).toMatch(/data-scrollto="cdb-panel-soc"/);
    expect(nav).toMatch(/data-scrollto="cdb-panel-sentinel"/);
    // AI SecOps / MSSP keep the real tab-toggle wiring (data-target + role="tab").
    expect(nav).toMatch(/data-target="cdb-panel-ai"[^>]*role="tab"/);
    expect(nav).toMatch(/data-target="cdb-panel-mssp"[^>]*role="tab"/);
  });

  it('clicking a public jump-button only scrolls — it never hides any .cdb-cc-panel', () => {
    const start = js.indexOf('data-cc-jump="true"');
    expect(start).toBeGreaterThan(-1);
    const handlerBody = js.slice(start, js.indexOf('document.querySelectorAll(\'.cdb-cc-tab[data-target]\')', start));
    expect(handlerBody).toContain('scrollIntoView');
    expect(handlerBody).not.toContain('classList.remove');
  });

  it('the AI SecOps/MSSP exclusive toggle only ever hides itself and its sibling — never the 3 public panels', () => {
    const idx = js.indexOf("querySelectorAll('#cdb-panel-ai, #cdb-panel-mssp')");
    expect(idx, 'the hide-on-click call must be scoped to just the two gated panel IDs').toBeGreaterThan(-1);
    // Must NOT use the old blanket selector that hid every .cdb-cc-panel.
    expect(js).not.toContain("document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'))");
  });

  it('CSS makes non-active panels display:none and active panels display:block (multiple can be active at once)', () => {
    expect(fe).toContain('.cdb-cc-panel { display: none; }');
    expect(fe).toMatch(/\.cdb-cc-panel\.active\s*\{\s*display:\s*block/);
  });

  it('SOC Operations panel documents why it is safe to show publicly (case management self-gates)', () => {
    const idx = fe.indexOf('id="cdb-panel-soc"');
    expect(idx).toBeGreaterThan(-1);
    const before = fe.slice(Math.max(0, idx - 400), idx);
    expect(before).toMatch(/self-gates|401|login prompt/i);
  });

  it('AI SecOps and MSSP panels are documented as intentionally excluded (customer/revenue data)', () => {
    const aiIdx = fe.indexOf('id="cdb-panel-ai"');
    const msspIdx = fe.indexOf('id="cdb-panel-mssp"');
    expect(fe.slice(Math.max(0, aiIdx - 300), aiIdx)).toMatch(/customer/i);
    expect(fe.slice(Math.max(0, msspIdx - 300), msspIdx)).toMatch(/customer|revenue/i);
  });
});
