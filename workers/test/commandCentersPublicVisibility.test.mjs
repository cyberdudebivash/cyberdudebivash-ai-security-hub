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
 *
 * A first pass at this fix (making the 3 public buttons plain, non-tab
 * children of a role="tablist" container) passed manual review but FAILED
 * axe-core in CI twice, for real reasons — both confirmed and re-verified
 * fixed with a local axe-core run (matching CI's exact recipe: same
 * @axe-core/cli version, a matching Chrome-for-Testing build, the same
 * `python3 -m http.server --directory frontend/`) before pushing again:
 *  1. aria-required-parent — soc-case-detail.js self-injects a genuine
 *     role="tab" button directly into .cdb-cc-nav at runtime; swapping that
 *     container's role away from tablist left every role="tab" child
 *     (including the injected one) without its required ARIA parent.
 *  2. aria-required-children — a tablist may only contain tab children;
 *     mixing the 3 plain jump-buttons directly into a role="tablist"
 *     container violated this the other way around.
 *  3. color-contrast — soc-investigations.js's injected Case Management
 *     sub-section (previously always display:none, so axe never evaluated
 *     it) used a non-token color (#475569) that fails WCAG AA against the
 *     page's dark background.
 * Resolved by nesting the real tablist (just the 2 static gated tabs) as a
 * `display:contents` child of the outer group — zero visual/layout change,
 * but now a `role="tablist"` truly contains only `role="tab"` children, and
 * soc-case-detail.js targets that inner tablist so its injected tab lands
 * inside it too. Muted text switched to the existing --text-muted token.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe   = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');
const js   = readFileSync(resolve(root, '../frontend/dashboard-live.js'), 'utf8');
const socInv    = readFileSync(resolve(root, '../frontend/soc-investigations.js'), 'utf8');
const socDetail = readFileSync(resolve(root, '../frontend/soc-case-detail.js'), 'utf8');

function panelClassAttr(id) {
  const m = fe.match(new RegExp(`<div[^>]*id="${id}"[^>]*>`));
  expect(m, `panel #${id} must exist`).toBeTruthy();
  const classMatch = m[0].match(/class="([^"]*)"/);
  return classMatch ? classMatch[1] : '';
}

describe('Command Centers — public sections visible by default (CAP dashboard-intel-visibility)', () => {
  it('Executive, SOC Operations, and Sentinel APEX Intel panels are active (visible) and marked public by default', () => {
    for (const id of ['cdb-panel-exec', 'cdb-panel-soc', 'cdb-panel-sentinel']) {
      const cls = panelClassAttr(id);
      expect(cls).toContain('active');
      expect(cls).toContain('cdb-cc-panel-public');
    }
  });

  it('AI SecOps and MSSP Operations (customer/revenue sections) remain hidden and unmarked by default', () => {
    for (const id of ['cdb-panel-ai', 'cdb-panel-mssp']) {
      const cls = panelClassAttr(id);
      expect(cls).not.toContain('active');
      expect(cls).not.toContain('cdb-cc-panel-public');
    }
  });

  it('a role="tablist" exists and contains only the two real gated tabs (aria-required-children)', () => {
    const start = fe.indexOf('class="cdb-cc-tablist" role="tablist"');
    expect(start, '.cdb-cc-tablist wrapper must exist').toBeGreaterThan(-1);
    const end = fe.indexOf('</div>', start);
    const inner = fe.slice(start, end);
    expect(inner).toContain('data-target="cdb-panel-ai"');
    expect(inner).toContain('data-target="cdb-panel-mssp"');
    // Must not contain any of the 3 public jump-buttons.
    expect(inner).not.toContain('data-cc-jump');
  });

  it('the tablist wrapper uses display:contents so nesting it causes no visual/layout change', () => {
    expect(fe).toContain('class="cdb-cc-tablist" role="tablist" style="display:contents"');
  });

  it('every role="tab" element has a role="tablist" ancestor (aria-required-parent) — outer group is not itself a tablist', () => {
    const navStart = fe.indexOf('aria-label="Command center sections"');
    expect(navStart).toBeGreaterThan(-1);
    const navTagStart = fe.lastIndexOf('<div', navStart);
    const navTag = fe.slice(navTagStart, fe.indexOf('>', navTagStart) + 1);
    expect(navTag).toContain('role="group"');
    expect(navTag).not.toContain('role="tablist"');
  });

  it('the public panels are marked as jump-links, not exclusive show/hide tabs', () => {
    const start = fe.indexOf('Command center sections');
    expect(start).toBeGreaterThan(-1);
    const nav = fe.slice(start, start + 1100);
    expect(nav).toMatch(/data-scrollto="cdb-panel-exec"[^>]*data-cc-jump="true"|data-cc-jump="true"[^>]*data-scrollto="cdb-panel-exec"/);
    expect(nav).toMatch(/data-scrollto="cdb-panel-soc"/);
    expect(nav).toMatch(/data-scrollto="cdb-panel-sentinel"/);
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

  it('the AI SecOps/MSSP exclusive toggle uses the public-panel exclusion class, never hardcoded IDs', () => {
    expect(js).toContain(".cdb-cc-panel:not(.cdb-cc-panel-public)");
    // Must NOT use the old blanket selector that hid every .cdb-cc-panel.
    expect(js).not.toContain("document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'))");
  });

  it('soc-case-detail.js\'s injected Investigation tab targets the real tablist, and its own toggle also excludes public panels', () => {
    expect(socDetail).toContain("document.querySelector('.cdb-cc-tablist')");
    expect(socDetail).not.toContain("document.querySelector('.cdb-cc-nav')");
    expect(socDetail).toContain(".cdb-cc-panel:not(.cdb-cc-panel-public)");
    expect(socDetail).not.toContain("document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'))");
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

  it('the Case Management sub-section (now potentially visible by default) uses a WCAG-AA-safe muted color, not the old failing one', () => {
    expect(socInv).not.toContain('#475569');
    expect(socInv).toContain('#94a3b8'); // --text-muted token used elsewhere on this same page
  });
});
