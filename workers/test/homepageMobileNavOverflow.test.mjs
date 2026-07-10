/* CAP-IDN-001 regression — P0: mobile "Sign In" nav entry point unreachable.
 *
 * ROOT CAUSE (confirmed live in a real Chromium session against production,
 * viewports 320/360/375/390/414/428px, before this fix):
 * frontend/assets/cdb-mobile-responsive.css ("UNIVERSAL MOBILE / TABLET
 * RESPONSIVE LAYER", authored 2026-06-13) never constrained #cdb-nav-actions
 * (search trigger + notification bell + hamburger toggle) because at that
 * time it only held 3 fixed-size icon buttons that fit every phone width.
 * CAP-IDN-001 (commit f3c38d0, 2026-07-09) later injected a 4th child — a
 * ~90px "Sign In" pill — into that same row for logged-out visitors. Nobody
 * re-verified mobile nav layout after that change: the row's total content
 * width (measured 424px, constant regardless of viewport) exceeded every
 * common phone viewport, and with `overflow-x: clip` on html/body (added for
 * an unrelated reason, further up in this same file) the excess is silently
 * clipped rather than scrollable. The #nav-hamburger toggle — and on
 * narrower phones part of the notification bell — rendered completely
 * outside the reachable viewport, making the mobile nav drawer unreachable.
 * (Sign In itself stayed visible only because it's inserted as the FIRST
 * child of the row — incidental, not a fix, and not guaranteed to survive
 * any future addition to that same row.)
 *
 * FIX: reclaim width from the row itself (hide the keyboard-only search
 * trigger on touch, tighten gaps, shrink icon buttons and the injected Sign
 * In pill, lightly compact the wordmark on the narrowest phones) — verified
 * live via Playwright to bring both #nav-hamburger and the injected Sign In
 * link fully within the viewport at 320/360/375/390/414/428px, and confirmed
 * the hamburger click now actually opens #nav-mobile-drawer.
 *
 * SECONDARY HARDENING: frontend/index.html's readAuth() (called at the top
 * of the same cdbApplyGates() IIFE that injects Sign In) called
 * localStorage.getItem() with no try/catch. Any browser context where
 * localStorage access throws (privacy-restricted in-app webviews, storage
 * disabled by device policy) aborted the entire IIFE before
 * window.cdbApplyGates was even assigned — silently deleting the Sign In
 * injection, the Dashboard link, and owner gates for that visitor with no
 * visible error. Verified live (Playwright, localStorage getter forced to
 * throw on every access) that with this guard, window.cdbApplyGates and the
 * Sign In link both still exist.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const css = readFileSync(resolve(root, '../frontend/assets/cdb-mobile-responsive.css'), 'utf8');
const html = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

function fnBody(source, name) {
  const start = source.indexOf(`function ${name}`);
  if (start === -1) return '';
  return source.slice(start, start + 1200);
}

describe('Homepage mobile nav overflow (CAP-IDN-001 follow-on)', () => {
  it('reclaims width in #cdb-nav-actions inside a max-width:768px query (zero desktop impact)', () => {
    const idx = css.indexOf('#cdb-nav-actions { gap: 4px !important; }');
    expect(idx).toBeGreaterThan(-1);
    const mediaStart = css.lastIndexOf('@media (max-width: 768px)', idx);
    expect(mediaStart).toBeGreaterThan(-1);
    // The rule must actually be inside that media block, not merely preceded by it.
    const blockOpen = css.indexOf('{', mediaStart);
    const blockClose = css.indexOf('\n}', idx);
    expect(idx).toBeGreaterThan(blockOpen);
    expect(idx).toBeLessThan(blockClose);
  });

  it('hides the keyboard-only search trigger and shrinks the icon buttons on phones', () => {
    expect(css).toContain('#cdb-search-trigger { display: none !important; }');
    expect(css).toMatch(/#cdb-notif-bell,\s*#nav-hamburger\s*\{\s*width:\s*32px\s*!important;\s*height:\s*32px\s*!important;/);
  });

  it('compacts the JS-injected Sign In pill so it no longer inflates the row on phones', () => {
    const idx = css.indexOf('#cdb-nav-actions [data-auth-section="signin"]');
    expect(idx).toBeGreaterThan(-1);
    expect(css.slice(idx, idx + 150)).toContain('font-size: 11px !important');
  });

  it('compacts the wordmark on the narrowest phones without removing either text line', () => {
    expect(css).toContain('@media (max-width: 340px)');
    expect(css).toContain('a.nav-brand img');
    // Must NOT delete the wordmark text — only resize it.
    expect(css).not.toMatch(/nav-brand[^{]*\{\s*display:\s*none/);
    expect(css).not.toMatch(/nav-brand\s*>\s*div\s*\{\s*display:\s*none/);
  });

  it('readAuth() guards localStorage access so a throwing storage context cannot delete the Sign In injection', () => {
    const gate = fnBody(html, 'readAuth');
    expect(gate).not.toBe('');
    expect(gate).toMatch(/try\s*\{[\s\S]*localStorage\.getItem\(['"]cdb_email['"]\)/);
    expect(gate).toMatch(/\}\s*catch\s*\(e\)\s*\{\s*return\s*\{\s*email:\s*null,\s*tier:\s*'FREE',\s*isAuthenticated:\s*false/);
  });

  it('the guarded readAuth() still runs before cdbApplyGates is defined (ordering unchanged)', () => {
    const readAuthIdx = html.indexOf('function readAuth()');
    const applyGatesIdx = html.indexOf('window.cdbApplyGates = function cdbApplyGates()');
    expect(readAuthIdx).toBeGreaterThan(-1);
    expect(applyGatesIdx).toBeGreaterThan(readAuthIdx);
  });
});
