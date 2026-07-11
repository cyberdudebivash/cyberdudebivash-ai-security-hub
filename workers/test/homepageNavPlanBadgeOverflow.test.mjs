/* P1 — the homepage's desktop nav row ("#nav-links-desktop") is a
 * non-wrapping flex row with a lot of items (Free Scan, Pricing, API, AI
 * Security, AI Threat Intel, Threat Intel, Trust, MASOC, GOD MODE, the
 * FREEMIUM plan badge, Book Demo), followed by the auth-gated "Sign In" link
 * injected into #cdb-nav-actions. The FREEMIUM badge — inert branding text,
 * not a link or button — was one of the widest items in that row and
 * several scripts (renderPlanBadge, fixFreeBadge, patchBranding) kept
 * re-showing it. Confirmed live at real desktop widths (1280px, 1440px):
 * "Sign In" was pushed fully off-screen at 1280px and clipped at the very
 * edge of the viewport at 1440px, while mobile (which hides this whole row
 * for a hamburger drawer) was unaffected — matching the customer report of
 * "Sign In lists clearly on mobile but not on desktop".
 *
 * Fix: a CSS override forces the badge to permanently render nothing and
 * take zero layout space, without deleting the element — a separate script
 * anchors the "API Keys" nav-button injection to this exact node
 * (insertBefore(keyBtn, navBadge.nextSibling)), so removing the element
 * outright would have silently broken that button for logged-in users.
 * Live-verified after the fix: "Sign In" fully inside the viewport at both
 * 1280px and 1440px, and the anchor-based API Keys button injection still
 * works with the badge hidden.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const html = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

describe('Homepage nav plan badge no longer crowds "Sign In" off the desktop viewport (P1)', () => {
  it('a CSS rule forces #nav-plan-badge to never render', () => {
    const idx = html.indexOf('#nav-plan-badge { display: none !important; }');
    expect(idx).toBeGreaterThan(-1);
  });

  it('the badge element itself is still present in the DOM (required as the API Keys button anchor)', () => {
    expect(html).toContain('<span id="nav-plan-badge"');
  });

  it('the API Keys button injection still anchors off nav-plan-badge (untouched)', () => {
    const idx = html.indexOf("const navBadge = document.getElementById('nav-plan-badge')");
    expect(idx).toBeGreaterThan(-1);
    expect(html.slice(idx, idx + 700)).toContain('insertBefore(keyBtn, navBadge.nextSibling)');
  });
});
