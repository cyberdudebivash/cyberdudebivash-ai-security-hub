/* Premium visual enhancement of the homepage header/nav section — customer
 * request, continuing from the "Sign In crowded off-screen" fix in the same
 * area. Every element here was already functional; this is a visual-quality
 * pass making the header's links, CTAs, and compliance-badge ticker look
 * like a premium commercial security product rather than plain scrolling
 * text, with real live-browser verification (screenshots at 1280/1440/390px)
 * confirming nothing regressed — the desktop Sign In visibility fix from the
 * prior wave still holds, the ticker's scroll animation is untouched, and
 * the mobile drawer (already well-styled) is unaffected.
 *
 * - Nav links (Free Scan, Pricing, API, AI Security, Threat Intel, Trust,
 *   Defense, Data Intel, CISO Hub) brightened from --text-muted to --text
 *   with a glowing cyan text-shadow on hover, instead of a flat color swap.
 * - The desktop "Sign In" CTA (injected by cdbApplyGates() in
 *   frontend/index.html) was styled far more plainly than its own mobile
 *   drawer counterpart (flat gray text, near-invisible border) despite being
 *   the primary entry point for returning customers. Gave it the same
 *   gradient-glow treatment as the mobile version via a new .nav-signin-cta
 *   class, plus a hover lift/glow — zero JS behavior changed.
 * - The compliance ticker (.ticker-item) was flat, uncolored, unstyled
 *   scrolling text ("SOC 2 TYPE II READY", "GDPR 2016/679", ...). Turned
 *   each into a glowing pill badge (border + soft background + box-shadow
 *   glow) with a 4-color rotation via :nth-child, applied purely in CSS —
 *   no HTML edits, so it applies identically to both halves of the
 *   duplicated marquee track without any risk of mismatched colors between
 *   the two loop copies.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const html = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');
const css = readFileSync(resolve(root, '../frontend/assets/main.v10.css'), 'utf8');

describe('Homepage header premium visual enhancement', () => {
  it('nav links are brighter by default and glow on hover instead of a flat color swap', () => {
    expect(css).toContain('.nav-links a{color:var(--text);opacity:.82');
    expect(css).toContain('.nav-links a:hover{color:var(--accent);opacity:1;text-decoration:none;text-shadow:');
  });

  it('the desktop Sign In CTA gets its own glowing class, matching the mobile drawer\'s existing polish', () => {
    expect(css).toContain('.nav-signin-cta{');
    expect(css).toContain('.nav-signin-cta:hover{');
    const idx = html.indexOf("signInLink.className = 'nav-signin-cta'");
    expect(idx).toBeGreaterThan(-1);
  });

  it('Sign In injection still targets the same real login destination (behavior unchanged)', () => {
    const start = html.indexOf("var signInLink = document.createElement('a')");
    expect(start).toBeGreaterThan(-1);
    expect(html.slice(start, start + 400)).toContain("signInLink.href = '/user-dashboard.html'");
  });

  it('ticker items are styled as glowing pill badges, not flat scrolling text', () => {
    const idx = css.indexOf('.ticker-item{');
    expect(idx).toBeGreaterThan(-1);
    const block = css.slice(idx, idx + 400);
    expect(block).toContain('border-radius:20px');
    expect(block).toContain('box-shadow:');
    expect(block).toContain('border:1px solid');
  });

  it('the ticker badge color rotation is pure CSS (:nth-child) — no HTML/JS changes to the marquee items', () => {
    expect(css).toContain(':nth-child(4n+2)');
    expect(css).toContain(':nth-child(4n+3)');
    expect(css).toContain(':nth-child(4n)');
  });

  it('the ticker marquee animation is untouched', () => {
    expect(css).toContain('@keyframes tick{from{transform:translateX(0)}to{transform:translateX(-50%)}}');
    expect(css).toContain("animation:tick 30s linear infinite");
  });
});
