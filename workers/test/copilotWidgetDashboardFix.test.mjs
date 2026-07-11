/* P0/P1 — APEX Copilot widget silently unauthenticated on the dashboard, and
 * its floating launcher visually collided with the dashboard sidebar's own
 * nav links.
 *
 * ROOT CAUSE (auth): frontend/assets/copilot-widget.js is loaded site-wide
 * (250+ pages, including frontend/user-dashboard.html). Its authHeaders()
 * only checked localStorage/sessionStorage 'cdb_token' — the key
 * frontend/index.html and its OAuth callback genuinely use. But
 * user-dashboard.html's own login/signup overlay (saveTokens()) writes the
 * real session token to sessionStorage['cdb_access'] only. A customer who
 * signed up or logged in through the dashboard — the primary paid-product
 * surface — got a copilot chat that silently sent every request with no
 * Authorization header at all, so the backend treated them as an anonymous
 * FREE-tier visitor regardless of their real plan. Confirmed live via
 * Playwright: before the fix, /api/copilot/capabilities went out with no
 * Authorization header for a freshly signed-up, still-in-session dashboard
 * user; after the fix, it carries `Bearer <the real per-user JWT>`.
 *
 * ROOT CAUSE (overlap): #cdb-copilot-fab is fixed at left:24/bottom:150,
 * chosen to clear the marketing homepage's own bottom-right clutter
 * (WhatsApp CTA, back-to-top). Nobody accounted for
 * frontend/user-dashboard.html's own fixed-height `.sidebar`, whose last nav
 * items (API Usage, Settings) render in that same bottom-left band — the
 * FAB's z-index:99980 sat on top of them on every dashboard screenshot taken
 * at desktop width, visually obscuring (and, given the z-index, very likely
 * click-stealing from) those nav links.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const widget = readFileSync(resolve(root, '../frontend/assets/copilot-widget.js'), 'utf8');
const dashboard = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fnBody(src, name, len = 800) {
  const start = src.indexOf(`function ${name}`);
  if (start === -1) return '';
  return src.slice(start, start + len);
}

describe('APEX Copilot widget reads the dashboard session token (P0/P1)', () => {
  it('authHeaders() checks sessionStorage cdb_access before the homepage cdb_token keys', () => {
    const body = fnBody(widget, 'authHeaders');
    expect(body).not.toBe('');
    const accessIdx = body.indexOf("sessionStorage.getItem('cdb_access')");
    const tokenIdx = body.indexOf("localStorage.getItem('cdb_token')");
    expect(accessIdx).toBeGreaterThan(-1);
    expect(tokenIdx).toBeGreaterThan(-1);
    expect(accessIdx).toBeLessThan(tokenIdx);
  });

  it('the homepage/OAuth cdb_token fallback is preserved (still used by index.html, god-mode.html, intel-hub.html)', () => {
    const body = fnBody(widget, 'authHeaders');
    expect(body).toContain("localStorage.getItem('cdb_token')");
    expect(body).toContain("sessionStorage.getItem('cdb_token')");
  });
});

describe('APEX Copilot FAB avoids the dashboard sidebar (P1)', () => {
  it('injectStyles() adds a dashboard-scoped override when .sidebar is present', () => {
    const idx = widget.indexOf("document.querySelector('.sidebar')");
    expect(idx).toBeGreaterThan(-1);
    const around = widget.slice(idx, idx + 500);
    expect(around).toContain('cdb-copilot-dashboard-override');
    expect(around).toContain('right:24px');
    expect(around).toContain('bottom:100px');
  });

  it('the override only applies at desktop widths, matching the sidebar\'s own 769px breakpoint', () => {
    const idx = widget.indexOf('cdb-copilot-dashboard-override');
    expect(idx).toBeGreaterThan(-1);
    expect(widget.slice(idx, idx + 300)).toContain('min-width:769px');
  });

  it('user-dashboard.html still hides .sidebar below 768px (the override\'s assumption holds)', () => {
    expect(dashboard).toContain('.sidebar { display: none; }');
  });
});

describe('AI Analysis page no longer shows the dead "— queries left" badge (cleanup)', () => {
  it('the inert ai-credits-badge span is gone', () => {
    expect(dashboard).not.toContain('id="ai-credits-badge"');
    expect(dashboard).not.toContain('>— queries left<');
  });

  it('the AI Threat Analyst panel header is otherwise intact', () => {
    expect(dashboard).toContain('<span class="ai-panel-title">AI Threat Analyst</span>');
  });
});
