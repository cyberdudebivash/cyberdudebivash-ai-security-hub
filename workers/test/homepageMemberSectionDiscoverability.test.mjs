/* Customer-reported production gap, 2026-07-11 — clicking through from the
 * dashboard to 11 named homepage sections (frontend/index.html anchors like
 * #executive-hub, #auto-defense, #data-dominance) landed on content the
 * customer described as "not properly built." Investigation found most of
 * the 11 are real, backend-wired sections — but 3 of them (executive-hub,
 * auto-defense, data-dominance) are `data-auth-gate="true"` and `display:none`,
 * and any visitor who doesn't satisfy the gate (not logged in, or logged in
 * but browsing a page without direct knowledge of the exact #hash) was
 * silently scrolled back to the homepage top with ZERO explanation —
 * indistinguishable from a broken or nonexistent page — and even a
 * successfully-authenticated visitor had no nav link anywhere to discover
 * these sections exist at all (CDB_SECTIONS had no entries for them, and no
 * nav tab/drawer item pointed at them).
 *
 * Fixed: (1) CDB_SECTIONS now has proper labels for breadcrumb/nav-state
 * instead of falling back to the raw section id; (2) cdbNavigate()'s
 * auth-gate check now calls a new _showGateNotice() before redirecting,
 * telling the visitor why (sign in, or staff-only) instead of a silent
 * bounce; (3) cdbApplyGates() now injects nav links for these 3 sections
 * (both desktop nav and mobile drawer) for authenticated users, mirroring
 * the exact pre-existing Dashboard-link insertion pattern. The sections'
 * own gating attribute (data-auth-gate="true") and their content are
 * untouched — this is a discoverability/feedback fix, not a re-gate.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const indexHtml = readFileSync(
  fileURLToPath(new URL('../../frontend/index.html', import.meta.url)), 'utf8'
);

function spaRouterScriptBlock(html) {
  const start = html.indexOf('CDB v12.0 — PROFESSIONAL SPA NAVIGATION ROUTER');
  expect(start).toBeGreaterThan(-1);
  const end = html.indexOf('})();', start);
  return html.slice(start, end);
}

function authGateScriptBlock(html) {
  const start = html.indexOf('(function initAuthGate()');
  expect(start).toBeGreaterThan(-1);
  const end = html.indexOf('})();', start);
  return html.slice(start, end);
}

describe('CDB_SECTIONS now labels the 3 previously-uncatalogued member sections', () => {
  it('executive-hub, auto-defense, and data-dominance have real labels, not a raw-id fallback', () => {
    const block = spaRouterScriptBlock(indexHtml);
    expect(block).toMatch(/'executive-hub':\s*\{\s*label:\s*'Executive Hub'/);
    expect(block).toMatch(/'auto-defense':\s*\{\s*label:\s*'Auto-Defense'/);
    expect(block).toMatch(/'data-dominance':\s*\{\s*label:\s*'Threat Confidence'/);
  });

  it('the pre-existing section entries are untouched', () => {
    const block = spaRouterScriptBlock(indexHtml);
    expect(block).toMatch(/'hero':\s*\{\s*label:\s*'Home'/);
    expect(block).toMatch(/'dashboard':\s*\{\s*label:\s*'Dashboard'/);
    expect(block).toMatch(/'enterprise':\s*\{\s*label:\s*'Enterprise'/);
  });
});

describe('cdbNavigate()\'s auth-gate redirect now explains itself instead of a silent bounce', () => {
  it('calls _showGateNotice() before redirecting to hero, for both the member and owner gate branches', () => {
    const block = spaRouterScriptBlock(indexHtml);
    const gateIdx = block.indexOf("_gateAttr === 'owner' && !_auth.isOwner");
    expect(gateIdx).toBeGreaterThan(-1);
    const gateBlock = block.slice(gateIdx, gateIdx + 800);
    expect(gateBlock).toContain("_showGateNotice(_gateAttr === 'owner' ? 'owner' : 'auth', sectionId)");
    // The redirect itself (scroll-to-hero) must still happen — this is an
    // added explanation, not a replacement of the existing safe behavior.
    expect(gateBlock).toContain("window.scrollTo({ top: 0, behavior: 'smooth' })");
    expect(gateBlock).toContain("history.pushState({ section: 'hero' }, '', '#home')");
  });

  it('_showGateNotice() is defined, distinguishes owner-gate vs auth-gate wording, and offers a sign-in link only for the auth case', () => {
    const block = spaRouterScriptBlock(indexHtml);
    expect(block).toContain('function _showGateNotice(kind, sectionId)');
    const fnIdx = block.indexOf('function _showGateNotice');
    const fnBlock = block.slice(fnIdx, fnIdx + 1500);
    expect(fnBlock).toMatch(/kind === 'owner'/);
    expect(fnBlock).toContain("label + ' is staff-only.'");
    expect(fnBlock).toContain("'Sign in to view ' + label + '.'");
    expect(fnBlock).toContain("link.href = '/user-dashboard.html'");
    // The sign-in link is only appended in the non-owner branch.
    const ifIdx = fnBlock.indexOf("if (kind !== 'owner')");
    expect(ifIdx).toBeGreaterThan(-1);
    expect(fnBlock.indexOf('box.appendChild(link)')).toBeGreaterThan(ifIdx);
  });

  it('does not depend on any other script block\'s toast helper (self-contained — a cross-closure reference would ReferenceError for every hash link on the page)', () => {
    const block = spaRouterScriptBlock(indexHtml);
    const fnIdx = block.indexOf('function _showGateNotice');
    const fnBlock = block.slice(fnIdx, fnIdx + 1500);
    expect(fnBlock).not.toMatch(/\bp3Toast\(|\bp4Toast\(|\bshowToast\(/);
    // Reuses the pre-existing global p3SlideIn keyframe rather than inventing
    // a new one that would need its own <style> addition.
    expect(fnBlock).toContain('p3SlideIn');
  });
});

describe('cdbApplyGates() now makes the 3 member sections reachable from nav for authenticated users', () => {
  it('injects executive-hub, auto-defense, and data-dominance links into both desktop nav and the mobile drawer', () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toMatch(/id:\s*'executive-hub',\s*label:\s*'Executive Hub'/);
    expect(block).toMatch(/id:\s*'auto-defense',\s*label:\s*'Auto-Defense'/);
    expect(block).toMatch(/id:\s*'data-dominance',\s*label:\s*'Threat Confidence'/);
    expect(block).toContain("var mobileDrawerEl = document.getElementById('nav-mobile-drawer');");
    expect(block).toMatch(/\[\['desktop', navLinks\], \['mobile', mobileDrawerEl\]\]/);
  });

  it('each injected link is idempotent (insert-once guard) and navigates via cdbNavigate, matching the Dashboard link pattern', () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toContain('container.querySelector(\'[data-auth-section="\' + m.id + \'"]\')');
    expect(block).toContain('link.setAttribute(\'data-auth-section\', m.id)');
    expect(block).toContain('link.setAttribute(\'onclick\', "cdbNavigate(\'" + m.id + "\');return false")');
  });

  it('the sections themselves are untouched: still data-auth-gate="true" (member, not owner), still hidden by default', () => {
    expect(indexHtml).toMatch(/data-auth-gate="true" data-section-id="executive-hub-2" id="executive-hub" style="display:none/);
    expect(indexHtml).toMatch(/data-auth-gate="true" data-section-id="auto-defense-2" id="auto-defense" style="display:none/);
    expect(indexHtml).toMatch(/data-auth-gate="true" data-section-id="data-dominance-2" id="data-dominance" style="display:none/);
  });

  it('the pre-existing Dashboard-link injection and Sign In injection are unaffected', () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toContain("dashLink.textContent = 'Dashboard';");
    expect(block).toContain("signInLink.textContent = 'Sign In';");
    expect(block).toContain('document.querySelectorAll(\'[data-auth-gate="true"]\')');
  });
});
