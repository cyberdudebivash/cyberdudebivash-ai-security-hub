/* Customer-reported production gap, 2026-07-11 — clicking through from the
 * dashboard to 11 named homepage sections (frontend/index.html anchors like
 * #executive-hub, #auto-defense, #data-dominance) landed on content the
 * customer described as "not properly built." Investigation found most of
 * the 11 are real, backend-wired sections — but 3 of them (executive-hub,
 * auto-defense, data-dominance) are `data-auth-gate="true"` and `display:none`,
 * and any visitor who doesn't satisfy the gate was silently scrolled back to
 * the homepage top with ZERO explanation — indistinguishable from a broken or
 * nonexistent page.
 *
 * SELF-CORRECTION (same day, found while investigating the customer's
 * follow-up "nothing changed"): the original pass in this file also claimed
 * "no nav link anywhere" pointed at these 3 sections, and added a brand new
 * injection to cdbApplyGates() to fix that. That claim was wrong — a
 * pre-existing p3InjectNav() (Phase 3 Engine block, this same file) already
 * injected nav links for exactly these 3 sections, labeled "Defense" / "Data
 * Intel" / "CISO Hub". A static grep never found it because the links are
 * built via document.createElement() + property assignment, not literal
 * href="..." text. The real bugs in p3InjectNav(), now fixed: (1) it ran
 * unconditionally for every visitor, including logged-out ones who can never
 * pass these sections' own auth gate — a nav item that always dead-ends for
 * the one visitor who can see it; (2) it only ever targeted the desktop nav,
 * leaving mobile with zero discoverability. The redundant, differently-
 * labeled injection this file's earlier version added to cdbApplyGates() has
 * been removed — it would have shown each section twice, under two different
 * names, for an authenticated visitor. CDB_SECTIONS' labels now match
 * p3InjectNav()'s real, already-shipped labels (CISO Hub / Defense / Data
 * Intel) instead of the invented ones from the first pass, so
 * _showGateNotice()'s message matches what the visitor actually clicked.
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

function phase3EngineScriptBlock(html) {
  const start = html.indexOf('PHASE 3 ENGINE');
  expect(start).toBeGreaterThan(-1);
  const end = html.indexOf('END PHASE 3 ENGINE', start);
  expect(end).toBeGreaterThan(start);
  return html.slice(start, end);
}

describe('CDB_SECTIONS labels match the real, already-shipped nav labels (not invented ones)', () => {
  it('executive-hub, auto-defense, and data-dominance are labeled CISO Hub / Defense / Data Intel', () => {
    const block = spaRouterScriptBlock(indexHtml);
    expect(block).toMatch(/'executive-hub':\s*\{\s*label:\s*'CISO Hub'/);
    expect(block).toMatch(/'auto-defense':\s*\{\s*label:\s*'Defense'/);
    expect(block).toMatch(/'data-dominance':\s*\{\s*label:\s*'Data Intel'/);
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

describe('p3InjectNav() now only shows these 3 links to visitors who can actually pass the gate, in both desktop nav and mobile drawer', () => {
  it('bails out immediately unless window.CDB_AUTH.isAuthenticated is true (previously ran unconditionally for every visitor)', () => {
    const block = phase3EngineScriptBlock(indexHtml);
    const fnIdx = block.indexOf('function p3InjectNav()');
    expect(fnIdx).toBeGreaterThan(-1);
    const fnBlock = block.slice(fnIdx, fnIdx + 200);
    expect(fnBlock).toContain('if (!(window.CDB_AUTH && window.CDB_AUTH.isAuthenticated)) return;');
  });

  it('targets both the desktop nav and the mobile drawer (previously desktop only)', () => {
    const block = phase3EngineScriptBlock(indexHtml);
    expect(block).toContain("var mobileDrawer = document.getElementById('nav-mobile-drawer');");
    expect(block).toMatch(/\[nav, mobileDrawer\]\.forEach/);
  });

  it('still injects the real, already-shipped labels (Defense / Data Intel / CISO Hub) via createElement + click handler calling cdbNavigate', () => {
    const block = phase3EngineScriptBlock(indexHtml);
    expect(block).toMatch(/sectionId:\s*'auto-defense',\s*label:\s*'Defense'/);
    expect(block).toMatch(/sectionId:\s*'data-dominance',\s*label:\s*'Data Intel'/);
    expect(block).toMatch(/sectionId:\s*'executive-hub',\s*label:\s*'CISO Hub'/);
    expect(block).toContain("if (typeof cdbNavigate === 'function') cdbNavigate(item.sectionId);");
  });

  it('is idempotent per container (data-p3nav insert-once guard, now checked against BOTH desktop and mobile containers independently)', () => {
    const block = phase3EngineScriptBlock(indexHtml);
    expect(block).toContain('container.querySelector(\'[data-p3nav="\' + item.sectionId + \'"]\')');
  });

  it('re-runs on the cdb:login event (SPA-style, no reload) so the links appear for a visitor who logs in without leaving the page', () => {
    const block = phase3EngineScriptBlock(indexHtml);
    expect(block).toContain("window.addEventListener('cdb:login', p3InjectNav);");
  });
});

describe('cdbApplyGates() no longer duplicates p3InjectNav()\'s links under different labels', () => {
  it('has no second, redundant injection for executive-hub/auto-defense/data-dominance', () => {
    const start = indexHtml.indexOf('(function initAuthGate()');
    expect(start).toBeGreaterThan(-1);
    const end = indexHtml.indexOf('})();', start);
    const block = indexHtml.slice(start, end);
    // Check the actual code pattern (an object-literal label assignment),
    // not a bare substring — this function's own removal comment
    // legitimately mentions these label names as prose, explaining what
    // was taken out and why.
    expect(block).not.toMatch(/label:\s*'Executive Hub'/);
    expect(block).not.toMatch(/label:\s*'Auto-Defense'/);
    expect(block).not.toMatch(/label:\s*'Threat Confidence'/);
    expect(block).not.toMatch(/var memberLinks = \[/);
  });

  it('the sections themselves are untouched: still data-auth-gate="true" (member, not owner), still hidden by default', () => {
    expect(indexHtml).toMatch(/data-auth-gate="true" data-section-id="executive-hub-2" id="executive-hub" style="display:none/);
    expect(indexHtml).toMatch(/data-auth-gate="true" data-section-id="auto-defense-2" id="auto-defense" style="display:none/);
    expect(indexHtml).toMatch(/data-auth-gate="true" data-section-id="data-dominance-2" id="data-dominance" style="display:none/);
  });

  it('the pre-existing Dashboard-link injection and Sign In injection are unaffected', () => {
    const start = indexHtml.indexOf('(function initAuthGate()');
    const end = indexHtml.indexOf('})();', start);
    const block = indexHtml.slice(start, end);
    expect(block).toContain("dashLink.textContent = 'Dashboard';");
    expect(block).toContain("signInLink.textContent = 'Sign In';");
    expect(block).toContain('document.querySelectorAll(\'[data-auth-gate="true"]\')');
  });
});
