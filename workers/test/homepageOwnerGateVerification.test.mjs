/* Customer-reported production gap, 2026-07-11 (follow-up wave) — the
 * homepage (frontend/index.html) revealed 3 owner-only internal-tooling
 * sections (CRM pipeline / sales metrics, proposal generator, growth
 * analytics funnel) based purely on a client-side flag:
 *
 *   `/?owner=1` → localStorage.setItem('cdb_owner', '1') → read back
 *   synchronously by initAuthGate()'s readAuth() → data-auth-gate="owner"
 *   elements revealed.
 *
 * Any visitor could grant themselves this view from the URL bar or devtools
 * with zero proof of identity — same vulnerability class already fixed for
 * revenue-intelligence-dashboard.html and enterprise-kpi-dashboard.html
 * (adminRevenueShellGating.test.mjs) via the platform's proven
 * frontend/assets/staff-auth.js magic-link session gate. The underlying data
 * (e.g. GET /api/conversion/funnel behind growth-analytics) was already
 * isOwner()-gated server-side, so this was a shell/DOM reveal-without-
 * verification issue, not a raw data breach — but the same severity class
 * and the same professional-appearance problem the customer flagged.
 *
 * Fixed: the owner flag is now a real, async, server-verified value
 * (ownerVerified, flipped true only after GET /api/staff/me succeeds via
 * CDB_STAFF_AUTH.authFetch()) instead of a synchronous localStorage read.
 * `?owner=1` alone no longer does anything; an already-verified staff
 * session (created by logging in once on any staff-gated page, e.g.
 * /admin-portal.html — shared via localStorage across cyberdudebivash.in)
 * is picked up automatically. `?owner=0` still clears the session on demand.
 * A redundant, independently-insecure duplicate reveal script inside the
 * crm-ops-internal section (its own direct `localStorage.getItem('cdb_owner')`
 * read, bypassing initAuthGate() entirely) was also removed.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const indexHtml = readFileSync(
  fileURLToPath(new URL('../../frontend/index.html', import.meta.url)), 'utf8'
);

function authGateScriptBlock(html) {
  const start = html.indexOf('(function initAuthGate()');
  expect(start).toBeGreaterThan(-1);
  const end = html.indexOf('})();', start);
  return html.slice(start, end);
}

describe('frontend/index.html — owner-only sections now require real server verification', () => {
  it('loads staff-auth.js before the auth gate controller', () => {
    const scriptIdx = indexHtml.indexOf('<script src="/assets/staff-auth.js"></script>');
    const gateIdx = indexHtml.indexOf('(function initAuthGate()');
    expect(scriptIdx).toBeGreaterThan(-1);
    expect(gateIdx).toBeGreaterThan(-1);
    expect(scriptIdx).toBeLessThan(gateIdx);
  });

  it('no longer grants owner status from the URL flag alone (?owner=1 → localStorage bootstrap removed)', () => {
    expect(indexHtml).not.toMatch(/qp\.get\('owner'\)\s*===\s*'1'\)\s*localStorage\.setItem\('cdb_owner'/);
  });

  it("readAuth()'s isOwner comes from the verified closure variable, not a direct localStorage read", () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toContain('var ownerVerified = false;');
    expect(block).toMatch(/isOwner:\s*ownerVerified/);
    expect(block).not.toMatch(/isOwner:\s*localStorage\.getItem\('cdb_owner'\)/);
  });

  it('verifyOwner() only flips ownerVerified true after a real GET /api/staff/me success, then re-applies gates', () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toContain('function verifyOwner()');
    expect(block).toContain("window.CDB_STAFF_AUTH.authFetch('/api/staff/me')");
    expect(block).toMatch(/if\s*\(res\.ok\)\s*\{\s*ownerVerified = true;/);
    expect(block).toContain('window.CDB_STAFF_AUTH.clearSession();');
    // verifyOwner() must actually run (as the last statement before the IIFE
    // closes), not merely be defined and left uncalled.
    expect(block.trim().endsWith('verifyOwner();')).toBe(true);
  });

  it('?owner=0 still clears the (now real) session on demand', () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toMatch(/qp\.get\('owner'\)\s*===\s*'0'\)\s*window\.CDB_STAFF_AUTH\.clearSession\(\)/);
  });

  it('the redundant duplicate reveal script inside crm-ops-internal (its own direct localStorage.cdb_owner read) is gone', () => {
    expect(indexHtml).not.toContain("var isOwner = localStorage.getItem('cdb_owner') === '1';");
    // The section itself is untouched and still relies solely on the shared gate.
    expect(indexHtml).toContain('<div data-auth-gate="owner" data-section-id="crm-ops-internal" style="display:none">');
  });

  it('the other owner-gated sections (proposal-gen, growth-analytics) and their nav tabs are unaffected', () => {
    expect(indexHtml).toContain('data-section-id="proposal-gen-2"');
    expect(indexHtml).toContain('data-section-id="growth-analytics-2"');
    expect(indexHtml).toContain('data-owner-tab="1"');
  });

  it("cdbApplyGates()'s other responsibilities (member gate, plan badge, nav injection) are untouched", () => {
    const block = authGateScriptBlock(indexHtml);
    expect(block).toContain('document.querySelectorAll(\'[data-auth-gate="true"]\')');
    expect(block).toContain("var badge = document.getElementById('nav-plan-badge');");
    expect(block).toContain("dashLink.textContent = 'Dashboard';");
    expect(block).toContain("signInLink.textContent = 'Sign In';");
  });
});

describe('GET /api/staff/me — backend check this fix relies on is real (regression guard)', () => {
  it('the router resolves a real auth context and the handler requires non-empty platformRoles, not just authentication', () => {
    const routerSrc = readFileSync(
      fileURLToPath(new URL('../src/index.js', import.meta.url)), 'utf8'
    );
    const routeIdx = routerSrc.indexOf("path === '/api/staff/me'");
    expect(routeIdx).toBeGreaterThan(-1);
    const routeBlock = routerSrc.slice(routeIdx, routeIdx + 300);
    expect(routeBlock).toContain('resolveAuthV5(request, env)');
    expect(routeBlock).toContain('handleStaffMe(request, env, authCtx)');

    const staffAuthSrc = readFileSync(
      fileURLToPath(new URL('../src/handlers/staffAuth.js', import.meta.url)), 'utf8'
    );
    const handlerIdx = staffAuthSrc.indexOf('export async function handleStaffMe');
    expect(handlerIdx).toBeGreaterThan(-1);
    const handlerBlock = staffAuthSrc.slice(handlerIdx, handlerIdx + 300);
    expect(handlerBlock).toMatch(/!authCtx\.platformRoles \|\| authCtx\.platformRoles\.length === 0/);
    expect(handlerBlock).toContain('401');
  });

  it('resolveStaffSession() requires a real, non-expired KV-backed session token with roles — not a trivially-forgeable value', () => {
    const staffAuthSrc = readFileSync(
      fileURLToPath(new URL('../src/handlers/staffAuth.js', import.meta.url)), 'utf8'
    );
    const fnIdx = staffAuthSrc.indexOf('export async function resolveStaffSession');
    expect(fnIdx).toBeGreaterThan(-1);
    const fnBlock = staffAuthSrc.slice(fnIdx, fnIdx + 700);
    expect(fnBlock).toContain('env.KV.get(`staff:session:${token}`)');
    expect(fnBlock).toMatch(/if \(!session\?\.roles\?\.length\) return null;/);
  });
});
