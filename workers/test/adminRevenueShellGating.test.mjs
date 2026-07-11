/* Customer-reported production gap, 2026-07-11: admin/revenue dashboard
 * sections visible to the public. Full-platform investigation found the
 * *data* was already consistently protected server-side (isOwner()/
 * adminGuard()/assertAdmin()/checkTier() — 6+ endpoint families checked, all
 * real, all correctly rejecting unauthorized access) — but several
 * standalone admin/revenue pages rendered their full shell (nav, labels,
 * section headers) to any visitor, relying entirely on the underlying data
 * calls failing. The platform already has a proven, secure pattern for this
 * exact problem (frontend/assets/staff-auth.js — a real magic-link,
 * server-verified session gate, already correctly used by admin-portal.html,
 * god-mode.html, mssp-command-center.html, revenue-command-center.html, and
 * proposal-generator.html) that was never extended to every admin page.
 *
 * Fixed: revenue-intelligence-dashboard.html and enterprise-kpi-dashboard.html
 * (the two clearest, most severe cases — literally "revenue"/"executive KPI"
 * dashboards with backend-protected data but zero frontend shell gate) now
 * use the same proven staff-auth.js pattern. Both previously also used
 * `credentials:'include'` (cookies) for their fetches — this platform's
 * auth resolver (resolveAuthV5) never checks cookies at all, so those calls
 * were silently falling through to an anonymous IP-fallback identity before
 * being correctly 403'd by isOwner()/adminGuard() — meaning these pages were
 * BOTH publicly shell-visible AND non-functional for the real, legitimate
 * owner. Migrating to staff-auth.js's real Bearer-token authFetch() fixes
 * both problems at once.
 *
 * Separately: user-dashboard.html's CISO Executive Metrics (a real
 * PRO/ENTERPRISE/MSSP paid feature, backend-gated) had a free-tier upsell
 * banner that never actually blocked anything — execution fell through to a
 * client-side fallback that recomputed the same metrics directly from the
 * customer's own scan history, completely bypassing the backend tier check.
 * Fixed to show only the honest locked/empty state for free tier.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function readFrontend(name) {
  return readFileSync(fileURLToPath(new URL(`../../frontend/${name}`, import.meta.url)), 'utf8');
}

describe('revenue-intelligence-dashboard.html — now uses the proven staff-auth.js gate', () => {
  const html = readFrontend('revenue-intelligence-dashboard.html');

  it('loads staff-auth.js and calls CDB_STAFF_AUTH.guard() before any data loads', () => {
    expect(html).toContain('<script src="/assets/staff-auth.js"></script>');
    expect(html).toMatch(/CDB_STAFF_AUTH\.guard\(\s*document\.getElementById\('gateOverlay'\)/);
  });

  it('has a gate overlay hidden by default, matching the proven pattern', () => {
    expect(html).toContain('<div class="gate-overlay" id="gateOverlay" style="display:none">');
    expect(html).toContain('<div class="gate-box" id="gateBox"></div>');
  });

  it('no longer uses cookie-based credentials for any /api/platform/revenue-intelligence call — uses the real Bearer-token authFetch instead', () => {
    expect(html).not.toMatch(/credentials:\s*'include'/);
    const authFetchCalls = html.match(/CDB_STAFF_AUTH\.authFetch\(`\$\{API\}\/api\/platform\/revenue-intelligence/g) || [];
    expect(authFetchCalls.length).toBeGreaterThanOrEqual(4);
  });

  it('data loading and auto-refresh only start inside the guard\'s unlocked callback, not unconditionally at page load', () => {
    // The old bug: an unindented top-level call, immediately followed by
    // setInterval on the next line — distinct from the new call nested
    // inside the guard()'s arrow-function callback (indented, same line as
    // setInterval). Anchor on zero leading whitespace to target only the
    // old, now-removed top-level form.
    expect(html).not.toMatch(/^loadDashboard\(\);\nsetInterval\(refreshAll/m);
    expect(html).toMatch(/\(\)\s*=>\s*\{\s*loadDashboard\(\);\s*setInterval\(refreshAll, 300_000\);/);
  });
});

describe('enterprise-kpi-dashboard.html — now uses the proven staff-auth.js gate', () => {
  const html = readFrontend('enterprise-kpi-dashboard.html');

  it('loads staff-auth.js and calls CDB_STAFF_AUTH.guard() before any data loads', () => {
    expect(html).toContain('<script src="/assets/staff-auth.js"></script>');
    expect(html).toMatch(/CDB_STAFF_AUTH\.guard\(\s*document\.getElementById\('gateOverlay'\)/);
  });

  it('has a gate overlay hidden by default, and is no longer indexable by search engines', () => {
    expect(html).toContain('<div class="gate-overlay" id="gateOverlay" style="display:none">');
    expect(html).toContain('<meta name="robots" content="noindex,nofollow"/>');
  });

  it('no longer uses cookie-based credentials for /api/platform/kpi — uses the real Bearer-token authFetch instead', () => {
    expect(html).not.toMatch(/credentials:\s*'include'/);
    expect(html).toContain("CDB_STAFF_AUTH.authFetch(`${API}/api/platform/kpi`)");
  });

  it('data loading and auto-refresh only start inside the guard\'s unlocked callback', () => {
    expect(html).not.toMatch(/^loadKPI\(\);\s*$/m);
    expect(html).toMatch(/\(\)\s*=>\s*\{\s*loadKPI\(\);\s*setInterval\(loadKPI, 300000\);/);
  });
});

describe('user-dashboard.html — CISO Executive Metrics no longer leaks a paid feature to free tier', () => {
  const html = readFrontend('user-dashboard.html');

  it('the free-tier branch sets the honest empty state and never reaches the real API call or the client-side fallback', () => {
    const fnMatch = html.match(/async function loadCisoMetrics\(\)[\s\S]*?\n  \}\n\n  \/\//);
    expect(fnMatch).not.toBeNull();
    const fn = fnMatch[0];

    // The free-tier branch must set _empty:true and must not fall through
    // to apiFetch or the scan-history-derived fallback computation.
    const freeTierBranch = fn.slice(fn.indexOf("if (plan === 'free')"), fn.indexOf('} else {'));
    expect(freeTierBranch).toContain('_empty: true');
    expect(freeTierBranch).not.toContain('apiFetch');
    expect(freeTierBranch).not.toContain('_allScans');
  });

  it('the real API call and scan-history fallback are still there for paid tiers (PRO/ENTERPRISE/MSSP unaffected)', () => {
    expect(html).toContain("const res = await apiFetch('/api/ciso/metrics');");
    expect(html).toContain('_allScans.forEach(s => {');
  });
});

describe('GET /api/ciso/metrics — backend tier gate this fix relies on is real (regression guard)', () => {
  it('the router enforces PRO/ENTERPRISE/MSSP tier or admin capability, not just authentication', () => {
    const routerSrc = readFileSync(
      fileURLToPath(new URL('../src/index.js', import.meta.url)), 'utf8'
    );
    const routeBlock = routerSrc.slice(
      routerSrc.indexOf("path === '/api/ciso/metrics'"),
      routerSrc.indexOf("path === '/api/ciso/metrics'") + 800
    );
    expect(routeBlock).toMatch(/_cisoTierOk\s*=\s*\['PRO',\s*'ENTERPRISE',\s*'MSSP'\]/);
    expect(routeBlock).toContain("requireCan(authCtx, env, 'admin:analytics:read'");
  });
});
