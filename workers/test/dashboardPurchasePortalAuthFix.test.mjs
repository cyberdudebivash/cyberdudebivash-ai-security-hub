/* P0 — 7 dashboard sections silently unauthenticated for every real customer.
 *
 * ROOT CAUSE: frontend/user-dashboard.html's real session token is written
 * exclusively to sessionStorage under 'cdb_access' (saveTokens(), called by
 * doLogin()/doSignup()/doMfaVerify()/the token-refresh path). Six call sites
 * across five functions instead read localStorage.getItem('cdb_token') — a
 * key the real login/signup flow never writes to (it's written by a
 * completely unrelated flow: the homepage's anonymous scan/lead-capture code
 * in frontend/index.html, and an OAuth callback page). For a customer who
 * logged in through the dashboard's own overlay — the normal path — that
 * localStorage key is always null, so every one of these functions took the
 * "not authenticated" branch (or sent an unauthenticated request that 401'd)
 * even though the customer was genuinely logged in with a valid session.
 *
 * Confirmed live via Playwright against production (route-intercepted to
 * serve the fixed file, real backend): before the fix, My Tools/My
 * Reports/My Trainings/My Purchases/Intel Reports/Subscriptions/API Usage
 * either showed "Sign in to view…" or got 401s from
 * /api/user/plan, /api/keys, /api/user/reports, /api/delivery/my-purchases,
 * /api/marketplace/{orders,entitlements,subscriptions} for a freshly
 * signed-up, still-in-session user. After the fix, all seven sections show
 * the correct authenticated (empty-for-a-new-account) state and every one
 * of those endpoints returns 200.
 *
 * SECOND BUG in the same function (loadMyTools): the "Scans This Month" stat
 * (formerly mislabeled "Scans Today" — there is no daily counter anywhere in
 * the API) read planData.usage.today_count, a field that has never existed
 * in GET /api/user/plan's response shape (confirmed live: the real field is
 * usage.scans_used, a monthly counter per usage.reset_date — the same field
 * frontend/user-dashboard.html's own loadPlan() already reads correctly for
 * the Overview tab). Always fell back to '—' regardless of real usage.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const html = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fnBody(name, len = 1500) {
  const start = html.indexOf(`function ${name}`);
  if (start === -1) return '';
  return html.slice(start, start + len);
}

describe('Dashboard purchase-portal sections read the real session token (P0)', () => {
  it('the wrong storage key is gone everywhere in the file', () => {
    expect(html).not.toContain("localStorage.getItem('cdb_token')");
    expect(html).not.toContain('localStorage.getItem("cdb_token")');
  });

  it('loadMyTrainings(), loadMyDeliveries(), loadMyTools(), loadUserReports() all read sessionStorage cdb_access', () => {
    for (const name of ['loadMyTrainings', 'loadMyDeliveries', 'loadMyTools', 'loadUserReports']) {
      const body = fnBody(name);
      expect(body, `${name} not found`).not.toBe('');
      expect(body).toContain("const token = sessionStorage.getItem('cdb_access')");
    }
  });

  it('the SENTINEL APEX self-service portal (Intel Reports/Subscriptions/API Usage) apexFetch() reads sessionStorage cdb_access', () => {
    const body = fnBody('apexFetch');
    expect(body).not.toBe('');
    expect(body).toContain("const token = sessionStorage.getItem('cdb_access')");
  });

  it("loadIntelReports()'s own guard check also uses the correct token source", () => {
    const idx = html.indexOf('window.loadIntelReports = async function()');
    expect(idx).toBeGreaterThan(-1);
    expect(html.slice(idx, idx + 300)).toContain("sessionStorage.getItem('cdb_access')");
  });

  it('loadMyTools() reads the real usage.scans_used field (not the nonexistent usage.today_count)', () => {
    const body = fnBody('loadMyTools', 3000);
    expect(body).not.toContain('usage?.today_count');
    expect(body).toContain('planData?.usage?.scans_used');
  });

  it('the "Scans This Month" stat label matches the monthly (not daily) data it now displays', () => {
    const idx = html.indexOf('id="mt-scans-today"');
    expect(idx).toBeGreaterThan(-1);
    const before = html.slice(Math.max(0, idx - 200), idx);
    expect(before).toContain('Scans This Month');
    expect(before).not.toContain('Scans Today');
  });
});
