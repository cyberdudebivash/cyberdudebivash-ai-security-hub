/* Regression test — user-dashboard.html's post-upgrade billing flow
 * (full-frontend-audit follow-up, Tier 1 item #7; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * After a successful subscription upgrade, handleVerifyPayment (payments.js)
 * issues a real JWT (with the new tier baked in) as `token`/`refresh_token`.
 * This page's own established pattern for "just got a new token" is
 * `_token = ...; saveTokens(_token, refresh)` (used by doLogin()'s own
 * success path, sessionStorage['cdb_access']/['cdb_refresh']) — but the
 * upgrade success handler instead wrote to localStorage['cdb_token'], a
 * key/storage type apiFetch() and every other read site on this page never
 * looks at. The UI kept enforcing the pre-upgrade tier until the session
 * naturally expired.
 *
 * Separately, the same success path called loadDashboard() — a function
 * that does not exist anywhere in this file — throwing a ReferenceError
 * right after the "Access Unlocked" modal, surfaced as a confusing
 * "Something went wrong" toast to a customer who just successfully paid.
 * initDashboard() is the real full-refresh function (used by doLogin()'s
 * own success path) and already calls syncPlanCards() once its data loads.
 *
 * Pure static parse — no browser/network.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n  }', start); // this function is indented 2 levels inside the module IIFE
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

describe('Post-upgrade success handler — real token storage', () => {
  it('stores the new token via _token/saveTokens() (sessionStorage), not localStorage', () => {
    const idx = fe.indexOf("if (type === 'subscription' && d.token)");
    expect(idx).toBeGreaterThan(-1);
    const body = fe.slice(idx, idx + 250);
    expect(body).toContain('_token = d.token');
    expect(body).toContain('saveTokens(_token, d.refresh_token)');
    expect(body).not.toContain("localStorage.setItem('cdb_token'");
  });

  it('saveTokens() itself writes to sessionStorage (the value apiFetch() actually reads)', () => {
    const body = fnBody('saveTokens');
    expect(body).toContain("sessionStorage.setItem('cdb_access'");
  });
});

describe('Post-upgrade success handler — real dashboard refresh', () => {
  it('calls initDashboard(), a function that exists, not the nonexistent loadDashboard()', () => {
    const idx = fe.indexOf("if (type === 'subscription') {\n        await initDashboard();");
    expect(idx).toBeGreaterThan(-1);
    expect(fe).not.toContain('await loadDashboard()');
  });

  it('loadDashboard is not defined anywhere in this file (confirms it really was a dead reference)', () => {
    expect(fe).not.toContain('function loadDashboard');
  });

  it('initDashboard already syncs plan cards itself once data loads', () => {
    const body = fnBody('initDashboard');
    expect(body).toContain('syncPlanCards()');
  });
});
