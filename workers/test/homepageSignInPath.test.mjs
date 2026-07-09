/* CAP-IDN-001 — Login/Sign-In entry point was a dead end for logged-out
 * homepage visitors (docs/capability-registry/domains/identity.json).
 *
 * ROOT CAUSE: cdbApplyGates() (frontend/index.html) already had a working,
 * idempotent pattern that injects a "Dashboard" link into nav for
 * authenticated visitors — but the symmetric "not authenticated" branch was
 * never written, so a logged-out visitor had zero nav path to sign in.
 * Separately, the only "Sign In" surface reachable from a gated action (the
 * createMonitorModal() "Sign In Required" dialog) had a single button whose
 * only behavior was to close itself — a confirmed dead end, independently
 * re-verified live 2026-07-09 before this fix.
 *
 * FIX: extend the existing pattern with the missing else-branch (desktop nav
 * + mobile drawer), both pointing at frontend/user-dashboard.html's
 * #login-overlay (shown automatically whenever no valid session token is
 * present — confirmed by reading workers/src/handlers/auth.js's consumer,
 * user-dashboard.html:1997-2003). The modal's dead-end button now navigates
 * there too, with a separate Cancel button preserving the original dismiss
 * behavior.
 *
 * A THIRD dead end (2026-07-09, reported live via a "token already used"
 * scan error — CISCO prospect hit this exact path): the 403 scan-error
 * banner's "log in" link called showModal('loginModal') — an id that never
 * existed anywhere in the file (grep-confirmed 0 matches), so the click
 * silently no-opped. showModal() itself is not broken (showModal('leadModal')
 * elsewhere correctly targets a real element) — only this one call pointed
 * at nothing. Fixed by replacing the dead onclick with a real
 * href="/user-dashboard.html" anchor — no synthetic modal was built, since
 * one login system already exists and works; this was purely a broken
 * pointer to it, the same bug class as the other two, not a missing feature.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  if (start === -1) return '';
  return fe.slice(start, start + 4000);
}

describe('Homepage Sign In path (CAP-IDN-001)', () => {
  it('cdbApplyGates injects a real Sign In link for logged-out visitors, pointing at the working login form', () => {
    const gate = fnBody('cdbApplyGates');
    expect(gate).not.toBe('');
    // Must exist inside the `else` branch guarding a.isAuthenticated.
    expect(gate).toMatch(/}\s*else\s*{[\s\S]*data-auth-section['"]?\s*,\s*['"]signin['"]/);
    expect(gate).toContain("signInLink.href = '/user-dashboard.html'");
    expect(gate).toContain("signInLinkMobile.href = '/user-dashboard.html'");
  });

  it('the injected Sign In link is removed again once the visitor is authenticated (no stale UI post-login)', () => {
    const gate = fnBody('cdbApplyGates');
    // Cleanup lives in the `if (a.isAuthenticated)` branch, before the else.
    const authedBranch = gate.slice(0, gate.indexOf('} else {'));
    expect(authedBranch).toContain('data-auth-section="signin"');
    expect(authedBranch).toMatch(/querySelectorAll\(.*signin.*\)\.forEach\(function\(el\)\{\s*el\.remove\(\)/);
  });

  it('the "Sign In Required" modal no longer dead-ends — its primary button navigates to the login page', () => {
    const start = fe.indexOf('Sign In Required');
    expect(start).toBeGreaterThan(-1);
    const modalHtml = fe.slice(start, start + 600);
    // The old bug: the only button just removed the modal and went nowhere.
    expect(modalHtml).toContain("location.href='/user-dashboard.html'");
    // The dismiss capability must still exist (backward compatibility) —
    // just no longer as the ONLY option.
    expect(modalHtml).toContain("document.getElementById('_monitor-modal')?.remove()");
  });

  it('the scan-error "log in" link (403 / reused-token path) no longer targets a nonexistent modal', () => {
    expect(fe).not.toContain("showModal('loginModal')");
    expect(fe).not.toContain('id="loginModal"');
    const idx = fe.indexOf('Please <a href="/user-dashboard.html"');
    expect(idx).toBeGreaterThan(-1);
    expect(fe.slice(idx, idx + 120)).toContain('log in');
  });
});
