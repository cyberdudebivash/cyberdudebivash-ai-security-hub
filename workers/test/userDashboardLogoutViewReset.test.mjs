/* P0 Wave 3 (Production Dashboard UAT) — Sign Out left the login overlay on
 * whichever auth view (login/signup/forgot/reset/mfa) was last active in the
 * browser session, instead of resetting to login-view. Found via a real
 * headless-Chromium session against live production: sign up (which shows
 * #signup-view), get auto-logged-in, click "🚪 Sign Out" — the overlay
 * reappears still showing #signup-view (display:block) with #login-view
 * hidden (display:none), so #login-email is not visible/fillable and the
 * customer cannot sign back in without first noticing and clicking the
 * secondary "Already have an account? Sign in" link. Confirmed live: after
 * the fix, re-login immediately post-signout succeeds (POST /api/auth/login
 * 200, dashboard renders) against the exact same production backend.
 *
 * Static-parse regression, same convention as
 * workers/test/homepageSignInPath.test.mjs and
 * workers/test/userDashboardSignupAndMfa.test.mjs — reads
 * frontend/user-dashboard.html directly rather than driving a browser in CI.
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';

const src = fs.readFileSync(new URL('../../frontend/user-dashboard.html', import.meta.url), 'utf8');

describe('doLogout() resets the auth overlay to login-view (was: left on whatever view was last active)', () => {
  it('doLogout() calls showAuthView(\'login-view\') before/while showing the overlay', () => {
    const match = src.match(/function doLogout\(\)\s*\{([\s\S]*?)\n\s*\}/);
    expect(match, 'doLogout() function body found').toBeTruthy();
    const body = match[1];
    expect(body).toMatch(/showAuthView\(\s*['"]login-view['"]\s*\)/);
  });

  it('doLogout() still clears tokens and shows the overlay (fix is additive, not a rewrite)', () => {
    const match = src.match(/function doLogout\(\)\s*\{([\s\S]*?)\n\s*\}/);
    const body = match[1];
    expect(body).toMatch(/clearTokens\(\)/);
    expect(body).toMatch(/login-overlay['"]\)\.style\.display\s*=\s*['"]flex['"]/);
  });

  it('showAuthView(\'login-view\') is called before the overlay is set to display:flex (correct view is ready before the overlay becomes visible)', () => {
    const match = src.match(/function doLogout\(\)\s*\{([\s\S]*?)\n\s*\}/);
    const body = match[1];
    const showIdx = body.indexOf("showAuthView('login-view')");
    const displayIdx = body.indexOf("style.display");
    expect(showIdx).toBeGreaterThan(-1);
    expect(showIdx).toBeLessThan(displayIdx);
  });
});
