// CAP-IDN-002 — Sign-Up / Account Creation entry point + CAP-IDN-001 MFA
// login-completion gap (docs/capability-registry/domains/identity.json).
//
// ROOT CAUSE #1 (CAP-IDN-002): POST /api/auth/signup (workers/src/handlers/auth.js
// handleSignup) has been a complete, production-grade implementation — password
// hashing, duplicate-email checks, rollback on partial failure, welcome email,
// auto-provisioned API key — since before this fix, and is wired at
// workers/src/index.js. But zero frontend code anywhere on the site ever called
// it. frontend/user-dashboard.html's login overlay only had login/forgot/reset
// views; "No account? Get started free" was a plain `<a href="/">`, sending a
// prospective customer back to the homepage instead of a signup form. Reported
// live by a Microsoft customer escalation: signup "simply returns to the home
// page." Confirmed by grep before the fix: zero matches anywhere in frontend/
// for "api/auth/signup", "doSignup", "signup-view", or any signup modal id.
//
// ROOT CAUSE #2 (MFA login completion): handleLogin() (workers/src/handlers/auth.js)
// returns HTTP 200 with { mfa_required: true, mfa_challenge_token } — no
// access_token — whenever the account has MFA enabled. user-dashboard.html's
// doLogin() never checked for mfa_required; since res.ok was true it fell through
// to the success path with _token === undefined, hid the login overlay, and called
// initDashboard(), which then 401'd on GET /api/auth/me with no refresh token
// available, silently bounced back to the login screen. POST /api/auth/mfa/authenticate
// (workers/src/handlers/mfa.js handleMFAAuthenticate) already existed, fully
// tested (workers/test/mfaAuthGate.test.mjs covers its auth gating), and
// returns the identical token shape as handleLogin — nothing in the frontend
// ever called it.
//
// FIX: additive only. Added #signup-view + doSignup() (mirrors doLogin()'s
// exact fetch/error/spinner pattern) and #mfa-view + doMfaVerify() (same
// pattern, posts to the existing, tested MFA-authenticate endpoint). Extended
// showAuthView()'s view list. Zero changes to the existing login/forgot/reset
// views or their backend contracts.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DASH  = readFileSync(resolve(__dirname, '../../frontend/user-dashboard.html'), 'utf8');
const INDEX = readFileSync(resolve(__dirname, '../src/index.js'), 'utf8');
const AUTH  = readFileSync(resolve(__dirname, '../src/handlers/auth.js'), 'utf8');
const MFA   = readFileSync(resolve(__dirname, '../src/handlers/mfa.js'), 'utf8');

function fnBody(src, name) {
  const start = src.indexOf(`function ${name}`);
  if (start === -1) return '';
  return src.slice(start, start + 2500);
}

describe('Sign-Up entry point (CAP-IDN-002)', () => {
  it('"Get started free" no longer sends the visitor back to the homepage', () => {
    expect(DASH).not.toContain('No account? <a href="/">Get started free</a>');
  });

  it('"Get started free" opens the real signup view', () => {
    const idx = DASH.indexOf('Get started free');
    expect(idx).toBeGreaterThan(-1);
    expect(DASH.slice(idx - 120, idx)).toContain("showAuthView('signup-view')");
  });

  it('a real #signup-view exists with email + password fields', () => {
    const idx = DASH.indexOf('id="signup-view"');
    expect(idx).toBeGreaterThan(-1);
    const view = DASH.slice(idx, idx + 1800);
    expect(view).toContain('id="signup-email"');
    expect(view).toContain('id="signup-pass"');
    expect(view).toContain('onclick="doSignup()"');
  });

  it('showAuthView() knows about signup-view (so it actually toggles visible)', () => {
    const fn = fnBody(DASH, 'showAuthView');
    expect(fn).toContain("'signup-view'");
  });

  it('doSignup() calls the real, existing POST /api/auth/signup endpoint', () => {
    const fn = fnBody(DASH, 'doSignup');
    expect(fn).not.toBe('');
    expect(fn).toContain("API_BASE + '/api/auth/signup'");
    expect(fn).toContain("method: 'POST'");
    // Must send the fields handleSignup actually reads.
    expect(fn).toMatch(/email[,\s]/);
    expect(fn).toContain('password: pass');
    expect(fn).toContain('full_name: name');
  });

  it('on success, doSignup() stores tokens and initializes the dashboard exactly like doLogin()', () => {
    const fn = fnBody(DASH, 'doSignup');
    expect(fn).toContain('saveTokens(_token, d.refresh_token)');
    expect(fn).toContain("getElementById('login-overlay').style.display = 'none'");
    expect(fn).toContain('initDashboard()');
  });

  it('backend really exposes POST /api/auth/signup, and handleSignup reads the fields the form sends', () => {
    expect(INDEX).toContain("path === '/api/auth/signup' && method === 'POST'");
    expect(AUTH).toContain('export async function handleSignup');
    expect(AUTH).toContain("body?.email");
    expect(AUTH).toContain("body?.password");
    expect(AUTH).toContain("body?.full_name");
  });
});

describe('MFA login-completion (CAP-IDN-001 follow-up)', () => {
  it('doLogin() checks mfa_required before treating the response as a successful login', () => {
    const fn = fnBody(DASH, 'doLogin');
    expect(fn).not.toBe('');
    expect(fn).toContain('d.mfa_required');
    // The mfa branch must come before tokens are trusted/stored.
    const mfaIdx   = fn.indexOf('d.mfa_required');
    const tokenIdx = fn.indexOf('_token = d.access_token');
    expect(mfaIdx).toBeGreaterThan(-1);
    expect(tokenIdx).toBeGreaterThan(mfaIdx);
  });

  it('a real #mfa-view exists with a code field and calls doMfaVerify()', () => {
    const idx = DASH.indexOf('id="mfa-view"');
    expect(idx).toBeGreaterThan(-1);
    const view = DASH.slice(idx, idx + 1000);
    expect(view).toContain('id="mfa-code"');
    expect(view).toContain('onclick="doMfaVerify()"');
  });

  it('showAuthView() knows about mfa-view', () => {
    const fn = fnBody(DASH, 'showAuthView');
    expect(fn).toContain("'mfa-view'");
  });

  it('doMfaVerify() calls the real, existing, already-tested POST /api/auth/mfa/authenticate endpoint', () => {
    const fn = fnBody(DASH, 'doMfaVerify');
    expect(fn).not.toBe('');
    expect(fn).toContain("API_BASE + '/api/auth/mfa/authenticate'");
    expect(fn).toContain('mfa_challenge_token: _mfaChallengeToken');
    expect(fn).toContain('totp_code: code');
  });

  it('on success, doMfaVerify() stores tokens and initializes the dashboard exactly like doLogin()', () => {
    const fn = fnBody(DASH, 'doMfaVerify');
    expect(fn).toContain('saveTokens(_token, d.refresh_token)');
    expect(fn).toContain('initDashboard()');
  });

  it('backend really exposes POST /api/auth/mfa/authenticate returning the same token shape as login', () => {
    expect(INDEX).toContain("path === '/api/auth/mfa/authenticate' && method === 'POST'");
    expect(MFA).toContain('export async function handleMFAAuthenticate');
    expect(MFA).toContain('access_token:  accessToken');
    expect(MFA).toContain('refresh_token: refreshData.token');
  });
});
