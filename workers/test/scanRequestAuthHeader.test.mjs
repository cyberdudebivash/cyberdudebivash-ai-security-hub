/* 2026-07-10 incident: a paying STARTER customer's pricing-page badge
 * correctly showed "Active Subscription: STARTER" (SUBSCRIPTION.fetch() reads
 * the real cdb_token JWT), yet an actual scan immediately failed with "Rate
 * limit reached: Daily limit reached for domain on Free tier."
 *
 * ROOT CAUSE: executeScan()/runMCPScan()/runVibeCodeScan() — the only three
 * call sites that submit the ten scan modules (domain, ai, redteam, identity,
 * compliance, cloudsec, darkscan, appsec, mcp_security, vibe_code) — built
 * their fetch() headers without ever attaching Authorization: Bearer
 * <cdb_token>. workers/src/auth/middleware.js resolveAuthV5() falls through
 * to its anonymous IP-fallback (tier: FREE) whenever no credential is
 * presented, so every scan request from every paying customer was silently
 * rate-limited exactly like an anonymous visitor — the subscription had zero
 * functional effect on the platform's core feature, regardless of what the
 * plan badge displayed.
 *
 * FIX: attach SUBSCRIPTION.getToken() (the same JWT source already used by
 * SUBSCRIPTION.fetch()/renderPlanBadge()) as a Bearer Authorization header on
 * all three call sites. This locks that wiring against regression. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

function fnBody(name, window = 4000) {
  const start = fe.indexOf(`function ${name}`);
  if (start === -1) return '';
  return fe.slice(start, start + window);
}

describe('Scan requests carry the paying customer\'s JWT (post 2026-07-10 incident)', () => {
  it('executeScan() attaches Authorization: Bearer <token> to the shared scan-submission fetch (covers 8 of the 10 modules)', () => {
    const body = fnBody('executeScan', 5000);
    expect(body).not.toBe('');
    const tokenIdx = body.indexOf('SUBSCRIPTION.getToken()');
    expect(tokenIdx).toBeGreaterThan(-1);
    const fetchIdx = body.indexOf('safeFetch(endpoints[module]');
    expect(fetchIdx).toBeGreaterThan(-1);
    // The token must be read before the fetch call, and the fetch call's own
    // headers must reference that token in an Authorization: Bearer header —
    // not just declare it unused somewhere else in the function.
    expect(tokenIdx).toBeLessThan(fetchIdx);
    const callSite = body.slice(fetchIdx, fetchIdx + 400);
    expect(callSite).toMatch(/Authorization['"]?\s*:\s*['"]Bearer\s*['"]\s*\+\s*_authToken/);
  });

  it('runMCPScan() attaches Authorization: Bearer <token> to the /api/mcp-security/scan fetch', () => {
    const body = fnBody('runMCPScan');
    expect(body).not.toBe('');
    const fetchIdx = body.indexOf("safeFetch('/api/mcp-security/scan'");
    expect(fetchIdx).toBeGreaterThan(-1);
    const callSite = body.slice(fetchIdx, fetchIdx + 300);
    expect(callSite).toContain('SUBSCRIPTION.getToken()');
    expect(callSite).toContain("'Authorization': 'Bearer ' + SUBSCRIPTION.getToken()");
  });

  it('runVibeCodeScan() attaches Authorization: Bearer <token> to the /api/vibe-code/scan fetch', () => {
    const body = fnBody('runVibeCodeScan');
    expect(body).not.toBe('');
    const fetchIdx = body.indexOf("safeFetch('/api/vibe-code/scan'");
    expect(fetchIdx).toBeGreaterThan(-1);
    const callSite = body.slice(fetchIdx, fetchIdx + 300);
    expect(callSite).toContain('SUBSCRIPTION.getToken()');
    expect(callSite).toContain("'Authorization': 'Bearer ' + SUBSCRIPTION.getToken()");
  });

  it('backend: resolveAuthV5 derives tier from the JWT payload, so an attached token actually changes rate-limit behavior', () => {
    const auth = readFileSync(resolve(root, 'src/auth/middleware.js'), 'utf8');
    const fnStart = auth.indexOf('async function resolveFromJWT');
    const fnBody2 = auth.slice(fnStart, fnStart + 1200);
    expect(fnBody2).toContain("tier:          payload.tier || 'FREE'");
  });
});

/* 2026-07-11 follow-on: the fix above assumed SUBSCRIPTION.getToken() itself
 * always returns a real token for any authenticated customer — it only
 * checked localStorage/sessionStorage 'cdb_token', the homepage's own
 * login/signup key. frontend/user-dashboard.html's login/signup overlay —
 * the platform's primary customer-facing auth surface — writes its real
 * session token to sessionStorage['cdb_access'] only. A customer who signed
 * up or logged in there and then used the homepage's scanner still got
 * every SUBSCRIPTION.getToken() call (executeScan's Authorization header,
 * the plan badge, every feature-gate check on this page) silently treated
 * as anonymous — the exact same key-mismatch bug already found and fixed in
 * the copilot widget and the org-invite email lookup, this time in the
 * single shared function the whole scan-auth fix above depends on.
 * Confirmed live: before this fix, a real POST /api/scan/domain fired with
 * no Authorization header at all for a dashboard-only-authenticated
 * customer; after, it carries `Bearer <their real cdb_access token>`. */
describe('SUBSCRIPTION.getToken() also recognizes a dashboard-only-authenticated customer', () => {
  it('checks sessionStorage cdb_access before its own cdb_token keys', () => {
    const start = fe.indexOf('function _loadToken()');
    expect(start).toBeGreaterThan(-1);
    const body = fe.slice(start, start + 1000);
    const accessIdx = body.indexOf("sessionStorage.getItem('cdb_access')");
    const tokenIdx = body.indexOf('localStorage.getItem(JWT_KEY)');
    expect(accessIdx).toBeGreaterThan(-1);
    expect(tokenIdx).toBeGreaterThan(-1);
    expect(accessIdx).toBeLessThan(tokenIdx);
  });

  it('the homepage\'s own cdb_token fallback is preserved (still used by its own login/signup/OAuth-callback flows)', () => {
    const start = fe.indexOf('function _loadToken()');
    const body = fe.slice(start, start + 1000);
    expect(body).toContain('localStorage.getItem(JWT_KEY)');
    expect(body).toContain('sessionStorage.getItem(JWT_KEY)');
  });
});
