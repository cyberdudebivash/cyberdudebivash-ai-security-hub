/* Coverage for the scan-token abuse-prevention gate (scanTokenEngine.js).
 *
 * This control shipped in v30.0 with a docstring claiming "every public domain
 * scan request MUST carry a valid scan token", but verifyScanToken() was never
 * actually called from anywhere — a dead P1 control (found during the platform
 * gap audit). This suite covers the engine directly; authGateRealUser.test.mjs
 * covers the route-level wiring (runSyncPipeline actually calling it for
 * POST /api/scan/domain, and only for non-api_key callers).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { issueScanToken, verifyScanToken, scanTokenError } from '../src/lib/scanTokenEngine.js';

function kvStub() {
  const store = new Map();
  return {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, v); },
  };
}
function reqWithIP(ip) {
  return new Request('https://cyberdudebivash.in/api/scan/token', { method: 'POST', headers: { 'CF-Connecting-IP': ip } });
}
function scanReqWithToken(token, ip) {
  return new Request('https://cyberdudebivash.in/api/scan/domain', {
    method: 'POST',
    headers: { 'CF-Connecting-IP': ip, ...(token ? { 'X-Scan-Token': token } : {}) },
  });
}
async function getToken(env, ip = '1.2.3.4') {
  const res = await issueScanToken(reqWithIP(ip), env);
  return (await res.json()).token;
}

describe('issueScanToken', () => {
  it('issues a well-formed 5-part token with a 5-minute expiry', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const res = await issueScanToken(reqWithIP('1.2.3.4'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token.split('.')).toHaveLength(5);
    expect(body.expires_in).toBe(300);
  });

  it('rate-limits issuance after 10 tokens per IP per minute', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    for (let i = 0; i < 10; i++) {
      expect((await issueScanToken(reqWithIP('9.9.9.9'), env)).status).toBe(200);
    }
    const blocked = await issueScanToken(reqWithIP('9.9.9.9'), env);
    expect(blocked.status).toBe(429);
  });

  it('answers CORS preflight without touching KV', async () => {
    const res = await issueScanToken(new Request('https://x/api/scan/token', { method: 'OPTIONS' }), { SECURITY_HUB_KV: kvStub() });
    expect(res.status).toBe(204);
  });
});

describe('verifyScanToken', () => {
  afterEach(() => { vi.useRealTimers(); });

  it('accepts a freshly issued token presented from the same IP', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(env, '1.2.3.4');
    const result = await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), env);
    expect(result.valid).toBe(true);
  });

  it('accepts a token when neither request carries CF-Connecting-IP (fallback must match issueScanToken\'s exactly)', async () => {
    // Regression: issueScanToken fell back to 'unknown', verifyScanToken fell
    // back to '' — different strings hash differently, so any caller lacking
    // the header (every non-Cloudflare-edge context, e.g. tests) got a false
    // ip_mismatch on every request.
    const env = { SECURITY_HUB_KV: kvStub() };
    const tokRes = await issueScanToken(new Request('https://x/api/scan/token', { method: 'POST' }), env);
    const { token } = await tokRes.json();
    const result = await verifyScanToken(new Request('https://x/api/scan/domain', {
      method: 'POST', headers: { 'X-Scan-Token': token },
    }), env);
    expect(result.valid).toBe(true);
  });

  it('rejects a missing token', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const result = await verifyScanToken(scanReqWithToken(null, '1.2.3.4'), env);
    expect(result).toEqual({ valid: false, reason: 'missing_scan_token' });
  });

  it('rejects a malformed token', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const result = await verifyScanToken(scanReqWithToken('not.enough.parts', '1.2.3.4'), env);
    expect(result.reason).toBe('malformed_token');
  });

  it('rejects an incompatible token version', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const parts = (await getToken(env)).split('.');
    parts[0] = 'cdb99';
    const result = await verifyScanToken(scanReqWithToken(parts.join('.'), '1.2.3.4'), env);
    expect(result.reason).toBe('invalid_token_version');
  });

  it('rejects a token presented from a different IP than it was issued to', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(env, '1.1.1.1');
    const result = await verifyScanToken(scanReqWithToken(token, '2.2.2.2'), env);
    expect(result.reason).toBe('ip_mismatch');
  });

  it('rejects a tampered token (signature no longer matches)', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const parts = (await getToken(env)).split('.');
    parts[3] = parts[3].split('').reverse().join(''); // corrupt the nonce inside the signed payload
    const result = await verifyScanToken(scanReqWithToken(parts.join('.'), '1.2.3.4'), env);
    expect(result.reason).toBe('invalid_signature');
  });

  it('is single-use — a second verification of the same token is rejected', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(env);
    expect((await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), env)).valid).toBe(true);
    const second = await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), env);
    expect(second.valid).toBe(false);
    expect(second.reason).toBe('token_already_used');
  });

  it('rejects a token older than the 5-minute validity window', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const env = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(env);
    vi.setSystemTime(new Date('2026-01-01T00:06:00Z'));
    const result = await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), env);
    expect(result.reason).toBe('token_expired');
  });

  it('fails open (availability over strictness) if KV is unavailable at the burn step', async () => {
    const env = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(env);
    const brokenEnv = { SECURITY_HUB_KV: { get: async () => { throw new Error('KV down'); }, put: async () => {} } };
    const result = await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), brokenEnv);
    expect(result.valid).toBe(true);
  });

  // ── IR-3 lock: Workers KV eventual consistency ─────────────────────────────
  // Live incident (2026-07-06, caught by the CEAP sweep ~11 min after deploy):
  // every first-use JWT browser scan 403'd `token_already_used_or_expired`
  // because verify's kv.get() could not yet see issue's unawaited kv.put()
  // (different invocation / edge cache — KV is eventually consistent). The
  // perfectly-consistent kvStub in this file masked it. A missing record must
  // fail OPEN (the HMAC proves issuance; TTL + IP bind it); only a visible
  // used tombstone proves replay.
  it('accepts a cryptographically valid token whose issuance record is not yet visible in KV (eventual consistency)', async () => {
    const issueEnv = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(issueEnv, '1.2.3.4');
    const verifyEnv = { SECURITY_HUB_KV: kvStub() }; // fresh store: put not propagated
    const result = await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), verifyEnv);
    expect(result.valid).toBe(true);
  });

  it('still rejects replay after an eventual-consistency first use (tombstone written by verify itself)', async () => {
    const issueEnv  = { SECURITY_HUB_KV: kvStub() };
    const token = await getToken(issueEnv, '1.2.3.4');
    const verifyEnv = { SECURITY_HUB_KV: kvStub() };
    expect((await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), verifyEnv)).valid).toBe(true);
    const replay = await verifyScanToken(scanReqWithToken(token, '1.2.3.4'), verifyEnv);
    expect(replay.valid).toBe(false);
    expect(replay.reason).toBe('token_already_used');
  });
});

describe('scanTokenError', () => {
  it('returns 403 with a stable error code and an actionable hint', async () => {
    const res = scanTokenError('missing_scan_token');
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('scan_token_invalid');
    expect(body.reason).toBe('missing_scan_token');
    expect(body.hint).toMatch(/scan\/token/);
  });
});
