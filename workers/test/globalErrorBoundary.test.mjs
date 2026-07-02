/* Global operational guard — exported fetch() in src/index.js.
 *
 * Before this guard existed, the 6,700-line route chain ran bare inside
 * fetch(): any uncaught handler exception (auth resolver hitting a D1 error
 * outside a route-local try, a dynamic import failing, a TypeError in a
 * handler) surfaced as a Cloudflare 1101 HTML error page — no CORS headers,
 * no JSON envelope, no system_errors record, no alert. Browsers saw an opaque
 * network failure and ops saw nothing.
 *
 * The caller's X-Request-ID was also generated but never attached: every
 * response carried a fresh random ID from withSecurityHeaders(), so client
 * logs, worker logs, and error records could never be correlated.
 *
 * These tests lock in the guard's contract:
 *   1. Uncaught exception → structured JSON 500 (ERR_UNHANDLED) with CORS +
 *      security headers + the request's correlation ID.
 *   2. Caller-supplied X-Request-ID is echoed on the response.
 *   3. When no ID is supplied, a cdb_-prefixed one is minted and returned.
 *   4. X-Response-Time is stamped on every response.
 *   5. The 404 fallback (and its envelope) is unchanged by the refactor.
 */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

function kvStub() {
  return {
    get:    async () => null,
    put:    async () => {},
    delete: async () => {},
    list:   async () => ({ keys: [] }),
  };
}

function dbStub() {
  const results = { results: [], success: true };
  const stmt = {
    bind:  () => stmt,
    first: async () => null,
    all:   async () => results,
    run:   async () => ({ success: true }),
  };
  return { prepare: () => stmt, batch: async () => [] };
}

function baseEnv() {
  return { DB: dbStub(), KV: kvStub(), SECURITY_HUB_DB: dbStub(), SECURITY_HUB_KV: kvStub() };
}

function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

describe('global exception boundary', () => {
  it('converts an uncaught routing exception into a structured JSON 500 with CORS + security headers', async () => {
    // A request object whose URL cannot be parsed makes routeRequest() throw
    // outside every route-local try/catch — exactly the class of failure that
    // previously escaped fetch() and became a Cloudflare 1101 HTML page.
    const badRequest = {
      url:     'this is not a URL',
      method:  'GET',
      headers: new Headers({ 'X-Request-ID': 'corr-boom-1' }),
    };

    const res = await worker.fetch(badRequest, baseEnv(), ctxStub());

    expect(res.status).toBe(500);
    expect(res.headers.get('Content-Type')).toContain('application/json');
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.code).toBe('ERR_UNHANDLED');
    expect(body.error).toBe('Internal server error');
    // No stack trace or internal detail leaks to the caller
    expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/);
    // Correlation survives the failure path
    expect(body.request_id).toBe('corr-boom-1');
    expect(res.headers.get('X-Request-ID')).toBe('corr-boom-1');
    // Response is still fully decorated — browser clients get CORS, not an opaque error
    expect(res.headers.get('Access-Control-Allow-Origin')).toBeTruthy();
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('never throws out of fetch() even when alerting/error-log dependencies are absent', async () => {
    const badRequest = { url: '::::', method: 'POST', headers: new Headers() };
    // Completely empty env — logSystemError and sendAlert must both degrade silently
    const res = await worker.fetch(badRequest, {}, ctxStub());
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.code).toBe('ERR_UNHANDLED');
  });
});

describe('request correlation (X-Request-ID)', () => {
  it('echoes the caller-supplied X-Request-ID on the response', async () => {
    const req = new Request('https://cyberdudebivash.in/api/nonexistent-route-for-test', {
      headers: { 'X-Request-ID': 'client-supplied-abc123' },
    });
    const res = await worker.fetch(req, baseEnv(), ctxStub());
    expect(res.headers.get('X-Request-ID')).toBe('client-supplied-abc123');
  });

  it('mints a cdb_-prefixed correlation ID when the caller sends none', async () => {
    const req = new Request('https://cyberdudebivash.in/api/nonexistent-route-for-test');
    const res = await worker.fetch(req, baseEnv(), ctxStub());
    expect(res.headers.get('X-Request-ID')).toMatch(/^cdb_/);
  });
});

describe('response timing', () => {
  it('stamps X-Response-Time on every response', async () => {
    const req = new Request('https://cyberdudebivash.in/api/nonexistent-route-for-test');
    const res = await worker.fetch(req, baseEnv(), ctxStub());
    expect(res.headers.get('X-Response-Time')).toMatch(/^\d+ms$/);
  });
});

describe('404 fallback regression', () => {
  it('unmatched API routes still return the structured 404 envelope', async () => {
    const req = new Request('https://cyberdudebivash.in/api/nonexistent-route-for-test');
    const res = await worker.fetch(req, baseEnv(), ctxStub());
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe('Not Found');
    expect(body.path).toBe('/api/nonexistent-route-for-test');
  });
});
