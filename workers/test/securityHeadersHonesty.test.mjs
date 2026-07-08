/* Regression test — withSecurityHeaders() previously sent a literal
 * "X-Zero-Trust: enforced" header on every response with no Zero Trust
 * architecture behind it (RBAC covers a handful of handlers; most
 * authorization is still a single ADMIN_KEY/owner-email bypass). A
 * technical buyer's review would catch this as a false claim. Lock that it
 * stays removed rather than creep back in. */
import { describe, it, expect } from 'vitest';
import { withSecurityHeaders } from '../src/middleware/security.js';

describe('withSecurityHeaders — no unbacked architecture claims', () => {
  it('does not send X-Zero-Trust on responses', () => {
    const resp = withSecurityHeaders(new Response('ok', { status: 200 }), 'req_test');
    expect(resp.headers.get('X-Zero-Trust')).toBeNull();
  });

  it('still sends the legitimate identity/support headers', () => {
    const resp = withSecurityHeaders(new Response('ok', { status: 200 }), 'req_test');
    expect(resp.headers.get('X-Powered-By')).toBeTruthy();
    expect(resp.headers.get('X-Request-ID')).toBe('req_test');
  });
});
