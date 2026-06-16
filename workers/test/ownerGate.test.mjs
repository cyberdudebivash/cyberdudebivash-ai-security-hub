/* Regression tests — owner-only gate for internal sales/CRM/proposal/funnel APIs.
 * These endpoints serve single-tenant owner business data (leads, deal values,
 * client PII, revenue). They must reject anonymous IP-fallback callers and regular
 * customers, and allow only the admin key or a logged-in owner-email account. */
import { describe, it, expect } from 'vitest';
import { isOwner, ownerEmails, forbidden } from '../src/auth/middleware.js';

describe('owner gate (isOwner / ownerEmails)', () => {
  it('defaults the owner email to bivash@cyberdudebivash.com', () => {
    expect(ownerEmails({})).toContain('bivash@cyberdudebivash.com');
  });

  it('honors env.OWNER_EMAILS override (comma-separated, case-insensitive)', () => {
    const list = ownerEmails({ OWNER_EMAILS: 'a@x.com, B@Y.com' });
    expect(list).toEqual(['a@x.com', 'b@y.com']);
  });

  it('treats the ADMIN_KEY context (isAdmin) as owner', () => {
    expect(isOwner({ isAdmin: true, email: null }, {})).toBe(true);
  });

  it('treats a logged-in owner-email account as owner (case-insensitive)', () => {
    expect(isOwner({ method: 'jwt', email: 'Bivash@CyberDudeBivash.com' }, {})).toBe(true);
  });

  it('REJECTS anonymous IP-fallback (authenticated:true but no email)', () => {
    // resolveAuthV5 returns authenticated:true for IP fallback — this is exactly
    // the case that used to leak data; isOwner must still return false.
    expect(isOwner({ authenticated: true, method: 'ip_fallback', email: null, user_id: null }, {})).toBe(false);
  });

  it('REJECTS a regular logged-in customer', () => {
    expect(isOwner({ method: 'jwt', email: 'customer@example.com', tier: 'PRO' }, {})).toBe(false);
  });

  it('forbidden() returns a 403 JSON response', async () => {
    const res = forbidden();
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('Forbidden');
  });
});
