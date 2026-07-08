/* handleEnterpriseStats admin gate.
 *
 * CORRECTION (2026-07-08): the original version of this test (P1-4,
 * 2026-07-06) asserted that a `role: 'admin'` field must be REJECTED, on the
 * premise that authCtx.role is "never populated in production" and a stray/
 * forgeable field. That premise was wrong for this route: index.js's real
 * GET /api/enterprise/stats call site passes a narrowed
 * { userId, role: authCtx.role } object — never the full authCtx, never
 * `.isAdmin` — and `authCtx.role` is itself derived server-side by
 * withAuthAliases() (from isAdmin/tier/partnerId), not client-forgeable. The
 * isAdmin-only fix this test was written to lock in had actually made this
 * admin dashboard 403 for every real admin, live, since it shipped — the
 * exact case the test's own third assertion claims to guard against. Fixed
 * the handler to accept both shapes; corrected this test to match. */
import { describe, it, expect } from 'vitest';
import { handleEnterpriseStats } from '../src/handlers/enterpriseLayer.js';

function makeEnv() {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return {}; },
          async all() { return { results: [] }; },
        };
      },
    },
  };
}

describe('GET /api/enterprise/stats — admin gate', () => {
  it('rejects a non-admin caller', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { tier: 'ENTERPRISE' });
    expect(res.status).toBe(403);
  });

  it('rejects a caller with an unrelated, non-"admin" role value', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { role: 'partner', isAdmin: false });
    expect(res.status).toBe(403);
  });

  it('allows role: "admin" — the real narrowed-wrapper shape index.js actually passes, server-derived by withAuthAliases()', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { userId: 'admin', role: 'admin' });
    expect(res.status).not.toBe(403);
  });

  it('allows the real admin (isAdmin bypass) — also works if ever called with a full authCtx instead', async () => {
    const res = await handleEnterpriseStats(new Request('https://x/api/enterprise/stats'), makeEnv(), { isAdmin: true });
    expect(res.status).not.toBe(403);
  });
});
